"""可解释、可版本化的时钟校准。

调查中每个来源设备（车端、路侧、云端、笔录）都有自己的时钟，
本模块把"来源时钟读数 -> 统一时间轴（UTC 主时间轴）"的换算规则做成
**不可变的校准版本**：

* 每条 :class:`CalibrationRule` 显式记录适用设备时钟、时间区间、换算参数
  （恒定偏差 ``offset`` 或带频偏的 ``linear``）与依据说明；
* 每次登记规则都会产生新的 :class:`CalibrationVersion`，并链上前一版本
  的指纹，旧版本永不改变——校准规则收紧或修正不会改写既往调查版本；
* :meth:`ClockCalibrator.explain` 返回完整换算过程，可逐毫秒复核。
"""

from __future__ import annotations

import threading
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import StrEnum

from .fingerprints import fingerprint


class RuleKind(StrEnum):
    OFFSET = "offset"
    LINEAR = "linear"


MASTER_TIMELINE = "master:utc"


class CalibrationError(ValueError):
    """校准规则本身不合法（区间重叠、参数缺失等）。"""


class ClockNotCalibrated(LookupError):
    """请求的校准版本中，该时钟在该时刻没有适用规则。"""


@dataclass(frozen=True)
class CalibrationRule:
    rule_id: str
    clock_id: str
    kind: RuleKind
    offset_ms: int = 0
    # 线性（频偏）模型参数：
    # common = anchor_common + (source - anchor_source) * (1 + rate_ppm / 1e6)
    rate_ppm: int = 0
    anchor_source: datetime | None = None
    anchor_common: datetime | None = None
    valid_from: datetime | None = None
    valid_to: datetime | None = None
    note: str = ""

    def __post_init__(self) -> None:
        if not self.rule_id.strip() or not self.clock_id.strip():
            raise CalibrationError("规则标识与时钟标识均不能为空")
        if self.valid_from and self.valid_from.tzinfo is None:
            raise CalibrationError("valid_from 必须携带时区")
        if self.valid_to and self.valid_to.tzinfo is None:
            raise CalibrationError("valid_to 必须携带时区")
        if (
            self.valid_from
            and self.valid_to
            and self.valid_to < self.valid_from
        ):
            raise CalibrationError("规则适用区间结束早于开始")
        if self.kind == RuleKind.LINEAR:
            if self.anchor_source is None or self.anchor_common is None:
                raise CalibrationError("线性规则必须提供 anchor_source/anchor_common")
            if self.anchor_source.tzinfo is None or self.anchor_common.tzinfo is None:
                raise CalibrationError("线性规则锚点必须携带时区")
        elif self.kind == RuleKind.OFFSET:
            pass
        else:  # pragma: no cover - StrEnum 已封闭
            raise CalibrationError(f"未知规则类型: {self.kind}")

    def covers(self, when: datetime) -> bool:
        if self.valid_from is not None and when < self.valid_from:
            return False
        if self.valid_to is not None and when > self.valid_to:
            return False
        return True

    def map(self, when: datetime) -> datetime:
        if when.tzinfo is None:
            raise CalibrationError("待校准时间必须携带时区")
        if self.kind == RuleKind.OFFSET:
            return when + timedelta(milliseconds=self.offset_ms)
        delta_us = int((when - self.anchor_source).total_seconds() * 1_000_000)
        factor_num = 1_000_000 + self.rate_ppm
        if delta_us >= 0:
            adjusted = (delta_us * factor_num + 500_000) // 1_000_000
        else:  # 负数四舍五入保持对称
            adjusted = -((-delta_us * factor_num + 500_000) // 1_000_000)
        return self.anchor_common + timedelta(microseconds=adjusted)


@dataclass(frozen=True)
class CalibrationVersion:
    version: int
    created_at: datetime
    description: str
    rules: tuple[CalibrationRule, ...]
    prev_fingerprint: str | None
    timeline_id: str = MASTER_TIMELINE
    fingerprint_value: str = field(default="", hash=False)  # type: ignore[assignment]

    def __post_init__(self) -> None:
        if not self.rules and self.version > 0:
            raise CalibrationError("校准版本至少要包含一条规则")
        object.__setattr__(self, "fingerprint_value", fingerprint(self._digest_input()))

    def _digest_input(self) -> dict:
        return {
            "type": "calibration_version",
            "version": self.version,
            "created_at": self.created_at,
            "description": self.description,
            "timeline_id": self.timeline_id,
            "rules": list(self.rules),
            "prev_fingerprint": self.prev_fingerprint,
        }


@dataclass(frozen=True)
class CalibrationExplanation:
    """一次时间换算的完整、可人工复核的解释。"""

    clock_id: str
    source_time: datetime
    common_time: datetime
    calibration_version: int
    rule_id: str
    rule_kind: RuleKind
    offset_ms: int
    rate_ppm: int
    anchor_source: datetime | None
    anchor_common: datetime | None
    timeline_id: str
    note: str

    @property
    def delta_ms(self) -> int:
        delta = self.common_time - self.source_time
        return int(delta.total_seconds() * 1000)

    def describe(self) -> str:
        if self.rule_kind == RuleKind.OFFSET:
            detail = f"恒定偏差 {self.offset_ms:+d} ms"
        else:
            detail = (
                f"以 ({self.anchor_source.isoformat()} -> "
                f"{self.anchor_common.isoformat()}) 为锚点，频偏 {self.rate_ppm:+d} ppm"
            )
        return (
            f"[{self.timeline_id}] 时钟 {self.clock_id} 的读数 "
            f"{self.source_time.isoformat()} 经规则 {self.rule_id}（{detail}）"
            f"映射为 {self.common_time.isoformat()}；依据：{self.note or '无'}"
        )


class ClockCalibrator:
    """持有一串不可变校准版本，按指定版本解释时间映射。"""

    def __init__(self) -> None:
        self._versions: dict[int, CalibrationVersion] = {}
        self._lock = threading.Lock()

    # ---- 版本登记 -------------------------------------------------------

    def register(
        self,
        rules: list[CalibrationRule] | tuple[CalibrationRule, ...],
        description: str,
        created_at: datetime | None = None,
    ) -> CalibrationVersion:
        rules = tuple(rules)
        if not rules:
            raise CalibrationError("至少登记一条校准规则")
        self._validate_no_overlap(rules)
        created_at = created_at or datetime.now(timezone.utc)
        with self._lock:
            prev = self.latest_version()
            prev_fp = self._versions[prev].fingerprint_value if prev else None
            version = CalibrationVersion(
                version=(prev or 0) + 1,
                created_at=created_at,
                description=description,
                rules=rules,
                prev_fingerprint=prev_fp,
            )
            self._versions[version.version] = version
        return version

    @staticmethod
    def _validate_no_overlap(rules: tuple[CalibrationRule, ...]) -> None:
        by_clock: dict[str, list[CalibrationRule]] = {}
        for rule in rules:
            by_clock.setdefault(rule.clock_id, []).append(rule)
        for clock_id, grouped in by_clock.items():
            for i, a in enumerate(grouped):
                for b in grouped[i + 1 :]:
                    if _intervals_overlap(a.valid_from, a.valid_to, b.valid_from, b.valid_to):
                        raise CalibrationError(
                            f"时钟 {clock_id} 的规则 {a.rule_id} 与 {b.rule_id} 适用区间重叠"
                        )

    # ---- 查询 -----------------------------------------------------------

    def latest_version(self) -> int | None:
        return max(self._versions) if self._versions else None

    def version(self, number: int) -> CalibrationVersion:
        try:
            return self._versions[number]
        except KeyError:
            raise CalibrationError(f"校准版本 {number} 不存在") from None

    def versions(self) -> tuple[CalibrationVersion, ...]:
        return tuple(self._versions[k] for k in sorted(self._versions))

    def _find_rule(
        self, version: CalibrationVersion, clock_id: str, when: datetime
    ) -> CalibrationRule:
        candidates = [
            rule
            for rule in version.rules
            if rule.clock_id == clock_id and rule.covers(when)
        ]
        if not candidates:
            raise ClockNotCalibrated(
                f"校准版本 v{version.version} 中，时钟 {clock_id} 在 {when.isoformat()} 无适用规则"
            )
        return candidates[0]  # 登记时已拒绝重叠，这里至多一条

    def explain(
        self,
        source_time: datetime,
        clock_id: str,
        at_version: int | None = None,
    ) -> CalibrationExplanation:
        number = at_version or self.latest_version()
        if number is None:
            raise ClockNotCalibrated("尚未登记任何校准版本")
        version = self.version(number)
        rule = self._find_rule(version, clock_id, source_time)
        common = rule.map(source_time)
        return CalibrationExplanation(
            clock_id=clock_id,
            source_time=source_time,
            common_time=common,
            calibration_version=version.version,
            rule_id=rule.rule_id,
            rule_kind=rule.kind,
            offset_ms=rule.offset_ms,
            rate_ppm=rule.rate_ppm,
            anchor_source=rule.anchor_source,
            anchor_common=rule.anchor_common,
            timeline_id=version.timeline_id,
            note=rule.note,
        )

    def map_time(
        self, source_time: datetime, clock_id: str, at_version: int | None = None
    ) -> datetime:
        return self.explain(source_time, clock_id, at_version).common_time


def _intervals_overlap(
    a_start: datetime | None,
    a_end: datetime | None,
    b_start: datetime | None,
    b_end: datetime | None,
) -> bool:
    """半开区间语义下判断两个 [from, to] 区间是否有正长度交集。"""

    latest_start = max_datetime(a_start, b_start)
    earliest_end = min_datetime(a_end, b_end)
    if latest_start is None or earliest_end is None:
        return True  # 至少一侧无界且共享时钟，保守视为重叠
    return latest_start < earliest_end


def max_datetime(a: datetime | None, b: datetime | None) -> datetime | None:
    if a is None:
        return b
    if b is None:
        return a
    return max(a, b)


def min_datetime(a: datetime | None, b: datetime | None) -> datetime | None:
    if a is None:
        return b
    if b is None:
        return a
    return min(a, b)
