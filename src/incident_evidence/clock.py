"""可解释的时钟校准：把源时钟读数映射到统一时间轴。

映射规则（对每个事件完全可重放、可解释）：

    修正量 = offset_ms + drift_ppm × 自校准时刻起经过的秒数 / 1000
    统一时间 = 源时钟读数 - 修正量

其中 offset_ms 是校准时刻测得的“源时钟 - 统一参考”的毫秒差，
drift_ppm 是源时钟每秒漂移的微秒数。原始读数永不改动，
映射结果与校准轨迹（用了哪份档案、哪条规则、修正量多少）一并输出。
"""

from datetime import datetime, timedelta

from .contracts import CalibrationProfile, CalibrationTrace, ClockCalibrationRule
from .errors import CalibrationGapError


def map_to_unified(
    source_time: datetime, rule: ClockCalibrationRule, profile_ref: str
) -> tuple[datetime, CalibrationTrace]:
    elapsed_seconds = (source_time - rule.measured_at).total_seconds()
    drift_ms = rule.drift_ppm * elapsed_seconds / 1000.0
    correction_ms = rule.offset_ms + drift_ms
    unified = source_time - timedelta(milliseconds=correction_ms)
    adjustment = (
        f"source - {correction_ms:.3f}ms"
        if correction_ms >= 0
        else f"source + {abs(correction_ms):.3f}ms"
    )
    formula = (
        f"unified = source - (offset {rule.offset_ms}ms"
        f" + drift {rule.drift_ppm}ppm × {elapsed_seconds:.3f}s)"
        f" = {adjustment}"
    )
    trace = CalibrationTrace(
        clock_id=rule.clock_id,
        profile_ref=profile_ref,
        offset_ms=rule.offset_ms,
        drift_ppm=rule.drift_ppm,
        correction_ms=correction_ms,
        method=rule.method,
        rationale=rule.rationale,
        formula=formula,
    )
    return unified, trace


def resolve_rule(profile: CalibrationProfile, clock_id: str) -> ClockCalibrationRule:
    rule = profile.rule_for(clock_id)
    if rule is None:
        raise CalibrationGapError(
            f"校准档案 {profile.ref} 缺少时钟 {clock_id!r} 的规则"
        )
    return rule
