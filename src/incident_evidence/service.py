"""证据封存、版本化与时间线生成的核心服务。

不可变原则贯穿整个服务：

* 接收即落收据 :class:`Receipt`（含接收时刻、批次、内容指纹、来源时钟原始读数）；
* 同一字节内容重复接收会被识别并拒绝，不会产生第二条证据；
* 补充/更正通过 ``supersedes`` 形成关联的新版本，旧版本原样保留；
* 撤回只对指定版本追加撤回记录，不删除任何字节；
* 调查版本 :class:`InvestigationVersion` 冻结「时点 + 校准版本 + 证据成员快照」；
* 证据包 :class:`EvidencePackage` 签封后不得增删，保全解除只改变保全状态；
* 报告与导出物都带规范指纹，可在任意时刻离线重算复核。
"""

from __future__ import annotations

import hashlib
import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import StrEnum
from typing import Any, Iterable

from .audit import (
    AccessController,
    Actor,
    AuditAction,
    AuditLog,
    Permission,
)
from .clock import (
    CalibrationExplanation,
    CalibrationVersion,
    ClockCalibrator,
    ClockNotCalibrated,
)
from .contracts import (
    CollectionWindow,
    EvidenceKind,
    EvidenceRef,
    LifecycleStatus,
    SourceClock,
)
from .fingerprints import canonical, content_fingerprint, fingerprint


class EvidenceError(ValueError):
    """登记参数不合法。"""


class DuplicateEvidence(EvidenceError):
    """内容指纹已存在：重复接收。"""

    def __init__(self, content_fp: str, existing: EvidenceRef) -> None:
        super().__init__(
            f"内容 {content_fp} 已在 {existing} 接收，禁止重复入登记"
        )
        self.existing = existing


class UnknownEvidence(LookupError):
    pass


class PackageError(ValueError):
    pass


class PackageSealedError(PackageError):
    pass


class SealConflictError(PackageError):
    pass


@dataclass(frozen=True)
class Receipt:
    """一次证据接收的不可变收据（证据的某个版本）。"""

    evidence_id: str
    version: int
    kind: EvidenceKind
    source_id: str
    summary: str
    source_clock: SourceClock
    source_time: datetime
    collection_window: CollectionWindow | None
    batch_id: str
    received_at: datetime
    payload_ref: str | None
    content_fingerprint_value: str
    supersedes: EvidenceRef | None
    receipt_fingerprint: str = ""  # type: ignore[assignment]

    def __post_init__(self) -> None:
        if not self.evidence_id.strip() or not self.batch_id.strip():
            raise EvidenceError("证据标识与接收批次不能为空")
        if not self.content_fingerprint_value.strip():
            raise EvidenceError("证据完整性指纹不能为空")
        if self.source_time.tzinfo is None:
            raise EvidenceError("来源时间必须携带时区")
        if self.received_at.tzinfo is None:
            raise EvidenceError("接收时刻必须携带时区")
        if self.collection_window is not None and (
            self.collection_window.clock_id != self.source_clock.clock_id
        ):
            raise EvidenceError("采集区间必须使用与证据相同的来源时钟")
        object.__setattr__(self, "receipt_fingerprint", fingerprint(self._digest()))

    @property
    def ref(self) -> EvidenceRef:
        return EvidenceRef(self.evidence_id, self.version)

    def _digest(self) -> dict[str, Any]:
        return {
            "type": "evidence_receipt",
            "evidence_id": self.evidence_id,
            "version": self.version,
            "kind": self.kind,
            "source_id": self.source_id,
            "summary": self.summary,
            "source_clock": self.source_clock,
            "source_time": self.source_time,
            "collection_window": self.collection_window,
            "batch_id": self.batch_id,
            "received_at": self.received_at,
            "payload_ref": self.payload_ref,
            "content_fingerprint": self.content_fingerprint_value,
            "supersedes": self.supersedes,
        }


@dataclass(frozen=True)
class WithdrawalRecord:
    ref: EvidenceRef
    reason: str
    at: datetime
    actor_id: str

    def __post_init__(self) -> None:
        if not self.reason.strip():
            raise EvidenceError("撤回必须说明理由")


@dataclass(frozen=True)
class BatchRecord:
    batch_id: str
    refs: tuple[EvidenceRef, ...]
    fingerprint_value: str


@dataclass(frozen=True)
class VersionStatus:
    ref: EvidenceRef
    status: LifecycleStatus
    reason: str = ""
    superseded_by: EvidenceRef | None = None


@dataclass(frozen=True)
class InvestigationVersion:
    """调查版本：冻结时点、校准版本与证据成员集合。"""

    number: int
    label: str
    created_at: datetime
    as_of: datetime
    calibration_version: int
    active_refs: tuple[EvidenceRef, ...]
    excluded: tuple[VersionStatus, ...]
    prev_fingerprint: str | None
    fingerprint_value: str = ""  # type: ignore[assignment]

    def __post_init__(self) -> None:
        object.__setattr__(self, "fingerprint_value", fingerprint(self._digest()))

    def _digest(self) -> dict[str, Any]:
        return {
            "type": "investigation_version",
            "number": self.number,
            "label": self.label,
            "created_at": self.created_at,
            "as_of": self.as_of,
            "calibration_version": self.calibration_version,
            "active_refs": list(self.active_refs),
            "excluded": list(self.excluded),
            "prev_fingerprint": self.prev_fingerprint,
        }


@dataclass(frozen=True)
class PackageItem:
    ref: EvidenceRef
    content_fingerprint: str
    receipt_fingerprint: str
    kind: EvidenceKind
    source_clock_id: str
    source_time: datetime


@dataclass(frozen=True)
class CustodyRecord:
    from_actor: str | None
    to_actor: str
    at: datetime
    note: str


class PackageStatus(StrEnum):
    SEALED = "sealed"        # 已签封，处于保全中
    RELEASED = "released"    # 已解除保全（内容仍不可变）


@dataclass(frozen=True)
class EvidencePackage:
    package_id: str
    sealed_at: datetime
    sealed_by: str
    custodian: str
    items: tuple[PackageItem, ...]
    calibration_version: int
    status: PackageStatus
    custody: tuple[CustodyRecord, ...]
    released_at: datetime | None
    released_by: str | None
    package_fingerprint: str = ""  # type: ignore[assignment]

    def __post_init__(self) -> None:
        object.__setattr__(self, "package_fingerprint", fingerprint(self._digest()))

    @property
    def refs(self) -> tuple[EvidenceRef, ...]:
        return tuple(item.ref for item in self.items)

    def _digest(self) -> dict[str, Any]:
        return {
            "type": "evidence_package",
            "package_id": self.package_id,
            "sealed_at": self.sealed_at,
            "sealed_by": self.sealed_by,
            "items": list(self.items),
            "calibration_version": self.calibration_version,
        }


@dataclass(frozen=True)
class TimelineEvent:
    evidence_id: str
    version: int
    kind: EvidenceKind
    source_id: str
    summary: str
    batch_id: str
    source_clock_id: str
    source_time: datetime
    common_time: datetime
    calibration_version: int
    rule_id: str
    explanation: str
    window_source_start: datetime | None
    window_source_end: datetime | None
    window_common_start: datetime | None
    window_common_end: datetime | None
    content_fingerprint: str
    receipt_fingerprint: str


@dataclass(frozen=True)
class TimelineReport:
    investigation_version: int
    label: str
    generated_at: datetime
    as_of: datetime
    calibration_version: int
    calibration_fingerprint: str
    investigation_fingerprint: str
    events: tuple[TimelineEvent, ...]
    excluded: tuple[VersionStatus, ...]
    report_fingerprint: str = ""  # type: ignore[assignment]

    def __post_init__(self) -> None:
        object.__setattr__(self, "report_fingerprint", fingerprint(self._digest()))

    def _digest(self) -> dict[str, Any]:
        # generated_at 只是生成时刻元数据，不参与摘要：
        # 同一调查版本在任意时刻重新生成的报告指纹必须一致。
        return {
            "type": "timeline_report",
            "investigation_version": self.investigation_version,
            "label": self.label,
            "as_of": self.as_of,
            "calibration_version": self.calibration_version,
            "calibration_fingerprint": self.calibration_fingerprint,
            "investigation_fingerprint": self.investigation_fingerprint,
            "events": list(self.events),
            "excluded": list(self.excluded),
        }


@dataclass(frozen=True)
class ExportBundle:
    """导出物：自描述的规范字节流 + 指纹，接收方可独立复核。"""

    package_id: str
    package_fingerprint: str
    exported_at: datetime
    exported_by: str
    data: bytes
    export_fingerprint: str


class EvidenceService:
    """线程安全的事故证据封存与时间线服务。"""

    def __init__(
        self,
        audit: AuditLog | None = None,
        access: AccessController | None = None,
        calibrator: ClockCalibrator | None = None,
    ) -> None:
        self.audit = audit or AuditLog()
        self.access = access or AccessController()
        self.calibrator = calibrator or ClockCalibrator()
        self._receipts: dict[EvidenceRef, Receipt] = {}
        self._by_content: dict[str, EvidenceRef] = {}
        self._versions_of: dict[str, list[int]] = {}
        self._withdrawals: dict[EvidenceRef, WithdrawalRecord] = {}
        self._batches: dict[str, list[EvidenceRef]] = {}
        self._investigations: dict[int, InvestigationVersion] = {}
        self._packages: dict[str, EvidencePackage] = {}
        self._exports: list[ExportBundle] = []
        self._lock = threading.RLock()

    # ------------------------------------------------------------------ #
    # 授权辅助
    # ------------------------------------------------------------------ #

    def _require(self, actor: Actor, permission: Permission, ref: str) -> None:
        if self.access.permit(actor, permission):
            return
        self.audit.append(
            actor.actor_id,
            AuditAction.PERMISSION_DENIED,
            ref,
            permission=permission,
            allowed=False,
        )
        self.access.require(actor, permission)  # 抛出 AuthorizationError

    # ------------------------------------------------------------------ #
    # 证据接收 / 更正 / 撤回
    # ------------------------------------------------------------------ #

    def receive(
        self,
        actor: Actor,
        *,
        evidence_id: str,
        kind: EvidenceKind,
        source_id: str,
        summary: str,
        source_clock: SourceClock,
        source_time: datetime,
        content: bytes,
        batch_id: str,
        collection_window: CollectionWindow | None = None,
        payload_ref: str | None = None,
        supersedes: EvidenceRef | None = None,
        received_at: datetime | None = None,
    ) -> Receipt:
        self._require(actor, Permission.RECEIVE, f"evidence:{evidence_id}")
        received_at = received_at or datetime.now(timezone.utc)
        content_fp = content_fingerprint(content)

        with self._lock:
            if content_fp in self._by_content:
                duplicate = DuplicateEvidence(content_fp, self._by_content[content_fp])
                self.audit.append(
                    actor.actor_id,
                    AuditAction.EVIDENCE_RECEIVED,
                    str(duplicate.existing),
                    permission=Permission.RECEIVE,
                    allowed=False,
                    details={
                        "reason": "duplicate_content",
                        "batch_id": batch_id,
                        "content_fingerprint": content_fp,
                    },
                )
                raise duplicate

            existing_versions = self._versions_of.setdefault(evidence_id, [])
            version = len(existing_versions) + 1
            if supersedes is not None:
                if supersedes.evidence_id != evidence_id:
                    raise EvidenceError("更正版本必须与原证据使用同一标识")
                if supersedes.version not in existing_versions:
                    raise UnknownEvidence(f"被更正的 {supersedes} 不存在")
                if supersedes.version != existing_versions[-1]:
                    raise EvidenceError(
                        f"只能更正最新版本，{evidence_id} 当前最新为 v{existing_versions[-1]}"
                    )
                if supersedes in self._withdrawals:
                    raise EvidenceError(f"{supersedes} 已撤回，不能再对其更正")

            receipt = Receipt(
                evidence_id=evidence_id,
                version=version,
                kind=kind,
                source_id=source_id,
                summary=summary,
                source_clock=source_clock,
                source_time=source_time,
                collection_window=collection_window,
                batch_id=batch_id,
                received_at=received_at,
                payload_ref=payload_ref,
                content_fingerprint_value=content_fp,
                supersedes=supersedes,
            )
            self._receipts[receipt.ref] = receipt
            self._by_content[content_fp] = receipt.ref
            existing_versions.append(version)
            self._batches.setdefault(batch_id, []).append(receipt.ref)
            self.audit.append(
                actor.actor_id,
                AuditAction.EVIDENCE_RECEIVED,
                str(receipt.ref),
                permission=Permission.RECEIVE,
                details={
                    "batch_id": batch_id,
                    "content_fingerprint": content_fp,
                    "supersedes": str(supersedes) if supersedes else None,
                },
            )
            if supersedes is not None:
                self.audit.append(
                    actor.actor_id,
                    AuditAction.EVIDENCE_SUPERSEDED,
                    str(supersedes),
                    permission=Permission.RECEIVE,
                    details={"by": str(receipt.ref)},
                )
            return receipt

    def withdraw(
        self,
        actor: Actor,
        ref: EvidenceRef,
        reason: str,
        *,
        at: datetime | None = None,
    ) -> WithdrawalRecord:
        self._require(actor, Permission.RECEIVE, str(ref))
        at = at or datetime.now(timezone.utc)
        with self._lock:
            if ref not in self._receipts:
                raise UnknownEvidence(f"{ref} 不存在")
            if ref in self._withdrawals:
                raise EvidenceError(f"{ref} 已有撤回记录")
            record = WithdrawalRecord(ref=ref, reason=reason, at=at, actor_id=actor.actor_id)
            self._withdrawals[ref] = record
            self.audit.append(
                actor.actor_id,
                AuditAction.EVIDENCE_WITHDRAWN,
                str(ref),
                permission=Permission.RECEIVE,
                details={"reason": reason},
            )
            return record

    def get_receipt(self, actor: Actor, ref: EvidenceRef) -> Receipt:
        self._require(actor, Permission.VIEW, str(ref))
        with self._lock:
            try:
                receipt = self._receipts[ref]
            except KeyError:
                raise UnknownEvidence(f"{ref} 不存在") from None
            self.audit.append(
                actor.actor_id,
                AuditAction.EVIDENCE_ACCESSED,
                str(ref),
                permission=Permission.VIEW,
                details={"content_fingerprint": receipt.content_fingerprint_value},
            )
            return receipt

    def batch(self, batch_id: str) -> BatchRecord:
        """批次记录：成员引用（按接收顺序）+ 成员内容指纹的摘要。"""

        with self._lock:
            refs = tuple(self._batches[batch_id])
            digest = {
                "type": "evidence_batch",
                "batch_id": batch_id,
                "refs": [
                    {"ref": r, "content_fingerprint": self._receipts[r].content_fingerprint_value}
                    for r in refs
                ],
            }
            return BatchRecord(batch_id, refs, fingerprint(digest))

    # ------------------------------------------------------------------ #
    # 校准
    # ------------------------------------------------------------------ #

    def register_calibration(
        self,
        actor: Actor,
        rules: list,
        description: str,
        *,
        created_at: datetime | None = None,
    ) -> CalibrationVersion:
        self._require(actor, Permission.RECEIVE, "calibration")
        version = self.calibrator.register(rules, description, created_at=created_at)
        self.audit.append(
            actor.actor_id,
            AuditAction.CALIBRATION_REGISTERED,
            f"calibration:v{version.version}",
            permission=Permission.RECEIVE,
            details={
                "description": description,
                "rules": [rule.rule_id for rule in version.rules],
                "fingerprint": version.fingerprint_value,
            },
        )
        return version

    # ------------------------------------------------------------------ #
    # 调查版本与时间线报告
    # ------------------------------------------------------------------ #

    def _status_at(self, receipt: Receipt, as_of: datetime) -> VersionStatus:
        ref = receipt.ref
        withdrawal = self._withdrawals.get(ref)
        if withdrawal is not None and withdrawal.at <= as_of:
            return VersionStatus(ref, LifecycleStatus.WITHDRAWN, reason=withdrawal.reason)
        later = [
            EvidenceRef(ref.evidence_id, v)
            for v in self._versions_of[ref.evidence_id]
            if v > ref.version and self._receipts[EvidenceRef(ref.evidence_id, v)].received_at <= as_of
        ]
        if later:
            by = later[0]
            return VersionStatus(
                ref,
                LifecycleStatus.SUPERSEDED,
                reason=f"被更正版本 {by} 取代",
                superseded_by=by,
            )
        return VersionStatus(ref, LifecycleStatus.ACTIVE)

    def create_investigation_version(
        self,
        actor: Actor,
        label: str,
        *,
        calibration_version: int | None = None,
        as_of: datetime | None = None,
        created_at: datetime | None = None,
    ) -> InvestigationVersion:
        self._require(actor, Permission.SEAL, "investigation_version")
        created_at = created_at or datetime.now(timezone.utc)
        as_of = as_of or created_at
        cal_number = calibration_version or self.calibrator.latest_version()
        if cal_number is None:
            raise ClockNotCalibrated("创建调查版本前必须先登记校准规则")
        self.calibrator.version(cal_number)  # 存在性检查

        with self._lock:
            visible = [
                receipt
                for receipt in self._receipts.values()
                if receipt.received_at <= as_of
            ]
            statuses = [self._status_at(receipt, as_of) for receipt in visible]
            active = tuple(
                sorted(
                    (s.ref for s in statuses if s.status == LifecycleStatus.ACTIVE),
                    key=lambda r: (r.evidence_id, r.version),
                )
            )
            excluded = tuple(
                sorted(
                    (s for s in statuses if s.status != LifecycleStatus.ACTIVE),
                    key=lambda s: (s.ref.evidence_id, s.ref.version),
                )
            )
            number = (max(self._investigations) + 1) if self._investigations else 1
            prev_fp = (
                self._investigations[number - 1].fingerprint_value
                if number > 1 and number - 1 in self._investigations
                else None
            )
            iv = InvestigationVersion(
                number=number,
                label=label,
                created_at=created_at,
                as_of=as_of,
                calibration_version=cal_number,
                active_refs=active,
                excluded=excluded,
                prev_fingerprint=prev_fp,
            )
            self._investigations[number] = iv
            self.audit.append(
                actor.actor_id,
                AuditAction.INVESTIGATION_VERSION_CREATED,
                f"investigation:v{number}",
                permission=Permission.SEAL,
                details={
                    "label": label,
                    "as_of": as_of.isoformat(),
                    "calibration_version": cal_number,
                    "active_count": len(active),
                    "excluded_count": len(excluded),
                    "fingerprint": iv.fingerprint_value,
                },
            )
            return iv

    def investigation_version(self, number: int) -> InvestigationVersion:
        try:
            return self._investigations[number]
        except KeyError:
            raise LookupError(f"调查版本 v{number} 不存在") from None

    def investigation_numbers(self) -> tuple[int, ...]:
        with self._lock:
            return tuple(sorted(self._investigations))

    def _explain_for(self, receipt: Receipt, cal_number: int) -> CalibrationExplanation:
        return self.calibrator.explain(
            receipt.source_time,
            receipt.source_clock.clock_id,
            at_version=cal_number,
        )

    def build_timeline_report(
        self,
        actor: Actor,
        investigation_number: int,
        *,
        generated_at: datetime | None = None,
    ) -> TimelineReport:
        self._require(actor, Permission.VIEW, f"investigation:v{investigation_number}")
        with self._lock:
            iv = self.investigation_version(investigation_number)
            generated_at = generated_at or datetime.now(timezone.utc)
            cal = self.calibrator.version(iv.calibration_version)

            events: list[TimelineEvent] = []
            for ref in iv.active_refs:
                receipt = self._receipts[ref]
                explanation = self._explain_for(receipt, iv.calibration_version)
                win = receipt.collection_window
                win_src_start = win_src_end = win_common_start = win_common_end = None
                if win is not None:
                    win_src_start, win_src_end = win.start, win.end
                    win_common_start = self.calibrator.map_time(
                        win.start, win.clock_id, at_version=iv.calibration_version
                    )
                    win_common_end = self.calibrator.map_time(
                        win.end, win.clock_id, at_version=iv.calibration_version
                    )
                events.append(
                    TimelineEvent(
                        evidence_id=receipt.evidence_id,
                        version=receipt.version,
                        kind=receipt.kind,
                        source_id=receipt.source_id,
                        summary=receipt.summary,
                        batch_id=receipt.batch_id,
                        source_clock_id=receipt.source_clock.clock_id,
                        source_time=receipt.source_time,
                        common_time=explanation.common_time,
                        calibration_version=iv.calibration_version,
                        rule_id=explanation.rule_id,
                        explanation=explanation.describe(),
                        window_source_start=win_src_start,
                        window_source_end=win_src_end,
                        window_common_start=win_common_start,
                        window_common_end=win_common_end,
                        content_fingerprint=receipt.content_fingerprint_value,
                        receipt_fingerprint=receipt.receipt_fingerprint,
                    )
                )
            events.sort(key=lambda e: (e.common_time, e.evidence_id, e.version))
            report = TimelineReport(
                investigation_version=iv.number,
                label=iv.label,
                generated_at=generated_at,
                as_of=iv.as_of,
                calibration_version=iv.calibration_version,
                calibration_fingerprint=cal.fingerprint_value,
                investigation_fingerprint=iv.fingerprint_value,
                events=tuple(events),
                excluded=iv.excluded,
            )
            self.audit.append(
                actor.actor_id,
                AuditAction.EVIDENCE_ACCESSED,
                f"report:v{investigation_number}",
                permission=Permission.VIEW,
                details={
                    "report_fingerprint": report.report_fingerprint,
                    "event_count": len(events),
                },
            )
            return report

    @staticmethod
    def verify_report(report: TimelineReport) -> None:
        """离线复核：重算报告指纹，不一致即被篡改。"""

        rebuilt = TimelineReport(
            investigation_version=report.investigation_version,
            label=report.label,
            generated_at=report.generated_at,
            as_of=report.as_of,
            calibration_version=report.calibration_version,
            calibration_fingerprint=report.calibration_fingerprint,
            investigation_fingerprint=report.investigation_fingerprint,
            events=report.events,
            excluded=report.excluded,
        )
        if rebuilt.report_fingerprint != report.report_fingerprint:
            raise RuntimeError("时间线报告指纹复核失败")

    # ------------------------------------------------------------------ #
    # 签封 / 导出 / 移交 / 解除保全
    # ------------------------------------------------------------------ #

    def seal_package(
        self,
        actor: Actor,
        package_id: str,
        refs: Iterable[EvidenceRef],
        *,
        calibration_version: int | None = None,
        sealed_at: datetime | None = None,
    ) -> EvidencePackage:
        self._require(actor, Permission.SEAL, f"package:{package_id}")
        sealed_at = sealed_at or datetime.now(timezone.utc)
        cal_number = calibration_version or self.calibrator.latest_version()
        if cal_number is None:
            raise ClockNotCalibrated("签封前必须先登记校准规则")
        refs = tuple(sorted(refs, key=lambda r: (r.evidence_id, r.version)))

        with self._lock:
            if package_id in self._packages:
                conflict = SealConflictError(
                    f"证据包 {package_id} 已签封，签封具有唯一性，禁止重复签封或改写"
                )
                self.audit.append(
                    actor.actor_id,
                    AuditAction.SEAL_CONFLICT,
                    f"package:{package_id}",
                    permission=Permission.SEAL,
                    allowed=False,
                    details={"reason": "already_sealed"},
                )
                raise conflict
            if not refs:
                raise PackageError("空证据包不得签封")
            items: list[PackageItem] = []
            for ref in refs:
                receipt = self._receipts.get(ref)
                if receipt is None:
                    raise UnknownEvidence(f"无法签封不存在的 {ref}")
                if ref in self._withdrawals:
                    raise PackageError(f"{ref} 已撤回，不得签封")
                items.append(
                    PackageItem(
                        ref=ref,
                        content_fingerprint=receipt.content_fingerprint_value,
                        receipt_fingerprint=receipt.receipt_fingerprint,
                        kind=receipt.kind,
                        source_clock_id=receipt.source_clock.clock_id,
                        source_time=receipt.source_time,
                    )
                )
            self.calibrator.version(cal_number)
            package = EvidencePackage(
                package_id=package_id,
                sealed_at=sealed_at,
                sealed_by=actor.actor_id,
                custodian=actor.actor_id,
                items=tuple(items),
                calibration_version=cal_number,
                status=PackageStatus.SEALED,
                custody=(
                    CustodyRecord(
                        from_actor=None,
                        to_actor=actor.actor_id,
                        at=sealed_at,
                        note="签封时取得保管权",
                    ),
                ),
                released_at=None,
                released_by=None,
            )
            self._packages[package_id] = package
            self.audit.append(
                actor.actor_id,
                AuditAction.PACKAGE_SEALED,
                f"package:{package_id}",
                permission=Permission.SEAL,
                details={
                    "refs": [str(r) for r in refs],
                    "fingerprint": package.package_fingerprint,
                    "calibration_version": cal_number,
                },
            )
            return package

    def package(self, package_id: str) -> EvidencePackage:
        try:
            return self._packages[package_id]
        except KeyError:
            raise LookupError(f"证据包 {package_id} 不存在") from None

    @staticmethod
    def verify_package(package: EvidencePackage) -> None:
        rebuilt = EvidencePackage(
            package_id=package.package_id,
            sealed_at=package.sealed_at,
            sealed_by=package.sealed_by,
            custodian=package.custodian,
            items=package.items,
            calibration_version=package.calibration_version,
            status=package.status,
            custody=package.custody,
            released_at=package.released_at,
            released_by=package.released_by,
        )
        if rebuilt.package_fingerprint != package.package_fingerprint:
            raise RuntimeError(f"证据包 {package.package_id} 指纹复核失败")

    def transfer_package(
        self,
        actor: Actor,
        package_id: str,
        to_actor_id: str,
        note: str = "",
        *,
        at: datetime | None = None,
    ) -> EvidencePackage:
        self._require(actor, Permission.TRANSFER, f"package:{package_id}")
        at = at or datetime.now(timezone.utc)
        with self._lock:
            current = self.package(package_id)
            if actor.actor_id != current.custodian:
                raise PackageError(
                    f"仅当前保管人 {current.custodian} 可移交，{actor.actor_id} 不是"
                )
            if current.status != PackageStatus.SEALED:
                raise PackageError("证据包已解除保全，不能再移交")
            record = CustodyRecord(actor.actor_id, to_actor_id, at, note)
            transferred = EvidencePackage(
                package_id=current.package_id,
                sealed_at=current.sealed_at,
                sealed_by=current.sealed_by,
                custodian=to_actor_id,
                items=current.items,
                calibration_version=current.calibration_version,
                status=current.status,
                custody=current.custody + (record,),
                released_at=None,
                released_by=None,
            )
            # 移交不改写签封指纹：仅追加保管链。
            assert transferred.package_fingerprint == current.package_fingerprint
            self._packages[package_id] = transferred
            self.audit.append(
                actor.actor_id,
                AuditAction.PACKAGE_TRANSFERRED,
                f"package:{package_id}",
                permission=Permission.TRANSFER,
                details={"to": to_actor_id, "note": note},
            )
            return transferred

    def release_hold(
        self,
        actor: Actor,
        package_id: str,
        *,
        note: str = "",
        at: datetime | None = None,
    ) -> EvidencePackage:
        self._require(actor, Permission.RELEASE_HOLD, f"package:{package_id}")
        at = at or datetime.now(timezone.utc)
        with self._lock:
            current = self.package(package_id)
            if current.status == PackageStatus.RELEASED:
                raise PackageError("证据包已解除保全")
            released = EvidencePackage(
                package_id=current.package_id,
                sealed_at=current.sealed_at,
                sealed_by=current.sealed_by,
                custodian=current.custodian,
                items=current.items,
                calibration_version=current.calibration_version,
                status=PackageStatus.RELEASED,
                custody=current.custody,
                released_at=at,
                released_by=actor.actor_id,
            )
            assert released.package_fingerprint == current.package_fingerprint
            self._packages[package_id] = released
            self.audit.append(
                actor.actor_id,
                AuditAction.HOLD_RELEASED,
                f"package:{package_id}",
                permission=Permission.RELEASE_HOLD,
                details={"note": note},
            )
            return released

    def export_package(
        self,
        actor: Actor,
        package_id: str,
        *,
        at: datetime | None = None,
    ) -> ExportBundle:
        self._require(actor, Permission.EXPORT, f"package:{package_id}")
        at = at or datetime.now(timezone.utc)
        with self._lock:
            package = self.package(package_id)
            payload = {
                "package": package,
                "receipts": [self._receipts[ref] for ref in package.refs],
            }
            data = canonical(payload)
            bundle = ExportBundle(
                package_id=package_id,
                package_fingerprint=package.package_fingerprint,
                exported_at=at,
                exported_by=actor.actor_id,
                data=data,
                export_fingerprint=fingerprint(
                    {
                        "type": "evidence_export",
                        "package_id": package_id,
                        "package_fingerprint": package.package_fingerprint,
                        "exported_at": at,
                        "exported_by": actor.actor_id,
                        "payload_sha256": "sha256:" + hashlib.sha256(data).hexdigest(),
                    }
                ),
            )
            self._exports.append(bundle)
            self.audit.append(
                actor.actor_id,
                AuditAction.PACKAGE_EXPORTED,
                f"package:{package_id}",
                permission=Permission.EXPORT,
                details={
                    "export_fingerprint": bundle.export_fingerprint,
                    "bytes": len(data),
                },
            )
            return bundle

    # ------------------------------------------------------------------ #
    # 查询
    # ------------------------------------------------------------------ #

    @staticmethod
    def verify_export(bundle: ExportBundle) -> None:
        """离线复核导出物：重算载荷摘要与导出指纹。"""

        expected = fingerprint(
            {
                "type": "evidence_export",
                "package_id": bundle.package_id,
                "package_fingerprint": bundle.package_fingerprint,
                "exported_at": bundle.exported_at,
                "exported_by": bundle.exported_by,
                "payload_sha256": "sha256:" + hashlib.sha256(bundle.data).hexdigest(),
            }
        )
        if expected != bundle.export_fingerprint:
            raise RuntimeError("导出指纹复核失败：导出物被篡改")

    def receipt_count(self) -> int:
        with self._lock:
            return len(self._receipts)
