"""事故证据封存与时间线服务（对外 API）。

职责：
- 登记接收：来源、摘要、采集区间、接收批次、完整性指纹；重复接收幂等，
  内容变更只能以“更正修订”形成关联版本；
- 时钟校准：校准档案不可变、按版本发布，签封时钉死版本，映射可解释；
- 签封：证据包一经签封不得改写，补充/更正/撤回形成关联版本；
- 保全：访问、导出、移交、解除保全均需权限并写入哈希链审计日志；
- 时间线：按调查版本生成可重放、可验证的时间线与证据清单。

所有写操作在单把可重入锁内串行化，并发签封只会产生唯一、连续的版本链。
"""

import threading
from dataclasses import replace
from datetime import datetime, timezone
from typing import Callable, Iterable

from .access import AccessPolicy
from .audit import AuditLog
from .contracts import (
    AuditEntry,
    CalibrationProfile,
    CheckResult,
    ClockCalibrationRule,
    CustodyRecord,
    EvidenceItem,
    EvidencePackage,
    EvidenceRecord,
    EvidenceStatus,
    EvidenceSubmission,
    ExportBundle,
    PackageEntry,
    Permission,
    ReceivingBatch,
    RegistrationResult,
    TimelineReport,
    VerificationResult,
    WithdrawalRecord,
)
from .errors import (
    CalibrationGapError,
    HoldReleasedError,
    InvalidStateError,
    NotFoundError,
    PermissionDeniedError,
    ValidationError,
)
from .hashing import content_hash
from .store import EvidenceStore
from .timeline import build_timeline

_RECORD_HASH_EXCLUDE = frozenset({"record_hash", "status"})
_SEAL_HASH_EXCLUDE = frozenset({"seal_hash"})
_REPORT_HASH_EXCLUDE = frozenset({"report_hash", "generated_by", "generated_at"})
_BUNDLE_HASH_EXCLUDE = frozenset({"bundle_hash", "exported_by", "exported_at"})

DEFAULT_CUSTODIAN = "evidence-office"


class EvidenceService:
    def __init__(
        self,
        *,
        grants: dict[str, Iterable[Permission]] | None = None,
        now_fn: Callable[[], datetime] | None = None,
    ) -> None:
        self._store = EvidenceStore()
        self._audit = AuditLog()
        self._policy = AccessPolicy(grants)
        self._now_fn = now_fn or (lambda: datetime.now(timezone.utc))
        self._lock = threading.RLock()

    # ------------------------------------------------------------------
    # 内部工具
    # ------------------------------------------------------------------

    def _now(self) -> datetime:
        return _require_aware(self._now_fn(), "服务时钟").astimezone(timezone.utc)

    def _log(self, actor: str, action: str, target: str, outcome: str, detail: str) -> AuditEntry:
        return self._audit.append(
            timestamp=self._now(),
            actor=actor,
            action=action,
            target=target,
            outcome=outcome,
            detail=detail,
        )

    def _require(self, actor: str, permission: Permission, action: str, target: str) -> None:
        if not self._policy.check(actor, permission):
            self._log(actor, action, target, "denied", f"缺少权限 {permission.value}")
            raise PermissionDeniedError(f"主体 {actor!r} 缺少权限 {permission.value}")

    def _require_hold_active(self, investigation_id: str) -> None:
        if self._store.holds.get(investigation_id, "active") == "released":
            raise HoldReleasedError(f"调查 {investigation_id} 的保全已解除，禁止写入")

    # ------------------------------------------------------------------
    # 授权
    # ------------------------------------------------------------------

    def grant(self, actor: str, target_actor: str, *permissions: Permission) -> None:
        with self._lock:
            self._require(actor, Permission.ADMIN, "grant_permission", target_actor)
            self._policy.grant(target_actor, *permissions)
            granted = ",".join(sorted(p.value for p in permissions))
            self._log(actor, "grant_permission", target_actor, "success", granted)

    # ------------------------------------------------------------------
    # 登记接收
    # ------------------------------------------------------------------

    def register_evidence(self, actor: str, submission: EvidenceSubmission) -> RegistrationResult:
        with self._lock:
            self._require(actor, Permission.EVIDENCE_REGISTER, "register_evidence",
                          f"{submission.investigation_id}/{submission.evidence_id}")
            self._require_hold_active(submission.investigation_id)
            self._validate_submission(submission)

            received_at = submission.received_at or self._now()
            batch = self._ensure_batch(actor, submission, received_at)
            key = (submission.investigation_id, submission.evidence_id)
            existing_hashes = self._store.revision_hashes(*key)

            # 重复接收：同一证据号 + 同一指纹 -> 幂等返回，不产生新记录
            for record_hash in existing_hashes:
                existing = self._store.records[record_hash]
                if existing.item.integrity_fingerprint == submission.integrity_fingerprint:
                    self._log(actor, "register_evidence",
                              f"{submission.investigation_id}/{submission.evidence_id}",
                              "duplicate",
                              f"指纹与修订 {existing.revision} 一致，按重复接收处理；批次 {submission.batch_id}")
                    return RegistrationResult(existing, "duplicate", batch)

            if existing_hashes:
                latest = self._store.records[existing_hashes[-1]]
                if latest.status == EvidenceStatus.WITHDRAWN:
                    raise InvalidStateError(
                        f"证据 {submission.evidence_id} 已撤回，如需重新提交请使用新的证据编号"
                    )
                revision = latest.revision + 1
                supersedes = latest.record_hash
                outcome = "correction"
            else:
                latest = None
                revision = 1
                supersedes = None
                outcome = "registered"

            record = self._build_record(submission, received_at, revision, supersedes)
            self._store.put_record(record)
            if latest is not None:
                self._store.update_record(replace(latest, status=EvidenceStatus.SUPERSEDED))

            self._log(actor, "register_evidence",
                      f"{submission.investigation_id}/{submission.evidence_id}",
                      "success" if outcome == "registered" else outcome,
                      f"修订 {revision} record_hash={record.record_hash[:16]}… 批次 {batch.batch_id}")
            return RegistrationResult(record, outcome, batch)

    def _validate_submission(self, sub: EvidenceSubmission) -> None:
        for field_name, value in (
            ("investigation_id", sub.investigation_id),
            ("evidence_id", sub.evidence_id),
            ("source_id", sub.source_id),
            ("digest", sub.digest),
            ("batch_id", sub.batch_id),
        ):
            if not str(value).strip():
                raise ValidationError(f"{field_name} 不能为空")
        if not sub.integrity_fingerprint.strip():
            raise ValidationError("完整性指纹不能为空")
        start = _require_aware(sub.collected_start, "collected_start")
        end = _require_aware(sub.collected_end, "collected_end")
        if end < start:
            raise ValidationError("采集区间终点早于起点")
        if sub.received_at is not None:
            _require_aware(sub.received_at, "received_at")
        for event in sub.events:
            if not event.event_id.strip() or not event.label.strip():
                raise ValidationError("事件的 event_id 与 label 不能为空")
            _require_aware(event.source_time, f"事件 {event.event_id} 的 source_time")

    def _ensure_batch(
        self, actor: str, sub: EvidenceSubmission, received_at: datetime
    ) -> ReceivingBatch:
        batch = self._store.batches.get(sub.batch_id)
        if batch is None:
            batch = ReceivingBatch(
                batch_id=sub.batch_id,
                investigation_id=sub.investigation_id,
                received_by=actor,
                received_at=received_at,
                transport=sub.transport,
            )
            self._store.batches[sub.batch_id] = batch
        return batch

    def _build_record(
        self,
        sub: EvidenceSubmission,
        received_at: datetime,
        revision: int,
        supersedes: str | None,
    ) -> EvidenceRecord:
        item = EvidenceItem(
            evidence_id=sub.evidence_id,
            kind=sub.kind,
            source_id=sub.source_id,
            source_time=_require_aware(sub.collected_start, "collected_start"),
            source_clock=sub.clock,
            integrity_fingerprint=sub.integrity_fingerprint,
        )
        draft = EvidenceRecord(
            item=item,
            investigation_id=sub.investigation_id,
            digest=sub.digest,
            collected_end=_require_aware(sub.collected_end, "collected_end"),
            batch_id=sub.batch_id,
            transport=sub.transport,
            received_at=received_at,
            events=tuple(sub.events),
            revision=revision,
            supersedes=supersedes,
            status=EvidenceStatus.ACTIVE,
            record_hash="",
        )
        return replace(draft, record_hash=content_hash(draft, exclude=_RECORD_HASH_EXCLUDE))

    # ------------------------------------------------------------------
    # 时钟校准档案
    # ------------------------------------------------------------------

    def publish_calibration_profile(
        self,
        actor: str,
        profile_id: str,
        rules: Iterable[ClockCalibrationRule],
        note: str = "",
    ) -> CalibrationProfile:
        with self._lock:
            self._require(actor, Permission.CALIBRATION_MANAGE, "publish_calibration", profile_id)
            rules = tuple(rules)
            if not rules:
                raise ValidationError("校准档案至少需要一条规则")
            clock_ids = [rule.clock_id for rule in rules]
            if len(set(clock_ids)) != len(clock_ids):
                raise ValidationError("校准规则中存在重复的 clock_id")
            for rule in rules:
                _require_aware(rule.measured_at, f"规则 {rule.clock_id} 的 measured_at")

            versions = self._store.profiles.get(profile_id, {})
            profile = CalibrationProfile(
                profile_id=profile_id,
                version=max(versions, default=0) + 1,
                rules=rules,
                note=note,
                created_at=self._now(),
            )
            self._store.put_profile(profile)
            self._log(actor, "publish_calibration", profile_id, "success",
                      f"{profile.ref} 规则数={len(rules)}")
            return profile

    def _resolve_profile(self, profile_id: str | None) -> CalibrationProfile:
        if profile_id is None:
            if not self._store.profiles:
                raise CalibrationGapError("尚未发布任何时钟校准档案")
            if len(self._store.profiles) > 1:
                raise ValidationError("存在多份校准档案，请显式指定 profile_id")
            profile_id = next(iter(self._store.profiles))
        versions = self._store.profiles.get(profile_id)
        if not versions:
            raise NotFoundError(f"校准档案不存在: {profile_id}")
        return versions[max(versions)]

    def _profile_by_ref(self, ref: str) -> CalibrationProfile:
        profile_id, _, version_text = ref.rpartition("@")
        try:
            return self._store.profiles[profile_id][int(version_text)]
        except (KeyError, ValueError):
            raise NotFoundError(f"校准档案不存在: {ref}") from None

    # ------------------------------------------------------------------
    # 签封与撤回
    # ------------------------------------------------------------------

    def _active_entries(self, investigation_id: str) -> tuple[PackageEntry, ...]:
        entries = []
        for evidence_id in self._store.evidence_ids(investigation_id):
            hashes = self._store.revision_hashes(investigation_id, evidence_id)
            latest = self._store.records[hashes[-1]]
            if latest.status == EvidenceStatus.ACTIVE:
                entries.append(PackageEntry(
                    evidence_id=evidence_id,
                    revision=latest.revision,
                    record_hash=latest.record_hash,
                    integrity_fingerprint=latest.item.integrity_fingerprint,
                ))
        return tuple(entries)  # evidence_ids 已排序，条目顺序确定

    def seal_package(
        self,
        actor: str,
        investigation_id: str,
        *,
        profile_id: str | None = None,
        note: str = "",
    ) -> EvidencePackage:
        with self._lock:
            self._require(actor, Permission.PACKAGE_SEAL, "seal_package", investigation_id)
            self._require_hold_active(investigation_id)
            entries = self._active_entries(investigation_id)
            if not entries:
                raise InvalidStateError(f"调查 {investigation_id} 没有可签封的有效证据")
            profile = self._resolve_profile(profile_id)
            self._check_clock_coverage(profile, entries)

            versions = self._store.packages.get(investigation_id, [])
            if versions:
                last = versions[-1]
                if last.entries == entries and last.calibration_profile == profile.ref:
                    self._log(actor, "seal_package", investigation_id, "duplicate",
                              f"内容与版本 {last.version} 一致，幂等返回 {last.seal_hash[:16]}…")
                    return last

            package = self._create_package(
                actor, investigation_id, entries, profile.ref, withdrawals=(), note=note
            )
            self._log(actor, "seal_package", investigation_id, "success",
                      f"版本 {package.version} seal_hash={package.seal_hash[:16]}… "
                      f"证据数={len(entries)} 校准={profile.ref}")
            return package

    def _check_clock_coverage(
        self, profile: CalibrationProfile, entries: tuple[PackageEntry, ...]
    ) -> None:
        missing = []
        for entry in entries:
            clock_id = self._store.records[entry.record_hash].item.source_clock.clock_id
            if profile.rule_for(clock_id) is None:
                missing.append(f"{entry.evidence_id}({clock_id})")
        if missing:
            raise CalibrationGapError(
                f"校准档案 {profile.ref} 缺少时钟规则: {', '.join(missing)}"
            )

    def _create_package(
        self,
        actor: str,
        investigation_id: str,
        entries: tuple[PackageEntry, ...],
        profile_ref: str,
        *,
        withdrawals: tuple[WithdrawalRecord, ...],
        note: str,
    ) -> EvidencePackage:
        versions = self._store.packages.get(investigation_id, [])
        draft = EvidencePackage(
            investigation_id=investigation_id,
            version=len(versions) + 1,
            entries=entries,
            calibration_profile=profile_ref,
            supersedes=versions[-1].seal_hash if versions else None,
            withdrawals=withdrawals,
            sealed_by=actor,
            sealed_at=self._now(),
            note=note,
            seal_hash="",
        )
        package = replace(draft, seal_hash=content_hash(draft, exclude=_SEAL_HASH_EXCLUDE))
        self._store.append_package(package)
        return package

    def withdraw_evidence(
        self, actor: str, investigation_id: str, evidence_id: str, reason: str
    ) -> EvidencePackage | None:
        """撤回证据：标记全部修订为已撤回；若已有签封包，自动形成关联版本。"""
        with self._lock:
            self._require(actor, Permission.EVIDENCE_WITHDRAW, "withdraw_evidence",
                          f"{investigation_id}/{evidence_id}")
            self._require_hold_active(investigation_id)
            hashes = self._store.revision_hashes(investigation_id, evidence_id)
            if not hashes:
                raise NotFoundError(f"证据不存在: {investigation_id}/{evidence_id}")
            latest = self._store.records[hashes[-1]]
            if latest.status == EvidenceStatus.WITHDRAWN:
                raise InvalidStateError(f"证据 {evidence_id} 已撤回")

            for record_hash in hashes:
                record = self._store.records[record_hash]
                self._store.update_record(replace(record, status=EvidenceStatus.WITHDRAWN))

            withdrawal = WithdrawalRecord(
                evidence_id=evidence_id,
                reason=reason,
                withdrawn_by=actor,
                withdrawn_at=self._now(),
            )
            versions = self._store.packages.get(investigation_id, [])
            if not versions:
                self._log(actor, "withdraw_evidence", f"{investigation_id}/{evidence_id}",
                          "success", "尚无签封包，仅标记撤回")
                return None

            entries = self._active_entries(investigation_id)
            package = self._create_package(
                actor, investigation_id, entries, versions[-1].calibration_profile,
                withdrawals=(withdrawal,), note=f"撤回 {evidence_id}: {reason}",
            )
            self._log(actor, "withdraw_evidence", f"{investigation_id}/{evidence_id}",
                      "success",
                      f"已撤回并形成关联版本 {package.version} seal_hash={package.seal_hash[:16]}…")
            return package

    # ------------------------------------------------------------------
    # 时间线与验证
    # ------------------------------------------------------------------

    def generate_timeline(
        self, actor: str, investigation_id: str, version: int | None = None
    ) -> TimelineReport:
        with self._lock:
            self._require(actor, Permission.EVIDENCE_VIEW, "generate_timeline", investigation_id)
            report = self._build_report(investigation_id, version, generated_by=actor)
            self._log(actor, "generate_timeline", investigation_id, "success",
                      f"版本 {report.package_version} report_hash={report.report_hash[:16]}…")
            return report

    def _build_report(
        self, investigation_id: str, version: int | None, *, generated_by: str
    ) -> TimelineReport:
        package = self._get_package(investigation_id, version)
        profile = self._profile_by_ref(package.calibration_profile)
        records = {e.record_hash: self._store.records[e.record_hash] for e in package.entries}
        events, manifest = build_timeline(package, records, profile)
        draft = TimelineReport(
            investigation_id=investigation_id,
            package_version=package.version,
            seal_hash=package.seal_hash,
            calibration_profile=package.calibration_profile,
            events=events,
            evidence_manifest=manifest,
            report_hash="",
            generated_by=generated_by,
            generated_at=self._now(),
        )
        return replace(draft, report_hash=content_hash(draft, exclude=_REPORT_HASH_EXCLUDE))

    def verify_report(
        self, report: TimelineReport, actor: str = "external-verifier"
    ) -> VerificationResult:
        """验证既有报告：自洽性、签封完整性、可重放性、审计链。无需权限。"""
        with self._lock:
            checks: list[CheckResult] = []

            recomputed = content_hash(report, exclude=_REPORT_HASH_EXCLUDE)
            checks.append(CheckResult(
                "report_hash_self_consistent",
                recomputed == report.report_hash,
                "报告哈希与内容自洽" if recomputed == report.report_hash else "报告内容被改动",
            ))

            try:
                package = self._get_package(report.investigation_id, report.package_version)
                seal_ok = (
                    package.seal_hash == report.seal_hash
                    and content_hash(package, exclude=_SEAL_HASH_EXCLUDE) == package.seal_hash
                )
                seal_detail = "签封哈希匹配且未被改写"
            except NotFoundError as exc:
                seal_ok = False
                seal_detail = str(exc)
            checks.append(CheckResult("seal_intact", seal_ok, seal_detail))

            try:
                rebuilt = self._build_report(
                    report.investigation_id, report.package_version, generated_by=actor
                )
                replay_ok = (
                    rebuilt.events == report.events
                    and rebuilt.evidence_manifest == report.evidence_manifest
                    and rebuilt.report_hash == report.report_hash
                )
                replay_detail = "按钉死的校准档案重放结果一致"
            except (NotFoundError, CalibrationGapError, KeyError) as exc:
                replay_ok = False
                replay_detail = f"重放失败: {exc}"
            checks.append(CheckResult("timeline_replay", replay_ok, replay_detail))

            chain_ok = self._audit.verify_chain()
            checks.append(CheckResult(
                "audit_chain_intact", chain_ok,
                "审计哈希链完整" if chain_ok else "审计日志被篡改",
            ))

            ok = all(check.passed for check in checks)
            self._log(actor, "verify_report", report.investigation_id,
                      "success" if ok else "failed",
                      f"版本 {report.package_version} 验证{'通过' if ok else '未通过'}")
            return VerificationResult(ok, tuple(checks))

    # ------------------------------------------------------------------
    # 导出、移交、解除保全
    # ------------------------------------------------------------------

    def export_package(
        self, actor: str, investigation_id: str, version: int | None = None
    ) -> ExportBundle:
        with self._lock:
            self._require(actor, Permission.PACKAGE_EXPORT, "export_package", investigation_id)
            package = self._get_package(investigation_id, version)
            profile = self._profile_by_ref(package.calibration_profile)
            records = tuple(self._store.records[e.record_hash] for e in package.entries)
            draft = ExportBundle(
                investigation_id=investigation_id,
                package_version=package.version,
                package=package,
                records=records,
                profile=profile,
                bundle_hash="",
                exported_by=actor,
                exported_at=self._now(),
            )
            bundle = replace(draft, bundle_hash=content_hash(draft, exclude=_BUNDLE_HASH_EXCLUDE))
            self._log(actor, "export_package", investigation_id, "success",
                      f"版本 {package.version} bundle_hash={bundle.bundle_hash[:16]}…")
            return bundle

    def transfer_custody(
        self, actor: str, investigation_id: str, to_custodian: str, note: str = ""
    ) -> CustodyRecord:
        with self._lock:
            self._require(actor, Permission.CUSTODY_TRANSFER, "transfer_custody", investigation_id)
            if not to_custodian.strip():
                raise ValidationError("接收方保管人不能为空")
            record = CustodyRecord(
                investigation_id=investigation_id,
                from_custodian=self.current_custodian(investigation_id),
                to_custodian=to_custodian,
                transferred_by=actor,
                transferred_at=self._now(),
                note=note,
            )
            self._store.append_custody(record)
            self._log(actor, "transfer_custody", investigation_id, "success",
                      f"{record.from_custodian} -> {to_custodian}")
            return record

    def current_custodian(self, investigation_id: str) -> str:
        history = self._store.custody.get(investigation_id, [])
        return history[-1].to_custodian if history else DEFAULT_CUSTODIAN

    def release_hold(self, actor: str, investigation_id: str, reason: str) -> None:
        with self._lock:
            self._require(actor, Permission.HOLD_RELEASE, "release_hold", investigation_id)
            if self._store.holds.get(investigation_id) == "released":
                raise InvalidStateError(f"调查 {investigation_id} 的保全已解除")
            self._store.holds[investigation_id] = "released"
            self._log(actor, "release_hold", investigation_id, "success", reason)

    # ------------------------------------------------------------------
    # 只读查询
    # ------------------------------------------------------------------

    def get_package(self, actor: str, investigation_id: str, version: int | None = None) -> EvidencePackage:
        with self._lock:
            self._require(actor, Permission.EVIDENCE_VIEW, "get_package", investigation_id)
            return self._get_package(investigation_id, version)

    def _get_package(self, investigation_id: str, version: int | None) -> EvidencePackage:
        versions = self._store.packages.get(investigation_id, [])
        if not versions:
            raise NotFoundError(f"调查 {investigation_id} 尚无签封包")
        if version is None:
            return versions[-1]
        for package in versions:
            if package.version == version:
                return package
        raise NotFoundError(f"调查 {investigation_id} 不存在版本 {version} 的签封包")

    def list_packages(self, actor: str, investigation_id: str) -> tuple[EvidencePackage, ...]:
        with self._lock:
            self._require(actor, Permission.EVIDENCE_VIEW, "list_packages", investigation_id)
            return tuple(self._store.packages.get(investigation_id, []))

    def get_record(self, actor: str, record_hash: str) -> EvidenceRecord:
        with self._lock:
            self._require(actor, Permission.EVIDENCE_VIEW, "get_record", record_hash[:16])
            try:
                return self._store.records[record_hash]
            except KeyError:
                raise NotFoundError(f"记录不存在: {record_hash}") from None

    def audit_trail(self, actor: str, investigation_id: str | None = None) -> tuple[AuditEntry, ...]:
        with self._lock:
            self._require(actor, Permission.AUDIT_VIEW, "audit_trail",
                          investigation_id or "*")
            entries = self._audit.entries()
            if investigation_id is None:
                return entries
            prefix = investigation_id + "/"
            return tuple(
                e for e in entries
                if e.target == investigation_id or e.target.startswith(prefix)
            )

    def audit_chain_intact(self) -> bool:
        with self._lock:
            return self._audit.verify_chain()


def _require_aware(value: datetime, field: str) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValidationError(f"{field} 必须为带时区时间")
    return value
