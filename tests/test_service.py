import sys
import unittest
from datetime import timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parents[1] / "src"))
sys.path.insert(0, str(Path(__file__).parents[1]))

from incident_evidence.audit import (
    AuditAction,
    AuditChainBroken,
    AuditLog,
    AuthorizationError,
    Permission,
)
from incident_evidence.contracts import EvidenceRef, LifecycleStatus
from incident_evidence.service import (
    DuplicateEvidence,
    EvidenceError,
    PackageError,
    SealConflictError,
    EvidenceService,
)
from tests.fixtures import (
    COMMON_V1_MS,
    RSU,
    T0,
    VEH,
    actors,
    rules_v1,
    rules_v2,
    seed,
)


class ServiceTestBase(unittest.TestCase):
    def setUp(self) -> None:
        self.service = EvidenceService()
        self.actors = actors()
        self.coord = self.actors["coordinator"]
        self.analyst = self.actors["analyst"]
        self.auditor = self.actors["auditor"]
        self.custodian = self.actors["custodian"]
        self.receipts = seed(self.service, self.coord)


class ReceiveAndFingerprintTests(ServiceTestBase):
    def test_receipts_carry_batch_times_and_fingerprints(self):
        r = self.receipts["veh_brake"]
        self.assertEqual(r.version, 1)
        self.assertEqual(r.batch_id, "batch-20261001-01")
        self.assertTrue(r.receipt_fingerprint.startswith("sha256:"))
        self.assertTrue(r.content_fingerprint_value.startswith("sha256:"))
        # 原始时钟读数与来源时钟原样保留
        self.assertEqual(r.source_clock.clock_id, VEH)
        self.assertIsNotNone(r.collection_window)

    def test_duplicate_content_is_rejected_but_register_unchanged(self):
        original = self.receipts["veh_brake"]
        before = self.service.receipt_count()
        with self.assertRaises(DuplicateEvidence) as ctx:
            self.service.receive(
                self.coord,
                evidence_id="EV-VEH-99",  # 即便换一个新证据标识
                kind=original.kind,
                source_id=original.source_id,
                summary="重复接收同一份字节",
                source_clock=original.source_clock,
                source_time=original.source_time,
                content=b"vehicle-can: AEB brake request",
                batch_id="batch-late",
            )
        self.assertEqual(ctx.exception.existing, original.ref)
        self.assertEqual(self.service.receipt_count(), before)
        # 重复接收仍留审计（拒绝记录）
        denied = [
            e for e in self.service.audit.entries()
            if e.action == AuditAction.EVIDENCE_RECEIVED and not e.allowed
        ]
        self.assertEqual(len(denied), 1)

    def test_same_id_different_content_creates_related_version(self):
        original = self.receipts["veh_brake"]
        corrected = self.service.receive(
            self.coord,
            evidence_id="EV-VEH-01",
            kind=original.kind,
            source_id=original.source_id,
            summary="车端 CAN 日志：AEB 制动请求（厂商补传，修正时间戳）",
            source_clock=original.source_clock,
            source_time=original.source_time,
            content=b"vehicle-can: AEB brake request [re-exported v2]",
            batch_id="batch-20261002-02",
            supersedes=original.ref,
        )
        self.assertEqual(corrected.version, 2)
        self.assertEqual(corrected.supersedes, EvidenceRef("EV-VEH-01", 1))
        # 旧版本收据原样可取，指纹不变
        old = self.service.get_receipt(self.coord, original.ref)
        self.assertEqual(old.receipt_fingerprint, original.receipt_fingerprint)


class TimelineReportTests(ServiceTestBase):
    def _ids_on_axis(self, report):
        return [(e.evidence_id, e.version) for e in report.events]

    def test_timeline_uses_common_axis_and_keeps_raw_time(self):
        iv = self.service.create_investigation_version(self.coord, "初版报告")
        report = self.service.build_timeline_report(self.analyst, iv.number)
        ids = self._ids_on_axis(report)
        self.assertEqual(
            ids,
            [
                ("EV-VEH-01", 1),
                ("EV-CLOUD-01", 1),
                ("EV-RSU-01", 1),
                ("EV-VEH-02", 1),
                ("EV-WIT-01", 1),
            ],
        )
        by_id = {e.evidence_id: e for e in report.events}
        brake = by_id["EV-VEH-01"]
        self.assertEqual(brake.common_time, T0 + timedelta(milliseconds=COMMON_V1_MS["veh_brake"]))
        # 原始时间同时保留，且不等于统一时间
        self.assertNotEqual(brake.source_time, brake.common_time)
        self.assertIn("veh-ecu-clock", brake.explanation)
        self.assertIn("cal-v1", brake.rule_id)
        # 采集区间也映射到统一轴
        self.assertEqual(
            brake.window_common_end - brake.window_common_start,
            timedelta(seconds=10),
        )

    def test_report_is_verifiable_and_tamper_is_detected(self):
        iv = self.service.create_investigation_version(self.coord, "初版报告")
        report = self.service.build_timeline_report(self.analyst, iv.number)
        EvidenceService.verify_report(report)  # 不抛即通过

        tampered = type(report)(
            **{**report.__dict__, "label": "被篡改的标题"},
        )
        # 篡改内容后仍保留原指纹，模拟"改了内容但签名没换"
        object.__setattr__(tampered, "report_fingerprint", report.report_fingerprint)
        with self.assertRaises(RuntimeError):
            EvidenceService.verify_report(tampered)

    def test_calibration_change_does_not_change_existing_report(self):
        iv1 = self.service.create_investigation_version(self.coord, "基于粗校准")
        report1 = self.service.build_timeline_report(self.analyst, iv1.number)
        fp1 = report1.report_fingerprint
        rsu_pos_v1 = [e.evidence_id for e in report1.events].index("EV-RSU-01")

        # 后补精校准并创建新调查版本
        self.service.register_calibration(self.coord, rules_v2(), "厂商复核精校准")
        iv2 = self.service.create_investigation_version(self.coord, "基于精校准")
        report2 = self.service.build_timeline_report(self.analyst, iv2.number)

        # 旧报告逐字节不变（即使事件顺序在新报告中翻转）
        re_report1 = self.service.build_timeline_report(self.coord, iv1.number)
        self.assertEqual(re_report1.report_fingerprint, fp1)
        self.assertEqual(re_report1.calibration_version, 1)

        ids_v2 = [e.evidence_id for e in report2.events]
        self.assertLess(ids_v2.index("EV-VEH-02"), ids_v2.index("EV-RSU-01"))
        rsu = next(e for e in report2.events if e.evidence_id == "EV-RSU-01")
        self.assertEqual(rsu.common_time, T0 + timedelta(milliseconds=2_850))
        self.assertEqual(rsu.calibration_version, 2)
        # v1 中两者顺序相反
        impact_v1 = next(e for e in report1.events if e.evidence_id == "EV-VEH-02")
        rsu_v1 = next(e for e in report1.events if e.evidence_id == "EV-RSU-01")
        self.assertLess(rsu_v1.common_time, impact_v1.common_time)
        self.assertEqual(rsu_pos_v1, 2)

    def test_withdrawal_only_affects_later_versions(self):
        iv1 = self.service.create_investigation_version(self.coord, "撤回前版本")
        report_before = self.service.build_timeline_report(self.auditor, iv1.number)
        self.assertIn(
            ("EV-WIT-01", 1),
            [(e.evidence_id, e.version) for e in report_before.events],
        )

        self.service.withdraw(
            self.coord, EvidenceRef("EV-WIT-01", 1),
            reason="目击者事后翻供：其手表时间记忆有误，笔录撤回",
        )
        iv2 = self.service.create_investigation_version(self.coord, "撤回后版本")
        report_after = self.service.build_timeline_report(self.analyst, iv2.number)
        ids = [(e.evidence_id, e.version) for e in report_after.events]
        self.assertNotIn(("EV-WIT-01", 1), ids)
        excluded = {s.ref.evidence_id: s for s in report_after.excluded}
        self.assertEqual(excluded["EV-WIT-01"].status, LifecycleStatus.WITHDRAWN)
        self.assertIn("翻供", excluded["EV-WIT-01"].reason)

        # 撤回不删除：旧版本报告指纹不变、仍可复核
        old = self.service.build_timeline_report(self.coord, iv1.number)
        self.assertEqual(old.report_fingerprint, report_before.report_fingerprint)
        EvidenceService.verify_report(old)

    def test_superseded_version_excluded_but_chain_visible(self):
        original = self.receipts["rsu_detect"]
        self.service.receive(
            self.coord,
            evidence_id="EV-RSU-01",
            kind=original.kind,
            source_id=original.source_id,
            summary="路侧感知：行人进入横道（算法复核后置信度修正）",
            source_clock=original.source_clock,
            source_time=original.source_time + timedelta(milliseconds=4),
            content=b"rsu: pedestrian enters crosswalk [reviewed]",
            batch_id="batch-20261002-02",
            supersedes=original.ref,
        )
        iv = self.service.create_investigation_version(self.coord, "含更正")
        report = self.service.build_timeline_report(self.analyst, iv.number)
        active = [(e.evidence_id, e.version) for e in report.events]
        self.assertIn(("EV-RSU-01", 2), active)
        self.assertNotIn(("EV-RSU-01", 1), active)
        excluded = {s.ref: s for s in report.excluded}
        status = excluded[EvidenceRef("EV-RSU-01", 1)]
        self.assertEqual(status.status, LifecycleStatus.SUPERSEDED)
        self.assertEqual(status.superseded_by, EvidenceRef("EV-RSU-01", 2))

    def test_cannot_supersede_withdrawn_or_non_latest(self):
        first = self.receipts["rsu_detect"]
        second = self.service.receive(
            self.coord,
            evidence_id="EV-RSU-01", kind=first.kind, source_id=first.source_id,
            summary="更正一", source_clock=first.source_clock, source_time=first.source_time,
            content=b"rsu corrected 1", batch_id="b2", supersedes=first.ref,
        )
        with self.assertRaises(EvidenceError):
            self.service.receive(
                self.coord,
                evidence_id="EV-RSU-01", kind=first.kind, source_id=first.source_id,
                summary="跨过 v2 直接更正 v1", source_clock=first.source_clock,
                source_time=first.source_time,
                content=b"rsu corrected 2", batch_id="b3", supersedes=first.ref,
            )
        self.service.withdraw(self.coord, second.ref, reason="v2 也作废")
        with self.assertRaises(EvidenceError):
            self.service.receive(
                self.coord,
                evidence_id="EV-RSU-01", kind=first.kind, source_id=first.source_id,
                summary="在已撤回版本上继续更正", source_clock=first.source_clock,
                source_time=first.source_time,
                content=b"rsu corrected 3", batch_id="b4", supersedes=second.ref,
            )


class PackageTests(ServiceTestBase):
    def test_sealed_package_is_immutable_and_verifiable(self):
        refs = [r.ref for r in self.receipts.values()]
        package = self.service.seal_package(self.coord, "PKG-01", refs)
        EvidenceService.verify_package(package)
        # 重复签封同一标识被拒绝（并发签封语义见并发测试）
        with self.assertRaises(SealConflictError):
            self.service.seal_package(self.coord, "PKG-01", refs)
        # 撤回已签封的证据不影响证据包内容指纹
        self.service.withdraw(self.coord, EvidenceRef("EV-WIT-01", 1), reason="事后撤回")
        again = self.service.package("PKG-01")
        self.assertEqual(again.package_fingerprint, package.package_fingerprint)
        self.assertEqual(again.refs, package.refs)
        EvidenceService.verify_package(again)

    def test_withdrawn_evidence_cannot_be_sealed(self):
        self.service.withdraw(self.coord, EvidenceRef("EV-WIT-01", 1), reason="作废")
        with self.assertRaises(PackageError):
            self.service.seal_package(
                self.coord, "PKG-X", [r.ref for r in self.receipts.values()]
            )

    def test_transfer_and_release_chain(self):
        package = self.service.seal_package(
            self.coord, "PKG-02", [self.receipts["veh_impact"].ref]
        )
        # 非保管人不能移交
        other_coord = self.actors["custodian"]
        with self.assertRaises(PackageError):
            self.service.transfer_package(other_coord, "PKG-02", "evidence-locker-2")
        moved = self.service.transfer_package(
            self.coord, "PKG-02", other_coord.actor_id, note="移交证物库"
        )
        self.assertEqual(moved.custodian, other_coord.actor_id)
        self.assertEqual(len(moved.custody), 2)
        # 移交不改签封指纹
        self.assertEqual(moved.package_fingerprint, package.package_fingerprint)

        # coordinator 无解除保全权限；custodian 可以
        with self.assertRaises(AuthorizationError):
            self.service.release_hold(self.coord, "PKG-02")
        released = self.service.release_hold(other_coord, "PKG-02", note="调查结束依法解除")
        self.assertEqual(released.status.value, "released")
        self.assertEqual(released.package_fingerprint, package.package_fingerprint)
        with self.assertRaises(PackageError):
            self.service.release_hold(other_coord, "PKG-02")

    def test_export_bundle_roundtrip_verification(self):
        package = self.service.seal_package(
            self.coord, "PKG-03", [self.receipts["veh_brake"].ref]
        )
        bundle = self.service.export_package(self.auditor, "PKG-03")
        self.assertEqual(bundle.package_fingerprint, package.package_fingerprint)
        EvidenceService.verify_export(bundle)
        # 载荷中携带完整收据（原始时间、内容与收据指纹）
        self.assertIn(b"EV-VEH-01", bundle.data)
        self.assertIn(
            self.receipts["veh_brake"].receipt_fingerprint.encode(),
            bundle.data,
        )

        tampered = type(bundle)(
            **{**bundle.__dict__, "data": bundle.data + b" "}
        )
        with self.assertRaises(RuntimeError):
            EvidenceService.verify_export(tampered)


class AuthorizationAndAuditTests(ServiceTestBase):
    def test_roles_are_enforced_and_denials_are_audited(self):
        # analyst 不能签封 / 不能解除保全
        with self.assertRaises(AuthorizationError):
            self.service.seal_package(
                self.analyst, "PKG-DENY", [self.receipts["veh_brake"].ref]
            )
        with self.assertRaises(AuthorizationError):
            self.service.release_hold(self.auditor, "whatever")
        denied = [e for e in self.service.audit.entries() if not e.allowed]
        self.assertTrue(any(e.permission == Permission.SEAL for e in denied))
        self.assertTrue(any(e.permission == Permission.RELEASE_HOLD for e in denied))

    def test_every_sensitive_action_has_audit_trail(self):
        iv = self.service.create_investigation_version(self.coord, "初版")
        self.service.build_timeline_report(self.auditor, iv.number)
        self.service.get_receipt(self.analyst, self.receipts["veh_brake"].ref)
        package = self.service.seal_package(
            self.coord, "PKG-A", [self.receipts["veh_brake"].ref]
        )
        self.service.export_package(self.auditor, "PKG-A")
        self.service.transfer_package(self.coord, "PKG-A", self.custodian.actor_id)
        self.service.release_hold(self.custodian, "PKG-A")

        actions = {e.action for e in self.service.audit.entries()}
        for expected in (
            AuditAction.EVIDENCE_RECEIVED,
            AuditAction.EVIDENCE_ACCESSED,
            AuditAction.CALIBRATION_REGISTERED,
            AuditAction.INVESTIGATION_VERSION_CREATED,
            AuditAction.PACKAGE_SEALED,
            AuditAction.PACKAGE_EXPORTED,
            AuditAction.PACKAGE_TRANSFERRED,
            AuditAction.HOLD_RELEASED,
        ):
            self.assertIn(expected, actions)
        # 谁查看过：view 动作带操作者
        views = [
            e for e in self.service.audit.entries()
            if e.action == AuditAction.EVIDENCE_ACCESSED
        ]
        viewers = {e.actor_id for e in views}
        self.assertIn(self.auditor.actor_id, viewers)
        self.assertIn(self.analyst.actor_id, viewers)
        # package 变量在断言中使用以固定签封时间语义
        self.assertTrue(package.package_fingerprint.startswith("sha256:"))

    def test_audit_chain_detects_tampering(self):
        self.service.create_investigation_version(self.coord, "初版")
        self.service.audit.verify()  # 正常链通过

        log: AuditLog = self.service.audit
        # 直接篡改内部存储模拟事后删改
        original = log._entries[0]
        forged = type(original)(**{**original.__dict__, "actor_id": "intruder"})
        # __init__ 重算指纹；同时把后续 prev 链保持不变 -> 必在某处断裂
        log._entries[0] = forged
        with self.assertRaises(AuditChainBroken):
            log.verify()


class BatchTests(ServiceTestBase):
    def test_batch_record_fingerprints_membership(self):
        batch = self.service.batch("batch-20261001-01")
        self.assertEqual(len(batch.refs), 5)
        self.assertTrue(batch.fingerprint_value.startswith("sha256:"))
        # 同一批次重复计算指纹稳定
        self.assertEqual(self.service.batch("batch-20261001-01").fingerprint_value,
                         batch.fingerprint_value)


if __name__ == "__main__":
    unittest.main()
