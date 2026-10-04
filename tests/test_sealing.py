"""签封：不可改写、版本链、幂等、解除保全后的写禁止。"""

import dataclasses
import unittest

from support import (
    COORDINATOR,
    INVESTIGATION,
    EvidenceKind,
    make_service,
    publish_default_profile,
    register_standard_evidence,
    submission,
)
from incident_evidence.errors import HoldReleasedError, InvalidStateError


class SealingTests(unittest.TestCase):
    def setUp(self):
        self.service = make_service()
        publish_default_profile(self.service)
        register_standard_evidence(self.service)

    def test_seal_creates_version_one_with_sorted_entries(self):
        package = self.service.seal_package(COORDINATOR, INVESTIGATION)
        self.assertEqual(package.version, 1)
        self.assertIsNone(package.supersedes)
        self.assertEqual(package.calibration_profile, "cal-main@1")
        ids = [e.evidence_id for e in package.entries]
        self.assertEqual(ids, sorted(ids))
        self.assertEqual(len(package.seal_hash), 64)

    def test_sealed_package_is_frozen(self):
        package = self.service.seal_package(COORDINATOR, INVESTIGATION)
        with self.assertRaises(dataclasses.FrozenInstanceError):
            package.seal_hash = "tampered"  # type: ignore[misc]

    def test_store_rejects_duplicate_version(self):
        package = self.service.seal_package(COORDINATOR, INVESTIGATION)
        with self.assertRaises(InvalidStateError):
            self.service._store.append_package(package)

    def test_identical_reseal_is_idempotent(self):
        first = self.service.seal_package(COORDINATOR, INVESTIGATION)
        second = self.service.seal_package(COORDINATOR, INVESTIGATION)
        self.assertEqual(first.seal_hash, second.seal_hash)
        self.assertEqual(len(self.service.list_packages(COORDINATOR, INVESTIGATION)), 1)

    def test_correction_leads_to_linked_new_version(self):
        v1 = self.service.seal_package(COORDINATOR, INVESTIGATION)
        # 更正车端日志（新指纹 -> 新修订）
        sub = submission("EV-VEH", EvidenceKind.VEHICLE_LOG, "vehicle-7", "veh-clock",
                         "车端日志（更正：补全碰撞后 5 秒）",
                         [], fingerprint="sha256:EV-VEH-v2", batch_id="BATCH-2")
        self.service.register_evidence(COORDINATOR, sub)
        v2 = self.service.seal_package(COORDINATOR, INVESTIGATION)
        self.assertEqual(v2.version, 2)
        self.assertEqual(v2.supersedes, v1.seal_hash)
        # v2 锁定的是修订 2，v1 仍锁定修订 1
        entry_v2 = next(e for e in v2.entries if e.evidence_id == "EV-VEH")
        entry_v1 = next(e for e in v1.entries if e.evidence_id == "EV-VEH")
        self.assertEqual(entry_v2.revision, 2)
        self.assertEqual(entry_v1.revision, 1)
        self.assertNotEqual(entry_v2.record_hash, entry_v1.record_hash)

    def test_seal_empty_investigation_rejected(self):
        with self.assertRaises(InvalidStateError):
            self.service.seal_package(COORDINATOR, "INV-EMPTY")

    def test_release_hold_blocks_writes_but_keeps_reads(self):
        self.service.seal_package(COORDINATOR, INVESTIGATION)
        self.service.release_hold(COORDINATOR, INVESTIGATION, "调查结案")
        with self.assertRaises(HoldReleasedError):
            self.service.seal_package(COORDINATOR, INVESTIGATION)
        with self.assertRaises(HoldReleasedError):
            self.service.register_evidence(COORDINATOR, submission(
                "EV-NEW", EvidenceKind.VEHICLE_LOG, "v", "veh-clock", "新材料", []))
        with self.assertRaises(HoldReleasedError):
            self.service.withdraw_evidence(COORDINATOR, INVESTIGATION, "EV-VEH", "x")
        # 读与验证仍然可用
        report = self.service.generate_timeline(COORDINATOR, INVESTIGATION, 1)
        self.assertTrue(self.service.verify_report(report).ok)
        # 重复解除保全报错
        with self.assertRaises(InvalidStateError):
            self.service.release_hold(COORDINATOR, INVESTIGATION, "再次解除")


if __name__ == "__main__":
    unittest.main()
