"""登记接收：字段落库、校验、重复接收幂等、更正形成修订链。"""

import unittest
from dataclasses import replace
from datetime import datetime, timedelta

from support import (
    COORDINATOR,
    INVESTIGATION,
    UTC,
    COLLISION,
    EvidenceKind,
    EvidenceSubmission,
    SourceClock,
    SourceEvent,
    make_service,
    publish_default_profile,
    submission,
)


class RegistrationTests(unittest.TestCase):
    def setUp(self):
        self.service = make_service()

    def test_register_stores_full_metadata(self):
        result = self.service.register_evidence(
            COORDINATOR, submission("EV-1", EvidenceKind.VEHICLE_LOG, "vehicle-7", "veh-clock",
                                    "车端日志", [("e1", "碰撞检测", COLLISION)]))
        record = result.record
        self.assertEqual(result.outcome, "registered")
        self.assertEqual(record.digest, "车端日志")
        self.assertEqual(record.batch_id, "BATCH-1")
        self.assertEqual(record.revision, 1)
        self.assertEqual(record.status, "active")
        self.assertEqual(record.collected_start, COLLISION - timedelta(seconds=30))
        self.assertEqual(record.collected_end, COLLISION + timedelta(seconds=30))
        self.assertEqual(len(record.record_hash), 64)
        # 接收批次已登记
        batch = self.service._store.batches["BATCH-1"]
        self.assertEqual(batch.investigation_id, INVESTIGATION)
        self.assertEqual(batch.received_by, COORDINATOR)

    def test_record_hash_is_stable_and_content_based(self):
        first = self.service.register_evidence(
            COORDINATOR, submission("EV-1", EvidenceKind.VEHICLE_LOG, "v", "veh-clock", "摘要", []))
        again = self.service.register_evidence(
            COORDINATOR, submission("EV-1", EvidenceKind.VEHICLE_LOG, "v", "veh-clock", "摘要", []))
        self.assertEqual(first.record.record_hash, again.record.record_hash)

    def test_duplicate_receipt_is_idempotent(self):
        sub = submission("EV-1", EvidenceKind.VEHICLE_LOG, "v", "veh-clock", "摘要", [])
        first = self.service.register_evidence(COORDINATOR, sub)
        # 同一材料换个批次再次送达
        second = self.service.register_evidence(
            COORDINATOR, replace(sub, batch_id="BATCH-2"))
        self.assertEqual(second.outcome, "duplicate")
        self.assertEqual(second.record.record_hash, first.record.record_hash)
        self.assertEqual(len(self.service._store.records), 1)
        # 审计中留下重复接收痕迹
        actions = [(e.action, e.outcome) for e in self.service.audit_trail(COORDINATOR)]
        self.assertIn(("register_evidence", "duplicate"), actions)

    def test_correction_creates_linked_revision(self):
        sub = submission("EV-1", EvidenceKind.VEHICLE_LOG, "v", "veh-clock", "原始摘要", [])
        first = self.service.register_evidence(COORDINATOR, sub)
        corrected = self.service.register_evidence(
            COORDINATOR, replace(sub, digest="更正摘要", integrity_fingerprint="sha256:EV-1-v2"))
        self.assertEqual(corrected.outcome, "correction")
        self.assertEqual(corrected.record.revision, 2)
        self.assertEqual(corrected.record.supersedes, first.record.record_hash)
        # 旧修订被标记为已取代，但仍可按哈希取回（历史不丢）
        old = self.service.get_record(COORDINATOR, first.record.record_hash)
        self.assertEqual(old.status, "superseded")

    def test_validation_rejects_bad_input(self):
        base = submission("EV-1", EvidenceKind.VEHICLE_LOG, "v", "veh-clock", "摘要", [])
        # 空摘要
        with self.assertRaises(ValueError):
            self.service.register_evidence(COORDINATOR, replace(base, digest=" "))
        # 空指纹
        with self.assertRaises(ValueError):
            self.service.register_evidence(COORDINATOR, replace(base, integrity_fingerprint=""))
        # 区间倒置
        with self.assertRaises(ValueError):
            self.service.register_evidence(
                COORDINATOR, replace(base, collected_end=base.collected_start - timedelta(seconds=1)))
        # 无时区时间
        with self.assertRaises(ValueError):
            self.service.register_evidence(
                COORDINATOR, replace(base, collected_start=datetime(2026, 10, 3, 10, 0)))
        # 事件缺少标签
        with self.assertRaises(ValueError):
            self.service.register_evidence(
                COORDINATOR, replace(base, events=(SourceEvent("e1", " ", COLLISION),)))

    def test_naive_event_time_rejected(self):
        sub = EvidenceSubmission(
            investigation_id=INVESTIGATION, evidence_id="EV-9",
            kind=EvidenceKind.WITNESS_NOTE, source_id="p-1", digest="笔录",
            collected_start=COLLISION, collected_end=COLLISION,
            clock=SourceClock("wall-clock"), integrity_fingerprint="sha256:x",
            batch_id="B-9",
            events=(SourceEvent("e1", "陈述", datetime(2026, 10, 3, 10, 15)),),
        )
        with self.assertRaises(ValueError):
            self.service.register_evidence(COORDINATOR, sub)

    def test_reregister_withdrawn_evidence_rejected(self):
        publish_default_profile(self.service)
        sub = submission("EV-1", EvidenceKind.VEHICLE_LOG, "v", "veh-clock", "摘要", [])
        self.service.register_evidence(COORDINATOR, sub)
        self.service.seal_package(COORDINATOR, INVESTIGATION)
        self.service.withdraw_evidence(COORDINATOR, INVESTIGATION, "EV-1", "来源不可靠")
        with self.assertRaises(Exception) as ctx:
            self.service.register_evidence(
                COORDINATOR, replace(sub, integrity_fingerprint="sha256:EV-1-v3"))
        self.assertIn("撤回", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
