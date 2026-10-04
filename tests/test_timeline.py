"""时间线生成与验证：统一排序、原始时间保留、确定性、篡改可发现。"""

import unittest
from dataclasses import replace
from datetime import timedelta

from support import (
    COLLISION,
    COORDINATOR,
    INVESTIGATION,
    make_service,
    publish_default_profile,
    register_standard_evidence,
)


class TimelineTests(unittest.TestCase):
    def setUp(self):
        self.service = make_service()
        publish_default_profile(self.service)
        register_standard_evidence(self.service)
        self.service.seal_package(COORDINATOR, INVESTIGATION)
        self.report = self.service.generate_timeline(COORDINATOR, INVESTIGATION, 1)

    def test_events_sorted_on_unified_axis(self):
        unified = [e.unified_time for e in self.report.events]
        self.assertEqual(unified, sorted(unified))
        # 四方来源各就各位：路侧最早（进入交叉口），碰撞帧最晚
        self.assertEqual(self.report.events[0].event_id, "rsu-1")
        self.assertEqual(self.report.events[-1].event_id, "rsu-2")

    def test_mapping_math_and_original_time_preserved(self):
        by_id = {e.event_id: e for e in self.report.events}
        # 车端 +120ms：统一时间 = 源读数 - 120ms
        veh = by_id["veh-2"]
        self.assertEqual(veh.source_time, COLLISION + timedelta(milliseconds=50))
        self.assertEqual(veh.unified_time, COLLISION - timedelta(milliseconds=70))
        self.assertEqual(veh.trace.profile_ref, "cal-main@1")
        self.assertIn("120", veh.trace.formula)
        # 路侧 -80ms：统一时间 = 源读数 + 80ms
        rsu = by_id["rsu-2"]
        self.assertEqual(rsu.unified_time, COLLISION + timedelta(milliseconds=170))

    def test_manifest_lists_all_evidence_with_fingerprints(self):
        manifest = {m.evidence_id: m for m in self.report.evidence_manifest}
        self.assertEqual(set(manifest), {"EV-VEH", "EV-RSU", "EV-CLD", "EV-WIT"})
        self.assertEqual(manifest["EV-VEH"].integrity_fingerprint, "sha256:EV-VEH-v1")
        self.assertEqual(manifest["EV-VEH"].batch_id, "BATCH-1")

    def test_regeneration_is_deterministic(self):
        again = self.service.generate_timeline(COORDINATOR, INVESTIGATION, 1)
        self.assertEqual(again.report_hash, self.report.report_hash)
        self.assertEqual(again.events, self.report.events)

    def test_verify_ok(self):
        result = self.service.verify_report(self.report)
        self.assertTrue(result.ok)
        self.assertTrue(all(c.passed for c in result.checks))

    def test_tampered_report_fails_verification(self):
        forged = replace(
            self.report,
            events=tuple(
                replace(e, label="伪造：未踩刹车") if e.event_id == "veh-1" else e
                for e in self.report.events
            ),
        )
        result = self.service.verify_report(forged)
        self.assertFalse(result.ok)
        failed = {c.name for c in result.checks if not c.passed}
        self.assertIn("report_hash_self_consistent", failed)

    def test_report_with_wrong_seal_fails(self):
        forged = replace(self.report, seal_hash="0" * 64)
        result = self.service.verify_report(forged)
        self.assertFalse(result.ok)

    def test_latest_version_is_default(self):
        latest = self.service.generate_timeline(COORDINATOR, INVESTIGATION)
        self.assertEqual(latest.package_version, 1)


if __name__ == "__main__":
    unittest.main()
