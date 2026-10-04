"""时钟校准：映射算术、可解释轨迹、档案版本化、签封时覆盖检查。"""

import unittest
from datetime import timedelta

from support import (
    COLLISION,
    COORDINATOR,
    INVESTIGATION,
    MEASURED_AT,
    ClockCalibrationRule,
    EvidenceKind,
    make_service,
    publish_default_profile,
    register_standard_evidence,
    submission,
)
from incident_evidence.clock import map_to_unified
from incident_evidence.errors import CalibrationGapError


class ClockMappingTests(unittest.TestCase):
    def test_offset_mapping(self):
        rule = ClockCalibrationRule("veh-clock", 120, MEASURED_AT)
        unified, trace = map_to_unified(COLLISION, rule, "cal-main@1")
        self.assertEqual(unified, COLLISION - timedelta(milliseconds=120))
        self.assertEqual(trace.offset_ms, 120)

    def test_negative_offset(self):
        rule = ClockCalibrationRule("rsu-clock", -80, MEASURED_AT)
        unified, _ = map_to_unified(COLLISION, rule, "cal-main@1")
        self.assertEqual(unified, COLLISION + timedelta(milliseconds=80))

    def test_drift_accumulates_from_measurement(self):
        rule = ClockCalibrationRule("veh-clock", 0, MEASURED_AT, drift_ppm=100.0)
        # 校准后 100 秒：漂移 100ppm × 100s = 10ms
        unified, trace = map_to_unified(
            MEASURED_AT + timedelta(seconds=100), rule, "cal-main@1")
        self.assertAlmostEqual(
            (MEASURED_AT + timedelta(seconds=100) - unified).total_seconds() * 1000, 10.0)
        self.assertAlmostEqual(trace.correction_ms, 10.0)

    def test_trace_is_explainable(self):
        rule = ClockCalibrationRule(
            "veh-clock", 120, MEASURED_AT, method="gps-pps", rationale="GPS 秒脉冲比对")
        _, trace = map_to_unified(COLLISION, rule, "cal-main@1")
        self.assertIn("120", trace.formula)
        self.assertIn("offset", trace.formula)
        self.assertEqual(trace.method, "gps-pps")
        self.assertEqual(trace.profile_ref, "cal-main@1")


class CalibrationProfileTests(unittest.TestCase):
    def setUp(self):
        self.service = make_service()

    def test_profile_versions_are_immutable_and_sequential(self):
        v1 = publish_default_profile(self.service, vehicle_offset_ms=120)
        v2 = publish_default_profile(self.service, vehicle_offset_ms=200, note="复测修正")
        self.assertEqual((v1.version, v2.version), (1, 2))
        # 两个版本都保留，旧版本仍可引用
        self.assertEqual(self.service._store.profiles["cal-main"][1].rule_for("veh-clock").offset_ms, 120)
        self.assertEqual(self.service._store.profiles["cal-main"][2].rule_for("veh-clock").offset_ms, 200)

    def test_duplicate_clock_rule_rejected(self):
        rules = [
            ClockCalibrationRule("veh-clock", 1, MEASURED_AT),
            ClockCalibrationRule("veh-clock", 2, MEASURED_AT),
        ]
        with self.assertRaises(ValueError):
            self.service.publish_calibration_profile(COORDINATOR, "cal-x", rules)

    def test_seal_rejects_clock_gap(self):
        # 档案只覆盖车端时钟，但登记了路侧证据
        self.service.publish_calibration_profile(
            COORDINATOR, "cal-partial",
            [ClockCalibrationRule("veh-clock", 120, MEASURED_AT)])
        self.service.register_evidence(COORDINATOR, submission(
            "EV-1", EvidenceKind.VEHICLE_LOG, "v", "veh-clock", "车端", []))
        self.service.register_evidence(COORDINATOR, submission(
            "EV-2", EvidenceKind.ROADSIDE_SENSOR, "r", "rsu-clock", "路侧", []))
        with self.assertRaises(CalibrationGapError):
            self.service.seal_package(COORDINATOR, INVESTIGATION, profile_id="cal-partial")

    def test_seal_without_any_profile_fails(self):
        self.service.register_evidence(COORDINATOR, submission(
            "EV-1", EvidenceKind.VEHICLE_LOG, "v", "veh-clock", "车端", []))
        with self.assertRaises(CalibrationGapError):
            self.service.seal_package(COORDINATOR, INVESTIGATION)


if __name__ == "__main__":
    unittest.main()
