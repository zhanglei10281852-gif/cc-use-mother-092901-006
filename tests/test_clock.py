import sys
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parents[1] / "src"))

from incident_evidence.clock import (
    CalibrationError,
    CalibrationRule,
    ClockCalibrator,
    ClockNotCalibrated,
    RuleKind,
)
from tests.fixtures import (
    CLOUD,
    CLOUD_ACK_SRC,
    RSU,
    RSU_DETECT_SRC,
    T0,
    VEH,
    VEH_BRAKE_SRC,
    VEH_IMPACT_SRC,
    rules_v1,
    rules_v2,
)


class ClockCalibrationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.cal = ClockCalibrator()

    def test_offset_rule_maps_with_explanation(self):
        v1 = self.cal.register(rules_v1(), "初始粗校准")
        self.assertEqual(v1.version, 1)

        exp = self.cal.explain(VEH_BRAKE_SRC, VEH, at_version=1)
        self.assertEqual(exp.common_time, T0 + timedelta(milliseconds=1_000))
        self.assertEqual(exp.rule_id, f"cal-v1-{VEH}")
        self.assertEqual(exp.delta_ms, 1_500)
        # 解释里同时保留原始读数与统一时间
        self.assertIn(VEH_BRAKE_SRC.isoformat(), exp.describe())
        self.assertIn((T0 + timedelta(milliseconds=1_000)).isoformat(), exp.describe())

    def test_raw_order_differs_from_common_order(self):
        self.cal.register(rules_v1(), "初始粗校准")
        # 原始读数：碰撞(1.300) 早于 路侧(3.000)
        self.assertLess(VEH_IMPACT_SRC, RSU_DETECT_SRC)
        common_impact = self.cal.map_time(VEH_IMPACT_SRC, VEH, at_version=1)
        common_rsu = self.cal.map_time(RSU_DETECT_SRC, RSU, at_version=1)
        # 统一时间轴上：路侧(2.000) 早于 碰撞(2.800)——顺序被翻转
        self.assertLess(common_rsu, common_impact)

    def test_new_calibration_version_flips_order_but_old_version_stays(self):
        v1 = self.cal.register(rules_v1(), "初始粗校准")
        v2 = self.cal.register(rules_v2(), "精校准")
        self.assertEqual(v2.version, 2)
        self.assertEqual(v2.prev_fingerprint, v1.fingerprint_value)

        # v1：路侧 2.000 早于 碰撞 2.800
        rsu_v1 = self.cal.map_time(RSU_DETECT_SRC, RSU, at_version=1)
        impact_v1 = self.cal.map_time(VEH_IMPACT_SRC, VEH, at_version=1)
        self.assertLess(rsu_v1, impact_v1)

        # v2：碰撞 2.810 早于 路侧 2.850
        rsu_v2 = self.cal.map_time(RSU_DETECT_SRC, RSU, at_version=2)
        impact_v2 = self.cal.map_time(VEH_IMPACT_SRC, VEH, at_version=2)
        self.assertLess(impact_v2, rsu_v2)
        self.assertEqual(impact_v2, T0 + timedelta(milliseconds=2_810))

        # v1 规则对象与映射结果完全不变
        self.assertEqual(
            self.cal.map_time(RSU_DETECT_SRC, RSU, at_version=1), rsu_v1
        )

    def test_linear_rule_uses_anchor_and_rate(self):
        self.cal.register(rules_v1(), "v1")
        self.cal.register(rules_v2(), "v2")
        # 刹车点距锚点 -1800ms，+250ppm 下约 -1800.45ms -> 锚点 2.810 + 偏移 ≈ 1.010
        brake = self.cal.map_time(VEH_BRAKE_SRC, VEH, at_version=2)
        self.assertEqual(brake, T0 + timedelta(microseconds=1_009_550))

    def test_unmapped_clock_raises(self):
        self.cal.register(rules_v1(), "v1")
        unknown_time = T0 + timedelta(hours=10)
        with self.assertRaises(ClockNotCalibrated):
            self.cal.map_time(unknown_time, "some-unregistered-clock", at_version=1)

    def test_overlapping_rules_rejected(self):
        rules = [
            CalibrationRule(
                rule_id="r1", clock_id=CLOUD, kind=RuleKind.OFFSET, offset_ms=100,
                valid_from=T0, valid_to=T0 + timedelta(seconds=10),
            ),
            CalibrationRule(
                rule_id="r2", clock_id=CLOUD, kind=RuleKind.OFFSET, offset_ms=200,
                valid_from=T0 + timedelta(seconds=5),
                valid_to=T0 + timedelta(seconds=15),
            ),
        ]
        with self.assertRaises(CalibrationError):
            self.cal.register(rules, "重叠区间非法")
        # 失败的登记不产生任何版本
        self.assertIsNone(self.cal.latest_version())

    def test_adjacent_validity_windows_are_supported(self):
        rules = [
            CalibrationRule(
                rule_id="early", clock_id=CLOUD, kind=RuleKind.OFFSET, offset_ms=100,
                valid_to=T0 + timedelta(seconds=10),
            ),
            CalibrationRule(
                rule_id="late", clock_id=CLOUD, kind=RuleKind.OFFSET, offset_ms=200,
                valid_from=T0 + timedelta(seconds=10),
            ),
        ]
        self.cal.register(rules, "分时段校准")
        self.assertEqual(
            self.cal.map_time(T0 + timedelta(seconds=9), CLOUD, at_version=1),
            T0 + timedelta(seconds=9, milliseconds=100),
        )
        self.assertEqual(
            self.cal.map_time(T0 + timedelta(seconds=11), CLOUD, at_version=1),
            T0 + timedelta(seconds=11, milliseconds=200),
        )

    def test_linear_rule_requires_anchors(self):
        with self.assertRaises(CalibrationError):
            CalibrationRule(
                rule_id="bad", clock_id=VEH, kind=RuleKind.LINEAR, rate_ppm=10,
            )

    def test_fingerprint_stable_across_process_boundary(self):
        v1 = self.cal.register(rules_v1(), "初始粗校准", created_at=T0)
        # 全新校准器重建同一版本，指纹必须逐字节一致
        rebuilt = ClockCalibrator().register(rules_v1(), "初始粗校准", created_at=T0)
        self.assertEqual(rebuilt.fingerprint_value, v1.fingerprint_value)

    def test_naive_datetime_rejected(self):
        self.cal.register(rules_v1(), "v1")
        with self.assertRaises(CalibrationError):
            self.cal.map_time(datetime(2026, 10, 1, 8, 0, 0), CLOUD, at_version=1)


if __name__ == "__main__":
    unittest.main()
