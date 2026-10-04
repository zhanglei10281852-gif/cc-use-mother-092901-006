"""健壮性：重复接收、校准规则变化、证据撤回、并发签封
都不破坏既有报告的可验证性。"""

import unittest
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import timedelta

from support import (
    COLLISION,
    COORDINATOR,
    INVESTIGATION,
    EvidenceKind,
    make_service,
    publish_default_profile,
    register_standard_evidence,
    submission,
)


class DuplicateReceptionRobustnessTests(unittest.TestCase):
    """同一材料重复送达（甚至换批次、换送达方式）不得改变既有报告。"""

    def test_duplicate_receipt_keeps_report_verifiable(self):
        service = make_service()
        publish_default_profile(service)
        register_standard_evidence(service)
        service.seal_package(COORDINATOR, INVESTIGATION)
        report = service.generate_timeline(COORDINATOR, INVESTIGATION, 1)

        # 同一批材料整体重复送达一次（新批次号）
        for evidence_id, kind, source_id, clock_id, digest in [
            ("EV-VEH", EvidenceKind.VEHICLE_LOG, "vehicle-7", "veh-clock", "车端日志：AEB 介入与碰撞检测"),
            ("EV-RSU", EvidenceKind.ROADSIDE_SENSOR, "rsu-12", "rsu-clock", "路侧感知：目标轨迹与碰撞帧"),
        ]:
            result = service.register_evidence(COORDINATOR, submission(
                evidence_id, kind, source_id, clock_id, digest, [],
                fingerprint=f"sha256:{evidence_id}-v1", batch_id="BATCH-REDELIVER"))
            self.assertEqual(result.outcome, "duplicate")

        # 记录数未变，报告逐字节一致且仍可验证
        self.assertEqual(len(service._store.records), 4)
        regenerated = service.generate_timeline(COORDINATOR, INVESTIGATION, 1)
        self.assertEqual(regenerated.report_hash, report.report_hash)
        self.assertTrue(service.verify_report(report).ok)
        self.assertTrue(service.audit_chain_intact())


class CalibrationChangeRobustnessTests(unittest.TestCase):
    """校准规则修订只能发布新档案版本；既有签封钉死旧版本，报告不变。"""

    def test_calibration_change_keeps_existing_report_verifiable(self):
        service = make_service()
        publish_default_profile(service, vehicle_offset_ms=120)
        register_standard_evidence(service)
        v1 = service.seal_package(COORDINATOR, INVESTIGATION)
        report_v1 = service.generate_timeline(COORDINATOR, INVESTIGATION, 1)
        veh_before = next(e for e in report_v1.events if e.event_id == "veh-2")

        # 复测后发现车端偏移应为 +200ms：发布 cal-main@2
        publish_default_profile(service, vehicle_offset_ms=200, note="复测修正")
        v2 = service.seal_package(COORDINATOR, INVESTIGATION)
        self.assertEqual(v2.calibration_profile, "cal-main@2")
        self.assertEqual(v1.calibration_profile, "cal-main@1")

        # 旧版本时间线仍按 cal-main@1 重放，逐字节一致
        replayed_v1 = service.generate_timeline(COORDINATOR, INVESTIGATION, 1)
        self.assertEqual(replayed_v1.report_hash, report_v1.report_hash)
        veh_after = next(e for e in replayed_v1.events if e.event_id == "veh-2")
        self.assertEqual(veh_after.unified_time, veh_before.unified_time)

        # 新版本应用新规则：同一源读数映射到不同统一时间
        report_v2 = service.generate_timeline(COORDINATOR, INVESTIGATION, 2)
        veh_v2 = next(e for e in report_v2.events if e.event_id == "veh-2")
        self.assertEqual(veh_v2.source_time, veh_before.source_time)  # 原始时间不动
        self.assertEqual(
            veh_v2.unified_time,
            veh_before.unified_time - timedelta(milliseconds=80))
        self.assertEqual(veh_v2.trace.profile_ref, "cal-main@2")

        # 两个版本的报告都可验证
        self.assertTrue(service.verify_report(report_v1).ok)
        self.assertTrue(service.verify_report(report_v2).ok)
        self.assertTrue(service.audit_chain_intact())


class WithdrawalRobustnessTests(unittest.TestCase):
    """撤回证据形成关联版本；旧版本内容不变、报告仍可验证。"""

    def test_withdrawal_keeps_existing_report_verifiable(self):
        service = make_service()
        publish_default_profile(service)
        register_standard_evidence(service)
        service.seal_package(COORDINATOR, INVESTIGATION)
        report_v1 = service.generate_timeline(COORDINATOR, INVESTIGATION, 1)
        self.assertEqual(len(report_v1.evidence_manifest), 4)

        # 撤回人工笔录：自动形成关联版本 v2
        v2 = service.withdraw_evidence(COORDINATOR, INVESTIGATION, "EV-WIT", "证人撤回陈述")
        self.assertIsNotNone(v2)
        self.assertEqual(v2.version, 2)
        self.assertEqual(v2.supersedes, service.get_package(COORDINATOR, INVESTIGATION, 1).seal_hash)
        self.assertEqual([w.evidence_id for w in v2.withdrawals], ["EV-WIT"])

        # v1 报告原样可重放：仍包含被撤回证据（历史如实保留）
        replayed_v1 = service.generate_timeline(COORDINATOR, INVESTIGATION, 1)
        self.assertEqual(replayed_v1.report_hash, report_v1.report_hash)
        self.assertIn("EV-WIT", {m.evidence_id for m in replayed_v1.evidence_manifest})

        # v2 时间线不再包含被撤回证据
        report_v2 = service.generate_timeline(COORDINATOR, INVESTIGATION, 2)
        self.assertNotIn("EV-WIT", {m.evidence_id for m in report_v2.evidence_manifest})
        self.assertNotIn("wit-1", {e.event_id for e in report_v2.events})

        # 两个版本都可验证；撤回记录本体仍可按哈希取回
        self.assertTrue(service.verify_report(report_v1).ok)
        self.assertTrue(service.verify_report(report_v2).ok)
        withdrawn = service.get_record(
            COORDINATOR, report_v1.evidence_manifest[3].record_hash)
        self.assertEqual(withdrawn.status, "withdrawn")
        self.assertTrue(service.audit_chain_intact())


class ConcurrentSealingRobustnessTests(unittest.TestCase):
    """并发签封被串行化：版本唯一连续、链完整、幂等收敛、全部可验证。"""

    def test_concurrent_identical_seals_collapse_to_one_version(self):
        service = make_service()
        publish_default_profile(service)
        register_standard_evidence(service)

        with ThreadPoolExecutor(max_workers=8) as pool:
            packages = list(pool.map(
                lambda _: service.seal_package(COORDINATOR, INVESTIGATION), range(8)))

        # 8 个并发请求收敛到同一个签封版本
        self.assertEqual({p.seal_hash for p in packages}, {packages[0].seal_hash})
        versions = service.list_packages(COORDINATOR, INVESTIGATION)
        self.assertEqual(len(versions), 1)
        report = service.generate_timeline(COORDINATOR, INVESTIGATION, 1)
        self.assertTrue(service.verify_report(report).ok)

    def test_concurrent_mixed_writes_keep_chain_consistent(self):
        service = make_service()
        publish_default_profile(service)
        register_standard_evidence(service)
        service.seal_package(COORDINATOR, INVESTIGATION)  # v1

        def register_and_seal(index: int):
            service.register_evidence(COORDINATOR, submission(
                f"EV-LATE-{index}", EvidenceKind.WITNESS_NOTE, f"officer-{index}",
                "wall-clock", f"补充笔录 {index}",
                [(f"late-{index}", "补充陈述", COLLISION + timedelta(seconds=index))],
                batch_id=f"BATCH-LATE-{index}"))
            return service.seal_package(COORDINATOR, INVESTIGATION)

        with ThreadPoolExecutor(max_workers=6) as pool:
            sealed = list(pool.map(register_and_seal, range(6)))

        # 版本连续无空洞（签封幂等可能收敛部分版本，数量在 2..7 之间）
        versions = service.list_packages(COORDINATOR, INVESTIGATION)
        self.assertEqual([p.version for p in versions],
                         list(range(1, len(versions) + 1)))
        self.assertGreaterEqual(len(versions), 2)
        # 链式引用完整
        for prev, nxt in zip(versions, versions[1:]):
            self.assertEqual(nxt.supersedes, prev.seal_hash)
        # 每个并发返回的包都在链上
        on_chain = {p.seal_hash for p in versions}
        self.assertTrue(all(p.seal_hash in on_chain for p in sealed))
        # 最后一个签封必然发生在全部登记之后：最终版本收齐 6 份补充笔录
        final_ids = {e.evidence_id for e in versions[-1].entries}
        self.assertTrue(all(f"EV-LATE-{i}" in final_ids for i in range(6)))
        # 每个版本的时间线都可生成、可验证
        for version in range(1, len(versions) + 1):
            report = service.generate_timeline(COORDINATOR, INVESTIGATION, version)
            self.assertTrue(service.verify_report(report).ok, f"版本 {version} 验证失败")
        self.assertTrue(service.audit_chain_intact())

    def test_concurrent_seal_and_withdraw_stay_consistent(self):
        service = make_service()
        publish_default_profile(service)
        register_standard_evidence(service)
        service.seal_package(COORDINATOR, INVESTIGATION)

        with ThreadPoolExecutor(max_workers=4) as pool:
            futures = [
                pool.submit(service.withdraw_evidence, COORDINATOR, INVESTIGATION, "EV-WIT", "撤回"),
                pool.submit(service.seal_package, COORDINATOR, INVESTIGATION),
                pool.submit(service.seal_package, COORDINATOR, INVESTIGATION),
            ]
            results = [f.result() for f in futures]

        self.assertIsNotNone(results[0])
        versions = service.list_packages(COORDINATOR, INVESTIGATION)
        self.assertEqual([p.version for p in versions], [1, 2])
        self.assertEqual(versions[1].supersedes, versions[0].seal_hash)
        # 最终版本不含被撤回证据，且全部可验证
        final = service.generate_timeline(COORDINATOR, INVESTIGATION, 2)
        self.assertNotIn("EV-WIT", {m.evidence_id for m in final.evidence_manifest})
        for version in (1, 2):
            report = service.generate_timeline(COORDINATOR, INVESTIGATION, version)
            self.assertTrue(service.verify_report(report).ok)
        self.assertTrue(service.audit_chain_intact())


if __name__ == "__main__":
    unittest.main()
