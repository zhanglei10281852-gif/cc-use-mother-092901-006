"""并发不变量测试：重复接收、校准规则变化与并发签封。"""

import sys
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parents[1] / "src"))
sys.path.insert(0, str(Path(__file__).parents[1]))

from incident_evidence.audit import Actor
from incident_evidence.contracts import EvidenceRef
from incident_evidence.service import (
    DuplicateEvidence,
    EvidenceService,
    SealConflictError,
)
from tests.fixtures import VEH, actors, rules_v1, rules_v2, seed


class ConcurrencyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.service = EvidenceService()
        self.coord = actors()["coordinator"]
        self.receipts = seed(self.service, self.coord)

    def test_concurrent_seal_same_id_only_one_wins(self):
        refs = [r.ref for r in self.receipts.values()]
        n = 16
        barrier = threading.Barrier(n)
        results: list[object] = []
        lock = threading.Lock()

        def seal(i: int) -> None:
            barrier.wait()  # 尽量让所有线程在同一刻竞争
            try:
                package = self.service.seal_package(
                    self.coord,
                    "PKG-RACE",
                    # 每个线程试图签封略有差异的成员集合
                    refs[: max(1, (i % len(refs)) + 1)],
                )
                with lock:
                    results.append(("ok", package))
            except SealConflictError as exc:
                with lock:
                    results.append(("conflict", str(exc)))

        with ThreadPoolExecutor(max_workers=n) as pool:
            list(pool.map(seal, range(n)))

        wins = [r for r in results if r[0] == "ok"]
        conflicts = [r for r in results if r[0] == "conflict"]
        self.assertEqual(len(wins), 1)
        self.assertEqual(len(conflicts), n - 1)

        winner = wins[0][1]
        stored = self.service.package("PKG-RACE")
        # 赢的那次签封内容就是最终内容，指纹一致且可复核
        self.assertIs(stored, winner)
        self.service.verify_package(stored)
        # 之后再签封仍被拒绝
        with self.assertRaises(SealConflictError):
            self.service.seal_package(self.coord, "PKG-RACE", refs)

    def test_concurrent_calibration_registration_keeps_versions_intact(self):
        """多个线程并发登记校准规则：版本号唯一连续，链指纹一一对应；
        先于并发产生的调查版本（引用 v1）报告指纹保持不变。"""

        iv1 = self.service.create_investigation_version(self.coord, "并发前基线")
        baseline = self.service.build_timeline_report(self.coord, iv1.number)

        n = 10
        barrier = threading.Barrier(n)
        errors: list[BaseException] = []

        def register(i: int) -> None:
            barrier.wait()
            try:
                self.service.register_calibration(
                    self.coord,
                    rules_v2() if i % 2 == 0 else rules_v1(),
                    f"并发登记 #{i}",
                )
            except BaseException as exc:  # noqa: BLE001
                errors.append(exc)

        with ThreadPoolExecutor(max_workers=n) as pool:
            list(pool.map(register, range(n)))

        self.assertEqual(errors, [])
        versions = self.service.calibrator.versions()
        numbers = [v.version for v in versions]
        self.assertEqual(numbers, list(range(1, n + 2)))
        # 指纹两两不同，且严格按前指纹成链
        fingerprints = {v.fingerprint_value for v in versions}
        self.assertEqual(len(fingerprints), n + 1)
        for prev, nxt in zip(versions, versions[1:]):
            self.assertEqual(nxt.prev_fingerprint, prev.fingerprint_value)

        # 既有报告不被任何后续校准改写
        again = self.service.build_timeline_report(self.coord, iv1.number)
        self.assertEqual(again.report_fingerprint, baseline.report_fingerprint)
        self.assertEqual(again.calibration_version, 1)
        self.service.audit.verify()

    def test_concurrent_duplicate_receive_only_one_accepted(self):
        witness = self.receipts["witness"]
        duplicate_payload = b"witness: duplicate race payload v9"
        assert duplicate_payload not in {
            b"vehicle-can: AEB brake request",
        }
        n = 12
        barrier = threading.Barrier(n)
        accepted = []
        rejected = []
        lock = threading.Lock()

        def receive() -> None:
            barrier.wait()
            try:
                receipt = self.service.receive(
                    self.coord,
                    evidence_id="EV-DUP",
                    kind=witness.kind,
                    source_id=witness.source_id,
                    summary="并发重复接收",
                    source_clock=witness.source_clock,
                    source_time=witness.source_time,
                    content=duplicate_payload,
                    batch_id="batch-race",
                )
                with lock:
                    accepted.append(receipt)
            except DuplicateEvidence:
                with lock:
                    rejected.append("dup")

        with ThreadPoolExecutor(max_workers=n) as pool:
            list(pool.map(lambda _: receive(), range(n)))

        self.assertEqual(len(accepted), 1)
        self.assertEqual(len(rejected), n - 1)
        self.assertEqual(self.service.receipt_count(), len(self.receipts) + 1)

    def test_concurrent_distinct_receives_all_accepted(self):
        n = 12
        barrier = threading.Barrier(n)

        def receive(i: int) -> None:
            barrier.wait()
            self.service.receive(
                self.coord,
                evidence_id=f"EV-CONC-{i:02d}",
                kind=self.receipts["witness"].kind,
                source_id=f"source-{i}",
                summary=f"并发不同材料 {i}",
                source_clock=self.receipts["witness"].source_clock,
                source_time=datetime(2026, 10, 1, 9, 0, 0, tzinfo=timezone.utc)
                + timedelta(milliseconds=i),
                content=f"distinct payload {i}".encode(),
                batch_id="batch-concurrent",
            )

        with ThreadPoolExecutor(max_workers=n) as pool:
            list(pool.map(receive, range(n)))

        self.assertEqual(self.service.receipt_count(), len(self.receipts) + n)
        self.assertEqual(len(self.service.batch("batch-concurrent").refs), n)
        self.service.audit.verify()

    def test_concurrent_investigation_versions_get_unique_numbers(self):
        n = 8
        barrier = threading.Barrier(n)
        numbers = []
        lock = threading.Lock()

        def create(i: int) -> None:
            barrier.wait()
            iv = self.service.create_investigation_version(
                self.coord, f"并发版本 {i}"
            )
            with lock:
                numbers.append(iv.number)

        with ThreadPoolExecutor(max_workers=n) as pool:
            list(pool.map(create, range(n)))

        self.assertEqual(sorted(numbers), list(range(1, n + 1)))
        # 每个版本都有独立链指纹，报告均可复核，且都锚定同一校准版本
        reports = [self.service.build_timeline_report(self.coord, k) for k in numbers]
        report_fps = {r.report_fingerprint for r in reports}
        self.assertEqual(len(report_fps), n)
        self.assertTrue({r.calibration_version for r in reports} == {1})
        for r in reports:
            self.service.verify_report(r)


if __name__ == "__main__":
    unittest.main()
