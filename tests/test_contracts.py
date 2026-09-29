import sys
import unittest
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parents[1] / "src"))

from incident_evidence.contracts import EvidenceItem, EvidenceKind, SourceClock


class EvidenceContractTests(unittest.TestCase):
    def test_evidence_keeps_original_clock(self):
        clock = SourceClock("rsu-1", -80)
        item = EvidenceItem("E-3", EvidenceKind.ROADSIDE_SENSOR, "R-9", datetime.now(timezone.utc), clock, "sha256:3")
        self.assertEqual(item.source_clock.offset_ms, -80)

    def test_fingerprint_is_required(self):
        with self.assertRaises(ValueError):
            EvidenceItem("E-4", EvidenceKind.WITNESS_NOTE, "P-1", datetime.now(timezone.utc), SourceClock("human"), " ")


if __name__ == "__main__":
    unittest.main()
