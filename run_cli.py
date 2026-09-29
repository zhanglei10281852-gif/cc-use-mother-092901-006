import json
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent / "src"))

from incident_evidence.contracts import EvidenceItem, EvidenceKind, SourceClock


clock = SourceClock("vehicle-clock", 125)
item = EvidenceItem("EV-1", EvidenceKind.VEHICLE_LOG, "vehicle-7", datetime(2026, 10, 21, tzinfo=timezone.utc), clock, "sha256:demo")
print(json.dumps({"evidence_id": item.evidence_id, "kind": item.kind.value, "offset_ms": item.source_clock.offset_ms}, ensure_ascii=False))
