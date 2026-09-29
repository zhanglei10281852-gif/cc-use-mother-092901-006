"""事故证据接收与时间校准的数据契约。"""

from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum


class EvidenceKind(StrEnum):
    VEHICLE_LOG = "vehicle_log"
    ROADSIDE_SENSOR = "roadside_sensor"
    CLOUD_DECISION = "cloud_decision"
    WITNESS_NOTE = "witness_note"


@dataclass(frozen=True)
class SourceClock:
    clock_id: str
    offset_ms: int = 0


@dataclass(frozen=True)
class EvidenceItem:
    evidence_id: str
    kind: EvidenceKind
    source_id: str
    source_time: datetime
    source_clock: SourceClock
    integrity_fingerprint: str

    def __post_init__(self) -> None:
        if not self.integrity_fingerprint.strip():
            raise ValueError("证据完整性指纹不能为空")
