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


class LifecycleStatus(StrEnum):
    """证据逻辑版本在某个调查时点的生命周期状态。"""

    ACTIVE = "active"
    SUPERSEDED = "superseded"
    WITHDRAWN = "withdrawn"


@dataclass(frozen=True)
class CollectionWindow:
    """材料在其来源时钟上的采集区间（保留原始时钟读数）。"""

    clock_id: str
    start: datetime
    end: datetime

    def __post_init__(self) -> None:
        if not self.clock_id.strip():
            raise ValueError("来源时钟标识不能为空")
        if self.start.tzinfo is None or self.end.tzinfo is None:
            raise ValueError("采集区间必须携带时区")
        if self.end < self.start:
            raise ValueError("采集区间结束时间不能早于开始时间")


@dataclass(frozen=True)
class EvidenceRef:
    """证据的不可变版本引用：逻辑标识 + 单调版本号。"""

    evidence_id: str
    version: int

    def __post_init__(self) -> None:
        if not self.evidence_id.strip():
            raise ValueError("证据标识不能为空")
        if self.version < 1:
            raise ValueError("证据版本号必须从 1 开始")

    def __str__(self) -> str:
        return f"{self.evidence_id}@v{self.version}"
