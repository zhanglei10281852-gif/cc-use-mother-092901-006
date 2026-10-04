"""由签封包重建统一时间线。

纯函数：同样的（签封包, 证据记录, 校准档案）永远产出同样的结果，
这是报告可重放验证的基础。
"""

from .contracts import (
    CalibrationProfile,
    EvidencePackage,
    EvidenceRecord,
    ManifestEntry,
    TimelineEvent,
)
from .clock import map_to_unified, resolve_rule


def build_timeline(
    package: EvidencePackage,
    records: dict[str, EvidenceRecord],
    profile: CalibrationProfile,
) -> tuple[tuple[TimelineEvent, ...], tuple[ManifestEntry, ...]]:
    events: list[TimelineEvent] = []
    manifest: list[ManifestEntry] = []
    for entry in package.entries:  # entries 在签封时已按 evidence_id 排序
        record = records[entry.record_hash]
        rule = resolve_rule(profile, record.item.source_clock.clock_id)
        for source_event in record.events:
            unified, trace = map_to_unified(
                source_event.source_time, rule, profile.ref
            )
            events.append(
                TimelineEvent(
                    evidence_id=record.evidence_id,
                    event_id=source_event.event_id,
                    label=source_event.label,
                    kind=record.item.kind,
                    source_id=record.item.source_id,
                    source_time=source_event.source_time,
                    unified_time=unified,
                    trace=trace,
                )
            )
        manifest.append(
            ManifestEntry(
                evidence_id=record.evidence_id,
                revision=record.revision,
                kind=record.item.kind,
                source_id=record.item.source_id,
                digest=record.digest,
                batch_id=record.batch_id,
                integrity_fingerprint=record.item.integrity_fingerprint,
                record_hash=record.record_hash,
            )
        )
    events.sort(key=lambda e: (e.unified_time, e.evidence_id, e.event_id))
    return tuple(events), tuple(manifest)
