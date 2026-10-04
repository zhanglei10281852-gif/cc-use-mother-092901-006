"""测试共享支撑：服务工厂、可控时钟与标准事故场景数据。"""

import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parents[1] / "src"))

from incident_evidence.contracts import (
    ClockCalibrationRule,
    EvidenceKind,
    EvidenceSubmission,
    Permission,
    SourceClock,
    SourceEvent,
)
from incident_evidence.service import EvidenceService

UTC = timezone.utc

# 事故发生的标准时刻（统一时间轴）：2026-10-03 10:15:01.000 UTC
COLLISION = datetime(2026, 10, 3, 10, 15, 1, 0, tzinfo=UTC)
MEASURED_AT = datetime(2026, 10, 3, 9, 0, 0, tzinfo=UTC)

INVESTIGATION = "INV-2026-1003"

ADMIN = "admin"
COORDINATOR = "coordinator"
VIEWER = "viewer"
OUTSIDER = "outsider"

COORDINATOR_PERMISSIONS = {
    Permission.EVIDENCE_REGISTER,
    Permission.EVIDENCE_VIEW,
    Permission.EVIDENCE_WITHDRAW,
    Permission.PACKAGE_SEAL,
    Permission.PACKAGE_EXPORT,
    Permission.CUSTODY_TRANSFER,
    Permission.HOLD_RELEASE,
    Permission.CALIBRATION_MANAGE,
    Permission.AUDIT_VIEW,
}


class FakeClock:
    """每次调用前进 1ms 的可控时钟，保证测试时间确定且单调。"""

    def __init__(self, start: datetime | None = None) -> None:
        self._t = start or datetime(2026, 10, 3, 12, 0, 0, tzinfo=UTC)

    def __call__(self) -> datetime:
        current = self._t
        self._t += timedelta(milliseconds=1)
        return current


def make_service() -> EvidenceService:
    return EvidenceService(
        grants={
            ADMIN: {Permission.ADMIN},
            COORDINATOR: set(COORDINATOR_PERMISSIONS),
            VIEWER: {Permission.EVIDENCE_VIEW},
        },
        now_fn=FakeClock(),
    )


def default_rules(vehicle_offset_ms: int = 120) -> list[ClockCalibrationRule]:
    """标准四时钟校准规则：车端 +120ms、路侧 -80ms、云端 +15ms、笔录 0。"""
    return [
        ClockCalibrationRule(
            clock_id="veh-clock", offset_ms=vehicle_offset_ms, measured_at=MEASURED_AT,
            method="gps-pps", rationale="与 GPS 秒脉冲比对，车端时钟偏快",
        ),
        ClockCalibrationRule(
            clock_id="rsu-clock", offset_ms=-80, measured_at=MEASURED_AT,
            method="ntp-sync", rationale="路侧单元 NTP 同步，时钟偏慢 80ms",
        ),
        ClockCalibrationRule(
            clock_id="cloud-clock", offset_ms=15, measured_at=MEASURED_AT,
            method="ntp-sync", rationale="云平台 NTP 偏移",
        ),
        ClockCalibrationRule(
            clock_id="wall-clock", offset_ms=0, measured_at=MEASURED_AT,
            method="manual", rationale="笔录使用调查终端 UTC 时钟",
        ),
    ]


def publish_default_profile(
    service: EvidenceService, vehicle_offset_ms: int = 120, note: str = "初始校准"
):
    return service.publish_calibration_profile(
        COORDINATOR, "cal-main", default_rules(vehicle_offset_ms), note=note
    )


def submission(
    evidence_id: str,
    kind: EvidenceKind,
    source_id: str,
    clock_id: str,
    digest: str,
    events: list[tuple[str, str, datetime]],
    *,
    fingerprint: str | None = None,
    batch_id: str = "BATCH-1",
    investigation_id: str = INVESTIGATION,
) -> EvidenceSubmission:
    start = COLLISION - timedelta(seconds=30)
    end = COLLISION + timedelta(seconds=30)
    return EvidenceSubmission(
        investigation_id=investigation_id,
        evidence_id=evidence_id,
        kind=kind,
        source_id=source_id,
        digest=digest,
        collected_start=start,
        collected_end=end,
        clock=SourceClock(clock_id),
        integrity_fingerprint=fingerprint or f"sha256:{evidence_id}-v1",
        batch_id=batch_id,
        transport="field-laptop",
        events=tuple(SourceEvent(eid, label, t) for eid, label, t in events),
    )


def register_standard_evidence(service: EvidenceService) -> None:
    """登记标准四方材料：车端日志、路侧感知、云端决策、人工笔录。"""
    service.register_evidence(COORDINATOR, submission(
        "EV-VEH", EvidenceKind.VEHICLE_LOG, "vehicle-7", "veh-clock",
        "车端日志：AEB 介入与碰撞检测",
        [("veh-1", "AEB 介入", COLLISION - timedelta(milliseconds=100)),
         ("veh-2", "碰撞检测", COLLISION + timedelta(milliseconds=50))],
    ))
    service.register_evidence(COORDINATOR, submission(
        "EV-RSU", EvidenceKind.ROADSIDE_SENSOR, "rsu-12", "rsu-clock",
        "路侧感知：目标轨迹与碰撞帧",
        [("rsu-1", "目标进入交叉口", COLLISION - timedelta(seconds=2, milliseconds=500)),
         ("rsu-2", "碰撞帧", COLLISION + timedelta(milliseconds=90))],
    ))
    service.register_evidence(COORDINATOR, submission(
        "EV-CLD", EvidenceKind.CLOUD_DECISION, "cloud-fleet", "cloud-clock",
        "云端决策：下发接管请求",
        [("cld-1", "下发接管请求", COLLISION - timedelta(milliseconds=515))],
    ))
    service.register_evidence(COORDINATOR, submission(
        "EV-WIT", EvidenceKind.WITNESS_NOTE, "officer-3", "wall-clock",
        "人工笔录：目击者听到急刹",
        [("wit-1", "听到急刹", COLLISION - timedelta(milliseconds=50))],
    ))
