"""端到端冒烟演示：接收 -> 校准 -> 签封 -> 时间线 -> 验证 -> 更正/撤回 -> 复验。"""

import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent / "src"))

from incident_evidence import (
    ClockCalibrationRule,
    EvidenceKind,
    EvidenceService,
    EvidenceSubmission,
    Permission,
    SourceClock,
    SourceEvent,
)

UTC = timezone.utc
COLLISION = datetime(2026, 10, 3, 10, 15, 1, tzinfo=UTC)
MEASURED = datetime(2026, 10, 3, 9, 0, 0, tzinfo=UTC)
INV = "INV-2026-1003"


def show(title, payload):
    print(f"\n== {title} ==")
    print(json.dumps(payload, ensure_ascii=False, indent=1, default=str))


def main():
    service = EvidenceService(grants={
        "coordinator": set(Permission) - {Permission.ADMIN},
    })

    # 1. 发布时钟校准档案（可解释：方法 + 依据）
    profile = service.publish_calibration_profile("coordinator", "cal-main", [
        ClockCalibrationRule("veh-clock", 120, MEASURED, method="gps-pps",
                             rationale="车端时钟与 GPS 秒脉冲比对偏快 120ms"),
        ClockCalibrationRule("rsu-clock", -80, MEASURED, method="ntp-sync",
                             rationale="路侧单元 NTP 同步偏慢 80ms"),
        ClockCalibrationRule("cloud-clock", 15, MEASURED, method="ntp-sync",
                             rationale="云平台 NTP 偏移 +15ms"),
        ClockCalibrationRule("wall-clock", 0, MEASURED, method="manual",
                             rationale="笔录使用调查终端 UTC 时钟"),
    ], note="初始校准")
    show("校准档案", {"ref": profile.ref, "规则数": len(profile.rules)})

    # 2. 按批次登记四方材料（来源/摘要/采集区间/批次/指纹）
    materials = [
        ("EV-VEH", EvidenceKind.VEHICLE_LOG, "vehicle-7", "veh-clock",
         "车端日志：AEB 介入与碰撞检测", "BATCH-A",
         [("veh-1", "AEB 介入", COLLISION - timedelta(milliseconds=100)),
          ("veh-2", "碰撞检测", COLLISION + timedelta(milliseconds=50))]),
        ("EV-RSU", EvidenceKind.ROADSIDE_SENSOR, "rsu-12", "rsu-clock",
         "路侧感知：目标轨迹与碰撞帧", "BATCH-A",
         [("rsu-1", "目标进入交叉口", COLLISION - timedelta(seconds=2, milliseconds=500)),
          ("rsu-2", "碰撞帧", COLLISION + timedelta(milliseconds=90))]),
        ("EV-CLD", EvidenceKind.CLOUD_DECISION, "cloud-fleet", "cloud-clock",
         "云端决策：下发接管请求", "BATCH-B",
         [("cld-1", "下发接管请求", COLLISION - timedelta(milliseconds=515))]),
        ("EV-WIT", EvidenceKind.WITNESS_NOTE, "officer-3", "wall-clock",
         "人工笔录：目击者听到急刹", "BATCH-C",
         [("wit-1", "听到急刹", COLLISION - timedelta(milliseconds=50))]),
    ]
    for eid, kind, src, clock, digest, batch, events in materials:
        result = service.register_evidence("coordinator", EvidenceSubmission(
            investigation_id=INV, evidence_id=eid, kind=kind, source_id=src,
            digest=digest,
            collected_start=COLLISION - timedelta(seconds=30),
            collected_end=COLLISION + timedelta(seconds=30),
            clock=SourceClock(clock),
            integrity_fingerprint=f"sha256:{eid}-v1",
            batch_id=batch, transport="field-laptop",
            events=tuple(SourceEvent(i, label, t) for i, label, t in events),
        ))
        print(f"登记 {eid}: {result.outcome} 批次={result.batch.batch_id} "
              f"hash={result.record.record_hash[:12]}…")

    # 3. 签封 v1 并生成时间线
    v1 = service.seal_package("coordinator", INV, note="首批材料签封")
    show("签封 v1", {"version": v1.version, "seal_hash": v1.seal_hash[:20] + "…",
                     "证据数": len(v1.entries), "校准": v1.calibration_profile})
    report_v1 = service.generate_timeline("coordinator", INV, 1)
    show("统一时间线 v1", [
        {"事件": e.label, "来源": e.source_id,
         "原始时间": e.source_time.isoformat(),
         "统一时间": e.unified_time.isoformat(),
         "校准": e.trace.formula}
        for e in report_v1.events
    ])
    print("验证 v1 报告:", service.verify_report(report_v1).ok)

    # 4. 后补材料：更正车端日志（新指纹 -> 修订 2），签封 v2
    corrected = service.register_evidence("coordinator", EvidenceSubmission(
        investigation_id=INV, evidence_id="EV-VEH", kind=EvidenceKind.VEHICLE_LOG,
        source_id="vehicle-7", digest="车端日志（更正：补全碰撞后 5 秒）",
        collected_start=COLLISION - timedelta(seconds=30),
        collected_end=COLLISION + timedelta(seconds=35),
        clock=SourceClock("veh-clock"),
        integrity_fingerprint="sha256:EV-VEH-v2", batch_id="BATCH-D",
        events=(SourceEvent("veh-1", "AEB 介入", COLLISION - timedelta(milliseconds=100)),
                SourceEvent("veh-2", "碰撞检测", COLLISION + timedelta(milliseconds=50)),
                SourceEvent("veh-3", "车辆静止", COLLISION + timedelta(seconds=4))),
    ))
    print(f"\n更正登记 EV-VEH: {corrected.outcome} 修订={corrected.record.revision}")
    v2 = service.seal_package("coordinator", INV, note="纳入更正后的车端日志")
    print(f"签封 v2: supersedes={v2.supersedes[:12]}…")

    # 5. 撤回人工笔录 -> 自动形成关联版本 v3
    v3 = service.withdraw_evidence("coordinator", INV, "EV-WIT", "证人撤回陈述")
    print(f"撤回 EV-WIT -> 关联版本 v{v3.version}")

    # 6. 既有报告仍可验证：v1 逐字节重放
    replay_v1 = service.generate_timeline("coordinator", INV, 1)
    show("既有报告复验", {
        "v1 报告哈希不变": replay_v1.report_hash == report_v1.report_hash,
        "v1 验证": service.verify_report(report_v1).ok,
        "v3 验证": service.verify_report(
            service.generate_timeline("coordinator", INV, 3)).ok,
        "审计链完整": service.audit_chain_intact(),
    })

    # 7. 移交与审计
    service.transfer_custody("coordinator", INV, "交警物证科", note="移交进一步调查")
    trail = service.audit_trail("coordinator", INV)
    print(f"审计条目 {len(trail)} 条，链完整: {service.audit_chain_intact()}")


if __name__ == "__main__":
    main()
