"""测试共用的事故事景夹具。

构造一个多时钟偏差的路口碰撞故事，刻意让「各设备原始读数顺序」与
「校准后统一时间轴顺序」不同，且 v2 精校准会再次翻转其中两个事件的先后：

统一时间轴 v1（粗校准）：
  刹车 1.000 < 云端确认 1.100 < 路侧行人 2.000 < 碰撞 2.800 < 笔录 3.000
统一时间轴 v2（精校准）：
  刹车 ≈1.010 < 云端确认 1.095 < 碰撞 2.810 < 路侧行人 2.850 < 笔录 3.000
    （路侧与车端碰撞的先后被新校准规则翻转）
原始时钟读数顺序：
  刹车 -0.500 < 云端 1.000 < 碰撞 1.300 < 路侧 3.000 < 笔录 63.000
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from incident_evidence.audit import Actor
from incident_evidence.clock import CalibrationRule, RuleKind
from incident_evidence.contracts import (
    CollectionWindow,
    EvidenceKind,
    SourceClock,
)
from incident_evidence.service import EvidenceService

T0 = datetime(2026, 10, 1, 8, 0, 0, tzinfo=timezone.utc)

VEH = "veh-ecu-clock"
RSU = "rsu-7-clock"
CLOUD = "cloud-master-clock"
WITNESS = "witness-watch"

# v1：初始粗校准（恒定偏差，毫秒）：common = source + offset
OFFSET_V1 = {VEH: 1500, RSU: -1000, CLOUD: 100, WITNESS: -60_000}

# v2：精校准——车端发现晶振频偏（线性模型重锚碰撞点），
# 路侧复核发现其时钟只慢 150ms（而非 1000ms），云端偏差修正为 95ms。
OFFSET_V2 = {RSU: -150, CLOUD: 95, WITNESS: -60_000}
VEH_V2_RATE_PPM = 250

# 各证据在自己时钟上的读数
VEH_BRAKE_SRC = T0 - timedelta(milliseconds=500)    # v1 -> 1.000，v2 -> ≈1.00955
CLOUD_ACK_SRC = T0 + timedelta(seconds=1)           # v1 -> 1.100，v2 -> 1.095
VEH_IMPACT_SRC = T0 + timedelta(milliseconds=1300)  # v1 -> 2.800，v2 -> 2.810（锚点）
RSU_DETECT_SRC = T0 + timedelta(seconds=3)          # v1 -> 2.000，v2 -> 2.850
WITNESS_IMPACT_SRC = T0 + timedelta(seconds=63)     # v1/v2 -> 3.000

# v1 统一时间轴上的期望值（毫秒）
COMMON_V1_MS = {
    "veh_brake": 1_000,
    "cloud_ack": 1_100,
    "rsu_detect": 2_000,
    "veh_impact": 2_800,
    "witness": 3_000,
}
COMMON_V2_MS = {
    "veh_brake": 1_010,   # 1.00955 四舍五入
    "cloud_ack": 1_095,
    "rsu_detect": 2_850,
    "veh_impact": 2_810,
    "witness": 3_000,
}


def rules_v1() -> list[CalibrationRule]:
    return [
        CalibrationRule(
            rule_id=f"cal-v1-{clock}",
            clock_id=clock,
            kind=RuleKind.OFFSET,
            offset_ms=offset,
            note="v1 初始粗校准：路口授时比对",
        )
        for clock, offset in OFFSET_V1.items()
    ]


def rules_v2() -> list[CalibrationRule]:
    return [
        CalibrationRule(
            rule_id="cal-v2-veh",
            clock_id=VEH,
            kind=RuleKind.LINEAR,
            rate_ppm=VEH_V2_RATE_PPM,
            anchor_source=VEH_IMPACT_SRC,
            anchor_common=T0 + timedelta(milliseconds=COMMON_V2_MS["veh_impact"]),
            note="v2 厂商日志复核：车端晶振频偏 +250ppm，碰撞点重锚",
        ),
        *[
            CalibrationRule(
                rule_id=f"cal-v2-{clock}",
                clock_id=clock,
                kind=RuleKind.OFFSET,
                offset_ms=offset,
                note="v2 精确授时比对",
            )
            for clock, offset in OFFSET_V2.items()
        ],
    ]


def seed(service: EvidenceService, actor: Actor, *, batch: str = "batch-20261001-01") -> dict:
    """登记校准 v1 与全部五份材料，返回 {key: Receipt}。"""

    service.register_calibration(actor, rules_v1(), "初始粗校准")

    def recv(evidence_id, kind, source_id, clock, source_time, payload, summary, window=None):
        return service.receive(
            actor,
            evidence_id=evidence_id,
            kind=kind,
            source_id=source_id,
            summary=summary,
            source_clock=SourceClock(clock, OFFSET_V1[clock]),
            source_time=source_time,
            content=payload,
            batch_id=batch,
            collection_window=window,
        )

    receipts = {}
    receipts["veh_brake"] = recv(
        "EV-VEH-01", EvidenceKind.VEHICLE_LOG, "veh-7", VEH, VEH_BRAKE_SRC,
        b"vehicle-can: AEB brake request",
        "车端 CAN 日志：自动紧急制动请求",
        CollectionWindow(VEH, VEH_BRAKE_SRC - timedelta(seconds=5), VEH_BRAKE_SRC + timedelta(seconds=5)),
    )
    receipts["cloud_ack"] = recv(
        "EV-CLOUD-01", EvidenceKind.CLOUD_DECISION, "cloud-region-3", CLOUD, CLOUD_ACK_SRC,
        b"cloud: remote operator ack",
        "云端决策记录：远程接管确认",
    )
    receipts["veh_impact"] = recv(
        "EV-VEH-02", EvidenceKind.VEHICLE_LOG, "veh-7", VEH, VEH_IMPACT_SRC,
                b"vehicle-can: impact deceleration peak",
        "车端 CAN 日志：碰撞减速度峰值",
        CollectionWindow(VEH, VEH_IMPACT_SRC - timedelta(seconds=3), VEH_IMPACT_SRC + timedelta(seconds=1)),
    )
    receipts["rsu_detect"] = recv(
        "EV-RSU-01", EvidenceKind.ROADSIDE_SENSOR, "rsu-7", RSU, RSU_DETECT_SRC,
        b"rsu: pedestrian enters crosswalk",
        "路侧感知：行人进入人行横道",
        CollectionWindow(RSU, RSU_DETECT_SRC - timedelta(seconds=2), RSU_DETECT_SRC + timedelta(seconds=2)),
    )
    receipts["witness"] = recv(
        "EV-WIT-01", EvidenceKind.WITNESS_NOTE, "witness-li", WITNESS, WITNESS_IMPACT_SRC,
        "目击者李某笔录：碰撞瞬间路口东西向绿灯".encode("utf-8"),
        "人工笔录：目击者对碰撞时刻的陈述",
    )
    return receipts


def actors() -> dict[str, Actor]:
    return {
        "coordinator": Actor("coord-zhao", "coordinator"),
        "analyst": Actor("analyst-qian", "analyst"),
        "auditor": Actor("auditor-sun", "auditor"),
        "custodian": Actor("custodian-zhou", "custodian"),
        "admin": Actor("admin-wu", "admin"),
    }
