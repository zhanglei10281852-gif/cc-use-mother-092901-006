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


# ---------------------------------------------------------------------------
# 接收与登记
# ---------------------------------------------------------------------------


class EvidenceStatus(StrEnum):
    ACTIVE = "active"          # 有效，可参与后续签封
    SUPERSEDED = "superseded"  # 已被更正版本取代（历史保留）
    WITHDRAWN = "withdrawn"    # 已撤回（历史保留，不再参与新签封）


@dataclass(frozen=True)
class SourceEvent:
    """从材料中提取的事件点；source_time 始终是源时钟原始读数。"""

    event_id: str
    label: str
    source_time: datetime


@dataclass(frozen=True)
class EvidenceSubmission:
    """登记请求：描述一份待接收的事故材料。"""

    investigation_id: str
    evidence_id: str
    kind: EvidenceKind
    source_id: str
    digest: str                       # 摘要：材料内容的人读简述
    collected_start: datetime         # 采集区间起点（源时钟）
    collected_end: datetime           # 采集区间终点（源时钟）
    clock: SourceClock                # 来源时钟
    integrity_fingerprint: str        # 完整性指纹，如 sha256:...
    batch_id: str                     # 接收批次
    transport: str = "upload"         # 送达方式（介质/网络等）
    events: tuple[SourceEvent, ...] = ()
    received_at: datetime | None = None  # 缺省由服务接收时钟填充


@dataclass(frozen=True)
class ReceivingBatch:
    """接收批次：一次物理/逻辑接收动作的登记。"""

    batch_id: str
    investigation_id: str
    received_by: str
    received_at: datetime
    transport: str
    note: str = ""


@dataclass(frozen=True)
class EvidenceRecord:
    """登记后的证据记录。

    record_hash 只覆盖证据内容（不含 status），因此保管状态变化
    （生效/被取代/撤回）不会改变证据的内容身份；已签封的报告永远
    可以通过 record_hash 找回当初的内容。
    """

    item: EvidenceItem                # item.source_time 即采集区间起点
    investigation_id: str
    digest: str
    collected_end: datetime
    batch_id: str
    transport: str
    received_at: datetime
    events: tuple[SourceEvent, ...]
    revision: int                     # 同一 evidence_id 的修订序号，从 1 开始
    supersedes: str | None            # 被取代记录的 record_hash
    status: EvidenceStatus
    record_hash: str

    @property
    def evidence_id(self) -> str:
        return self.item.evidence_id

    @property
    def collected_start(self) -> datetime:
        return self.item.source_time


@dataclass(frozen=True)
class RegistrationResult:
    record: EvidenceRecord
    outcome: str  # registered | duplicate | correction
    batch: ReceivingBatch


# ---------------------------------------------------------------------------
# 时钟校准
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ClockCalibrationRule:
    """单一时钟的校准规则。

    offset_ms：校准时刻测得的“源时钟读数 - 统一参考时间”，毫秒；
    drift_ppm：源时钟漂移率（每秒钟漂移的微秒数），自 measured_at 起累计；
    measured_at：测量偏移时源时钟的读数；
    method / rationale：测量方式与依据，供校准轨迹解释。
    """

    clock_id: str
    offset_ms: int
    measured_at: datetime
    drift_ppm: float = 0.0
    method: str = "manual"
    rationale: str = ""
    confidence: str = "medium"


@dataclass(frozen=True)
class CalibrationProfile:
    """一组校准规则的不可变版本；规则变更只能发布新版本。"""

    profile_id: str
    version: int
    rules: tuple[ClockCalibrationRule, ...]
    note: str
    created_at: datetime

    @property
    def ref(self) -> str:
        return f"{self.profile_id}@{self.version}"

    def rule_for(self, clock_id: str) -> ClockCalibrationRule | None:
        for rule in self.rules:
            if rule.clock_id == clock_id:
                return rule
        return None


@dataclass(frozen=True)
class CalibrationTrace:
    """单个事件映射的可解释轨迹：用了哪份档案、哪条规则、修正量多少。"""

    clock_id: str
    profile_ref: str
    offset_ms: int
    drift_ppm: float
    correction_ms: float
    method: str
    rationale: str
    formula: str


# ---------------------------------------------------------------------------
# 签封与版本链
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class PackageEntry:
    """签封包锁定的证据快照指针（精确到修订）。"""

    evidence_id: str
    revision: int
    record_hash: str
    integrity_fingerprint: str


@dataclass(frozen=True)
class WithdrawalRecord:
    evidence_id: str
    reason: str
    withdrawn_by: str
    withdrawn_at: datetime


@dataclass(frozen=True)
class EvidencePackage:
    """一次签封形成的不可变证据包版本。

    签封后不得改写；补充、更正、撤回只能通过 supersedes 串起的
    后续版本表达。seal_hash 覆盖除自身外的全部字段。
    """

    investigation_id: str
    version: int
    entries: tuple[PackageEntry, ...]
    calibration_profile: str          # 钉死的校准档案引用 "profile_id@version"
    supersedes: str | None            # 上一版本的 seal_hash
    withdrawals: tuple[WithdrawalRecord, ...]
    sealed_by: str
    sealed_at: datetime
    note: str
    seal_hash: str


# ---------------------------------------------------------------------------
# 时间线报告
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class TimelineEvent:
    evidence_id: str
    event_id: str
    label: str
    kind: EvidenceKind
    source_id: str
    source_time: datetime   # 原始源时钟读数，始终保留
    unified_time: datetime  # 映射到统一时间轴后的时间
    trace: CalibrationTrace


@dataclass(frozen=True)
class ManifestEntry:
    evidence_id: str
    revision: int
    kind: EvidenceKind
    source_id: str
    digest: str
    batch_id: str
    integrity_fingerprint: str
    record_hash: str


@dataclass(frozen=True)
class TimelineReport:
    """指定调查版本的时间线与证据清单。

    report_hash 只覆盖可重放的决定性内容（前六个字段）；
    generated_by / generated_at 是生成元数据，不参与摘要，
    因此同一版本重复生成会得到完全相同的 report_hash。
    """

    investigation_id: str
    package_version: int
    seal_hash: str
    calibration_profile: str
    events: tuple[TimelineEvent, ...]
    evidence_manifest: tuple[ManifestEntry, ...]
    report_hash: str
    generated_by: str
    generated_at: datetime


# ---------------------------------------------------------------------------
# 权限、审计与保管
# ---------------------------------------------------------------------------


class Permission(StrEnum):
    ADMIN = "admin"                          # 授权管理
    EVIDENCE_REGISTER = "evidence:register"  # 登记接收
    EVIDENCE_VIEW = "evidence:view"          # 查看证据与时间线
    EVIDENCE_WITHDRAW = "evidence:withdraw"  # 撤回证据
    PACKAGE_SEAL = "package:seal"            # 签封
    PACKAGE_EXPORT = "package:export"        # 导出
    CUSTODY_TRANSFER = "custody:transfer"    # 移交
    HOLD_RELEASE = "hold:release"            # 解除保全
    CALIBRATION_MANAGE = "calibration:manage"  # 发布校准档案
    AUDIT_VIEW = "audit:view"                # 查看审计日志


@dataclass(frozen=True)
class AuditEntry:
    """仅追加审计日志条目；entry_hash 链接前一条，篡改可被发现。"""

    seq: int
    timestamp: datetime
    actor: str
    action: str
    target: str
    outcome: str   # success | duplicate | denied | failed
    detail: str
    prev_hash: str
    entry_hash: str


@dataclass(frozen=True)
class CustodyRecord:
    investigation_id: str
    from_custodian: str
    to_custodian: str
    transferred_by: str
    transferred_at: datetime
    note: str = ""


@dataclass(frozen=True)
class ExportBundle:
    """导出包：签封包 + 证据记录 + 校准档案，整体可校验。"""

    investigation_id: str
    package_version: int
    package: EvidencePackage
    records: tuple[EvidenceRecord, ...]
    profile: CalibrationProfile
    bundle_hash: str
    exported_by: str
    exported_at: datetime


@dataclass(frozen=True)
class CheckResult:
    name: str
    passed: bool
    detail: str


@dataclass(frozen=True)
class VerificationResult:
    ok: bool
    checks: tuple[CheckResult, ...]
