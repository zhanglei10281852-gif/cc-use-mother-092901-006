"""智能车辆事故证据领域包。

模块：
- contracts：领域契约（证据、时钟、采集区间、版本引用、生命周期）
- fingerprints：规范化序列化与 SHA-256 指纹
- clock：可解释、可版本化的时钟校准
- audit：角色权限与哈希链审计
- service：证据接收/撤回/更正、调查版本、签封/移交/解除保全、时间线报告
- api：HTTP API
"""

from .audit import (
    AccessController,
    Actor,
    AuditAction,
    AuditLog,
    Permission,
)
from .clock import (
    CalibrationExplanation,
    CalibrationRule,
    CalibrationVersion,
    ClockCalibrator,
    RuleKind,
)
from .contracts import (
    CollectionWindow,
    EvidenceItem,
    EvidenceKind,
    EvidenceRef,
    LifecycleStatus,
    SourceClock,
)
from .service import (
    DuplicateEvidence,
    EvidencePackage,
    EvidenceService,
    ExportBundle,
    InvestigationVersion,
    Receipt,
    TimelineReport,
)
