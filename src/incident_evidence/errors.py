"""证据服务的异常体系。"""


class EvidenceError(Exception):
    """证据服务基础异常。"""


class ValidationError(EvidenceError, ValueError):
    """提交内容不合法（时间、区间、指纹等）。"""


class PermissionDeniedError(EvidenceError):
    """主体缺少执行该操作所需的权限。"""


class NotFoundError(EvidenceError):
    """请求的调查、证据、版本或校准档案不存在。"""


class CalibrationGapError(EvidenceError):
    """校准档案缺失或无法覆盖全部证据时钟。"""


class HoldReleasedError(EvidenceError):
    """保全已解除，禁止再写入或签封。"""


class InvalidStateError(EvidenceError):
    """当前状态不允许该操作（如重复签封、重复撤回）。"""
