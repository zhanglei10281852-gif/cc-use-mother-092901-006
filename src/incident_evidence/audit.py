"""访问控制与防篡改审计链。

每一次敏感操作（接收、查看、签封、导出、移交、解除保全、撤回……）都落成
一条 :class:`AuditEntry`；条目通过「前一条指纹 + 本条目内容」的哈希首尾相链，
任何事后插入、删除或修改都会让链断裂，:meth:`AuditLog.verify` 可独立复核。
"""

from __future__ import annotations

import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import StrEnum
from typing import Any

from .fingerprints import fingerprint


class Permission(StrEnum):
    RECEIVE = "receive"          # 接收证据入登记
    VIEW = "view"                # 查看证据与时间线
    SEAL = "seal"                # 签封证据包
    EXPORT = "export"            # 导出报告 / 证据包
    TRANSFER = "transfer"        # 移交保管权
    RELEASE_HOLD = "release_hold"  # 解除保全
    ADMIN = "admin"              # 用户与角色管理（隐含全部权限）


# 预置角色的权限集合
ROLE_PERMISSIONS: dict[str, frozenset[Permission]] = {
    "coordinator": frozenset(
        {
            Permission.RECEIVE,
            Permission.VIEW,
            Permission.SEAL,
            Permission.EXPORT,
            Permission.TRANSFER,
        }
    ),
    "analyst": frozenset({Permission.RECEIVE, Permission.VIEW, Permission.EXPORT}),
    "auditor": frozenset({Permission.VIEW, Permission.EXPORT}),
    "custodian": frozenset(
        {Permission.VIEW, Permission.RECEIVE, Permission.TRANSFER, Permission.RELEASE_HOLD}
    ),
    "admin": frozenset(Permission),
}


@dataclass(frozen=True)
class Actor:
    actor_id: str
    role: str

    def __post_init__(self) -> None:
        if not self.actor_id.strip():
            raise ValueError("操作者标识不能为空")
        if self.role not in ROLE_PERMISSIONS:
            raise ValueError(f"未知角色: {self.role}")


class AuthorizationError(PermissionError):
    """角色不具备执行该操作的权限。"""


class AuditChainBroken(RuntimeError):
    """审计链复核失败：存在缺失、插入或篡改。"""


class AuditAction(StrEnum):
    EVIDENCE_RECEIVED = "evidence_received"
    EVIDENCE_ACCESSED = "evidence_accessed"
    EVIDENCE_WITHDRAWN = "evidence_withdrawn"
    EVIDENCE_SUPERSEDED = "evidence_superseded"
    CALIBRATION_REGISTERED = "calibration_registered"
    INVESTIGATION_VERSION_CREATED = "investigation_version_created"
    PACKAGE_SEALED = "package_sealed"
    PACKAGE_EXPORTED = "package_exported"
    PACKAGE_TRANSFERRED = "package_transferred"
    HOLD_RELEASED = "hold_released"
    PERMISSION_DENIED = "permission_denied"
    SEAL_CONFLICT = "seal_conflict"


@dataclass(frozen=True)
class AuditEntry:
    sequence: int
    at: datetime
    actor_id: str
    action: AuditAction
    permission: Permission | None
    allowed: bool
    object_ref: str
    details: dict[str, Any]
    prev_fingerprint: str | None
    fingerprint_value: str = ""  # type: ignore[assignment]

    def __post_init__(self) -> None:
        object.__setattr__(self, "fingerprint_value", fingerprint(self._digest_input()))

    def _digest_input(self) -> dict[str, Any]:
        return {
            "type": "audit_entry",
            "sequence": self.sequence,
            "at": self.at,
            "actor_id": self.actor_id,
            "action": self.action,
            "permission": self.permission,
            "allowed": self.allowed,
            "object_ref": self.object_ref,
            "details": self.details,
            "prev_fingerprint": self.prev_fingerprint,
        }


class AccessController:
    """按预置角色做授权判断。"""

    def __init__(self, roles: dict[str, frozenset[Permission]] | None = None) -> None:
        self._roles = dict(roles or ROLE_PERMISSIONS)

    def permit(self, actor: Actor, permission: Permission) -> bool:
        return permission in self._roles.get(actor.role, frozenset())

    def require(self, actor: Actor, permission: Permission) -> None:
        if not self.permit(actor, permission):
            raise AuthorizationError(
                f"操作者 {actor.actor_id}（角色 {actor.role}）缺少权限 {permission.value}"
            )


class AuditLog:
    """线程安全的追加式哈希链审计日志。"""

    GENESIS = "sha256:genesis"

    def __init__(self) -> None:
        self._entries: list[AuditEntry] = []
        self._lock = threading.Lock()

    def append(
        self,
        actor_id: str,
        action: AuditAction,
        object_ref: str,
        *,
        permission: Permission | None = None,
        allowed: bool = True,
        details: dict[str, Any] | None = None,
        at: datetime | None = None,
    ) -> AuditEntry:
        at = at or datetime.now(timezone.utc)
        with self._lock:
            prev = self._entries[-1].fingerprint_value if self._entries else self.GENESIS
            entry = AuditEntry(
                sequence=len(self._entries) + 1,
                at=at,
                actor_id=actor_id,
                action=action,
                permission=permission,
                allowed=allowed,
                object_ref=object_ref,
                details=dict(details or {}),
                prev_fingerprint=prev,
            )
            self._entries.append(entry)
            return entry

    def entries(self) -> tuple[AuditEntry, ...]:
        with self._lock:
            return tuple(self._entries)

    def verify(self) -> None:
        """从链首重算全部指纹，发现异常即抛出 :class:`AuditChainBroken`。"""

        prev = self.GENESIS
        for index, entry in enumerate(self._entries):
            if entry.sequence != index + 1:
                raise AuditChainBroken(f"第 {index + 1} 条序号不连续")
            if entry.prev_fingerprint != prev:
                raise AuditChainBroken(
                    f"第 {entry.sequence} 条前向指纹不匹配（链在此处断裂）"
                )
            rebuilt = AuditEntry(
                sequence=entry.sequence,
                at=entry.at,
                actor_id=entry.actor_id,
                action=entry.action,
                permission=entry.permission,
                allowed=entry.allowed,
                object_ref=entry.object_ref,
                details=entry.details,
                prev_fingerprint=entry.prev_fingerprint,
            )
            if rebuilt.fingerprint_value != entry.fingerprint_value:
                raise AuditChainBroken(
                    f"第 {entry.sequence} 条内容指纹不一致（条目被篡改）"
                )
            prev = entry.fingerprint_value

    @property
    def head_fingerprint(self) -> str:
        with self._lock:
            return self._entries[-1].fingerprint_value if self._entries else self.GENESIS
