"""主体权限策略。"""

from typing import Iterable

from .contracts import Permission
from .errors import PermissionDeniedError


class AccessPolicy:
    """简单的主体→权限集合映射；持有 ADMIN 的主体可授予他人权限。"""

    def __init__(self, grants: dict[str, Iterable[Permission]] | None = None) -> None:
        self._grants: dict[str, set[Permission]] = {
            actor: set(perms) for actor, perms in (grants or {}).items()
        }

    def grant(self, actor: str, *permissions: Permission) -> None:
        self._grants.setdefault(actor, set()).update(permissions)

    def permissions_of(self, actor: str) -> frozenset[Permission]:
        return frozenset(self._grants.get(actor, set()))

    def check(self, actor: str, permission: Permission) -> bool:
        granted = self._grants.get(actor, set())
        return permission in granted or Permission.ADMIN in granted

    def require(self, actor: str, permission: Permission) -> None:
        if not self.check(actor, permission):
            raise PermissionDeniedError(f"主体 {actor!r} 缺少权限 {permission.value}")
