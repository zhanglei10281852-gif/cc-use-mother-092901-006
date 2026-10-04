"""仅追加的哈希链审计日志。

每条条目包含前一条的 entry_hash，任何对历史条目的篡改都会
使 verify_chain 失败。追加操作由服务层在锁内调用。
"""

from dataclasses import replace
from datetime import datetime

from .contracts import AuditEntry
from .hashing import content_hash

GENESIS_HASH = "0" * 64
_ENTRY_HASH_EXCLUDE = frozenset({"entry_hash"})


class AuditLog:
    def __init__(self) -> None:
        self._entries: list[AuditEntry] = []

    def append(
        self,
        *,
        timestamp: datetime,
        actor: str,
        action: str,
        target: str,
        outcome: str,
        detail: str,
    ) -> AuditEntry:
        prev_hash = self._entries[-1].entry_hash if self._entries else GENESIS_HASH
        draft = AuditEntry(
            seq=len(self._entries) + 1,
            timestamp=timestamp,
            actor=actor,
            action=action,
            target=target,
            outcome=outcome,
            detail=detail,
            prev_hash=prev_hash,
            entry_hash="",
        )
        entry = replace(draft, entry_hash=content_hash(draft, exclude=_ENTRY_HASH_EXCLUDE))
        self._entries.append(entry)
        return entry

    def entries(self) -> tuple[AuditEntry, ...]:
        return tuple(self._entries)

    def verify_chain(self) -> bool:
        prev_hash = GENESIS_HASH
        for expected_seq, entry in enumerate(self._entries, start=1):
            if entry.seq != expected_seq or entry.prev_hash != prev_hash:
                return False
            if content_hash(entry, exclude=_ENTRY_HASH_EXCLUDE) != entry.entry_hash:
                return False
            prev_hash = entry.entry_hash
        return True
