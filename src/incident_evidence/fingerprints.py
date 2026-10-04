"""规范化序列化与 SHA-256 完整性指纹。

所有需要"可验证"的结构（收据、校准版本、报告、证据包、审计条目、导出包）
都先经 :func:`canonical` 转为字节再哈希，保证同一逻辑内容在任何进程、
任何时间重新计算得到完全一致的摘要。
"""

from __future__ import annotations

import dataclasses
import hashlib
import json
from datetime import datetime
from enum import Enum
from typing import Any


def to_plain(obj: Any) -> Any:
    """把领域对象递归转换成只含 JSON 基础类型的规范结构。"""

    if obj is None or isinstance(obj, (str, bool, int, float)):
        return obj
    if isinstance(obj, datetime):
        if obj.tzinfo is None:
            raise ValueError("参与指纹计算的时间必须携带时区")
        return obj.isoformat()
    if isinstance(obj, Enum):
        return obj.value
    if dataclasses.is_dataclass(obj):
        return {
            key: to_plain(getattr(obj, key))
            for key in obj.__dataclass_fields__
        }
    if isinstance(obj, dict):
        return {str(key): to_plain(value) for key, value in obj.items()}
    if isinstance(obj, (set, frozenset)):
        # 集合无序：先递归再按规范 JSON 字符串排序，保证稳定。
        rendered = [to_plain(item) for item in obj]
        return sorted(
            rendered,
            key=lambda item: json.dumps(item, sort_keys=True, ensure_ascii=False),
        )
    if isinstance(obj, (list, tuple)):
        return [to_plain(item) for item in obj]
    if isinstance(obj, bytes):
        return {"__bytes_base64__": __import__("base64").b64encode(obj).decode()}
    raise TypeError(f"无法规范化序列化类型: {type(obj)!r}")


def canonical(obj: Any) -> bytes:
    """返回确定性的紧凑 UTF-8 JSON 字节。"""

    return json.dumps(
        to_plain(obj),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def fingerprint(obj: Any) -> str:
    """对任意可规范化对象计算 ``sha256:`` 前缀指纹。"""

    return "sha256:" + sha256_hex(canonical(obj))


def content_fingerprint(data: bytes) -> str:
    """对证据原始字节计算内容指纹（内容寻址）。"""

    return "sha256:" + sha256_hex(data)
