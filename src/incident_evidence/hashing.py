"""规范化 JSON 与内容摘要工具。

所有可验证哈希（record_hash / seal_hash / report_hash / 审计链）都建立在
同一份规范化规则上：键排序、UTF-8、无空白、时间统一为 UTC ISO 格式，
保证跨时间、跨进程重算结果一致。
"""

import hashlib
import json
from dataclasses import fields, is_dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Any


def canonicalize(obj: Any) -> Any:
    """把领域对象递归转换为可 JSON 序列化的规范结构。"""
    if is_dataclass(obj) and not isinstance(obj, type):
        return {f.name: canonicalize(getattr(obj, f.name)) for f in fields(obj)}
    if isinstance(obj, datetime):
        return obj.astimezone(timezone.utc).isoformat()
    if isinstance(obj, Enum):
        return obj.value
    if isinstance(obj, (tuple, list, frozenset)):
        return [canonicalize(x) for x in obj]
    if isinstance(obj, dict):
        return {str(k): canonicalize(obj[k]) for k in sorted(obj, key=str)}
    return obj


def canonical_json(obj: Any) -> str:
    return json.dumps(canonicalize(obj), sort_keys=True, ensure_ascii=False, separators=(",", ":"))


def content_hash(obj: Any, exclude: frozenset[str] = frozenset()) -> str:
    """对对象规范化结构计算 SHA-256；exclude 中的顶层字段不参与摘要。

    例如 record_hash 排除自身与保管状态 status——状态是保管元数据，
    不应改变证据内容的身份。
    """
    data = canonicalize(obj)
    if isinstance(data, dict) and exclude:
        data = {k: v for k, v in data.items() if k not in exclude}
    payload = json.dumps(data, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()
