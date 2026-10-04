"""事故证据封存与时间线服务的 HTTP API（标准库实现）。

鉴权：每个请求携带 ``X-Actor-Id`` 与 ``X-Role`` 头，服务端据此构造
:class:`Actor` 做角色授权；所有敏感操作在底层自动落审计链。

主要端点：

``POST /evidence``                 接收（含更正版本）
``POST /evidence/withdraw``        撤回指定版本
``POST /calibrations``             登记新一版校准规则
``POST /investigations``           创建调查版本
``GET  /investigations``           调查版本清单
``GET  /investigations/{n}/timeline``   指定调查版本的统一时间线
``GET  /investigations/{n}/evidence``   指定调查版本的证据清单
``POST /packages``                 签封证据包
``POST /packages/{id}/transfer``   移交保管权
``POST /packages/{id}/release``    解除保全
``POST /packages/{id}/export``     导出（自描述、带指纹）
``GET  /packages/{id}``            查询证据包与保管链
``GET  /audit``                    审计链（仅 admin）并复核
"""

from __future__ import annotations

import base64
import json
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import urlparse

from .audit import (
    AccessController,
    Actor,
    AuditChainBroken,
    AuditLog,
    AuthorizationError,
    Permission,
)
from .clock import (
    CalibrationError,
    ClockCalibrator,
    ClockNotCalibrated,
    RuleKind,
    CalibrationRule,
)
from .contracts import (
    CollectionWindow,
    EvidenceKind,
    EvidenceRef,
    SourceClock,
)
from .fingerprints import to_plain
from .service import (
    DuplicateEvidence,
    EvidenceError,
    EvidenceService,
    PackageError,
    PackageSealedError,
    SealConflictError,
    UnknownEvidence,
)


def parse_dt(value: str | None, field: str) -> datetime | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise ValueError(f"{field} 必须是 ISO 8601 字符串")
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    dt = datetime.fromisoformat(text)
    if dt.tzinfo is None:
        raise ValueError(f"{field} 必须携带时区")
    return dt


def require_dt(body: dict, field: str) -> datetime:
    dt = parse_dt(body.get(field), field)
    if dt is None:
        raise ValueError(f"缺少必填时间字段: {field}")
    return dt


def parse_actor(headers) -> Actor:
    actor_id = headers.get("X-Actor-Id")
    role = headers.get("X-Role")
    if not actor_id or not role:
        raise AuthorizationError("缺少 X-Actor-Id / X-Role 请求头")
    return Actor(actor_id=actor_id, role=role)


def parse_ref(value: dict) -> EvidenceRef:
    return EvidenceRef(evidence_id=value["evidence_id"], version=int(value["version"]))


def parse_rule(value: dict) -> CalibrationRule:
    kind = RuleKind(value["kind"])
    return CalibrationRule(
        rule_id=value["rule_id"],
        clock_id=value["clock_id"],
        kind=kind,
        offset_ms=int(value.get("offset_ms", 0)),
        rate_ppm=int(value.get("rate_ppm", 0)),
        anchor_source=parse_dt(value.get("anchor_source"), "anchor_source"),
        anchor_common=parse_dt(value.get("anchor_common"), "anchor_common"),
        valid_from=parse_dt(value.get("valid_from"), "valid_from"),
        valid_to=parse_dt(value.get("valid_to"), "valid_to"),
        note=value.get("note", ""),
    )


def parse_window(value: dict | None) -> CollectionWindow | None:
    if value is None:
        return None
    return CollectionWindow(
        clock_id=value["clock_id"],
        start=require_dt(value, "start"),
        end=require_dt(value, "end"),
    )


class ApiState:
    """跨请求共享的单套服务（线程安全）。"""

    def __init__(self, service: EvidenceService | None = None) -> None:
        self.service = service or EvidenceService()


def build_handler(state: ApiState) -> type[BaseHTTPRequestHandler]:
    service = state.service

    class Handler(BaseHTTPRequestHandler):
        server_version = "IncidentEvidenceHTTP/1.0"

        def log_message(self, fmt: str, *args: Any) -> None:  # 静默
            return

        # -- 工具 -------------------------------------------------------

        def _read_json(self) -> dict:
            length = int(self.headers.get("Content-Length", "0"))
            raw = self.rfile.read(length) if length else b"{}"
            try:
                body = json.loads(raw.decode("utf-8"))
            except json.JSONDecodeError as exc:
                raise ValueError(f"请求体不是合法 JSON: {exc}") from exc
            if not isinstance(body, dict):
                raise ValueError("请求体必须是 JSON 对象")
            return body

        def _send(self, status: int, payload: Any) -> None:
            data = json.dumps(to_plain(payload), ensure_ascii=False).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def _error(self, status: int, code: str, message: str) -> None:
            self._send(status, {"error": code, "message": message})

        def _handle(self, fn) -> None:
            try:
                fn()
            except AuthorizationError as exc:
                self._error(403, "forbidden", str(exc))
            except (DuplicateEvidence, SealConflictError) as exc:
                self._error(409, "conflict", str(exc))
            except (
                EvidenceError,
                CalibrationError,
                PackageError,
                PackageSealedError,
                ValueError,
            ) as exc:
                self._error(400, "bad_request", str(exc))
            except KeyError as exc:
                self._error(400, "bad_request", f"缺少必填字段: {exc}")
            except ClockNotCalibrated as exc:
                self._error(422, "not_calibrated", str(exc))
            except UnknownEvidence as exc:
                self._error(404, "not_found", str(exc))
            except AuditChainBroken as exc:
                self._error(500, "audit_chain_broken", str(exc))

        # -- 路由 -------------------------------------------------------

        def do_GET(self) -> None:  # noqa: N802
            self._handle(self._route_get)

        def do_POST(self) -> None:  # noqa: N802
            self._handle(self._route_post)

        def _route_get(self) -> None:
            path = urlparse(self.path).path.strip("/").split("/")
            if path == ["health"]:
                self._send(200, {"status": "ok"})
                return
            actor = parse_actor(self.headers)

            if path == ["investigations"]:
                self._send(
                    200,
                    {
                        "investigations": [
                            service.investigation_version(n)
                            for n in service.investigation_numbers()
                        ]
                    },
                )
            elif len(path) == 3 and path[0] == "investigations" and path[2] == "timeline":
                report = service.build_timeline_report(actor, int(path[1]))
                self._send(200, report)
            elif len(path) == 3 and path[0] == "investigations" and path[2] == "evidence":
                self._send(200, self._evidence_list(actor, int(path[1])))
            elif len(path) == 2 and path[0] == "packages":
                self._send(200, service.package(path[1]))
            elif path == ["audit"]:
                service.access.require(actor, Permission.ADMIN)
                service.audit.verify()
                self._send(
                    200,
                    {
                        "verified": True,
                        "head_fingerprint": service.audit.head_fingerprint,
                        "entries": list(service.audit.entries()),
                    },
                )
            else:
                self._error(404, "not_found", f"未知端点: /{'/'.join(path)}")

        def _evidence_list(self, actor: Actor, number: int) -> dict:
            iv = service.investigation_version(number)
            items = [service.get_receipt(actor, ref) for ref in iv.active_refs]
            return {
                "investigation_version": iv.number,
                "label": iv.label,
                "as_of": iv.as_of,
                "calibration_version": iv.calibration_version,
                "investigation_fingerprint": iv.fingerprint_value,
                "evidence": items,
                "excluded": list(iv.excluded),
            }

        def _route_post(self) -> None:
            path = urlparse(self.path).path.strip("/").split("/")
            actor = parse_actor(self.headers)
            body = self._read_json()

            if path == ["evidence"]:
                clock = body.get("source_clock") or {}
                content_b64 = body.get("content_base64", "")
                receipt = service.receive(
                    actor,
                    evidence_id=body["evidence_id"],
                    kind=EvidenceKind(body["kind"]),
                    source_id=body["source_id"],
                    summary=body.get("summary", ""),
                    source_clock=SourceClock(
                        clock_id=clock["clock_id"],
                        offset_ms=int(clock.get("offset_ms", 0)),
                    ),
                    source_time=require_dt(body, "source_time"),
                    content=base64.b64decode(content_b64),
                    batch_id=body["batch_id"],
                    collection_window=parse_window(body.get("collection_window")),
                    payload_ref=body.get("payload_ref"),
                    supersedes=parse_ref(body["supersedes"]) if body.get("supersedes") else None,
                    received_at=parse_dt(body.get("received_at"), "received_at"),
                )
                self._send(201, receipt)

            elif path == ["evidence", "withdraw"]:
                record = service.withdraw(
                    actor,
                    parse_ref(body["ref"]),
                    reason=body["reason"],
                    at=parse_dt(body.get("at"), "at"),
                )
                self._send(200, record)

            elif path == ["calibrations"]:
                version = service.register_calibration(
                    actor,
                    rules=[parse_rule(r) for r in body["rules"]],
                    description=body.get("description", ""),
                    created_at=parse_dt(body.get("created_at"), "created_at"),
                )
                self._send(201, version)

            elif path == ["investigations"]:
                iv = service.create_investigation_version(
                    actor,
                    label=body["label"],
                    calibration_version=body.get("calibration_version"),
                    as_of=parse_dt(body.get("as_of"), "as_of"),
                    created_at=parse_dt(body.get("created_at"), "created_at"),
                )
                self._send(201, iv)

            elif path == ["packages"]:
                package = service.seal_package(
                    actor,
                    package_id=body["package_id"],
                    refs=[parse_ref(r) for r in body["refs"]],
                    calibration_version=body.get("calibration_version"),
                    sealed_at=parse_dt(body.get("sealed_at"), "sealed_at"),
                )
                self._send(201, package)

            elif len(path) == 3 and path[0] == "packages" and path[2] == "transfer":
                package = service.transfer_package(
                    actor,
                    package_id=path[1],
                    to_actor_id=body["to_actor_id"],
                    note=body.get("note", ""),
                    at=parse_dt(body.get("at"), "at"),
                )
                self._send(200, package)

            elif len(path) == 3 and path[0] == "packages" and path[2] == "release":
                package = service.release_hold(
                    actor, package_id=path[1], note=body.get("note", ""),
                    at=parse_dt(body.get("at"), "at"),
                )
                self._send(200, package)

            elif len(path) == 3 and path[0] == "packages" and path[2] == "export":
                bundle = service.export_package(
                    actor, path[1], at=parse_dt(body.get("at"), "at")
                )
                self._send(
                    200,
                    {
                        "package_id": bundle.package_id,
                        "package_fingerprint": bundle.package_fingerprint,
                        "exported_at": bundle.exported_at,
                        "exported_by": bundle.exported_by,
                        "export_fingerprint": bundle.export_fingerprint,
                        "data_base64": base64.b64encode(bundle.data).decode("ascii"),
                    },
                )
            else:
                self._error(404, "not_found", f"未知端点: /{'/'.join(path)}")

    return Handler


def create_server(host: str = "127.0.0.1", port: int = 0, state: ApiState | None = None):
    handler = build_handler(state or ApiState())
    httpd = ThreadingHTTPServer((host, port), handler)
    return httpd


def serve_forever(host: str = "127.0.0.1", port: int = 8080) -> None:
    httpd = create_server(host, port)
    actual_host, actual_port = httpd.server_address[:2]
    print(f"事故证据封存与时间线服务已启动: http://{actual_host}:{actual_port}")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()


if __name__ == "__main__":  # pragma: no cover
    serve_forever()
