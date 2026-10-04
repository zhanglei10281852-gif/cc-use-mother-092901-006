import base64
import json
import sys
import threading
import unittest
import urllib.error
import urllib.request
from datetime import timedelta
from http.server import ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parents[1] / "src"))
sys.path.insert(0, str(Path(__file__).parents[1]))

from incident_evidence.api import ApiState, build_handler
from incident_evidence.service import EvidenceService
from tests.fixtures import (
    CLOUD_ACK_SRC,
    RSU_DETECT_SRC,
    T0,
    VEH_BRAKE_SRC,
    VEH_IMPACT_SRC,
    WITNESS_IMPACT_SRC,
)


class ApiClient:
    def __init__(self, base_url: str, actor_id: str, role: str) -> None:
        self.base_url = base_url
        self.actor_id = actor_id
        self.role = role

    def request(self, method: str, path: str, body: dict | None = None):
        data = json.dumps(body).encode("utf-8") if body is not None else None
        req = urllib.request.Request(
            self.base_url + path,
            data=data,
            method=method,
            headers={
                "X-Actor-Id": self.actor_id,
                "X-Role": self.role,
                "Content-Type": "application/json",
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                return resp.status, json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            return exc.code, json.loads(exc.read().decode("utf-8"))


class HttpApiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.service = EvidenceService()
        handler = build_handler(ApiState(cls.service))
        cls.httpd = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        host, port = cls.httpd.server_address[:2]
        cls.base_url = f"http://{host}:{port}"
        cls.thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.httpd.shutdown()
        cls.httpd.server_close()
        cls.thread.join(timeout=5)

    def setUp(self) -> None:
        self.coord = ApiClient(self.base_url, "coord-zhao", "coordinator")
        self.analyst = ApiClient(self.base_url, "analyst-qian", "analyst")
        self.auditor = ApiClient(self.base_url, "auditor-sun", "auditor")
        self.custodian = ApiClient(self.base_url, "custodian-zhou", "custodian")
        self.admin = ApiClient(self.base_url, "admin-wu", "admin")

    def _register_calibration_v1(self):
        rules = [
            {"rule_id": f"v1-{c}", "clock_id": c, "kind": "offset",
             "offset_ms": off, "note": "粗校准"}
            for c, off in (
                ("veh-ecu-clock", 1500),
                ("rsu-7-clock", -1000),
                ("cloud-master-clock", 100),
                ("witness-watch", -60000),
            )
        ]
        status, body = self.coord.request("POST", "/calibrations",
                                          {"rules": rules, "description": "初始粗校准"})
        self.assertEqual(status, 201, body)
        return body

    def _receive_all(self):
        materials = [
            ("EV-VEH-01", "vehicle_log", "veh-7", "veh-ecu-clock", VEH_BRAKE_SRC,
             b"vehicle-can: AEB brake request", "车端制动"),
            ("EV-CLOUD-01", "cloud_decision", "cloud-region-3", "cloud-master-clock",
             CLOUD_ACK_SRC, b"cloud: remote operator ack", "云端确认"),
            ("EV-RSU-01", "roadside_sensor", "rsu-7", "rsu-7-clock", RSU_DETECT_SRC,
             b"rsu: pedestrian enters crosswalk", "路侧行人"),
            ("EV-VEH-02", "vehicle_log", "veh-7", "veh-ecu-clock", VEH_IMPACT_SRC,
             b"vehicle-can: impact deceleration peak", "碰撞峰值"),
            ("EV-WIT-01", "witness_note", "witness-li", "witness-watch",
             WITNESS_IMPACT_SRC, "目击者笔录".encode(), "人工笔录"),
        ]
        refs = []
        for evidence_id, kind, source_id, clock, when, payload, summary in materials:
            status, body = self.coord.request("POST", "/evidence", {
                "evidence_id": evidence_id,
                "kind": kind,
                "source_id": source_id,
                "summary": summary,
                "source_clock": {"clock_id": clock},
                "source_time": when.isoformat(),
                "content_base64": base64.b64encode(payload).decode(),
                "batch_id": "batch-http-01",
            })
            self.assertEqual(status, 201, body)
            refs.append({"evidence_id": evidence_id, "version": 1})
        return refs

    def test_full_investigation_flow(self):
        # 健康检查
        status, body = self.coord.request("GET", "/health")
        self.assertEqual((status, body["status"]), (200, "ok"))

        self._register_calibration_v1()
        refs = self._receive_all()

        # 重复接收 -> 409
        status, body = self.coord.request("POST", "/evidence", {
            "evidence_id": "EV-DUP", "kind": "vehicle_log", "source_id": "veh-7",
            "summary": "重复", "source_clock": {"clock_id": "veh-ecu-clock"},
            "source_time": VEH_BRAKE_SRC.isoformat(),
            "content_base64": base64.b64encode(b"vehicle-can: AEB brake request").decode(),
            "batch_id": "batch-http-late",
        })
        self.assertEqual(status, 409)
        self.assertEqual(body["error"], "conflict")

        # 创建调查版本
        status, iv = self.coord.request("POST", "/investigations", {"label": "HTTP 初版"})
        self.assertEqual(status, 201, iv)
        n = iv["number"]

        # 时间线：统一轴顺序正确，原始时间保留
        status, timeline = self.analyst.request("GET", f"/investigations/{n}/timeline")
        self.assertEqual(status, 200)
        ids = [e["evidence_id"] for e in timeline["events"]]
        self.assertEqual(
            ids, ["EV-VEH-01", "EV-CLOUD-01", "EV-RSU-01", "EV-VEH-02", "EV-WIT-01"]
        )
        impact = next(e for e in timeline["events"] if e["evidence_id"] == "EV-VEH-02")
        self.assertEqual(impact["common_time"],
                         (T0 + timedelta(milliseconds=2800)).isoformat())
        self.assertNotEqual(impact["source_time"], impact["common_time"])
        self.assertTrue(timeline["report_fingerprint"].startswith("sha256:"))

        # 证据清单
        status, listing = self.analyst.request("GET", f"/investigations/{n}/evidence")
        self.assertEqual(status, 200)
        self.assertEqual(len(listing["evidence"]), 5)
        self.assertTrue(all(e["receipt_fingerprint"] for e in listing["evidence"]))

        # 先签封（撤回不应影响已签封的证据包）
        status, package = self.coord.request("POST", "/packages", {
            "package_id": "PKG-HTTP-1", "refs": refs,
        })
        self.assertEqual(status, 201, package)
        # 并发/重复签封 -> 409
        status, body = self.coord.request("POST", "/packages", {
            "package_id": "PKG-HTTP-1", "refs": refs[:2],
        })
        self.assertEqual(status, 409)
        # analyst 无权签封
        status, body = self.analyst.request("POST", "/packages", {
            "package_id": "PKG-HTTP-2", "refs": refs[:1],
        })
        self.assertEqual(status, 403)

        # 撤回 -> 新版本清单少一份，旧版本与证据包不变
        status, _ = self.coord.request("POST", "/evidence/withdraw", {
            "ref": {"evidence_id": "EV-WIT-01", "version": 1},
            "reason": "翻供撤回",
        })
        self.assertEqual(status, 200)
        status, iv2 = self.coord.request("POST", "/investigations", {"label": "HTTP 撤回后"})
        self.assertEqual(status, 201)
        status, timeline2 = self.analyst.request(
            "GET", f"/investigations/{iv2['number']}/timeline"
        )
        self.assertEqual(len(timeline2["events"]), 4)
        self.assertEqual(timeline2["excluded"][0]["status"], "withdrawn")
        # 旧版报告指纹未变
        status, old_timeline = self.analyst.request(
            "GET", f"/investigations/{n}/timeline"
        )
        self.assertEqual(old_timeline["report_fingerprint"], timeline["report_fingerprint"])
        # 已签封证据包内容指纹也不受撤回影响
        status, pkg_after = self.coord.request("GET", "/packages/PKG-HTTP-1")
        self.assertEqual(pkg_after["package_fingerprint"], package["package_fingerprint"])

        # 移交与解除保全
        status, moved = self.coord.request("POST", "/packages/PKG-HTTP-1/transfer", {
            "to_actor_id": "custodian-zhou", "note": "入库",
        })
        self.assertEqual(status, 200)
        self.assertEqual(len(moved["custody"]), 2)
        status, body = self.coord.request("POST", "/packages/PKG-HTTP-1/release", {})
        self.assertEqual(status, 403)  # coordinator 无解除保全权限
        status, released = self.custodian.request("POST", "/packages/PKG-HTTP-1/release",
                                                  {"note": "结案"})
        self.assertEqual(status, 200)
        self.assertEqual(released["status"], "released")
        self.assertEqual(released["package_fingerprint"], package["package_fingerprint"])

        # 导出：载荷可解析、指纹可比对
        status, exported = self.auditor.request("POST", "/packages/PKG-HTTP-1/export", {})
        self.assertEqual(status, 200)
        payload = json.loads(base64.b64decode(exported["data_base64"]))
        self.assertEqual(payload["package"]["package_id"], "PKG-HTTP-1")
        self.assertEqual(len(payload["receipts"]), 5)

        # 审计链：仅 admin 可取，且校验通过
        status, body = self.analyst.request("GET", "/audit")
        self.assertEqual(status, 403)
        status, audit = self.admin.request("GET", "/audit")
        self.assertEqual(status, 200)
        self.assertTrue(audit["verified"])
        self.assertGreater(len(audit["entries"]), 10)
        self.assertTrue(audit["head_fingerprint"].startswith("sha256:"))

    def test_missing_actor_headers_rejected(self):
        req = urllib.request.Request(self.base_url + "/health")
        # /health 本不要求角色；用一个受保护端点验证
        req = urllib.request.Request(self.base_url + "/investigations", method="GET")
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            urllib.request.urlopen(req, timeout=5)
        self.assertEqual(ctx.exception.code, 403)


if __name__ == "__main__":
    unittest.main()
