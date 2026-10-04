"""命令行冒烟：接收 -> 校准 -> 调查版本 -> 时间线 -> 签封 -> 导出复核。"""

import json
import sys
from datetime import timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent / "src"))
sys.path.insert(0, str(Path(__file__).parent))

from incident_evidence.service import EvidenceService
from tests.fixtures import T0, actors, rules_v2, seed


def main() -> None:
    service = EvidenceService()
    coord = actors()["coordinator"]
    auditor = actors()["auditor"]

    receipts = seed(service, coord)
    iv1 = service.create_investigation_version(coord, "初版：粗校准时间线")
    report1 = service.build_timeline_report(auditor, iv1.number)

    service.register_calibration(coord, rules_v2(), "厂商复核精校准")
    iv2 = service.create_investigation_version(coord, "再版：精校准时间线")
    report2 = service.build_timeline_report(auditor, iv2.number)

    package = service.seal_package(
        coord, "PKG-SMOKE-01", [r.ref for r in receipts.values()]
    )
    bundle = service.export_package(auditor, "PKG-SMOKE-01")
    EvidenceService.verify_export(bundle)
    service.audit.verify()

    def row(event):
        return {
            "证据": event.evidence_id,
            "原始时钟读数": event.source_time.isoformat(),
            "统一时间": event.common_time.isoformat(),
            "校准规则": event.rule_id,
        }

    summary = {
        "v1 时间线": [row(e) for e in report1.events],
        "v2 时间线": [row(e) for e in report2.events],
        "v1 报告指纹": report1.report_fingerprint,
        "v2 报告指纹": report2.report_fingerprint,
        "证据包指纹": package.package_fingerprint,
        "导出指纹": bundle.export_fingerprint,
        "审计链": "核验通过",
        "审计条目数": len(service.audit.entries()),
    }
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    # v2 中碰撞与路侧的先后发生翻转
    v2_ids = [e.evidence_id for e in report2.events]
    assert v2_ids.index("EV-VEH-02") < v2_ids.index("EV-RSU-01")
    v1_first = report1.events[0]
    assert v1_first.evidence_id == "EV-VEH-01"
    assert v1_first.common_time == T0 + timedelta(milliseconds=1_000)


if __name__ == "__main__":
    main()
