"""权限与审计：越权拒绝留痕、授权、移交、解除保全、审计哈希链。"""

import unittest
from dataclasses import replace

from support import (
    ADMIN,
    COORDINATOR,
    INVESTIGATION,
    OUTSIDER,
    VIEWER,
    Permission,
    make_service,
    publish_default_profile,
    register_standard_evidence,
)
from incident_evidence.errors import PermissionDeniedError


class AccessTests(unittest.TestCase):
    def setUp(self):
        self.service = make_service()
        publish_default_profile(self.service)
        register_standard_evidence(self.service)
        self.service.seal_package(COORDINATOR, INVESTIGATION)

    def test_denied_action_raises_and_is_audited(self):
        with self.assertRaises(PermissionDeniedError):
            self.service.generate_timeline(OUTSIDER, INVESTIGATION)
        denied = [e for e in self.service.audit_trail(COORDINATOR) if e.outcome == "denied"]
        self.assertTrue(any(e.actor == OUTSIDER for e in denied))

    def test_viewer_cannot_seal_or_export(self):
        with self.assertRaises(PermissionDeniedError):
            self.service.seal_package(VIEWER, INVESTIGATION)
        with self.assertRaises(PermissionDeniedError):
            self.service.export_package(VIEWER, INVESTIGATION)
        # 但查看时间线是允许的
        report = self.service.generate_timeline(VIEWER, INVESTIGATION)
        self.assertEqual(report.package_version, 1)

    def test_admin_can_grant_and_grantee_can_act(self):
        with self.assertRaises(PermissionDeniedError):
            self.service.export_package(OUTSIDER, INVESTIGATION)
        self.service.grant(ADMIN, OUTSIDER, Permission.PACKAGE_EXPORT)
        bundle = self.service.export_package(OUTSIDER, INVESTIGATION)
        self.assertEqual(bundle.exported_by, OUTSIDER)

    def test_non_admin_cannot_grant(self):
        with self.assertRaises(PermissionDeniedError):
            self.service.grant(COORDINATOR, OUTSIDER, Permission.PACKAGE_EXPORT)

    def test_export_requires_permission_and_is_audited(self):
        bundle = self.service.export_package(COORDINATOR, INVESTIGATION)
        self.assertEqual(len(bundle.bundle_hash), 64)
        self.assertEqual(len(bundle.records), 4)
        actions = [e.action for e in self.service.audit_trail(COORDINATOR)]
        self.assertIn("export_package", actions)

    def test_custody_transfer_chain(self):
        first = self.service.transfer_custody(COORDINATOR, INVESTIGATION, "交警物证科")
        self.assertEqual(first.from_custodian, "evidence-office")
        second = self.service.transfer_custody(COORDINATOR, INVESTIGATION, "司法鉴定中心")
        self.assertEqual(second.from_custodian, "交警物证科")
        self.assertEqual(self.service.current_custodian(INVESTIGATION), "司法鉴定中心")

    def test_release_hold_requires_permission(self):
        with self.assertRaises(PermissionDeniedError):
            self.service.release_hold(VIEWER, INVESTIGATION, "越权")
        self.service.release_hold(COORDINATOR, INVESTIGATION, "结案")
        self.assertEqual(self.service._store.holds[INVESTIGATION], "released")


class AuditChainTests(unittest.TestCase):
    def setUp(self):
        self.service = make_service()
        publish_default_profile(self.service)
        register_standard_evidence(self.service)
        self.service.seal_package(COORDINATOR, INVESTIGATION)
        self.service.generate_timeline(COORDINATOR, INVESTIGATION)

    def test_chain_is_intact_after_operations(self):
        self.assertTrue(self.service.audit_chain_intact())
        entries = self.service.audit_trail(COORDINATOR)
        self.assertEqual([e.seq for e in entries], list(range(1, len(entries) + 1)))

    def test_tampering_with_history_breaks_chain(self):
        entries = list(self.service._audit._entries)
        forged = replace(entries[2], detail="篡改：删除不利记录")
        self.service._audit._entries[2] = forged
        self.assertFalse(self.service.audit_chain_intact())

    def test_audit_view_requires_permission(self):
        with self.assertRaises(PermissionDeniedError):
            self.service.audit_trail(OUTSIDER)


if __name__ == "__main__":
    unittest.main()
