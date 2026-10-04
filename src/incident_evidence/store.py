"""内存证据仓库。

内容寻址：记录按 record_hash 存取，签封包钉死 record_hash 后，
后续更正/撤回都不会改变已签封版本指向的内容。
所有写路径都有防御性检查；并发串行化由服务层的锁保证。
"""

from .contracts import (
    CalibrationProfile,
    CustodyRecord,
    EvidencePackage,
    EvidenceRecord,
    ReceivingBatch,
)
from .errors import InvalidStateError


class EvidenceStore:
    def __init__(self) -> None:
        self.records: dict[str, EvidenceRecord] = {}            # record_hash -> record
        self.revisions: dict[tuple[str, str], list[str]] = {}   # (调查, 证据号) -> [record_hash]
        self.packages: dict[str, list[EvidencePackage]] = {}    # 调查 -> 按版本有序的签封包
        self.profiles: dict[str, dict[int, CalibrationProfile]] = {}
        self.batches: dict[str, ReceivingBatch] = {}
        self.custody: dict[str, list[CustodyRecord]] = {}
        self.holds: dict[str, str] = {}                         # 调查 -> active | released

    # -- 证据记录 ----------------------------------------------------------

    def put_record(self, record: EvidenceRecord) -> None:
        self.records[record.record_hash] = record
        key = (record.investigation_id, record.evidence_id)
        hashes = self.revisions.setdefault(key, [])
        if record.record_hash not in hashes:
            hashes.append(record.record_hash)

    def update_record(self, record: EvidenceRecord) -> None:
        """更新保管状态等元数据；record_hash 不覆盖状态，因此键不变。"""
        if record.record_hash not in self.records:
            raise InvalidStateError(f"记录不存在: {record.record_hash}")
        self.records[record.record_hash] = record

    def revision_hashes(self, investigation_id: str, evidence_id: str) -> list[str]:
        return list(self.revisions.get((investigation_id, evidence_id), []))

    def evidence_ids(self, investigation_id: str) -> list[str]:
        return sorted(
            evidence_id
            for (inv, evidence_id) in self.revisions
            if inv == investigation_id
        )

    # -- 签封包 ------------------------------------------------------------

    def append_package(self, package: EvidencePackage) -> None:
        versions = self.packages.setdefault(package.investigation_id, [])
        if any(p.version == package.version for p in versions):
            raise InvalidStateError(
                f"调查 {package.investigation_id} 的版本 {package.version} 已存在，签封包不可改写"
            )
        versions.append(package)

    # -- 校准档案 ----------------------------------------------------------

    def put_profile(self, profile: CalibrationProfile) -> None:
        versions = self.profiles.setdefault(profile.profile_id, {})
        if profile.version in versions:
            raise InvalidStateError(f"校准档案 {profile.ref} 已存在，不可改写")
        versions[profile.version] = profile

    # -- 保管 --------------------------------------------------------------

    def append_custody(self, record: CustodyRecord) -> None:
        self.custody.setdefault(record.investigation_id, []).append(record)
