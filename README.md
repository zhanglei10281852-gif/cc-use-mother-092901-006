# 智能车辆事故证据封存与时间线服务

面向自动驾驶测试车事故调查的证据保全系统：多来源材料（车端日志、路侧感知、
云端决策、人工笔录）统一登记接收，通过可解释的时钟校准映射到统一时间轴，
证据包签封后不可改写，全部敏感操作留痕于哈希链审计日志。

## 设计要点

- **登记接收**：每份材料记录来源、摘要、采集区间、接收批次与完整性指纹；
  内容以 `record_hash` 寻址。同一证据号 + 同一指纹的重复接收幂等返回；
  内容变化只能形成带 `supersedes` 链接的更正修订，历史永不覆盖。
- **可解释时钟校准**：校准档案（`CalibrationProfile`）不可变、按版本发布；
  每条规则记录偏移、漂移、测量方式与依据。事件映射输出校准轨迹
  （`CalibrationTrace`），统一时间可复算，原始时间始终保留。
- **签封与版本链**：签封包（`EvidencePackage`）钉死证据修订与校准档案版本，
  `seal_hash` 覆盖全内容；一经签封不得改写，补充/更正/撤回只能形成
  `supersedes` 串起的关联版本。撤回自动产生新版本，旧版本如实保留历史。
- **权限与审计**：登记、查看、签封、导出、移交、解除保全等操作均需权限；
  允许与拒绝都写入仅追加的哈希链审计日志，篡改可被 `verify_chain` 发现。
- **可验证报告**：`generate_timeline` 产出指定调查版本的时间线与证据清单，
  `report_hash` 只覆盖决定性内容，重复生成逐字节一致；
  `verify_report` 通过自洽性、签封完整性、重放一致性、审计链四项检查。

## 模块结构

```
src/incident_evidence/
  contracts.py   领域契约（提交、记录、批次、校准、签封包、报告、审计）
  hashing.py     规范化 JSON 与内容摘要（可复算验证的基础）
  clock.py       可解释时钟校准映射
  access.py      权限策略
  audit.py       哈希链仅追加审计日志
  store.py       内容寻址仓库（指纹去重、版本链）
  timeline.py    纯函数时间线重建（可重放）
  service.py     EvidenceService 对外 API（写操作锁内串行化）
  errors.py      异常体系
```

## API 速览

```python
service = EvidenceService(grants={"coordinator": {...}}, now_fn=None)
service.register_evidence(actor, submission)          # 登记（幂等/更正修订）
service.publish_calibration_profile(actor, id, rules) # 发布校准档案新版本
service.seal_package(actor, investigation_id)         # 签封（内容不变则幂等）
service.withdraw_evidence(actor, inv, evidence_id, reason)  # 撤回并生成关联版本
service.generate_timeline(actor, inv, version)        # 时间线 + 证据清单
service.verify_report(report)                         # 四项验证，无需权限
service.export_package(actor, inv, version)           # 导出（需权限）
service.transfer_custody(actor, inv, to)              # 移交（需权限）
service.release_hold(actor, inv, reason)              # 解除保全（禁写不禁读）
```

## 运行

```bash
python -m unittest discover -s tests -v   # 测试
python -m compileall -q src tests run_cli.py  # 编译检查
python run_cli.py                          # 端到端冒烟演示
```

`tests/test_robustness.py` 证明四类扰动不破坏既有报告的可验证性：
重复接收、校准规则变化、证据撤回、并发签封。
