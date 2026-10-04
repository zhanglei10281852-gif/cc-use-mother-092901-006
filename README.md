# 智能车辆事故证据封存与时间线服务

路口碰撞事故中，车端日志、路侧感知、云端决策和人工笔录来自时钟各异的设备，
后补材料还可能推翻最初的事件顺序。本服务提供一套 Python 实现，解决三件事：

1. **每份材料可追溯**：登记来源、摘要、来源时钟原始读数、采集区间、接收批次与
   内容指纹（SHA-256），接收即生成不可变收据；
2. **事件可解释地映射到统一时间轴**：校准规则版本化，每次换算都给出所用规则、
   参数与依据，原始时间原样保留；校准规则变化只产生新版本，不改写既往结论；
3. **封存与保全全程可审计**：证据包签封后不得增删，补充/更正只能形成关联版本；
   访问、导出、移交、解除保全都受角色权限控制并写入哈希链审计日志。

## 不可变模型

| 对象 | 不变性保证 |
|---|---|
| 收据 `Receipt` | 接收即算指纹；同一字节内容重复接收返回 `409/conflict`，不入登记 |
| 证据版本 `EvidenceRef(id, version)` | 更正通过 `supersedes` 链接到新版本；旧版原样保留并在后续调查版本中标记 `superseded` |
| 撤回 `WithdrawalRecord` | 只追加撤回理由，不删除任何字节；已撤回证据不得签封 |
| 校准版本 `CalibrationVersion` | 规则成组冻结并链向前一版指纹；支持恒定偏差与线性（锚点+频偏）模型 |
| 调查版本 `InvestigationVersion` | 冻结「时点 + 校准版本 + 证据成员快照」，指纹链式相连 |
| 时间线报告 `TimelineReport` | 指纹只取决于调查版本与内容，任何时刻重新生成指纹一致，可离线 `verify_report` |
| 证据包 `EvidencePackage` | 签封指纹只覆盖签封时内容；移交只追加保管链，解除保全只改状态，均不改签封指纹 |
| 审计链 `AuditLog` | 每条记录含前一条指纹，`verify()` 可发现任何插入/删除/篡改（含被拒绝的操作） |

## 运行

```bash
python3 -m unittest discover -s tests -v   # 36 个测试
python3 -m compileall -q src tests run_cli.py
python3 run_cli.py                          # 端到端冒烟
python3 -m incident_evidence.api            # 启动 HTTP 服务（默认 127.0.0.1:8080）
```

## HTTP API

所有请求需携带 `X-Actor-Id` 与 `X-Role` 头。角色：
`coordinator`（接收/签封/导出/移交）、`analyst`（接收/查看/导出）、
`auditor`（查看/导出）、`custodian`（接收/移交/解除保全）、`admin`（审计）。

```
POST /evidence                        接收证据（content_base64 传原始字节）
POST /evidence/withdraw               撤回指定版本（需理由）
POST /calibrations                    登记新一版校准规则
POST /investigations                  创建调查版本（可指定 calibration_version/as_of）
GET  /investigations                  调查版本清单
GET  /investigations/{n}/timeline     指定调查版本的统一时间线报告
GET  /investigations/{n}/evidence     指定调查版本的证据清单（含排除项）
POST /packages                        签封证据包（重复签封同 ID 返回 409）
GET  /packages/{id}                   证据包与保管链
POST /packages/{id}/transfer          移交（仅当前保管人）
POST /packages/{id}/release           解除保全（需 release_hold 权限）
POST /packages/{id}/export            导出自描述规范字节流与指纹
GET  /audit                           审计链复核与导出（仅 admin）
```

时间线事件同时包含 `source_time`（原始时钟读数）、`common_time`（统一时间轴）、
`rule_id` 与人类可读的 `explanation`，采集区间也给出原始/统一两套端点。

## 测试覆盖的关键不变量

- **重复接收**：同内容并发接收 12 次，恰好 1 次入登记，其余拒绝且审计留痕；
- **校准规则变化**：精校准 v2 让路侧事件与碰撞事件先后翻转，但引用 v1 的既有
  报告指纹逐字节不变，仍可离线复核；
- **证据撤回与更正**：只影响之后创建的调查版本；旧报告、已签封证据包指纹不变；
- **并发签封**：16 个线程同时签封同一证据包 ID，恰好 1 次成功；
- **权限与审计**：越权操作被拒绝并记录；篡改审计链/报告/导出物均被 `verify` 检出。

## 目录

```
src/incident_evidence/
  contracts.py     领域契约（证据、时钟、采集区间、版本引用、生命周期）
  fingerprints.py  规范化 JSON 序列化与 SHA-256 指纹
  clock.py         可解释、可版本化的时钟校准
  audit.py         角色权限与哈希链审计
  service.py       接收/撤回/更正、调查版本、签封/移交/解除保全、时间线报告
  api.py           标准库 ThreadingHTTPServer 实现的 HTTP API
tests/             单元、并发与 HTTP 端到端测试 + 事故夹具
```
