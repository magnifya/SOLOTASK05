# SOLOTASK05 门限签名托管后端

用 Python 加 cryptography 实现的两方门限（2-of-2）Ed25519 签名托管后端，
对外提供 HTTP 服务与命令行入口。

## 密码学设计

- 建钱包时生成两个**彼此独立**的 Ed25519 密钥对（份额 `share-1`、`share-2`）。
  系统中任何位置都**不存在完整私钥**，只有两个 32 字节份额私钥。
- 钱包公钥 `public_key` ＝ 两个份额公钥按序拼接（64 字节，hex）。
- 每个份额用自己的私钥对 `signing_request_id` 与 `message` 的**直接拼接**
  （UTF-8）做 Ed25519 签名。
- 门限签名 `signature` ＝ 两个份额签名按 `share-1, share-2` 顺序拼接
  （128 字节，hex）。任何持有 `public_key` 的人都可以把公钥与签名各拆成
  两半，用标准 Ed25519 分别独立验证。

## HTTP 接口

| 方法 | 路径 | 说明 |
| ---- | ---- | ---- |
| POST | `/v1/wallets` | 建钱包，请求体 `{"wallet_id", "shares"}`，`shares` 必须为 2 |
| GET  | `/v1/wallets/{wallet_id}` | 返回 `public_key` 与 `created_at` |
| PUT  | `/v1/wallets/{wallet_id}/approval-policy` | 设置审批策略 `{"required_approvals": 1\|2, "timeout_seconds": >0}` |
| PUT  | `/v1/wallets/{wallet_id}/transaction-policy` | 设置冷热钱包交易策略 `{"mode":"hot"\|"cold","max_delta":正整数,"allowed_assets":[...]}` |
| GET  | `/v1/wallets/{wallet_id}/transaction-policy` | 查询冷热钱包交易策略（未配置 404） |
| POST | `/v1/wallets/{wallet_id}/sign-requests` | 创建签名请求审批单 `{"id", "message"}` |
| GET  | `/v1/wallets/{wallet_id}/sign-requests/{id}` | 查询审批单 |
| POST | `/v1/wallets/{wallet_id}/sign-requests/{id}/approve` | 批准 `{"approver_id", "reason"?}` |
| POST | `/v1/wallets/{wallet_id}/sign-requests/{id}/reject` | 拒绝 `{"approver_id", "reason"?}` |
| GET  | `/v1/wallets/{wallet_id}/audit-events` | 查询审计事件（seq 升序，分页 `from_seq`/`limit`） |
| POST | `/v1/wallets/{wallet_id}/sign` | 提交两份份额签名，返回聚合 `signature` |
| POST | `/v1/wallets/{wallet_id}/share-rotations` | 准备份额轮换 `{"rotation_id"}` |
| GET  | `/v1/wallets/{wallet_id}/share-rotations/{rotation_id}` | 查询轮换状态 |
| POST | `/v1/wallets/{wallet_id}/share-rotations/{rotation_id}/activate` | 激活轮换 |
| POST | `/v1/wallets/{wallet_id}/asset-operations` | 创建资产操作 `{"operation_id", "asset_id", "delta"}` |
| POST | `/v1/wallets/{wallet_id}/asset-operations/{operation_id}/commit` | 提交资产操作 |
| GET  | `/v1/wallets/{wallet_id}/assets/{asset_id}` | 查询资产 `balance` 与 `version` |

状态码：

- 建钱包成功 `201`，返回 `wallet_id`、`public_key`、`share_ids`；
  `shares != 2` 返回 `400`；`wallet_id` 重复返回 `409`。
- 查询成功 `200`；钱包不存在 `404`。
- 签名两份齐备且全部校验通过返回 `201`；缺一份、份额重复/未知、
  签名非法或校验失败返回 `400`；钱包不存在 `404`。
- 同一 `signing_request_id` 重复提交幂等返回已有签名（`200`）。

## 审批工作流（可选）

- `PUT approval-policy`：`required_approvals` 必须为整数 1 或 2，
  `timeout_seconds` 必须为正整数；成功 `200`，参数非法 `400`，
  钱包不存在 `404`。
- `POST sign-requests`：`id`、`message` 均须非空；未设策略 `409`；
  首次创建 `201`；同 id 同文幂等 `200`；同 id 异文 `409`。
- `GET sign-requests/{id}` 返回 `{id, message, state, approvers, count,
  req, t0, t1, reason}`；`state` 为 `pending | approved | rejected |
  expired | signed`。任何操作前会把已超时的 `pending` 单持久化为
  `expired`（懒过期）。
- `approve` / `reject`：`approver_id` 必填（非空白字符串）；`reason`
  可选，字符串且不超过 1024 字符；类型错误、空白、布尔值一律 `400`。
  `pending` 单批准返回 `200`（同一 approver 重复批准不计数，达到
  `required_approvals` 门槛转为 `approved`）；拒绝返回 `200` 并转为
  `rejected`；对非 `pending` 单操作返回 `409`。
- 设置策略后，`POST /sign` 要求存在同 id、同 message 且已 `approved`
  的审批单，两份额签名齐备返回 `201` 并把审批单推进为 `signed`；
  未设策略时行为不变（首签 `201`，重放 `200`）。

## 冷热钱包交易策略（可选）

`PUT /v1/wallets/{wallet_id}/transaction-policy` 设置每钱包的冷热钱包
交易策略，请求体与成功响应（`200`）同为

```json
{"mode": "hot|cold", "max_delta": 正整数,
 "allowed_assets": ["BTC", "ETH"]}
```

- `mode` 必须是字符串 `"hot"` 或 `"cold"`；`max_delta` 必须是正整数
  （拒绝布尔、0、负数、小数）；`allowed_assets` 必须是**非空数组**，
  每项匹配 `[A-Za-z0-9_-]{1,128}`，**去重**（重复项 `400`）。
  类型错误、空值、重复或非法资产一律 `400`；钱包不存在 `404`。
- 策略状态与 `transaction_policy_updated` 事件在每钱包事务锁内原子
  持久化（失败回滚策略，不产生事件或 seq 缺口）；**同值更新也记事件**，
  `details` 恰为 `mode`/`max_delta`/`allowed_assets` 三项。
- `GET .../transaction-policy`：已配置 `200` 同体，未配置 `404`。
  策略文件（`transaction-policies/<wallet_id>.json`）只含标识与整数，
  重启后保持。
- **对资产操作的影响**：未配置策略时行为完全不变。配置后，pending
  资产操作**首次创建**按创建时刻的策略检查：`asset_id` 必须在
  `allowed_assets` 白名单内且 `abs(delta) <= max_delta`，否则 `409`，
  且账本、`version`、操作状态、审计与幂等结果均不变（检查先于任何
  写入）；`committed` 重放 `200` 同体、不再校验；策略后续更新不影响
  已存在的 pending 操作，重放也不按新策略复查。
- **对签名的影响**：
  - `hot` 沿用审批章节既有规则：配置了审批策略才要求 approved 审批单，
    未配置审批策略时行为不变；
  - `cold` 的**首签**必须存在同 `id`、同 `message` 且 `approved` 的
    审批单；未配置审批策略（无法建单）、无单或单未 `approved` 一律
    `409`；签名重放 `200` 且不再校验。

## 审计事件

`GET /v1/wallets/{wallet_id}/audit-events` 返回
`{"wallet_id": ..., "events": [...]}`，事件按 `seq` **升序**。
查询参数 `from_seq`、`limit` 均为正整数，默认 `1` / `1000`，
`limit` 上限 `1000`；非法（0、负数、小数、非数字、超限）返回 `400`，
钱包不存在返回 `404`。审计查询是纯只读，**不触发** pending 懒过期。

每条事件字段为
`seq, type, at, request_id, actor_id, reason, details`，
`at` 为 UTC（`...Z`），不适用的字段取 `null`。`seq` 从 1 起、
落盘后单调递增；服务重启后续写，接续文件中已有最大 seq。

| 类型 | 何时记录 | request_id / actor_id / reason / details |
| ---- | ---- | ---- |
| `policy_updated` (P) | 策略设置成功，**同值更新也记** | rid/actor/reason 为 null；`d={required_approvals, timeout_seconds, operation: created\|updated}` |
| `request_created` (C) | 审批单**首次创建** | `rid=id`，其余 null；`d={message}`。同 id 异文 `409`，重放不记 |
| `request_approved` (A) | **首次**批准（同一 approver 重复批准不计数、不记） | `rid=id, a=approver_id, r=传入\|null`；`d={count, req, state}` |
| `request_rejected` (R) | **首次**拒绝 | `rid=id, a=approver_id, r=传入\|null`；`d={count, req, state: rejected}` |
| `request_expired` (E) | pending 单超时被懒过期 | `rid=id`，actor/reason 为 null；`d={state: expired}`。GET 审批单、approve、reject、sign 触发，每个单只记一次 |
| `request_signed` (S) | **首次**签名成功 | `rid=id`，actor/reason 为 null；`d={message, state: signed}`。重放 `200` 不记 |

对终态单（approved/rejected/expired/signed）再 approve/reject 返回 `409`
且不记事件；签名重放、审批单创建重放均不产生事件。

## 份额轮换灾备

`POST /v1/wallets/{wallet_id}/share-rotations` 准备一次份额轮换：

- 请求体 `{"rotation_id"}`，`rotation_id` 必须匹配
  `[A-Za-z0-9_-]{1,128}`，否则 `400`；钱包不存在 `404`。
- 首次准备生成两份新份额，`share_ids` 为 `{rotation_id}-share-1` 与
  `{rotation_id}-share-2`，新份额私钥只写入**暂存文件**
  （`rotation-staging/<wallet_id>/<rotation_id>/`，一份一个文件），
  在激活前绝不触碰在用份额与钱包元数据。成功 `201`，返回
  `{rotation_id, state: prepared, share_ids, public_key}`。
- 每钱包同时只允许一个 `prepared` 轮换，冲突 `409`；
  同 `rotation_id` 重放返回 `200` 且不重新生成。
- `GET .../share-rotations/{rotation_id}` 查询轮换（`200`），
  未知轮换 `404`。
- `POST .../share-rotations/{rotation_id}/activate` 仅 `prepared`
  可激活：在每钱包事务锁内原子替换份额文件、钱包 `shares`/`public_key`
  与轮换状态，成功 `201`（`state: active`）；`active` 重放 `200`；
  其余状态 `409`。激活成功后删除暂存的新份额文件与备份。
- **失败回滚**：激活任一环节失败，回滚份额文件、公钥与轮换状态并
  清理备份；崩溃恢复以 `share_rotation_activated` 事件为唯一提交点——
  事件未落盘（含状态已写到 `active`）重启回滚为 `prepared`，事件已
  落盘则保持 `active` 前滚补齐，轮换状态跨重启持久（详见"多进程与
  故障恢复"）。
- 激活后未首签的签名请求必须使用新 `share_ids`，旧份额提交返回
  `400`；已首签的请求重放仍 `200`。

轮换审计事件（七字段 `seq, type, at, request_id, actor_id, reason,
details`，`seq` 连续，`request_id`/`actor_id`/`reason` 为 `null`）：

| 类型 | 何时记录 | details |
| ---- | ---- | ---- |
| `share_rotation_prepared` | 轮换**首次准备** | `{rotation_id, share_ids, public_key}` |
| `share_rotation_activated` | 轮换**首次激活** | `{rotation_id, share_ids, public_key, previous_public_key}` |

`details` 只含标识与公钥，绝不含私钥；状态变更与事件追加在每钱包
事务锁内原子完成，失败不产生事件或 seq 缺口；重放不重复记事件。

**状态/事件原子性**：状态变更与事件追加在每钱包事务锁内完成；
若事件落盘失败，则回滚本次状态（删除新建策略/审批单/签名，或恢复
更新前的旧值/原 pending 状态），保证状态与事件一致。

## 资产账本

每个钱包维护一本资产账本（`assets/<wallet_id>.json`）：资产操作
（asset-operations，状态机 `pending | committed`）与每个资产的
`balance`/`version` 存放于同一文件、原子写入；文件只含标识与整数，
不含任何私钥材料。

- `POST asset-operations`：请求体 `{"operation_id", "asset_id",
  "delta"}`。两个 ID 均须非空且匹配 `[A-Za-z0-9_-]{1,128}`，`delta`
  必须是非布尔、非零整数；参数非法 `400`，钱包不存在 `404`。
  首次创建 `201`，返回 `R={operation_id, asset_id, delta, state,
  balance, version}`（`state: pending`，`balance`/`version` 为资产
  在创建时刻的账本快照）；同 `operation_id` 同参数重放 `200` 同体，
  异参数 `409`；`operation_id` 钱包内唯一。创建不记审计事件。
- `POST .../commit`：仅 `pending` 可提交。在每钱包事务锁内检查
  `balance + delta >= 0`：不足 `409`，状态不变、可重试；成功则原子
  改余额、`version+1`、状态转 `committed`，`201` 返回 R。并发提交
  恰一个 `201`，其余幂等重放 `200`；`committed` 重放 `200` 同体，
  不重复改账。操作不存在 `404`。
- `GET assets/{asset_id}`：返回 `{asset_id, balance, version}`；
  资产无任何已提交操作 `404`，钱包不存在 `404`。
- 重启后 `pending`/`committed` 状态与幂等性保持，`version` 单调
  递增、不回退、不重号。

账本审计事件（七字段，`seq` 连续）：

| 类型 | 何时记录 | request_id / actor_id / reason / details |
| ---- | ---- | ---- |
| `asset_operation_committed` | 操作**首次提交成功** | `rid=operation_id`，actor/reason 为 null；`d=R`（committed 视图）。重放与余额不足失败均不记 |
| `transaction_policy_updated` | 交易策略设置成功，**同值更新也记** | rid/actor/reason 为 null；`d={mode, max_delta, allowed_assets}`。事件追加失败回滚策略，无事件、无 seq 缺口 |

提交是一个**可恢复事务**（在每钱包跨进程事务锁内）：先写只含标识与
整数的提交意图（`asset-intents/<wallet_id>/<operation_id>.json`），再
原子改账本（状态转 committed、`balance`、`version+1`），随后追加唯一
的 `asset_operation_committed` 事件（`details` 即 committed 视图 R），
成功后删除意图。任一落盘阶段被强制终止，同一 data-dir 重启（或下一次
持锁访问）先恢复：**事件已持久化则保留事件并按 R 把账本前滚补齐**为
唯一 committed 结果；**事件未持久化则恢复 pending 与提交前余额/版本**，
事件从未分配 seq，故无事件、无 seq 缺口、可重试。恢复后不会出现提交
无事件、事件与余额不符、重复 version 或重复事件；意图文件不含私钥。

## 多进程与故障恢复

- 多个服务进程可**共用同一 data-dir**：策略、审批单、签名、份额轮换
  与审计追加都在每钱包跨进程事务锁（`locks/<wallet_id>.lock`，
  fcntl.flock）内提交；进程异常退出后内核自动释放文件锁，后续进程
  不会被陈旧锁阻塞。跨进程并发或重启交错时，同一操作只有一个首次
  提交，其余按幂等重放处理。
- 启动恢复在每个钱包的事务锁内扫描轮换残留：仅当轮换记录为
  `prepared`、暂存目录名与 `rotation_id` 一致、目录内恰有记录中两个
  `share_ids` 的份额文件、JSON 可解析且 `share_id`、`public_key`、
  32 字节私钥相互匹配时保留；其余目录与无效记录安全删除，不改动在
  用钱包，不留私钥副本。
- **激活以 `share_rotation_activated` 事件为唯一提交点**：事件已落盘
  则激活不可撤回——无论轮换记录停在 `activating` 还是 `active`、暂存
  或备份是否已清理，恢复都把在用份额、钱包 `shares`/`public_key`
  与轮换状态前滚补齐为唯一 `active` 结果（新份额逐份做密码学校验，
  绝不猜写密钥），并清掉全部暂存/备份残留，且不重复记事件；
  事件未落盘则激活未生效——即使轮换状态已写到 `active`，也恢复旧
  公钥与旧份额、把轮换置回 `prepared`，保留经校验有效的暂存份额。
  仅当换入已发生却又缺失回滚所需备份等无法安全对账时，恢复失败、
  **阻止服务就绪**（`serve` 以非零码退出；常驻进程对该钱包的请求
  返回 `503`），绝不静默跳过或暴露半完成状态。恢复与孤儿清理不产生
  审计事件，审计 seq 跨重启接续、连续不重号。
- 资产提交的恢复在同一把钱包事务锁内完成：启动时扫描 `asset-intents`
  残留逐一对账；常驻进程在持锁的查询/创建/提交前自愈他进程崩溃遗留
  的意图（轮换现场同样在持锁的查询/签名/激活/审批/资产操作前自愈）。
  多进程同时启动或提交同一操作时，恢复与提交按钱包串行，最终仅一个
  首次 `201`，其余 `200` 同体；恢复完成前查询与重放都读不到半
  完成状态；意图损坏且无法安全对账时同样阻止就绪/返回 `503`。

## 安装

```bash
pip install -r requirements.txt   # 唯一运行依赖：cryptography
```

## 启动服务

```bash
python -m threshold_wallet.cli serve --host 0.0.0.0 --port 8080 --data-dir ./data
```

## 命令行

`create` / `sign` / `show` 与三个接口一一对应，成功打印单行 JSON 到 stdout，
失败打印单行 JSON 到 stderr 并以非零码退出。

```bash
# 建钱包
python -m threshold_wallet.cli create --wallet-id alice --shares 2

# 查询
python -m threshold_wallet.cli show --wallet-id alice

# 两个份额持有方各自在本地用本机房份额私钥生成份额签名（不经过网络）
S1=$(python -m threshold_wallet.cli share-sign --wallet-id alice --share-id share-1 \
     --signing-request-id req-1 --message pay-100 | python -c "import sys,json;print(json.load(sys.stdin)['signature'])")
S2=$(python -m threshold_wallet.cli share-sign --wallet-id alice --share-id share-2 \
     --signing-request-id req-1 --message pay-100 | python -c "import sys,json;print(json.load(sys.stdin)['signature'])")

# 收齐两份份额签名后提交
python -m threshold_wallet.cli sign --wallet-id alice --signing-request-id req-1 \
     --message pay-100 --signature share-1=$S1 --signature share-2=$S2
```

审批工作流对应的子命令为 `policy` / `request-create` / `request-show` /
`approve` / `reject`，同样支持 `--url` 与 `--wallet-id`，失败时打印单行
JSON 到 stderr 并以退出码 1 结束：

```bash
python -m threshold_wallet.cli policy --wallet-id alice \
     --required-approvals 2 --timeout-seconds 3600
python -m threshold_wallet.cli request-create --wallet-id alice \
     --signing-request-id req-1 --message pay-100
python -m threshold_wallet.cli approve --wallet-id alice \
     --signing-request-id req-1 --approver-id ops-1
python -m threshold_wallet.cli request-show --wallet-id alice \
     --signing-request-id req-1
```

可用 `--url` 指定服务地址（默认 `http://127.0.0.1:8080`），
`share-sign` 用 `--data-dir` 指向服务端数据目录：读取份额前会先在该
钱包事务锁内做懒恢复（自愈轮换/资产提交崩溃现场），再按当前在用份额
签名；恢复失败或份额不存在时输出单行 JSON 到 stderr 并非零退出。

## 测试

```bash
python -m unittest discover -s tests -v
```

覆盖：份额原语、持久化、全部 HTTP 状态码、幂等重放、聚合公钥独立验证，
以及磁盘/响应/日志的"无完整私钥"安全审计。

## 私钥安全边界

- **响应**：建钱包只返回 `share_ids` 与公钥，任何接口都不返回私钥。
- **磁盘**：钱包元数据文件不含任何私钥；两个份额私钥分文件存放
  （`shares/<wallet_id>/<share_id>.json`），轮换准备期的新份额私钥
  分文件暂存于 `rotation-staging/<wallet_id>/<rotation_id>/`，
  任何文件至多含一个份额私钥，从不存在两者拼接后的完整私钥。
  资产账本（`assets/<wallet_id>.json`）只含标识与整数，不含私钥。
  提交意图（`asset-intents/<wallet_id>/<operation_id>.json`）同样只含
  标识与整数，不含私钥。
  冷热钱包交易策略（`transaction-policies/<wallet_id>.json`）只含
  mode 标识、整数上限与资产标识，不含私钥。
  写入采用临时文件 + 原子替换。
- **日志**：访问日志只记录 `方法 路径 -> 状态码`，绝不读取或记录请求/响应体。
