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
| POST | `/v1/wallets/{wallet_id}/sign-requests` | 创建签名请求审批单 `{"id", "message"}` |
| GET  | `/v1/wallets/{wallet_id}/sign-requests/{id}` | 查询审批单 |
| POST | `/v1/wallets/{wallet_id}/sign-requests/{id}/approve` | 批准 `{"approver_id", "reason"?}` |
| POST | `/v1/wallets/{wallet_id}/sign-requests/{id}/reject` | 拒绝 `{"approver_id", "reason"?}` |
| GET  | `/v1/wallets/{wallet_id}/audit-events` | 查询审计事件（seq 升序，分页 `from_seq`/`limit`） |
| POST | `/v1/wallets/{wallet_id}/sign` | 提交两份份额签名，返回聚合 `signature` |
| POST | `/v1/wallets/{wallet_id}/share-rotations` | 准备份额轮换 `{"rotation_id"}` |
| GET  | `/v1/wallets/{wallet_id}/share-rotations/{rotation_id}` | 查询轮换状态 |
| POST | `/v1/wallets/{wallet_id}/share-rotations/{rotation_id}/activate` | 激活轮换 |

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
  清理备份；服务启动时先把崩溃残留的未完成激活（`activating`）
  回滚为 `prepared`，轮换状态跨重启持久。
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
- 崩溃时停留在 `activating` 的现场回滚为 `prepared`（恢复原钱包元
  数据与旧份额）；已提交 `active` 的暂存与备份被清理。恢复与孤儿
  清理不产生审计事件，审计 seq 跨重启接续、连续不重号。

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
`share-sign` 用 `--data-dir` 指向服务端数据目录。

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
  写入采用临时文件 + 原子替换。
- **日志**：访问日志只记录 `方法 路径 -> 状态码`，绝不读取或记录请求/响应体。
