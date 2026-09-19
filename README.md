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
| POST | `/v1/wallets/{wallet_id}/sign` | 提交两份份额签名，返回聚合 `signature` |

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
  （`shares/<wallet_id>/<share_id>.json`），任何文件至多含一个份额私钥，
  从不存在两者拼接后的完整私钥。写入采用临时文件 + 原子替换。
- **日志**：访问日志只记录 `方法 路径 -> 状态码`，绝不读取或记录请求/响应体。
