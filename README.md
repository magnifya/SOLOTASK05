# SOLOTASK05 门限签名托管后端

用 Python + cryptography 实现的两方门限（threshold）签名托管后端，提供 HTTP 服务与命令行入口。

## 设计说明

- 份额签名采用 **Ed25519**。建钱包时为两方各生成一把独立的 Ed25519 密钥，
  系统中**任何时刻都不存在"完整私钥"**：
  - 聚合公钥 = 两把份额公钥顺序拼接（64 字节，base64 输出）；
  - 聚合签名 = 两份份额签名按份额存储顺序拼接（128 字节，base64 输出）；
  - 校验时逐份额用各自公钥验证同一段待签名消息，任一份失败即整体失败。
- 各份额的待签名内容统一为 `signing_request_id` 的 UTF-8 编码与 `message`
  原始字节直接拼接。
- 每个钱包在磁盘上对应一个 JSON 文件（`--data-dir` 目录下），只保存：
  份额标识、份额私钥（32 字节种子，base64）、份额公钥、聚合公钥、创建时间，
  以及已完成的签名记录（用于幂等去重）。写入采用临时文件 + `os.replace`
  原子替换，文件权限 `0600`。
- **安全约束**：响应、磁盘、日志中都不会出现完整私钥（系统本身不产生它）。
  HTTP 访问日志只记录方法、路径、状态码、响应大小，绝不记录请求体。

## 接口

二进制字段（`message`、份额 `signature`、`public_key`、聚合 `signature`）
均使用 base64 编码。

### 创建钱包 `POST /v1/wallets`

请求：`{"wallet_id": "...", "shares": 2}`

- 成功 `201`：`{"wallet_id", "public_key", "share_ids"}`（`share_ids` 长度为 2）
- `shares != 2`：`400`
- `wallet_id` 已存在：`409`

### 提交份额签名 `POST /v1/wallets/{wallet_id}/sign`

请求：

```json
{
  "signing_request_id": "...",
  "message": "<base64>",
  "signatures": [
    {"share_id": "...", "signature": "<base64 份额签名>"},
    {"share_id": "...", "signature": "<base64 份额签名>"}
  ]
}
```

- 两份齐备且逐份额校验通过：`201`，返回 `{"signature": "<base64 聚合签名>"}`
- 缺份额、份额未知/重复、签名非法或校验失败：`400`
- 钱包不存在：`404`
- 同一 `signing_request_id` 重复提交：幂等返回已有聚合签名（`201`）

### 查询钱包 `GET /v1/wallets/{wallet_id}`

- 成功 `200`：`{"public_key", "created_at"}`
- 不存在：`404`

## 安装依赖

```bash
python3 -m pip install -r requirements.txt
```

仅依赖 `cryptography`；HTTP 服务与 CLI 均使用 Python 标准库（Python 3.10+）。

## 启动服务

```bash
python3 -m threshold_wallet.server --host 127.0.0.1 --port 8080 --data-dir ./data
```

## 命令行

服务端地址通过 `--server` 或环境变量 `THRESHOLD_WALLET_URL` 指定。
每个子命令打印单行 JSON，成功退出码 0，业务/HTTP 错误退出码 1，参数错误退出码 2。

```bash
# create -> POST /v1/wallets
python3 -m threshold_wallet.cli create my-wallet --shares 2

# show   -> GET /v1/wallets/{id}
python3 -m threshold_wallet.cli show my-wallet

# sign   -> POST /v1/wallets/{id}/sign
# 两个份额持有方各自用本地份额私钥（--share-key share_id=<base64 私钥>）当场签名；
# 也可用 --signature share_id=<base64 签名> 直接提交现成份额签名。
python3 -m threshold_wallet.cli sign my-wallet \
  --signing-request-id req-1 --message "hello" \
  --share-key "<share_id_1>=<base64 私钥1>" \
  --share-key "<share_id_2>=<base64 私钥2>"
```

## 测试

```bash
python3 -m unittest discover -s tests -v
```

覆盖 crypto 原语、service 全部状态码与幂等语义，以及在随机端口启动真实
HTTP 服务的端到端集成测试。
