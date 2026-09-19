# SOLOTASK05 门限签名托管后端

用 Python 加 cryptography 实现一个两方门限签名托管后端，对外提供 HTTP 服务与命令行入口。建钱包走 POST /v1/wallets，请求体是 JSON，含 wallet_id 与 shares；shares 必须等于 2，返回 201 与 wallet_id、public_key 和两个份额标识 share_ids；shares 不等于 2 返回 400，wallet_id 重复则返回 409。份额签名用 Ed25519，各用自身私钥对 signing_request_id 与 message 拼接结果签名。签名走 POST /v1/wallets/{wallet_id}/sign，请求体是 JSON，含 signing_request_id、message 与 signatures，元素含 share_id 与 signature；两份齐备且校验通过返回 201 与 signature，缺一份或校验失败返回 400；同一 signing_request_id 重复提交返回已有签名。GET /v1/wallets/{wallet_id} 返回 public_key 与 created_at，不存在返回 404。命令行提供 create、sign、show 三个子命令，与接口一一对应，打印单行 JSON。服务端只保存份额，响应、磁盘与日志都不得出现完整私钥。

## 当前状态

上述接口尚未实现。实现完成后，请在此补充安装依赖、启动方式与基础测试命令。
