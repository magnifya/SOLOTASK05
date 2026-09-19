# SOLOTASK05

门限签名托管后端。Python 加 cryptography，对外提供 HTTP 服务与命令行入口，两者能力一致。

## 运行

    python -m app --port <port>      # 启动 HTTP 服务
    python -m app <subcommand>       # 命令行入口，输出单行 JSON

## 公开接口

POST /v1/wallets
  请求：wallet_id、shares（shares 为 2 表示两方各持一个份额）
  成功：201 -> wallet_id、public_key、两个份额标识
  份额数不为 2：400
  wallet_id 重复创建：409

POST /v1/wallets/{wallet_id}/sign
  请求：signing_request_id、两个份额签名
  成功：201 -> signature
  缺少任一份额或份额校验失败：400
  同一 signing_request_id 重复提交：返回已有签名，不重复计入

GET /v1/wallets/{wallet_id}
  成功：200 -> public_key、created_at
  不存在：404

## 约定

- 完整的私钥不得在任何时刻存在于任何单一位置
- 服务端不得保存完整私钥；响应与磁盘上都不能出现完整私钥材料
- 缺少任一份额时不得产出可用的完整签名

## 当前状态

接口尚未实现；实现完成后需在此补充安装依赖、启动方式与基础测试命令。
