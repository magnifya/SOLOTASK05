# SOLOTASK05 门限签名托管后端

两方门限（2-of-2）Ed25519 签名托管后端，用 Python 加 `cryptography`
实现，对外提供 HTTP 服务与命令行入口。无任何完整私钥落盘，支持审批
工作流、冷热钱包交易策略、份额轮换、资产账本、可恢复签名会话与离线
灾备（backup/restore）。

## 密码学设计

- 建钱包生成两个**彼此独立**的 Ed25519 密钥对（份额 `share-1`、
  `share-2`）。系统中任何位置都**不存在完整私钥**，只有两个 32 字节份额。
- 钱包公钥 `public_key` ＝ 两个份额公钥按序拼接（64 字节 hex）。
- 每个份额用自己的私钥对 `signing_request_id` 与 `message` 的直接拼接
  （UTF-8）做 Ed25519 签名。
- 门限签名 `signature` ＝ 两个份额签名按 `share-1, share-2` 顺序拼接
  （128 字节 hex）。任何持公钥者可把公钥与签名各拆两半，用标准
  Ed25519 独立验证。

## 安装、启动与测试

唯一运行依赖是 `cryptography`：

```bash
pip install -r requirements.txt
python -m threshold_wallet.cli serve --host 0.0.0.0 --port 8080 --data-dir ./data
python -m unittest discover -s tests -v
```

启动时若任一钱包现场无法对账恢复，`serve` 打印单行 JSON 错误并以非零
码退出（fail-closed，不绑定端口）；常驻请求遇到不可对账现场统一返回
`503`。异常三分类保持到启动边界：持久化 JSON 损坏抛
`CorruptDataError`、审计/文件 I/O 失败抛 `OSError`、现场语义矛盾抛
`RecoveryError`——三者 HTTP 一律 `503`、`serve` 一律拒绝就绪。

## HTTP 接口

| 方法 | 路径 | 说明 |
| ---- | ---- | ---- |
| POST | `/v1/wallets` | 建钱包 `{"wallet_id", "shares"`，`shares` 必须为 2 |
| GET  | `/v1/wallets/{id}` | 返回 `public_key` 与 `created_at` |
| POST | `/v1/wallets/{id}/freeze` | 应急冻结钱包 `{"reason"}` |
| POST | `/v1/wallets/{id}/unfreeze` | 解除应急冻结 `{"reason"}` |
| GET  | `/v1/wallets/{id}/security-state` | 查询安全状态 `{wallet_id,state,reason}` |
| GET  | `/v1/wallets/{id}/change-control` | 查询高风险配置双人变更控制开关 `{"enabled":bool}`（缺省 false） |
| POST | `/v1/wallets/{id}/policy-changes` | 双人审批统一变更受控配置 |
| GET  | `/v1/wallets/{id}/policy-changes/{change_id}` | 查询已应用的配置变更视图 |
| PUT  | `/v1/wallets/{id}/approval-policy` | 审批策略 `{"required_approvals":1\|2,"timeout_seconds":>0}` |
| PUT/GET | `/v1/wallets/{id}/approval-roster` | 钱包级审批人名单 `{"allowed_approvers":[...]}` |
| PUT  | `/v1/wallets/{id}/transaction-policy` | 交易策略 `{"mode":"hot"\|"cold","max_delta":正整数,"allowed_assets":[...]}` |
| GET  | `/v1/wallets/{id}/transaction-policy` | 查询交易策略（未配置 404） |
| PUT  | `/v1/wallets/{id}/dkg-failover-policy` | DKG 故障审批开关 `{"enabled":bool}` |
| GET  | `/v1/wallets/{id}/dkg-failover-policy` | 查询 DKG 故障审批开关（缺省 `{"enabled":false}`） |
| PUT  | `/v1/wallets/{id}/nodes` | 设置 DKG 节点健康表 `{"nodes":{...}}` |
| GET  | `/v1/wallets/{id}/nodes` | 查询 DKG 节点健康表（未配置 404） |
| PUT  | `/v1/wallets/{id}/chain-adapters` | 设置跨链适配器健康熔断表 `{"adapters":{...}}` |
| GET  | `/v1/wallets/{id}/chain-adapters` | 查询跨链适配器健康熔断表（未配置 404） |
| POST | `/v1/wallets/{id}/nodes/{node}/rejoin` | 故障节点重新加入 `{"rejoin_id","dkg_id","round","key","approval_request_id"}` |
| POST | `/v1/wallets/{id}/sign-requests` | 建审批单 `{"id","message"}` |
| GET  | `/v1/wallets/{id}/sign-requests/{rid}` | 查审批单 |
| POST | `/v1/wallets/{id}/sign-requests/{rid}/approve` | 批准 `{"approver_id","reason"?}` |
| POST | `/v1/wallets/{id}/sign-requests/{rid}/reject` | 拒绝 |
| POST | `/v1/wallets/{id}/sign-requests/{rid}/cancel` | 撤销审批单 `{"cancel_id","reason"}` |
| GET  | `/v1/wallets/{id}/audit-events` | 审计事件（seq 升序，分页 `from_seq`/`limit`） |
| GET  | `/v1/wallets/{id}/audit-evidence` | 区间逐条证据（`from_seq`/`to_seq`/`expected_head`） |
| GET  | `/v1/wallets/{id}/audit-integrity` | 审计防篡改摘要链校验（可带 `expected_head`） |
| POST | `/v1/wallets/{id}/sign` | 提交两份份额签名，返回聚合签名 |
| POST | `/v1/wallets/{id}/share-rotations` | 准备轮换 `{"rotation_id"}` |
| GET  | `/v1/wallets/{id}/share-rotations/{rid}` | 查轮换状态 |
| POST | `/v1/wallets/{id}/share-rotations/{rid}/activate` | 激活轮换 |
| POST | `/v1/wallets/{id}/share-bind` | 绑定 DKG 复职节点到轮换份额槽位 `{"id","rotation","dkg","round","node","slot","approval"}` |
| POST | `/v1/wallets/{id}/asset-operations` | 建资产操作 `{"operation_id","asset_id","delta"}` |
| GET | `/v1/wallets/{id}/asset-operations/{oid}` | 查询资产操作与取消信息 |
| POST | `/v1/wallets/{id}/asset-operations/{oid}/commit` | 提交资产操作 |
| POST | `/v1/wallets/{id}/asset-operations/{oid}/cancel` | 撤销未落账资产操作 `{"cancel_id","approval_request_id"}` |
| GET  | `/v1/wallets/{id}/assets/{asset_id}` | 查资产 `balance`/`version`（可带 `at_seq`/`expected_head` 读历史状态） |
| POST | `/v1/wallets/{id}/assets/{asset_id}/freeze` | 资产粒度应急冻结 `{"reason"}` |
| POST | `/v1/wallets/{id}/assets/{asset_id}/unfreeze` | 解除单个资产冻结 `{"reason"}` |
| GET  | `/v1/wallets/{id}/assets/{asset_id}/security-state` | 查询资产安全状态 `{wallet_id,asset_id,state,reason}` |
| PUT  | `/v1/wallets/{id}/chain/{asset_id}` | 跨链确认策略 `{"chain_id","enabled","required_confirmations","reorg_window"}` |
| GET  | `/v1/wallets/{id}/chain/{asset_id}` | 查询跨链确认策略（未配置 404） |
| POST | `/v1/wallets/{id}/chain/{oid}/report` | 上报链上确认数 `{"chain_id","tx_id","block_height","block_hash","confirmations"}` |
| PUT  | `/v1/wallets/{id}/chain/{asset_id}/arbitration` | 多源仲裁策略 `{"sources","quorum"}` |
| GET  | `/v1/wallets/{id}/chain/{asset_id}/arbitration` | 查询多源仲裁策略（未配置 404） |
| POST | `/v1/wallets/{id}/chain/{oid}/observe` | 多源观察上报 `{"source","report"}` |
| POST | `/v1/wallets/{id}/chain/{oid}/dispatch` | 请求跨链派发 `{"dispatch_id","adapter_id","approval_request_id"}` |
| POST | `/v1/wallets/{id}/chain/{oid}/dispatch-auto` | 健康感知自动派发 `{"dispatch_id","approval_request_id"}` |
| POST | `/v1/wallets/{id}/chain/{did}/result` | 上报跨链派发结果回执 `{"adapter_id","state","tx_id"}` |
| POST | `/v1/wallets/{id}/chain/{did}/confirm` | 上报跨链派发确认进展 `{"adapter_id","tx_id","block_height","block_hash","confirmations"}` |
| POST | `/v1/wallets/{id}/chain/{did}/takeover` | 失败派发由新适配器接管 `{"adapter_id","approval_request_id"}` |
| POST | `/v1/wallets/{id}/chain/{did}/isolate` | 隔离显式 down 适配器的在途派发（体须恰为 `{}`） |
| GET  | `/v1/wallets/{id}/chain/{did}/finality` | 查询跨链派发最终性 |
| POST | `/v1/wallets/{id}/chain/{did}/settle` | 最终性资产结算（空体） |
| POST | `/v1/wallets/{id}/sign-sessions` | 建可恢复会话 `{"id","message","timeout_seconds"}` |
| GET  | `/v1/wallets/{id}/sign-sessions/{sid}` | 查会话视图 |
| POST | `/v1/wallets/{id}/sign-sessions/{sid}/shares` | 投递一份额签名 `{"share_id","signature"}` |
| POST | `/v1/wallets/{id}/sign-sessions/{sid}/participants/replace` | 替换会话单个参与方份额 `{"replacement_id","offline_share_id"}` |
| POST | `/v1/wallets/{id}/sign-sessions/{sid}/participants/takeover` | 两阶段接管会话参与方份额 `{"takeover_id","stage","offline_share_id"}` |
| POST | `/v1/dkg/{id}/{did}` | 推进两方 DKG 一个阶段 `{"op","node","key","hash","peer"}` |
| GET  | `/v1/dkg/{id}/{did}` | 查询两方 DKG 会话视图 |
| POST | `/v1/dkg/{id}/{did}/failover` | 提交 DKG 故障轮次 `{"round","action","node","replacement","key"}`（启用故障审批或 `reinstate` 时另加 `approval_request_id`） |

ID（wallet/rotation/operation/asset/session/dkg/node 等）一律匹配
`[A-Za-z0-9_-]{1,128}`，非法 `400`；钱包不存在 `404`；请求体须为
JSON 对象。

### 建钱包 / 查询 / 签名

- 建钱包成功 `201`（返回 `wallet_id`、`public_key`、`share_ids`），
  `shares != 2` 为 `400`，`wallet_id` 重复为 `409`。
- 查询成功 `200`，钱包不存在 `404`。
- `/sign`：两份齐备且全部校验通过 `201`；缺份、份额重复/未知、签名
  非法或校验失败 `400`；钱包不存在 `404`。同一 `signing_request_id`
  重复提交幂等返回已有签名（`200`）。

### 审批工作流（可选）

- `PUT approval-policy`：`required_approvals` 为 1 或 2，
  `timeout_seconds` 为正整数；成功 `200`，非法 `400`，钱包不存在 `404`。
- `PUT/GET approval-roster`：请求/响应体仅含 `allowed_approvers` 数组；
  成员为 1..128 字符非空白字符串且不得重复，响应按 Unicode 码点升序，
  空数组取消限制。缺字段、夹带字段、成员非法或重复、钱包标识非法为
  `400`，钱包不存在为 `404`；GET 对已存在钱包始终 `200`，未设置为
  空数组且不记事件。首次设置、修改、清空和同值更新均为 `200` 并记录
  `approval_roster_updated`，details 仅含当前名单；名单只由该事件序列
  的最后一条重建。
- `POST sign-requests`：`id`、`message` 非空；未设策略 `409`；首建
  `201`；同 id 同文幂等 `200`；同 id 异文 `409`。
- 审批单视图 `{id,message,state,approvers,count,req,t0,t1,reason}`，
`state` 为 `pending|approved|rejected|expired|signed|cancelled`；操作前懒过期
到点的 pending 单为 `expired`。
- `approve`/`reject`：`approver_id` 为非空白字符串，`reason` 可选且
  ≤1024 字符；非法 `400`。pending 单批准 `200`（同一 approver 重复
  批准不计数，达门槛转 `approved`），拒绝转 `rejected`；对终态单操作
  `409`，但同人同决定重放为 `200` 且不计数、不复查名单。配置非空
  名单后，只有名单成员可作出新的批准或拒绝决定，名单外为 `409`；
  名单变更不追溯既有批准，冷签名、资产撤销、节点复职、份额绑定和
  跨链接管等入口的审批单门控不变。
- 设策略后 `/sign` 须存在同 id、同 message 且 `approved` 的审批单，
两份额齐备 `201` 并推进审批单为 `signed`；未设策略时行为不变。
- `request-cancel`/`cancel`：请求体恰为 `{"cancel_id","reason"}`；
  `cancel_id` 匹配安全标识，`reason` 为 1..1024 字符非空白字符串。仅
  pending 且未过期审批单可撤销，首次 `201` 并转 `cancelled`；同 rid、同
  cancel_id、同 reason 重放 `200`。cancel_id 复用、参数变化或对
  approved/rejected/expired/signed 再撤销均为 `409`；冻结钱包写入为
  `409`。撤销只追加一条 `request_cancelled` 事件，`request_id` 绑定审批
  单、`actor_id` 为 cancel_id、`details` 恰含 cancel_id/reason。

### 高风险配置双人变更控制（可选）

默认保持基线行为：审批/交易策略、DKG 故障审批开关、节点健康表与跨链适配
器配置仍由各自 PUT 直接更新。新增可选的高风险配置双人变更控制；启用后受控
配置不再接受原 PUT，启停与一切受控配置变更只经统一变更入口。

- `GET /v1/wallets/{id}/change-control` 始终 `200` 返回 `{"enabled":bool}`，
  初始 `{"enabled":false}`；钱包不存在 `404`，标识非法 `400`。
- 受控 target 恰七类：`approval-policy`、`approval-roster`、
  `transaction-policy`、`dkg-failover-policy`、`nodes`、`chain-adapters`、
  `change-control`。
- `POST /v1/wallets/{id}/policy-changes` 请求体**恰为**
  `{"change_id","target","before","after","approval_request_id"}`（缺键/
  夹带一律 `400`）。`after` 为该 target 对应公开视图配置（各 target 沿用其
  PUT 的形状与归一规则：名单码点升序、节点 ID 升序且每值 `key,state`、
  适配器 ASCII 升序）；`before` 等于应用前配置，未配置策略为 `null`
  （`approval-policy`/`transaction-policy`/`nodes`/`chain-adapters` 可空；
  `approval-roster`/`dkg-failover-policy`/`change-control` 恒有缺省值，不
  接受 null；`after` 恒非空）。标识、target、before/after 配置形状非法
  `400`。
- 审批 `message` 是**仅含** `change_id,target,before,after` 四键（该固定
  序）的 ASCII 紧凑 JSON（无空白、非 ASCII 转义），且与请求逐字匹配；
  审批单必须为同钱包 `approved`、有两位**不同**审批人且未过期（未知单
  `404`；`pending`/`rejected`/`expired`、已过期、message 不符或仅一位审批
  人均 `409`）。
- 应用在钱包事务锁内比较 `before` 与当前配置、写配置并**原子**追加唯一
  `policy_change_applied` 事件（`request_id` 为 change_id、`actor_id` 为
  approval_request_id、`reason` 为 null，details 即五字段）；`before` 漂移
  `409`。首次 `201` 返回含 `change_id,target,before,after,
  approval_request_id,seq` 的视图；同参重放 `200` 同体且不新增事件；同
  change_id 异参 `409`。未知 change_id 的 GET `404`。
- 启用后（含 `change-control` 本身）六类受控 PUT 一律 `409`
  `change control required` 且**零副作用**（在任何校验/写入之前判定，但晚
  于钱包存在性与冻结闸门）；`GET .../policy-changes/{change_id}` 返回已应用
  视图。关闭仍走统一入口（after `{"enabled":false}`），关闭后原 PUT 恢复。
- 配置状态由 legacy 写入事件与 `policy_change_applied` 按 seq 统一折叠：
  audit-only 配置（roster/故障开关/nodes/adapters/开关）的全部读取与按 seq
  的事前健康快照折叠（DKG 自动替补、rejoin、share-bind、自动派发、隔离）
  都把两类事件当作同一快照流；文件型配置（approval/transaction policy）以
  审计为提交点，崩溃窗口按提交前意图前滚/回滚并把文件对账到折叠结果。并发
  与重启只产生一次首次应用；事件畸形或无法一致对账 fail-closed（`503`、
  serve 拒绝就绪、保留现场）。响应、日志、审计与新增文件均不含份额私钥或
  签名载荷；其余现有功能保持兼容。

### 冷热钱包交易策略（可选）

请求/成功响应（`200`）同为
`{"mode","max_delta","allowed_assets"}`。`mode` 为 `hot|cold`；
`max_delta` 为正整数（拒绝布尔/0/负/小数）；`allowed_assets` 为非空
数组，每项匹配安全标识并去重（重复 `400`）。`GET` 已配置 `200` 同体、
未配置 `404`。**同值更新也记事件。**

- 资产操作：未配置策略时行为不变。配置后仅**首次创建**按创建时刻策略
  检查白名单与 `abs(delta) <= max_delta`，否则 `409`（先检查后写，
  账本/version/状态/审计/幂等均不变）；`committed` 重放 `200` 同体、
  不再校验；策略更新不影响已存在的 pending 操作与重放。
- 签名：`hot` 沿用审批规则（配了审批策略才要求 approved 单）；`cold`
  **首签**必须有同 id、同 message 的 approved 审批单，否则 `409`；
  签名重放 `200` 不再校验。

### 可恢复签名会话

- 首建 `201`；同 id 同 `message`/`timeout_seconds` 重放 `200` 同体；
  同 id 异参 `409`；非法 `400`；钱包不存在 `404`。
- 视图（创建/查询/投递同形）
  `{id,message,state,received_shares,missing_shares,expires_at}`，
  `state` 为 `collecting|ready|signed|expired`，`aggregate_signature`
  仅 signed 时存在（128 字节 hex），不回传单份额签名。
- 未知会话 `404`；查询与投递均懒过期，到点的 collecting/ready 原子转
  `expired`（创建重放不触发）。
- 投递 `{"share_id","signature"}`：仅接受**当前在用份额**对 id+message
  直接拼接载荷的有效 64 字节 hex 份额签名。首收 `201`；同份额同值重放
  `200`、异值 `409`；编码/长度/校验失败或份额未知/已轮换失效 `400`；
  会话已 expired `409`。
- 两份齐备转 ready，随即按既有审批/hot-cold 门控聚合：门控通过转
  signed（`201`），门控失败 `409` 且保留 ready（补齐审批后重放在用
  份额即重试，成功 `200`）。signed 后任意重放 `200` 同体。
- 会话与审计在每钱包跨进程事务锁内原子持久化，服务重启后续作；多进程
  共用 data-dir 时只有一个首次状态推进。轮换后：signed 会话冻结创建时
  快照（旧份额同值重放仍 `200`、异值 `409`）；collecting/ready 在途
  会话迁移到当前两份在用份额（旧份额被剔除，投递旧份额 `400`）。
- 会话文件 JSON 损坏或形状/事件/历史公钥/聚合签名自相矛盾时
  fail-closed：常驻请求 `503`、`serve` 拒绝就绪，保留现场不归一。
- 审计事件统一为 `session_event`，动作 `created`/`share_received`/
  `expired`/`signed`；重放不产生事件，details 只含标识/状态/整数/原文，
  绝不含签名或私钥。

### 会话单节点参与者替换

`POST /v1/wallets/{id}/sign-sessions/{sid}/participants/replace`，请求体
仅 `{"replacement_id","offline_share_id"}`（含其他键或缺键一律
`400`）：把会话 `sid` 的单个参与方份额（`offline_share_id`）下线，
生成新份额 `<replacement_id>-share` 顶替原槽位。既有接口与 CLI 不变。

- 两个 ID 均须匹配安全标识，非法 `400`；钱包/会话未知 `404`；会话非
  `collecting|ready`（含到点懒过期）、或 `offline_share_id` 不是该会话
  当前在用份额，`409`。
- 首次替换 `201`；同 `replacement_id` 同参重放 `200` 同体、异参
  `409`；`replacement_id` 被其他会话占用 `409`；已提交的重放优先于
  状态判定。响应为既有会话视图。
- 迁移在每钱包跨进程事务锁内原子完成：新份额替换 `share_ids` 中的原
  槽位、移除旧份额已投递的签名、保留另一份（份数不足两份回到
  `collecting`）。此后旧份额投递 `400`，新份额沿用 Ed25519 校验与
  既有审批/hot-cold 门控。
- 新份额私钥只写 `shares/<id>/<replacement_id>-share.json`（恰含
  `private_key`/`public_key`/`share_id` 三键，两个 hex 值均为 64 位
  小写，UTF-8 无 BOM、`sort_keys`、2 空格缩进、末尾换行，临时文件 +
  原子替换）；任何文件至多含一个份额私钥。
- 审计事件 `session_participant_replaced`（`request_id` 为会话 id，
  `actor_id`/`reason` 为 `null`，details 恰含
  `session_id,old_share_id,new_share_id`）是唯一提交点：事件落盘前
  崩溃回滚并删除新份额文件，落盘后前滚迁移会话记录；损坏/矛盾现场
  保留并 `503`。跨进程并发只有一个 `201`，审计 seq 连续不重号；
  响应、日志与非份额文件绝不泄露份额私钥。
- 替换后该会话快照与钱包轮换解耦：其后的份额轮换不再迁移该会话；
  未替换的会话行为不变。

### 会话两阶段参与者接管

`POST /v1/wallets/{id}/sign-sessions/{sid}/participants/takeover`，
请求体恰含 `{"takeover_id","stage","offline_share_id"}`（含其他键或
缺键一律 `400`）：分两个阶段把会话 `sid` 的两个参与方槽位依次接管，
`stage` 为 `1`/`2`，阶段 `s` 生成新份额
`<takeover_id>-<s>-share` 顶替 `offline_share_id` 所在槽位。

- `takeover_id`/`offline_share_id` 均须匹配安全标识，`stage` 须为
  非布尔整数 `1` 或 `2`，非法 `400`；钱包/会话未知 `404`。
- 阶段必须从 `1` 起按序提交：`stage=2` 之前必须已提交同
  `takeover_id` 的 `stage=1`（跳号 `409`）；两阶段必须替换**不同**
  槽位——槽位按有序位置判定，`stage=2` 的 `offline_share_id` 必须是
  stage 1 未触碰的那个槽位的当前占用份额（命中 stage 1 已替换的
  槽位，含该槽位此后又被换入的份额，一律 `409`）。
- 每阶段迁移与单节点替换一致：新份额替换 `share_ids` 中的原槽位、
  移除该槽已投递的签名、保留另一份（不足两份回到 `collecting`），
  响应为既有会话视图。会话非 `collecting|ready`（含到点懒过期）、
  或 `offline_share_id` 不是该会话当前在用份额，`409`。
- 阶段首提 `201`；同 `takeover_id` 同阶段同参重放 `200` 当前视图、
  异参 `409`；`takeover_id` 被其他会话占用、或其新份额 id 已被
  替换/接管占用 `409`；已提交的重放优先于状态判定。
- 迁移在每钱包跨进程事务锁内原子提交，`session_takeover` 事件
  （`request_id` 为会话 id，`actor_id`/`reason` 为 `null`，details
  恰含 `takeover_id,stage,old_share_id,new_share_id`）是唯一提交点：
  事件落盘前崩溃回滚并删除新份额文件，落盘后前滚迁移会话记录；
  损坏/矛盾现场保留并 `503`、`serve` 拒绝就绪。跨进程并发同一阶段
  只有一个 `201`，审计 seq 连续不重号。
- 新份额私钥只写 `shares/<id>/<takeover_id>-<stage>-share.json`
  （恰含 `private_key`/`public_key`/`share_id` 三键，两个 hex 值均为
  64 位小写，UTF-8 无 BOM、`sort_keys`、2 空格缩进、末尾换行，临时
  文件 + 原子替换）；任何文件至多含一个份额私钥。
- 接管后该会话快照与钱包轮换解耦（与单节点替换同一规则）；旧份额
  再投递 `400`，新份额沿用 Ed25519 校验与既有审批/hot-cold 门控。

### 可恢复两方 DKG

`POST /v1/dkg/{id}/{did}`，请求体恰含
`{"op","node","key","hash","peer"}` 五键（含其他键或缺键一律
`400`）：两个参与方（`node` 为安全标识）依序推进
register→commit→share→done 完成两方密钥生成。后端只登记各方公开
承诺，**份额链下交换、后端绝不收份额正文**。

- `register`：仅 `key` 非 null 且为 64 位小写 hex（该方公钥贡献），
  `hash`/`peer` 必须为 null；`commit`：仅 `hash` 非 null 且为 64 位
  小写 sha256；`share`：仅 `hash`、`peer` 非 null，确认已收到 `peer`
  的链下份额，`hash` 必须等于 `peer` 的 commit 承诺。字段约束不满足
  一律 `400`。
- 首提 `201`；同方同值重放 `200`（优先于阶段判定）；异值、错阶段
  （未齐两份注册即 commit、未齐两份承诺即 share）、第三节点一律
  `409`；钱包不存在 `404`，非 register 的未知会话 `404`。
- GET/POST 响应体键序固定为
  `{id,round,state,nodes,committed,shared,public_key}`，`round` 为当前
  轮次（基线轮为 1），`state` 为 `register|commit|share|done|aborted`，
  `nodes`/`committed`/`shared` 三数组均按注册序；完成（done）时
  `public_key` 为两份注册 key 按注册序拼接，非 done 为 `null`。
- 状态仅由七字段 `dkg_stage` 审计事件持久化（基线轮 `request_id` 为
  会话 id，派生轮为 `<会话id>/<轮次>`；`actor_id`/`reason` 为 `null`，
  details 依次 `id,op,node,key,hash,peer,state`，未用值 `null`）：
  首提在每钱包跨进程事务锁内追加，事件为唯一提交点，重放不记。
  矛盾/损坏现场 fail-closed（常驻 `503`、`serve` 拒绝就绪），灾备恢复
  后视图与 seq 不变。响应、日志与非份额文件绝不含私钥或份额正文。

### DKG 故障轮次

`POST /v1/dkg/{id}/{did}/failover`（仅 POST）。DKG 故障审批开关缺省
**关闭**（见下文「DKG 故障审批」）：关闭时请求体恰含
`{"round","action","node","replacement","key"}` 五键（含其他键或缺键
一律 `400`），**`reinstate` 例外——恒须另加 `approval_request_id`
一键（见下文「DKG 故障节点复职（reinstate）」）**。当某方节点故障时，
从当前轮派生下一轮（`round` 必须恰为当前轮 +1）——首轮故障基于基线轮
（第 1 轮），后续故障基于当前轮。`node`/`replacement` 为安全标识。
开关启用时请求体在旧五键之外恰增 `approval_request_id` 一键，其余契约
不变（`reinstate` 无论开关都恰为这六键）。

- `abort`：仅限非终态轮（非 `done`/`aborted`），`node`/`replacement`/
  `key` 必须全为 `null`；派生轮 `state` 为 `aborted`，三数组为空。
- `replace`：仅限两方已注册的 `commit|share` 轮；`key` 为 64 位小写
  hex（换入方公钥贡献），`node` 须为当前轮在用节点、`replacement`
  须空闲；新轮中 `replacement` 顶替 `node` 的槽位，`committed`/
  `shared` 两数组清空，回到 `commit` 阶段。非法 `400`、冲突 `409`。
  另支持 `replacement`/`key` 双 `null` 的**自动替补**（见下文
  「DKG 节点健康与自动替补」）；一项 `null` 另一项非 `null` 为 `400`。
- `reinstate`：请求体恰含旧五键及 `approval_request_id` 六键（审批
  开关**不豁免**，开关关闭同样强制）。沿用 `replace` 的换槽派生契约，
  但 `replacement` 额外须为**已提交 `node_rejoined` 事件对应**、且在
  当前生效健康表中为 `up` 的空闲（非当前轮参与）节点，`key` 须与其
  健康表公钥一致；`node` 仍须为当前轮在用节点。详见下文「DKG 故障
  节点复职（reinstate）」。非法 `400`、冲突/未批准 `409`。
- 首提 `201`；已提交轮次的旧五键同参重放 `200`（**优先于状态与审批
  判定，不复查审批单**）；同 `round` 异参 `409`；`round` 不等于
  当前轮 +1 `409`；钱包/会话未知 `404`。自动替补（双 `null`）的重放
  规则见下文「DKG 节点健康与自动替补」。**`reinstate` 须六字段
  （旧五键及 `approval_request_id`）全同方按重放 `200`；更换审批单
  或任一值一律 `409`。**
- 无任何故障轮次时，`/v1/dkg/{id}/{did}` 无需参照轮次（行为与旧版
  一致）；存在故障轮次后必须带 `?round=R` 当前轮：缺参 `409`、旧轮
  `409`、未知轮 `404`、非法 R `400`；GET 成功 `200`，POST 体仍为旧
  五键。`aborted` 轮一律 `409`；派生轮不接受 `register`（`409`），
  `commit`/`share` 沿用旧约。
- 故障轮次仅由 `dkg_failover` 审计事件持久化（逻辑键序
  `seq,type,at,request_id,actor_id,reason,details`，落盘外层七字段为
  规范序 `actor_id,at,details,reason,request_id,seq,type`；**外层键序
  在审计读取归一化之前校验——落盘外层错序即 `RecoveryError`，绝不先
  归一而抹平重排、绝不写盘**；
  `request_id` 为 `<会话id>/<轮次>`，`reason` 恒为 `null`；手工/旧事件
  details 依次 `id,round,action,node,replacement,key,state`（K 原位
  展开）；自动替补事件为既有七键加末键 `mode`（`mode=auto`））。
  **`abort`/`replace`（含自动替补）的 `actor_id` 为 `null`、details
  不含审批标识；唯独 `reinstate` 的 `actor_id=approval_request_id` 非
  null、details 仍为同样七键、`state=commit`。** 首提在每钱包跨进程
  事务锁内追加，事件为唯一提交点，跨进程并发只有一个 `201`，重放不记。
  恢复对 `reinstate` 按 `actor_id` 复核同钱包审批单（存在、message
  逐字为 dkg_id 后接 K 的紧凑 JSON、状态 approved/signed），并核验
  replacement 在事件提交之前的生效健康表（最近 `node_state` 快照折叠
  其间更早 rejoin 翻转）中为 up 空闲节点、key 一致、且有更早提交的
  `node_rejoined` 对应；abort/replace 仍按旧契约（`actor_id` 必须为
  null）。矛盾/损坏现场 fail-closed（常驻 `503`、`serve` 拒绝就绪），
  重启/灾备恢复后轮次与 seq 不变。响应、日志、非份额文件绝不含私钥或
  份额正文。

### DKG 节点健康与自动替补（可选）

`PUT /v1/wallets/{id}/nodes` 设置 DKG 节点健康表，请求体与成功响应
（`200`）同为 `Q={"nodes": {节点ID: {"key","state"}, ...}}`：

- `nodes` 必须**非空**；键为安全标识，服务端归一为按节点 ID **升序**
  返回/落盘；每个值恰含 `key`、`state` 两键且键序固定为
  `key,state`：`key` 为 64 位小写 hex（该节点公钥贡献），`state` 为
  `up|down|ban`。任何形状/取值非法一律 `400`。
- `GET` 已配置 `200` 返回 Q，**从未配置 `404`**；钱包不存在时 GET/PUT
  一律 `404`；`PUT` 可首建。健康表仅由 `node_state` 审计事件持久化
  （`request_id`/`actor_id`/`reason` 为 `null`，details 即 Q，取最后
  一条恢复），不写状态文件。**同值不记事件**；仅当与当前表不同才追加
  一条 `node_state`。恢复对每条 `node_state` 事件严格校验 README 键序：
  事件**外层七字段**须为落盘规范序
  （`actor_id,at,details,reason,request_id,seq,type`）、details 恰含
  `nodes`、节点 ID 按**升序唯一**、每个节点值恰为键序 `key,state`；
  重排、形状或取值矛盾都 fail-closed（抛 `RecoveryError`，常驻 `503`、
  `serve` 拒绝就绪），重启/灾备恢复后健康表与 seq 不变。

`POST /v1/dkg/{id}/{did}/failover` 的 `replace` 支持**自动替补**：

- 请求里 `replacement` 与 `key` **双 `null`** 即请求自动选择（恰好
  一项为 `null`、另一项非 `null` 一律 `400`）。
- 首提前置：DKG 故障审批开关必须**关闭**（开启时 `409`，自动替补不
  走审批单）；当前轮为两方已注册的 `commit|share`；`node` 为当前轮
  在用节点且在当前健康表中为 `down|ban`。取健康表中**首个 `up` 的非
  参与节点**（按节点 ID 升序）及其 `key` 实写换入；健康表缺失、
  `node` 未故障或没有候选一律 `409`，不落事件、DKG 现场不变。
- 首提 `201`，跨进程并发同一轮只有一个 `201`。该 `dkg_failover`
  事件 details 为既有七键加末键 `mode`（`mode="auto"`），其中
  `replacement`/`key` 写**实选值**而非 `null`；手工/旧事件保持旧七键，
  恢复只对手工事件按手工语义核验。
- **自动重放**：同 `round`/`action`/`node` 的双 `null` 请求优先返回
  `200` 当前轮视图，**不复查**审批开关、审批单、健康表、候选与阶段
  （审批事后开启、健康事后翻转都不影响幂等重放）；与已提交自动替补的
  `node` 不符等其余情况一律 `409`。
- 重启/灾备恢复时，每条自动替补事件都以其**提交之前最近的
  `node_state` 快照**重新核验选择：`node` 当时 `down|ban`、被选替补
  当时为首个 `up` 的非参与节点、记录的 `replacement`/`key` 与快照
  一致。事前无快照、无候选或任何矛盾都 fail-closed（抛
  `RecoveryError`）；审计 JSON 损坏抛 `CorruptDataError`、审计文件
  I/O 失败抛 `OSError`——三者 HTTP 一律 `503`、`serve` 拒绝就绪。
  恢复本身不新增审计事件，响应、日志、非份额文件绝不泄露份额私钥或
  份额正文。

### DKG 故障节点重新加入（rejoin）

`POST /v1/wallets/{id}/nodes/{node}/rejoin`（仅 POST），请求体 B 恰含
`{"rejoin_id","dkg_id","round","key","approval_request_id"}` 五键
（含其他键或缺键一律 `400`）：把当前轮之外处于 `down|ban` 的待命节点
重新置为 `up`。路径 `{node}` 即重新加入的节点 N。

- `rejoin_id`/`dkg_id`/N/`approval_request_id` 沿用安全标识
  `[A-Za-z0-9_-]{1,128}`；`key` 为 64 位小写 hex；`round` 为非布尔正
  整数。B 的键集/类型/值错 `400`；钱包、DKG 会话、节点（不在健康表）
  未知一律 `404`。
- **首提前置**：生效健康表（最后一条 `node_state` 快照折叠其后的
  rejoin 翻转）中 N 必须为 `down|ban` 且 `key` 与其记录一致；`round`
  必须恰为该 DKG **当前** `commit|share` 轮，且 N **不占用**该轮槽位
  （N 是轮外待命节点）。任一不满足 `409`，现场不变。
- **审批**：`approval_request_id` 必须指向**同一钱包**既有、且为
  `approved` 的审批单；其 `message` 必须与紧凑 JSON **逐字一致**
  （无空格、键序固定）：
  `{"rejoin_id":"RJ","dkg_id":"D","round":R,"node":N,"key":K}`。审批
  单未知、非 `approved`（操作前按既有契约懒过期）或 message 不符一律
  `409`，不追加事件、健康/DKG 现场不变。
- 成功把 N 置为 `up`，`201` 返回
  `V={"rejoin_id","dkg_id","round","node","key","state"}`，键序固定且
  `state="up"`。同 `rejoin_id` **同参**（含 `approval_request_id`）重放
  `200` 返回同一 V（优先于状态判定，不复查现状）；同 `rejoin_id`
  **异参** `409`。
- 节点状态仅由审计事件持久化：`node_rejoined` 是唯一提交点
  （`request_id=rejoin_id`、`actor_id=approval_request_id`、
  `reason=null`、details 即 V，键序
  `rejoin_id,dkg_id,round,node,key,state`），不另写健康状态文件；
  `GET .../nodes` 返回的生效健康表为最后一条 `node_state` 快照折叠其后
  全部 rejoin 翻转。首提在每钱包跨进程事务锁内追加，跨进程并发只有一个
  `201`（其余同参 `200`），审计 seq 连续不重号，重放不记事件。
- 重启/灾备恢复时，每条 `node_rejoined` 都按其**提交之前**的现场逐条
  复核：事前最近 `node_state` 快照（仅折叠该快照之后、本事件之前的
  rejoin 翻转）中 N 存在、`key` 一致且为 `down|ban`；事前 DKG
  （按 seq 前缀重建）存在该会话、当前轮恰为 `round` 且处
  `commit|share`、N 不占槽；同钱包审批单存在且 message 逐字一致、状态
  为 `approved`（其后经 `/sign` 推进为 `signed` 亦认可）。重复
  `rejoin_id`、事前无快照或任何矛盾都 fail-closed（抛
  `RecoveryError`）；`node_rejoined` 的 details 键序在审计读取归一化
  **之前**校验（落盘必须恰为 `rejoin_id,dkg_id,round,node,key,state`，
  错序即 `RecoveryError`，绝不先归一而抹平重排）；审计 JSON 损坏抛
  `CorruptDataError`、审计文件 I/O 失败抛 `OSError`——三者 HTTP 一律
  `503`、`serve` 拒绝就绪。恢复不新增事件、不改 seq，响应、日志、非
  份额文件绝不泄露份额私钥或份额正文。

### DKG 故障节点复职（reinstate）

`POST /v1/dkg/{id}/{did}/failover` 的 `action="reinstate"`：把一个经
rejoin 审批恢复为 `up` 的轮外待命节点正式换入当前轮槽位（与 `replace`
一样派生下一轮、清空 `committed`/`shared` 回到 `commit`）。请求体恰含
`{"round","action","node","replacement","key","approval_request_id"}`
六键（K 即前五字段；含其他键或缺键一律 `400`），**DKG 故障审批开关不
豁免**——开关关闭时 `reinstate` 仍强制带 `approval_request_id`（五键
提交 `400`）。

- 取值与 `replace` 一致：`round` 须恰为当前轮 +1，`node`/`replacement`
  为安全标识，`key` 为 64 位小写 hex，`node` 须为当前轮在用节点、
  `replacement` 须空闲。额外前置：`replacement` 必须是某条**已提交
  `node_rejoined` 事件对应**的节点、且在当前生效健康表（最后
  `node_state` 快照折叠其后 rejoin 翻转）中为 `up`，提交 `key` 须与其
  健康表公钥一致。无健康表、节点未 rejoin、当前非 up、key 不符、阶段/
  槽位不满足，一律 `409` 且不落事件、DKG 现场不变。
- **审批**：`approval_request_id` 必须指向**同一钱包**既有且为
  `approved` 的审批单（操作前按既有契约懒过期）；其 `message` 必须与
  紧凑 JSON **逐字一致**（无空格、键序固定，dkg_id 后接 K）：
  `{"dkg_id":"D","round":R,"action":"reinstate","node":N,"replacement":X,"key":K}`。
  审批单未知、非 approved、message 不符一律 `409`。
- 首提 `201` 返回派生轮视图。**重放须六字段（K 及
  `approval_request_id`）全同才 `200`（优先于状态与审批判定，不复查
  审批单现状）；更换审批单或 K 中任一值一律 `409`。**
- 提交点为唯一 `dkg_failover` 事件：`request_id=<dkg_id>/<round>`、
  `actor_id=approval_request_id`（**非 null**）、`reason=null`，
  details 仍依次 `id,round,action,node,replacement,key,state`
  （`state=commit`，K 原位展开），不含 mode。**仅 reinstate 的
  actor_id 非 null；abort/replace 仍为 null，其余契约不变。**
- 重启/灾备恢复时按 `actor_id` 复核：同钱包审批单存在、message 逐字
  一致、状态 approved（其后推进为 signed 亦认可）；replacement 在该
  事件提交之前的生效健康表（最近快照折叠其间更早 rejoin 翻转）中为
  up 空闲节点、key 一致，且有一条更早提交的 `node_rejoined` 与之
  对应。审批单缺失/未批准/message 不符、事前无快照、replacement 当时
  非 up/key 不符/占槽、无更早 rejoin 或任何矛盾都 fail-closed（抛
  `RecoveryError`）；审计 JSON 损坏抛 `CorruptDataError`、I/O 失败抛
  `OSError`——HTTP 一律 `503`、`serve` 拒绝就绪。恢复不新增事件、不改
  seq。

### DKG 故障审批（可选）

- `PUT /v1/wallets/{id}/dkg-failover-policy`：请求体仅收
  `{"enabled": bool}`（恰一键，多/缺或非布尔 `400`），成功 `200`
  返回同体；`GET` 成功 `200` 同体，从未设置时缺省
  `{"enabled": false}`（无 `404`）；钱包不存在 `404`。
- 开关仅由 `dkg_failover_policy_updated` 审计事件持久化
  （`request_id`/`actor_id`/`reason` 均为 `null`，details 恰为
  `{"enabled": bool}`，取最后一条恢复），不写策略状态文件；**同值
  更新也记事件**。事件损坏/形状矛盾 fail-closed（常驻 `503`、`serve`
  拒绝就绪），重启/灾备恢复后开关与 seq 不变。
- 开关启用时 `POST .../failover` 请求体恰收旧五键及
  `approval_request_id`（匹配安全标识，非法/缺失 `400`）；关闭时
  夹带该键一律 `400`。**`action="reinstate"` 不受开关影响：无论开关
  开关都恰收六键（恒须 `approval_request_id`），见「DKG 故障节点
  复职（reinstate）」。**
- `approval_request_id` 必须指向**同一钱包**既有审批单；审批工作流
  沿用 sign-requests 契约（须先配置审批策略、建单并批准）。审批单
  `message` 必须与紧凑 JSON **逐字一致**（无空格、键序固定）：
  `{"dkg_id":"D","round":R,"action":"A","node":N,"replacement":X,"key":K}`，
  其中 N/X/K 按旧五键约定为字符串或 `null`（`reinstate` 三值均为
  字符串）。
- 审批单为 `approved` 且提交轮次恰为当前轮 +1 时故障方可执行
  （`201`）；审批单未知、`pending`、`rejected`、`expired`（操作前
  按既有契约懒过期）、message 不符，或审批通过但轮次已变化，一律
  `409` 且不追加事件、DKG 现场不变。
- 已提交轮次的旧五键同参重放优先返回 `200`，不再复查开关与审批单
  现状（审批单事后被拒绝/过期、开关切换都不影响幂等重放）；异参仍
  `409`。**`reinstate` 的重放须六字段（含 `approval_request_id`）
  全同才 `200`，更换审批单或任一值 `409`。**
- 审批检查、事件追加与 DKG 轮次派生全在同一把每钱包跨进程事务锁内
  原子完成，跨进程并发同一轮次只有一个 `201`，审计 seq 连续不重号。

### 份额轮换

- `POST share-rotations`：`rotation_id` 非法 `400`，钱包不存在 `404`。
  首建生成两份新份额（`<rotation_id>-share-1/2`），新私钥只写暂存文件，
  激活前不碰在用份额；成功 `201` 返回
  `{rotation_id,state:"prepared",share_ids,public_key}`。每钱包同时
  只允许一个 prepared 轮换，冲突 `409`；同 id 重放 `200` 不重新生成。
- `GET`：`200`，未知 `404`。
- `activate`：仅 prepared 可激活（锁内原子替换份额/公钥/状态），成功
  `201`（`state:"active"`）；active 重放 `200`；其余状态 `409`。
- 激活后未首签的请求必须用新 share_ids（旧份额 `400`）；已首签请求
  重放仍 `200`。
- 审计事件 `share_rotation_prepared` / `share_rotation_activated`，
  details 只含标识与公钥，重放不重复记；**历史签名按其签名时刻（由轮换
  链确定）的钱包公钥拆半独立验通，轮换后连续有效**。

### DKG 复职节点份额槽位绑定（share-bind）

`POST /v1/wallets/{id}/share-bind`（仅 POST），请求体 B 恰含
`{"id","rotation","dkg","round","node","slot","approval"}` 七键（含其他
键或缺键一律 `400`）：把一个经 reinstate 换入 DKG 当前完成轮的 `up`
复职节点，正式绑定到一笔**已 prepared 未激活**轮换的某个份额槽位。

- `id`/`rotation`/`dkg`/`node`/`approval` 沿用安全标识
  `[A-Za-z0-9_-]{1,128}`；`round` 为非布尔正整数；`slot` 为非布尔整数
  `1` 或 `2`（布尔一律拒）。键集/类型/值错 `400`；钱包不存在 `404`。
- **首提前置**：`rotation` 必须是当前 `prepared` 轮换（active/其余状态
  `409`）；`round` 必须恰为该 DKG **当前**轮且状态 `done`；`node` 必须
  是创建该轮的故障派生中 `action="reinstate"` 换入（`replacement=node`）
  且在该轮节点集合中的节点，并在当前生效健康表（最后 `node_state` 快照
  折叠其后 rejoin 翻转）中为 `up`。轮换/DKG 未知 `404`、节点不在健康表
  `404`；轮换非 prepared、round 非当前 done、node 非该轮 reinstate 换入
  节点、node 当前非 up，一律 `409`。
- **审批**：`approval` 必须指向**同一钱包**既有、且为 `approved` 的审批
  单（操作前按既有契约懒过期）；其 `message` 必须与紧凑 JSON **逐字一致**
  （无空格、键序固定，即 B 去掉 `approval`）：
  `{"id":"B","rotation":"R","dkg":"D","round":N,"node":N0,"slot":S}`。
  审批单未知（含跨钱包审批单）`404`；非 approved、message 不符一律
  `409`，不追加事件、现场不变。
- **槽位占用**：同一轮换槽位（份额 id 全局唯一
  `<rotation>-share-<slot>`）至多绑定一次；该份额已被更早绑定事件占用即
  `409`。
- 成功 `201` 返回
  `V={"id","node","slot","share_id"}`（键序固定），其中
  `share_id` 取该 prepared 轮换 `share_ids[slot-1]`。同 `id` 七字段全同
  重放 `200` 返回同一 V（**优先于状态与审批判定，不复查审批单/健康表现
  状**）；同 `id` 异参（含更换审批单、rotation/dkg/round/node/slot 任一
  不同）`409`。
- 节点状态仅由审计事件持久化：`share_participant_reinstated` 是唯一提交
  点（`request_id=id`、`actor_id=approval`、`reason=null`、details 即 V，
  键序 `id,node,slot,share_id`），不另写绑定状态文件。首提在每钱包跨进程
  事务锁内追加，跨进程并发同一 id 只有一个 `201`（其余全同 `200`），审计
  seq 连续不重号，重放不记事件。
- **激活后绑定仅约束签名会话/shares**：轮换激活、被绑定份额成为在用份额
  后，向 `sign-sessions/{sid}/shares` 投递**该被绑定份额**时请求体必须恰
  含 `{"node","share_id","signature"}` 三键，且 `node` 与绑定的复职节点
  一致：键集错（缺 `node`/夹带其他键/类型错）`400`，`node` 不匹配 `409`，
  签名与其余契约沿用 `/shares`。绑定随**份额身份**存在（份额 id 全局
  唯一）：冻结了被绑定份额的 signed 会话即使在后续轮换后同值重放，仍须
  三键体且 `node` 一致。**未绑定份额**的投递体仍恰含
  `{"share_id","signature"}`（夹带 `node` 一律 `400`）；`/sign` 与
  `share-sign` 不变；绑定在轮换激活前（份额尚未在用）不约束任何投递。
- 重启/灾备恢复时，每条 `share_participant_reinstated` 都按其**提交之前**
  的现场逐条复核：事前同钱包审批单存在、message 逐字一致、状态 approved
  （其后经 `/sign` 推进为 signed 亦认可）；rotation 事前已 prepared 且未
  激活、details.share_id 恰为该 prepared 轮换该槽份额；事前 DKG 当前轮恰
  为 round 且 done、由 `replacement=node` 的 reinstate 派生、node 在轮内；
  node 在事前生效健康表中为 up；同一轮换份额无更早绑定。重复 id、审批单
  缺失/未批准/message 不符或任何矛盾都 fail-closed（抛 `RecoveryError`）；
  `details` 键序在审计读取归一化**之前**校验（落盘必须恰为
  `id,node,slot,share_id`，错序即 `RecoveryError`）；审计 JSON 损坏抛
  `CorruptDataError`、审计文件 I/O 失败抛 `OSError`——三者 HTTP 一律
  `503`、`serve` 拒绝就绪。恢复不新增事件、不改 seq，响应、日志、非份额
  文件绝不泄露份额私钥或份额正文。

### 资产账本

每钱包一本账（`assets/<id>.json`），操作状态机
`pending|committed|cancelled`，原子写入，只含标识与整数。

- `POST asset-operations`：两个 ID 为安全标识，`delta` 为非布尔非零
  整数；非法 `400`，钱包不存在 `404`。首建 `201` 返回
  `R={operation_id,asset_id,delta,state,balance,version}`（pending，
  balance/version 为创建时刻快照）；同 id 同参重放 `200` 同体，异参
  `409`。创建不记事件。
- `POST commit`：仅 pending 可提交；`balance+delta < 0` 为 `409`
  （状态不变、可重试）；成功原子改余额、`version+1`、转 committed，
  `201` 返回 R。并发恰一个 `201`，其余幂等 `200`；committed 重放
  `200` 同体不重复改账。操作不存在 `404`。
- `POST cancel`：请求体恰为 `{"cancel_id","approval_request_id"}`，
  两个标识沿用安全标识；请求体/ID 非法 `400`，钱包/操作/审批单不存在
  `404`。仅撤销 pending 操作：成功后转 cancelled，余额与 version 不变、
  未落账前不创建资产条目，`201` 返回既有操作视图（state=cancelled）。
  撤销复用同钱包审批：审批单必须 `approved`，message 必须逐字等于按
  `operation_id,cancel_id` 排列的紧凑 JSON
  （`{"operation_id":"...","cancel_id":"..."}`）；审批单非 approved、
  过期或 message 异文 `409`。同 cancel_id、同操作、同审批参数重放优先
  `200`；同 cancel_id 异参、撤销 committed/cancelled 操作、同一操作已有
  其他 cancel_id、或与 commit 在同钱包事务锁内并发落败均 `409` 且账本、
  version、审计不变（失败不写意图，也不懒落过期事件）。唯一取消事件
  已存在后，三键完全相同的重放优先返回 `200`，即使审批单随后推进为
  `signed` 也不再复查当前审批状态。冻结钱包撤销沿用 `409` 闸门。
- `GET asset-operations/{oid}`：在每钱包事务锁和恢复/对账后只读返回
  固定键序的既有操作视图，末键 `cancellation` 在未撤销时为 `null`；
  已撤销时为 `{cancel_id,approval_request_id,seq}`，`seq` 为
  `asset_operation_cancelled` 事件序号。非法 `operation_id` 返回 `400`，
  钱包或操作不存在返回 `404`；冻结钱包可查询。查询不触发懒过期、不写
  状态/意图/事件、不分配 seq，不改变余额、version、操作状态或摘要链。
- 撤销事务可恢复（意图与提交意图共用 `asset-intents/`，以
  `kind:"cancel"` 区分）：唯一提交点是审计事件
  `asset_operation_cancelled`（`request_id` 为 cancel_id、`actor_id` 为
  approval_request_id、details 为 cancelled 操作视图，仅首次撤销记
  一次）；崩溃按事件是否落盘前滚为 cancelled 或回滚为 pending，
  恢复不新增审计。
- `GET assets/{asset_id}`：返回 `{asset_id,balance,version}`；资产无
  已提交操作 `404`。可选查询参数 `at_seq` 读历史资产状态（见下节）。
- 重启后 pending/committed 与幂等保持，version 单调不回退、不重号。
  账本或提交意图损坏/矛盾时 fail-closed（常驻 `503`、阻止就绪），绝不
  归一为空或覆盖删除。
- 审计事件 `asset_operation_committed`（details 即 committed 视图 R，
  仅首次提交记一次）、`asset_operation_cancelled` 与
  `transaction_policy_updated`。

#### 历史资产状态（at_seq）

`GET /v1/wallets/{id}/assets/{asset_id}?at_seq=N[&expected_head=H]`
只接受 GET。`at_seq` 缺省时响应与错误语义与现状完全一致；提供时以钱包
审计序列中 `seq <= N` 的事件为边界回答历史状态，成功 `200` 返回
`{asset_id,balance,version,at_seq,head}`：

- `balance`/`version` 仅由边界内该资产**最后一条**
  `asset_operation_committed` 事件的 R（`balance`/`version`）给出；
  人工提交、链上确认、多源仲裁、派发最终性结算与重组补偿五类提交点
  统一适用，每笔已提交操作只计入一次，pending、cancelled 与幂等重放
  不改变结果；不同资产分别计算余额与版本。
- 资产变化从 `asset_operation_committed` 事件序号起生效：边界落在同批
  报告/投票/结算/重组事件但未包含提交事件时，按落账前状态回答。边界
  可落在任意事件上，不要求属于所查资产；`head` 绑定**整个钱包**审计
  前缀，为边界事件后的摘要链头，与 `audit-evidence` 同一
  `to_seq=N` 的 `end_head` 完全相同。
- 边界内该资产无已提交操作（含空钱包与资产从未落账）返回 `404`
  `asset '<id>' not found`，绝不以当前余额或零余额代替；`at_seq`
  超过当前审计尾序号返回 `404` `at_seq beyond the audit tail`。
  后续操作、策略修改或资产冻结都不改变同一边界的结果；重启或恢复
  包含该边界的合法灾备快照后结果一致。

参数规则（`parse_qs` 字符串列表；空值保留不丢弃）：

- `at_seq` 只接受由 ASCII 数字组成的正整数（空值、纯空白、带符号、
  小数、指数、Unicode 数字均非法），非法 `400` `invalid at_seq`；
- 任一新增参数重复出现 `400`
  （`duplicate at_seq parameters` /
  `duplicate expected_head parameters`）；
- `expected_head` 只能随 `at_seq` 使用（缺 `at_seq` 时连同非法
  `at_seq` 一并 `400`），格式为 64 位小写十六进制，格式错误 `400`
  `invalid expected_head`，格式合法但与 `head` 不符 `409`
  `expected_head does not match chain head`（先于边界/资产 `404`
  判定之后）。

错误次序：钱包不存在 `404` 先于一切参数校验（标识沿用现有校验，
非法 `400`）；其后为重复参数 → `at_seq` 非法 → `expected_head`
缺 `at_seq`/格式非法 → 边界越尾 `404` → 边界前资产无落账 `404` →
`expected_head` 不符 `409`。查询在既有恢复检查（`_heal_wallet`）
之后、每钱包事务锁内读取一致现场，先做与 audit-evidence 同一套 DKG
重放对账与整条摘要链完整性校验：完整审计链、账本或恢复现场损坏及
读取失败时沿用 `503` `service temporarily unavailable`，保留现场、
不返回部分结果。钱包或资产冻结时仍可使用；查询不触发审批懒过期、
不新增事件或历史状态文件，不改变余额、version 或摘要链。响应与日志
不含私钥、份额或单份额签名。

### 跨链资产确认（可选）

按资产配置链上确认策略后，该资产的 pending 操作不能人工提交，只能随
链上确认数报告达门槛后按既有 commit 契约自动提交。

- `PUT /v1/wallets/{id}/chain/{asset_id}`：请求体恰为
  `Q={"chain_id","enabled","required_confirmations","reorg_window"}`
  （含其他键或缺键一律 `400`）。`chain_id` 为安全标识；`enabled` 须为
  布尔；`required_confirmations` 为非布尔正整数；`reorg_window` 为非
  布尔非负整数。成功 `200` 返回 Q；钱包不存在 `404`。策略仅由
  `chain_policy` 审计事件持久化（`request_id` 为资产标识，
  `actor_id`/`reason` 为 `null`，details 即 Q，每个资产取最后一条
  恢复），**同值更新也记事件**，不写策略状态文件。
- `GET /v1/wallets/{id}/chain/{asset_id}`：已配置 `200` 同体，未配置
  `404`；钱包不存在 `404`。
- `POST /v1/wallets/{id}/chain/{oid}/report`：`oid` 为资产操作 id。
  请求体恰为
  `B={"chain_id","tx_id","block_height","block_hash","confirmations"}`，
  成功响应同体。`tx_id`/`block_hash` 为 64 位小写 hex；
  `block_height`/`confirmations` 为非布尔非负整数。键集/值错 `400`；
  钱包/操作未知 `404`；策略未配置或未启用、`chain_id` 与策略链不符、
  换 tx/换链冲突、同块确认数下降、高度回退越界、终态后异体报告一律
  `409`。
- 首报绑定 `tx_id` 与 `chain_id`（须等于策略链）：后续报告换 tx 或
  换链一律 `409`。同块（高度与哈希均同）确认数只增不减；换块仅限
  pending 且高度回退 `<= reorg_window`，换块后确认数可降。首报或
  采纳的新报告 `201`，同体报告幂等 `200`。
- 报告首达 `required_confirmations` 时按既有 commit 契约提交一次
  （`201`）：`chain_report` 事件（`request_id` 为操作 id，details 即
  B）与紧邻的唯一 `asset_operation_committed` 事件构成提交点；余额
  不足等提交失败时报告不落盘（`409`，可重试）。操作 committed
  （终态）后同体报告仍 `200`，异体报告 `409`。
- 策略启用时 `POST .../asset-operations/{oid}/commit` 对该资产
  pending 操作一律 `409`（committed 重放仍 `200`）；策略未配置或
  `enabled:false` 时原契约不变。
- 策略与报告状态仅由审计事件持久化：并发、跨进程、服务重启与灾备
  恢复后视图与 seq 连续不变；事件损坏/矛盾 fail-closed（常驻 `503`、
  `serve` 拒绝就绪），恢复不新增审计事件。

### 多源仲裁（可选）

按资产配置多源仲裁策略后，该资产的 pending 操作不能人工提交、也不
接受单条链上确认报告，只能由多个安全数据源各自上报达门槛观察，凑齐
quorum 后按既有 commit 契约自动提交。

- `PUT /v1/wallets/{id}/chain/{asset_id}/arbitration`：请求体恰为
  `Q={"sources","quorum"}`（含其他键或缺键一律 `400`）。`sources` 为
  ID 升序的 `{安全ID: bool}`（至少一个启用源）；`quorum` 为
  `[2, 启用源数]` 内的非布尔整数（拒绝布尔/0/1/越界/小数）。成功
  `200` 返回 Q；钱包不存在 `404`。该资产**只要存在任一 pending 资产
  操作**（即使尚无任何观察票）`PUT` 一律 `409`，策略、审计与 seq 均
  不变；无 pending 操作（全部终态或尚无操作）时方可更新。策略仅由
  **七字段 `chain_vote`** 审计事件持久化（`request_id` 为资产标识，
  `actor_id`/`reason` 为 `null`，details 键序 `sources,quorum`，每个
  资产取最后一条恢复），**同值更新也记事件**，不写策略状态文件。
- `GET .../arbitration`：已配置 `200` 同体，未配置 `404`；钱包不
  存在 `404`。
- `POST /v1/wallets/{id}/chain/{oid}/observe`：`oid` 为资产操作 id。
  请求体恰为 `{"source","report"}`，`source` 为安全 ID，`report` 为
  达门槛链上报告 B（与 chain report 同体五字段
  `{chain_id,tx_id,block_height,block_hash,confirmations}`，确认数须
  ≥ 该资产跨链确认策略的 required_confirmations）。键集/值错 `400`；
  钱包/操作/仲裁策略未知 `404`；源未知或停用、报告链与跨链策略链不
  符或跨链策略未启用、确认数未达门槛、同源改报、终态后新增票一律
  `409`。响应体为 `{"state"}`，`state` 为
  `collecting|conflict|adopted`。
- 每个源首收一张票 `201`；同源同体重放 `200`（**重放不记事件**），
  同源改报 `409`。异体报告（B 体不同）的票并存时状态为 `conflict`；
  其余未凑齐为 `collecting`；与本票同体的票数（含本票）达到 quorum
  时本票状态为 `adopted`，按既有 commit 契约提交一次（`201`）。
  余额不足等提交失败时票不落盘（`409`，可重试）。
- 达 quorum 时决定性 `chain_vote` 观察票（details 键序
  `source,report,state`，state=adopted）、`chain_report`(B) 与紧邻的
  唯一 `asset_operation_committed` 三事件在每钱包事务锁内**同批一次
  原子落盘**（seq 为 n、n+1、n+2），崩溃窗口内绝无孤票或缺 seq。
  提交后同源同体仍 `200`（state=adopted），异体或新源票 `409`。
- 仲裁策略事件与观察票事件**同为七字段 `chain_vote`**，恢复按 details
  的**精确键集**区分：`{sources,quorum}` 为策略、
  `{source,report,state}` 为票；键集两者皆非即损坏。合法旧
  `chain_arbitration` 策略事件仅**只读兼容**（与新事件一同按 seq 重放，
  每资产取最后一条；在线 PUT 不再写该类型）。
- 启用仲裁后 `POST .../chain/{oid}/report` 对该资产 pending 操作一律
  `409`（committed 重放仍 `200`）；仲裁票的 `chain_id` 必须与该资产
  已启用的跨链确认策略链一致。
- 策略与票仅由审计事件持久化：启动与持钱包锁访问都重放策略、票、操作
  和相邻提交事件；未知操作票、畸形票、重复来源、错误 state 或提交关系
  矛盾均保留现场并抛 `RecoveryError`，审计 JSON 损坏抛
  `CorruptDataError`、文件系统失败抛 `OSError`——三者 HTTP 均为 JSON
  `503`、`serve` 拒绝就绪，不新增事件或改状态。并发、跨进程、服务重启
  与灾备恢复后视图与 seq 连续不变；恢复不重报、不提交、不新增审计事件、
  不改 seq。

### 跨链派发（dispatch）

`POST /v1/wallets/{id}/chain/{oid}/dispatch`（仅 POST），`oid` 为资产
操作 id。请求体 B 恰含 `{"dispatch_id","adapter_id","approval_request_id"}`
三键（含其他键或缺键一律 `400`），三个值均须匹配安全标识
`[A-Za-z0-9_-]{1,128}`，非法 `400`：把一个 `pending` 资产操作按该资产
已启用的跨链确认策略请求派发到链上适配器。

- 钱包、操作、该资产跨链确认策略、同钱包审批单任一未知一律 `404`。
- **首提前置**：操作须为 `pending`；该资产策略须已启用
  （`enabled:true`，停用 `409`）；`approval_request_id` 必须指向
  **同一钱包**既有、且为 `approved` 的审批单（操作前按既有契约懒
  过期）；其 `message` 必须与紧凑 JSON **逐字一致**（无空格、键序
  固定为 operation_id,dispatch_id,adapter_id,chain_id）：
  `{"operation_id":"O","dispatch_id":"D","adapter_id":"A","chain_id":"C"}`，
  其中 `chain_id` 取该资产策略链。操作非 pending、策略停用、审批单
  非 `approved` 或 message 不符一律 `409`，不追加事件、现场不变。
- 成功 `201` 返回
  `V={"dispatch_id","operation_id","adapter_id","chain_id","state"}`，
  键序固定且 `state="requested"`。同 `dispatch_id` **同参**（路径
  操作、`adapter_id`、`approval_request_id` 全同）重放 `200` 返回
  同一 V（**优先于状态与审批判定，不复查审批单/策略现状**）；同
  `dispatch_id` 异参、或该操作已有其他 `dispatch_id` 的派发，一律
  `409`。
- 派发仅由审计事件持久化：`chain_dispatch_requested` 是唯一提交点
  （`request_id=dispatch_id`、`actor_id=approval_request_id`、
  `reason=null`、details 即 V，键序
  `dispatch_id,operation_id,adapter_id,chain_id,state`），不另写
  派发状态文件。首提在每钱包跨进程事务锁内追加，跨进程并发只有一个
  `201`（其余同参 `200`），审计 seq 连续不重号，失败/重放不记事件。
- 重启/灾备恢复时，每条 `chain_dispatch_requested` 都按其**提交之前**
  的现场逐条复核：操作在账本中存在且当时为 pending（提交点之前无该
  操作的提交事件）、每个操作至多一条派发、事前该资产策略（该事件
  seq 之前最后一条 `chain_policy`）已启用且链一致、同钱包审批单存在
  且 message 逐字一致、状态为 `approved`（其后经 `/sign` 推进为
  `signed` 亦认可）。重复 `dispatch_id`、审批单缺失/未批准/message
  不符或任何矛盾都 fail-closed（抛 `RecoveryError`）；`details` 键序
  在审计读取归一化**之前**校验（落盘必须恰为
  `dispatch_id,operation_id,adapter_id,chain_id,state`，错序即
  `RecoveryError`，绝不先归一而抹平重排）；审计 JSON 损坏抛
  `CorruptDataError`、审计文件 I/O 失败抛 `OSError`——三者 HTTP 一律
  `503`、`serve` 拒绝就绪。恢复不新增事件、不改 seq，响应、日志、非
  份额文件绝不泄露份额私钥或份额正文。

### 健康感知自动派发（dispatch-auto）

`POST /v1/wallets/{W}/chain/{O}/dispatch-auto`（仅 POST），`O` 为资产
操作 id。请求体 B **恰含** `{"dispatch_id","approval_request_id"}`
两键（含其他键或缺键一律 `400`；适配器不在请求体中，由服务端按健康
熔断表选择），两个值与路径 `O` 均须匹配安全标识
`[A-Za-z0-9_-]{1,128}`，非法 `400`：把一个 `pending` 资产操作按该资产
已启用的跨链确认策略**自动**派发到健康表中当前可用的链上适配器。

- 钱包、操作、该资产跨链确认策略、同钱包审批单任一未知一律 `404`。
- **首提前置**：操作须为 `pending`；该资产策略须已启用
  （`enabled:true`，停用 `409`）；**当前健康熔断表必须已配置且至少有
  一个 `up` 适配器**——服务端在该钱包跨进程事务锁内取当前快照，选其中
  ID **ASCII 最小**的 `up` 适配器（确定性、无随机性）；健康表未配置或
  表中无 `up` 适配器一律 `409`。`approval_request_id` 必须指向**同一
  钱包**既有、且为 `approved` 的审批单（操作前按既有契约懒过期）；其
  `message` 必须与紧凑 JSON **逐字一致**（无空格、键序固定为
  operation_id,dispatch_id,chain_id，**不含 adapter_id**——适配器由
  服务端选择）：
  `{"operation_id":"O","dispatch_id":"D","chain_id":"C"}`，其中
  `chain_id` 取该资产策略链。操作非 pending、策略停用、健康表未配置、
  无 `up` 适配器、审批单非 `approved` 或 message 不符一律 `409`，不
  追加事件、现场不变。
- 成功 `201` 返回
  `V={"dispatch_id","operation_id","adapter_id","chain_id","state"}`，
  键序固定（与手工 dispatch 同形）、`state="requested"`，其中
  `adapter_id` 即锁内选出的 ASCII 最小 `up` 适配器。同 `dispatch_id`
  **同参**（路径操作、`approval_request_id` 全同）重放 `200` 返回
  同一 V（**优先于状态、健康表与审批判定，不复查现场**——事后把适配器
  翻为 `down`、审批单经 `/sign` 推进都不影响幂等重放）；同
  `dispatch_id` 异参、或该操作已有其他 `dispatch_id` 的派发（手工或
  自动），一律 `409`。
- 自动派发仅由审计事件持久化：**七字段
  `chain_dispatch_auto_requested` 是唯一提交点**
  （`request_id=dispatch_id`、`actor_id=approval_request_id`、
  `reason=null`、details 即 V，键序
  `dispatch_id,operation_id,adapter_id,chain_id,state`），不另写派发
  状态文件。首提在每钱包跨进程事务锁内追加，跨进程并发只有一个 `201`
  （其余同参 `200`），审计 seq 连续不重号，失败/重放不记事件。
- **后续沿用 dispatch 契约**：result/confirm/finality/settle/takeover/
  isolate 不区分手工与自动派发——自动派发的 V 即派发请求视图，适配器
  归属、播链交易、隔离与接管规则全部与
  `chain_dispatch_requested` 相同；同一 `dispatch_id` 不得同时出现在
  两类请求事件中，同一资产操作在两类事件合计中至多一条派发，任一矛盾
  都是不可对账现场。
- 重启/灾备恢复时，每条 `chain_dispatch_auto_requested` 都按其**提交
  之前**的现场逐条复核：操作在账本中存在且当时为 pending、每操作至多
  一条派发（与手工派发交叉计数）、事前该资产策略已启用且链一致、
  **事前存在健康快照且 details.adapter_id 恰为该快照中 ASCII 最小的
  `up` 适配器**（快照缺失、无 up、所选适配器不符都 fail-closed）、同
  钱包审批单存在且 message 逐字为按
  operation_id,dispatch_id,chain_id 序的紧凑 JSON、状态为 `approved`
  （其后经 `/sign` 推进为 `signed` 亦认可）。重复 `dispatch_id`、
  跨类型重复、审批单缺失/未批准/message 不符或任何矛盾都 fail-closed
  （抛 `RecoveryError`）；`details` 键序在审计读取归一化**之前**校验
  （落盘必须恰为
  `dispatch_id,operation_id,adapter_id,chain_id,state`，错序即
  `RecoveryError`，绝不先归一而抹平重排）；审计 JSON 损坏抛
  `CorruptDataError`、审计文件 I/O 失败抛 `OSError`——三者 HTTP 一律
  `503`、`serve` 拒绝就绪。重启/灾备恢复/重放都不新增事件、不改 seq，
  沿用 README 的 JSON 字节与私钥边界。

### 跨链派发结果回执（result）

`POST /v1/wallets/{id}/chain/{did}/result`（仅 POST），`did` 为已派发
的 `dispatch_id`。请求体 B 恰含 `{"adapter_id","state","tx_id"}` 三键
（含其他键或缺键一律 `400`）：链上适配器回执一笔跨链派发的最终
结果。

- `did`/`adapter_id` 均须匹配安全标识 `[A-Za-z0-9_-]{1,128}`；
  `state` 为 `broadcasted` 或 `failed`；`state=broadcasted` 时 `tx_id`
  为 64 位小写 hex，`state=failed` 时 `tx_id` 为 `null`。键集/类型/
  值错一律 `400`；钱包或派发未知 `404`；`adapter_id` 与派发归属不符、
  或同 `dispatch_id` 异参重报一律 `409`。
- 成功 `201` 返回
  `V={"dispatch_id","operation_id","adapter_id","chain_id","state","tx_id"}`，
  键序固定（`operation_id`/`chain_id` 取自派发请求）。同 `dispatch_id`
  **同参**（`adapter_id`/`state`/`tx_id` 全同）重放 `200` 返回同一 V
  （优先于一切现状判定）；同 `dispatch_id` **异参** `409`。
- 结果仅由审计事件持久化：`chain_dispatch_result` 是唯一提交点
  （`request_id=dispatch_id`、`actor_id=adapter_id`、`reason=null`、
  details 即 V，键序
  `dispatch_id,operation_id,adapter_id,chain_id,state,tx_id`），不另写
  结果状态文件。首提在每钱包跨进程事务锁内追加，跨进程并发只有一个
  `201`（其余同参 `200`），审计 seq 连续不重号，重放不记事件。
- 启动及持锁访问按 seq 逐条复核每条 `chain_dispatch_result`：请求
  （同一 `dispatch_id` 的 `chain_dispatch_requested`）必须**先于**
  结果提交、归属一致（`operation_id`/`adapter_id`/`chain_id` 与请求
  相同）、每个派发至多一条结果。任一矛盾都 fail-closed（抛
  `RecoveryError`）；审计 JSON 损坏抛 `CorruptDataError`、审计文件
  I/O 失败抛 `OSError`——三者 HTTP 一律 `503`、`serve` 拒绝就绪，
  保留现场、不增 seq。恢复不新增事件、不改 seq，响应、日志、非
  份额文件绝不泄露份额私钥或份额正文。

### 跨链派发失败接管（takeover）

`POST /v1/wallets/{W}/chain/{D}/takeover`（仅 POST），`D` 为已派发的
`dispatch_id`。请求体 B 恰含 `{"adapter_id","approval_request_id"}`
两键（含其他键或缺键一律 `400`），两值与路径 `D` 均须匹配安全标识
`[A-Za-z0-9_-]{1,128}`，非法 `400`：把一笔**结果已 `failed`** 或**已
隔离（isolate）**的派发交给一个**新的**链上适配器重新播链。

- 钱包、派发、同钱包审批单任一未知一律 `404`。
- **首提前置**：派发所属资产操作仍为 `pending`；且下列二者恰居其一——
  该派发恰有一条 `chain_dispatch_result` 且 `state="failed"`、尚无接管
  也无隔离；**或**该派发已有一条 `chain_dispatch_isolated` 且没有任何
  result（即接管可从 `failed` 或 `isolated` 发起）；新 `adapter_id`
  必须与派发原适配器**不同**，且其在**当前**健康熔断表中**不得显式为
  `down`**（健康表未配置或该适配器缺席视为 `up`；显式 `down` 一律
  `409`）；`approval_request_id` 必须指向**同一钱包**既有、且为
  `approved` 的审批单（操作前按既有契约懒过期）；其 `message` 必须与
  紧凑 JSON **逐字一致**（无空格、键序固定为
  dispatch_id,adapter_id）：`{"dispatch_id":"D","adapter_id":"A2"}`。
  操作已提交、无结果且无隔离、结果为 `broadcasted`、隔离与结果并存、
  已接管、新旧适配器相同、新适配器显式 `down`、审批单非 `approved` 或
  message 不符一律 `409`，不追加事件、现场不变（零副作用）。
- 成功 `201` 返回
  `V={"dispatch_id","adapter_id","state"}`，键序固定且
  `state="requested"`。同 D **同参**（`adapter_id`、
  `approval_request_id` 全同）重放 `200` 返回同一 V（**优先于一切现状
  判定，不复查现场**）；同 D 异参、或对已接管派发再次接管一律 `409`。
- 接管仅由审计事件持久化：**七字段
  `chain_dispatch_taken_over`** 是唯一提交事件
  （`request_id=D`、`actor_id=approval_request_id`、`reason=null`、
  details 即响应 V，键序 `dispatch_id,adapter_id,state`），不另写接管
  状态文件。首提在每钱包跨进程事务锁内追加，跨进程并发只有一个 `201`
  （其余同参 `200`），审计 seq 连续不重号，重放不记事件。
- **接管之后**：`result` 只接受**新适配器**的**恰好一条**结果（隔离后
  或接管后的旧适配器回执、或新适配器第二条/异参结果一律 `409`，同参仍
  `200`）；
  `confirm` 只承接新适配器 `broadcasted` 交易的确认进展（新适配器、
  新 tx；旧适配器身份或旧 tx 一律 `409`）；`finality`/`settle` 以及
  已结算后的重组补偿随之以接管后的生效适配器与交易链为准，契约不变。
- 重启/灾备恢复按 seq 逐条复核每条 `chain_dispatch_taken_over`：派发
  请求必须**先于**接管；接管时资产操作仍为 pending（其提交点不得早于
  接管）；接管前置为互斥二者之一——接管之前恰有一条 `failed` 结果且无
  隔离，**或**接管之前有一条 `chain_dispatch_isolated` 且没有任何
  result；两种接管都要求新适配器不同于原适配器；
  actor_id 指向同钱包审批单且存在、message 逐字为按
  dispatch_id,adapter_id 序的紧凑 JSON、状态为 `approved`（其后经
  `/sign` 推进为 `signed` 亦认可）；每派发至多一条接管。接管后那条
  结果在结果对账中按接管事件校验归属（新适配器、operation/chain 不变）
  ，确认/结算/重组对账按接管后的生效适配器与 broadcasted 交易复核。
  重复接管、审批单缺失/未批准/message 不符、结果或归属矛盾都
  fail-closed（抛 `RecoveryError`）；`details` 键序在审计读取归一化
  **之前**校验（落盘必须恰为 `dispatch_id,adapter_id,state`，错序即
  `RecoveryError`）；审计 JSON 损坏抛 `CorruptDataError`、审计文件
  I/O 失败抛 `OSError`——三者 HTTP 一律 `503`、`serve` 拒绝就绪。
  恢复不新增事件、不改 seq，重放不记事件。

### 跨链派发隔离（isolate）

`POST /v1/wallets/{W}/chain/{D}/isolate`（仅 POST），`D` 为已派发的
`dispatch_id`。请求体**须恰为空 JSON 对象 `{}`**（夹带任何键、空体、
非 JSON、非 JSON 对象一律 `400`）：把一笔尚在途、但其派发原适配器已在
当前健康熔断表中显式 `down` 的派发标记为隔离，此后只允许由**新的**适配
器接管（见上文 takeover），旧适配器不再被采信。

- 路径 `D` 须匹配安全标识 `[A-Za-z0-9_-]{1,128}`，非法 `400`；钱包或
  派发未知 `404`（存在性先于参数判定）。
- **首提前置**（全部在该钱包跨进程事务锁内判定，任一不满足 `409` 且
  **零副作用**，均抛 `ServiceError`——不追加事件、现场不变）：
  - 派发所属资产操作仍为 `pending`；
  - 该派发没有任何 `chain_dispatch_result`、没有 `chain_dispatch_taken_over`、
    没有 `chain_dispatch_isolated`（result/takeover/isolate 互斥在前）；
  - 派发**原适配器**（dispatch 请求中的 `adapter_id`）在**当前**
    `chain_adapter_health` 健康表中显式为 `down`；健康表未配置、该适配器
    在表中缺席或为 `up`，一律视为不可隔离（`409`）。
- 成功 `201` 返回
  `V={"dispatch_id","adapter_id","state"}`，键序固定且
  `state="isolated"`，`adapter_id` 为派发原适配器。**同 D 重放优先
  `200` 返回同一 V**，不复查健康表与现场现状（事后把适配器翻回 `up` 不
  影响幂等重放）。
- 隔离仅由审计事件持久化：**七字段
  `chain_dispatch_isolated`** 是唯一提交事件（`request_id=D`、
  `actor_id=null`、`reason=null`、details 即响应 V，details 键序
  `dispatch_id,adapter_id,state`，外层七字段按落盘规范序
  `actor_id,at,details,reason,request_id,seq,type`），不另写隔离状态
  文件。首提在每钱包跨进程事务锁内追加，跨进程并发只有一个 `201`（其余
  同 D 重放 `200`），审计 seq 连续不重号，重放不记事件。
- **隔离之后**：旧适配器（原 `adapter_id`）的 `result` 一律 `409`
  （failed/broadcasted、同参异参皆然）；该派发可按 takeover 契约由一个
  **不同于原适配器**的新适配器接管（接管前置此时为「已隔离且无结果」，
  与「恰一条 failed 结果」二选一，见下）；接管后新适配器的
  result/confirm/finality/settle 契约不变。
- 重启/灾备恢复按 seq 逐条复核每条 `chain_dispatch_isolated`：同一
  `dispatch_id` 的 `chain_dispatch_requested` 必须**先于**隔离提交且
  details 适配器一致；隔离提交**之前最近**一条 `chain_adapter_health`
  快照必须存在且该适配器显式为 `down`；隔离时操作仍 pending（提交点不
  得早于隔离）；隔离之前没有任何 result/takeover；隔离之后、接管（若有）
  之前不得出现 result；每个 `dispatch_id` 至多一条隔离。任一矛盾都保留
  现场并抛 `RecoveryError`；审计 JSON 损坏抛 `CorruptDataError`、审计
  文件 I/O 失败抛 `OSError`——三者 HTTP 一律 `503`、`serve` 拒绝就绪。
  重启/灾备恢复/重放都不新增事件、不改 seq。

### 跨链派发确认进展（confirm）

`POST /v1/wallets/{id}/chain/{did}/confirm`（仅 POST），`did` 为已派发
的 `dispatch_id`。请求体 B 恰含
`{"adapter_id","tx_id","block_height","block_hash","confirmations"}`
五键（含其他键或缺键一律 `400`）：链上适配器上报一笔已播链派发的
确认进展。

- `did`/`adapter_id` 均须匹配安全标识 `[A-Za-z0-9_-]{1,128}`；
  `tx_id`/`block_hash` 为 64 位小写 hex；`block_height`/`confirmations`
  为非布尔非负整数。键集/类型/值错一律 `400`；钱包或派发未知 `404`；
  无 `broadcasted` 结果（尚无结果或结果为 `failed`）、`adapter_id` 或
  `tx_id` 与派发归属（请求适配器 / 播链交易）不符、或迁移冲突一律
  `409`。
- 阈值/窗口取**派发请求提交之前**该资产已启用策略的
  `required_confirmations`/`reorg_window`：同块（高度与哈希均同）
  确认数只增不减；换块（迁移）仅限确认中且
  `0 ≤ 旧高度 − 新高度 ≤ reorg_window`；确认数达
  `required_confirmations` 即转 `finalized`（终态），终态仅许历史
  同体重放，新进展一律 `409`。
- 新进展 `201` 返回
  `V={"dispatch_id","adapter_id","tx_id","block_height","block_hash","confirmations","state"}`，
  键序固定，`state` 为 `confirming|finalized`（已结算派发的重组补偿
  另有 `reorged`，见下）。历史同体（B 五键全同）
  重放**优先**返回 `200` 与原 V（含原 state），不复查现状；同
  `dispatch_id` 异体新进展按状态机判定。
- **已结算派发的重组补偿**：派发已 `settle` 后，`confirm` 仅接受
  重组形态的新 B——`adapter_id` 与派发归属一致，且相对最后一条
  （`finalized`）进展 `tx_id` 或区块（高度/哈希）改变、
  `confirmations` 低于 `required_confirmations`、高度回退
  `0 ≤ 旧高度 − 新高度 ≤ reorg_window`；其余一律 `409`，历史同体
  仍 `200`。接受时以 `D` 为 `operation_id` 创建**同资产、反向
  delta** 的补偿操作并原子提交：补偿 id 被占用或补偿后余额将负
  一律 `409` 且**零副作用**（不写意图/账本、不记事件）。成功 `201`
  返回既有七键 V（`state="reorged"`）；同 B 重放 `200` 同 V、异体
  `409`，锁内并发只有一个 `201`。重组在每钱包跨进程事务锁内**原子**
  完成并连续追加三个七字段事件：`chain_dispatch_confirmation`
  （details 即 V）、`chain_dispatch_reorged`（details 键序恰为
  `dispatch_id,operation_id`，两值均为 `D`）、
  `asset_operation_committed`（details 即补偿操作的 R，落盘与恢复键序
  恰为 `operation_id,asset_id,delta,state,balance,version`），seq 为
  n、n+1、n+2 一次原子落盘，三事件 `request_id=D`、
  `actor_id=adapter_id`、`reason=null`。三事件**俱在前滚、俱无
  回滚**：崩溃后按提交意图对账——俱在则前滚补齐账本，俱不在则删除
  新建补偿操作并恢复提交前余额/version；残缺或矛盾（含任一 details
  键序被重排，含补偿提交事件不按上述 R 序）是不可对账现场，抛
  `RecoveryError` 并保留现场（常驻 `503`、`serve` 拒绝就绪）。
  `reorged` 同为终态：其后不再接受任何新进展（历史同体重放除外）。
- 确认进展仅由审计事件持久化：`chain_dispatch_confirmation` 是唯一
  提交点（`request_id=dispatch_id`、`actor_id=adapter_id`、
  `reason=null`、details 即 V，键序
  `dispatch_id,adapter_id,tx_id,block_height,block_hash,confirmations,state`），
  不另写确认状态文件。首提在每钱包跨进程事务锁内追加，跨进程并发只有
  一个 `201`（其余同体 `200`），审计 seq 连续不重号，重放不记事件。
- 启动、持锁访问与灾备恢复按 seq 逐条复核每条
  `chain_dispatch_confirmation`：请求与 `broadcasted` 结果必须**先于**
  确认提交、归属一致（`adapter_id` 同请求、`tx_id` 同结果）、迁移状态机
  （同块不降、换块窗口、达门槛即 finalized、终态后无新进展、无同体
  重复事件）逐条成立。任一矛盾都 fail-closed（抛 `RecoveryError`）；
  审计 JSON 损坏抛 `CorruptDataError`、审计文件 I/O 失败抛
  `OSError`——三者 HTTP 一律 `503`、`serve` 拒绝就绪，保留现场、不改
  账本、不写旁路文件、不重记。恢复不新增事件、不改 seq，响应、日志、
  非份额文件绝不泄露份额私钥或份额正文。

### 跨链派发最终性查询与资产结算（finality / settle）

`GET /v1/wallets/{W}/chain/{D}/finality`（仅 GET），`D` 为已派发的
`dispatch_id`：查询一笔已播链派发的最终性。

- 成功 `200` 返回
  `F={"operation_id","chain_id","confirmation"}`，键序固定，末值为
  confirm 既有七键 V（即最后一条确认进展，含其 `confirming|finalized`
  状态）。**纯只读**：不写文件、不记事件、不分配 seq。
- `D` 非法 `400`；钱包/派发未知 `404`；无 `broadcasted` 结果（尚无
  结果或结果为 `failed`）或尚无任何确认进展一律 `409`。

`POST /v1/wallets/{W}/chain/{D}/settle`（仅 POST），**空体**（零字节）
请求：把一笔已 `finalized` 派发源资产操作按既有 commit 契约结算一次。
非空体（含空 JSON 对象 `{}`）一律 `400`。`D` 非法 `400`；钱包/派发
未知 `404`。

- **首提前置**：派发归属（`adapter_id`）、播链交易（`tx_id`）与事件链
  一致，最后一条确认进展 V 已 `finalized`，且资产操作仍为 `pending`。
  确认中（`confirming`/无确认）、余额不足、或操作已在别处提交（链上
  确认自动提交、人工提交等）一律 `409`，**无任何副作用**（不写意图/
  账本、不记事件）。
- 首提 `201` 返回既有资产操作视图
  `R={operation_id,asset_id,delta,state,balance,version}`
  （`state="committed"`，balance/version 按既有 commit 契约改账）；
  同 `D` 重放**优先** `200` 返回同一 R（不复查现状，不记事件）；
  `201`/`200` 的 R 键序统一为
  `operation_id,asset_id,delta,state,balance,version`；锁内并发
  只有一个 `201`，其余幂等 `200`。
- 结算在每钱包跨进程事务锁内**原子**完成并相邻追加两个七字段事件：
  `chain_dispatch_settled` 与紧邻的唯一
  `asset_operation_committed`（seq 为 n、n+1，一次原子落盘）。前者
  `request_id=D`、`actor_id=adapter_id`、`reason=null`、details 键序
  恰为 `dispatch_id,operation_id`；后者 details 即 R（与既有提交事件
  同形）。两事件**俱在前滚、俱无回滚**：崩溃后启动或下一次持锁访问
  按提交意图对账——两事件都在则前滚补齐账本，都不在则回滚 pending 与
  提交前余额/version；只落其一是不可对账现场，抛 `RecoveryError` 并
  保留现场（常驻 `503`、`serve` 拒绝就绪）。
- 最终性查询沿用 confirm 的紧凑 JSON 字节规则（成功体与错误体均为
  UTF-8 紧凑 JSON，无末换行）；重放不记事件，响应、日志与非份额文件
  绝不泄露私钥或份额正文。

### 跨链适配器健康熔断（可选）

`PUT /v1/wallets/{W}/chain-adapters` 设置跨链适配器健康熔断表，请求体
与成功响应（`200`）同为
`Q={"adapters": {适配器ID: "up"|"down", ...}}`：

- `adapters` 必须**非空**；键 A 匹配安全标识
  `[A-Za-z0-9_-]{1,128}`，请求体与返回/落盘均须按 **ASCII 升序**排列
  （键未升序即 `400`，服务端不替客户端重排）；每个值恰为字符串 `"up"`
  或 `"down"`（布尔等非字符串一律拒）。键集、类型、顺序、值错一律
  `400`。
- `GET` 已配置 `200` 返回 Q，**从未配置 `404`**；钱包不存在时 GET/PUT
  一律 `404`；`PUT` 可首建。健康表仅由 **七字段
  `chain_adapter_health`** 审计事件持久化
  （`request_id`/`actor_id`/`reason` 均为 `null`，details 恰为 Q，取最后
  一条恢复），不写状态文件。**首配/变更各记一条事件；同值不记**（并发
  同参在钱包跨进程锁内线性化，只有一个首配、其余同值不记）。
- 恢复对每条 `chain_adapter_health` 事件严格校验 README 键序：事件
  **外层七字段**须为落盘规范序
  （`actor_id,at,details,reason,request_id,seq,type`）、details 恰含
  `adapters`、适配器 ID 按 ASCII **升序唯一**、每个值恰为 `up|down`；
  重排、形状或取值矛盾都 fail-closed（抛 `RecoveryError`，常驻 `503`、
  `serve` 拒绝就绪、**不写盘**），重启/灾备恢复后健康表与 seq 不变。
- `PUT`/`GET` 成功体与错误体均为 UTF-8 紧凑 JSON（`ensure_ascii`，非
  ASCII 原样、无末换行）。

**对派发的熔断语义**（`POST /v1/wallets/{W}/chain/{O}/dispatch`，其余
派发契约不变）：

- 仅作用于派发**首提**：首提指向的 `adapter_id` 在当前健康表中显式为
  `down` 时抛 `ServiceError(409)`，**零副作用**（不追加事件、现场不
  变）。健康表未配置、或该适配器在表中缺席，一律视为 `up`（不熔断）。
- **同参重放优先 `200`**：已提交派发的同参重放先于健康判定直接返回，
  事后把适配器翻为 `down` 不影响幂等重放。
- 健康变化**不改写、不终止、也不自动接管**任何已有派发；result/confirm/
  takeover/finality/settle 等其余派发接口契约不变。显式 `down` 适配器
  的在途派发只能经 `POST .../isolate` 显式隔离、再由新适配器 takeover
  （或在收到 `failed` 回执后直接 takeover）；隔离首提与 takeover 首提
  对新适配器的健康判定都在钱包锁内按当前快照完成。
- 健康表同时服务于**健康感知自动派发**
  （`POST .../dispatch-auto`，详见上文「健康感知自动派发」）：自动派发
  要求健康表已配置且至少一个显式 `up` 适配器，并在钱包锁内取 ASCII
  最小的 `up`；表未配置或无 `up` 一律 `409`。
- 健康表的读取、更新与派发判定都在该钱包跨进程事务锁内线性化。

### 审计事件

### 钱包应急冻结（freeze / unfreeze）

`POST /v1/wallets/{id}/freeze` 与 `POST /v1/wallets/{id}/unfreeze`
（仅 POST），请求体**恰为** `{"reason":"..."}`（缺键、夹带其他键、非
JSON 对象、`reason` 非字符串、空串/纯空白或超过 1024 字符一律 `400`）；
`reason` 为 1 到 1024 个字符的非空白字符串（首尾允许空白但必须含非空白
字符）。钱包不存在 `404`。

- `GET /v1/wallets/{id}/security-state` 始终 `200` 返回
  `{"wallet_id","state","reason"}`，键序固定，`state` 为
  `active|frozen`；活跃（active）时 `reason` 为 `null`，冻结（frozen）时
  `reason` 为最近一次冻结的原文。
- 首次转换 `201`：active 钱包 freeze 转 frozen、frozen 钱包 unfreeze 转
  active；响应同 security-state 视图。当前状态对应的最近一次**同类转换
记录**（frozen 时最近 `wallet_frozen`、active 时最近
  `wallet_unfrozen`）与请求 **同 reason** 时幂等重放 `200`（返回当前视图，
不复查现场、不记事件）；reason 与该记录不同 `409`。从未冻结过的天然
active 钱包没有 unfreeze 记录，对其 unfreeze 一律 `409`。
- **冻结闸门**：钱包 frozen 时，该钱包**全部既有写接口**统一返回 `409`，
  包括审批（建单/批准/拒绝）、`/sign` 与签名会话（建会话/投递/参与者
  替换与接管）、轮换准备/激活与 share-bind 参与者迁移、资产操作与全部
  跨链接口（策略/报告/仲裁/派发/回执/确认/接管/隔离/结算）、两方 DKG 与
  故障轮次、节点健康表/rejoin 与适配器熔断表、三类策略写入——即便请求本
  来命中幂等 `200` 重放也一律 `409` 且**零副作用**（不触发懒过期、不追加
  事件、不改现场）；闸门在每钱包事务锁内、钱包存在性判定之后判定。
  冻结期间只有查询、审计读取、security-state、freeze 与 unfreeze 可用；
  查询路径上的审批单/签名会话懒过期在冻结期间挂起（不记
  `request_expired`/`session_event`，按磁盘现状返回），解冻后首次访问再
  按既有契约到期。未冻结时既有接口的 `201/200/409` 语义完全不变。
- 状态**只由审计事件承载**，不写任何状态文件：`wallet_frozen` 与
  `wallet_unfrozen` 是唯一提交点，`request_id`/`actor_id`/`reason` 均为
  `null`，details 恰为 `{"reason":"..."}`。判定与事件追加在每钱包跨进程
  事务锁内原子完成：同一操作并发只有一个 `201`，其余同参请求得到 `200`，
  审计 seq 连续不重号，重放不产生新事件。
- **崩溃与灾备恢复**：启动、持锁访问与 backup/restore 都按 seq 折叠两类
  事件重建状态（无事件为 active；事件必须严格交替，首条必为
  `wallet_frozen`），恢复不新增事件、不改 seq；frozen 状态与冻结闸门在
  服务重启及快照恢复后继续生效。事件 details 畸形（reason 非 1..1024
  非空白字符串、夹带字段）、三 id 字段非 null 或同态连续（重复 freeze /
  重复 unfreeze）等现场自相矛盾一律抛 `RecoveryError`；审计 JSON 损坏抛
  `CorruptDataError`；文件 I/O 失败抛 `OSError`——三者 HTTP 统一 `503`、
  `serve` 拒绝就绪，保留现场不猜写。reason 原文只出现在事件 details 与
  security-state/freeze 响应中，不进入访问日志。

### 资产粒度应急冻结（asset freeze / unfreeze）

在钱包级冻结之外，另提供按资产粒度的应急冻结，只影响单个有已提交余额
的资产，钱包内其余资产与全部既有功能行为不变。

- `POST /v1/wallets/{id}/assets/{asset_id}/freeze` 与
  `POST /v1/wallets/{id}/assets/{asset_id}/unfreeze`（仅 POST），请求体
  **恰为** `{"reason":"..."}`（与钱包冻结同一 reason 规则：缺键、夹带、
  非 JSON 对象、非字符串、空串/纯空白或超过 1024 字符一律 `400`）。
  `asset_id` 非法 `400`；钱包不存在或该资产**尚无已提交操作**（只有
  pending/cancelled 操作不构成资产现场）`404`。
- `GET /v1/wallets/{id}/assets/{asset_id}/security-state` 返回固定键序
  `{wallet_id,asset_id,state,reason}`，`state` 仅取 `active|frozen`；
  active 时 `reason` 为 `null`，frozen 时为最近一次冻结原文。钱包不存
  在或资产尚无已提交操作 `404`，标识非法 `400`。纯只读，不触发懒过期、
  不分配 seq。
- 首次转换 `201`：active 资产 freeze 转 frozen、frozen 资产 unfreeze 转
  active，响应同 security-state 视图。当前状态最近一次**同类转换记录**
  （frozen 时最近 `asset_frozen`、active 时最近 `asset_unfrozen`）与请求
  **同 reason** 时幂等重放 `200`（不复查现场、不记事件）；reason 不同、
  重复冻结、或对从未冻结资产解冻一律 `409`。
- **冻结闸门**：资产 frozen 时，改变该资产余额、version、操作状态或链上
  派发进程的写入口统一 `409`，覆盖资产操作创建/提交/撤销，跨链确认策略
  与多源仲裁策略更新，链上确认报告（report）与观察上报（observe），
  跨链派发请求（dispatch/dispatch-auto）、结果回执（result）、确认进展
  （confirm，含已结算派发的重组补偿）、接管（takeover）、隔离（isolate）
  与结算（settle）——即便请求本来命中幂等 `200` 重放也一律 `409` 且
  **零副作用**（不触发懒过期、不追加事件、不改现场）。闸门在每钱包事务
  锁内、钱包冻结闸门与存在性判定之后、幂等/业务判定之前判定；钱包 frozen
  时钱包闸门优先。冻结期间该资产的只读接口（资产/操作/策略/最终性查询、
  审计读取、security-state）返回磁盘现状，其他资产与钱包其余行为不变。
- 状态**只由审计事件承载**，不写任何状态文件：`asset_frozen` 与
  `asset_unfrozen` 是唯一提交点，`request_id` 为资产标识、`details` 恰为
  固定序 `{"asset_id","reason"}`（两值绑定同一资产），`actor_id` 与外层
  `reason` 恒为 `null`。判定与事件追加在每钱包事务锁内原子完成：同一转换
  并发只有一个 `201`，其余同参 `200`，seq 连续不重号，重放不记事件。
- **崩溃与灾备恢复**：启动、持锁访问与 backup/restore 按 (钱包, 资产)
  分组折叠两类事件重建状态，每资产事件必须严格交替（首条必为
  asset_frozen）；每条事件绑定的资产都必须在账本中存在已提交操作；恢复
  不新增事件、不改 seq，重启及快照恢复后冻结继续生效、闸门不变。事件
  details 畸形（reason 非 1..1024 非空白字符串、夹带/错序字段）、
  asset_id 与 request_id 不符、三 id 字段非 null、同态连续、或冻结事件
  引用无已提交操作资产等矛盾现场一律抛 `RecoveryError`；审计 JSON 损坏
  抛 `CorruptDataError`；文件 I/O 失败抛 `OSError`——三者 HTTP 统一
  `503`、`serve` 拒绝就绪并保留现场。reason 原文只出现在事件 details 与
  security-state/freeze 响应中，不进入访问日志；响应、日志与审计不含
  私钥、份额或份额签名。

`GET audit-events` 返回 `{"wallet_id","events":[...]}`，按 `seq` 升序。
`from_seq`/`limit` 为正整数，默认 1/1000，limit 上限 1000；非法 `400`，
钱包不存在 `404`。纯只读，不触发懒过期、不分配 seq。

每条事件七字段 `seq,type,at,request_id,actor_id,reason,details`，
`at` 为 UTC（`...Z`），不适用字段为 `null`。seq 从 1 起、落盘后单调
递增，**服务重启后续写、连续不重号；恢复不新增审计事件**。事件类型：
`policy_updated`、`request_created/approved/rejected/expired/signed/cancelled`、
`share_rotation_prepared/activated`、`asset_operation_committed`、
`asset_operation_cancelled`（`request_id` 为 cancel_id、`actor_id` 为
approval_request_id、details 即 cancelled 操作视图）、
`transaction_policy_updated`、`session_event`、
`session_participant_replaced`、`session_takeover`、`dkg_stage`、
`dkg_failover`、`dkg_failover_policy_updated`、`node_state`、
`node_rejoined`、`share_participant_reinstated`、`chain_policy`、
`chain_report`、`chain_arbitration`、`chain_vote`、
`chain_dispatch_requested`、`chain_dispatch_auto_requested`、
`chain_dispatch_result`、
`chain_dispatch_confirmation`、`chain_dispatch_settled`、
`chain_dispatch_reorged`、`chain_dispatch_taken_over`、
`chain_dispatch_isolated`、`chain_adapter_health`。
钱包应急冻结/解冻另有 `wallet_frozen`、`wallet_unfrozen`（details 恰为
`{"reason":"..."}`，两类事件严格交替，按 seq 折叠出 active/frozen 状态）。
资产粒度应急冻结/解冻另有 `asset_frozen`、`asset_unfrozen`
（`request_id` 为资产标识、details 恰为固定序
`{"asset_id","reason"}`，两类事件按 (钱包, 资产) 分组严格交替，按 seq
折叠出各资产 active/frozen 状态）。
高风险配置双人变更另有 `policy_change_applied`（`request_id` 为 change_id、
`actor_id` 为 approval_request_id、reason 为 null，details 恰含
`change_id,target,before,after,approval_request_id` 五键固定序；同时作为七类
受控配置的快照事件按 seq 折叠）。

### 审计完整性（摘要链）
审计文件顶层携带顺序摘要链 `chain`，恰含 `algorithm`/`head`/`count`，
`algorithm` 固定 `sha256`。首条前序摘要为 64 个零字符；每条事件把七个
字段（含 `details`）按审计读取归一化后的形态取键升序编码为 UTF-8 紧凑
JSON（无空白、非 ASCII 不转义），先算事件 SHA-256（64 位小写十六进制），
再以"前序摘要文本 + 事件摘要文本"计算下一个链头。旧记录缺链时按事件
顺序补算（启动读取边界、事件追加与出包迁移点），不改写事件正文；
启动恢复对缺链审计持锁补算并持久化后才对外服务（恢复不新增审计事件、
seq 与事件正文不变）。链元数据存在却不匹配、事件被改动、seq 不连续、
details 形状矛盾一律 fail-closed（`503`、serve 拒绝就绪、保留现场
不覆盖）。

`GET /v1/wallets/{id}/audit-integrity` 只接受 GET（其他方法 `405`），
成功返回 `{"wallet_id","state","count","head"}`，`state` 恒为 `valid`，
`count` 为事件数、`head` 为 64 位小写十六进制（无事件时为 64 个零）。
可带 `expected_head`：格式或钱包标识非法 `400`，钱包不存在 `404`，
期望摘要与链头不符 `409`；不带该参数时只校验链。审计记录及链元数据
随灾备快照校验，摘要不完整或被篡改时恢复失败且不写目标数据。

#### 区间逐条证据（audit-evidence）

`GET /v1/wallets/{id}/audit-evidence?from_seq=F&to_seq=T[&expected_head=H]`
只接受 GET（其他方法 `405`，`error` 为 `method not allowed`），供审计方
取得区间逐条摘要及前后局部链头。`from_seq`/`to_seq` 为正整数且
`from_seq <= to_seq`，区间至多 1000 条；`expected_head` 可省，提供时
为 64 位小写十六进制且须等于范围结束后的摘要头。成功 `200` 返回
`{"wallet_id","range","events","event_digests","start_head","end_head",
"count","state"}`：

- `range` 为 `{"from_seq":F,"to_seq":T}`；`events` 按 seq 升序并沿用
  audit-events 的公开七字段视图，不含密钥或中间值；
- `event_digests` 与 `events` 一一对应，按既有七字段摘要规则（七键键
  升序紧凑 JSON 的 SHA-256）计算；
- `start_head` 为 from_seq 前一事件后的链头，from_seq 为 1 时是 64 个
  零；`end_head` 为 to_seq 后的链头，可由 start_head 与 event_digests
  按既有递推规则（前序摘要文本 + 事件摘要文本）复算；
- `count` 为区间事件数，`state` 恒为 `valid`。

错误次序（钱包存在性先于参数判定，钱包不存在 `404`）：缺参 `400`
`missing evidence parameters`、重复参数 `400`
`duplicate evidence parameters`、`from_seq` 非法 `400`
`invalid from_seq`、`to_seq` 非法 `400` `invalid to_seq`、
`expected_head` 格式非法 `400` `invalid expected_head`、范围非法
（from>to 或超 1000 条）`400` `invalid evidence range`；空钱包（无
任何事件）`404` `empty evidence range`；`to_seq` 越界 `404`
`evidence range out of bounds`；expected_head 与 end_head 不符 `409`
`expected_head does not match chain head`；审计不可对账（链元数据
缺失/矛盾、事件被改动等）`503` `service temporarily unavailable`。
证据为纯只读：不分配 seq、不改状态、不写文件；同一区间重复查询结果
一致，追加事件后旧 end_head 仍可作为新请求的 expected_head 验证新的
链头。成功体与错误体均为 UTF-8 紧凑 JSON（非 ASCII 不转义、无末换行）。

## 多进程与故障恢复（保证）

- 多进程可共用同一 data-dir：状态变更与审计追加都在每钱包跨进程事务锁
  （`locks/<id>.lock`，fcntl.flock）内提交；进程异常退出内核自动释放
  锁。跨进程并发或重启交错时同一操作只有一个首次提交，其余按幂等重放。
- 轮换激活、资产提交、签名会话、灾备恢复都以审计事件/事务标记为唯一
  提交点：崩溃后启动或下一次持锁访问自动前滚或回滚到一致现场，恢复窗口
  内任何请求都看不到半状态；无法安全对账时 fail-closed（阻止就绪 /
  `503`），保留现场、不猜写、不静默跳过。恢复不新增审计、不改余额/
  version，后续签名、轮换、会话与历史公钥验证继续有效。

## 命令行

`create`/`sign`/`show` 及 `policy`/`request-create`/`request-show`/
`approve`/`reject`/`request-cancel` 与 HTTP 接口一一对应，成功打印单行 JSON 到 stdout，
失败打印单行 `{"error":...}` 到 stderr 并非零退出；客户端命令用 `--url`
（默认 `http://127.0.0.1:8080`）。

`share-sign` 为份额持有方本地辅助命令，用 `--data-dir` 在该钱包事务锁
内先自愈再按当前在用份额签名（不经网络）：

```bash
python -m threshold_wallet.cli create --wallet-id alice --shares 2
S1=$(python -m threshold_wallet.cli share-sign --wallet-id alice --share-id share-1 \
     --signing-request-id req-1 --message pay-100 | python -c "import sys,json;print(json.load(sys.stdin)['signature'])")
S2=$(python -m threshold_wallet.cli share-sign --wallet-id alice --share-id share-2 \
     --signing-request-id req-1 --message pay-100 | python -c "import sys,json;print(json.load(sys.stdin)['signature'])")
python -m threshold_wallet.cli sign --wallet-id alice --signing-request-id req-1 \
     --message pay-100 --signature share-1=$S1 --signature share-2=$S2
```

## 兼容灾备（backup / restore）

两个**离线**子命令直接在 `--data-dir` 上工作（不经 HTTP），只操作单个
钱包 `--wallet-id W`，绝不触碰 data-dir 内其他钱包的任何文件。

```bash
python -m threshold_wallet.cli backup --data-dir ./data \
     --wallet-id alice --snapshot-id snap-1 --output ./alice.tar
python -m threshold_wallet.cli restore --data-dir ./data2 \
     --wallet-id alice --input ./alice.tar
```

### backup

参数：`--data-dir D`、`--wallet-id W`、`--snapshot-id S`（匹配
`[A-Za-z0-9_-]{1,128}`，否则失败退出）、`--output B`。

- **输出边界**：`--output` 解析后（含符号链接）必须位于 data-dir
  **之外**，否则在取得钱包锁后、读取任何文件前即以 400 失败。指向
  data-dir 内的业务/份额/事务/记录/锁文件（无论是否已存在）、data-dir
  本身、或同目录原子临时路径都被拒绝；失败不触发自愈、不改动钱包现场
  或既有快照。输出位于 data-dir 外时先写同目录临时文件再原子替换，
  写盘中断或并发调用都不会留下半包。
- 在该钱包跨进程事务锁内先自愈轮换/资产意图/签名会话现场（与线上同一套
  恢复），无法对账即失败——**不能对账不出包**。
- 仅打包该钱包白名单内普通文件：`wallets/W.json`、`shares/W/*`、业务
  目录中的 W 单文件（`audit`/`signatures`/`policies`/`requests`/
  `rotations`/`assets`/`transaction-policies`/`sign-sessions`）与
  `rotation-staging/W/*`。拒绝绝对路径、`..` 穿越、重复成员、符号链接、
  白名单外额外文件、锁文件、原子写临时文件与激活备份（`*.bak.json`）。
- 产物为确定性 tar，首项 `manifest.json`（**manifest v1**），含
  `version`、`wallet_id`、`snapshot_id` 与每项 `{path,bytes,sha256}`；
  `manifest_sha256` 绑定**含 S 在内**的 manifest 主体 sha256，使 S 与
  内容不可分别篡改。manifest 只含标识/公钥/哈希/整数/业务原文，**绝不
  含份额私钥**。
- 成功 stdout 单行 `{"status":201,"snapshot_id","manifest"}`；失败
  stderr 单行 `{"error":...}`、退出码 1（钱包不存在 404、非法标识 400、
  无法对账/读盘失败 503）。

### restore

参数：`--data-dir D`、`--wallet-id W`、`--input B`。在该钱包事务锁内
先收敛上一次崩溃的恢复、再自愈线上现场，然后做**全量校验，失败绝不
写盘**：

- 身份：manifest 的 `wallet_id` 必须等于命令行 W，否则 `409`；
- 白名单与哈希：成员路径合法、无重复/链接/额外，每项字节数与 sha256
  与 manifest 一致，manifest 绑定哈希验通；
- 形状/公私钥：各 JSON 形状严格；当前两份份额私钥各 32 字节、可推出
  份额公钥并拼成钱包公钥；
- 审计 `seq` 自 1 起连续；账本 version/余额重算自洽且与
  `asset_operation_committed` 事件一一对应；会话按 `session_event`
  严格对账（历史公钥逐份重验、聚合签名重算）；轮换激活链连续；审批单
  与请求类事件双向一致；
- 每条已完成签名都能用其**签名时刻**（由轮换链确定）的钱包公钥拆半
  独立验通，保证历史签名连续。

提交是崩溃安全事务：先写 `restore-txn/W/S/prepared.json` 并把替换前
文件完整备份到其 `old/`（备份清单带每项 path/bytes/sha256），再原子
替换目标、删除多余文件，最后写 `committed.json` 作为唯一提交点。

崩溃后（启动恢复或下一次持钱包锁访问）按标记收敛：

- **committed 在**：先封闭校验标记的 `wallet_id`、`snapshot_id`、
  `manifest_sha256` 与 `files` 项（path/bytes/sha256）。路径必须是目标
  钱包白名单内的相对普通文件，不能重复、越界、缺失、符号链接或额外；
  逐项核对 bytes 与 sha256，并核对目标集合严格相等。任一不符统一
  **503**、阻止 serve 就绪、该钱包访问失败，**保留 restore-txn，不
  补写、不删除、不登记 restore-records**。校验通过后才前滚、清理残留
  并补登唯一恢复记录；记录哈希冲突仍 503。
- **prepared 无 committed**：先完整校验 `old_files` 备份清单、路径、
  类型、存在性、长度与哈希（备份闭集无额外），再整体回滚并清理；无法
  安全还原时保持现场、fail-closed。

恢复窗口期内任何请求都看不到半状态；并发、强制终止与重启交错只能提交
一次。提交完成后在 `restore-records/W.json` 记录 S 与 manifest_sha256。
恢复本身**不新增审计事件、不改余额/version、不破坏幂等与历史签名**。

跨目录登记目录 `restore-records/` 是多钱包共享的扁平闭集：仅许各钱包
正式记录 `<id>.json` 与其确定性原子写临时名 `.<id>.json.tmp`；强杀于
登记期间残留的半截 `.<id>.json.tmp` 由该钱包下一次登记原子续作（先解链
再 O_EXCL），缺记录只登记一次。符号链接、子目录、激活备份
（`*.bak.json`）、随机临时名（`.tmp-*`、裸 `*.tmp`）或任何非法命名一律
不可对账：常驻请求 `503`、`serve` 拒绝就绪，**保留现场**、不猜写、不
删除。记录文件恰含 `wallet_id`、`snapshots` 两键，`snapshots` 为
`S -> {"manifest_sha256"}`，以 UTF-8、`sort_keys`、2 空格缩进、末尾换行
原子落盘；本钱包记录 JSON/形状/哈希损坏同样 `503` 留现场。

参数 `data_dir`/`wallet_id`/`input` 类型错或空值、ID 不匹配
`[A-Za-z0-9_-]{1,128}` 一律 `400`；快照 `wallet_id` 与命令行 W 不一致为
归属冲突 `409`；缺输入文件、JSON/哈希/形状错、不可对账或 OSError 一律
`503` 且现场不变。

结果语义：首次恢复 `status=201`；同 S 且同 manifest 重放 `status=200`
且返回体逐字节相同（同体）；同 S 但内容不同 `409`（不覆盖既有恢复
点）；快照损坏或不可对账 `503` 且现场不变。成功 stdout 单行
`{"status","wallet_id","snapshot_id","manifest_sha256","manifest"}`；
失败 stderr 单行 `{"error":...}`、退出码 1。响应、日志与快照都不泄露
份额私钥或签名载荷。

## 私钥安全边界

- **响应**：建钱包只返回 `share_ids` 与公钥，任何接口都不返回私钥。
- **磁盘**：钱包元数据与账本/策略/会话/审批单等业务文件不含任何私钥；
  两个份额私钥分文件存放（`shares/<id>/<share_id>.json`），轮换准备期
  新份额私钥分文件暂存于 `rotation-staging/<id>/<rid>/`，会话参与者
  替换的新份额私钥分文件存放于
  `shares/<id>/<replacement_id>-share.json`，两阶段接管的阶段份额私钥
  分文件存放于
  `shares/<id>/<takeover_id>-<stage>-share.json`，任何文件至多
  含一个份额私钥，从不存在两者拼接的完整私钥。写入一律临时文件 + 原子
  替换。
- **日志**：访问日志只记录 `方法 路径 -> 状态码`，绝不读取或记录
  请求/响应体。
