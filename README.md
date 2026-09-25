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
`503`。

## HTTP 接口

| 方法 | 路径 | 说明 |
| ---- | ---- | ---- |
| POST | `/v1/wallets` | 建钱包 `{"wallet_id", "shares"`，`shares` 必须为 2 |
| GET  | `/v1/wallets/{id}` | 返回 `public_key` 与 `created_at` |
| PUT  | `/v1/wallets/{id}/approval-policy` | 审批策略 `{"required_approvals":1\|2,"timeout_seconds":>0}` |
| PUT  | `/v1/wallets/{id}/transaction-policy` | 交易策略 `{"mode":"hot"\|"cold","max_delta":正整数,"allowed_assets":[...]}` |
| GET  | `/v1/wallets/{id}/transaction-policy` | 查询交易策略（未配置 404） |
| POST | `/v1/wallets/{id}/sign-requests` | 建审批单 `{"id","message"}` |
| GET  | `/v1/wallets/{id}/sign-requests/{rid}` | 查审批单 |
| POST | `/v1/wallets/{id}/sign-requests/{rid}/approve` | 批准 `{"approver_id","reason"?}` |
| POST | `/v1/wallets/{id}/sign-requests/{rid}/reject` | 拒绝 |
| GET  | `/v1/wallets/{id}/audit-events` | 审计事件（seq 升序，分页 `from_seq`/`limit`） |
| POST | `/v1/wallets/{id}/sign` | 提交两份份额签名，返回聚合签名 |
| POST | `/v1/wallets/{id}/share-rotations` | 准备轮换 `{"rotation_id"}` |
| GET  | `/v1/wallets/{id}/share-rotations/{rid}` | 查轮换状态 |
| POST | `/v1/wallets/{id}/share-rotations/{rid}/activate` | 激活轮换 |
| POST | `/v1/wallets/{id}/asset-operations` | 建资产操作 `{"operation_id","asset_id","delta"}` |
| POST | `/v1/wallets/{id}/asset-operations/{oid}/commit` | 提交资产操作 |
| GET  | `/v1/wallets/{id}/assets/{asset_id}` | 查资产 `balance`/`version` |
| POST | `/v1/wallets/{id}/sign-sessions` | 建可恢复会话 `{"id","message","timeout_seconds"}` |
| GET  | `/v1/wallets/{id}/sign-sessions/{sid}` | 查会话视图 |
| POST | `/v1/wallets/{id}/sign-sessions/{sid}/shares` | 投递一份额签名 `{"share_id","signature"}` |
| POST | `/v1/wallets/{id}/sign-sessions/{sid}/participants/replace` | 替换会话单节点参与者 `{"replacement_id","offline_share_id"}` |

ID（wallet/rotation/operation/asset/session 等）一律匹配
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
- `POST sign-requests`：`id`、`message` 非空；未设策略 `409`；首建
  `201`；同 id 同文幂等 `200`；同 id 异文 `409`。
- 审批单视图 `{id,message,state,approvers,count,req,t0,t1,reason}`，
  `state` 为 `pending|approved|rejected|expired|signed`；操作前懒过期
  到点的 pending 单为 `expired`。
- `approve`/`reject`：`approver_id` 为非空白字符串，`reason` 可选且
  ≤1024 字符；非法 `400`。pending 单批准 `200`（同一 approver 重复
  批准不计数，达门槛转 `approved`），拒绝转 `rejected`；对终态单操作
  `409`。
- 设策略后 `/sign` 须存在同 id、同 message 且 `approved` 的审批单，
  两份额齐备 `201` 并推进审批单为 `signed`；未设策略时行为不变。

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

### 会话单节点替换

`POST /v1/wallets/{id}/sign-sessions/{sid}/participants/replace`，请求体
仅 `{"replacement_id","offline_share_id"}`，两个 ID 均为安全标识
（非法 `400`）；钱包/会话未知 `404`；会话非 `collecting|ready`（含到点
懒过期）或 `offline_share_id` 不是该会话当前在用份额 `409`。

- 首次替换生成全新 Ed25519 份额 `<replacement_id>-share` 替换原槽位：
  会话快照原槽位换入新 id，剔除旧份额已收签名、保留另一份（ready 回
  退为 collecting）。成功 `201`；同 ID 同参重放 `200`（**已提交重放
  优先**，不再做状态/到期检查）；同 ID 异参或派生份额 id 已被占用
  `409`。响应为既有会话视图。
- 新份额私钥只写入 `shares/<id>/<replacement_id>-share.json`（恰
  `share_id`/`public_key`/`private_key` 三键，两个 hex 值均为 64 位
  小写；UTF-8 无 BOM、`sort_keys`、2 空格缩进、末尾换行的原子写）。
  钱包元数据与钱包公钥不变。
- 替换后旧份额投递 `400`；新份额沿用 Ed25519 校验与既有审批/hot-cold
  门控，两份齐备后按原规则聚合。
- 审计事件 `session_participant_replaced`：`request_id` 为会话 id，
  `actor_id`/`reason` 为 `null`，`details` 恰含
  `session_id,old_share_id,new_share_id`。该事件为唯一提交点：落盘前
  回滚并删除新份额文件，落盘后前滚补齐；跨进程仅一个 `201`，损坏或
  矛盾现场保留并 `503`。

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

### 资产账本

每钱包一本账（`assets/<id>.json`），操作状态机 `pending|committed`，
原子写入，只含标识与整数。

- `POST asset-operations`：两个 ID 为安全标识，`delta` 为非布尔非零
  整数；非法 `400`，钱包不存在 `404`。首建 `201` 返回
  `R={operation_id,asset_id,delta,state,balance,version}`（pending，
  balance/version 为创建时刻快照）；同 id 同参重放 `200` 同体，异参
  `409`。创建不记事件。
- `POST commit`：仅 pending 可提交；`balance+delta < 0` 为 `409`
  （状态不变、可重试）；成功原子改余额、`version+1`、转 committed，
  `201` 返回 R。并发恰一个 `201`，其余幂等 `200`；committed 重放
  `200` 同体不重复改账。操作不存在 `404`。
- `GET assets/{asset_id}`：返回 `{asset_id,balance,version}`；资产无
  已提交操作 `404`。
- 重启后 pending/committed 与幂等保持，version 单调不回退、不重号。
  账本或提交意图损坏/矛盾时 fail-closed（常驻 `503`、阻止就绪），绝不
  归一为空或覆盖删除。
- 审计事件 `asset_operation_committed`（details 即 committed 视图 R，
  仅首次提交记一次）与 `transaction_policy_updated`。

### 审计事件

`GET audit-events` 返回 `{"wallet_id","events":[...]}`，按 `seq` 升序。
`from_seq`/`limit` 为正整数，默认 1/1000，limit 上限 1000；非法 `400`，
钱包不存在 `404`。纯只读，不触发懒过期、不分配 seq。

每条事件七字段 `seq,type,at,request_id,actor_id,reason,details`，
`at` 为 UTC（`...Z`），不适用字段为 `null`。seq 从 1 起、落盘后单调
递增，**服务重启后续写、连续不重号；恢复不新增审计事件**。事件类型：
`policy_updated`、`request_created/approved/rejected/expired/signed`、
`share_rotation_prepared/activated`、`asset_operation_committed`、
`transaction_policy_updated`、`session_event`、
`session_participant_replaced`。

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
`approve`/`reject` 与 HTTP 接口一一对应，成功打印单行 JSON 到 stdout，
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
  新份额私钥分文件暂存于 `rotation-staging/<id>/<rid>/`，任何文件至多
  含一个份额私钥，从不存在两者拼接的完整私钥。写入一律临时文件 + 原子
  替换。
- **日志**：访问日志只记录 `方法 路径 -> 状态码`，绝不读取或记录
  请求/响应体。
