"""门限签名业务逻辑（与 HTTP 框架无关）。

规则：
- 建钱包：shares 必须恰为 2，否则 400；wallet_id 重复返回 409；
  成功生成两个独立份额并返回钱包公钥与两个 share_id（201）。
- 查询：不存在返回 404，成功返回 public_key 与 created_at。
- 签名：服务端不代替任何一方签名，只校验两个份额持有人提交上来的
  Ed25519 份额签名，两份齐备且全部校验通过才聚合返回（201）；
  缺份、份额不对、签名校验失败一律 400；同一 signing_request_id
  重复提交直接返回已有签名（200，幂等）。
"""

from __future__ import annotations

import hashlib
import json
import re
import threading
from datetime import datetime, timedelta, timezone

from . import audit, crypto
from .audit import AuditStore
from .flock import FileLock, wallet_lock_path
from .store import (
    CorruptDataError,
    DuplicateWalletError,
    RecoveryError,
    WalletStore,
    _SAFE_ID,
    _SAFE_SHARE_ID,
    parse_utc_iso,
)

#: 两方门限：份额数固定为 2
REQUIRED_SHARES = 2

#: 服务端为两个份额生成的固定标识（按此顺序聚合公钥与签名）
SHARE_IDS = ("share-1", "share-2")

#: 审批策略允许的 required_approvals 取值
ALLOWED_REQUIRED_APPROVALS = (1, 2)

#: 冷热钱包交易策略允许的 mode 取值
TRANSACTION_POLICY_MODES = ("hot", "cold")

#: approve/reject 附言 reason 的最大长度
MAX_REASON_LENGTH = 1024

#: 钱包级审批人名单成员的最大长度（按 Unicode 码点计）
MAX_APPROVER_LENGTH = 128

#: rotation_id 允许的字符（与存储层安全 id 一致）
ROTATION_ID_RE = re.compile(r"^[A-Za-z0-9_-]{1,128}$")

#: 会话参与者替换/接管生成的新份额 id 形态：以 ``-share`` 结尾。
#: 替换份额为 <replacement_id>-share（前缀 ≤128），接管阶段份额为
#: <takeover_id>-<stage>-share（前缀 ≤130）；总长上限与 _SAFE_SHARE_ID
#: 的 136 一致。
REPLACEMENT_SHARE_ID_RE = re.compile(r"^[A-Za-z0-9_-]{1,130}-share$")

#: 两阶段接管允许的 stage 取值（须按序提交）
TAKEOVER_STAGES = (1, 2)

#: 两方 DKG 允许的操作（双方依序推进 register→commit→share→done）
DKG_OPS = ("register", "commit", "share")

#: DKG 故障轮次允许的动作（abort 中止当前轮并派生空轮；replace 换槽派生
#: 新轮；reinstate 把经 rejoin 审批恢复为 up 的空闲节点换入槽位派生新轮）
DKG_FAILOVER_ACTIONS = ("abort", "replace", "reinstate")

#: DKG 节点健康状态：up 在用可用、down 离线、ban 封禁
DKG_NODE_STATES = ("up", "down", "ban")

#: 跨链适配器健康状态：up 可派发、down 熔断（首提指向显式 down 适配器
#: 一律 409；未配置或适配器缺席视为 up）
CHAIN_ADAPTER_STATES = ("up", "down")

#: 高风险配置双人变更控制的受控配置 target 取值（恰八类）。chain-policy
#: 是唯一的资产粒度目标：请求/审批 message/事件 details/视图都在 target
#: 之后携带 asset_id。
CHANGE_CONTROL_TARGETS = (
    "approval-policy",
    "approval-roster",
    "transaction-policy",
    "dkg-failover-policy",
    "nodes",
    "chain-adapters",
    "change-control",
    "chain-policy",
)

#: 存在"未配置（null）"状态的受控 target：这五类 GET 未配置时 404/无策略，
#: policy-changes 的 before/after 允许为 null；其余三类（approval-roster、
#: dkg-failover-policy、change-control）始终有缺省值，不接受 null。
_CHANGE_NULLABLE_TARGETS = frozenset(
    (
        "approval-policy",
        "transaction-policy",
        "nodes",
        "chain-adapters",
        "chain-policy",
    )
)

#: 跨链派发结果回执 state 取值：broadcasted 已播链（带 tx_id）、failed
#: 失败（tx_id 为 null）
DISPATCH_RESULT_STATES = ("broadcasted", "failed")

#: 跨链派发确认进展 state 取值：confirming 确认中（未达门槛）、finalized
#: 已达门槛终态（终态后仅许历史同体重放，不再接受新进展；已结算派发
#: 例外，见下）、reorged 已结算派发发生重组（仅由重组补偿流程写入，
#: 同为终态，其后不再接受任何新进展）
DISPATCH_CONFIRMATION_STATES = ("confirming", "finalized", "reorged")

#: 钱包安全状态：active 正常（reason 为 null）、frozen 应急冻结。
#: 状态不由任何状态文件承载，只由 wallet_frozen/wallet_unfrozen 审计
#: 事件按 seq 折叠恢复，两类事件必须严格交替（首条必为 frozen）。
WALLET_STATE_ACTIVE = "active"
WALLET_STATE_FROZEN = "frozen"

#: 资产安全状态：active 正常（reason 为 null）、frozen 资产粒度应急冻结。
#: 状态不由任何状态文件承载，只由 asset_frozen/asset_unfrozen 审计事件
#: 按 (wallet, asset) 分组的 seq 折叠恢复，每资产两类事件严格交替
#: （首条必为 asset_frozen）。
ASSET_STATE_ACTIVE = "active"
ASSET_STATE_FROZEN = "frozen"

#: 审计事件落盘的外层七字段规范键序（audit 写盘按 sort_keys，惟既定
#: 类型 details 保序）。恢复据此核对事件**外层**未被重排：正常现场恒为
#: 此序，任何重排都是外部篡改，按不可对账现场 fail-closed。
_AUDIT_OUTER_KEY_ORDER = (
    "actor_id",
    "at",
    "details",
    "reason",
    "request_id",
    "seq",
    "type",
)

#: node_state 事件 details 内单个节点条目的固定键序。
_NODE_STATE_ENTRY_KEY_ORDER = ("key", "state")

#: dkg_failover 事件在**公开审计查询**（get_audit_events / GET
#: audit-events）中的外层键序。落盘外层仍为 sort_keys 序
#: （见 _AUDIT_OUTER_KEY_ORDER），查询仅对该类型事件重排**副本**；
#: 其余事件类型的公开键序维持落盘序不变。
_DKG_FAILOVER_PUBLIC_KEY_ORDER = (
    "seq",
    "type",
    "at",
    "request_id",
    "actor_id",
    "reason",
    "details",
)


class ServiceError(Exception):
    """业务错误，携带 HTTP 状态码与错误信息。"""

    def __init__(self, status: int, message: str) -> None:
        super().__init__(message)
        self.status = status
        self.message = message


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _is_lower_hex_32(value: object) -> bool:
    """恰为 64 位小写 hex（32 字节）的字符串判定。"""
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(c in "0123456789abcdef" for c in value)
    )


def _parse_iso(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


class _WalletTransactionLock:
    """每钱包事务锁：进程内 threading.Lock + 跨进程文件锁的组合。

    同一 data-dir 可被多个服务进程共用；状态变更与审计追加必须在这把
    组合锁内完成，跨进程互斥由 flock 保证，进程异常退出后内核自动
    释放文件锁，不会被陈旧锁阻塞。
    """

    def __init__(self, thread_lock: threading.Lock, file_lock: FileLock) -> None:
        self._thread_lock = thread_lock
        self._file_lock = file_lock

    def __enter__(self) -> "_WalletTransactionLock":
        self._thread_lock.acquire()
        try:
            self._file_lock.acquire()
        except BaseException:
            self._thread_lock.release()
            raise
        return self

    def __exit__(self, *exc_info: object) -> None:
        try:
            self._file_lock.release()
        finally:
            self._thread_lock.release()


class WalletService:
    """建钱包、查询钱包、校验并聚合两份额签名。"""

    def __init__(self, store: WalletStore, recover: bool = True) -> None:
        self._store = store
        self._audit = AuditStore(store.data_dir)
        # 每钱包一把事务锁：串行化同一钱包的"状态变更 + 审计事件"，
        # ThreadingHTTPServer 并发下保证状态与事件原子、懒过期只记一次。
        self._wallet_locks: dict[str, threading.Lock] = {}
        self._wallet_locks_guard = threading.Lock()
        # 离线灾备命令（backup/restore）只操作单个钱包：它们传
        # recover=False 跳过全局启动恢复，自行在该钱包锁内调用
        # _heal_wallet 做同等的崩溃现场自愈，避免因不相关钱包的现场
        # 让单个钱包的离线快照失败。
        if recover:
            # 启动恢复：崩溃时停留在 activating 的轮换先回滚为 prepared，
            # 轮换残留按有效性判定保留或安全删除，然后才对外服务。
            # 同一 data-dir 可能有另一存活进程正在服务，因此每个钱包的恢复
            # 都在其跨进程事务锁内进行：对方在途的激活/签名提交完成后才
            # 判定现场，对方已崩溃时 flock 自动释放、不会阻塞恢复。
            self._recover_on_startup()

    def _thread_lock_for(self, wallet_id: str) -> threading.Lock:
        with self._wallet_locks_guard:
            lock = self._wallet_locks.get(wallet_id)
            if lock is None:
                lock = threading.Lock()
                self._wallet_locks[wallet_id] = lock
            return lock

    def _wallet_lock(self, wallet_id: str) -> _WalletTransactionLock:
        """返回该钱包的事务锁上下文管理器（进程内 + 跨进程）。

        wallet_id 含非法字符时抛 ValueError（与存储层一致）。
        """
        return _WalletTransactionLock(
            self._thread_lock_for(wallet_id),
            FileLock(wallet_lock_path(self._store.data_dir, wallet_id)),
        )

    def _recover_on_startup(self) -> None:
        """启动恢复编排：逐个钱包在其跨进程事务锁内恢复轮换现场与未完成
        的资产提交事务。对外服务前必须完成，使任何查询/重放都读不到
        半完成状态。

        任一钱包恢复失败都向上抛出，由调用方阻止服务就绪（fail-closed）：
        绝不静默跳过带着损坏现场对外服务。异常类型保持 README 的三分
        边界——持久化 JSON 损坏抛 CorruptDataError、审计/文件 I/O 失败抛
        OSError、现场语义矛盾抛 RecoveryError（三者 HTTP 一律 503、serve
        一律拒绝就绪），绝不再把 CorruptDataError 包装成 RecoveryError
        而抹平"坏 JSON"与"矛盾"的区分。"""
        wallet_ids = sorted(
            set(self._store.list_rotation_wallet_ids())
            | set(self._store.list_staging_wallet_ids())
            | set(self._store.list_asset_intent_wallet_ids())
            | set(self._store.list_asset_ledger_wallet_ids())
            | set(self._store.list_sign_session_wallet_ids())
            | set(self._store.list_request_wallet_ids())
            | set(self._store.list_request_cancel_intent_wallet_ids())
            | set(self._store.list_policy_change_intent_wallet_ids())
            | set(self._audit.list_audit_wallet_ids())
            | set(self._list_restore_txn_wallet_ids())
            | set(self._list_restore_records_wallet_ids())
        )
        for wallet_id in wallet_ids:
            with self._wallet_lock(wallet_id):
                # 异常类型原样上抛：坏 JSON=CorruptDataError、I/O=OSError、
                # 矛盾=RecoveryError；_recover_wallet 已保证只有这三类
                # （及 wallet_id 非法的 ValueError，不会出现在枚举所得 id）。
                self._recover_wallet(wallet_id)

    def _list_restore_txn_wallet_ids(self) -> list[str]:
        """存在未完成灾备恢复事务（restore-txn）的钱包（延迟导入避免环）。"""
        from . import drbackup

        return drbackup.list_txn_wallet_ids(self._store.data_dir)

    def _list_restore_records_wallet_ids(self) -> list[str]:
        """存有跨目录恢复登记（restore-records）的钱包（延迟导入避免环）。

        目录闭集损坏（符号链接/目录/备份/随机临时名等）与其他启动恢复失败
        一样 fail-closed：统一转成 RecoveryError，绝不静默跳过。
        """
        from . import drbackup

        try:
            return drbackup.list_records_wallet_ids(self._store.data_dir)
        except drbackup.BackupError as exc:
            raise RecoveryError(
                f"restore-records cannot be reconciled: {exc.message}"
            ) from exc

    def _activated_rotations(self, wallet_id: str) -> dict[str, dict]:
        """该钱包已落盘的 share_rotation_activated 事件映射。"""
        return self._audit.activated_rotation_events(wallet_id)

    def _prepared_rotations(self, wallet_id: str) -> dict[str, dict]:
        """该钱包已落盘的 share_rotation_prepared 事件映射（同 id 多条时
        取最后一条）。"""
        return self._audit.prepared_rotation_events(wallet_id)

    def _reconcile_chain_state_locked(self, wallet_id: str) -> dict:
        """持钱包事务锁访问链/仲裁状态前的严格只读重放（调用方须持锁）。

        重放跨链确认与多源仲裁的策略、票、操作及相邻提交事件：畸形票、
        未知操作票、重复来源、错误 state、孤 adopted 票或提交关系矛盾
        都抛 RecoveryError（fail-closed，保留现场），审计 JSON 损坏抛
        CorruptDataError，文件系统失败抛 OSError。纯只读，不记事件、
        不改状态/seq。heal 在账本文件存在时已重放过一遍；账本文件缺失
        的纯策略/观察路径由本方法补齐，绝不绕过对账。返回经语义校验的
        账本供调用方复用。"""
        self._reconcile_chain_events(wallet_id)
        self._reconcile_chain_arbitration_events(wallet_id)
        self._reconcile_chain_dispatch_events(wallet_id)
        # 健康感知自动派发（chain_dispatch_auto_requested）：与手工派发
        # 同形共享每操作至多一条，另按事前健康快照复核 ASCII 最小 up
        # 适配器与三键审批 message，矛盾/坏 JSON/I/O fail-closed。
        self._reconcile_chain_dispatch_auto_events(wallet_id)
        self._reconcile_chain_dispatch_result_events(wallet_id)
        self._reconcile_chain_dispatch_confirmation_events(wallet_id)
        self._reconcile_chain_dispatch_settled_events(wallet_id)
        self._reconcile_chain_dispatch_reorged_events(wallet_id)
        self._reconcile_chain_dispatch_taken_over_events(wallet_id)
        # 派发隔离（chain_dispatch_isolated）与派发请求/健康表/result/
        # takeover 对账：派发在先、事前健康表显式 down、操作仍 pending、
        # 每派发至多一次且与 result/takeover 互斥在前，矛盾/损坏
        # fail-closed；纯只读。
        self._reconcile_chain_dispatch_isolated_events(wallet_id)
        # 跨链适配器健康熔断表（chain_adapter_health）：仅由审计事件
        # 持久化，逐事件严格核对键集/适配器 ID ASCII 升序/up|down，
        # 重排或取值矛盾 fail-closed；纯只读，不记事件、不改 seq。
        self._chain_adapter_health_events_strict(wallet_id)
        return self._store.check_asset_ledger_semantics(wallet_id)

    def _reconcile_dkg_events_locked(self, wallet_id: str) -> None:
        """按既有 DKG 恢复规则重放并严格对账该钱包全部 DKG 类审计事件
        （调用方须持钱包事务锁）。

        启动恢复与公开审计查询（get_audit_events / GET audit-events）
        共用同一条对账路径：

        - DKG 会话仅由 dkg_stage 事件持久化、故障轮次仅由 dkg_failover
          事件持久化：严格重建轮次链并逐条校验（details 既定键序
          id,round,action,node,replacement,key,state，自动替补末键
          mode=auto；abort 的 state 只能为 aborted，手工/自动 replace
          及 reinstate 只能为 commit；轮次链、节点槽位、健康快照与
          审批复核），矛盾/损坏 fail-closed；
        - DKG 故障审批开关仅由 dkg_failover_policy_updated 事件持久化：
          逐事件严格校验（三 id 字段为 null、details 恰含布尔
          enabled）；
        - DKG 节点健康表仅由 node_state 事件持久化、auto 故障的选择须
          以事前健康快照核验：逐事件严格校验健康表形状（此处），auto
          故障的事前核验在 _dkg_sessions 内随轮次链完成；
        - node_rejoined 事件按其提交之前的健康表/DKG/审批单逐条复核：
          任何矛盾（节点当时不 down|ban、key 不符、非当前 commit|share
          轮、不占槽、审批单未批准/message 不符）fail-closed；
        - share_participant_reinstated 绑定事件按其提交之前的轮换/DKG/
          健康表/审批单逐条复核：rotation 当时 prepared、round 为当前
          done 轮、node 为该轮 reinstate 换入且当前 up、槽位未占用、
          share_id 为当时在用份额；任何矛盾 fail-closed。

        纯只读：不写任何状态、不记事件、不改 seq、不触发懒过期。任何
        状态或上下文矛盾抛 RecoveryError，审计 JSON 损坏抛
        CorruptDataError，文件系统失败抛 OSError。"""
        self._dkg_sessions(wallet_id)
        self._dkg_failover_policy_enabled(wallet_id)
        self._node_state_events_strict(wallet_id)
        self._reconcile_node_rejoins(wallet_id)
        self._reconcile_share_bindings(wallet_id)

    def _recover_wallet(self, wallet_id: str) -> None:
        """在已持有该钱包事务锁的前提下，恢复轮换现场与未完成的资产提交。

        两者以同一把钱包锁串行，任何一个失败都向上抛出（RecoveryError/
        CorruptDataError/OSError），由调用方决定阻止就绪或把请求转成
        503，绝不静默。

        损坏 JSON / 形状异常在存储层表现为 CorruptDataError（ValueError
        子类）：损坏现场原样向上抛出，保持调用方的异常类型边界
        （损坏＝CorruptDataError、I/O 失败＝OSError、无法对账＝
        RecoveryError，三者 HTTP 一律 503、serve 一律拒绝就绪）；仅其余
        非 CorruptDataError 的 ValueError 才统一转成 RecoveryError，绝不
        把 ValueError 漏给调用方当成普通参数错误。"""
        try:
            # 灾备恢复事务的崩溃残留最先对账：committed 在则前滚到快照现场、
            # 否则按 old/ 备份整体回滚到恢复前现场。必须先于审计/账本/轮换
            # 校验——替换窗口内 data-dir 可能混有新旧两套文件，只有先把它
            # 收敛成一个完整一致的现场，后续对账才有意义。
            from . import drbackup

            try:
                drbackup._resume_pending_restore(self, wallet_id)
            except drbackup.BackupError as exc:
                # 灾备残留现场枚举/回滚时的严格校验失败（符号链接、白名单
                # 外文件等）在启动/持锁恢复语义下同样是不可对账：统一转成
                # RecoveryError，由上层 fail-closed（阻止就绪/503）。
                raise RecoveryError(
                    f"wallet {wallet_id!r} restore transaction cannot be "
                    f"reconciled: {exc.message}"
                ) from exc
            try:
                # 跨目录恢复登记（restore-records/）闭集与本钱包记录形状：
                # 崩溃可能发生在提交后的登记/清理阶段，闭集外条目（链接、
                # 目录、备份、随机临时名）或损坏记录同样不可对账，fail-closed。
                drbackup.reconcile_restore_records(
                    self._store.data_dir, wallet_id
                )
            except drbackup.BackupError as exc:
                raise RecoveryError(
                    f"wallet {wallet_id!r} restore records cannot be "
                    f"reconciled: {exc.message}"
                ) from exc
            # 审计是轮换激活/资产提交/会话动作的唯一提交点：日志形状或
            # seq 连续性损坏时任何前滚/回滚判定都不可信，最先 fail-closed。
            self._audit.check_log(wallet_id)
            # 旧审计可能缺防篡改摘要链：在启动读取边界持锁按事件顺序
            # 补算并持久化 chain 元数据（只新增链对象，绝不改写事件正文、
            # 不新增审计事件、不改 seq）。chain 已存在但与事件不匹配在
            # check_log 阶段即 RecoveryError（serve 拒绝就绪/HTTP 503），
            # 补算写盘 I/O 失败按 OSError 原样上抛。
            self._audit.backfill_chain(wallet_id)
            # 钱包应急冻结/解冻事件（wallet_frozen/wallet_unfrozen）：
            # 状态只由这两类事件折叠，逐事件严格校验 details 与交替状态
            # 机；畸形/同态连续 fail-closed，恢复不新增事件、不改 seq。
            self._freeze_events_strict(wallet_id)
            # 资产粒度应急冻结/解冻事件（asset_frozen/asset_unfrozen）：
            # 按 (wallet, asset) 分组折叠，逐事件严格校验 details 与每资产
            # 交替状态机（绑定资产 id 与 reason）；畸形/同态连续
            # fail-closed，恢复不新增事件、不改 seq。
            self._asset_freeze_events_strict(wallet_id)
            # 钱包审批人名单仅由 approval_roster_updated 事件承载：逐事件
            # 校验成员形状/去重/码点升序，取最后一条重建，不新增事件。
            self._approval_roster_events_strict(wallet_id)
            # 高风险配置双人变更控制：严格校验 policy_change_applied 事件
            # （形状/审批门控/两位不同审批人），按提交前意图前滚/回滚崩溃
            # 窗口，并把文件型策略对账到 legacy 事件与变更事件的 seq 折叠
            # 结果；audit-sourced 配置在各自重放路径按合并快照折叠。恢复
            # 不新增事件、不改 seq，矛盾/损坏 fail-closed。
            self._recover_policy_changes(wallet_id)
            # 审批单撤销以 request_cancelled 为唯一提交点：凭提交前意图
            # 前滚/回滚崩溃窗口，并双向对账已 settled 的 cancelled 现场。
            self._recover_request_cancellations(wallet_id)
            # 先校验资产账本（形状 + 语义）：账本损坏时任何对账都不可信，
            # 直接 fail-closed。
            self._store.check_asset_ledger_semantics(wallet_id)
            self._store.recover_wallet_rotation(
                wallet_id,
                self._activated_rotations(wallet_id),
                self._prepared_rotations(wallet_id),
                self._audit.cancelled_rotation_events(wallet_id),
            )
            self._recover_wallet_asset_commits(wallet_id)
            # 意图清零后再做账本 ↔ asset_operation_committed 事件的双向
            # 对账：提交事件与 committed 操作必须一一对应、details 即 R。
            self._reconcile_asset_committed_events(wallet_id)
            # 账本 cancelled 操作 ↔ asset_operation_cancelled 事件同样
            # 双向对账：撤销事件是撤销的唯一提交点，与 cancelled 操作
            # 一一对应、details 即 cancelled 视图。
            self._reconcile_asset_cancelled_events(wallet_id)
            # 账本已提交转账 ↔ asset_transfer_committed 事件同样双向
            # 对账：转账事件是转账的唯一提交点，与已提交转账一一对应、
            # details 即九键转账视图 R。
            self._reconcile_asset_transfer_events(wallet_id)
            # 资产冻结事件绑定的每个资产都必须在账本中有已提交操作：
            # 冻结入口只对有已提交余额的资产开放，引用无已提交操作资产
            # 的冻结事件是不可对账现场。须排在账本语义校验之后。
            self._reconcile_asset_freeze_ledger(wallet_id)
            # 链确认事件（chain_policy/chain_report）与提交门控对账：
            # 报告状态机逐事件重放，矛盾/损坏 fail-closed；纯只读。
            self._reconcile_chain_events(wallet_id)
            # 多源仲裁事件（chain_vote 策略/票、合法旧 chain_arbitration）
            # 与票/报告/提交三事件提交点对账：逐事件重放，矛盾/损坏
            # fail-closed；纯只读。
            self._reconcile_chain_arbitration_events(wallet_id)
            # 跨链派发事件（chain_dispatch_requested）与账本/策略/审批单
            # 对账：逐事件按提交前现场复核，矛盾/损坏 fail-closed；纯只读。
            self._reconcile_chain_dispatch_events(wallet_id)
            # 健康感知自动派发（chain_dispatch_auto_requested）：另按事前
            # 健康快照复核首选 up 适配器与三键审批 message，矛盾/损坏
            # fail-closed；纯只读。
            self._reconcile_chain_dispatch_auto_events(wallet_id)
            # 跨链派发结果回执（chain_dispatch_result）与派发请求对账：
            # 请求先于结果、归属一致、每派发至多一结果，矛盾/损坏
            # fail-closed；纯只读。
            self._reconcile_chain_dispatch_result_events(wallet_id)
            # 跨链派发确认进展（chain_dispatch_confirmation）与派发请求/
            # 结果/策略对账：请求与 broadcasted 结果在先、归属一致、迁移
            # 状态机逐事件成立，矛盾/损坏 fail-closed；纯只读。
            self._reconcile_chain_dispatch_confirmation_events(wallet_id)
            # 跨链派发最终性结算（chain_dispatch_settled）与派发请求/
            # 结果/finalized 确认及紧邻提交事件对账：前置齐备、归属一致、
            # 结算与提交两事件同批紧邻，矛盾/损坏 fail-closed；纯只读。
            self._reconcile_chain_dispatch_settled_events(wallet_id)
            # 已结算派发重组补偿（chain_dispatch_reorged）与派发请求/
            # 结算/reorged 确认及紧邻提交事件对账：前置齐备、归属一致、
            # 三事件同批紧邻、补偿与原操作同资产反向，矛盾/损坏
            # fail-closed；纯只读。
            self._reconcile_chain_dispatch_reorged_events(wallet_id)
            # 失败派发接管（chain_dispatch_taken_over）与派发请求/失败
            # 结果/审批单对账，并由结果/确认/结算对账复核接管后的归属与
            # 交易链：前置齐备、新适配器不同、审批单 approved 且 message
            # 逐字一致，矛盾/损坏 fail-closed；纯只读。
            self._reconcile_chain_dispatch_taken_over_events(wallet_id)
            # 派发隔离（chain_dispatch_isolated）与派发请求/事前健康表/
            # result/takeover/审批无关（隔离 actor 为 null）对账：派发在先、
            # 事前健康表显式 down、操作仍 pending、每派发至多一次且与
            # result/takeover 互斥在前，矛盾/损坏 fail-closed；纯只读。
            self._reconcile_chain_dispatch_isolated_events(wallet_id)
            # 跨链适配器健康熔断表（chain_adapter_health）：仅由审计事件
            # 持久化，逐事件严格核对键集/适配器 ID ASCII 升序/up|down，
            # 重排或取值矛盾 fail-closed；纯只读，不记事件、不改 seq。
            self._chain_adapter_health_events_strict(wallet_id)
            self._recover_sign_sessions(wallet_id)
            # DKG 类事件（dkg_stage/dkg_failover/故障审批开关/健康表/
            # rejoin/share-bind）仅由审计事件持久化：按既有 DKG 恢复规则
            # 重放并严格对账，矛盾/损坏 fail-closed；对账不写任何状态、
            # 不记事件、不改 seq。
            self._reconcile_dkg_events_locked(wallet_id)
        except (RecoveryError, CorruptDataError, OSError):
            # 矛盾=RecoveryError / 坏 JSON=CorruptDataError / I/O=OSError：
            # 三类异常都保持各自类型向上抛出（HTTP 一律 503、serve 拒绝
            # 就绪），绝不把 I/O 或坏 JSON 重新包装成 RecoveryError。
            raise
        except ValueError as exc:
            # 其余非 CorruptDataError 的 ValueError（持久化形状/取值异常）：
            # 无法对账，统一转 RecoveryError；绝不漏给调用方当参数错误。
            raise RecoveryError(
                f"wallet {wallet_id!r} cannot be reconciled: {exc}"
            ) from exc

    def _heal_wallet(self, wallet_id: str) -> None:
        """持锁后自愈他进程崩溃遗留的现场（懒恢复，fail-closed）。

        常驻进程不会重跑启动恢复；为使任何查询/重放永远读不到他进程
        留下的半完成激活或半完成提交，业务操作在拿到钱包事务锁后先调用
        本方法。在途事务必持同锁，故这里看到的残留只能来自崩溃进程：

        - 资产提交意图残留：按提交事件是否落盘前滚或回滚；
        - activating 记录：激活事务窗口内的残留，按激活事件前滚/回滚；
        - active 记录但暂存/备份仍残留、或激活事件缺失：崩溃现场，
          按事件前滚补齐或（事件在却无法补齐时）fail-closed；
        - 无任何记录对应的孤儿暂存目录：安全删除。

        静止现场不触发恢复：prepared（暂存完整待激活）与干净完成的
        active（事件在、暂存已清空）。对账失败向上抛出
        RecoveryError/CorruptDataError/OSError，绝不静默继续。检测读取
        本身遇到损坏 JSON/形状异常（CorruptDataError）时无法判断现场是否
        静止，按损坏现场原样向上抛出、fail-closed。
        """
        try:
            # 灾备恢复事务的崩溃残留优先收敛（committed 前滚/否则整体回滚），
            # 再进入账本/会话/轮换的静止快路径：替换窗口内现场可能新旧混杂。
            # restore-txn 根一出现（哪怕不属于本钱包、或根自身/根下有任何
            # 非安全项）就进入完整恢复：根目录闭集校验在恢复路径内统一
            # fail-closed，绝不让持锁访问绕过不可对账的灾备现场。
            import os as _os

            from . import drbackup

            _txn_root = _os.path.join(
                self._store.data_dir, drbackup.RESTORE_TXN_DIRNAME
            )
            if _os.path.lexists(_txn_root):
                self._recover_wallet(wallet_id)
                return
            # 即便没有 restore-txn（提交后的清理已完成，或强杀发生在登记
            # 阶段），跨目录登记根 restore-records/ 仍须闭集可信：链接、目录、
            # 备份、随机临时名或损坏的本钱包记录都 fail-closed，绝不让持锁
            # 访问绕过不可对账的登记现场。
            try:
                drbackup.reconcile_restore_records(
                    self._store.data_dir, wallet_id
                )
            except drbackup.BackupError as exc:
                raise RecoveryError(
                    f"wallet {wallet_id!r} restore records cannot be "
                    f"reconciled: {exc.message}"
                ) from exc
            # 资产账本是所有创建/提交/查询/审计读路径的依赖：形状或语义
            # 损坏时无法与意图/事件对账，绝不能静默当成空账本。任何持锁
            # 访问都先校验账本，损坏即由 _recover_wallet 统一 fail-closed。
            self._store.check_asset_ledger_semantics(wallet_id)
            # 签名会话文件形状损坏同样 fail-closed，绝不把坏会话当空会话。
            # 这里只做形状校验；会话对账必须排在轮换/资产恢复之后——会话
            # 迁移依据"当前在用份额"，而他进程崩溃遗留的半完成激活可能仍
            # 持有错误的钱包份额，必须先按激活事件前滚/回滚确定在用份额，
            # 再对账会话，避免把会话迁移到未提交轮换的份额上。
            self._store.check_sign_sessions(wallet_id)
            if self._store.get_request_cancel_intents(
                wallet_id
            ) or self._store.request_file_exists(wallet_id):
                self._recover_request_cancellations(wallet_id)
            # 高风险配置文件型变更（approval-policy/transaction-policy）
            # 崩溃窗口残留提交前意图：走完整恢复，按审计提交点前滚/回滚。
            if self._store.get_policy_change_intents(wallet_id):
                self._recover_wallet(wallet_id)
                return
            if self._store.list_asset_intents(wallet_id):
                self._recover_wallet(wallet_id)
                return
            rotations = self._store.list_rotations(wallet_id)
            staging_ids = set(self._store.list_staging_rotation_ids(wallet_id))
            needs_recovery = False
            active_check = False
            for record in rotations:
                state = record.get("state")
                rid = record.get("rotation_id")
                if state == "activating":
                    needs_recovery = True
                elif state == "active":
                    # 干净完成的 active：事件在且暂存已清空。暂存残留或
                    # 事件缺失才是崩溃现场（后者需读审计判定）。
                    if rid in staging_ids:
                        needs_recovery = True
                    else:
                        active_check = True
                elif state == "prepared" and isinstance(rid, str):
                    # prepared 的暂存目录是预期现场，不算孤儿
                    staging_ids.discard(rid)
            if not needs_recovery and active_check:
                activated = self._activated_rotations(wallet_id)
                for record in rotations:
                    if (
                        record.get("state") == "active"
                        and record.get("rotation_id") not in activated
                    ):
                        needs_recovery = True
                        break
            if not needs_recovery and (rotations or staging_ids):
                # 看似静止也要按审计 seq 对账一次激活链：连续多轮轮换后，
                # 历史记录缺失、链乱序/跨轮次不相容、链顶公钥/份额与磁盘
                # 不符等矛盾不会体现为 activating/暂存残留，必须在此拦住，
                # 绝不带矛盾现场对外服务。
                if not active_check:
                    activated = self._activated_rotations(wallet_id)
                if not self._store.verify_rotation_scene_consistent(
                    wallet_id,
                    activated,
                    self._prepared_rotations(wallet_id),
                    self._audit.cancelled_rotation_events(wallet_id),
                ):
                    needs_recovery = True
            if not needs_recovery and staging_ids:
                # 无对应 prepared 记录的孤儿暂存目录
                needs_recovery = True
            if needs_recovery:
                # 内含轮换 -> 资产提交 -> 会话的完整有序恢复
                self._recover_wallet(wallet_id)
                return
            # 轮换现场静止后，再对他进程崩溃遗留的半完成会话对账（无会话
            # 文件时立即返回，零开销；此时读取审计不影响审计无关路由）。
            # 账本文件存在时同理做账本 ↔ committed 事件对账：只有存在
            # 账本现场时才需要读取审计，保持"无业务文件的纯钱包不依赖
            # 审计日志"的既有可用性边界。
            if self._store.asset_ledger_file_exists(wallet_id):
                self._reconcile_asset_committed_events(wallet_id)
                self._reconcile_asset_cancelled_events(wallet_id)
                # 账本已提交转账 ↔ asset_transfer_committed 事件同属账本
                # 一致性：账本存在时一并双向对账，矛盾即 fail-closed。
                self._reconcile_asset_transfer_events(wallet_id)
                # 资产冻结事件与账本交叉对账：每条冻结事件绑定的资产都
                # 必须有已提交操作（仅在账本文件存在时需要，资产冻结事件
                # 只可能随已提交操作出现）。
                self._reconcile_asset_freeze_ledger(wallet_id)
                # 链确认报告/策略事件与账本提交门控同属账本一致性：
                # 账本存在时一并按 seq 重放对账，矛盾即 fail-closed。
                self._reconcile_chain_events(wallet_id)
                # 多源仲裁票/策略事件与三事件提交点同属账本一致性：
                # 账本存在时一并按 seq 重放对账，矛盾即 fail-closed。
                self._reconcile_chain_arbitration_events(wallet_id)
                # 跨链派发事件与账本/策略/审批单同属账本一致性：账本存在
                # 时一并按 seq 重放对账，矛盾即 fail-closed。
                self._reconcile_chain_dispatch_events(wallet_id)
                # 健康感知自动派发另按事前健康快照复核首选适配器：账本
                # 存在时一并按 seq 重放对账，矛盾即 fail-closed。
                self._reconcile_chain_dispatch_auto_events(wallet_id)
                # 派发结果回执与派发请求的先后/归属同属账本一致性：账本
                # 存在时一并按 seq 重放对账，矛盾即 fail-closed。
                self._reconcile_chain_dispatch_result_events(wallet_id)
                # 派发确认进展与派发请求/结果/策略的先后、归属与迁移同属
                # 账本一致性：账本存在时一并按 seq 重放对账，矛盾即
                # fail-closed。
                self._reconcile_chain_dispatch_confirmation_events(wallet_id)
                # 最终性结算与派发请求/结果/finalized 确认及紧邻提交事件
                # 同属账本一致性：账本存在时一并按 seq 重放对账，矛盾即
                # fail-closed。
                self._reconcile_chain_dispatch_settled_events(wallet_id)
                # 重组补偿与派发请求/结算/reorged 确认及紧邻提交事件同属
                # 账本一致性：账本存在时一并按 seq 重放对账，矛盾即
                # fail-closed。
                self._reconcile_chain_dispatch_reorged_events(wallet_id)
                # 失败派发接管与派发请求/失败结果/审批单同属账本一致性：
                # 账本存在时一并按 seq 重放对账，矛盾即 fail-closed。
                self._reconcile_chain_dispatch_taken_over_events(wallet_id)
                # 派发隔离与派发请求/事前健康表/result/takeover 同属账本
                # 一致性：账本存在时一并按 seq 重放对账，矛盾即 fail-closed。
                self._reconcile_chain_dispatch_isolated_events(wallet_id)
                # 跨链适配器健康熔断表与派发熔断同属账本一致性：账本存在
                # 时一并严格重放全部快照形状，矛盾即 fail-closed。
                self._chain_adapter_health_events_strict(wallet_id)
            self._recover_sign_sessions(wallet_id)
        except (RecoveryError, CorruptDataError, OSError):
            # 矛盾=RecoveryError / 坏 JSON=CorruptDataError / I/O=OSError：
            # 三类异常保持各自类型向上抛出（HTTP 一律 503），绝不把 I/O
            # 失败重新包装成 RecoveryError。
            raise
        except ValueError as exc:
            # 其余非 CorruptDataError 的 ValueError：现场不可假定静止，
            # fail-closed（RecoveryError）。
            raise RecoveryError(
                f"wallet {wallet_id!r} cannot be reconciled: {exc}"
            ) from exc

    @staticmethod
    def _audit_event(
        event_type: str,
        request_id=None,
        actor_id=None,
        reason=None,
        details=None,
    ) -> dict:
        """构造审计事件（seq 由 AuditStore 分配）。"""
        return {
            "type": event_type,
            "at": _utc_now_iso(),
            "request_id": request_id,
            "actor_id": actor_id,
            "reason": reason,
            "details": details,
        }

    def _emit(self, wallet_id: str, event: dict) -> dict:
        return self._audit.append_event(wallet_id, event)

    # ---- 建钱包 ---------------------------------------------------------

    def create_wallet(self, wallet_id: object, shares: object) -> dict:
        if not isinstance(wallet_id, str) or not wallet_id:
            raise ServiceError(400, "wallet_id must be a non-empty string")
        # bool 是 int 的子类，必须先排除；2.0 == 2，必须要求真正的 int
        if not isinstance(shares, int) or isinstance(shares, bool):
            raise ServiceError(400, "shares must equal 2")
        if shares != REQUIRED_SHARES:
            raise ServiceError(400, "shares must equal 2")
        try:
            share_keys = [crypto.generate_share_key(sid) for sid in SHARE_IDS]
            # 跨进程防重：同一 data-dir 上多个服务进程并发建同名钱包时，
            # 只有一个能在事务锁内提交成功
            with self._wallet_lock(wallet_id):
                self._store.create_wallet(
                    wallet_id, share_keys, _utc_now_iso()
                )
        except DuplicateWalletError:
            raise ServiceError(409, f"wallet {wallet_id!r} already exists")
        except ValueError:
            # wallet_id 含非法字符
            raise ServiceError(400, "invalid wallet_id")
        public_key = crypto.combine_public_keys(
            [k.public_bytes for k in share_keys]
        )
        return {
            "wallet_id": wallet_id,
            "public_key": public_key.hex(),
            "share_ids": list(SHARE_IDS),
        }

    # ---- 查询钱包 -------------------------------------------------------

    def get_wallet(self, wallet_id: str) -> dict:
        try:
            with self._wallet_lock(wallet_id):
                # 查询前先自愈他进程崩溃遗留的激活现场，绝不把换了一半
                # 的公钥/份额经 GET 暴露出去
                self._heal_wallet(wallet_id)
                record = self._store.get_wallet(wallet_id)
        except CorruptDataError:
            # 钱包元数据损坏：fail-closed（由 HTTP 边界转 503）
            raise
        except ValueError:
            raise ServiceError(400, "invalid wallet_id")
        if record is None:
            raise ServiceError(404, f"wallet {wallet_id!r} not found")
        return {
            "wallet_id": record["wallet_id"],
            "public_key": record["public_key"],
            "created_at": record["created_at"],
        }

    def share_sign(
        self,
        wallet_id: str,
        share_id: object,
        signing_request_id: object,
        message: object,
    ) -> dict:
        """份额持有方本地签名（CLI share-sign 专用，不经网络）。

        在该钱包的事务锁内先做懒恢复（``_heal_wallet``），再依据钱包
        元数据中当前在用的 share_id 读取份额私钥并签名：绝不在轮换激活
        半完成、或份额已轮换失效时读到半换入/已删除的份额。恢复无法
        对账时向上抛 RecoveryError/OSError（fail-closed），由调用方输出
        JSON 错误并非零退出。

        份额文件损坏（JSON 不可解析、非对象、字段缺失、私钥非 hex、长度
        非法）或私钥推导不出记录中的份额公钥（被篡改）时，绝不基于不一致
        的密钥签名：统一抛 ServiceError(503) 与不含私钥/载荷的泛化信息。
        """
        if (
            not isinstance(signing_request_id, str)
            or not signing_request_id
        ):
            raise ServiceError(
                400, "signing_request_id must be a non-empty string"
            )
        if not isinstance(message, str):
            raise ServiceError(400, "message must be a string")
        with self._wallet_lock(wallet_id):
            # 懒恢复可能抛 RecoveryError/OSError（fail-closed），保持上抛。
            self._heal_wallet(wallet_id)
            try:
                wallet = self._store.get_wallet(wallet_id)
            except CorruptDataError:
                raise
            except ValueError:
                raise ServiceError(400, "invalid wallet_id")
            if wallet is None:
                raise ServiceError(404, f"wallet {wallet_id!r} not found")
            in_use = {
                s.get("share_id"): s.get("public_key")
                for s in wallet.get("shares", [])
                if isinstance(s, dict)
            }
            if not isinstance(share_id, str) or share_id not in in_use:
                raise ServiceError(
                    404,
                    f"share {share_id!r} of wallet {wallet_id!r} not found",
                )
            try:
                share = self._store.get_share(wallet_id, share_id)
            except CorruptDataError:
                # 份额文件损坏：由下方完整性校验统一报泛化 503
                share = None
            except ValueError:
                raise ServiceError(400, "invalid share_id")
            # 份额完整性校验：任何形状/编码/长度/密钥对应关系异常都视为
            # 数据损坏，fail-closed，绝不读出私钥盲目签名，也绝不把底层
            # 异常文本、私钥或签名载荷暴露给调用方。
            private_bytes = self._load_share_private_bytes(
                share, expected_share_id=share_id,
                expected_public_hex=in_use[share_id],
            )
            payload = crypto.build_payload(signing_request_id, message)
            try:
                signature = crypto.sign_share(private_bytes, payload)
            except (ValueError, TypeError):
                # 理论上 32 字节私钥不会触发，仍兜底避免 traceback
                raise ServiceError(
                    503, "share is unavailable, refusing to sign"
                )
            return {"share_id": share_id, "signature": signature.hex()}

    @staticmethod
    def _load_share_private_bytes(
        share: object, *, expected_share_id: str, expected_public_hex: object
    ) -> bytes:
        """从份额记录中取出经一致性校验的 32 字节私钥。

        校验记录为对象、share_id 一致、public_key/private_key 均为字符串、
        各自解码为 32 字节、私钥推导出的公钥恰为记录/在用公钥。任一不满足
        都抛 ServiceError(503) 泛化错误（数据损坏或被篡改），不含私钥。"""
        generic = "share is unavailable, refusing to sign"
        if not isinstance(share, dict):
            raise ServiceError(503, generic)
        if share.get("share_id") != expected_share_id:
            raise ServiceError(503, generic)
        public_hex = share.get("public_key")
        private_hex = share.get("private_key")
        if not isinstance(public_hex, str) or not isinstance(private_hex, str):
            raise ServiceError(503, generic)
        try:
            public_bytes = bytes.fromhex(public_hex)
            private_bytes = bytes.fromhex(private_hex)
        except ValueError:
            raise ServiceError(503, generic)
        if len(public_bytes) != 32 or len(private_bytes) != 32:
            raise ServiceError(503, generic)
        try:
            derived = crypto.public_key_from_private(private_bytes)
        except (ValueError, TypeError):
            raise ServiceError(503, generic)
        if derived != public_bytes:
            raise ServiceError(503, generic)
        # 份额记录的公钥还必须与钱包元数据中当前在用公钥一致
        if not isinstance(expected_public_hex, str):
            raise ServiceError(503, generic)
        try:
            in_use_public = bytes.fromhex(expected_public_hex)
        except ValueError:
            raise ServiceError(503, generic)
        if in_use_public != public_bytes:
            raise ServiceError(503, generic)
        return private_bytes

    # ---- 审批策略 -------------------------------------------------------

    def _get_wallet_or_404(self, wallet_id: str) -> dict:
        try:
            wallet = self._store.get_wallet(wallet_id)
        except CorruptDataError:
            # 钱包元数据损坏：fail-closed（由 HTTP 边界转 503），绝不
            # 当成普通 400 或返回半完成公钥
            raise
        except ValueError:
            raise ServiceError(400, "invalid wallet_id")
        if wallet is None:
            raise ServiceError(404, f"wallet {wallet_id!r} not found")
        return wallet

    # ---- 钱包应急冻结/解冻 ----------------------------------------------

    @staticmethod
    def _validate_freeze_reason(reason: object) -> str:
        """freeze/unfreeze 请求体 reason：必须是 1..1024 字符的非空白
        字符串（bool 拒绝；仅空白拒绝）。非法抛 ServiceError(400)。"""
        if not isinstance(reason, str) or isinstance(reason, bool):
            raise ServiceError(400, "reason must be a string")
        if len(reason) < 1 or len(reason) > MAX_REASON_LENGTH:
            raise ServiceError(
                400,
                f"reason must be 1 to {MAX_REASON_LENGTH} characters long",
            )
        if not reason.strip():
            raise ServiceError(400, "reason must be non-blank")
        return reason

    @staticmethod
    def _security_state_view(
        wallet_id: str, state: str, reason: object
    ) -> dict:
        """安全状态对外视图，固定键序 wallet_id,state,reason；
        active 时 reason 恒为 null。"""
        return {
            "wallet_id": wallet_id,
            "state": state,
            "reason": reason,
        }

    def _freeze_events_strict(self, wallet_id: str) -> list[dict]:
        """按 seq 升序返回该钱包全部 wallet_frozen/wallet_unfrozen 事件，
        逐条严格校验并核对交替状态机（调用方须持钱包事务锁）。

        每条事件的 request_id/actor_id/reason 必须为 null，details 恰为
        ``{"reason": <1..1024 字符非空白字符串>}``；事件必须严格交替：
        首条必为 wallet_frozen（active -> frozen），其后 frozen/unfrozen
        轮流出现（frozen -> active -> frozen ...）。任何畸形或同态连续
        （重复 freeze / 重复 unfreeze）都是不可对账现场（RecoveryError，
        fail-closed），绝不静默取最后一条。审计 JSON 损坏由下层抛
        CorruptDataError，文件 I/O 失败抛 OSError。纯只读，不记事件、
        不改 seq。"""
        events = [
            event
            for event in self._audit.all_events(wallet_id)
            if event.get("type")
            in (audit.TYPE_WALLET_FROZEN, audit.TYPE_WALLET_UNFROZEN)
        ]
        expected = audit.TYPE_WALLET_FROZEN
        for event in events:
            if (
                event.get("request_id") is not None
                or event.get("actor_id") is not None
                or event.get("reason") is not None
            ):
                raise RecoveryError(
                    f"wallet {wallet_id!r} has a freeze event with "
                    "request_id/actor_id/reason set"
                )
            details = event.get("details")
            reason = (
                details.get("reason")
                if isinstance(details, dict)
                else None
            )
            if (
                not isinstance(details, dict)
                or set(details) != {"reason"}
                or not isinstance(reason, str)
                or isinstance(reason, bool)
                or len(reason) < 1
                or len(reason) > MAX_REASON_LENGTH
                or not reason.strip()
            ):
                raise RecoveryError(
                    f"wallet {wallet_id!r} has a malformed freeze event"
                )
            if event.get("type") != expected:
                raise RecoveryError(
                    f"wallet {wallet_id!r} has non-alternating freeze events"
                )
            expected = (
                audit.TYPE_WALLET_UNFROZEN
                if expected == audit.TYPE_WALLET_FROZEN
                else audit.TYPE_WALLET_FROZEN
            )
        return events

    def _security_state_locked(self, wallet_id: str) -> dict:
        """按审计事件折叠当前安全状态（调用方须持钱包事务锁）。

        状态只由 wallet_frozen/wallet_unfrozen 事件承载：无事件为
        active（reason=null）；有事件时末条为 frozen 即 frozen，reason
        取**最近一次 freeze** 的 reason；末条为 unfrozen 即 active。
        矛盾/损坏现场 fail-closed。纯只读，不新增事件、不改 seq。"""
        events = self._freeze_events_strict(wallet_id)
        if not events or events[-1]["type"] == audit.TYPE_WALLET_UNFROZEN:
            return self._security_state_view(
                wallet_id, WALLET_STATE_ACTIVE, None
            )
        reason = events[-1]["details"]["reason"]
        return self._security_state_view(
            wallet_id, WALLET_STATE_FROZEN, reason
        )

    def _assert_wallet_active_locked(self, wallet_id: str) -> None:
        """frozen 钱包的既有写接口统一 409（调用方须持钱包事务锁）。

        在钱包存在性判定之后、任何参数/幂等/业务判定之前调用：冻结是
        应急闸门，frozen 期间只有查询、审计读取、security-state、
        freeze 与 unfreeze 可用，故即便请求本来会命中幂等 200 重放也一律
        409 且零副作用（不触发懒过期、不追加事件、不改现场）。"""
        if (
            self._security_state_locked(wallet_id)["state"]
            == WALLET_STATE_FROZEN
        ):
            raise ServiceError(
                409, f"wallet {wallet_id!r} is frozen"
            )

    def freeze_wallet(
        self, wallet_id: str, reason: object
    ) -> tuple[int, dict]:
        """POST /v1/wallets/<id>/freeze。返回 (201|200, 安全状态视图)。

        active -> frozen 首次转换 201，在每钱包跨进程事务锁内原子判定并
        追加唯一 wallet_frozen 事件（details 恰为 {"reason": ...}）；
        frozen 期间同 reason 重放 200（不复查、不记事件），异 reason
        409。并发同一操作只有一个 201，其余同参得到 200，审计 seq 连续
        不重号。reason 非字符串/空白/超长 400；钱包不存在 404。"""
        try:
            with self._wallet_lock(wallet_id):
                self._heal_wallet(wallet_id)
                # 404 优先于 400：存在性在锁内、heal 之后先判定
                self._get_wallet_or_404(wallet_id)
                self._validate_freeze_reason(reason)
                state = self._security_state_locked(wallet_id)
                if state["state"] == WALLET_STATE_FROZEN:
                    # 已冻结：仅允许与最近一次 freeze 同 reason 的重放
                    if state["reason"] != reason:
                        raise ServiceError(
                            409,
                            f"wallet {wallet_id!r} is frozen with a "
                            "different reason",
                        )
                    return 200, state
                self._emit(
                    wallet_id,
                    self._audit_event(
                        audit.TYPE_WALLET_FROZEN,
                        details={"reason": reason},
                    ),
                )
        except CorruptDataError:
            raise
        except ValueError:
            # wallet_id 含非法字符（构造锁路径时抛出）
            raise ServiceError(400, "invalid wallet_id")
        return 201, self._security_state_view(
            wallet_id, WALLET_STATE_FROZEN, reason
        )

    def unfreeze_wallet(
        self, wallet_id: str, reason: object
    ) -> tuple[int, dict]:
        """POST /v1/wallets/<id>/unfreeze。返回 (201|200, 安全状态视图)。

        frozen -> active 首次转换 201，在每钱包跨进程事务锁内原子判定并
        追加唯一 wallet_unfrozen 事件（details 恰为 {"reason": ...}）；
        active 期间仅当存在同类转换记录（最近一次 unfreeze）且 reason
        相同才重放 200，无 unfreeze 记录或异 reason 一律 409。reason
        非字符串/空白/超长 400；钱包不存在 404。"""
        try:
            with self._wallet_lock(wallet_id):
                self._heal_wallet(wallet_id)
                # 404 优先于 400：存在性在锁内、heal 之后先判定
                self._get_wallet_or_404(wallet_id)
                self._validate_freeze_reason(reason)
                events = self._freeze_events_strict(wallet_id)
                if (
                    events
                    and events[-1]["type"] == audit.TYPE_WALLET_FROZEN
                ):
                    # 当前 frozen（末条为 freeze）：首提解冻。
                    self._emit(
                        wallet_id,
                        self._audit_event(
                            audit.TYPE_WALLET_UNFROZEN,
                            details={"reason": reason},
                        ),
                    )
                    return 201, self._security_state_view(
                        wallet_id, WALLET_STATE_ACTIVE, None
                    )
                # 当前 active（含从未冻结过的天然 active）：必须存在最近
                # 一次 unfreeze 记录且 reason 相同才允许幂等重放；无
                # unfreeze 记录或异 reason 一律 409。
                last_unfrozen = next(
                    (
                        event
                        for event in reversed(events)
                        if event["type"] == audit.TYPE_WALLET_UNFROZEN
                    ),
                    None,
                )
                if (
                    last_unfrozen is not None
                    and last_unfrozen["details"]["reason"] == reason
                ):
                    return 200, self._security_state_view(
                        wallet_id, WALLET_STATE_ACTIVE, None
                    )
                raise ServiceError(
                    409, f"wallet {wallet_id!r} is not frozen"
                )
        except CorruptDataError:
            raise
        except ValueError:
            # wallet_id 含非法字符（构造锁路径时抛出）
            raise ServiceError(400, "invalid wallet_id")

    def get_security_state(self, wallet_id: str) -> dict:
        """GET /v1/wallets/<id>/security-state：始终 200 返回
        ``{wallet_id,state,reason}``，active 时 reason 为 null。

        纯只读（不触发懒过期、不记事件）；冻结事件损坏/矛盾 fail-closed
        （由 HTTP 边界转 503）。钱包不存在 404。"""
        try:
            with self._wallet_lock(wallet_id):
                self._heal_wallet(wallet_id)
                # 404 优先：锁内先判定钱包存在，再折叠冻结事件
                self._get_wallet_or_404(wallet_id)
                return self._security_state_locked(wallet_id)
        except CorruptDataError:
            raise
        except ValueError:
            raise ServiceError(400, "invalid wallet_id")

    # ---- 资产粒度应急冻结/解冻 -------------------------------------------

    @staticmethod
    def _asset_security_state_view(
        wallet_id: str, asset_id: str, state: str, reason: object
    ) -> dict:
        """资产安全状态对外视图，固定键序 wallet_id,asset_id,state,reason；
        active 时 reason 恒为 null。"""
        return {
            "wallet_id": wallet_id,
            "asset_id": asset_id,
            "state": state,
            "reason": reason,
        }

    def _asset_freeze_events_strict(
        self, wallet_id: str
    ) -> dict[str, list[dict]]:
        """按 seq 折叠该钱包全部 asset_frozen/asset_unfrozen 事件，按资产
        标识分组（组内按 seq 升序），逐条严格校验并核对每资产的交替状态
        机（调用方须持钱包事务锁）。

        每条事件 request_id 必须等于 details.asset_id（安全标识），
        actor_id/reason(外层) 必须为 null，details 恰为
        ``{"asset_id", "reason"}``（落盘序 asset_id,reason），reason 为
        1..1024 字符非空白字符串；每个资产的事件必须严格交替，首条必为
        asset_frozen（active -> frozen），其后 frozen/unfrozen 轮流出现。
        任何畸形或同态连续（重复 freeze / 重复 unfreeze）都是不可对账
        现场（RecoveryError，fail-closed）。审计 JSON 损坏由下层抛
        CorruptDataError，文件 I/O 失败抛 OSError。纯只读，不记事件、
        不改 seq。"""
        grouped: dict[str, list[dict]] = {}
        for event in self._audit.all_events(wallet_id):
            etype = event.get("type")
            if etype not in (
                audit.TYPE_ASSET_FROZEN,
                audit.TYPE_ASSET_UNFROZEN,
            ):
                continue
            if (
                event.get("actor_id") is not None
                or event.get("reason") is not None
            ):
                raise RecoveryError(
                    f"wallet {wallet_id!r} has an asset freeze event with "
                    "actor_id/reason set"
                )
            details = event.get("details")
            asset_id = (
                event.get("request_id")
                if isinstance(details, dict)
                else None
            )
            reason = (
                details.get("reason")
                if isinstance(details, dict)
                else None
            )
            if (
                not isinstance(details, dict)
                or list(details) != ["asset_id", "reason"]
                or not isinstance(asset_id, str)
                or not ROTATION_ID_RE.match(asset_id)
                or details.get("asset_id") != asset_id
                or not isinstance(reason, str)
                or isinstance(reason, bool)
                or len(reason) < 1
                or len(reason) > MAX_REASON_LENGTH
                or not reason.strip()
            ):
                raise RecoveryError(
                    f"wallet {wallet_id!r} has a malformed asset freeze event"
                )
            if not isinstance(event.get("request_id"), str) or not (
                ROTATION_ID_RE.match(event["request_id"])
            ):
                raise RecoveryError(
                    f"wallet {wallet_id!r} has an asset freeze event with a "
                    "malformed request_id"
                )
            grouped.setdefault(asset_id, []).append(event)
        for asset_id, events in grouped.items():
            expected = audit.TYPE_ASSET_FROZEN
            for event in events:
                if event.get("type") != expected:
                    raise RecoveryError(
                        f"wallet {wallet_id!r} asset {asset_id!r} has "
                        "non-alternating asset freeze events"
                    )
                expected = (
                    audit.TYPE_ASSET_UNFROZEN
                    if expected == audit.TYPE_ASSET_FROZEN
                    else audit.TYPE_ASSET_FROZEN
                )
        return grouped

    def _asset_security_states_locked(
        self, wallet_id: str
    ) -> dict[str, dict]:
        """按审计事件折叠该钱包全部资产的当前安全状态（调用方须持钱包
        事务锁）。返回 ``{asset_id: {state, reason}}``：无事件或末条为
        unfrozen 的资产不在表中（视为 active，reason=null）；末条为
        frozen 时 state=frozen、reason 取最近一次 asset_frozen 原文。
        矛盾/损坏现场 fail-closed。纯只读，不新增事件、不改 seq。"""
        result: dict[str, dict] = {}
        for asset_id, events in self._asset_freeze_events_strict(
            wallet_id
        ).items():
            last = events[-1]
            if last["type"] == audit.TYPE_ASSET_FROZEN:
                result[asset_id] = {
                    "state": ASSET_STATE_FROZEN,
                    "reason": last["details"]["reason"],
                }
        return result

    def _assert_asset_active_locked(
        self, wallet_id: str, asset_id: str
    ) -> None:
        """指定资产 frozen 时，改变其现场的写入口统一 409（调用方须持
        钱包事务锁，且已通过钱包存在性与钱包冻结闸门）。

        在幂等重放、懒过期与一切业务判定之前调用：资产 frozen 期间即便
        请求本来命中幂等 200 重放也一律 409 且零副作用（不触发懒过期、
        不追加事件、不改现场）。同时保证冻结事件 ↔ 账本交叉对账：任何
        资产的冻结事件引用了无已提交操作的资产即矛盾现场（503），绝不
        在矛盾现场上放行其他资产的写入。"""
        self._reconcile_asset_freeze_ledger(wallet_id)
        state = self._asset_security_states_locked(wallet_id).get(asset_id)
        if state is not None and state["state"] == ASSET_STATE_FROZEN:
            raise ServiceError(
                409, f"asset {asset_id!r} is frozen"
            )

    def _reconcile_asset_freeze_ledger(self, wallet_id: str) -> None:
        """资产冻结事件与账本的交叉对账（调用方须持钱包事务锁）。

        每一条 asset_frozen/asset_unfrozen 事件绑定的资产都必须在账本中
        存在已提交操作——资产冻结入口只对有已提交余额的资产开放，事件
        引用了无已提交操作的资产即外部篡改/不可对账现场。事件自身的形状
        与每资产交替状态机由 :meth:`_asset_freeze_events_strict` 校验。
        纯只读，不新增事件、不改 seq。"""
        ledger = self._store.check_asset_ledger_semantics(wallet_id)
        committed_assets = {
            record["asset_id"]
            for record in ledger["operations"].values()
            if record.get("state") == "committed"
        }
        # 已提交转账的来源/目标资产同样构成已提交现场（目标资产可经
        # 转账新建而无任何 asset-operation）
        for record in ledger["transfers"].values():
            committed_assets.add(record["from_asset_id"])
            committed_assets.add(record["to_asset_id"])
        for asset_id in self._asset_freeze_events_strict(wallet_id):
            if asset_id not in committed_assets:
                raise RecoveryError(
                    f"wallet {wallet_id!r} has asset freeze events for "
                    f"asset {asset_id!r} without any committed operation"
                )

    def _asset_has_committed_ops(
        self, wallet_id: str, asset_id: str
    ) -> bool:
        """该资产是否已有已提交（committed）变化。资产冻结入口与
        security-state 仅对有已提交余额的资产开放（pending/cancelled
        不构成资产现场）；已提交转账的来源/目标侧同样构成已提交变化。
        调用方须持钱包事务锁。"""
        ledger = self._store.check_asset_ledger_semantics(wallet_id)
        if any(
            record.get("asset_id") == asset_id
            and record.get("state") == "committed"
            for record in ledger["operations"].values()
        ):
            return True
        return any(
            record["from_asset_id"] == asset_id
            or record["to_asset_id"] == asset_id
            for record in ledger["transfers"].values()
        )

    def _assert_dispatch_asset_active_locked(
        self, wallet_id: str, dispatch_id: str
    ) -> str:
        """把 did 键的派发写入口（result/confirm/takeover/isolate/settle）
        统一接到其所属资产的冻结闸门：解析该派发请求事件的 operation_id，
        经账本得到 asset_id，frozen 时抛 409；派发不存在返回 None（由各
        入口既有 404 逻辑处理）。调用方须持钱包事务锁。返回 asset_id。"""
        grouped = self._dispatch_requests_grouped_locked(wallet_id).get(
            dispatch_id
        )
        if not grouped:
            return None
        if len(grouped) != 1:
            raise RecoveryError(
                f"wallet {wallet_id!r} has multiple dispatch request events "
                f"for {dispatch_id!r}"
            )
        operation_id = grouped[0]["details"]["operation_id"]
        record = self._store.get_asset_operation(wallet_id, operation_id)
        if record is None:
            raise RecoveryError(
                f"wallet {wallet_id!r} dispatch {dispatch_id!r} refers to an "
                "unknown asset operation"
            )
        self._assert_asset_active_locked(
            wallet_id, record["asset_id"]
        )
        return record["asset_id"]

    def freeze_asset(
        self, wallet_id: str, asset_id: object, reason: object
    ) -> tuple[int, dict]:
        """POST /v1/wallets/<id>/assets/<asset_id>/freeze。

        active -> frozen 首转 201，在钱包事务锁内原子追加唯一
        asset_frozen 事件（request_id/details.asset_id 绑定资产、details
        恰为 {asset_id,reason}）；frozen 期间同 reason 重放 200（不复查、
        不记事件），异 reason 409。并发同一转换只有一个 201。钱包冻结
        闸门优先。reason 非字符串/空白/超长 400；钱包或无已提交操作的
        资产 404；asset_id 非法 400。"""
        try:
            with self._wallet_lock(wallet_id):
                self._heal_wallet(wallet_id)
                # 404 优先于 400：钱包存在性在锁内先判定
                self._get_wallet_or_404(wallet_id)
                self._assert_wallet_active_locked(wallet_id)
                self._validate_asset_id(asset_id)
                # 冻结事件 ↔ 账本交叉对账先于 404：该（或任一）资产有冻结
                # 事件却无已提交操作是矛盾现场（503），不是普通 404。
                self._reconcile_asset_freeze_ledger(wallet_id)
                if not self._asset_has_committed_ops(wallet_id, asset_id):
                    raise ServiceError(
                        404, f"asset {asset_id!r} not found"
                    )
                self._validate_freeze_reason(reason)
                states = self._asset_security_states_locked(wallet_id)
                current = states.get(asset_id)
                if current is not None:
                    if current["reason"] != reason:
                        raise ServiceError(
                            409,
                            f"asset {asset_id!r} is frozen with a different "
                            "reason",
                        )
                    return 200, self._asset_security_state_view(
                        wallet_id,
                        asset_id,
                        ASSET_STATE_FROZEN,
                        current["reason"],
                    )
                self._emit(
                    wallet_id,
                    self._audit_event(
                        audit.TYPE_ASSET_FROZEN,
                        request_id=asset_id,
                        details={"asset_id": asset_id, "reason": reason},
                    ),
                )
        except CorruptDataError:
            raise
        except ValueError:
            raise ServiceError(400, "invalid wallet_id")
        return 201, self._asset_security_state_view(
            wallet_id, asset_id, ASSET_STATE_FROZEN, reason
        )

    def unfreeze_asset(
        self, wallet_id: str, asset_id: object, reason: object
    ) -> tuple[int, dict]:
        """POST /v1/wallets/<id>/assets/<asset_id>/unfreeze。

        frozen -> active 首转 201，原子追加唯一 asset_unfrozen 事件；
        active 期间仅当存在该资产最近一次 unfreeze 记录且 reason 相同才
        幂等 200，无 unfreeze 记录（从未冻结）或异 reason 一律 409。
        钱包冻结闸门优先。"""
        try:
            with self._wallet_lock(wallet_id):
                self._heal_wallet(wallet_id)
                self._get_wallet_or_404(wallet_id)
                self._assert_wallet_active_locked(wallet_id)
                self._validate_asset_id(asset_id)
                # 冻结事件 ↔ 账本交叉对账先于 404：该（或任一）资产有冻结
                # 事件却无已提交操作是矛盾现场（503），不是普通 404。
                self._reconcile_asset_freeze_ledger(wallet_id)
                if not self._asset_has_committed_ops(wallet_id, asset_id):
                    raise ServiceError(
                        404, f"asset {asset_id!r} not found"
                    )
                self._validate_freeze_reason(reason)
                events = self._asset_freeze_events_strict(wallet_id).get(
                    asset_id, []
                )
                if (
                    events
                    and events[-1]["type"] == audit.TYPE_ASSET_FROZEN
                ):
                    # 当前 frozen：首提解冻。
                    self._emit(
                        wallet_id,
                        self._audit_event(
                            audit.TYPE_ASSET_UNFROZEN,
                            request_id=asset_id,
                            details={"asset_id": asset_id, "reason": reason},
                        ),
                    )
                    return 201, self._asset_security_state_view(
                        wallet_id, asset_id, ASSET_STATE_ACTIVE, None
                    )
                # 当前 active（含从未冻结过）：须存在最近一次 unfreeze 记录
                # 且 reason 相同才幂等重放；否则 409。
                last_unfrozen = next(
                    (
                        event
                        for event in reversed(events)
                        if event["type"] == audit.TYPE_ASSET_UNFROZEN
                    ),
                    None,
                )
                if (
                    last_unfrozen is not None
                    and last_unfrozen["details"]["reason"] == reason
                ):
                    return 200, self._asset_security_state_view(
                        wallet_id, asset_id, ASSET_STATE_ACTIVE, None
                    )
                raise ServiceError(
                    409, f"asset {asset_id!r} is not frozen"
                )
        except CorruptDataError:
            raise
        except ValueError:
            raise ServiceError(400, "invalid wallet_id")

    def get_asset_security_state(
        self, wallet_id: str, asset_id: object
    ) -> dict:
        """GET /v1/wallets/<id>/assets/<asset_id>/security-state：返回
        ``{wallet_id,asset_id,state,reason}``，active 时 reason 为 null。

        纯只读（不触发懒过期、不记事件）；资产冻结事件损坏/矛盾
        fail-closed（HTTP 503）。钱包不存在或资产尚无已提交操作 404；
        asset_id 非法 400。"""
        try:
            with self._wallet_lock(wallet_id):
                self._heal_wallet(wallet_id)
                # 404 优先：钱包存在性先于 asset_id 校验
                self._get_wallet_or_404(wallet_id)
                self._validate_asset_id(asset_id)
                self._reconcile_asset_freeze_ledger(wallet_id)
                if not self._asset_has_committed_ops(wallet_id, asset_id):
                    raise ServiceError(
                        404, f"asset {asset_id!r} not found"
                    )
                current = self._asset_security_states_locked(
                    wallet_id
                ).get(asset_id)
                if current is None:
                    return self._asset_security_state_view(
                        wallet_id, asset_id, ASSET_STATE_ACTIVE, None
                    )
                return self._asset_security_state_view(
                    wallet_id,
                    asset_id,
                    ASSET_STATE_FROZEN,
                    current["reason"],
                )
        except CorruptDataError:
            raise
        except ValueError:
            raise ServiceError(400, "invalid wallet_id")

    def put_policy(
        self,
        wallet_id: str,
        required_approvals: object,
        timeout_seconds: object,
    ) -> dict:
        # 读取（钱包存在性、旧策略）、校验、持久化与事件追加全部在同一把
        # 每钱包事务锁内完成：多个 serve 进程并发更新同一钱包策略时，
        # operation(created|updated) 严格依据锁内旧值，policy_updated 的
        # seq 顺序即策略线性化顺序，绝不基于锁外陈旧快照判定。
        policy: dict | None = None
        try:
            with self._wallet_lock(wallet_id):
                self._heal_wallet(wallet_id)
                # 404 优先于 400：钱包存在性在锁内先于参数校验
                self._get_wallet_or_404(wallet_id)
                self._assert_wallet_active_locked(wallet_id)
                # 双人变更控制启用后受控 PUT 统一 409（零副作用，在参数校验
                # 与任何写入之前）；改配置只能经 policy-changes 统一入口。
                self._assert_change_control_not_required_locked(wallet_id)
                # bool 是 int 的子类，必须先排除
                if (
                    not isinstance(required_approvals, int)
                    or isinstance(required_approvals, bool)
                    or required_approvals not in ALLOWED_REQUIRED_APPROVALS
                ):
                    raise ServiceError(
                        400,
                        "required_approvals must be one of "
                        + ", ".join(str(v) for v in ALLOWED_REQUIRED_APPROVALS),
                    )
                if (
                    not isinstance(timeout_seconds, int)
                    or isinstance(timeout_seconds, bool)
                    or timeout_seconds <= 0
                ):
                    raise ServiceError(
                        400, "timeout_seconds must be a positive integer"
                    )
                policy = {
                    "wallet_id": wallet_id,
                    "required_approvals": required_approvals,
                    "timeout_seconds": timeout_seconds,
                }
                # 同值更新也成功并记录；operation 必须依据锁内旧值
                old_policy = self._store.get_policy(wallet_id)
                operation = "created" if old_policy is None else "updated"
                self._store.save_policy(wallet_id, policy)
                event = self._audit_event(
                    audit.TYPE_POLICY_UPDATED,
                    details={
                        "required_approvals": required_approvals,
                        "timeout_seconds": timeout_seconds,
                        "operation": operation,
                    },
                )
                try:
                    self._emit(wallet_id, event)
                except BaseException:
                    # 状态/事件原子：事件未落盘则回滚策略状态
                    if old_policy is None:
                        self._store.delete_policy(wallet_id)
                    else:
                        self._store.save_policy(wallet_id, old_policy)
                    raise
        except CorruptDataError:
            # 钱包元数据/策略损坏：fail-closed（由 HTTP 边界转 503）
            raise
        except ValueError:
            # wallet_id 含非法字符（构造锁路径时抛出）
            raise ServiceError(400, "invalid wallet_id")
        return policy

    # ---- 钱包级审批人名单 ------------------------------------------------

    @staticmethod
    def _normalize_allowed_approvers(allowed_approvers: object) -> list[str]:
        if not isinstance(allowed_approvers, list):
            raise ValueError("allowed_approvers must be an array")
        result = []
        for approver in allowed_approvers:
            if (
                not isinstance(approver, str)
                or isinstance(approver, bool)
                or len(approver) < 1
                or len(approver) > MAX_APPROVER_LENGTH
                or not approver.strip()
            ):
                raise ValueError(
                    "each allowed approver must be a 1 to "
                    f"{MAX_APPROVER_LENGTH} character non-blank string"
                )
            if approver in result:
                raise ValueError(
                    "allowed_approvers must not contain duplicates"
                )
            result.append(approver)
        return sorted(result)

    @staticmethod
    def _validate_allowed_approvers(allowed_approvers: object) -> list[str]:
        try:
            return WalletService._normalize_allowed_approvers(
                allowed_approvers
            )
        except ValueError as exc:
            raise ServiceError(400, str(exc)) from exc

    def _approval_roster_events_strict(self, wallet_id: str) -> list[str]:
        """按 seq 重放审批人名单事件并返回当前名单。

        名单只由 approval_roster_updated 事件承载。每条事件的
        request_id/actor_id/reason 必须为 null，details 恰含
        allowed_approvers；数组每项为 1..128 字符非空白字符串，无重复且
        已按 Unicode 码点升序排列。当前状态取最后一条事件；无事件为空
        名单（不限制审批人）。纯只读，不新增事件、不改 seq。
        """
        current: list[str] = []
        for event in self._audit.all_events(wallet_id):
            if event.get("type") != audit.TYPE_APPROVAL_ROSTER_UPDATED:
                continue
            if (
                event.get("request_id") is not None
                or event.get("actor_id") is not None
                or event.get("reason") is not None
            ):
                raise RecoveryError(
                    f"wallet {wallet_id!r} has an approval roster event "
                    "with request_id/actor_id/reason set"
                )
            details = event.get("details")
            if not isinstance(details, dict) or set(details) != {
                "allowed_approvers"
            }:
                raise RecoveryError(
                    f"wallet {wallet_id!r} has a malformed approval roster "
                    "event"
                )
            roster = details["allowed_approvers"]
            try:
                normalized = self._normalize_allowed_approvers(roster)
            except ValueError as exc:
                raise RecoveryError(
                    f"wallet {wallet_id!r} has a malformed approval roster "
                    "event"
                ) from exc
            if roster != normalized:
                raise RecoveryError(
                    f"wallet {wallet_id!r} has an approval roster event "
                    "with duplicate or out-of-order approvers"
                )
            current = list(normalized)
        return current

    @staticmethod
    def _approval_roster_view(allowed_approvers: list[str]) -> dict:
        return {"allowed_approvers": list(allowed_approvers)}

    def put_approval_roster(
        self, wallet_id: str, allowed_approvers: object
    ) -> dict:
        try:
            with self._wallet_lock(wallet_id):
                self._heal_wallet(wallet_id)
                self._get_wallet_or_404(wallet_id)
                self._assert_wallet_active_locked(wallet_id)
                # 双人变更控制启用后受控 PUT 统一 409（零副作用）。
                self._assert_change_control_not_required_locked(wallet_id)
                self._approval_roster_events_strict(wallet_id)
                roster = self._validate_allowed_approvers(allowed_approvers)
                # 首次设置、修改、清空和同值更新都以最后一条快照事件为
                # 提交点，并各记一条事件。
                self._emit(
                    wallet_id,
                    self._audit_event(
                        audit.TYPE_APPROVAL_ROSTER_UPDATED,
                        details={"allowed_approvers": roster},
                    ),
                )
        except CorruptDataError:
            raise
        except ValueError:
            raise ServiceError(400, "invalid wallet_id")
        return self._approval_roster_view(roster)

    def get_approval_roster(self, wallet_id: str) -> dict:
        try:
            with self._wallet_lock(wallet_id):
                self._heal_wallet(wallet_id)
                self._get_wallet_or_404(wallet_id)
                # 折叠 legacy approval_roster_updated 与变更控制下
                # target=approval-roster 的 policy_change_applied（按 seq）。
                roster = self._effective_roster_locked(wallet_id)
        except CorruptDataError:
            raise
        except ValueError:
            raise ServiceError(400, "invalid wallet_id")
        return self._approval_roster_view(roster)

    # ---- 冷热钱包交易策略 -------------------------------------------------

    @staticmethod
    def _validate_transaction_policy(
        mode: object, max_delta: object, allowed_assets: object
    ) -> None:
        """校验交易策略请求体：类型、空值、重复或非法资产一律 400。"""
        if not isinstance(mode, str) or mode not in TRANSACTION_POLICY_MODES:
            raise ServiceError(
                400,
                "mode must be one of "
                + ", ".join(TRANSACTION_POLICY_MODES),
            )
        # bool 是 int 的子类，必须先排除
        if (
            not isinstance(max_delta, int)
            or isinstance(max_delta, bool)
            or max_delta <= 0
        ):
            raise ServiceError(400, "max_delta must be a positive integer")
        if not isinstance(allowed_assets, list) or not allowed_assets:
            raise ServiceError(
                400, "allowed_assets must be a non-empty list"
            )
        seen: set[str] = set()
        for index, asset in enumerate(allowed_assets):
            if not isinstance(asset, str) or not ROTATION_ID_RE.match(asset):
                raise ServiceError(
                    400,
                    f"allowed_assets[{index}] must match "
                    "[A-Za-z0-9_-]{1,128}",
                )
            if asset in seen:
                raise ServiceError(
                    400, f"allowed_assets[{index}] duplicates a prior asset"
                )
            seen.add(asset)

    def put_transaction_policy(
        self,
        wallet_id: str,
        mode: object,
        max_delta: object,
        allowed_assets: object,
    ) -> dict:
        """设置（或覆盖）钱包的冷热钱包交易策略。

        成功 200 返回与请求体同形的 {mode, max_delta, allowed_assets}；
        钱包不存在 404；类型、空值、重复或非法资产 400。策略状态与
        transaction_policy_updated 事件在每钱包事务锁内原子持久化，
        同值更新也记事件（details 即策略三项）。

        恢复检查、钱包存在性判定、参数校验、旧策略读取、覆盖与事件追加
        全部在同一把每钱包跨进程事务锁内完成：绝不基于锁外快照决定
        404/400 或判定旧值，策略与资产首签/创建交错时只能看到锁提交时
        已生效的策略。
        """
        policy: dict | None = None
        try:
            with self._wallet_lock(wallet_id):
                self._heal_wallet(wallet_id)
                # 404 优先于 400：存在性在锁内、heal 之后先判定
                self._get_wallet_or_404(wallet_id)
                self._assert_wallet_active_locked(wallet_id)
                # 双人变更控制启用后受控 PUT 统一 409（零副作用）。
                self._assert_change_control_not_required_locked(wallet_id)
                self._validate_transaction_policy(mode, max_delta, allowed_assets)
                # 落盘文件恰含 mode/max_delta/allowed_assets 三项（公开契约）
                policy = {
                    "mode": mode,
                    "max_delta": max_delta,
                    "allowed_assets": list(allowed_assets),
                }
                old_policy = self._store.get_transaction_policy(wallet_id)
                self._store.save_transaction_policy(wallet_id, policy)
                event = self._audit_event(
                    audit.TYPE_TRANSACTION_POLICY_UPDATED,
                    details={
                        "mode": mode,
                        "max_delta": max_delta,
                        "allowed_assets": list(allowed_assets),
                    },
                )
                try:
                    self._emit(wallet_id, event)
                except BaseException:
                    # 状态/事件原子：事件未落盘则回滚策略状态
                    if old_policy is None:
                        self._store.delete_transaction_policy(wallet_id)
                    else:
                        self._store.save_transaction_policy(
                            wallet_id, old_policy
                        )
                    raise
        except CorruptDataError:
            # 钱包元数据/旧策略损坏：fail-closed（由 HTTP 边界转 503）
            raise
        except ValueError:
            # wallet_id 含非法字符（构造锁路径时抛出）
            raise ServiceError(400, "invalid wallet_id")
        # 对外视图与请求体同形（不含 wallet_id）
        return {
            "mode": policy["mode"],
            "max_delta": policy["max_delta"],
            "allowed_assets": list(policy["allowed_assets"]),
        }

    def get_transaction_policy(self, wallet_id: str) -> dict:
        """读取交易策略：已配置 200 同体，未配置 404。

        恢复检查、钱包存在性与策略读取全部在锁内：绝不先用锁外快照
        决定 404，也不会在并发覆盖/回滚窗口读到半完成策略。"""
        try:
            with self._wallet_lock(wallet_id):
                self._heal_wallet(wallet_id)
                # 404 优先：锁内先判定钱包存在，再判定策略是否已配置
                self._get_wallet_or_404(wallet_id)
                policy = self._store.get_transaction_policy(wallet_id)
        except CorruptDataError:
            raise
        except ValueError:
            raise ServiceError(400, "invalid wallet_id")
        if policy is None:
            raise ServiceError(
                404, f"wallet {wallet_id!r} has no transaction policy"
            )
        return {
            "mode": policy["mode"],
            "max_delta": policy["max_delta"],
            "allowed_assets": list(policy["allowed_assets"]),
        }

    # ---- DKG 故障审批策略 -------------------------------------------------

    #: approval_request_id 缺省哨兵：区别于显式传入 None
    _NO_APPROVAL = object()
    _NO_NODE = object()

    def _dkg_failover_policy_enabled(self, wallet_id: str) -> bool:
        """从 dkg_failover_policy_updated 事件序列恢复 DKG 故障审批开关。

        策略只由审计事件持久化（事件之外不写任何状态文件）：取最后一条
        同类型事件的 details.enabled，无事件缺省 False。每条事件的
        request_id/actor_id/reason 必须为 null，details 恰含布尔
        ``enabled``；任何畸形/矛盾都是不可对账现场（RecoveryError，
        fail-closed），绝不静默按缺省处理。纯只读，不分配 seq。"""
        enabled = False
        events = self._audit.events_by_type(
            wallet_id, audit.TYPE_DKG_FAILOVER_POLICY_UPDATED
        )
        for event in events:
            if (
                event.get("request_id") is not None
                or event.get("actor_id") is not None
                or event.get("reason") is not None
            ):
                raise RecoveryError(
                    f"wallet {wallet_id!r} has a dkg_failover_policy_updated "
                    "event with request_id/actor/reason set"
                )
            details = event.get("details")
            if (
                not isinstance(details, dict)
                or set(details) != {"enabled"}
                or not isinstance(details["enabled"], bool)
            ):
                raise RecoveryError(
                    f"wallet {wallet_id!r} has a malformed "
                    "dkg_failover_policy_updated event"
                )
            enabled = details["enabled"]
        return enabled

    def put_dkg_failover_policy(self, wallet_id: str, enabled: object) -> dict:
        """设置 DKG 故障审批开关。

        PUT 仅收 ``{"enabled": bool}``；成功 200 返回同体，GET/PUT 200
        同体；非法（非布尔、夹带其他键由 HTTP 边界拦）400；钱包不存在
        404。策略仅由 dkg_failover_policy_updated 事件持久化
        （request_id/actor_id/reason 为 null，details 恰含 enabled），
        **同值更新也记事件**，不写任何策略状态文件。"""
        try:
            with self._wallet_lock(wallet_id):
                self._heal_wallet(wallet_id)
                # 404 优先于 400：存在性在锁内、heal 之后先判定
                self._get_wallet_or_404(wallet_id)
                self._assert_wallet_active_locked(wallet_id)
                # 双人变更控制启用后受控 PUT 统一 409（零副作用）。
                self._assert_change_control_not_required_locked(wallet_id)
                # bool 必须严格为布尔（拒绝 int/None/字符串）
                if not isinstance(enabled, bool):
                    raise ServiceError(400, "enabled must be a boolean")
                self._emit(
                    wallet_id,
                    self._audit_event(
                        audit.TYPE_DKG_FAILOVER_POLICY_UPDATED,
                        details={"enabled": enabled},
                    ),
                )
        except CorruptDataError:
            raise
        except ValueError:
            # wallet_id 含非法字符（构造锁路径时抛出）
            raise ServiceError(400, "invalid wallet_id")
        return {"enabled": enabled}

    def get_dkg_failover_policy(self, wallet_id: str) -> dict:
        """读取 DKG 故障审批策略：始终 200，无事件缺省 ``{"enabled": False}``。

        策略纯由事件恢复；损坏/矛盾事件 fail-closed（由 HTTP 边界转
        503）。钱包不存在 404。"""
        try:
            with self._wallet_lock(wallet_id):
                self._heal_wallet(wallet_id)
                # 404 优先：锁内先判定钱包存在，再从事件恢复策略
                self._get_wallet_or_404(wallet_id)
                enabled = self._effective_dkg_failover_enabled_locked(wallet_id)
        except CorruptDataError:
            raise
        except ValueError:
            raise ServiceError(400, "invalid wallet_id")
        return {"enabled": enabled}

    # ---- 高风险配置双人变更控制 ------------------------------------------

    #: policy_change_applied 视图（与公开响应）固定五字段外加 seq。
    _POLICY_CHANGE_DETAILS_KEY_ORDER = (
        "change_id",
        "target",
        "before",
        "after",
        "approval_request_id",
    )
    #: target=chain-policy 的 details 固定六字段（target 后插入 asset_id）。
    _POLICY_CHANGE_DETAILS_KEY_ORDER_CHAIN = (
        "change_id",
        "target",
        "asset_id",
        "before",
        "after",
        "approval_request_id",
    )
    #: 审批单 message 固定四字段（不含 approval_request_id）。
    _POLICY_CHANGE_MESSAGE_KEY_ORDER = (
        "change_id",
        "target",
        "before",
        "after",
    )
    #: target=chain-policy 的审批单 message 固定五字段（target 后插入
    #: asset_id）。
    _POLICY_CHANGE_MESSAGE_KEY_ORDER_CHAIN = (
        "change_id",
        "target",
        "asset_id",
        "before",
        "after",
    )

    @staticmethod
    def _policy_change_message(payload: dict) -> str:
        """审批单 message 必须逐字一致的 ASCII 紧凑 JSON：仅含
        change_id,target,before,after 四键（该固定序），target=chain-policy
        时在 target 后插入 asset_id 共五键；无空白，非 ASCII 一律转义
        （ensure_ascii=True）。嵌套 before/after 为归一后的公开配置视图
        （节点/适配器/名单键序确定，链策略沿用 PUT 公开视图字段序）。"""
        if payload.get("target") == "chain-policy":
            order = WalletService._POLICY_CHANGE_MESSAGE_KEY_ORDER_CHAIN
        else:
            order = WalletService._POLICY_CHANGE_MESSAGE_KEY_ORDER
        ordered = {key: payload[key] for key in order}
        return json.dumps(
            ordered, ensure_ascii=True, separators=(",", ":")
        )

    def _approval_policy_view(self, stored: dict) -> dict:
        """审批策略的公开视图（不含内部 wallet_id 字段）。"""
        return {
            "required_approvals": stored["required_approvals"],
            "timeout_seconds": stored["timeout_seconds"],
        }

    def _current_approval_policy_view_locked(self, wallet_id: str):
        policy = self._store.get_policy(wallet_id)
        return None if policy is None else self._approval_policy_view(policy)

    def _current_transaction_policy_view_locked(self, wallet_id: str):
        policy = self._store.get_transaction_policy(wallet_id)
        if policy is None:
            return None
        return {
            "mode": policy["mode"],
            "max_delta": policy["max_delta"],
            "allowed_assets": list(policy["allowed_assets"]),
        }

    def _normalize_change_approval_policy(self, view: object) -> dict:
        if not isinstance(view, dict) or set(view) != {
            "required_approvals",
            "timeout_seconds",
        }:
            raise ServiceError(
                400,
                "approval-policy config must contain exactly "
                "required_approvals and timeout_seconds",
            )
        required = view["required_approvals"]
        timeout = view["timeout_seconds"]
        if (
            not isinstance(required, int)
            or isinstance(required, bool)
            or required not in ALLOWED_REQUIRED_APPROVALS
        ):
            raise ServiceError(
                400,
                "required_approvals must be one of "
                + ", ".join(str(v) for v in ALLOWED_REQUIRED_APPROVALS),
            )
        if (
            not isinstance(timeout, int)
            or isinstance(timeout, bool)
            or timeout <= 0
        ):
            raise ServiceError(
                400, "timeout_seconds must be a positive integer"
            )
        return {"required_approvals": required, "timeout_seconds": timeout}

    def _normalize_change_transaction_policy(self, view: object) -> dict:
        if not isinstance(view, dict) or set(view) != {
            "mode",
            "max_delta",
            "allowed_assets",
        }:
            raise ServiceError(
                400,
                "transaction-policy config must contain exactly mode, "
                "max_delta and allowed_assets",
            )
        mode = view["mode"]
        max_delta = view["max_delta"]
        allowed_assets = view["allowed_assets"]
        self._validate_transaction_policy(mode, max_delta, allowed_assets)
        return {
            "mode": mode,
            "max_delta": max_delta,
            "allowed_assets": list(allowed_assets),
        }

    @staticmethod
    def _normalize_change_enabled(view: object, what: str) -> dict:
        if not isinstance(view, dict) or set(view) != {"enabled"}:
            raise ServiceError(
                400, f"{what} config must contain exactly enabled"
            )
        enabled = view["enabled"]
        if not isinstance(enabled, bool):
            raise ServiceError(400, "enabled must be a boolean")
        return {"enabled": enabled}

    def _normalize_change_chain_policy(self, view: object) -> dict:
        """归一并校验 chain-policy 目标的非空公开配置视图：恰为 PUT 公开
        视图 Q 的四键与取值规则，返回固定键序
        chain_id,enabled,required_confirmations,reorg_window。非法抛
        ServiceError(400)。"""
        if not isinstance(view, dict) or set(view) != {
            "chain_id",
            "enabled",
            "required_confirmations",
            "reorg_window",
        }:
            raise ServiceError(
                400,
                "chain-policy config must contain exactly chain_id, "
                "enabled, required_confirmations and reorg_window",
            )
        chain_id = view["chain_id"]
        enabled = view["enabled"]
        required = view["required_confirmations"]
        window = view["reorg_window"]
        self._validate_chain_id(chain_id)
        if not isinstance(enabled, bool):
            raise ServiceError(400, "enabled must be a boolean")
        if (
            not isinstance(required, int)
            or isinstance(required, bool)
            or required <= 0
        ):
            raise ServiceError(
                400, "required_confirmations must be a positive integer"
            )
        if (
            not isinstance(window, int)
            or isinstance(window, bool)
            or window < 0
        ):
            raise ServiceError(
                400, "reorg_window must be a non-negative integer"
            )
        return {
            "chain_id": chain_id,
            "enabled": enabled,
            "required_confirmations": required,
            "reorg_window": window,
        }

    def _normalize_change_config(self, target: str, view: object) -> dict:
        """归一并校验某 target 的非空公开配置视图，非法抛 ServiceError(400)。

        节点表归一为节点 ID 升序、每值键序 key,state（与 PUT nodes 一致，
        服务端排序）；适配器表要求请求体已按 ASCII 升序（与 PUT
        chain-adapters 一致，错序 400）；名单按码点升序去重。"""
        if target == "approval-policy":
            return self._normalize_change_approval_policy(view)
        if target == "transaction-policy":
            return self._normalize_change_transaction_policy(view)
        if target in ("dkg-failover-policy", "change-control"):
            return self._normalize_change_enabled(view, target)
        if target == "approval-roster":
            if not isinstance(view, dict) or set(view) != {
                "allowed_approvers"
            }:
                raise ServiceError(
                    400,
                    "approval-roster config must contain exactly "
                    "allowed_approvers",
                )
            roster = self._validate_allowed_approvers(view["allowed_approvers"])
            return {"allowed_approvers": roster}
        if target == "nodes":
            if not isinstance(view, dict) or set(view) != {"nodes"}:
                raise ServiceError(
                    400, "nodes config must contain exactly nodes"
                )
            return {"nodes": self._normalize_nodes_body(view["nodes"])}
        if target == "chain-policy":
            return self._normalize_change_chain_policy(view)
        # chain-adapters
        if not isinstance(view, dict) or set(view) != {"adapters"}:
            raise ServiceError(
                400, "chain-adapters config must contain exactly adapters"
            )
        return {"adapters": self._normalize_adapters_body(view["adapters"])}

    def _recover_strict_change_config(
        self, target: str, view: object, *, allow_null: bool, wallet_id: str
    ):
        """恢复路径的配置形状校验：畸形是不可对账现场（RecoveryError），
        绝不归一或猜写。返回归一视图（或 null）。"""
        if view is None:
            if allow_null:
                return None
            raise RecoveryError(
                f"wallet {wallet_id!r} has a policy_change_applied event "
                f"for {target!r} with a null config"
            )
        try:
            if target == "approval-policy":
                normalized = self._normalize_change_approval_policy(view)
            elif target == "transaction-policy":
                normalized = self._normalize_change_transaction_policy(view)
            elif target in ("dkg-failover-policy", "change-control"):
                normalized = self._normalize_change_enabled(view, target)
            elif target == "chain-policy":
                normalized = self._normalize_change_chain_policy(view)
            elif target == "approval-roster":
                if not isinstance(view, dict) or set(view) != {
                    "allowed_approvers"
                }:
                    raise ValueError("bad roster config")
                roster = self._normalize_allowed_approvers(
                    view["allowed_approvers"]
                )
                if list(view["allowed_approvers"]) != roster:
                    raise ValueError("roster not sorted or duplicated")
                normalized = {"allowed_approvers": roster}
            elif target == "nodes":
                if not isinstance(view, dict) or set(view) != {"nodes"}:
                    raise ValueError("bad nodes config")
                nodes = view["nodes"]
                if not isinstance(nodes, dict) or not nodes:
                    raise ValueError("bad nodes table")
                if any(not isinstance(k, str) for k in nodes):
                    raise ValueError("bad node id")
                keys = list(nodes)
                if keys != sorted(keys) or len(set(keys)) != len(keys):
                    raise ValueError("nodes not strictly ascending")
                for node_id, entry in nodes.items():
                    if not ROTATION_ID_RE.match(node_id):
                        raise ValueError("bad node id")
                    if (
                        not isinstance(entry, dict)
                        or list(entry) != list(_NODE_STATE_ENTRY_KEY_ORDER)
                        or not _is_lower_hex_32(entry.get("key"))
                        or entry.get("state") not in DKG_NODE_STATES
                    ):
                        raise ValueError("bad node entry")
                normalized = {"nodes": {k: dict(nodes[k]) for k in keys}}
            else:  # chain-adapters
                if not isinstance(view, dict) or set(view) != {"adapters"}:
                    raise ValueError("bad adapters config")
                adapters = view["adapters"]
                if not isinstance(adapters, dict) or not adapters:
                    raise ValueError("bad adapters table")
                if any(not isinstance(k, str) for k in adapters):
                    raise ValueError("bad adapter id")
                keys = list(adapters)
                if keys != sorted(keys) or len(set(keys)) != len(keys):
                    raise ValueError("adapters not strictly ascending")
                for adapter_id, state in adapters.items():
                    if (
                        not ROTATION_ID_RE.match(adapter_id)
                        or not isinstance(state, str)
                        or state not in CHAIN_ADAPTER_STATES
                    ):
                        raise ValueError("bad adapter entry")
                normalized = {"adapters": {k: adapters[k] for k in keys}}
        except (ValueError, ServiceError) as exc:
            raise RecoveryError(
                f"wallet {wallet_id!r} has a policy_change_applied event "
                f"for {target!r} with a malformed config: {exc}"
            ) from exc
        return normalized

    def _policy_change_events_strict(self, wallet_id: str) -> list[dict]:
        """返回该钱包全部 policy_change_applied 事件（按 seq 升序）并逐条
        严格校验形状与提交时审批门控（调用方须持钱包事务锁）。

        - 外层七字段为落盘规范序；reason 为 null；
        - request_id/actor_id 均为安全标识，request_id==details.change_id，
          actor_id==details.approval_request_id；同一 change_id 至多一条；
        - details 恰为五键固定序（target=chain-policy 时在 target 后插入
          asset_id 共六键，asset_id 为安全标识，且 asset_id 键由
          chain-policy 独占）；target 属八类受控配置；
        - before 仅对五类可缺省目标允许 null，after 必须为合法非空视图；
          两者形状按各 target 公开视图严格校验（节点/适配器升序、名单
          码点升序、链策略四键取值）；
        - actor 审批单必须存在、message 逐字为四键（chain-policy 五键）
          ASCII 紧凑 JSON、状态 approved/signed 且有两位**不同**审批人。

        任何畸形/矛盾都是不可对账现场（RecoveryError，fail-closed，保留
        现场）。纯只读，不新增事件、不改 seq。"""
        events = self._audit.events_by_type(
            wallet_id, audit.TYPE_POLICY_CHANGE_APPLIED
        )
        seen: set[str] = set()
        for event in events:
            if list(event) != list(_AUDIT_OUTER_KEY_ORDER):
                raise RecoveryError(
                    f"wallet {wallet_id!r} has a policy_change_applied event "
                    "whose outer fields are out of the canonical order"
                )
            change_id = event.get("request_id")
            approval_id = event.get("actor_id")
            if not (
                isinstance(change_id, str) and ROTATION_ID_RE.match(change_id)
            ):
                raise RecoveryError(
                    f"wallet {wallet_id!r} has a policy_change_applied event "
                    "with a malformed change_id"
                )
            if change_id in seen:
                raise RecoveryError(
                    f"wallet {wallet_id!r} has multiple policy_change_applied "
                    f"events for {change_id!r}"
                )
            seen.add(change_id)
            if not (
                isinstance(approval_id, str)
                and ROTATION_ID_RE.match(approval_id)
            ):
                raise RecoveryError(
                    f"wallet {wallet_id!r} policy_change_applied "
                    f"{change_id!r} has a malformed approval_request_id"
                )
            if event.get("reason") is not None:
                raise RecoveryError(
                    f"wallet {wallet_id!r} policy_change_applied "
                    f"{change_id!r} has a non-null reason"
                )
            details = event.get("details")
            if not isinstance(details, dict):
                raise RecoveryError(
                    f"wallet {wallet_id!r} policy_change_applied "
                    f"{change_id!r} has malformed details"
                )
            if list(details) == list(self._POLICY_CHANGE_DETAILS_KEY_ORDER):
                asset_id = None
            elif list(details) == list(
                self._POLICY_CHANGE_DETAILS_KEY_ORDER_CHAIN
            ):
                asset_id = details["asset_id"]
                if not (
                    isinstance(asset_id, str)
                    and ROTATION_ID_RE.match(asset_id)
                ):
                    raise RecoveryError(
                        f"wallet {wallet_id!r} policy_change_applied "
                        f"{change_id!r} has a malformed asset_id"
                    )
            else:
                raise RecoveryError(
                    f"wallet {wallet_id!r} policy_change_applied "
                    f"{change_id!r} has malformed details"
                )
            target = details["target"]
            if (target == "chain-policy") != (asset_id is not None):
                # asset_id 键由 chain-policy 独占：原七类目标夹带、或
                # chain-policy 缺失，都是不可对账现场。
                raise RecoveryError(
                    f"wallet {wallet_id!r} policy_change_applied "
                    f"{change_id!r} details identifiers disagree"
                )
            if (
                details["change_id"] != change_id
                or details["approval_request_id"] != approval_id
            ):
                raise RecoveryError(
                    f"wallet {wallet_id!r} policy_change_applied "
                    f"{change_id!r} details identifiers disagree"
                )
            if target not in CHANGE_CONTROL_TARGETS:
                raise RecoveryError(
                    f"wallet {wallet_id!r} policy_change_applied "
                    f"{change_id!r} has an unknown target {target!r}"
                )
            allow_null = target in _CHANGE_NULLABLE_TARGETS
            before = self._recover_strict_change_config(
                target, details.get("before"),
                allow_null=allow_null, wallet_id=wallet_id,
            )
            after = self._recover_strict_change_config(
                target, details.get("after"),
                allow_null=False, wallet_id=wallet_id,
            )
            if details.get("before") != before:
                raise RecoveryError(
                    f"wallet {wallet_id!r} policy_change_applied "
                    f"{change_id!r} before config is not normalized"
                )
            if details.get("after") != after:
                raise RecoveryError(
                    f"wallet {wallet_id!r} policy_change_applied "
                    f"{change_id!r} after config is not normalized"
                )
            # 审批单复核：存在、message 逐字一致、approved/signed 且两位
            # 不同审批人（提交时已 approved；其后只可能停留 approved 或经
            # /sign 推进为 signed）。
            approval = self._store.get_request(wallet_id, approval_id)
            if not isinstance(approval, dict):
                raise RecoveryError(
                    f"wallet {wallet_id!r} policy_change_applied "
                    f"{change_id!r} refers to an unknown approval request"
                )
            expected_message = self._policy_change_message(
                {
                    "change_id": change_id,
                    "target": target,
                    "asset_id": asset_id,
                    "before": before,
                    "after": after,
                }
            )
            if approval.get("message") != expected_message:
                raise RecoveryError(
                    f"wallet {wallet_id!r} policy_change_applied "
                    f"{change_id!r} approval message does not match"
                )
            if approval.get("state") not in ("approved", "signed"):
                raise RecoveryError(
                    f"wallet {wallet_id!r} policy_change_applied "
                    f"{change_id!r} approval request is not approved"
                )
            approvers = approval.get("approvers")
            if (
                not isinstance(approvers, list)
                or len(set(approvers)) < 2
            ):
                raise RecoveryError(
                    f"wallet {wallet_id!r} policy_change_applied "
                    f"{change_id!r} approval lacks two distinct approvers"
                )
        return events

    def _change_control_enabled_locked(self, wallet_id: str) -> bool:
        """折叠当前双人变更控制开关：只取 target=change-control 的
        policy_change_applied 快照的最后一条 after.enabled，缺省 False。
        调用方须持钱包事务锁（事件先经严格校验）。"""
        enabled = False
        for event in self._policy_change_events_strict(wallet_id):
            if event["details"]["target"] == "change-control":
                enabled = event["details"]["after"]["enabled"]
        return enabled

    def get_change_control(self, wallet_id: str) -> dict:
        """GET /v1/wallets/{id}/change-control：始终 200，初始
        ``{"enabled": false}``；钱包不存在 404。"""
        try:
            with self._wallet_lock(wallet_id):
                self._heal_wallet(wallet_id)
                self._get_wallet_or_404(wallet_id)
                enabled = self._change_control_enabled_locked(wallet_id)
        except CorruptDataError:
            raise
        except ValueError:
            raise ServiceError(400, "invalid wallet_id")
        return {"enabled": enabled}

    def _assert_change_control_not_required_locked(
        self, wallet_id: str
    ) -> None:
        """双人变更控制启用后，受控配置的原 PUT（六类钱包级配置与跨链
        确认策略 PUT）统一 409（change control required）且零副作用。
        在钱包存在性/冻结判定之后、任何参数校验与写入之前调用。"""
        if self._change_control_enabled_locked(wallet_id):
            raise ServiceError(
                409, "change control required"
            )

    # -- 审计承载配置的统一快照折叠（legacy 事件 + policy_change_applied）--

    def _node_health_snapshot_events_locked(
        self, wallet_id: str
    ) -> list[dict]:
        """节点健康表的全部配置快照（按 seq 升序）：既有的 node_state 事件
        与 target=nodes 的 policy_change_applied 事件统一为
        ``{"seq","details":{"nodes"}}`` 快照。后者是变更控制启用后的唯一
        提交点，与 node_state 同样作为全量快照参与按 seq 的事前健康表折叠
        （DKG auto 选择/rejoin/share-bind 复核）。两类事件均先经严格校验。"""
        snapshots = [
            {"seq": event["seq"], "details": {"nodes": dict(
                event["details"]["nodes"]
            )}}
            for event in self._node_state_events_strict(wallet_id)
        ]
        for event in self._policy_change_events_strict(wallet_id):
            if event["details"]["target"] == "nodes":
                snapshots.append(
                    {
                        "seq": event["seq"],
                        "details": {
                            "nodes": dict(event["details"]["after"]["nodes"])
                        },
                    }
                )
        snapshots.sort(key=lambda e: e["seq"])
        return snapshots

    def _adapter_health_snapshot_events_locked(
        self, wallet_id: str
    ) -> list[dict]:
        """适配器健康熔断表的全部配置快照（按 seq 升序）：既有的
        chain_adapter_health 事件与 target=chain-adapters 的
        policy_change_applied 事件统一为
        ``{"seq","details":{"adapters"}}`` 快照，参与自动派发/隔离按 seq 的
        事前健康表折叠。两类事件均先经严格校验。"""
        snapshots = [
            {"seq": event["seq"],
             "details": {"adapters": dict(event["details"]["adapters"])}}
            for event in self._chain_adapter_health_events_strict(wallet_id)
        ]
        for event in self._policy_change_events_strict(wallet_id):
            if event["details"]["target"] == "chain-adapters":
                snapshots.append(
                    {
                        "seq": event["seq"],
                        "details": {
                            "adapters": dict(
                                event["details"]["after"]["adapters"]
                            )
                        },
                    }
                )
        snapshots.sort(key=lambda e: e["seq"])
        return snapshots

    def _effective_roster_locked(self, wallet_id: str) -> list[str]:
        """折叠当前审批人名单：approval_roster_updated 与
        target=approval-roster 的 policy_change_applied 按 seq 统一折叠，
        取最后一条快照；无事件为空名单。两类事件均已严格校验。"""
        current: list[str] = []
        # 先严格校验 legacy 名单事件（成员形状/去重/码点升序）。
        self._approval_roster_events_strict(wallet_id)
        legacy = {
            event["seq"]: event["details"]["allowed_approvers"]
            for event in self._audit.events_by_type(
                wallet_id, audit.TYPE_APPROVAL_ROSTER_UPDATED
            )
        }
        changes = {
            event["seq"]: event["details"]["after"]["allowed_approvers"]
            for event in self._policy_change_events_strict(wallet_id)
            if event["details"]["target"] == "approval-roster"
        }
        for seq in sorted(set(legacy) | set(changes)):
            if seq in changes:
                current = list(changes[seq])
            else:
                current = list(legacy[seq])
        return current

    def _effective_dkg_failover_enabled_locked(self, wallet_id: str) -> bool:
        """折叠 DKG 故障审批开关：dkg_failover_policy_updated 与
        target=dkg-failover-policy 的 policy_change_applied 按 seq 取最后。
        legacy 事件先经严格形状校验（畸形 fail-closed）。"""
        # 严格校验并折叠 legacy 事件（_dkg_failover_policy_enabled 逐条校验
        # 三 id 字段为 null、details 恰含布尔 enabled）。
        self._dkg_failover_policy_enabled(wallet_id)
        enabled = False
        legacy = {
            event["seq"]: event["details"]["enabled"]
            for event in self._audit.events_by_type(
                wallet_id, audit.TYPE_DKG_FAILOVER_POLICY_UPDATED
            )
        }
        changes = {
            event["seq"]: event["details"]["after"]["enabled"]
            for event in self._policy_change_events_strict(wallet_id)
            if event["details"]["target"] == "dkg-failover-policy"
        }
        for seq in sorted(set(legacy) | set(changes)):
            enabled = changes[seq] if seq in changes else legacy[seq]
        return enabled

    def _current_config_view_locked(
        self, wallet_id: str, target: str, asset_id: str | None = None
    ):
        """某受控 target 的当前公开配置视图（调用方须持钱包事务锁）。

        audit-sourced 配置统一折叠 legacy 快照与 policy_change_applied；
        文件型配置（heal/recover 已把文件对账到审计提交点）直接读文件。
        chain-policy 为资产粒度：返回该资产当前链确认策略（未配置 None），
        其他资产的配置与变动不参与比较。"""
        if target == "approval-policy":
            return self._current_approval_policy_view_locked(wallet_id)
        if target == "transaction-policy":
            return self._current_transaction_policy_view_locked(wallet_id)
        if target == "approval-roster":
            return {"allowed_approvers": self._effective_roster_locked(wallet_id)}
        if target == "dkg-failover-policy":
            return {
                "enabled": self._effective_dkg_failover_enabled_locked(wallet_id)
            }
        if target == "nodes":
            # 公开视图（GET /nodes）是生效健康表：最后快照再折叠其后
            # node_rejoined 的 up 翻转，before 须与之比较。
            nodes = self._health_table_folding_rejoins_locked(wallet_id)
            if nodes is None:
                return None
            return {"nodes": dict(nodes)}
        if target == "chain-adapters":
            snapshots = self._adapter_health_snapshot_events_locked(wallet_id)
            if not snapshots:
                return None
            return {"adapters": dict(snapshots[-1]["details"]["adapters"])}
        if target == "chain-policy":
            policy = self._chain_policies(wallet_id).get(asset_id)
            return None if policy is None else dict(policy)
        # change-control
        return {"enabled": self._change_control_enabled_locked(wallet_id)}

    def _policy_change_view(self, event: dict) -> dict:
        """已应用变更的公开视图（GET/首提/重放同形）：六键固定序
        （target=chain-policy 时在 target 后插入 asset_id 共七键），seq
        为事件落盘序号。"""
        details = event["details"]
        view = {
            "change_id": details["change_id"],
            "target": details["target"],
        }
        if "asset_id" in details:
            view["asset_id"] = details["asset_id"]
        view["before"] = self._clone_config(details["before"])
        view["after"] = self._clone_config(details["after"])
        view["approval_request_id"] = details["approval_request_id"]
        view["seq"] = event["seq"]
        return view

    @staticmethod
    def _clone_config(value):
        if value is None:
            return None
        if isinstance(value, dict):
            return {k: WalletService._clone_config(v) for k, v in value.items()}
        if isinstance(value, list):
            return [WalletService._clone_config(v) for v in value]
        return value

    def get_policy_change(self, wallet_id: str, change_id: str) -> dict:
        """GET /v1/wallets/{id}/policy-changes/{change_id}：返回已应用视图；
        钱包/change_id 未知 404，标识非法 400。"""
        if not isinstance(change_id, str) or not ROTATION_ID_RE.match(
            change_id
        ):
            raise ServiceError(
                400, "change_id must match [A-Za-z0-9_-]{1,128}"
            )
        try:
            with self._wallet_lock(wallet_id):
                self._heal_wallet(wallet_id)
                self._get_wallet_or_404(wallet_id)
                event = self._audit.find_event_by_request(
                    wallet_id,
                    audit.TYPE_POLICY_CHANGE_APPLIED,
                    change_id,
                )
        except CorruptDataError:
            raise
        except ValueError:
            raise ServiceError(400, "invalid wallet_id")
        if event is None:
            raise ServiceError(
                404, f"policy change {change_id!r} not found"
            )
        return self._policy_change_view(event)

    def post_policy_change(
        self,
        wallet_id: str,
        change_id: object,
        target: object,
        before: object,
        after: object,
        approval_request_id: object,
        asset_id: object = None,
    ) -> tuple[int, dict]:
        """POST /v1/wallets/{id}/policy-changes —— 高风险配置双人变更的
        统一入口。返回 (201|200, 视图)。

        顺序（全部在每钱包跨进程事务锁内，heal/存在性/冻结之后）：

        1. 字段 400：change_id/approval_request_id 安全标识、target 八类、
           asset_id 仅 chain-policy 必填（安全标识，其余目标夹带一律
           400）、before（可空目标允许 null）/after（恒非空）配置形状；
           chain-policy 目标资产 frozen 时新变更与重放一律 409（在幂等
           判定之前）；
        2. 幂等优先：同 change_id 已提交，同参（target/asset_id/before/
           after/approval_request_id 全等）重放 200 同体不复查现场、不记
           事件；异参（含换资产）409；
        3. 审批单未知 404；锁内懒过期后 message 须逐字为四键（chain-policy
           五键，target 后插入 asset_id）ASCII 紧凑 JSON，状态 approved
           且两位不同审批人，否则 409（零副作用）；
        4. before 必须等于当前配置（锁内折叠；chain-policy 只比较该资产
           当前策略，其他资产的变动不影响），漂移 409；
        5. 比较通过后写配置并**原子**追加唯一 policy_change_applied 事件：
           audit-sourced 目标只追加事件；文件型目标先落提交前意图，事件在
           则前滚、不在则回滚。首提 201，并发/重启只有一个首提。
        """
        try:
            with self._wallet_lock(wallet_id):
                self._heal_wallet(wallet_id)
                # 404 优先于 400：钱包存在性先于一切参数校验
                self._get_wallet_or_404(wallet_id)
                self._assert_wallet_active_locked(wallet_id)

                # --- 1. 字段校验（400）---
                if not isinstance(change_id, str) or not ROTATION_ID_RE.match(
                    change_id
                ):
                    raise ServiceError(
                        400,
                        "change_id must match [A-Za-z0-9_-]{1,128}",
                    )
                if not isinstance(target, str) or target not in \
                        CHANGE_CONTROL_TARGETS:
                    raise ServiceError(
                        400,
                        "target must be one of "
                        + ", ".join(CHANGE_CONTROL_TARGETS),
                    )
                if (
                    not isinstance(approval_request_id, str)
                    or not ROTATION_ID_RE.match(approval_request_id)
                ):
                    raise ServiceError(
                        400,
                        "approval_request_id must match "
                        "[A-Za-z0-9_-]{1,128}",
                    )
                if target == "chain-policy":
                    # chain-policy 是资产粒度目标：asset_id 必填且沿用资产
                    # 标识规则（不要求已有余额记录）。
                    self._validate_asset_id(asset_id)
                elif asset_id is not None:
                    # 原七类目标格式保持兼容：夹带 asset_id 一律 400。
                    raise ServiceError(
                        400,
                        "asset_id is only allowed for target chain-policy",
                    )
                if target == "chain-policy":
                    # 目标资产冻结闸门：frozen 时新变更与重放一律 409 且零
                    # 副作用（在幂等判定之前，与钱包冻结闸门同序）。
                    self._assert_asset_active_locked(wallet_id, asset_id)
                allow_null = target in _CHANGE_NULLABLE_TARGETS
                if before is not None or not allow_null:
                    before_view = self._normalize_change_config(target, before)
                else:
                    before_view = None
                after_view = self._normalize_change_config(target, after)

                # --- 2. 幂等优先（同 change_id）---
                committed = self._audit.find_event_by_request(
                    wallet_id,
                    audit.TYPE_POLICY_CHANGE_APPLIED,
                    change_id,
                )
                if committed is not None:
                    saved = committed["details"]
                    if (
                        saved["target"] == target
                        and saved.get("asset_id") == asset_id
                        and saved["before"] == before_view
                        and saved["after"] == after_view
                        and saved["approval_request_id"]
                        == approval_request_id
                    ):
                        return 200, self._policy_change_view(committed)
                    raise ServiceError(
                        409,
                        f"policy change {change_id!r} already exists with "
                        "different parameters",
                    )

                # --- 3. 审批门控（404 未知单 / 409 其余）---
                approval = self._store.get_request(
                    wallet_id, approval_request_id
                )
                if approval is None:
                    raise ServiceError(
                        404,
                        f"approval request {approval_request_id!r} not found",
                    )
                approval = self._expire_if_needed(wallet_id, approval)
                # 双人变更门控要求审批单"已批准且未过期"：approved 是终态、
                # 不会被懒过期翻转，故除 pending 的懒过期外还要显式按 t1 判定
                # 已到点的 approved 单一律 409。
                if datetime.now(timezone.utc) >= _parse_iso(approval["t1"]):
                    raise ServiceError(
                        409,
                        f"approval request {approval_request_id!r} has expired",
                    )
                message_payload = {
                    "change_id": change_id,
                    "target": target,
                    "asset_id": asset_id,
                    "before": before_view,
                    "after": after_view,
                }
                expected_message = self._policy_change_message(message_payload)
                if approval["message"] != expected_message:
                    raise ServiceError(
                        409,
                        "approval request message does not match this "
                        "policy change",
                    )
                if approval["state"] != "approved":
                    raise ServiceError(
                        409,
                        f"approval request {approval_request_id!r} is "
                        f"{approval['state']}, not approved",
                    )
                if len(set(approval["approvers"])) < 2:
                    raise ServiceError(
                        409,
                        "policy change requires two distinct approvers",
                    )

                # --- 4. before 漂移检查（锁内当前配置）---
                current = self._current_config_view_locked(
                    wallet_id, target, asset_id
                )
                if current != before_view:
                    raise ServiceError(
                        409,
                        "policy change before-config does not match the "
                        "current configuration",
                    )

                # --- 5. 应用：写配置 + 唯一提交事件，原子 ---
                event = self._apply_policy_change_locked(
                    wallet_id,
                    change_id,
                    target,
                    before_view,
                    after_view,
                    approval_request_id,
                    asset_id=asset_id,
                )
        except CorruptDataError:
            raise
        except ValueError:
            # wallet_id 含非法字符（构造锁路径时抛出）
            raise ServiceError(400, "invalid wallet_id")
        return 201, self._policy_change_view(event)

    def _apply_policy_change_locked(
        self,
        wallet_id: str,
        change_id: str,
        target: str,
        before_view,
        after_view: dict,
        approval_request_id: str,
        asset_id: str | None = None,
    ) -> dict:
        """在已持有钱包事务锁、全部校验通过后写配置并原子追加唯一
        policy_change_applied 事件，返回含 seq 的落盘事件（调用方持锁）。

        文件型目标（approval-policy/transaction-policy）先写提交前意图，
        事件是唯一提交点（崩溃由 _recover_policy_changes 前滚/回滚）；
        audit-sourced 目标（含 chain-policy）只追加事件。"""
        details = {
            "change_id": change_id,
            "target": target,
        }
        if target == "chain-policy":
            details["asset_id"] = asset_id
        details["before"] = before_view
        details["after"] = after_view
        details["approval_request_id"] = approval_request_id
        file_backed = target in ("approval-policy", "transaction-policy")
        if file_backed:
            if target == "approval-policy":
                previous_file = self._store.get_policy(wallet_id)
                stored_after = {
                    "wallet_id": wallet_id,
                    "required_approvals": after_view["required_approvals"],
                    "timeout_seconds": after_view["timeout_seconds"],
                }

                def _write_file():
                    self._store.save_policy(wallet_id, stored_after)
            else:
                previous_file = self._store.get_transaction_policy(wallet_id)
                stored_after = {
                    "mode": after_view["mode"],
                    "max_delta": after_view["max_delta"],
                    "allowed_assets": list(after_view["allowed_assets"]),
                }

                def _write_file():
                    self._store.save_transaction_policy(
                        wallet_id, stored_after
                    )

            self._store.save_policy_change_intent(
                wallet_id,
                change_id,
                {
                    "target": target,
                    "previous_file": previous_file,
                    "after_view": after_view,
                },
            )
            _write_file()
            try:
                event = self._emit(
                    wallet_id,
                    self._audit_event(
                        audit.TYPE_POLICY_CHANGE_APPLIED,
                        request_id=change_id,
                        actor_id=approval_request_id,
                        reason=None,
                        details=details,
                    ),
                )
            except BaseException:
                # 同进程内事件落盘失败：回滚策略文件并清除意图。
                if previous_file is None:
                    if target == "approval-policy":
                        self._store.delete_policy(wallet_id)
                    else:
                        self._store.delete_transaction_policy(wallet_id)
                else:
                    _write_file_restore = (
                        self._store.save_policy
                        if target == "approval-policy"
                        else self._store.save_transaction_policy
                    )
                    _write_file_restore(wallet_id, previous_file)
                self._store.delete_policy_change_intent(wallet_id, change_id)
                raise
            self._store.delete_policy_change_intent(wallet_id, change_id)
            return event

        # audit-sourced：事件即唯一状态承载，无其他状态文件。
        return self._emit(
            wallet_id,
            self._audit_event(
                audit.TYPE_POLICY_CHANGE_APPLIED,
                request_id=change_id,
                actor_id=approval_request_id,
                reason=None,
                details=details,
            ),
        )

    def _recover_policy_changes(self, wallet_id: str) -> None:
        """按 policy_change_applied 事件（崩溃）恢复高风险配置现场。

        - 逐条严格校验事件形状与提交时审批门控（畸形 fail-closed）；
        - 文件型目标：先按提交前意图前滚/回滚崩溃窗口，再把策略文件对账到
          legacy 写入事件与 policy_change_applied 按 seq 折叠的最后值
          （仅在存在该目标的变更事件时纠偏，纯 legacy 现场行为不变）；
        - audit-sourced 目标纯由事件折叠，无需写状态。

        恢复不新增事件、不改 seq。调用方须持钱包事务锁。"""
        changes = self._policy_change_events_strict(wallet_id)

        # --- 崩溃窗口：残留意图按事件是否落盘前滚/回滚 ---
        intents = self._store.get_policy_change_intents(wallet_id)
        for change_id, intent in intents.items():
            if not isinstance(intent, dict) or set(intent) != {
                "target",
                "previous_file",
                "after_view",
            }:
                raise RecoveryError(
                    f"wallet {wallet_id!r} policy change intent "
                    f"{change_id!r} is malformed"
                )
            target = intent.get("target")
            if target not in ("approval-policy", "transaction-policy"):
                raise RecoveryError(
                    f"wallet {wallet_id!r} policy change intent "
                    f"{change_id!r} has a bad target"
                )
            committed = self._audit.find_event_by_request(
                wallet_id, audit.TYPE_POLICY_CHANGE_APPLIED, change_id
            )
            previous_file = intent.get("previous_file")
            after_view = intent.get("after_view")
            if committed is not None:
                # 事件已落盘：前滚为 after（文件可能停留在旧值/半写）。
                stored_after = self._stored_file_policy(
                    wallet_id, target, after_view
                )
                self._save_file_policy(wallet_id, target, stored_after)
            else:
                # 事件未落盘：整体回滚到变更前文件（无则删除）。
                if previous_file is None:
                    self._delete_file_policy(wallet_id, target)
                else:
                    self._save_file_policy(wallet_id, target, previous_file)
            self._store.delete_policy_change_intent(wallet_id, change_id)

        # --- 文件型配置与审计提交点对账（仅有该目标变更事件时）---
        file_targets = ("approval-policy", "transaction-policy")
        for target in file_targets:
            target_changes = [
                e for e in changes if e["details"]["target"] == target
            ]
            if not target_changes:
                continue
            folded = self._fold_file_policy_from_audit(wallet_id, target)
            on_disk = (
                self._store.get_policy(wallet_id)
                if target == "approval-policy"
                else self._store.get_transaction_policy(wallet_id)
            )
            if folded is None:
                if on_disk is not None:
                    self._delete_file_policy(wallet_id, target)
            elif on_disk != folded:
                self._save_file_policy(wallet_id, target, folded)

    def _stored_file_policy(
        self, wallet_id: str, target: str, view: dict
    ) -> dict:
        if target == "approval-policy":
            return {
                "wallet_id": wallet_id,
                "required_approvals": view["required_approvals"],
                "timeout_seconds": view["timeout_seconds"],
            }
        return {
            "mode": view["mode"],
            "max_delta": view["max_delta"],
            "allowed_assets": list(view["allowed_assets"]),
        }

    def _save_file_policy(self, wallet_id: str, target: str, stored) -> None:
        if target == "approval-policy":
            self._store.save_policy(wallet_id, stored)
        else:
            self._store.save_transaction_policy(wallet_id, stored)

    def _delete_file_policy(self, wallet_id: str, target: str) -> None:
        if target == "approval-policy":
            self._store.delete_policy(wallet_id)
        else:
            self._store.delete_transaction_policy(wallet_id)

    def _fold_file_policy_from_audit(
        self, wallet_id: str, target: str
    ):
        """按 seq 折叠文件型配置的 legacy 写入事件与 policy_change_applied
        事件，返回最后一次写入的**存储形**（含 approval-policy 的
        wallet_id）；从无写入返回 None。仅供恢复对账。"""
        snapshots: list[tuple[int, object]] = []
        if target == "approval-policy":
            for event in self._audit.events_by_type(
                wallet_id, audit.TYPE_POLICY_UPDATED
            ):
                details = event.get("details")
                required = details.get("required_approvals") if isinstance(
                    details, dict
                ) else None
                timeout = details.get("timeout_seconds") if isinstance(
                    details, dict
                ) else None
                if (
                    not isinstance(details, dict)
                    or not isinstance(required, int)
                    or isinstance(required, bool)
                    or required not in ALLOWED_REQUIRED_APPROVALS
                    or not isinstance(timeout, int)
                    or isinstance(timeout, bool)
                    or timeout <= 0
                ):
                    raise RecoveryError(
                        f"wallet {wallet_id!r} has a malformed policy_updated"
                    )
                snapshots.append(
                    (
                        event["seq"],
                        {
                            "required_approvals": required,
                            "timeout_seconds": timeout,
                        },
                    )
                )
        else:
            for event in self._audit.events_by_type(
                wallet_id, audit.TYPE_TRANSACTION_POLICY_UPDATED
            ):
                details = event.get("details")
                if (
                    not isinstance(details, dict)
                    or details.get("mode") not in TRANSACTION_POLICY_MODES
                    or not isinstance(details.get("max_delta"), int)
                    or isinstance(details.get("max_delta"), bool)
                    or details["max_delta"] <= 0
                    or not isinstance(details.get("allowed_assets"), list)
                    or not details["allowed_assets"]
                    or not all(
                        isinstance(a, str) and ROTATION_ID_RE.match(a)
                        for a in details["allowed_assets"]
                    )
                ):
                    raise RecoveryError(
                        f"wallet {wallet_id!r} has a malformed "
                        "transaction_policy_updated"
                    )
                snapshots.append(
                    (
                        event["seq"],
                        {
                            "mode": details["mode"],
                            "max_delta": details["max_delta"],
                            "allowed_assets": list(details["allowed_assets"]),
                        },
                    )
                )
        for event in self._policy_change_events_strict(wallet_id):
            if event["details"]["target"] == target:
                snapshots.append(
                    (event["seq"], event["details"]["after"])
                )
        if not snapshots:
            return None
        snapshots.sort(key=lambda item: item[0])
        view = snapshots[-1][1]
        return self._stored_file_policy(wallet_id, target, view)

    # ---- DKG 节点健康 ------------------------------------------------------

    @staticmethod
    def _normalize_node_state_value(value: object) -> dict:
        """校验并归一单个节点健康值：须为恰含 ``key``/``state`` 两键的对象，
        key 为 64 位小写 hex，state ∈ up|down|ban；非法抛 ServiceError(400)。

        返回值固定键序 key,state。"""
        if not isinstance(value, dict) or set(value) != {"key", "state"}:
            raise ServiceError(
                400, "each node value must contain exactly key and state"
            )
        key = value["key"]
        state = value["state"]
        if not _is_lower_hex_32(key):
            raise ServiceError(
                400, "node key must be 64 lowercase hex characters"
            )
        if state not in DKG_NODE_STATES:
            raise ServiceError(
                400,
                "node state must be one of " + ", ".join(DKG_NODE_STATES),
            )
        return {"key": key, "state": state}

    def _normalize_nodes_body(self, nodes: object) -> dict:
        """校验 PUT nodes 请求体 Q 的 nodes 表并归一。

        nodes 须为非空对象，键为安全标识且不重复（dict 天然唯一）；每值恰
        含 key(64 位小写 hex)/state(up|down|ban)。归一为按节点 ID 升序的
        表，每值键序 key,state。非法抛 ServiceError(400)。"""
        if not isinstance(nodes, dict) or not nodes:
            raise ServiceError(
                400, "nodes must be a non-empty object keyed by node id"
            )
        # 先确认键全为合法标识，再排序（混合类型键会让 sorted 抛
        # TypeError，必须在排序前拦住，统一落 400 而非 503）。
        for node_id in nodes:
            if not isinstance(node_id, str) or not ROTATION_ID_RE.match(
                node_id
            ):
                raise ServiceError(
                    400, "node id must match [A-Za-z0-9_-]{1,128}"
                )
        normalized: dict[str, dict] = {}
        for node_id in sorted(nodes):
            normalized[node_id] = self._normalize_node_state_value(
                nodes[node_id]
            )
        return normalized

    def _node_state_events_strict(self, wallet_id: str) -> list[dict]:
        """返回该钱包全部 node_state 事件（按 seq 升序），逐条严格校验。

        每条事件 request_id/actor_id/reason 必须为 null，且：

        - **外层七字段键序**必须为 README 落盘规范序
          （actor_id,at,details,reason,request_id,seq,type）；
        - details 恰含 ``nodes``（单键，规范序）；
        - ``nodes`` 非空、键为安全标识且按节点 ID **升序唯一**；
        - 每个节点值恰含 ``key``/``state`` 两键且**键序固定为
          key,state**：key 为 64 位小写 hex，state 为 up|down|ban。

        外层/details/nodes/条目的键序重排、形状或取值非法都是不可对账
        现场（RecoveryError，fail-closed），绝不静默忽略。纯只读，不分配
        seq。"""
        events = self._audit.events_by_type(wallet_id, audit.TYPE_NODE_STATE)
        for event in events:
            # 外层七字段键序：读取不重排外层（details 顶层单键亦无歧义），
            # 故现场键序即落盘键序；任何重排都是外部篡改。
            if list(event) != list(_AUDIT_OUTER_KEY_ORDER):
                raise RecoveryError(
                    f"wallet {wallet_id!r} has a node_state event whose "
                    "outer fields are out of the canonical order"
                )
            if (
                event.get("request_id") is not None
                or event.get("actor_id") is not None
                or event.get("reason") is not None
            ):
                raise RecoveryError(
                    f"wallet {wallet_id!r} has a node_state event with "
                    "request_id/actor/reason set"
                )
            details = event.get("details")
            if not isinstance(details, dict) or list(details) != ["nodes"]:
                raise RecoveryError(
                    f"wallet {wallet_id!r} has a malformed node_state event"
                )
            nodes = details["nodes"]
            if not isinstance(nodes, dict) or not nodes:
                raise RecoveryError(
                    f"wallet {wallet_id!r} has an empty or malformed "
                    "node_state nodes table"
                )
            # 排序前先确认键全为字符串（损坏现场可能含非字符串键，直接
            # sorted 会抛 TypeError 而绕过 fail-closed 包装）。
            if any(not isinstance(k, str) for k in nodes):
                raise RecoveryError(
                    f"wallet {wallet_id!r} node_state has a non-string "
                    "node id"
                )
            keys = list(nodes)
            if keys != sorted(keys) or len(set(keys)) != len(keys):
                raise RecoveryError(
                    f"wallet {wallet_id!r} node_state nodes are not in "
                    "strictly ascending order"
                )
            for node_id, entry in nodes.items():
                if not ROTATION_ID_RE.match(node_id):
                    raise RecoveryError(
                        f"wallet {wallet_id!r} node_state has a malformed "
                        "node id"
                    )
                if (
                    not isinstance(entry, dict)
                    or list(entry) != list(_NODE_STATE_ENTRY_KEY_ORDER)
                    or not _is_lower_hex_32(entry.get("key"))
                    or entry.get("state") not in DKG_NODE_STATES
                ):
                    raise RecoveryError(
                        f"wallet {wallet_id!r} node_state has a malformed "
                        f"entry for node {node_id!r}"
                    )
        return events

    def put_dkg_nodes(self, wallet_id: str, nodes: object) -> dict:
        """设置 DKG 节点健康表，请求/成功响应（200）同为 Q={"nodes": ...}。

        PUT 仅收 Q；nodes 非空、键为安全标识（归一为 ID 升序），每值恰含
        key(64 位小写 hex)/state(up|down|ban)；非法 400，钱包不存在 404，
        可首建。**同值不记事件**；仅当与当前表不同才记一条 node_state
        （request_id/actor_id/reason 为 null，details 即 Q）。健康表纯由
        审计事件持久化，不写状态文件。"""
        try:
            with self._wallet_lock(wallet_id):
                self._heal_wallet(wallet_id)
                # 404 优先于 400：锁内先判定钱包存在性，再校验请求体
                self._get_wallet_or_404(wallet_id)
                self._assert_wallet_active_locked(wallet_id)
                # 双人变更控制启用后受控 PUT 统一 409（零副作用）。
                self._assert_change_control_not_required_locked(wallet_id)
                normalized = self._normalize_nodes_body(nodes)
                body = {"nodes": normalized}
                current = self._health_table_folding_rejoins_locked(wallet_id)
                # 同值（归一后逐键相等）不记事件；首建或任何差异才记。
                # 比对的是**生效**健康表（已折叠其后的 rejoin 翻转）。
                if current != normalized:
                    self._emit(
                        wallet_id,
                        self._audit_event(
                            audit.TYPE_NODE_STATE,
                            details=body,
                        ),
                    )
        except CorruptDataError:
            raise
        except ValueError:
            # wallet_id 含非法字符（构造锁路径时抛出）
            raise ServiceError(400, "invalid wallet_id")
        return body

    def get_dkg_nodes(self, wallet_id: str) -> dict:
        """读取 DKG 节点健康表：已配置 200 返回 Q，未配置 404。

        返回的是**生效**健康表：最后一条 node_state 快照，再折叠其后已
        提交 node_rejoined 事件把对应节点置 up（rejoin 不另写快照）。
        损坏/矛盾事件 fail-closed（由 HTTP 边界转 503）。钱包不存在
        404。"""
        try:
            with self._wallet_lock(wallet_id):
                self._heal_wallet(wallet_id)
                # 404 优先：锁内先判定钱包存在，再判定健康表是否已配置
                self._get_wallet_or_404(wallet_id)
                nodes = self._health_table_folding_rejoins_locked(wallet_id)
        except CorruptDataError:
            raise
        except ValueError:
            raise ServiceError(400, "invalid wallet_id")
        if nodes is None:
            raise ServiceError(
                404, f"wallet {wallet_id!r} has no configured node health"
            )
        return {"nodes": nodes}

    @staticmethod
    def _dkg_failover_approval_message(
        dkg_id: str,
        round_no: int,
        action: str,
        node: object,
        replacement: object,
        key: object,
    ) -> str:
        """审批单 message 必须逐字一致的紧凑 JSON（键序固定）。

        形如 {"dkg_id":"D","round":R,"action":"A","node":N,
        "replacement":X,"key":K}，N/X/K 为字符串或 null。"""
        return json.dumps(
            {
                "dkg_id": dkg_id,
                "round": round_no,
                "action": action,
                "node": node,
                "replacement": replacement,
                "key": key,
            },
            ensure_ascii=False,
            separators=(",", ":"),
        )

    # ---- DKG 节点重新加入（rejoin）---------------------------------------

    #: rejoin 审批单 message / 事件 details V 的固定键序
    _REJOIN_VIEW_KEY_ORDER = (
        "rejoin_id",
        "dkg_id",
        "round",
        "node",
        "key",
        "state",
    )

    @staticmethod
    def _rejoin_approval_message(
        rejoin_id: str,
        dkg_id: str,
        round_no: int,
        node: str,
        key: str,
    ) -> str:
        """rejoin 审批单 message 必须逐字一致的紧凑 JSON（无空格、键序
        固定为 rejoin_id,dkg_id,round,node,key）。"""
        return json.dumps(
            {
                "rejoin_id": rejoin_id,
                "dkg_id": dkg_id,
                "round": round_no,
                "node": node,
                "key": key,
            },
            ensure_ascii=False,
            separators=(",", ":"),
        )

    def _rejoin_view(
        self,
        rejoin_id: str,
        dkg_id: str,
        round_no: int,
        node: str,
        key: str,
    ) -> dict:
        """rejoin 成功/重放响应体 V（键序固定，state 恒为 up）。"""
        return {
            "rejoin_id": rejoin_id,
            "dkg_id": dkg_id,
            "round": round_no,
            "node": node,
            "key": key,
            "state": "up",
        }

    def _rejoin_events_strict(self, wallet_id: str) -> list[dict]:
        """返回该钱包全部 node_rejoined 事件（按 seq 升序）并逐条严格校验
        **形状**（外层七字段键序、request_id==rejoin_id、actor_id 为安全
        标识、reason 为 null、details 恰为六键 V 且键序固定、各值合法）。

        这里只做与现场无关的形状校验；与事前健康表/DKG/审批单的语义复核
        在 :meth:`_reconcile_node_rejoins` 按事件 seq 完成。任何形状畸形
        都是不可对账现场（RecoveryError）。纯只读，不分配 seq。"""
        # 用 events_by_type 而非按 request_id 分组：后者会丢掉 request_id
        # 为 null/非字符串的畸形事件，必须让它们也进入严格校验而非被静默
        # 忽略。
        events = self._audit.events_by_type(
            wallet_id, audit.TYPE_NODE_REJOINED
        )
        seen: set[str] = set()
        for event in events:
            if list(event) != list(_AUDIT_OUTER_KEY_ORDER):
                raise RecoveryError(
                    f"wallet {wallet_id!r} has a node_rejoined event whose "
                    "outer fields are out of the canonical order"
                )
            rejoin_id = event.get("request_id")
            actor_id = event.get("actor_id")
            if (
                not isinstance(rejoin_id, str)
                or not ROTATION_ID_RE.match(rejoin_id)
            ):
                raise RecoveryError(
                    f"wallet {wallet_id!r} has a node_rejoined event with a "
                    "malformed rejoin_id"
                )
            if rejoin_id in seen:
                raise RecoveryError(
                    f"wallet {wallet_id!r} has multiple node_rejoined events "
                    f"for {rejoin_id!r}"
                )
            seen.add(rejoin_id)
            if not (
                isinstance(actor_id, str) and ROTATION_ID_RE.match(actor_id)
            ):
                raise RecoveryError(
                    f"wallet {wallet_id!r} node_rejoined {rejoin_id!r} has a "
                    "malformed approval_request_id"
                )
            if event.get("reason") is not None:
                raise RecoveryError(
                    f"wallet {wallet_id!r} node_rejoined {rejoin_id!r} has a "
                    "non-null reason"
                )
            details = event.get("details")
            if (
                not isinstance(details, dict)
                or list(details) != list(self._REJOIN_VIEW_KEY_ORDER)
            ):
                raise RecoveryError(
                    f"wallet {wallet_id!r} node_rejoined {rejoin_id!r} has "
                    "malformed details"
                )
            if details["rejoin_id"] != rejoin_id:
                raise RecoveryError(
                    f"wallet {wallet_id!r} node_rejoined {rejoin_id!r} "
                    "details rejoin_id disagrees with its request_id"
                )
            dkg_id = details["dkg_id"]
            node = details["node"]
            key = details["key"]
            round_no = details["round"]
            if not isinstance(dkg_id, str) or not ROTATION_ID_RE.match(dkg_id):
                raise RecoveryError(
                    f"wallet {wallet_id!r} node_rejoined {rejoin_id!r} has a "
                    "malformed dkg_id"
                )
            if not isinstance(node, str) or not ROTATION_ID_RE.match(node):
                raise RecoveryError(
                    f"wallet {wallet_id!r} node_rejoined {rejoin_id!r} has a "
                    "malformed node"
                )
            if not _is_lower_hex_32(key):
                raise RecoveryError(
                    f"wallet {wallet_id!r} node_rejoined {rejoin_id!r} has a "
                    "malformed key"
                )
            if (
                not isinstance(round_no, int)
                or isinstance(round_no, bool)
                or round_no < 1
            ):
                raise RecoveryError(
                    f"wallet {wallet_id!r} node_rejoined {rejoin_id!r} has a "
                    "malformed round"
                )
            if details["state"] != "up":
                raise RecoveryError(
                    f"wallet {wallet_id!r} node_rejoined {rejoin_id!r} has a "
                    "state other than up"
                )
        return events

    def _health_table_folding_rejoins_locked(self, wallet_id: str) -> Optional[dict]:
        """当前生效健康表：最后一条 node_state 快照，再按其**之后**提交的
        node_rejoined 事件把对应节点翻为 up（details.key 不变）。

        无任何健康快照返回 None。读取前先按事前健康表/DKG/审批单
        完整复核全部 rejoin 事件（矛盾即 RecoveryError）。调用方须持钱包
        锁。健康快照既包括 node_state 也包括变更控制下 target=nodes 的
        policy_change_applied（统一按 seq 折叠）。"""
        self._reconcile_node_rejoins(wallet_id)
        node_events = self._node_health_snapshot_events_locked(wallet_id)
        if not node_events:
            return None
        last_state_seq = node_events[-1]["seq"]
        table = {
            node_id: dict(entry)
            for node_id, entry in node_events[-1]["details"]["nodes"].items()
        }
        for event in self._rejoin_events_strict(wallet_id):
            if event["seq"] <= last_state_seq:
                continue
            node = event["details"]["node"]
            if node in table:
                table[node] = {"key": table[node]["key"], "state": "up"}
        return table

    def _reconcile_node_rejoins(self, wallet_id: str) -> None:
        """按 seq 严格复核全部 node_rejoined 事件（调用方须持钱包锁）。

        每条事件都以其**提交之前**的现场复核在线首提的全部前置：

        - 事前健康表（该事件 seq 之前最近 node_state 快照，仅折叠该快照
          之后、本事件之前的更早 rejoin 翻转）中 N 存在、key 与
          details.key 一致、state 为 down|ban；
        - 事前 DKG（seq 前缀重建）存在会话 dkg_id，当前轮恰为 round 且
          状态为 commit|share，N **不占用**该轮槽位（轮外待命节点）；
        - 同钱包审批单 actor_id 存在，message 逐字为按
          rejoin_id,dkg_id,round,node,key 序的紧凑 JSON，且状态为
          approved（其后推进为 signed 亦认可）。

        任一不满足、或同一 rejoin_id 重复提交，都是不可对账现场
        （RecoveryError，fail-closed，保留现场）。纯只读，不记事件、不改
        seq、不写状态。"""
        events = self._rejoin_events_strict(wallet_id)
        if not events:
            return
        # 事前健康表来自合并快照流（node_state 与变更控制下 target=nodes 的
        # policy_change_applied 统一按 seq），两类都先经严格形状校验。
        node_events = self._node_health_snapshot_events_locked(wallet_id)
        for event in events:
            seq = event["seq"]
            rejoin_id = event["request_id"]
            actor_id = event["actor_id"]
            d = event["details"]
            dkg_id = d["dkg_id"]
            round_no = d["round"]
            node = d["node"]
            key = d["key"]

            # --- 事前健康表 ---
            health = None
            snapshot_seq = 0
            for ne in node_events:
                if ne["seq"] < seq:
                    health = ne["details"]["nodes"]
                    snapshot_seq = ne["seq"]
            if health is None:
                raise RecoveryError(
                    f"wallet {wallet_id!r} node_rejoined {rejoin_id!r} has "
                    "no prior node_state snapshot"
                )
            # 折叠该快照**之后**、本事件之前的更早 rejoin 翻转：快照自身
            # 已权威反映其之前所有 rejoin，只叠加快照之后的翻转。
            folded = {n: dict(e) for n, e in health.items()}
            for earlier in events:
                eseq = earlier["seq"]
                if eseq >= seq:
                    break
                if eseq <= snapshot_seq:
                    continue
                en = earlier["details"]["node"]
                if en in folded:
                    folded[en] = {"key": folded[en]["key"], "state": "up"}
            entry = folded.get(node)
            if not isinstance(entry, dict):
                raise RecoveryError(
                    f"wallet {wallet_id!r} node_rejoined {rejoin_id!r} node "
                    f"{node!r} is absent from the prior health table"
                )
            if entry.get("key") != key:
                raise RecoveryError(
                    f"wallet {wallet_id!r} node_rejoined {rejoin_id!r} key "
                    "does not match the health table"
                )
            if entry.get("state") not in ("down", "ban"):
                raise RecoveryError(
                    f"wallet {wallet_id!r} node_rejoined {rejoin_id!r} node "
                    "is not down or banned in the prior health table"
                )

            # --- 事前 DKG 现场 ---
            sessions = self._dkg_sessions(wallet_id, until_seq=seq - 1)
            session = sessions.get(dkg_id)
            if session is None:
                raise RecoveryError(
                    f"wallet {wallet_id!r} node_rejoined {rejoin_id!r} refers "
                    f"to unknown dkg session {dkg_id!r}"
                )
            if session["current"] != round_no:
                raise RecoveryError(
                    f"wallet {wallet_id!r} node_rejoined {rejoin_id!r} round "
                    "is not the current dkg round"
                )
            current_round = session["rounds"][round_no]
            if current_round["state"] not in ("commit", "share"):
                raise RecoveryError(
                    f"wallet {wallet_id!r} node_rejoined {rejoin_id!r} round "
                    "is not in the commit/share stage"
                )
            node_ids = [n for n, _ in current_round["nodes"]]
            if node in node_ids:
                raise RecoveryError(
                    f"wallet {wallet_id!r} node_rejoined {rejoin_id!r} node "
                    "already occupies a slot in the round"
                )

            # --- 审批单复核（同钱包、approved、message 逐字一致）---
            try:
                approval = self._store.get_request(wallet_id, actor_id)
            except CorruptDataError:
                raise
            except ValueError as exc:
                raise RecoveryError(
                    f"wallet {wallet_id!r} node_rejoined {rejoin_id!r} "
                    "approval record is unreadable"
                ) from exc
            if not isinstance(approval, dict):
                raise RecoveryError(
                    f"wallet {wallet_id!r} node_rejoined {rejoin_id!r} refers "
                    "to an unknown approval request"
                )
            expected_message = self._rejoin_approval_message(
                rejoin_id, dkg_id, round_no, node, key
            )
            if approval.get("message") != expected_message:
                raise RecoveryError(
                    f"wallet {wallet_id!r} node_rejoined {rejoin_id!r} "
                    "approval message does not match"
                )
            # 提交时必为 approved；其后该审批单只能停留 approved 或经
            # /sign 推进为 signed（pending 才可能转 rejected/expired），
            # 故这两者都证明提交时刻已批准。
            if approval.get("state") not in ("approved", "signed"):
                raise RecoveryError(
                    f"wallet {wallet_id!r} node_rejoined {rejoin_id!r} "
                    "approval request is not approved"
                )

    def post_node_rejoin(
        self,
        wallet_id: str,
        node: object,
        rejoin_id: object,
        dkg_id: object,
        round_no: object,
        key: object,
        approval_request_id: object,
    ) -> tuple[int, dict]:
        """故障节点重新加入，返回 (HTTP 状态码, 视图 V)。

        请求体恰含 rejoin_id,dkg_id,round,key,approval_request_id 五键
        （HTTP 边界拦键集）：rejoin_id/dkg_id/node/approval_request_id 为
        安全标识，key 为 64 位小写 hex，round 为非布尔正整数；键集/类型/
        值错 400；钱包/DKG/节点未知 404。

        首提须 N 当前 down|ban 且 key 与健康表一致、round 恰为 DKG 当前
        commit|share 轮且 N 不占用该轮槽位（轮外待命节点）、审批单为同
        钱包 approved 且 message 逐字为按
        rejoin_id,dkg_id,round,node,key 序的紧凑 JSON；
        否则 409 且现场不变。成功把 N 置 up，201 返回 V。同 rejoin_id 同
        参重放 200 同 V、异参 409。node_rejoined 是唯一提交点
        （request_id=rejoin_id、actor_id=approval_request_id、
        reason=null、details=V）；跨进程并发只有一个 201。
        """
        try:
            with self._wallet_lock(wallet_id):
                self._heal_wallet(wallet_id)
                # 404 优先于 400：存在性在锁内、heal 之后先判定
                self._get_wallet_or_404(wallet_id)
                self._assert_wallet_active_locked(wallet_id)
                # 持锁访问先严格复核 node_state / node_rejoined / DKG 现场：
                # 矛盾现场 fail-closed（503），优先于参数 400/404 判定。
                self._reconcile_node_rejoins(wallet_id)
                # 类型/取值校验（400）
                self._validate_dkg_node(node)
                if not isinstance(rejoin_id, str) or not ROTATION_ID_RE.match(
                    rejoin_id
                ):
                    raise ServiceError(
                        400,
                        "rejoin_id must match [A-Za-z0-9_-]{1,128}",
                    )
                self._validate_dkg_id(dkg_id)
                if (
                    not isinstance(round_no, int)
                    or isinstance(round_no, bool)
                    or round_no < 1
                ):
                    raise ServiceError(
                        400, "round must be a positive integer"
                    )
                if not _is_lower_hex_32(key):
                    raise ServiceError(
                        400, "key must be 64 lowercase hex characters"
                    )
                if (
                    not isinstance(approval_request_id, str)
                    or not ROTATION_ID_RE.match(approval_request_id)
                ):
                    raise ServiceError(
                        400,
                        "approval_request_id must match "
                        "[A-Za-z0-9_-]{1,128}",
                    )

                sessions = self._build_dkg_sessions(wallet_id, None)
                # 幂等优先于 404/状态判定：已提交的同 rejoin_id 重放。
                committed_groups = self._audit.node_rejoined_events(
                    wallet_id
                ).get(rejoin_id)
                if committed_groups:
                    if len(committed_groups) != 1:
                        raise RecoveryError(
                            f"wallet {wallet_id!r} has multiple "
                            f"node_rejoined events for {rejoin_id!r}"
                        )
                    saved = committed_groups[0]["details"]
                    if (
                        saved["dkg_id"] == dkg_id
                        and saved["round"] == round_no
                        and saved["node"] == node
                        and saved["key"] == key
                        and committed_groups[0]["actor_id"]
                        == approval_request_id
                    ):
                        # 同参（含审批单标识）重放：200 同 V，不复查现状
                        return 200, dict(saved)
                    raise ServiceError(
                        409,
                        f"rejoin {rejoin_id!r} already exists with different "
                        "parameters",
                    )

                # 404：DKG 会话未知 / 节点不在健康表
                session = sessions.get(dkg_id)
                if session is None:
                    raise ServiceError(
                        404, f"dkg session {dkg_id!r} not found"
                    )
                # 当前**生效**健康表：最新 node_state 快照折叠其后已提交的
                # rejoin 翻转（rejoin 只改 state、不改成员，故成员判定与
                # 原表一致）。
                folded = self._health_table_folding_rejoins_locked(wallet_id)
                if folded is None or node not in folded:
                    raise ServiceError(
                        404,
                        f"node {node!r} not found in the node health table",
                    )

                # 首提前置：生效健康表中 N down|ban 且 key 一致。
                entry = folded[node]
                if entry["state"] not in ("down", "ban"):
                    raise ServiceError(
                        409,
                        f"node {node!r} is not down or banned",
                    )
                if entry["key"] != key:
                    raise ServiceError(
                        409,
                        "key does not match the node health table",
                    )

                # round 须为当前 commit|share 轮，且 N 不占槽位。
                current = session["current"]
                if round_no != current:
                    raise ServiceError(
                        409,
                        f"round must be the current round {current}",
                    )
                current_round = session["rounds"][current]
                if current_round["state"] not in ("commit", "share"):
                    raise ServiceError(
                        409,
                        "rejoin requires the current round to be in the "
                        "commit or share stage",
                    )
                node_ids = [n for n, _ in current_round["nodes"]]
                if node in node_ids:
                    # rejoin 的 N 是当前轮之外的待命故障节点：已占用槽位
                    # 的在用节点不能"重新加入"。
                    raise ServiceError(
                        409,
                        f"node {node!r} already occupies a slot in the "
                        "current round",
                    )

                # 审批门控：同钱包既有 approved 审批单，message 逐字一致。
                # 按既有契约懒过期（可能原子记一次 request_expired）。
                approval = self._store.get_request(
                    wallet_id, approval_request_id
                )
                if approval is None:
                    raise ServiceError(
                        409,
                        f"approval request {approval_request_id!r} not found",
                    )
                approval = self._expire_if_needed(wallet_id, approval)
                expected_message = self._rejoin_approval_message(
                    rejoin_id, dkg_id, round_no, node, key
                )
                if approval["message"] != expected_message:
                    raise ServiceError(
                        409,
                        "approval request message does not match this rejoin",
                    )
                if approval["state"] != "approved":
                    raise ServiceError(
                        409,
                        f"approval request {approval_request_id!r} is "
                        f"{approval['state']}, not approved",
                    )

                # node_rejoined 是唯一提交点：在跨进程事务锁内追加事件，
                # 事件之外不写任何健康状态文件；当前健康表由"最后快照 +
                # 其后 rejoin 翻转"在读取时重建。
                view = self._rejoin_view(
                    rejoin_id, dkg_id, round_no, node, key
                )
                self._emit(
                    wallet_id,
                    self._audit_event(
                        audit.TYPE_NODE_REJOINED,
                        request_id=rejoin_id,
                        actor_id=approval_request_id,
                        reason=None,
                        details=view,
                    ),
                )
                return 201, view
        except CorruptDataError:
            raise
        except ValueError:
            # wallet_id 含非法字符（构造锁路径时抛出）
            raise ServiceError(400, "invalid wallet_id")

    # ---- DKG 复职节点份额槽位绑定（share-bind）----------------------------

    #: share-bind 审批单 message / 事件 details V 的固定键序
    _SHARE_BIND_VIEW_KEY_ORDER = ("id", "node", "slot", "share_id")

    @staticmethod
    def _share_bind_approval_message(
        bind_id: str,
        rotation_id: str,
        dkg_id: str,
        round_no: int,
        node: str,
        slot: int,
    ) -> str:
        """share-bind 审批单 message 必须逐字一致的紧凑 JSON（无空格、键序
        固定为 id,rotation,dkg,round,node,slot——即请求体去掉
        approval_request_id）。"""
        return json.dumps(
            {
                "id": bind_id,
                "rotation": rotation_id,
                "dkg": dkg_id,
                "round": round_no,
                "node": node,
                "slot": slot,
            },
            ensure_ascii=False,
            separators=(",", ":"),
        )

    def _share_bind_view(
        self, bind_id: str, node: str, slot: int, share_id: str
    ) -> dict:
        """share-bind 成功/重放响应体 V（键序固定 id,node,slot,share_id）。"""
        return {
            "id": bind_id,
            "node": node,
            "slot": slot,
            "share_id": share_id,
        }

    def _share_bind_events_strict(self, wallet_id: str) -> list[dict]:
        """返回该钱包全部 share_participant_reinstated 事件（按 seq 升序）并
        逐条严格校验**形状**（外层七字段键序、request_id==id、actor_id 为
        安全标识、reason 为 null、details 恰为四键 V 且键序固定、各值合法）。

        这里只做与现场无关的形状校验；与事前轮换/DKG/健康表/审批单/槽位占用
        的语义复核在 :meth:`_reconcile_share_bindings` 按事件 seq 完成。任何
        形状畸形都是不可对账现场（RecoveryError）。纯只读，不分配 seq。"""
        events = self._audit.events_by_type(
            wallet_id, audit.TYPE_SHARE_PARTICIPANT_REINSTATED
        )
        seen: set[str] = set()
        for event in events:
            if list(event) != list(_AUDIT_OUTER_KEY_ORDER):
                raise RecoveryError(
                    f"wallet {wallet_id!r} has a share_participant_reinstated "
                    "event whose outer fields are out of the canonical order"
                )
            bind_id = event.get("request_id")
            actor_id = event.get("actor_id")
            if (
                not isinstance(bind_id, str)
                or not ROTATION_ID_RE.match(bind_id)
            ):
                raise RecoveryError(
                    f"wallet {wallet_id!r} has a share_participant_reinstated "
                    "event with a malformed id"
                )
            if bind_id in seen:
                raise RecoveryError(
                    f"wallet {wallet_id!r} has multiple "
                    f"share_participant_reinstated events for {bind_id!r}"
                )
            seen.add(bind_id)
            if not (
                isinstance(actor_id, str) and ROTATION_ID_RE.match(actor_id)
            ):
                raise RecoveryError(
                    f"wallet {wallet_id!r} share-bind {bind_id!r} has a "
                    "malformed approval_request_id"
                )
            if event.get("reason") is not None:
                raise RecoveryError(
                    f"wallet {wallet_id!r} share-bind {bind_id!r} has a "
                    "non-null reason"
                )
            details = event.get("details")
            if (
                not isinstance(details, dict)
                or list(details) != list(self._SHARE_BIND_VIEW_KEY_ORDER)
            ):
                raise RecoveryError(
                    f"wallet {wallet_id!r} share-bind {bind_id!r} has "
                    "malformed details"
                )
            if details["id"] != bind_id:
                raise RecoveryError(
                    f"wallet {wallet_id!r} share-bind {bind_id!r} details id "
                    "disagrees with its request_id"
                )
            node = details["node"]
            slot = details["slot"]
            share_id = details["share_id"]
            if not isinstance(node, str) or not ROTATION_ID_RE.match(node):
                raise RecoveryError(
                    f"wallet {wallet_id!r} share-bind {bind_id!r} has a "
                    "malformed node"
                )
            if (
                not isinstance(slot, int)
                or isinstance(slot, bool)
                or slot not in (1, 2)
            ):
                raise RecoveryError(
                    f"wallet {wallet_id!r} share-bind {bind_id!r} has a "
                    "malformed slot"
                )
            if not isinstance(share_id, str) or not _SAFE_SHARE_ID.match(
                share_id
            ):
                raise RecoveryError(
                    f"wallet {wallet_id!r} share-bind {bind_id!r} has a "
                    "malformed share_id"
                )
        return events

    def _share_binding_for_share_locked(
        self, wallet_id: str, share_id: str
    ) -> Optional[dict]:
        """份额 id 对应的绑定 V（不要求当前在用），无绑定返回 None。

        份额 id 全局唯一（``<rotation>-share-<slot>``），绑定随份额身份
        存在：即使其后又有轮换把该份额轮换出在用集合，**冻结了该份额的
        signed 会话**重放仍须沿用绑定的三键体。读取前先严格复核全部绑定
        事件（矛盾即 RecoveryError）。调用方须持钱包锁。"""
        self._reconcile_share_bindings(wallet_id)
        for event in self._share_bind_events_strict(wallet_id):
            if event["details"]["share_id"] == share_id:
                return dict(event["details"])
        return None

    def _bound_slot_occupied_locked(
        self, wallet_id: str, share_id: str
    ) -> bool:
        """该轮换槽位（share_id）是否已被更早的绑定事件占用（调用方须持
        钱包锁）。

        槽位按轮换份额 id 判定：每个轮换的 share_ids 全局唯一
        （``<rotation>-share-<slot>``），故同一槽位被占用当且仅当已存在
        一条 share_id 相同的已提交绑定事件。"""
        return any(
            event["details"]["share_id"] == share_id
            for event in self._share_bind_events_strict(wallet_id)
        )

    @staticmethod
    def _decode_share_bind_message(message: object) -> Optional[dict]:
        """把审批单 message 解析为 share-bind 的六字段 B 去 approval。

        仅当 message 是逐字规范的紧凑 JSON（恰含
        id,rotation,dkg,round,node,slot、各值类型/取值合法）时返回该 dict；
        形状不符或与规范紧凑形有任何差异（空格、键序、额外键）一律
        返回 None。"""
        if not isinstance(message, str):
            return None
        try:
            parsed = json.loads(message)
        except ValueError:
            return None
        if not isinstance(parsed, dict) or set(parsed) != {
            "id",
            "rotation",
            "dkg",
            "round",
            "node",
            "slot",
        }:
            return None
        for key in ("id", "rotation", "dkg", "node"):
            if not isinstance(parsed[key], str) or not ROTATION_ID_RE.match(
                parsed[key]
            ):
                return None
        round_no = parsed["round"]
        if (
            not isinstance(round_no, int)
            or isinstance(round_no, bool)
            or round_no < 1
        ):
            return None
        slot = parsed["slot"]
        if not isinstance(slot, int) or isinstance(slot, bool) or slot not in (
            1,
            2,
        ):
            return None
        # 按**固定键序** id,rotation,dkg,round,node,slot 重新紧凑序列化后
        # 逐字比较：重排键序（解析保留源序，不能直接重 dump parsed）或任何
        # 空白差异都不接受。
        canonical = json.dumps(
            {
                "id": parsed["id"],
                "rotation": parsed["rotation"],
                "dkg": parsed["dkg"],
                "round": parsed["round"],
                "node": parsed["node"],
                "slot": parsed["slot"],
            },
            ensure_ascii=False,
            separators=(",", ":"),
        )
        if message != canonical:
            return None
        return parsed

    def _reconcile_share_bindings(self, wallet_id: str) -> None:
        """按 seq 严格复核全部 share_participant_reinstated 事件（调用方须
        持钱包锁）。

        每条事件都以其**提交之前**的现场复核在线首提的全部前置。事件
        details 只存 V={id,node,slot,share_id}；rotation/dkg/round 不落在
        details 中，而由 actor_id 所指同钱包审批单的 message（B 去
        approval 的紧凑 JSON）逐字锚定，故恢复先取审批单并解析 message：

        - 审批单存在，message 逐字为按 id,rotation,dkg,round,node,slot 序
          的紧凑 JSON 且 id/node/slot 与 details 一致，状态 approved
          （其后推进为 signed 亦认可）；
        - 轮换 rotation 在事件之前已 prepared 且尚未激活；
        - details.share_id 恰为事件之前当前在用两份份额按槽位（slot-1）的
          份额（由轮换激活时间线确定）；
        - 事前 DKG（seq 前缀重建）存在会话 dkg，当前轮恰为 round 且状态为
          done，创建该轮的故障派生是 replacement=node 的 reinstate，node
          在该轮节点中；
        - node 在事前生效健康表（最近 node_state 快照折叠其间更早 rejoin
          翻转）中为 up；
        - 同一槽位在事件之前未被仍占用当前在用份额的更早绑定占用。

        同一绑定 id 重复提交或任何矛盾都是不可对账现场（RecoveryError，
        fail-closed，保留现场）。纯只读，不记事件、不改 seq、不写状态。"""
        events = self._share_bind_events_strict(wallet_id)
        if not events:
            return
        node_events = self._node_health_snapshot_events_locked(wallet_id)
        rejoin_events = self._rejoin_events_strict(wallet_id)
        activated = self._audit.activated_rotation_events(wallet_id)
        prepared_events = self._audit.events_by_type(
            wallet_id, audit.TYPE_SHARE_ROTATION_PREPARED
        )
        for event in events:
            seq = event["seq"]
            actor_id = event["actor_id"]
            d = event["details"]
            bind_id = d["id"]
            node = d["node"]
            slot = d["slot"]
            share_id = d["share_id"]

            # --- 审批单复核（rotation/dkg/round 由其 message 锚定）---
            try:
                approval = self._store.get_request(wallet_id, actor_id)
            except CorruptDataError:
                raise
            except ValueError as exc:
                raise RecoveryError(
                    f"wallet {wallet_id!r} share-bind {bind_id!r} approval "
                    "record is unreadable"
                ) from exc
            if not isinstance(approval, dict):
                raise RecoveryError(
                    f"wallet {wallet_id!r} share-bind {bind_id!r} refers to "
                    "an unknown approval request"
                )
            message_body = self._decode_share_bind_message(
                approval.get("message")
            )
            if message_body is None:
                raise RecoveryError(
                    f"wallet {wallet_id!r} share-bind {bind_id!r} approval "
                    "message does not match a share-bind body"
                )
            if approval.get("state") not in ("approved", "signed"):
                raise RecoveryError(
                    f"wallet {wallet_id!r} share-bind {bind_id!r} approval "
                    "request is not approved"
                )
            if message_body["id"] != bind_id or message_body["node"] != node:
                raise RecoveryError(
                    f"wallet {wallet_id!r} share-bind {bind_id!r} approval "
                    "message does not agree with its event"
                )
            if message_body["slot"] != slot:
                raise RecoveryError(
                    f"wallet {wallet_id!r} share-bind {bind_id!r} approval "
                    "message slot does not agree with its event"
                )
            rotation_id = message_body["rotation"]
            dkg_id = message_body["dkg"]
            round_no = message_body["round"]

            # --- 事前轮换现场：已 prepared 且未激活 ---
            prepared = next(
                (
                    pe
                    for pe in prepared_events
                    if pe["seq"] < seq
                    and isinstance(pe.get("details"), dict)
                    and pe["details"].get("rotation_id") == rotation_id
                ),
                None,
            )
            if prepared is None:
                raise RecoveryError(
                    f"wallet {wallet_id!r} share-bind {bind_id!r} rotation "
                    f"{rotation_id!r} was not prepared before the event"
                )
            activation = activated.get(rotation_id)
            if activation is not None and activation["seq"] < seq:
                raise RecoveryError(
                    f"wallet {wallet_id!r} share-bind {bind_id!r} rotation "
                    f"{rotation_id!r} was already active before the event"
                )
            prepared_share_ids = prepared["details"].get("share_ids")
            if (
                not isinstance(prepared_share_ids, list)
                or len(prepared_share_ids) != 2
                or share_id != prepared_share_ids[slot - 1]
                or share_id != f"{rotation_id}-share-{slot}"
            ):
                raise RecoveryError(
                    f"wallet {wallet_id!r} share-bind {bind_id!r} share_id "
                    "does not match the prepared rotation slot"
                )

            # --- 事前 DKG 现场（前缀重建）---
            sessions = self._build_dkg_sessions(wallet_id, seq - 1)
            session = sessions.get(dkg_id)
            if session is None or session["current"] != round_no:
                raise RecoveryError(
                    f"wallet {wallet_id!r} share-bind {bind_id!r} round is "
                    "not the current dkg round"
                )
            current_round = session["rounds"][round_no]
            if current_round["state"] != "done":
                raise RecoveryError(
                    f"wallet {wallet_id!r} share-bind {bind_id!r} round is "
                    "not done"
                )
            committed = session["failovers"].get(round_no)
            node_ids = [n for n, _ in current_round["nodes"]]
            if (
                round_no < 2
                or not isinstance(committed, dict)
                or committed.get("action") != "reinstate"
                or committed.get("replacement") != node
                or node not in node_ids
            ):
                raise RecoveryError(
                    f"wallet {wallet_id!r} share-bind {bind_id!r} node is not "
                    "the reinstated node of the current done round"
                )

            # --- node 在事前生效健康表中为 up ---
            health = self._folded_health_before(
                node_events, rejoin_events, seq
            )
            entry = health.get(node) if isinstance(health, dict) else None
            if not isinstance(entry, dict):
                raise RecoveryError(
                    f"wallet {wallet_id!r} share-bind {bind_id!r} node is "
                    "absent from the prior health table"
                )
            if entry.get("state") != "up":
                raise RecoveryError(
                    f"wallet {wallet_id!r} share-bind {bind_id!r} node is not "
                    "up in the prior health table"
                )

            # --- 槽位占用：同一轮换槽位（share_id）至多绑定一次 ---
            for earlier in events:
                if earlier["seq"] >= seq:
                    break
                if earlier["details"]["share_id"] == share_id:
                    raise RecoveryError(
                        f"wallet {wallet_id!r} share-bind {bind_id!r} slot "
                        f"{slot} was already occupied"
                    )

    def post_share_bind(
        self,
        wallet_id: str,
        bind_id: object,
        rotation_id: object,
        dkg_id: object,
        round_no: object,
        node: object,
        slot: object,
        approval_request_id: object,
    ) -> tuple[int, dict]:
        """把 DKG 当前 done 轮的 reinstate 复职节点绑定到 prepared 轮换的
        某个份额槽位，返回 (HTTP 状态码, V={id,node,slot,share_id})。

        请求体恰含 id,rotation,dkg,round,node,slot,approval 七键（HTTP
        边界拦键集）：id/rotation/dkg/node/approval 为安全标识，round 为
        非布尔正整数，slot 为非布尔 1|2；键集/类型/值错 400；钱包未知
        404。

        首提前置：rotation 为当前 prepared 轮换；round 恰为 DKG 当前
        done 轮；node 为创建该轮的 reinstate 换入节点且在生效健康表中为
        up；approval 指向同钱包既有 approved 审批单，message 逐字为 B 去
        approval 后按 id,rotation,dkg,round,node,slot 序的紧凑 JSON；槽位
        （prepared 轮换份额 id）未被更早绑定占用。轮换/DKG/节点/审批未知
        404；其余前置不满足 409。share_id 取该 prepared 轮换
        share_ids[slot-1]。

        首提 201；同 id 七字段全同重放 200 返回同一 V（优先于状态与审批
        判定，不复查审批单现状）；同 id 异参 409。
        share_participant_reinstated 是唯一提交点（request_id=id、
        actor_id=approval、reason=null、details=V）；锁内并发只有一个 201，
        重启/灾备由事件序列恢复。"""
        try:
            with self._wallet_lock(wallet_id):
                self._heal_wallet(wallet_id)
                # 404 优先于 400：存在性在锁内、heal 之后先判定
                self._get_wallet_or_404(wallet_id)
                self._assert_wallet_active_locked(wallet_id)
                # 持锁访问先严格复核既有绑定/健康/rejoin 现场：矛盾现场
                # fail-closed（503），优先于参数 400/404 判定。
                self._reconcile_share_bindings(wallet_id)
                # 类型/取值校验（400）
                for name, value in (
                    ("id", bind_id),
                    ("rotation", rotation_id),
                    ("dkg", dkg_id),
                    ("node", node),
                ):
                    if not isinstance(value, str) or not ROTATION_ID_RE.match(
                        value
                    ):
                        raise ServiceError(
                            400,
                            f"{name} must match [A-Za-z0-9_-]{{1,128}}",
                        )
                if (
                    not isinstance(round_no, int)
                    or isinstance(round_no, bool)
                    or round_no < 1
                ):
                    raise ServiceError(
                        400, "round must be a positive integer"
                    )
                if not isinstance(slot, int) or isinstance(slot, bool) or (
                    slot not in (1, 2)
                ):
                    raise ServiceError(400, "slot must be 1 or 2")
                if (
                    not isinstance(approval_request_id, str)
                    or not ROTATION_ID_RE.match(approval_request_id)
                ):
                    raise ServiceError(
                        400,
                        "approval must match [A-Za-z0-9_-]{1,128}",
                    )

                # 幂等优先于 404/状态判定：已提交的同 id 重放。events 的
                # rotation/dkg/round 不落在 details 中，由已提交事件
                # actor_id 所指审批单的 message 锚定（只取数据，不复查审批
                # 单现状）。
                committed_groups = (
                    self._audit.share_participant_reinstated_events(
                        wallet_id
                    ).get(bind_id)
                )
                if committed_groups:
                    if len(committed_groups) != 1:
                        raise RecoveryError(
                            f"wallet {wallet_id!r} has multiple "
                            f"share_participant_reinstated events for "
                            f"{bind_id!r}"
                        )
                    committed_event = committed_groups[0]
                    saved = committed_event["details"]
                    prior_approval = self._store.get_request(
                        wallet_id, committed_event["actor_id"]
                    )
                    prior_body = (
                        self._decode_share_bind_message(
                            prior_approval.get("message")
                        )
                        if isinstance(prior_approval, dict)
                        else None
                    )
                    same = (
                        prior_body is not None
                        and prior_body["id"] == bind_id
                        and committed_event["actor_id"]
                        == approval_request_id
                        and prior_body["rotation"] == rotation_id
                        and prior_body["dkg"] == dkg_id
                        and prior_body["round"] == round_no
                        and saved["node"] == node
                        and saved["slot"] == slot
                    )
                    if same:
                        return 200, dict(saved)
                    raise ServiceError(
                        409,
                        f"share-bind {bind_id!r} already exists with "
                        "different parameters",
                    )

                # 404：轮换 / DKG 会话 / 节点 / 审批单未知
                rotation = self._store.get_rotation(wallet_id, rotation_id)
                if rotation is None:
                    raise ServiceError(
                        404,
                        f"share rotation {rotation_id!r} not found",
                    )
                sessions = self._dkg_sessions(wallet_id)
                session = sessions.get(dkg_id)
                if session is None:
                    raise ServiceError(
                        404, f"dkg session {dkg_id!r} not found"
                    )
                folded = self._health_table_folding_rejoins_locked(wallet_id)
                if folded is None or node not in folded:
                    raise ServiceError(
                        404,
                        f"node {node!r} not found in the node health table",
                    )
                approval = self._store.get_request(
                    wallet_id, approval_request_id
                )
                if approval is None:
                    raise ServiceError(
                        404,
                        f"approval request {approval_request_id!r} not found",
                    )

                # 409 前置：轮换须 prepared
                if rotation.get("state") != "prepared":
                    raise ServiceError(
                        409,
                        f"share rotation {rotation_id!r} is "
                        f"{rotation.get('state')}, not prepared",
                    )
                # round 须为当前轮且 done
                current = session["current"]
                if round_no != current:
                    raise ServiceError(
                        409,
                        f"round must be the current round {current}",
                    )
                current_round = session["rounds"][current]
                if current_round["state"] != "done":
                    raise ServiceError(
                        409,
                        "share-bind requires the current round to be done",
                    )
                # node 须为该轮 reinstate 换入的节点
                committed = session["failovers"].get(current)
                node_ids = [n for n, _ in current_round["nodes"]]
                if (
                    current < 2
                    or not isinstance(committed, dict)
                    or committed.get("action") != "reinstate"
                    or committed.get("replacement") != node
                    or node not in node_ids
                ):
                    raise ServiceError(
                        409,
                        f"node {node!r} is not the reinstated node of the "
                        f"current done round {current}",
                    )
                # node 须在生效健康表中为 up
                if folded[node].get("state") != "up":
                    raise ServiceError(
                        409, f"node {node!r} is not up in the health table"
                    )

                # 审批门控：同钱包既有 approved 审批单，message 逐字一致。
                # 按既有契约懒过期（可能原子记一次 request_expired）。
                approval = self._expire_if_needed(wallet_id, approval)
                expected_message = self._share_bind_approval_message(
                    bind_id, rotation_id, dkg_id, round_no, node, slot
                )
                if approval["message"] != expected_message:
                    raise ServiceError(
                        409,
                        "approval request message does not match this "
                        "share-bind",
                    )
                if approval["state"] != "approved":
                    raise ServiceError(
                        409,
                        f"approval request {approval_request_id!r} is "
                        f"{approval['state']}, not approved",
                    )

                # share_id 是 prepared 轮换暂存份额的该槽份额；激活后成为
                # 在用份额（V.share_id=share_ids[slot-1]）。
                staged_share_ids = rotation.get("share_ids")
                if (
                    not isinstance(staged_share_ids, list)
                    or len(staged_share_ids) != 2
                    or not all(isinstance(s, str) for s in staged_share_ids)
                ):
                    raise RecoveryError(
                        f"wallet {wallet_id!r} rotation {rotation_id!r} has "
                        "malformed staged share_ids"
                    )
                share_id = staged_share_ids[slot - 1]
                # 槽位占用：该轮换槽位（share_id）已被更早绑定占用即 409。
                if self._bound_slot_occupied_locked(wallet_id, share_id):
                    raise ServiceError(
                        409, f"share slot {slot} is already bound"
                    )

                # share_participant_reinstated 是唯一提交点：在跨进程事务
                # 锁内追加事件；事件之外不写任何绑定状态文件，绑定由审计
                # 事件序列重建。
                view = self._share_bind_view(bind_id, node, slot, share_id)
                self._emit(
                    wallet_id,
                    self._audit_event(
                        audit.TYPE_SHARE_PARTICIPANT_REINSTATED,
                        request_id=bind_id,
                        actor_id=approval_request_id,
                        reason=None,
                        details=view,
                    ),
                )
                return 201, view
        except CorruptDataError:
            raise
        except ValueError:
            # wallet_id 含非法字符（构造锁路径时抛出）
            raise ServiceError(400, "invalid wallet_id")

    # ---- 签名请求审批单 ---------------------------------------------------

    @staticmethod
    def _request_view(record: dict) -> dict:
        """审批单对外视图（GET/POST 响应体共用）。"""
        return {
            "id": record["id"],
            "message": record["message"],
            "state": record["state"],
            "approvers": list(record["approvers"]),
            "count": len(record["approvers"]),
            "req": record["req"],
            "t0": record["t0"],
            "t1": record["t1"],
            "reason": record["reason"],
        }

    @staticmethod
    def _valid_request_cancel_reason(value: object) -> bool:
        return (
            isinstance(value, str)
            and not isinstance(value, bool)
            and bool(value.strip())
            and len(value) <= MAX_REASON_LENGTH
        )

    def _request_cancel_events_strict(
        self, wallet_id: str
    ) -> dict[str, dict]:
        """严格读取并按 request_id 索引全部 request_cancelled 事件。"""
        events = self._audit.events_by_type(
            wallet_id, audit.TYPE_REQUEST_CANCELLED
        )
        by_request: dict[str, dict] = {}
        cancel_ids: dict[str, str] = {}
        terminal_types = {
            audit.TYPE_REQUEST_APPROVED,
            audit.TYPE_REQUEST_REJECTED,
            audit.TYPE_REQUEST_EXPIRED,
            audit.TYPE_REQUEST_SIGNED,
        }
        for event in events:
            rid = event.get("request_id")
            cancel_id = event.get("actor_id")
            reason = event.get("reason")
            details = event.get("details")
            if not isinstance(rid, str) or not _SAFE_ID.match(rid):
                raise RecoveryError("request_cancelled event has a bad request_id")
            if not isinstance(cancel_id, str) or not _SAFE_ID.match(cancel_id):
                raise RecoveryError("request_cancelled event has a bad cancel_id")
            if not self._valid_request_cancel_reason(reason):
                raise RecoveryError("request_cancelled event has a bad reason")
            if not isinstance(details, dict) or set(details) != {
                "cancel_id",
                "reason",
            }:
                raise RecoveryError("request_cancelled event has bad details")
            if details.get("cancel_id") != cancel_id or details.get("reason") != reason:
                raise RecoveryError("request_cancelled event identifiers disagree")
            if rid in by_request:
                raise RecoveryError(
                    f"request {rid!r} has multiple cancellation events"
                )
            previous_rid = cancel_ids.get(cancel_id)
            if previous_rid is not None and previous_rid != rid:
                raise RecoveryError(
                    f"cancel_id {cancel_id!r} was reused across requests"
                )
            cancel_ids[cancel_id] = rid
            by_request[rid] = event
        for event in self._audit.all_events(wallet_id):
            rid = event.get("request_id")
            if (
                isinstance(rid, str)
                and rid in by_request
                and event.get("type") in terminal_types
                and event["seq"] > by_request[rid]["seq"]
            ):
                raise RecoveryError(
                    f"cancelled request {rid!r} has a later lifecycle event"
                )
        return by_request

    def _recover_request_cancellations(self, wallet_id: str) -> None:
        """按 request_cancelled 事件前滚/回滚审批单撤销事务。

        事件是唯一提交点。提交前意图存在时，事件在则前滚为 cancelled，
        事件不在则回滚到意图中的完整 pending 快照；无意图的 cancelled
        现场或缺事件现场均为不可对账矛盾。恢复本身不新增事件、不改 seq。
        """
        cancel_events = self._request_cancel_events_strict(wallet_id)
        intents = self._store.get_request_cancel_intents(wallet_id)
        for rid, intent in intents.items():
            if not _SAFE_ID.match(rid) or not isinstance(intent, dict):
                raise RecoveryError("request cancellation intent is malformed")
            if set(intent) != {"request_id", "cancel_id", "reason", "previous"}:
                raise RecoveryError("request cancellation intent is malformed")
            cancel_id = intent.get("cancel_id")
            reason = intent.get("reason")
            previous = intent.get("previous")
            if intent.get("request_id") != rid or not (
                isinstance(cancel_id, str) and _SAFE_ID.match(cancel_id)
            ) or not self._valid_request_cancel_reason(reason):
                raise RecoveryError("request cancellation intent is malformed")
            if not isinstance(previous, dict) or previous.get("id") != rid:
                raise RecoveryError("request cancellation intent is malformed")
            current = self._store.get_request(wallet_id, rid)
            event = cancel_events.get(rid)
            if current is None:
                raise RecoveryError(
                    f"request cancellation intent for {rid!r} has no request"
                )
            if event is not None:
                committed = dict(previous)
                committed["state"] = "cancelled"
                committed["reason"] = reason
                if (
                    event["actor_id"] != cancel_id
                    or event["reason"] != reason
                ):
                    raise RecoveryError(
                        f"request cancellation intent for {rid!r} disagrees "
                        "with its event"
                    )
                if current != committed:
                    self._store.update_request(wallet_id, rid, committed)
            else:
                if current != previous:
                    self._store.update_request(wallet_id, rid, previous)
            self._store.delete_request_cancel_intent(wallet_id, rid)

        requests = self._store.list_requests(wallet_id)
        for rid, record in requests.items():
            event = cancel_events.get(rid)
            if event is None:
                if isinstance(record, dict) and record.get("state") == "cancelled":
                    raise RecoveryError(
                        f"cancelled request {rid!r} has no cancellation event"
                    )
                continue
            if not isinstance(record, dict):
                raise RecoveryError(f"request {rid!r} is malformed")
            if record.get("state") != "cancelled":
                raise RecoveryError(
                    f"request {rid!r} has a cancellation event but is "
                    f"{record.get('state')!r}"
                )
            if record.get("reason") != event["reason"]:
                raise RecoveryError(
                    f"cancelled request {rid!r} disagrees with its event reason"
                )
        for rid in cancel_events:
            if rid not in requests:
                raise RecoveryError(
                    f"request_cancelled event for {rid!r} has no request"
                )

    def _expire_if_needed(self, wallet_id: str, record: dict) -> dict:
        """懒过期：任何操作前把已超时的 pending 单持久化为 expired，
        并原子记录一次 request_expired 事件。调用方须持有该钱包事务锁。
        事件追加失败时回滚为原 pending 状态后向上抛出。"""
        if record["state"] == "pending" and (
            datetime.now(timezone.utc) >= _parse_iso(record["t1"])
        ):
            expired = dict(record)
            expired["state"] = "expired"
            self._store.update_request(wallet_id, record["id"], expired)
            try:
                self._emit(
                    wallet_id,
                    self._audit_event(
                        audit.TYPE_REQUEST_EXPIRED,
                        request_id=record["id"],
                        details={"state": "expired"},
                    ),
                )
            except BaseException:
                self._store.update_request(wallet_id, record["id"], record)
                raise
            record = expired
        return record

    def _fetch_request_or_404(self, wallet_id: str, request_id: str) -> dict:
        """只读取审批单（404），不做懒过期；调用方自行在钱包事务锁内过期。"""
        try:
            record = self._store.get_request(wallet_id, request_id)
        except CorruptDataError:
            raise
        except ValueError:
            raise ServiceError(400, "invalid signing_request_id")
        if record is None:
            raise ServiceError(
                404, f"signing request {request_id!r} not found"
            )
        return record

    @staticmethod
    def _validate_request_body(request_id: object, message: object) -> None:
        if (
            not isinstance(request_id, str)
            or not request_id
            or not request_id.strip()
        ):
            raise ServiceError(
                400, "signing_request_id must be a non-empty string"
            )
        if not isinstance(message, str) or not message or not message.strip():
            raise ServiceError(400, "message must be a non-empty string")

    def create_sign_request(
        self, wallet_id: str, request_id: object, message: object
    ) -> tuple[int, dict]:
        """返回 (HTTP 状态码, 响应体)。

        读取、校验、幂等判定、策略读取、req/t0/t1 取值与持久化、事件追加
        全部在同一把每钱包事务锁内完成。多个 serve 进程并发更新同一钱包
        审批策略与创建签名请求时，请求单只能采用**锁提交时已生效**的
        required_approvals/timeout_seconds；锁内判定仍无审批策略则 409 且
        不留下请求或事件；request_created 与 policy_updated 的 seq 顺序即
        该钱包的线性化顺序。
        """
        record: dict | None = None
        try:
            with self._wallet_lock(wallet_id):
                self._heal_wallet(wallet_id)
                # 404 优先于 400：钱包存在性在锁内先于请求体/id 校验
                self._get_wallet_or_404(wallet_id)
                self._assert_wallet_active_locked(wallet_id)
                self._validate_request_body(request_id, message)
                # 锁内查重：同 id 同文 200、异文 409 均不记事件、不改状态，
                # 也不依赖此刻是否仍有策略（既有幂等语义保持）。
                try:
                    existing = self._store.get_request(
                        wallet_id, request_id
                    )
                except CorruptDataError:
                    # 审批单文件损坏：fail-closed（由 HTTP 边界转 503）
                    raise
                except ValueError:
                    raise ServiceError(400, "invalid signing_request_id")
                if existing is not None:
                    # POST 不是懒过期触发点：原样返回磁盘中持久化的状态
                    # （pending/approved/rejected/expired/signed），绝不在响应里
                    # 把磁盘仍是 pending 的单临时呈现成 expired。
                    if existing["message"] != message:
                        raise ServiceError(
                            409,
                            f"signing request {request_id!r} already exists "
                            "with a different message",
                        )
                    return 200, self._request_view(existing)
                # 首次创建：按锁提交时刻已生效的策略决定可否建单与参数。
                # 锁内判定仍无策略：409 且不留下任何请求或事件。
                policy = self._store.get_policy(wallet_id)
                if policy is None:
                    raise ServiceError(
                        409, f"wallet {wallet_id!r} has no approval policy"
                    )
                now = datetime.now(timezone.utc)
                record = {
                    "id": request_id,
                    "message": message,
                    "state": "pending",
                    "approvers": [],
                    "req": policy["required_approvals"],
                    "t0": now.isoformat().replace("+00:00", "Z"),
                    "t1": (now + timedelta(seconds=policy["timeout_seconds"]))
                    .isoformat()
                    .replace("+00:00", "Z"),
                    "reason": None,
                }
                # 锁内已确认不存在；存储层仍原子查重兜底
                self._store.create_request(wallet_id, request_id, record)
                # 首次创建：状态 + C 事件原子
                event = self._audit_event(
                    audit.TYPE_REQUEST_CREATED,
                    request_id=request_id,
                    details={"message": message},
                )
                try:
                    self._emit(wallet_id, event)
                except BaseException:
                    self._store.delete_request(wallet_id, request_id)
                    raise
        except CorruptDataError:
            # 钱包元数据/审批单/策略损坏：fail-closed（由 HTTP 边界转 503）
            raise
        except ValueError:
            # wallet_id 含非法字符（构造锁路径时抛出）
            raise ServiceError(400, "invalid wallet_id")
        return 201, self._request_view(record)

    def get_sign_request(self, wallet_id: str, request_id: str) -> dict:
        try:
            with self._wallet_lock(wallet_id):
                self._heal_wallet(wallet_id)
                # 钱包存在性、审批单读取与懒过期全部在锁内：绝不先用锁外
                # 快照决定 404，也读不到并发事务半完成的审批单状态。
                self._get_wallet_or_404(wallet_id)
                record = self._fetch_request_or_404(wallet_id, request_id)
                # 冻结期间查询仍可用但不允许任何写入：跳过懒过期（不记
                # request_expired 事件），按磁盘现状返回，解冻后再到期。
                if (
                    self._security_state_locked(wallet_id)["state"]
                    != WALLET_STATE_FROZEN
                ):
                    record = self._expire_if_needed(wallet_id, record)
                return self._request_view(record)
        except CorruptDataError:
            raise
        except ValueError:
            raise ServiceError(400, "invalid wallet_id")

    def cancel_sign_request(
        self, wallet_id: str, request_id: str, body: object
    ) -> tuple[int, dict]:
        """撤销 pending 且未过期的审批单。

        request_cancelled 是唯一提交点；同 rid + cancel_id + reason 重放
        返回 200。cancel_id 复用或参数变化、审批单非 pending、冻结钱包
        均为 409。
        """
        record = None
        try:
            with self._wallet_lock(wallet_id):
                self._heal_wallet(wallet_id)
                self._get_wallet_or_404(wallet_id)
                self._assert_wallet_active_locked(wallet_id)
                if not isinstance(body, dict) or set(body) != {
                    "cancel_id",
                    "reason",
                }:
                    raise ServiceError(
                        400,
                        "body must contain exactly cancel_id and reason",
                    )
                cancel_id = body["cancel_id"]
                reason = body["reason"]
                if not isinstance(cancel_id, str) or not _SAFE_ID.match(
                    cancel_id
                ):
                    raise ServiceError(400, "invalid cancel_id")
                if not self._valid_request_cancel_reason(reason):
                    raise ServiceError(
                        400,
                        "reason must be a non-blank string of 1 to "
                        f"{MAX_REASON_LENGTH} characters",
                    )
                record = self._fetch_request_or_404(wallet_id, request_id)
                record = self._expire_if_needed(wallet_id, record)
                cancel_events = self._request_cancel_events_strict(wallet_id)
                existing = cancel_events.get(request_id)
                if existing is not None:
                    if (
                        existing["actor_id"] == cancel_id
                        and existing["reason"] == reason
                    ):
                        return 200, self._request_view(record)
                    raise ServiceError(
                        409,
                        "signing request was cancelled with different parameters",
                    )
                for event in cancel_events.values():
                    if event["actor_id"] == cancel_id:
                        raise ServiceError(
                            409, "cancel_id has already been used"
                        )
                if record["state"] != "pending":
                    raise ServiceError(
                        409,
                        f"signing request {request_id!r} is {record['state']}, "
                        "not pending",
                    )
                cancelled = dict(record)
                cancelled["state"] = "cancelled"
                cancelled["reason"] = reason
                self._store.save_request_cancel_intent(
                    wallet_id, request_id, cancel_id, reason, record
                )
                self._store.update_request(
                    wallet_id, request_id, cancelled
                )
                try:
                    self._emit(
                        wallet_id,
                        self._audit_event(
                            audit.TYPE_REQUEST_CANCELLED,
                            request_id=request_id,
                            actor_id=cancel_id,
                            reason=reason,
                            details={
                                "cancel_id": cancel_id,
                                "reason": reason,
                            },
                        ),
                    )
                except BaseException:
                    self._store.update_request(
                        wallet_id, request_id, record
                    )
                    self._store.delete_request_cancel_intent(
                        wallet_id, request_id
                    )
                    raise
                self._store.delete_request_cancel_intent(
                    wallet_id, request_id
                )
                record = cancelled
        except CorruptDataError:
            raise
        except ValueError:
            raise ServiceError(400, "invalid wallet_id")
        return 201, self._request_view(record)

    # ---- 审计事件查询 ---------------------------------------------------

    #: 审计事件查询每页上限与默认条数
    AUDIT_DEFAULT_LIMIT = 1000
    AUDIT_MAX_LIMIT = 1000

    #: event_type/request_id 筛选值解码后的最大码点数
    AUDIT_FILTER_MAX_LEN = 1024

    @staticmethod
    def _public_audit_event_view(event: dict) -> dict:
        """单条事件的公开查询视图（副本）。

        仅 dkg_failover 事件重排外层键序为公开契约序
        seq,type,at,request_id,actor_id,reason,details；其 details 已在
        严格加载时归一为既定键序（auto 末键 mode），原样保留。其余事件
        类型保持落盘外层序（sort_keys 序）不变。只重排副本，绝不写盘
        或分配 seq。"""
        if event.get("type") == audit.TYPE_DKG_FAILOVER:
            return {
                key: event[key] for key in _DKG_FAILOVER_PUBLIC_KEY_ORDER
            }
        return event

    @staticmethod
    def _parse_positive_int(value: object, name: str) -> int:
        """from_seq/limit 必须是正整数（bool/浮点/带符号/缺失均拒绝）。"""
        if isinstance(value, str):
            text = value.strip()
            if not text.isdigit():
                raise ServiceError(400, f"{name} must be a positive integer")
            value = int(text)
        if (
            not isinstance(value, int)
            or isinstance(value, bool)
            or value < 1
        ):
            raise ServiceError(400, f"{name} must be a positive integer")
        return value

    @staticmethod
    def _audit_filter_value(value: object, name: str) -> str | None:
        """event_type/request_id 筛选值：None 表示缺省，否则返回原文。

        parse_qs 单值列表取首项；长度 >1 即重复参数（即使同值）→ 400。
        单值须为 1..1024 个 Unicode 码点且不全为空白——显式空值、纯
        空白、超长一律 400，绝不按缺省处理。命中后原样返回：大小写与
        首尾空白保留，不做任何归一化或前缀解释。"""
        if value is None:
            return None
        if isinstance(value, list):
            if len(value) > 1:
                raise ServiceError(400, f"duplicate {name}")
            value = value[0]
        if (
            not isinstance(value, str)
            or not 1 <= len(value) <= WalletService.AUDIT_FILTER_MAX_LEN
            or not value.strip()
        ):
            raise ServiceError(400, f"invalid {name}")
        return value

    def get_audit_events(
        self,
        wallet_id: str,
        from_seq: object = None,
        limit: object = None,
        event_type: object = None,
        request_id: object = None,
    ) -> dict:
        """返回 {wallet_id, events}（seq 升序）。

        可选筛选：event_type/request_id 分别与事件外层 type/request_id
        精确匹配（URL 解码后比较，大小写与首尾空白保留，不做前缀匹配；
        两者同时给定取交集；不搜索 actor_id 或 details；事件中的 null
        不匹配文本 null）。from_seq 仍是包含端点的原始审计序号下界，
        limit 只限制符合全部条件的事件数。筛选值的重复/空值/纯空白/
        超长校验与分页参数一样在锁内 404 之后进行。

        纯只读：不触发 pending 审批单懒过期、不写任何状态/事件、不分配
        seq。但与其他所有访问钱包状态的路由一致，必须在该钱包事务锁内
        先自愈他进程崩溃遗留的轮换/资产提交残留，再读取审计：恢复无法
        对账（RecoveryError/OSError/CorruptDataError）时由调用方转 503，
        绝不返回可能半完成的公钥/余额/version 之外的不一致现场。

        DKG 类事件（dkg_stage/dkg_failover/故障审批开关/健康表/rejoin/
        share-bind）仅由审计事件持久化：查询与启动一样按既有 DKG 恢复
        规则重放对账（矛盾即 fail-closed 503，保留审计文件、不写盘、
        不分配 seq、不返回部分结果），绝不返回未对账的 DKG 现场。

        存在性判定、分页参数校验与审计读取全部在锁内：绝不先用锁外
        快照决定 404/400，也读不到并发事务半完成状态。"""
        try:
            with self._wallet_lock(wallet_id):
                self._heal_wallet(wallet_id)
                # 404 优先于 400：锁内先判定钱包存在，再校验分页参数
                self._get_wallet_or_404(wallet_id)
                # 与启动恢复同一套 DKG 重放对账：任何状态或上下文矛盾
                # （含 dkg_failover details 键序/state 与动作不符）都在
                # 此 fail-closed，纯只读、不触发懒过期。
                self._reconcile_dkg_events_locked(wallet_id)
                seq = (
                    1
                    if from_seq is None
                    else self._parse_positive_int(from_seq, "from_seq")
                )
                size = (
                    self.AUDIT_DEFAULT_LIMIT
                    if limit is None
                    else self._parse_positive_int(limit, "limit")
                )
                if size > self.AUDIT_MAX_LIMIT:
                    raise ServiceError(
                        400, f"limit must be at most {self.AUDIT_MAX_LIMIT}"
                    )
                # 筛选参数与分页参数同处校验（404 之后、读取之前）：
                # 重复/显式空值/纯空白/超长一律 400，绝不按缺省处理。
                event_type = self._audit_filter_value(event_type, "event_type")
                request_id = self._audit_filter_value(request_id, "request_id")
                # 只读自愈：把可恢复的崩溃现场对账到一致，但绝不记事件、
                # 绝不触发审批单懒过期。筛选在整份日志严格加载之后施加，
                # 被条件排除的异常记录同样触发 fail-closed，绝不返回部分
                # 结果。
                events = self._audit.list_events(
                    wallet_id,
                    from_seq=seq,
                    limit=size,
                    event_type=event_type,
                    request_id=request_id,
                )
        except CorruptDataError:
            raise
        except ValueError:
            # wallet_id 含非法字符（构造锁路径时抛出）；from_seq/limit 的
            # 非法值已在锁内转成 ServiceError(400)
            raise ServiceError(400, "invalid wallet_id")
        # 仅重排查询副本（dkg_failover 外层为公开契约序），不写盘、
        # 不分配 seq、不改存储内存现场。
        events = [self._public_audit_event_view(event) for event in events]
        return {"wallet_id": wallet_id, "events": events}

    # ---- 审计完整性（摘要链） -------------------------------------------

    #: expected_head 必须为 64 位小写十六进制
    _EXPECTED_HEAD_RE = re.compile(r"^[0-9a-f]{64}$")

    def get_audit_integrity(
        self, wallet_id: str, expected_head: object = None
    ) -> dict:
        """返回 {wallet_id, state, count, head}，state 恒为 "valid"。

        纯只读：在该钱包事务锁内先自愈，再按审计读取归一化后的事件重放
        防篡改摘要链并与审计文件顶层 chain 元数据严格对账。事件被改动、
        链元数据缺失/不匹配、seq 不连续、details 形状矛盾一律
        RecoveryError/CorruptDataError/OSError（由 HTTP 边界转 503），
        保留现场不覆盖。

        expected_head 缺省时只校验链；给定时还须与链头逐字一致，不一致
        抛 ServiceError(409)，格式非法抛 ServiceError(400)。钱包标识
        非法 400、钱包不存在 404（沿用锁内 404 优先于查询参数 400 的
        既有次序）。"""
        try:
            with self._wallet_lock(wallet_id):
                self._heal_wallet(wallet_id)
                self._get_wallet_or_404(wallet_id)
                if expected_head is not None and (
                    not isinstance(expected_head, str)
                    or not self._EXPECTED_HEAD_RE.match(expected_head)
                ):
                    raise ServiceError(
                        400,
                        "expected_head must be 64-char lowercase hex",
                    )
                # 与 audit-events 同一套 DKG 事件严格对账：details 形状
                # 矛盾在此即 fail-closed，绝不返回"链有效"的假结论。
                self._reconcile_dkg_events_locked(wallet_id)
                count, head = self._audit.integrity(wallet_id)
        except CorruptDataError:
            raise
        except ValueError:
            raise ServiceError(400, "invalid wallet_id")
        if expected_head is not None and expected_head != head:
            raise ServiceError(409, "expected_head does not match chain head")
        return {
            "wallet_id": wallet_id,
            "state": "valid",
            "count": count,
            "head": head,
        }

    # ---- 审计区间证据（逐条摘要 + 前后局部链头） -------------------------

    #: 单次证据区间最多 1000 条
    AUDIT_EVIDENCE_MAX_RANGE = 1000

    @staticmethod
    def _evidence_seq(value: object, invalid_message: str) -> int:
        """证据区间端点：非布尔正整数（parse_qs 单值列表取首项；字符串先
        strip，仅接受十进制数字，拒绝 0/负数/小数/布尔/其他类型）。非法抛
        调用方指定的 400 文案。调用方须先完成重复参数判定。"""
        text = value[0] if isinstance(value, list) else value
        if isinstance(text, str):
            text = text.strip()
            if not text.isdigit():
                raise ServiceError(400, invalid_message)
            text = int(text)
        if not isinstance(text, int) or isinstance(text, bool) or text < 1:
            raise ServiceError(400, invalid_message)
        return text

    def get_audit_evidence(
        self,
        wallet_id: str,
        from_seq: object = None,
        to_seq: object = None,
        expected_head: object = None,
    ) -> dict:
        """返回区间逐条审计证据::

            {wallet_id, range:{from_seq,to_seq}, events, event_digests,
             start_head, end_head, count, state:"valid"}

        - events 按 seq 升序并沿用 audit-events 公开视图（副本重排，绝不
          含密钥或中间值）；event_digests 与 events 一一对应，按既有七字段
          摘要规则（七键键升序紧凑 JSON 的 SHA-256）计算；
        - start_head 为 from_seq 前一事件后的链头（from_seq=1 时为 64 个
          零），end_head 为 to_seq 后的链头，可由 start_head 与
          event_digests 按既有递推规则复算；count 为区间事件数。

        纯只读：在该钱包事务锁内先自愈，再与其他审计读取同一套 DKG 重放
        对账并重放整条摘要链（integrity），链元数据缺失/不匹配、事件被
        改动等不可对账现场一律上抛（HTTP 边界转 503），不分配 seq、不改
        状态、不写文件；并发追加后再次查询结果一致，旧 end_head 可作为
        新请求的 expected_head 继续验证。

        三个参数接受 parse_qs 的字符串列表（None 表示缺参，长度 >1 即重复
        参数）。参数校验次序（钱包存在性 404 之后）：缺参 → 重复 →
        from_seq 非法 → to_seq 非法 → expected_head 格式 → 区间非法
        （from>to 或超 1000 条）；空钱包（无任何事件）404 empty evidence
        range；to_seq 越界 404 evidence range out of bounds；expected_head
        与 end_head 不符 409。
        """
        try:
            with self._wallet_lock(wallet_id):
                self._heal_wallet(wallet_id)
                # 404 优先于查询参数 400：与 audit-events / audit-integrity
                # 同一次序。
                self._get_wallet_or_404(wallet_id)
                # 1) 缺参（expected_head 可省；parse_qs 默认丢弃空白值，
                #    故空白值同样按缺省处理）
                if from_seq is None or to_seq is None:
                    raise ServiceError(
                        400, "missing evidence parameters"
                    )
                # 2) 重复参数：按 from_seq、to_seq、expected_head 次序报
                for value in (from_seq, to_seq, expected_head):
                    if isinstance(value, list) and len(value) > 1:
                        raise ServiceError(
                            400, "duplicate evidence parameters"
                        )
                # 3) from_seq 非法
                seq_from = self._evidence_seq(from_seq, "invalid from_seq")
                # 4) to_seq 非法
                seq_to = self._evidence_seq(to_seq, "invalid to_seq")
                # 5) expected_head 格式（可省；给定时须为 64 位小写十六进制）
                if isinstance(expected_head, list):
                    expected_head = expected_head[0]
                if expected_head is not None and (
                    not isinstance(expected_head, str)
                    or not self._EXPECTED_HEAD_RE.match(expected_head)
                ):
                    raise ServiceError(400, "invalid expected_head")
                # 6) 区间非法：from > to 或区间超过 1000 条
                if (
                    seq_from > seq_to
                    or seq_to - seq_from + 1 > self.AUDIT_EVIDENCE_MAX_RANGE
                ):
                    raise ServiceError(400, "invalid evidence range")
                # 与 audit-events 同一套严格 DKG 对账：details 形状矛盾等
                # 现场 fail-closed，绝不返回未经对账的"证据"。
                self._reconcile_dkg_events_locked(wallet_id)
                # 整条摘要链必须可对账：文件存在但缺 chain 元数据、链头与
                # 事件重算不符一律 RecoveryError（503），绝不静默出证。
                self._audit.integrity(wallet_id)
                evidence = self._audit.range_evidence(
                    wallet_id, seq_from, seq_to
                )
        except CorruptDataError:
            raise
        except ValueError:
            raise ServiceError(400, "invalid wallet_id")
        if evidence is None or evidence["count"] == 0:
            # 无审计文件或一条事件都没有：区间必然为空
            raise ServiceError(404, "empty evidence range")
        if seq_to > evidence["count"]:
            raise ServiceError(404, "evidence range out of bounds")
        if expected_head is not None and expected_head != evidence["end_head"]:
            raise ServiceError(
                409, "expected_head does not match chain head"
            )
        events = [
            self._public_audit_event_view(event)
            for event in evidence["events"]
        ]
        return {
            "wallet_id": wallet_id,
            "range": {"from_seq": seq_from, "to_seq": seq_to},
            "events": events,
            "event_digests": evidence["event_digests"],
            "start_head": evidence["start_head"],
            "end_head": evidence["end_head"],
            "count": len(events),
            "state": "valid",
        }

    # ---- 份额轮换 ---------------------------------------------------------

    @staticmethod
    def _rotation_view(record: dict) -> dict:
        """轮换记录对外视图（只含公钥与标识，绝不含私钥）。

        cancelled 轮换附加恰含 cancel_id/reason 的 cancellation 快照；
        其余状态的视图形状保持不变。"""
        view = {
            "rotation_id": record["rotation_id"],
            "state": record["state"],
            "share_ids": list(record["share_ids"]),
            "public_key": record["public_key"],
        }
        if record["state"] == "cancelled":
            cancellation = record["cancellation"]
            view["cancellation"] = {
                "cancel_id": cancellation["cancel_id"],
                "reason": cancellation["reason"],
            }
        return view

    @staticmethod
    def _validate_rotation_id(rotation_id: object) -> None:
        if not isinstance(rotation_id, str) or not ROTATION_ID_RE.match(
            rotation_id
        ):
            raise ServiceError(
                400, "rotation_id must match [A-Za-z0-9_-]{1,128}"
            )

    def create_share_rotation(
        self, wallet_id: str, rotation_id: object
    ) -> tuple[int, dict]:
        """准备一次份额轮换：生成两份新份额，私钥只落暂存文件。

        返回 (HTTP 状态码, 响应体)。同 rotation_id 重放返回 200 且不重新
        生成；每钱包同时只允许一个 prepared 轮换，冲突返回 409。

        恢复检查、钱包存在性、rotation_id 校验、查重与 prepared 冲突判定
        全部在锁内：绝不基于锁外快照决定 404/400/409 或幂等重放。
        """
        record: dict | None = None
        try:
            with self._wallet_lock(wallet_id):
                self._heal_wallet(wallet_id)
                # 404 优先于 400：存在性先于 rotation_id 校验
                self._get_wallet_or_404(wallet_id)
                self._assert_wallet_active_locked(wallet_id)
                self._validate_rotation_id(rotation_id)
                existing = self._store.get_rotation(wallet_id, rotation_id)
                if existing is not None:
                    # 幂等重放：原样返回，不重新生成、不记事件
                    return 200, self._rotation_view(existing)
                for other in self._store.list_rotations(wallet_id):
                    if other.get("state") in ("prepared", "activating"):
                        raise ServiceError(
                            409,
                            f"wallet {wallet_id!r} already has a prepared "
                            "share rotation",
                        )
                share_ids = [
                    f"{rotation_id}-share-1",
                    f"{rotation_id}-share-2",
                ]
                share_keys = [
                    crypto.generate_share_key(sid) for sid in share_ids
                ]
                public_key = crypto.combine_public_keys(
                    [k.public_bytes for k in share_keys]
                ).hex()
                record = {
                    "rotation_id": rotation_id,
                    "state": "prepared",
                    "share_ids": share_ids,
                    "public_key": public_key,
                    "created_at": _utc_now_iso(),
                }
                try:
                    # 新份额私钥只写入暂存文件（一份一个文件），激活前绝不
                    # 触碰在用份额与钱包元数据
                    for key in share_keys:
                        self._store.save_staging_share(
                            wallet_id,
                            rotation_id,
                            {
                                "share_id": key.share_id,
                                "public_key": key.public_bytes.hex(),
                                # 仅该份额自己的私钥；系统中不存在完整私钥
                                "private_key": key.private_bytes.hex(),
                            },
                        )
                    self._store.create_rotation(wallet_id, rotation_id, record)
                    self._emit(
                        wallet_id,
                        self._audit_event(
                            audit.TYPE_SHARE_ROTATION_PREPARED,
                            details={
                                "rotation_id": rotation_id,
                                "share_ids": share_ids,
                                "public_key": public_key,
                            },
                        ),
                    )
                except BaseException:
                    # 状态/事件原子：事件未落盘则回滚轮换记录与暂存文件
                    self._store.delete_rotation(wallet_id, rotation_id)
                    self._store.delete_staging(wallet_id, rotation_id)
                    raise
        except CorruptDataError:
            raise
        except ValueError:
            # wallet_id 含非法字符（构造锁路径时抛出）
            raise ServiceError(400, "invalid wallet_id")
        return 201, self._rotation_view(record)

    def get_share_rotation(self, wallet_id: str, rotation_id: str) -> dict:
        try:
            with self._wallet_lock(wallet_id):
                self._heal_wallet(wallet_id)
                # 钱包存在性先于轮换读取：绝不先用锁外快照决定 404
                self._get_wallet_or_404(wallet_id)
                # 锁内读取：并发激活期间不会读到瞬态 activating
                try:
                    record = self._store.get_rotation(wallet_id, rotation_id)
                except CorruptDataError:
                    raise
                except ValueError:
                    raise ServiceError(400, "invalid rotation_id")
                if record is None:
                    raise ServiceError(
                        404, f"share rotation {rotation_id!r} not found"
                    )
                return self._rotation_view(record)
        except CorruptDataError:
            raise
        except ValueError:
            raise ServiceError(400, "invalid wallet_id")

    def activate_share_rotation(
        self, wallet_id: str, rotation_id: str
    ) -> tuple[int, dict]:
        """激活一次已准备的轮换：锁内替换份额文件、钱包公钥与轮换状态。

        仅 prepared 可激活（201）；active 重放返回 200；其余状态 409。
        失败时回滚份额文件、公钥与状态并清理备份；激活成功后删除暂存。

        恢复检查、钱包存在性、rotation_id 校验、状态判定与整个替换事务
        全部在锁内：绝不基于锁外快照决定 404/400/409 或重放。
        """
        try:
            with self._wallet_lock(wallet_id):
                self._heal_wallet(wallet_id)
                # 404 优先于 400：存在性先于 rotation_id 校验
                self._get_wallet_or_404(wallet_id)
                self._assert_wallet_active_locked(wallet_id)
                self._validate_rotation_id(rotation_id)
                record = self._store.get_rotation(wallet_id, rotation_id)
                if record is None:
                    raise ServiceError(
                        404, f"share rotation {rotation_id!r} not found"
                    )
                if record["state"] == "active":
                    # 幂等重放：不重复替换、不记事件
                    return 200, self._rotation_view(record)
                if record["state"] != "prepared":
                    raise ServiceError(
                        409,
                        f"share rotation {rotation_id!r} is "
                        f"{record['state']}, not prepared",
                    )

                # 锁内重读钱包元数据，拿到当前在用份额与公钥
                wallet = self._store.get_wallet(wallet_id)
                if wallet is None:
                    raise ServiceError(404, f"wallet {wallet_id!r} not found")
                previous_public_key = wallet["public_key"]
                old_share_ids = [s["share_id"] for s in wallet["shares"]]
                old_share_records = []
                for share_id in old_share_ids:
                    share_record = self._store.get_share(wallet_id, share_id)
                    if share_record is None:
                        raise ServiceError(
                            409,
                            f"wallet {wallet_id!r} share files are incomplete",
                        )
                    old_share_records.append(share_record)
                new_share_records = []
                for share_id in record["share_ids"]:
                    staged = self._store.get_staging_share(
                        wallet_id, rotation_id, share_id
                    )
                    if staged is None:
                        raise ServiceError(
                            409,
                            f"share rotation {rotation_id!r} staging files "
                            "are incomplete",
                        )
                    new_share_records.append(staged)

                new_meta = dict(wallet)
                new_meta["shares"] = [
                    {
                        "share_id": r["share_id"],
                        "public_key": r["public_key"],
                    }
                    for r in new_share_records
                ]
                new_meta["public_key"] = record["public_key"]
                active_record = dict(record)
                active_record["state"] = "active"
                active_record["previous_public_key"] = previous_public_key

                try:
                    # 先落 activating 标记与旧份额/元数据备份：崩溃后启动
                    # 恢复据此回滚
                    activating = dict(record)
                    activating["state"] = "activating"
                    activating["previous_public_key"] = previous_public_key
                    self._store.update_rotation(
                        wallet_id, rotation_id, activating
                    )
                    self._store.save_activation_backups(
                        wallet_id, rotation_id, old_share_records, wallet
                    )
                    # 锁内替换：新份额文件、钱包 shares/public_key、轮换状态
                    for share_record in new_share_records:
                        self._store.save_share(wallet_id, share_record)
                    self._store.save_wallet_meta(wallet_id, new_meta)
                    for share_id in old_share_ids:
                        self._store.delete_share(wallet_id, share_id)
                    self._store.update_rotation(
                        wallet_id, rotation_id, active_record
                    )
                    self._emit(
                        wallet_id,
                        self._audit_event(
                            audit.TYPE_SHARE_ROTATION_ACTIVATED,
                            details={
                                "rotation_id": rotation_id,
                                "share_ids": list(record["share_ids"]),
                                "public_key": record["public_key"],
                                "previous_public_key": previous_public_key,
                            },
                        ),
                    )
                except BaseException:
                    # 以激活事件是否真正落盘为唯一判据，而不是是否抛错：
                    landed = (
                        self._activated_rotations(wallet_id).get(rotation_id)
                    )
                    if landed is not None:
                        # 事件已落盘（提交不可撤回）：前滚为唯一 active 并
                        # 清理残留，绝不回滚、不重复记事件
                        self._store.forward_complete_activation(
                            wallet_id, active_record, landed
                        )
                        return 201, self._rotation_view(active_record)
                    # 事件未落盘：回滚份额文件、公钥与状态，清理激活备份
                    # （保留暂存的新份额文件，prepared 轮换可重试激活）
                    self._store.rollback_activation_files(wallet_id, record)
                    self._store.update_rotation(wallet_id, rotation_id, record)
                    self._store.delete_activation_backups(
                        wallet_id, rotation_id
                    )
                    raise
                # 激活成功：删除暂存的新份额文件与备份。此清理非提交点，
                # 若清理 I/O 失败也不改结果（事件已落盘，激活已生效），
                # 残留由重放/下一次持锁访问/重启自愈前滚时清掉。
                try:
                    self._store.delete_staging(wallet_id, rotation_id)
                except OSError:
                    pass
        except CorruptDataError:
            raise
        except ValueError:
            # wallet_id 含非法字符（构造锁路径时抛出）
            raise ServiceError(400, "invalid wallet_id")
        return 201, self._rotation_view(active_record)

    def cancel_share_rotation(
        self,
        wallet_id: str,
        rotation_id: object,
        cancel_id: object,
        reason: object,
    ) -> tuple[int, dict]:
        """主动撤销一笔未激活的份额轮换，返回 (HTTP 状态码, 轮换视图)。

        - 钱包/轮换未知 404；冻结钱包一律 409（含重放）且零副作用；
        - rotation_id/cancel_id 须匹配安全标识、reason 须为 1..1024 字符
          且含非空白内容的字符串（原文保留），非法 400；
        - 仅 prepared 可首次撤销：成功 201 并原子转 cancelled，视图附加
          恰含 cancel_id/reason 的 cancellation 快照；active/activating
          及已撤销一律 409（撤销与激活交错时只有先提交的一方生效）；
        - cancel_id 只在同钱包的轮换撤销之间判重：同轮换同标识同原因
          重放 200 同体（不记事件）；异参、复用到其他轮换或对已撤销轮换
          以新标识再撤销均 409；
        - share_rotation_cancelled 事件是唯一提交点：事件未落盘则回滚
          记录为 prepared（保留暂存份额），落盘（含异常但已落盘）则保持
          撤销结果并继续完成暂存清理，绝不复活轮换；重放不追加事件；
        - 成功响应前严格清理该轮换的暂存份额：读取/写入/清理失败按
          OSError 上抛（HTTP 503）；不改变在用份额、钱包公钥、签名会话
          与历史签名。恢复检查、存在性、校验与整个撤销事务全部在锁内。
        """
        try:
            with self._wallet_lock(wallet_id):
                self._heal_wallet(wallet_id)
                # 404 优先于 400：存在性先于标识/原因校验
                self._get_wallet_or_404(wallet_id)
                # 冻结是应急闸门：撤销及其重放一律 409 且零副作用
                self._assert_wallet_active_locked(wallet_id)
                self._validate_rotation_id(rotation_id)
                self._validate_cancel_id(cancel_id)
                reason = self._validate_cancel_reason(reason)
                record = self._store.get_rotation(wallet_id, rotation_id)
                if record is None:
                    raise ServiceError(
                        404, f"share rotation {rotation_id!r} not found"
                    )
                # 已提交重放优先于一切状态判定：撤销事件是唯一提交点；
                # cancel_id 只在同钱包的轮换撤销之间判重。
                cancelled_events = self._audit.cancelled_rotation_events(
                    wallet_id
                )
                own_event = cancelled_events.get(rotation_id)
                for rid, event in cancelled_events.items():
                    if rid == rotation_id:
                        continue
                    details = event.get("details")
                    if (
                        isinstance(details, dict)
                        and details.get("cancel_id") == cancel_id
                    ):
                        raise ServiceError(
                            409,
                            f"cancel {cancel_id!r} is already in use",
                        )
                if own_event is not None:
                    details = own_event["details"]
                    if (
                        details.get("cancel_id") != cancel_id
                        or details.get("reason") != reason
                    ):
                        raise ServiceError(
                            409,
                            f"cancel {cancel_id!r} was committed with "
                            "different parameters",
                        )
                    # 同轮换同标识同原因重放：200 同体，不追加事件
                    return 200, self._rotation_view(record)
                if record["state"] != "prepared":
                    # active/activating 与已以其他标识撤销的 cancelled 一律
                    # 409：撤销与激活交错时只有先提交的一方生效
                    raise ServiceError(
                        409,
                        f"share rotation {rotation_id!r} is "
                        f"{record['state']}, not prepared",
                    )
                cancelled_record = dict(record)
                cancelled_record["state"] = "cancelled"
                cancelled_record["cancellation"] = {
                    "cancel_id": cancel_id,
                    "reason": reason,
                }
                # 提交点：状态落盘 + 撤销事件原子。任一写入失败以事件是否
                # 真正落盘为唯一判据：事件在则保持撤销结果并继续完成清理；
                # 事件不在则回滚为撤销前的 prepared（保留暂存份额）。
                self._store.update_rotation(
                    wallet_id, rotation_id, cancelled_record
                )
                try:
                    self._emit(
                        wallet_id,
                        self._audit_event(
                            audit.TYPE_SHARE_ROTATION_CANCELLED,
                            details={
                                "rotation_id": rotation_id,
                                "cancel_id": cancel_id,
                                "reason": reason,
                            },
                        ),
                    )
                except BaseException:
                    landed = self._audit.cancelled_rotation_events(
                        wallet_id
                    ).get(rotation_id)
                    if landed is None:
                        # 事件未落盘：回滚为 prepared，暂存份额保留可重试
                        self._store.update_rotation(
                            wallet_id, rotation_id, record
                        )
                        raise
                    # 事件已落盘（提交不可撤回）：保持撤销结果，绝不回滚、
                    # 不重复记事件；清理失败上抛，由恢复继续完成。
                    self._store.delete_staging_strict(
                        wallet_id, rotation_id
                    )
                    return 201, self._rotation_view(cancelled_record)
                # 成功响应前严格清理该轮换的暂存份额：清理失败按 OSError
                # 上抛（HTTP 503）；撤销已提交，残留由恢复继续清理。
                self._store.delete_staging_strict(wallet_id, rotation_id)
                return 201, self._rotation_view(cancelled_record)
        except CorruptDataError:
            raise
        except ValueError:
            # wallet_id 含非法字符（构造锁路径时抛出）
            raise ServiceError(400, "invalid wallet_id")

    # ---- 资产账本 ---------------------------------------------------------

    @staticmethod
    def _validate_operation_id(operation_id: object) -> None:
        if not isinstance(operation_id, str) or not ROTATION_ID_RE.match(
            operation_id
        ):
            raise ServiceError(
                400, "operation_id must match [A-Za-z0-9_-]{1,128}"
            )

    @staticmethod
    def _validate_asset_id(asset_id: object) -> None:
        if not isinstance(asset_id, str) or not ROTATION_ID_RE.match(
            asset_id
        ):
            raise ServiceError(
                400, "asset_id must match [A-Za-z0-9_-]{1,128}"
            )

    @staticmethod
    def _validate_delta(delta: object) -> None:
        # bool 是 int 的子类，必须先排除；0 不是合法的资产变动
        if not isinstance(delta, int) or isinstance(delta, bool) or delta == 0:
            raise ServiceError(400, "delta must be a non-zero integer")

    @staticmethod
    def _validate_expected_version(expected_version: object) -> None:
        # bool 是 int 的子类，必须先排除；0 表示资产尚无提交版本
        if (
            not isinstance(expected_version, int)
            or isinstance(expected_version, bool)
            or expected_version < 0
        ):
            raise ServiceError(
                400, "expected_version must be a non-negative integer"
            )

    @staticmethod
    def _validate_cancel_id(cancel_id: object) -> None:
        if not isinstance(cancel_id, str) or not ROTATION_ID_RE.match(
            cancel_id
        ):
            raise ServiceError(
                400, "cancel_id must match [A-Za-z0-9_-]{1,128}"
            )

    @staticmethod
    def _validate_approval_request_id_ref(approval_request_id: object) -> None:
        if not isinstance(
            approval_request_id, str
        ) or not ROTATION_ID_RE.match(approval_request_id):
            raise ServiceError(
                400,
                "approval_request_id must match [A-Za-z0-9_-]{1,128}",
            )

    @staticmethod
    def _cancel_approval_message(
        operation_id: str, cancel_id: str
    ) -> str:
        """撤销审批单 message 必须逐字一致的紧凑 JSON（无空格、键序固定
        为 operation_id,cancel_id）。"""
        return json.dumps(
            {
                "operation_id": operation_id,
                "cancel_id": cancel_id,
            },
            ensure_ascii=False,
            separators=(",", ":"),
        )

    def create_asset_operation(
        self,
        wallet_id: str,
        operation_id: object,
        asset_id: object,
        delta: object,
    ) -> tuple[int, dict]:
        """创建一条资产操作（pending）。返回 (HTTP 状态码, 响应体 R)。

        首次创建 201；同 operation_id 同参数幂等重放 200（返回当前记录，
        不重复记事件、不再按当前策略校验）；同 operation_id 异参数 409。
        创建本身不记审计事件。

        钱包配置了冷热钱包交易策略时，**仅首次创建**按创建时刻的策略
        检查：asset_id 必须在 allowed_assets 白名单内且
        ``abs(delta) <= max_delta``，否则 409 且账本/version/状态/审计/
        幂等结果均不变（检查发生在任何写入之前）。策略后续更新不影响
        已存在的 pending 操作；未配置策略时行为完全不变。

        恢复检查、钱包存在性、参数校验、幂等查重与策略读取全部在锁内：
        绝不基于锁外快照决定 404/400/409、重放或白名单结果。
        """
        record: dict | None = None
        try:
            with self._wallet_lock(wallet_id):
                # 快照前先自愈他进程崩溃遗留的提交意图，balance/version 才准确
                self._heal_wallet(wallet_id)
                # 404 优先于 400：存在性先于 id/delta 校验
                self._get_wallet_or_404(wallet_id)
                self._assert_wallet_active_locked(wallet_id)
                self._validate_operation_id(operation_id)
                self._validate_asset_id(asset_id)
                self._validate_delta(delta)
                # 资产粒度冻结闸门：先于幂等重放与一切业务判定，frozen
                # 资产即便同参重放也一律 409 且零副作用。
                self._assert_asset_active_locked(wallet_id, asset_id)
                existing = self._store.get_asset_operation(
                    wallet_id, operation_id
                )
                if existing is not None:
                    # 重放：原样返回磁盘中的当前记录，不按更新后的策略重新
                    # 校验、不改状态、不记事件（幂等结果不变）
                    if (
                        existing.get("asset_id") != asset_id
                        or existing.get("delta") != delta
                    ):
                        raise ServiceError(
                            409,
                            f"asset operation {operation_id!r} already exists "
                            "with different parameters",
                        )
                    return 200, existing
                # 首次创建：按锁提交时刻的交易策略检查白名单与单笔上限
                policy = self._store.get_transaction_policy(wallet_id)
                if policy is not None:
                    if asset_id not in policy["allowed_assets"]:
                        raise ServiceError(
                            409,
                            f"asset {asset_id!r} is not allowed by the "
                            "transaction policy",
                        )
                    if abs(delta) > policy["max_delta"]:
                        raise ServiceError(
                            409,
                            f"abs(delta)={abs(delta)} exceeds transaction "
                            f"policy max_delta={policy['max_delta']}",
                        )
                # R 的 balance/version 快照资产在创建时刻的账本状态
                asset = self._store.get_asset(wallet_id, asset_id)
                record = {
                    "operation_id": operation_id,
                    "asset_id": asset_id,
                    "state": "pending",
                    "delta": delta,
                    "balance": asset["balance"] if asset is not None else 0,
                    "version": asset["version"] if asset is not None else 0,
                }
                # 锁内已确认不存在；存储层仍原子查重兜底
                self._store.create_asset_operation(
                    wallet_id, operation_id, record
                )
        except CorruptDataError:
            raise
        except ValueError:
            # wallet_id 含非法字符（构造锁路径时抛出）
            raise ServiceError(400, "invalid wallet_id")
        return 201, record

    # ---- 资产提交的崩溃恢复 ----------------------------------------------

    def _recover_wallet_asset_commits(self, wallet_id: str) -> None:
        """恢复某钱包全部未完成的资产提交事务（调用方须持有钱包事务锁）。

        以 asset_operation_committed 事件是否已持久化作为唯一提交判据：
        - 事件在：提交已生效，按事件 details（即 committed 视图 R）把账本
          前滚补齐为一致的 committed 结果，再删意图（幂等，余额/版本按 R
          绝对值校正，不重复应用 delta）；
        - 事件不在：提交未生效，按意图记录的提交前快照把操作恢复为
          pending、资产恢复提交前 balance/version（提交前不存在则删除
          资产条目），再删意图。事件从未分配 seq，故无 seq 缺口。
        恢复本身不记任何审计事件。任一条意图无法对账到一致状态都抛
        RecoveryError，由调用方阻止就绪/返回 503，绝不静默跳过。
        """
        for operation_id, intent in self._store.list_asset_intents(wallet_id):
            # 撤销意图与提交意图共用 asset-intents 目录（同操作在锁内
            # 互斥，崩溃至多残留其一）：按 kind 分派，未知 kind 是无法
            # 识别的事务现场，fail-closed 绝不按任一已知事务猜测对账。
            if isinstance(intent, dict) and intent.get("kind") == "cancel":
                self._resolve_asset_cancel_intent(
                    wallet_id, operation_id, intent
                )
                continue
            if isinstance(intent, dict) and intent.get("kind") == "transfer":
                # 原子资产转账的提交意图（kind="transfer"，键即
                # transfer_id）：按 asset_transfer_committed 事件是否
                # 落盘前滚/回滚两个资产的账本变化。
                self._resolve_asset_transfer_intent(
                    wallet_id, operation_id, intent
                )
                continue
            if isinstance(intent, dict) and "kind" in intent:
                raise RecoveryError(
                    f"wallet {wallet_id!r} asset operation {operation_id!r} "
                    "intent has an unknown kind and cannot be reconciled"
                )
            self._resolve_asset_commit_intent(wallet_id, operation_id, intent)

    def _reconcile_asset_committed_events(self, wallet_id: str) -> None:
        """账本 committed 操作与 asset_operation_committed 事件双向对账
        （调用方须持钱包事务锁；意图残留须已先恢复清零）。

        唯一提交点是审计事件：

        - 每条 committed 操作必须恰有一条同 request_id 的事件，
          ``details`` 与账本中的 committed 视图 R 逐字段一致；
        - 每条 committed 事件必须对应一条账本 committed 操作
          （有事件无操作＝事件被半应用或历史被删，fail-closed）；
        - pending 操作不得有 committed 事件；
        - 同一 operation_id 出现多条 committed 事件＝重复提交点，
          fail-closed。

        审计日志损坏（CorruptDataError）同样向上抛出，由调用方 fail-closed。
        """
        ledger = self._store.check_asset_ledger_semantics(wallet_id)
        committed_ops: dict[str, dict] = {
            op_id: record
            for op_id, record in ledger["operations"].items()
            if record["state"] == "committed"
        }
        pending_ops = {
            op_id
            for op_id, record in ledger["operations"].items()
            if record["state"] == "pending"
        }
        events = self._audit.events_by_type(
            wallet_id, audit.TYPE_ASSET_OPERATION_COMMITTED
        )
        events_by_op: dict[str, dict] = {}
        for event in events:
            op_id = event.get("request_id")
            details = event.get("details")
            if not isinstance(op_id, str):
                raise RecoveryError(
                    f"wallet {wallet_id!r} has an asset_operation_committed "
                    "event without an operation id"
                )
            if op_id in events_by_op:
                # 重复提交点：绝不任取一条
                raise RecoveryError(
                    f"wallet {wallet_id!r} has multiple committed events for "
                    f"asset operation {op_id!r}"
                )
            if (
                not isinstance(details, dict)
                or details.get("operation_id") != op_id
                or not isinstance(details.get("asset_id"), str)
                or not isinstance(details.get("delta"), int)
                or isinstance(details.get("delta"), bool)
                or details.get("delta") == 0
                or details.get("state") != "committed"
                or not isinstance(details.get("balance"), int)
                or isinstance(details.get("balance"), bool)
                or not isinstance(details.get("version"), int)
                or isinstance(details.get("version"), bool)
            ):
                raise RecoveryError(
                    f"wallet {wallet_id!r} committed event for {op_id!r} is "
                    "malformed"
                )
            events_by_op[op_id] = event
            if op_id in pending_ops:
                raise RecoveryError(
                    f"wallet {wallet_id!r} asset operation {op_id!r} is "
                    "pending but has a committed event"
                )
            record = committed_ops.get(op_id)
            if record is None:
                raise RecoveryError(
                    f"wallet {wallet_id!r} has a committed event for "
                    f"{op_id!r} but no committed ledger operation"
                )
            if details != record:
                raise RecoveryError(
                    f"wallet {wallet_id!r} committed event for {op_id!r} "
                    "does not match the ledger record"
                )
        if set(committed_ops) != set(events_by_op):
            missing = sorted(set(committed_ops) - set(events_by_op))
            raise RecoveryError(
                f"wallet {wallet_id!r} committed operations {missing!r} have "
                "no committed event"
            )

    def _reconcile_asset_cancelled_events(self, wallet_id: str) -> None:
        """账本 cancelled 操作与 asset_operation_cancelled 事件双向对账
        （调用方须持钱包事务锁；意图残留须已先恢复清零）。

        asset_operation_cancelled 是撤销的唯一提交点：

        - 每条 cancelled 操作必须恰有一条 details 与其视图逐字段一致的
          事件；事件 request_id 为 cancel_id、actor_id 为
          approval_request_id（均为非空字符串）；
        - 每条撤销事件必须对应一条账本 cancelled 操作
          （有事件无操作＝半应用/历史被删，fail-closed）；
        - pending/committed 操作不得有撤销事件；
        - 同一 cancel_id（request_id）出现多条＝重复提交点，fail-closed。
        """
        ledger = self._store.check_asset_ledger_semantics(wallet_id)
        cancelled_ops: dict[str, dict] = {
            op_id: record
            for op_id, record in ledger["operations"].items()
            if record["state"] == "cancelled"
        }
        events = self._audit.events_by_type(
            wallet_id, audit.TYPE_ASSET_OPERATION_CANCELLED
        )
        events_by_cancel: dict[str, dict] = {}
        cancelled_events_by_op: dict[str, dict] = {}
        for event in events:
            cancel_id = event.get("request_id")
            approval_id = event.get("actor_id")
            details = event.get("details")
            if not isinstance(cancel_id, str) or not isinstance(
                approval_id, str
            ):
                raise RecoveryError(
                    f"wallet {wallet_id!r} has an asset_operation_"
                    "cancelled event without cancel/approval identifiers"
                )
            if cancel_id in events_by_cancel:
                raise RecoveryError(
                    f"wallet {wallet_id!r} has multiple cancelled events for "
                    f"cancel_id {cancel_id!r}"
                )
            if (
                not isinstance(details, dict)
                or details.get("state") != "cancelled"
                or not isinstance(details.get("operation_id"), str)
                or not isinstance(details.get("asset_id"), str)
                or not isinstance(details.get("delta"), int)
                or isinstance(details.get("delta"), bool)
                or details.get("delta") == 0
                or not isinstance(details.get("balance"), int)
                or isinstance(details.get("balance"), bool)
                or not isinstance(details.get("version"), int)
                or isinstance(details.get("version"), bool)
            ):
                raise RecoveryError(
                    f"wallet {wallet_id!r} cancelled event for "
                    f"{cancel_id!r} is malformed"
                )
            op_id = details["operation_id"]
            record = ledger["operations"].get(op_id)
            if record is None:
                raise RecoveryError(
                    f"wallet {wallet_id!r} has a cancelled event for "
                    f"{op_id!r} but no such ledger operation"
                )
            if record["state"] != "cancelled":
                raise RecoveryError(
                    f"wallet {wallet_id!r} asset operation {op_id!r} is "
                    f"{record['state']} but has a cancelled event"
                )
            if details != record:
                raise RecoveryError(
                    f"wallet {wallet_id!r} cancelled event for {op_id!r} "
                    "does not match the ledger record"
                )
            if op_id in cancelled_events_by_op:
                raise RecoveryError(
                    f"wallet {wallet_id!r} has multiple cancelled events "
                    f"for asset operation {op_id!r}"
                )
            cancelled_events_by_op[op_id] = event
            events_by_cancel[cancel_id] = event
        if set(cancelled_events_by_op) != set(cancelled_ops):
            missing = sorted(
                set(cancelled_ops) - set(cancelled_events_by_op)
            )
            raise RecoveryError(
                f"wallet {wallet_id!r} cancelled operations {missing!r} "
                "have no cancelled event"
            )

    def _resolve_asset_transfer_intent(
        self, wallet_id: str, transfer_id: str, intent: object
    ) -> None:
        """对账单条转账提交意图：asset_transfer_committed 事件在则前滚
        落账，否则回滚到转账前现场。调用方须持钱包事务锁。恢复本身不记
        任何审计事件。

        与单资产提交同一判据：事件是否已持久化是唯一提交点。损坏/非对象/
        缺少恢复所需标识与整数的意图都无法安全对账：先 fail-closed 并
        保留意图现场原样，绝不借"事件在即可前滚"之名把损坏意图删除或
        继续提交/回滚/清理。
        """
        if not self._store.valid_asset_transfer_intent(transfer_id, intent):
            raise RecoveryError(
                f"wallet {wallet_id!r} asset transfer {transfer_id!r} "
                "intent is missing or malformed and cannot be reconciled"
            )
        committed = intent["committed"]
        from_asset_id = intent["from_asset_id"]
        to_asset_id = intent["to_asset_id"]
        event = self._audit.find_event_by_request(
            wallet_id,
            audit.TYPE_ASSET_TRANSFER_COMMITTED,
            transfer_id,
        )
        if event is not None:
            # 唯一提交点已落盘：严格核对事件 details 就是本意图的转账
            # 视图 R，再按 R 绝对补齐账本（两个资产条目按 R 绝对值校正，
            # 不重复应用 amount），绝不重复记事件。
            if event.get("details") != committed:
                raise RecoveryError(
                    f"wallet {wallet_id!r} asset transfer {transfer_id!r} "
                    "intent does not match its committed event"
                )
            self._store.commit_asset_transfer(
                wallet_id,
                transfer_id,
                committed,
                from_asset_id,
                {
                    "balance": committed["from_balance"],
                    "version": committed["from_version"],
                },
                to_asset_id,
                {
                    "balance": committed["to_balance"],
                    "version": committed["to_version"],
                },
            )
            self._store.delete_asset_commit_intent(wallet_id, transfer_id)
            return
        # 事件未持久化：转账未生效，凭意图记录的转账前快照删除转账记录、
        # 两个资产恢复原 balance/version（转账前不存在则删除资产条目）。
        # 事件从未分配 seq，故无事件、无 seq 缺口，可重新转账。
        self._store.restore_asset_transfer(
            wallet_id,
            transfer_id,
            from_asset_id,
            intent["old_from_asset"],
            to_asset_id,
            intent["old_to_asset"],
        )
        self._store.delete_asset_commit_intent(wallet_id, transfer_id)

    def _reconcile_asset_transfer_events(self, wallet_id: str) -> None:
        """账本已提交转账与 asset_transfer_committed 事件双向对账
        （调用方须持钱包事务锁；意图残留须已先恢复清零）。

        asset_transfer_committed 是转账的唯一提交点：

        - 每条已提交转账必须恰有一条同 request_id 的事件，``details``
          与账本中的转账视图 R 逐字段一致；
        - 每条转账事件必须对应一条账本已提交转账（有事件无记录＝事件
          被半应用或历史被删，fail-closed）；
        - 同一 transfer_id 出现多条转账事件＝重复提交点，fail-closed。

        审计日志损坏（CorruptDataError）同样向上抛出，由调用方 fail-closed。
        """
        ledger = self._store.check_asset_ledger_semantics(wallet_id)
        transfers = ledger["transfers"]
        events = self._audit.events_by_type(
            wallet_id, audit.TYPE_ASSET_TRANSFER_COMMITTED
        )
        events_by_transfer: dict[str, dict] = {}
        for event in events:
            transfer_id = event.get("request_id")
            details = event.get("details")
            if not isinstance(transfer_id, str):
                raise RecoveryError(
                    f"wallet {wallet_id!r} has an asset_transfer_committed "
                    "event without a transfer id"
                )
            if transfer_id in events_by_transfer:
                # 重复提交点：绝不任取一条
                raise RecoveryError(
                    f"wallet {wallet_id!r} has multiple committed events "
                    f"for asset transfer {transfer_id!r}"
                )
            if not self._transfer_details_shape_ok(details):
                raise RecoveryError(
                    f"wallet {wallet_id!r} committed event for asset "
                    f"transfer {transfer_id!r} is malformed"
                )
            events_by_transfer[transfer_id] = event
            record = transfers.get(transfer_id)
            if record is None:
                raise RecoveryError(
                    f"wallet {wallet_id!r} has a committed event for asset "
                    f"transfer {transfer_id!r} but no ledger transfer"
                )
            if details != record:
                raise RecoveryError(
                    f"wallet {wallet_id!r} committed event for asset "
                    f"transfer {transfer_id!r} does not match the ledger "
                    "record"
                )
        if set(transfers) != set(events_by_transfer):
            missing = sorted(set(transfers) - set(events_by_transfer))
            raise RecoveryError(
                f"wallet {wallet_id!r} committed asset transfers "
                f"{missing!r} have no committed event"
            )

    @staticmethod
    def _transfer_details_shape_ok(details: object) -> bool:
        """转账事件 R 的形状：恰含九键（transfer_id/from_asset_id/
        to_asset_id/amount/state/from_balance/from_version/to_balance/
        to_version），两个资产均为安全标识且不同，amount 为非布尔正整数，
        state 恒 committed，from_balance 为非布尔非负整数，from_version/
        to_version 为非布尔正整数，to_balance 为非布尔整数。形状矛盾属
        不可对账现场（503），绝不任取或跳过。"""
        if not isinstance(details, dict) or set(details) != {
            "transfer_id",
            "from_asset_id",
            "to_asset_id",
            "amount",
            "state",
            "from_balance",
            "from_version",
            "to_balance",
            "to_version",
        }:
            return False
        if not isinstance(details["transfer_id"], str):
            return False
        if not isinstance(details["from_asset_id"], str) or not isinstance(
            details["to_asset_id"], str
        ):
            return False
        if details["from_asset_id"] == details["to_asset_id"]:
            return False
        if (
            not isinstance(details["amount"], int)
            or isinstance(details["amount"], bool)
            or details["amount"] <= 0
        ):
            return False
        if details["state"] != "committed":
            return False
        for key in (
            "from_balance",
            "from_version",
            "to_balance",
            "to_version",
        ):
            if not isinstance(details[key], int) or isinstance(
                details[key], bool
            ):
                return False
        return (
            details["from_balance"] >= 0
            and details["from_version"] >= 1
            and details["to_version"] >= 1
        )

    def _resolve_asset_cancel_intent(
        self, wallet_id: str, operation_id: str, intent: object
    ) -> None:
        """对账单条撤销意图：事件在则前滚为 cancelled，否则回滚为
        pending。调用方须持钱包事务锁。恢复本身不记任何审计事件。"""
        if not self._store.valid_asset_cancel_intent(operation_id, intent):
            raise RecoveryError(
                f"wallet {wallet_id!r} asset operation {operation_id!r} "
                "cancel intent is missing or malformed and cannot be "
                "reconciled"
            )
        cancel_id = intent["cancel_id"]
        approval_request_id = intent["approval_request_id"]
        pending = intent["pending"]
        asset_id = intent["asset_id"]
        old_asset = intent["old_asset"]
        cancelled_record = dict(pending)
        cancelled_record["state"] = "cancelled"
        event = self._audit.find_event_by_request(
            wallet_id,
            audit.TYPE_ASSET_OPERATION_CANCELLED,
            cancel_id,
        )
        if event is not None:
            # 唯一提交点已落盘：严格核对事件就是本意图的撤销事件
            # （同 cancel_id、同审批单、details 即 cancelled 视图），再
            # 按事件绝对补齐账本，绝不重复记事件。
            if (
                event.get("actor_id") != approval_request_id
                or event.get("details") != cancelled_record
            ):
                raise RecoveryError(
                    f"wallet {wallet_id!r} asset operation "
                    f"{operation_id!r} cancel intent does not match its "
                    "cancelled event"
                )
            self._store.cancel_asset_operation(
                wallet_id, operation_id, cancelled_record
            )
            self._store.delete_asset_cancel_intent(wallet_id, operation_id)
            return
        # 事件未持久化：撤销未生效，凭意图快照把操作恢复为 pending、
        # 资产原样还原（撤销从不改 balance/version）。事件从未分配 seq，
        # 故事件与 seq 均无缺口，可重新撤销/提交。
        self._store.restore_asset_operation(
            wallet_id,
            operation_id,
            pending,
            asset_id,
            old_asset if isinstance(old_asset, dict) else None,
        )
        self._store.delete_asset_cancel_intent(wallet_id, operation_id)

    def _resolve_asset_commit_intent(
        self, wallet_id: str, operation_id: str, intent: object
    ) -> Optional[dict]:
        """对账单条提交意图，返回 committed 视图 R（前滚）或 None（回滚）。"""
        # 无论提交事件是否已落盘，损坏/非对象/缺少恢复所需标识与整数的
        # 意图都无法安全对账：先 fail-closed 并保留意图现场原样，绝不借
        # "事件在即可前滚"之名把损坏意图删除或继续提交/回滚/清理。
        if not self._store.valid_asset_commit_intent(operation_id, intent):
            raise RecoveryError(
                f"wallet {wallet_id!r} asset operation {operation_id!r} "
                "commit intent is missing or malformed and cannot be reconciled"
            )
        # 报告触发的提交在意图中随附达门槛报告 B：报告事件与提交事件同批
        # 原子落盘，恢复据此核对两事件提交点完整且紧邻同体。
        report = intent.get("report")
        event = self._audit.find_event_by_request(
            wallet_id,
            audit.TYPE_ASSET_OPERATION_COMMITTED,
            operation_id,
        )
        if event is not None:
            details = event.get("details")
            asset_id = details.get("asset_id") if isinstance(details, dict) else None
            balance = details.get("balance") if isinstance(details, dict) else None
            version = details.get("version") if isinstance(details, dict) else None
            delta = details.get("delta") if isinstance(details, dict) else None
            # 仅当前滚目标是形状完整的 R 时才补齐；事件损坏（原子写使
            # 正常崩溃不会出现，此处只防御外部篡改）无法安全对账，fail-closed。
            if (
                not isinstance(details, dict)
                or not isinstance(asset_id, str)
                or not isinstance(delta, int)
                or isinstance(delta, bool)
                or not isinstance(balance, int)
                or isinstance(balance, bool)
                or not isinstance(version, int)
                or isinstance(version, bool)
            ):
                raise RecoveryError(
                    f"wallet {wallet_id!r} asset operation "
                    f"{operation_id!r} committed event is malformed"
                )
            if report is not None:
                self._check_report_commit_pair(
                    wallet_id, operation_id, event, report
                )
            vote = intent.get("vote")
            if vote is not None:
                # 多源仲裁达 quorum 的提交：决定性 adopted 票、chain_report
                # 与提交事件三事件同批紧邻落盘。报告对（seq-1）已由上方
                # 核对，这里再核对 seq-2 是同操作、同体的 adopted 票。
                self._check_vote_commit_triple(
                    wallet_id, operation_id, event, vote
                )
            settle = intent.get("settle")
            if settle is not None:
                # 最终性结算：chain_dispatch_settled 与提交事件两事件同批
                # 紧邻落盘（seq 为 n、n+1），核对紧邻前驱是同派发、同
                # 操作的结算事件。
                self._check_settle_commit_pair(
                    wallet_id, settle["dispatch_id"], event
                )
            reorg = intent.get("reorg")
            if reorg is not None:
                # 重组补偿：重组确认、重组与提交三事件同批紧邻落盘
                # （seq 为 n、n+1、n+2），核对紧邻前两条是同派发的
                # chain_dispatch_reorged 与同体的 chain_dispatch_
                # confirmation（state=reorged）。
                self._check_reorg_commit_triple(
                    wallet_id,
                    reorg["dispatch_id"],
                    event,
                    reorg["confirmation"],
                )
            committed_record = {
                "operation_id": operation_id,
                "asset_id": asset_id,
                "state": "committed",
                "delta": delta,
                "balance": balance,
                "version": version,
            }
            asset_record = {"balance": balance, "version": version}
            # 按事件 R 绝对补齐：即使账本已部分落盘也不重复加 delta、
            # 不产生重复 version
            self._store.commit_asset_operation(
                wallet_id,
                operation_id,
                committed_record,
                asset_id,
                asset_record,
            )
            self._store.delete_asset_commit_intent(wallet_id, operation_id)
            return committed_record

        # 事件未持久化：提交未生效，凭意图记录的提交前快照把操作恢复为
        # pending、资产恢复提交前 balance/version（意图已在方法入口通过
        # 严格校验，标识/整数/守恒均可信）。提交前不存在该资产条目时
        # 直接删除；事件从未分配 seq，故无事件、无 seq 缺口、可重试。
        if report is not None:
            # 报告触发的提交：报告事件与提交事件同批原子落盘，提交事件
            # 缺失即意图随附的报告事件也不可能落盘。回滚前重放该操作
            # 既有历史报告严格判定——只有历史是合法前缀、且意图随附
            # 报告是唯一合法下一报（合法顺延且达门槛）时回滚才安全，
            # 前序报告事件原样保留；历史已含同体报告或任何一步无法
            # 判定都是崩溃窗口外的矛盾现场（外部篡改/半写），
            # fail-closed 保留现场，绝不静默回滚抹掉证据后继续服务。
            self._check_report_rollback_prefix(
                wallet_id, operation_id, intent, report
            )
            if intent.get("vote") is not None:
                # 仲裁触发的提交：另须严格判定意图票是唯一合法的下一
                # adopted（quorum）票，历史票序列与策略自洽。
                self._check_vote_rollback_prefix(
                    wallet_id, operation_id, intent, intent["vote"]
                )
            if intent.get("settle") is not None:
                # 最终性结算：结算事件与提交事件同批原子落盘，提交事件
                # 缺失即结算事件也不可能落盘。审计中已存在该派发的结算
                # 事件即崩溃窗口外的矛盾现场（外部篡改/半写），fail-closed
                # 保留现场，绝不静默回滚抹掉证据。
                self._check_settle_rollback_prefix(
                    wallet_id, intent["settle"]["dispatch_id"]
                )
        reorg = intent.get("reorg")
        if reorg is not None:
            # 重组补偿：重组确认、重组与提交三事件同批原子落盘，提交事件
            # 缺失即重组确认/重组事件也不可能落盘。审计中已存在该派发的
            # 重组（或 reorged 确认）事件却没有对应提交事件即崩溃窗口外
            # 的矛盾现场（外部篡改/半写），fail-closed 保留现场，绝不
            # 静默回滚抹掉证据。
            self._check_reorg_rollback_prefix(
                wallet_id, reorg["dispatch_id"]
            )
        pending = intent["pending"]
        asset_id = intent["asset_id"]
        old_asset = intent["old_asset"]
        if reorg is not None:
            # 补偿操作由本事务新建（事务前账本中不存在）：回滚是删除该
            # 操作而非还原为 pending，资产恢复提交前 balance/version。
            self._store.remove_asset_operation(
                wallet_id,
                operation_id,
                asset_id,
                old_asset if isinstance(old_asset, dict) else None,
            )
        else:
            self._store.restore_asset_operation(
                wallet_id,
                operation_id,
                pending,
                asset_id,
                old_asset if isinstance(old_asset, dict) else None,
            )
        self._store.delete_asset_commit_intent(wallet_id, operation_id)
        return None

    def _check_report_commit_pair(
        self,
        wallet_id: str,
        operation_id: str,
        commit_event: dict,
        report: dict,
    ) -> None:
        """核对报告触发提交的两事件提交点：提交事件的前一条必须是同操作、
        同体（与意图随附报告逐字段一致）的 chain_report 事件。

        两事件同批原子落盘且紧邻（seq 为 n、n+1）；前条缺失、类型/操作
        不符或报告内容不一致都是不可对账的矛盾现场（RecoveryError，
        fail-closed，保留现场），绝不任选一条继续前滚。
        """
        commit_seq = commit_event.get("seq")
        predecessor = None
        if isinstance(commit_seq, int) and not isinstance(commit_seq, bool):
            for candidate in self._audit.all_events(wallet_id):
                if candidate.get("seq") == commit_seq - 1:
                    predecessor = candidate
                    break
        if (
            predecessor is None
            or predecessor.get("type") != audit.TYPE_CHAIN_REPORT
            or predecessor.get("request_id") != operation_id
            or predecessor.get("details") != report
        ):
            raise RecoveryError(
                f"wallet {wallet_id!r} committed asset operation "
                f"{operation_id!r} without an adjacent matching chain "
                "report event"
            )

    def _check_report_rollback_prefix(
        self,
        wallet_id: str,
        operation_id: str,
        intent: dict,
        report: dict,
    ) -> None:
        """回滚带报告意图前的严格判定（提交事件缺失时，调用方须持锁）。

        重放该操作既有历史报告（seq 升序）：只有历史是合法前缀、且意图
        随附报告是唯一合法下一报（相对历史末报合法顺延且达门槛）时才
        允许回滚——前序报告事件都是在线正常落盘的，意图随附报告从未
        成为事件。以下现场都无法安全判定，一律 RecoveryError（
        fail-closed，原样保留现场，绝不猜写）：

        - 历史已含同体报告：报告事件在而提交事件缺失，同批原子落盘的
          崩溃绝不可能留下这种现场（外部篡改/半写）；
        - 策略缺失/未启用/策略链与意图报告不符；
        - 历史前缀非法（换 tx/换链、同块确认数下降、回退越窗、低于
          门槛的重复报告），或历史中混有达门槛报告（其紧邻提交事件
          缺失即矛盾）；
        - 意图报告不能合法顺延历史末报，或未达门槛（未达门槛的报告
          在线绝不会触发提交意图）。
        """
        history: list[dict] = []
        for event in self._audit.events_by_type(
            wallet_id, audit.TYPE_CHAIN_REPORT
        ):
            past_operation, past = self._chain_report_shape(wallet_id, event)
            if past_operation == operation_id:
                history.append(past)
        for past in history:
            if past == report:
                raise RecoveryError(
                    f"wallet {wallet_id!r} has a chain_report event for "
                    f"asset operation {operation_id!r} without its "
                    "committed event"
                )
        policy = self._chain_policies(wallet_id).get(intent["asset_id"])
        if (
            policy is None
            or not policy["enabled"]
            or policy["chain_id"] != report["chain_id"]
        ):
            raise RecoveryError(
                f"wallet {wallet_id!r} report intent for asset operation "
                f"{operation_id!r} has no matching enabled chain policy"
            )
        last: Optional[dict] = None
        for past in history:
            error = self._report_transition_error(policy, last, past)
            if (
                error is not None
                or past["chain_id"] != policy["chain_id"]
                or past["confirmations"] >= policy["required_confirmations"]
            ):
                raise RecoveryError(
                    f"wallet {wallet_id!r} has an inconsistent chain_report "
                    f"history for asset operation {operation_id!r}"
                )
            last = past
        error = self._report_transition_error(policy, last, report)
        if (
            error is not None
            or report["confirmations"] < policy["required_confirmations"]
        ):
            raise RecoveryError(
                f"wallet {wallet_id!r} report intent for asset operation "
                f"{operation_id!r} is not the legal next report"
            )

    def _check_vote_commit_triple(
        self,
        wallet_id: str,
        operation_id: str,
        commit_event: dict,
        vote: dict,
    ) -> None:
        """核对仲裁提交三事件提交点：提交事件的前两条必须依次是同操作、
        同体的 chain_report(B) 与决定性 adopted 票 chain_vote。

        三事件同批原子落盘且紧邻（seq 为 n、n+1、n+2）；前序缺失、
        类型/操作不符或票内容不一致都是不可对账的矛盾现场
        （RecoveryError，fail-closed，保留现场）。紧邻报告对已由
        _check_report_commit_pair 核对，这里只核对再前一条的票。
        """
        commit_seq = commit_event.get("seq")
        vote_predecessor = None
        if isinstance(commit_seq, int) and not isinstance(commit_seq, bool):
            for candidate in self._audit.all_events(wallet_id):
                if candidate.get("seq") == commit_seq - 2:
                    vote_predecessor = candidate
                    break
        expected_vote = {
            "source": vote["source"],
            "report": vote["report"],
            "state": "adopted",
        }
        if (
            vote_predecessor is None
            or vote_predecessor.get("type") != audit.TYPE_CHAIN_VOTE
            or vote_predecessor.get("request_id") != operation_id
            or vote_predecessor.get("details") != expected_vote
        ):
            raise RecoveryError(
                f"wallet {wallet_id!r} committed asset operation "
                f"{operation_id!r} without an adjacent adopted chain_vote "
                "event"
            )

    def _check_vote_rollback_prefix(
        self,
        wallet_id: str,
        operation_id: str,
        intent: dict,
        vote: dict,
    ) -> None:
        """回滚仲裁触发提交意图前的严格判定（提交事件缺失时，调用方须持
        锁）。

        三事件（票 + 报告 + 提交）同批原子落盘：提交事件缺失则意图随附
        的票与报告也从未成为事件。重放该操作既有历史票（seq 升序）严格
        判定——当时仲裁策略须存在且 source 启用、报告链与跨链策略链
        一致、无重复 source 的票，且意图随附票必须是唯一合法的下一
        adopted 票（历史同体票计数 + 1 恰达当时 quorum、票报告与意图
        报告同体）。任何一步无法判定都是崩溃窗口外的矛盾现场
        （RecoveryError，fail-closed，原样保留现场）。
        """
        report = intent["report"]
        if not isinstance(report, dict):
            raise RecoveryError(
                f"wallet {wallet_id!r} vote intent for asset operation "
                f"{operation_id!r} is missing its report"
            )
        history: list[dict] = []
        for event in self._audit.events_by_type(
            wallet_id, audit.TYPE_CHAIN_VOTE
        ):
            # 策略事件（details {sources,quorum}）与观察票共用类型，
            # 按精确键集跳过策略；键集两者皆非即畸形事件，绝不静默忽略，
            # 直接 fail-closed（保留现场）。
            kind = self._chain_vote_event_kind(event)
            if kind == "policy":
                continue
            if kind is None:
                raise RecoveryError(
                    f"wallet {wallet_id!r} has a malformed chain_vote event"
                )
            past_operation, past = self._vote_shape(wallet_id, event)
            if past_operation == operation_id:
                history.append(past)
        # 历史不得已含同源票（在线重放不记事件，同批崩溃也不可能留下
        # 意图随附票），也不得已有 adopted 票。
        for past in history:
            if (
                past["source"] == vote["source"]
                or past["state"] == "adopted"
            ):
                raise RecoveryError(
                    f"wallet {wallet_id!r} has a chain_vote event for "
                    f"asset operation {operation_id!r} without its committed "
                    "event"
                )
        ledger = self._store.check_asset_ledger_semantics(wallet_id)
        record = ledger["operations"].get(operation_id)
        if record is None:
            raise RecoveryError(
                f"wallet {wallet_id!r} vote intent for asset operation "
                f"{operation_id!r} has no ledger operation"
            )
        # 策略取该资产最后一条仲裁策略（与在线一致，合并新旧事件）；
        # 逐历史票重放校验。
        arb_policies = self._chain_arbitration_policies(wallet_id)
        chain_policies = self._chain_policies(wallet_id)
        policy = arb_policies.get(record["asset_id"])
        chain_policy = chain_policies.get(record["asset_id"])
        if policy is None or chain_policy is None or not chain_policy["enabled"]:
            raise RecoveryError(
                f"wallet {wallet_id!r} vote intent for asset operation "
                f"{operation_id!r} has no matching arbitration/chain policy"
            )
        if report["chain_id"] != chain_policy["chain_id"]:
            raise RecoveryError(
                f"wallet {wallet_id!r} vote intent for asset operation "
                f"{operation_id!r} is on a different chain"
            )
        if not policy["sources"].get(vote["source"], False):
            raise RecoveryError(
                f"wallet {wallet_id!r} vote intent for asset operation "
                f"{operation_id!r} comes from a disabled source"
            )
        if vote["report"] != report or vote["state"] != "adopted":
            raise RecoveryError(
                f"wallet {wallet_id!r} vote intent for asset operation "
                f"{operation_id!r} does not match its report"
            )
        agreeing = [
            past for past in history if past["report"] == report
        ]
        if len(agreeing) + 1 != policy["quorum"]:
            # 意图票必须恰为达成 quorum 的决定性票（多则该源组合早已
            # adopted，少则不应触发提交），否则现场矛盾。
            raise RecoveryError(
                f"wallet {wallet_id!r} vote intent for asset operation "
                f"{operation_id!r} is not the deciding quorum vote"
            )

    def _check_settle_commit_pair(
        self,
        wallet_id: str,
        dispatch_id: str,
        commit_event: dict,
    ) -> None:
        """核对最终性结算两事件提交点：提交事件的前一条必须是同派发、
        同操作的 chain_dispatch_settled 事件。

        两事件同批原子落盘且紧邻（seq 为 n、n+1）；前条缺失或类型/派发/
        操作不符都是不可对账的矛盾现场（RecoveryError，fail-closed，保留
        现场），绝不任选一条继续前滚。"""
        commit_seq = commit_event.get("seq")
        predecessor = None
        if isinstance(commit_seq, int) and not isinstance(commit_seq, bool):
            for candidate in self._audit.all_events(wallet_id):
                if candidate.get("seq") == commit_seq - 1:
                    predecessor = candidate
                    break
        operation_id = commit_event.get("request_id")
        if (
            predecessor is None
            or predecessor.get("type") != audit.TYPE_CHAIN_DISPATCH_SETTLED
            or predecessor.get("request_id") != dispatch_id
            or predecessor.get("details")
            != {"dispatch_id": dispatch_id, "operation_id": operation_id}
        ):
            raise RecoveryError(
                f"wallet {wallet_id!r} committed asset operation "
                f"{operation_id!r} without an adjacent matching "
                "chain_dispatch_settled event"
            )

    def _check_settle_rollback_prefix(
        self,
        wallet_id: str,
        dispatch_id: str,
    ) -> None:
        """回滚结算意图前的严格判定（提交事件缺失时，调用方须持锁）。

        结算事件与提交事件同批原子落盘：提交事件缺失则结算事件也从未
        成为事件。审计中已存在该派发的 chain_dispatch_settled 事件却没有
        对应提交事件（走到这里说明没找到提交事件）即崩溃窗口外的矛盾
        现场（外部篡改/半写），fail-closed 原样保留现场，绝不猜写。"""
        grouped = self._audit.chain_dispatch_settled_events(wallet_id).get(
            dispatch_id
        )
        if grouped:
            raise RecoveryError(
                f"wallet {wallet_id!r} has a chain_dispatch_settled event "
                f"for {dispatch_id!r} without its committed event"
            )

    def _check_reorg_commit_triple(
        self,
        wallet_id: str,
        dispatch_id: str,
        commit_event: dict,
        confirmation: dict,
    ) -> None:
        """核对重组补偿三事件提交点：提交事件（request_id=D）的前两条
        必须是同派发的 chain_dispatch_reorged（seq-1）与同体 V 的
        chain_dispatch_confirmation（seq-2，state=reorged）。

        三事件同批原子落盘且紧邻（seq 为 n、n+1、n+2）；前条缺失或
        类型/派发/内容不符都是不可对账的矛盾现场（RecoveryError，
        fail-closed，保留现场），绝不任选一条继续前滚。"""
        commit_seq = commit_event.get("seq")
        reorged = confirmation_event = None
        if isinstance(commit_seq, int) and not isinstance(commit_seq, bool):
            for candidate in self._audit.all_events(wallet_id):
                if candidate.get("seq") == commit_seq - 1:
                    reorged = candidate
                elif candidate.get("seq") == commit_seq - 2:
                    confirmation_event = candidate
        if (
            reorged is None
            or reorged.get("type") != audit.TYPE_CHAIN_DISPATCH_REORGED
            or reorged.get("request_id") != dispatch_id
            or reorged.get("details")
            != {"dispatch_id": dispatch_id, "operation_id": dispatch_id}
            or confirmation_event is None
            or confirmation_event.get("type")
            != audit.TYPE_CHAIN_DISPATCH_CONFIRMATION
            or confirmation_event.get("request_id") != dispatch_id
            or confirmation_event.get("details") != confirmation
        ):
            raise RecoveryError(
                f"wallet {wallet_id!r} committed asset operation "
                f"{dispatch_id!r} without adjacent matching "
                "chain_dispatch_reorged and chain_dispatch_confirmation "
                "events"
            )

    def _check_reorg_rollback_prefix(
        self,
        wallet_id: str,
        dispatch_id: str,
    ) -> None:
        """回滚重组补偿意图前的严格判定（提交事件缺失时，调用方须持锁）。

        重组确认、重组与提交三事件同批原子落盘：提交事件缺失则重组
        确认/重组事件也从未成为事件。审计中已存在该派发的
        chain_dispatch_reorged 或 state=reorged 的
        chain_dispatch_confirmation 事件却没有对应提交事件（走到这里
        说明没找到提交事件）即崩溃窗口外的矛盾现场（外部篡改/半写），
        fail-closed 原样保留现场，绝不猜写。"""
        if self._audit.chain_dispatch_reorged_events(wallet_id).get(
            dispatch_id
        ):
            raise RecoveryError(
                f"wallet {wallet_id!r} has a chain_dispatch_reorged event "
                f"for {dispatch_id!r} without its committed event"
            )
        confirmations = self._audit.chain_dispatch_confirmation_events(
            wallet_id
        ).get(dispatch_id)
        for event in confirmations or []:
            details = event.get("details")
            if (
                isinstance(details, dict)
                and details.get("state") == "reorged"
            ):
                raise RecoveryError(
                    f"wallet {wallet_id!r} has a reorged "
                    f"chain_dispatch_confirmation event for {dispatch_id!r} "
                    "without its committed event"
                )

    #: expected_version 缺省哨兵：区别于显式传入（含 JSON null）
    _NO_EXPECTED_VERSION = object()

    def commit_asset_operation(
        self,
        wallet_id: str,
        operation_id: str,
        expected_version: object = _NO_EXPECTED_VERSION,
    ) -> tuple[int, dict]:
        """提交一条 pending 的资产操作（可恢复事务）。返回 (状态码, R)。

        事务顺序（全部在每钱包跨进程事务锁内）::

            1. 写提交意图（记录 committed 结果 R 与提交前资产快照）
            2. 原子提交账本：操作转 committed、balance 改、version+1
            3. 追加唯一的 asset_operation_committed 事件（details=R，
               request_id=operation_id）
            4. 删除提交意图

        崩溃恢复以事件是否落盘为准：事件在则前滚补齐，事件不在则回滚
        pending 与提交前余额/版本。故任何阶段被强制终止，重启后都不会
        出现提交无事件、事件与余额不符、重复 version 或重复事件。

        余额不足 409 且无副作用；committed 重放 200 同体，不改账、不记事件。

        可选乐观版本校验：调用方声明 expected_version（非布尔非负整数，
        0 表示资产尚无提交版本）时，仅在操作仍为 pending 的前提下于锁内
        比较提交瞬间的资产 version（无资产条目按 0），不一致 409
        "asset version conflict"，操作保持 pending，余额/version/审计/
        摘要链/提交意图均不变，可用新版本重试；一致才继续原有冻结闸门、
        链上策略、余额不足与提交逻辑。committed 重放不重新比较，仍按原
        幂等规则 200；未声明时完全沿用旧的无条件提交语义。版本比较、
        余额计算、账本写入与提交事件在同一钱包锁内线性化：多个操作声明
        同一版本时至多一个 201。条件失败不创建恢复意图；已进入提交事务
        的请求仍按事件提交点前滚/回滚，恢复不再解释 expected_version。

        恢复检查、钱包存在性、operation_id 校验、幂等/状态判定与整个
        提交事务全部在锁内：绝不基于锁外快照决定 404/409 或重放。
        """
        try:
            return self._commit_asset_operation_tx(
                wallet_id, operation_id, expected_version
            )
        except CorruptDataError:
            raise
        except ValueError:
            # wallet_id 含非法字符（构造锁路径时抛出）
            raise ServiceError(400, "invalid wallet_id")

    def _commit_asset_operation_tx(
        self,
        wallet_id: str,
        operation_id: str,
        expected_version: object = _NO_EXPECTED_VERSION,
    ) -> tuple[int, dict]:
        with self._wallet_lock(wallet_id):
            # 先自愈他进程崩溃遗留的任何提交意图，再基于一致账本判定，
            # 绝不基于半完成状态提交。
            self._heal_wallet(wallet_id)
            # 404 优先于 400：锁内先判定钱包存在，再校验 operation_id
            self._get_wallet_or_404(wallet_id)
            self._assert_wallet_active_locked(wallet_id)
            self._validate_operation_id(operation_id)
            if expected_version is not self._NO_EXPECTED_VERSION:
                self._validate_expected_version(expected_version)

            record = self._store.get_asset_operation(wallet_id, operation_id)
            if record is None:
                raise ServiceError(
                    404, f"asset operation {operation_id!r} not found"
                )
            # 乐观版本校验：仅 pending 且声明了 expected_version 时，锁内
            # 读取提交瞬间的资产 version（不存在按 0），不一致 409 且零
            # 副作用（不写意图/账本/事件）；一致才走原有冻结闸门等流程。
            # committed/cancelled 不比较：committed 重放沿用原幂等规则。
            if (
                record["state"] == "pending"
                and expected_version is not self._NO_EXPECTED_VERSION
            ):
                asset = self._store.get_asset(wallet_id, record["asset_id"])
                current_version = (
                    asset["version"] if asset is not None else 0
                )
                if current_version != expected_version:
                    raise ServiceError(409, "asset version conflict")
            # 资产粒度冻结闸门：先于 committed 幂等重放（frozen 时重放也
            # 一律 409），不改账、不记事件。
            self._assert_asset_active_locked(
                wallet_id, record["asset_id"]
            )
            if record["state"] == "committed":
                # 幂等重放：不重复改账、不记事件
                return 200, record
            if record["state"] != "pending":
                raise ServiceError(
                    409,
                    f"asset operation {operation_id!r} is "
                    f"{record['state']}, not pending",
                )
            # 资产已启用跨链确认策略时，pending 操作只能经链上确认报告
            # 达门槛后提交，人工提交一律 409（committed 重放不受影响）
            policy = self._chain_policies(wallet_id).get(record["asset_id"])
            if policy is not None and policy["enabled"]:
                raise ServiceError(
                    409,
                    f"asset {record['asset_id']!r} requires chain "
                    "confirmation reports to commit",
                )
            committed_record = self._commit_asset_operation_locked(
                wallet_id, operation_id, record
            )
        return 201, committed_record

    def cancel_asset_operation(
        self,
        wallet_id: str,
        operation_id: object,
        cancel_id: object,
        approval_request_id: object,
    ) -> tuple[int, dict]:
        """撤销一条 pending 的资产操作（可恢复事务）。

        撤销复用同钱包审批单：approval_request_id 必须指向一条 approved
        审批单，其 message 必须逐字等于按 operation_id,cancel_id 排列的
        紧凑 JSON。成功只把操作转为 cancelled（balance/version 不变、
        未落账不创建资产条目），并在同一钱包跨进程事务锁内追加唯一的
        asset_operation_cancelled 事件（request_id=cancel_id、
        actor_id=approval_request_id、details 为 cancelled 操作视图）。

        首次成功 201；同 cancel_id、同操作、同审批参数的重放优先 200。
        同 cancel_id 异参、撤销 committed/cancelled 操作、同一操作已有
        其他 cancel_id、或与 commit 并发落败均 409 且账本/version/审计
        不变。请求体/ID 非法 400；钱包、操作或审批单不存在 404；审批单
        非 approved、过期或 message 异文 409。冻结钱包沿用 409 闸门。
        """
        try:
            return self._cancel_asset_operation_tx(
                wallet_id, operation_id, cancel_id, approval_request_id
            )
        except CorruptDataError:
            raise
        except ValueError:
            # wallet_id 含非法字符（构造锁路径时抛出）
            raise ServiceError(400, "invalid wallet_id")

    def _cancel_asset_operation_tx(
        self,
        wallet_id: str,
        operation_id: object,
        cancel_id: object,
        approval_request_id: object,
    ) -> tuple[int, dict]:
        with self._wallet_lock(wallet_id):
            # 与提交共用同一把钱包事务锁：取消与提交在锁内竞争，落败方
            # 基于已收敛账本只能看到 committed/cancelled 终态，得 409。
            self._heal_wallet(wallet_id)
            # 404 优先于 400；冻结闸门先于一切业务/幂等判定（冻结期即便
            # 命中重放也一律 409）。
            self._get_wallet_or_404(wallet_id)
            self._assert_wallet_active_locked(wallet_id)
            self._validate_operation_id(operation_id)
            self._validate_cancel_id(cancel_id)
            self._validate_approval_request_id_ref(approval_request_id)

            record = self._store.get_asset_operation(wallet_id, operation_id)
            if record is None:
                raise ServiceError(
                    404, f"asset operation {operation_id!r} not found"
                )
            # 资产粒度冻结闸门：先于审批单查询、幂等重放与一切业务判定
            # （frozen 时即便同参重放也一律 409，账本/version/审计不变）。
            self._assert_asset_active_locked(
                wallet_id, record["asset_id"]
            )
            approval = self._store.get_request(
                wallet_id, approval_request_id
            )
            if approval is None:
                raise ServiceError(
                    404,
                    f"approval request {approval_request_id!r} not found",
                )

            cancel_events = {
                event.get("request_id"): event
                for event in self._audit.events_by_type(
                    wallet_id, audit.TYPE_ASSET_OPERATION_CANCELLED
                )
            }
            prior_for_cancel = cancel_events.get(cancel_id)
            op_event = next(
                (
                    event
                    for event in cancel_events.values()
                    if event.get("details", {}).get("operation_id")
                    == operation_id
                ),
                None,
            )
            # 唯一取消提交点已存在时，三键完全相同的重放优先成功，并且
            # 不再复查审批单当前状态（其后可因签名推进为 signed）。
            if (
                prior_for_cancel is not None
                and prior_for_cancel is op_event
                and prior_for_cancel.get("actor_id") == approval_request_id
            ):
                return 200, record
            # cancel_id 已指向他操作/他审批，或本操作已有其他取消提交点：
            # 均为异参重放，409 且零副作用。
            if prior_for_cancel is not None or op_event is not None:
                raise ServiceError(
                    409,
                    f"cancel_id {cancel_id!r} was already used with "
                    "different parameters",
                )

            # 以下仅适用于首次撤销：失败不写意图、账本或事件。过期判定
            # 只读，不在这里懒落 request_expired（与"撤销失败零副作用"
            # 契约一致）。
            approval_state = approval.get("state")
            if (
                approval_state == "pending"
                and datetime.now(timezone.utc)
                >= _parse_iso(approval["t1"])
            ):
                approval_state = "expired"
            expected_message = self._cancel_approval_message(
                operation_id, cancel_id
            )
            if approval.get("message") != expected_message:
                raise ServiceError(
                    409,
                    "approval request message does not match this cancel",
                )
            if approval_state != "approved":
                raise ServiceError(
                    409,
                    f"approval request {approval_request_id!r} is "
                    f"{approval_state}, not approved",
                )

            if record["state"] == "cancelled":
                raise ServiceError(
                    409,
                    f"asset operation {operation_id!r} is already cancelled",
                )
            if record["state"] == "committed":
                # 与提交并发落败或撤销已落账操作：409 且零副作用
                raise ServiceError(
                    409,
                    f"asset operation {operation_id!r} is committed and "
                    "cannot be cancelled",
                )
            cancelled_record = self._cancel_asset_operation_locked(
                wallet_id,
                operation_id,
                record,
                cancel_id,
                approval_request_id,
            )
        return 201, cancelled_record

    def _cancel_asset_operation_locked(
        self,
        wallet_id: str,
        operation_id: str,
        record: dict,
        cancel_id: str,
        approval_request_id: str,
    ) -> dict:
        """在每钱包事务锁内撤销一条 pending 操作，返回 cancelled 视图。

        调用方须已持锁、已 heal、已判定 record 为 pending 且审批门控通过。
        事务顺序：

            1. 写撤销意图（记录 pending 快照与资产快照 old_asset）
            2. 原子置操作状态为 cancelled（balance/version/资产条目不动）
            3. 追加唯一的 asset_operation_cancelled 事件（唯一提交点）
            4. 删除撤销意图

        崩溃恢复以事件是否落盘为准：事件在前滚为 cancelled，事件不在
        回滚为 pending，账本余额/version 始终不变。
        """
        asset_id = record["asset_id"]
        asset = self._store.get_asset(wallet_id, asset_id)
        cancelled_record = dict(record)
        cancelled_record["state"] = "cancelled"
        intent = {
            "kind": "cancel",
            "operation_id": operation_id,
            "asset_id": asset_id,
            "cancel_id": cancel_id,
            "approval_request_id": approval_request_id,
            "pending": record,
            "old_asset": asset,
        }
        try:
            self._store.write_asset_cancel_intent(
                wallet_id, operation_id, intent
            )
            self._store.cancel_asset_operation(
                wallet_id, operation_id, cancelled_record
            )
            self._emit(
                wallet_id,
                self._audit_event(
                    audit.TYPE_ASSET_OPERATION_CANCELLED,
                    request_id=cancel_id,
                    actor_id=approval_request_id,
                    details=cancelled_record,
                ),
            )
        except BaseException:
            # 与提交同构：事件真正落盘（如落盘成功但返回阶段报错）则
            # 前滚为唯一 cancelled，绝不重复记事件；否则回滚 pending。
            landed = self._audit.find_event_by_request(
                wallet_id,
                audit.TYPE_ASSET_OPERATION_CANCELLED,
                cancel_id,
            )
            if (
                landed is not None
                and landed.get("actor_id") == approval_request_id
                and landed.get("details") == cancelled_record
            ):
                self._store.cancel_asset_operation(
                    wallet_id, operation_id, cancelled_record
                )
                self._store.delete_asset_cancel_intent(
                    wallet_id, operation_id
                )
                return cancelled_record
            self._store.restore_asset_operation(
                wallet_id, operation_id, record, asset_id, asset
            )
            self._store.delete_asset_cancel_intent(wallet_id, operation_id)
            raise
        self._store.delete_asset_cancel_intent(wallet_id, operation_id)
        return cancelled_record

    def _commit_asset_operation_locked(
        self,
        wallet_id: str,
        operation_id: str,
        record: dict,
        report_details: dict | None = None,
        vote_details: dict | None = None,
        settle_dispatch_id: str | None = None,
        settle_adapter_id: str | None = None,
    ) -> dict:
        """在每钱包事务锁内提交一条 pending 操作，返回 committed 视图 R。

        调用方须已持锁、已 heal、已判定 record 为 pending。事务顺序：

            1. 写提交意图（记录 committed 结果 R 与提交前资产快照；
               报告触发的提交另随附达门槛报告 B，多源仲裁触发的提交
               另随附达成 quorum 的 adopted 票，最终性结算另随附
               {"dispatch_id": D}）
            2. 原子提交账本：操作转 committed、balance 改、version+1
            3. 追加提交事件（report_details/vote_details/settle_dispatch_id
               非 None 时，触发事件 chain_report/chain_vote/
               chain_dispatch_settled 与 asset_operation_committed 同批
               一次原子落盘，seq 连续，触发事件在先）
            4. 删除提交意图

        链上确认报告达门槛触发的提交传入 report_details；多源仲裁
        quorum 达成触发的提交传入 vote_details；跨链派发最终性结算传入
        settle_dispatch_id（触发事件链为 chain_dispatch_settled +
        asset_operation_committed 两事件）：触发事件与提交事件紧邻同批
        落盘，构成"触发事件后紧邻唯一提交事件"的单一提交点，崩溃窗口内
        绝不出现孤立触发事件或 seq 缺口。崩溃恢复以提交事件是否落盘为
        准：事件在则前滚补齐（并核对紧邻触发事件与意图随附内容一致），
        事件不在则整体回滚 pending 与提交前余额/版本。
        """
        asset_id = record["asset_id"]
        asset = self._store.get_asset(wallet_id, asset_id)
        old_balance = asset["balance"] if asset is not None else 0
        old_version = asset["version"] if asset is not None else 0
        new_balance = old_balance + record["delta"]
        if new_balance < 0:
            # 余额不足：状态不变（仍 pending），可重试，不记事件；
            # 报告触发的提交同样失败且报告不落盘
            raise ServiceError(
                409,
                f"asset {asset_id!r} has insufficient balance "
                "for this operation",
            )
        new_version = old_version + 1
        committed_record = {
            "operation_id": operation_id,
            "asset_id": asset_id,
            "state": "committed",
            "delta": record["delta"],
            "balance": new_balance,
            "version": new_version,
        }
        asset_record = {"balance": new_balance, "version": new_version}
        # 意图只含标识与整数，不含任何私钥材料
        intent = {
            "operation_id": operation_id,
            "asset_id": asset_id,
            "delta": record["delta"],
            "old_asset": asset,
            "pending": record,
            "new_balance": new_balance,
            "new_version": new_version,
        }
        if report_details is not None:
            # 报告触发的提交：意图随附达门槛报告 B，崩溃恢复据此把
            # 两事件提交点与孤立报告矛盾现场严格区分开
            intent["report"] = report_details
        if vote_details is not None:
            # 多源仲裁达 quorum 的提交：意图随附决定性 adopted 票
            # {source,report=B,state}，崩溃恢复据此把"票 + 报告 +
            # 提交"三事件批与矛盾现场严格区分开
            intent["vote"] = vote_details
        if settle_dispatch_id is not None:
            # 最终性结算：意图随附派发标识，崩溃恢复据此把
            # "chain_dispatch_settled + 提交"两事件批与矛盾现场严格
            # 区分开。
            intent["settle"] = {"dispatch_id": settle_dispatch_id}
        try:
            self._store.write_asset_commit_intent(
                wallet_id, operation_id, intent
            )
            self._store.commit_asset_operation(
                wallet_id,
                operation_id,
                committed_record,
                asset_id,
                asset_record,
            )
            if (
                report_details is not None
                or vote_details is not None
                or settle_dispatch_id is not None
            ):
                # 触发事件与提交事件同批一次原子落盘：要么全部在
                # （seq n、n+1、…），要么都不在，绝不留下孤立触发事件。
                # 多源仲裁达 quorum 时票事件在先、链上报告事件次之、
                # 提交事件收尾（三事件一次原子提交）；最终性结算为
                # chain_dispatch_settled 在先、提交事件收尾（两事件一次
                # 原子提交）。
                batch: list[dict] = []
                if vote_details is not None:
                    batch.append(
                        self._audit_event(
                            audit.TYPE_CHAIN_VOTE,
                            request_id=operation_id,
                            details=vote_details,
                        )
                    )
                if report_details is not None:
                    batch.append(
                        self._audit_event(
                            audit.TYPE_CHAIN_REPORT,
                            request_id=operation_id,
                            details=report_details,
                        )
                    )
                if settle_dispatch_id is not None:
                    batch.append(
                        self._audit_event(
                            audit.TYPE_CHAIN_DISPATCH_SETTLED,
                            request_id=settle_dispatch_id,
                            actor_id=settle_adapter_id,
                            reason=None,
                            details={
                                "dispatch_id": settle_dispatch_id,
                                "operation_id": operation_id,
                            },
                        )
                    )
                batch.append(
                    self._audit_event(
                        audit.TYPE_ASSET_OPERATION_COMMITTED,
                        request_id=operation_id,
                        details=committed_record,
                    )
                )
                self._audit.append_events(wallet_id, batch)
            else:
                self._emit(
                    wallet_id,
                    self._audit_event(
                        audit.TYPE_ASSET_OPERATION_COMMITTED,
                        request_id=operation_id,
                        details=committed_record,
                    ),
                )
        except BaseException:
            # 普通写入/事件追加失败：以事件是否真正落盘为准对账。
            # 事件在（如落盘成功但返回阶段报错）则前滚为唯一 committed，
            # 绝不重复记事件；事件不在则回滚 pending 与提交前余额/版本。
            # 两事件同批原子落盘，提交事件缺失即报告事件也未持久化，
            # 事件从未分配 seq，故无事件、无 seq 缺口，可重试。
            landed = self._audit.find_event_by_request(
                wallet_id,
                audit.TYPE_ASSET_OPERATION_COMMITTED,
                operation_id,
            )
            if landed is not None:
                self._store.commit_asset_operation(
                    wallet_id,
                    operation_id,
                    committed_record,
                    asset_id,
                    asset_record,
                )
                self._store.delete_asset_commit_intent(
                    wallet_id, operation_id
                )
                return committed_record
            self._store.restore_asset_operation(
                wallet_id, operation_id, record, asset_id, asset
            )
            self._store.delete_asset_commit_intent(wallet_id, operation_id)
            raise
        self._store.delete_asset_commit_intent(wallet_id, operation_id)
        return committed_record

    def _commit_reorg_compensation_locked(
        self,
        wallet_id: str,
        dispatch_id: str,
        adapter_id: str,
        asset_id: str,
        delta: int,
        view: dict,
    ) -> dict:
        """在每钱包事务锁内创建并提交重组补偿操作（operation_id 即 D，
        同资产、反向 delta），返回 committed 视图 R。

        调用方须已持锁、已 heal、已判定 D 未被占用且重组条件成立。
        事务顺序：

            1. 写提交意图（记录 committed 结果 R、提交前资产快照与
               reorg={dispatch_id: D, confirmation: V}；操作 D 由本事务
               新建，回滚是删除而非还原）
            2. 原子提交账本：操作 D 直接落为 committed、balance 改、
               version+1
            3. 同批原子追加三事件：chain_dispatch_confirmation
               （details=V，state=reorged）、chain_dispatch_reorged
               （details={dispatch_id: D, operation_id: D}）、
               asset_operation_committed（details=R），request_id=D、
               actor_id=adapter_id、reason=null，seq 连续
            4. 删除提交意图

        余额将负在任何写入之前抛 409（零副作用）。崩溃恢复以提交事件
        是否落盘为准：事件在则前滚补齐（并核对紧邻的重组确认/重组事件
        与意图随附内容一致），事件不在则删除新建操作、恢复提交前余额/
        版本。三事件俱在前滚、俱无回滚。
        """
        asset = self._store.get_asset(wallet_id, asset_id)
        old_balance = asset["balance"] if asset is not None else 0
        old_version = asset["version"] if asset is not None else 0
        new_balance = old_balance + delta
        if new_balance < 0:
            # 补偿后余额将负：零副作用（意图/账本/事件均未写），可重试
            raise ServiceError(
                409,
                f"asset {asset_id!r} has insufficient balance "
                "for this operation",
            )
        new_version = old_version + 1
        committed_record = {
            "operation_id": dispatch_id,
            "asset_id": asset_id,
            "delta": delta,
            "state": "committed",
            "balance": new_balance,
            "version": new_version,
        }
        asset_record = {"balance": new_balance, "version": new_version}
        # 意图只含标识与整数，不含任何私钥材料；pending 记录本事务新建
        # 操作的提交前形态（账本中尚不存在，仅供恢复校验/形状对账）
        intent = {
            "operation_id": dispatch_id,
            "asset_id": asset_id,
            "delta": delta,
            "old_asset": asset,
            "pending": {
                "operation_id": dispatch_id,
                "asset_id": asset_id,
                "state": "pending",
                "delta": delta,
                "balance": old_balance,
                "version": old_version,
            },
            "new_balance": new_balance,
            "new_version": new_version,
            # 重组补偿：意图随附派发标识与重组确认视图 V，崩溃恢复据此
            # 把"重组确认 + 重组 + 提交"三事件批与矛盾现场严格区分开。
            "reorg": {"dispatch_id": dispatch_id, "confirmation": view},
        }
        try:
            self._store.write_asset_commit_intent(
                wallet_id, dispatch_id, intent
            )
            self._store.commit_asset_operation(
                wallet_id,
                dispatch_id,
                committed_record,
                asset_id,
                asset_record,
            )
            # 三事件同批一次原子落盘：要么全部在（seq n、n+1、n+2），
            # 要么都不在，绝不留下孤立的重组确认/重组事件。
            self._audit.append_events(
                wallet_id,
                [
                    self._audit_event(
                        audit.TYPE_CHAIN_DISPATCH_CONFIRMATION,
                        request_id=dispatch_id,
                        actor_id=adapter_id,
                        reason=None,
                        details=view,
                    ),
                    self._audit_event(
                        audit.TYPE_CHAIN_DISPATCH_REORGED,
                        request_id=dispatch_id,
                        actor_id=adapter_id,
                        reason=None,
                        details={
                            "dispatch_id": dispatch_id,
                            "operation_id": dispatch_id,
                        },
                    ),
                    self._audit_event(
                        audit.TYPE_ASSET_OPERATION_COMMITTED,
                        request_id=dispatch_id,
                        actor_id=adapter_id,
                        reason=None,
                        details=committed_record,
                    ),
                ],
            )
        except BaseException:
            # 普通写入/事件追加失败：以提交事件是否真正落盘为准对账。
            # 事件在（如落盘成功但返回阶段报错）则前滚为唯一 committed，
            # 绝不重复记事件；事件不在则整体回滚（删除新建操作、恢复
            # 提交前余额/版本），事件从未分配 seq，故无事件、无 seq
            # 缺口，可重试。
            landed = self._audit.find_event_by_request(
                wallet_id,
                audit.TYPE_ASSET_OPERATION_COMMITTED,
                dispatch_id,
            )
            if landed is not None:
                self._store.commit_asset_operation(
                    wallet_id,
                    dispatch_id,
                    committed_record,
                    asset_id,
                    asset_record,
                )
                self._store.delete_asset_commit_intent(
                    wallet_id, dispatch_id
                )
                return committed_record
            self._store.remove_asset_operation(
                wallet_id, dispatch_id, asset_id, asset
            )
            self._store.delete_asset_commit_intent(wallet_id, dispatch_id)
            raise
        self._store.delete_asset_commit_intent(wallet_id, dispatch_id)
        return committed_record

    # ---- 原子资产转账 -----------------------------------------------------

    @staticmethod
    def _validate_transfer_id(transfer_id: object) -> None:
        if not isinstance(transfer_id, str) or not ROTATION_ID_RE.match(
            transfer_id
        ):
            raise ServiceError(
                400, "transfer_id must match [A-Za-z0-9_-]{1,128}"
            )

    @staticmethod
    def _validate_transfer_amount(amount: object) -> None:
        # bool 是 int 的子类，必须先排除；0 与负数不是合法的转账金额
        if not isinstance(amount, int) or isinstance(amount, bool) or amount <= 0:
            raise ServiceError(400, "amount must be a positive integer")

    @staticmethod
    def _validate_transfer_expected_version(
        name: str, value: object
    ) -> None:
        # bool 是 int 的子类，必须先排除；0 表示资产尚无提交版本
        if (
            not isinstance(value, int)
            or isinstance(value, bool)
            or value < 0
        ):
            raise ServiceError(
                400, f"{name} must be a non-negative integer"
            )

    def create_asset_transfer(
        self,
        wallet_id: str,
        transfer_id: object,
        from_asset_id: object,
        to_asset_id: object,
        amount: object,
        expected_from_version: object,
        expected_to_version: object,
    ) -> tuple[int, dict]:
        """原子资产转账（可恢复事务）。返回 (HTTP 状态码, 转账视图 R)。

        一次请求同时完成创建与提交：按当前账本同时校验两个资产的乐观
        版本，来源减 amount、目标加 amount，两个 version 各加一，状态
        为 committed，并追加唯一的 asset_transfer_committed 审计事件
        （details 即九键转账视图 R）作为唯一提交点。目标资产可新建；
        来源不存在或余额不足 409 "insufficient balance"。

        错误语义（全部零副作用：账本/version/审计/摘要链/意图均不变）：

        - 钱包不存在 404；transfer_id/资产标识非法、两个资产相同、
          amount 非正的非布尔整数、任一 expected_*_version 为非布尔
          非负整数之外的值一律 400；
        - 钱包或任一资产冻结 409 "wallet or asset frozen"（应急闸门，
          先于幂等重放与一切业务判定）；
        - 任一版本与当前账本不一致 409 "asset version conflict"；
        - 来源不存在或余额不足 409 "insufficient balance"；
        - 冷热交易策略白名单不含任一资产或 amount 超过 max_delta
          409 "transaction policy violation"；
        - transfer_id 同参（from/to/amount 相同）重放 200 返回原视图，
          不重新校验现场（与 committed 重放不重新比较 expected_version
          同一幂等规则）；异参 409 "transfer conflict"。

        恢复检查、钱包存在性、参数校验、幂等查重、版本/余额/策略判定与
        整个提交事务全部在每钱包跨进程事务锁内：绝不基于锁外快照决定
        404/400/409 或重放；多个声明同一版本的并发转账至多一个 201。
        """
        try:
            with self._wallet_lock(wallet_id):
                # 快照前先自愈他进程崩溃遗留的提交意图，balance/version
                # 才准确
                self._heal_wallet(wallet_id)
                # 404 优先于 400：存在性先于一切参数校验
                self._get_wallet_or_404(wallet_id)
                # 钱包冻结闸门：先于参数校验、幂等重放与一切业务判定
                if (
                    self._security_state_locked(wallet_id)["state"]
                    == WALLET_STATE_FROZEN
                ):
                    raise ServiceError(409, "wallet or asset frozen")
                self._validate_transfer_id(transfer_id)
                self._validate_asset_id(from_asset_id)
                self._validate_asset_id(to_asset_id)
                if from_asset_id == to_asset_id:
                    raise ServiceError(
                        400, "from_asset_id and to_asset_id must differ"
                    )
                self._validate_transfer_amount(amount)
                self._validate_transfer_expected_version(
                    "expected_from_version", expected_from_version
                )
                self._validate_transfer_expected_version(
                    "expected_to_version", expected_to_version
                )
                # 资产粒度冻结闸门：先于幂等重放与一切业务判定，frozen
                # 资产即便同参重放也一律 409 且零副作用。
                self._reconcile_asset_freeze_ledger(wallet_id)
                security_states = self._asset_security_states_locked(
                    wallet_id
                )
                for asset_id in (from_asset_id, to_asset_id):
                    state = security_states.get(asset_id)
                    if (
                        state is not None
                        and state["state"] == ASSET_STATE_FROZEN
                    ):
                        raise ServiceError(409, "wallet or asset frozen")
                existing = self._store.get_asset_transfer(
                    wallet_id, transfer_id
                )
                if existing is not None:
                    # 重放：原样返回磁盘中的转账视图，不按当前现场重新
                    # 校验版本/余额/策略、不改状态、不记事件（expected_*
                    # 是提交瞬间的乐观前提，与 committed 重放不重新比较
                    # expected_version 同一规则）
                    if (
                        existing.get("from_asset_id") != from_asset_id
                        or existing.get("to_asset_id") != to_asset_id
                        or existing.get("amount") != amount
                    ):
                        raise ServiceError(409, "transfer conflict")
                    return 200, existing
                # 首次转账：按锁提交时刻的账本同时校验两个资产的乐观
                # 版本（无资产条目按 0）
                from_asset = self._store.get_asset(wallet_id, from_asset_id)
                to_asset = self._store.get_asset(wallet_id, to_asset_id)
                from_version = (
                    from_asset["version"] if from_asset is not None else 0
                )
                to_version = (
                    to_asset["version"] if to_asset is not None else 0
                )
                if (
                    from_version != expected_from_version
                    or to_version != expected_to_version
                ):
                    raise ServiceError(409, "asset version conflict")
                from_balance = (
                    from_asset["balance"] if from_asset is not None else 0
                )
                if from_balance < amount:
                    # 来源不存在（余额 0）或余额不足：409 且零副作用
                    raise ServiceError(409, "insufficient balance")
                # 冷热交易策略：两个资产都须在白名单内且 amount 不超过
                # 单笔上限，否则 409 且零副作用
                policy = self._store.get_transaction_policy(wallet_id)
                if policy is not None:
                    if (
                        from_asset_id not in policy["allowed_assets"]
                        or to_asset_id not in policy["allowed_assets"]
                    ):
                        raise ServiceError(
                            409, "transaction policy violation"
                        )
                    if amount > policy["max_delta"]:
                        raise ServiceError(
                            409, "transaction policy violation"
                        )
                committed = self._commit_asset_transfer_locked(
                    wallet_id,
                    transfer_id,
                    from_asset_id,
                    to_asset_id,
                    amount,
                    from_asset,
                    to_asset,
                )
        except CorruptDataError:
            raise
        except ValueError:
            # wallet_id 含非法字符（构造锁路径时抛出）
            raise ServiceError(400, "invalid wallet_id")
        return 201, committed

    def _commit_asset_transfer_locked(
        self,
        wallet_id: str,
        transfer_id: str,
        from_asset_id: str,
        to_asset_id: str,
        amount: int,
        from_asset: Optional[dict],
        to_asset: Optional[dict],
    ) -> dict:
        """在每钱包事务锁内落一条原子转账，返回九键转账视图 R。

        调用方须已持锁、已 heal、已完成版本/余额/策略判定。事务顺序：

            1. 写提交意图（kind="transfer"，记录转账视图 R 与转账前
               两个资产的快照）
            2. 原子落账：转账记录与两个资产条目同文件一次写入（来源减、
               目标加，两个 version 各加一）
            3. 追加唯一的 asset_transfer_committed 事件（details=R，
               request_id=transfer_id）
            4. 删除提交意图

        崩溃恢复以事件是否落盘为准：事件在则前滚补齐（两个资产按 R
        绝对值校正），事件不在则整体回滚到转账前现场——绝不只恢复
        一边。意图只含标识与整数，不含任何私钥材料。
        """
        from_balance = from_asset["balance"] if from_asset is not None else 0
        from_version = from_asset["version"] if from_asset is not None else 0
        to_balance = to_asset["balance"] if to_asset is not None else 0
        to_version = to_asset["version"] if to_asset is not None else 0
        committed = {
            "transfer_id": transfer_id,
            "from_asset_id": from_asset_id,
            "to_asset_id": to_asset_id,
            "amount": amount,
            "state": "committed",
            "from_balance": from_balance - amount,
            "from_version": from_version + 1,
            "to_balance": to_balance + amount,
            "to_version": to_version + 1,
        }
        from_entry = {
            "balance": committed["from_balance"],
            "version": committed["from_version"],
        }
        to_entry = {
            "balance": committed["to_balance"],
            "version": committed["to_version"],
        }
        intent = {
            "kind": "transfer",
            "transfer_id": transfer_id,
            "from_asset_id": from_asset_id,
            "to_asset_id": to_asset_id,
            "amount": amount,
            "old_from_asset": from_asset,
            "old_to_asset": to_asset,
            "committed": committed,
        }
        try:
            self._store.write_asset_commit_intent(
                wallet_id, transfer_id, intent
            )
            self._store.commit_asset_transfer(
                wallet_id,
                transfer_id,
                committed,
                from_asset_id,
                from_entry,
                to_asset_id,
                to_entry,
            )
            self._emit(
                wallet_id,
                self._audit_event(
                    audit.TYPE_ASSET_TRANSFER_COMMITTED,
                    request_id=transfer_id,
                    details=committed,
                ),
            )
        except BaseException:
            # 普通写入/事件追加失败：以事件是否真正落盘为准对账。
            # 事件在（如落盘成功但返回阶段报错）则前滚为唯一 committed，
            # 绝不重复记事件；事件不在则整体回滚到转账前现场（两个资产
            # 一起恢复，绝不只恢复一边）。事件从未分配 seq，故无事件、
            # 无 seq 缺口，可重试。
            landed = self._audit.find_event_by_request(
                wallet_id,
                audit.TYPE_ASSET_TRANSFER_COMMITTED,
                transfer_id,
            )
            if landed is not None:
                self._store.commit_asset_transfer(
                    wallet_id,
                    transfer_id,
                    committed,
                    from_asset_id,
                    from_entry,
                    to_asset_id,
                    to_entry,
                )
                self._store.delete_asset_commit_intent(
                    wallet_id, transfer_id
                )
                return committed
            self._store.restore_asset_transfer(
                wallet_id,
                transfer_id,
                from_asset_id,
                from_asset,
                to_asset_id,
                to_asset,
            )
            self._store.delete_asset_commit_intent(wallet_id, transfer_id)
            raise
        self._store.delete_asset_commit_intent(wallet_id, transfer_id)
        return committed

    def get_asset(
        self,
        wallet_id: str,
        asset_id: str,
        at_seq: object = None,
        expected_head: object = None,
    ) -> dict:
        """查询某资产的账本状态（balance/version）。

        在每钱包事务锁内读取：提交事务进行中（账本已改、事件尚未落盘）的
        查询会被挡到事务结束，绝不会读到随后可能回滚的半完成余额。

        恢复检查、钱包存在性、asset_id 校验与余额读取全部在锁内：绝不
        先用锁外快照决定 404/400。

        ``at_seq`` 缺省时为当前账本读取，响应与错误语义保持不变
        （``{asset_id,balance,version}``）。``at_seq`` 提供时返回历史
        资产状态：以审计序列中 seq 不超过 ``at_seq`` 的事件为边界，
        余额/版本由边界内该资产最后一条 ``asset_operation_committed``
        或 ``asset_transfer_committed`` 事件（命中来源或目标侧）的 R
        给出，响应仅含 ``asset_id,balance,version,at_seq,head``；
        ``head`` 为边界事件后的摘要链头，与 audit-evidence 同一
        ``to_seq=at_seq`` 的 ``end_head`` 相同。边界可落在任意事件上，
        不要求属于所查资产；边界内该资产无已提交操作时 404，绝不以
        当前余额或零余额代替。边界超过当前审计尾序号 404。

        ``at_seq``/``expected_head`` 接受 parse_qs 的字符串列表
        （None 表示缺参，长度 >1 即重复参数）。参数校验次序（钱包
        存在性 404 之后）：重复 → at_seq 非法 → expected_head 缺
        at_seq/格式 → 边界与资产读取；expected_head 格式合法但与
        head 不符在边界/资产 404 之后判 409。历史读为纯只读：与
        audit-evidence 同一套 DKG 对账与整条摘要链完整性校验，链不可
        对账时上抛（HTTP 边界转 503），保留现场、不返回部分结果。
        """
        if at_seq is None and expected_head is None:
            return self._get_asset_current(wallet_id, asset_id)
        try:
            with self._wallet_lock(wallet_id):
                # 查询前先自愈他进程崩溃遗留的提交意图，绝不基于半完成
                # 余额/审计现场回答历史状态。
                self._heal_wallet(wallet_id)
                # 404 优先于查询参数 400：与 audit-evidence /
                # audit-events 同一次序。
                self._get_wallet_or_404(wallet_id)
                # 1) 重复参数：按 at_seq、expected_head 次序报
                if isinstance(at_seq, list) and len(at_seq) > 1:
                    raise ServiceError(400, "duplicate at_seq parameters")
                if (
                    isinstance(expected_head, list)
                    and len(expected_head) > 1
                ):
                    raise ServiceError(
                        400, "duplicate expected_head parameters"
                    )
                if isinstance(at_seq, list):
                    at_seq = at_seq[0]
                # 2) at_seq：仅接受由 ASCII 数字组成的正整数（空值、
                #    空白、带符号、小数、Unicode 数字一律拒绝；不做
                #    strip，空串即非法）。此时只校验形状并保留归一化
                #    文本（去前导零），int 转换推迟到尾序号比较之后，
                #    避免超长数字串（Python int 转换上限）被误当
                #    ValueError(400)——它仍是合法正整数，超尾应 404。
                boundary_text = self._asset_at_seq_text(at_seq)
                if isinstance(expected_head, list):
                    expected_head = expected_head[0]
                # 3) expected_head 只能随 at_seq 使用：缺 at_seq 或
                #    expected_head 为空/非 64 位小写十六进制均 400
                if expected_head is not None and (
                    not isinstance(expected_head, str)
                    or not self._EXPECTED_HEAD_RE.match(expected_head)
                ):
                    raise ServiceError(400, "invalid expected_head")
                self._validate_asset_id(asset_id)
                # 与 audit-evidence 同一套严格 DKG 对账与摘要链完整
                # 性校验：链元数据缺失/矛盾、事件被改动等不可对账
                # 现场 fail-closed，绝不静默出证。
                self._reconcile_dkg_events_locked(wallet_id)
                # integrity 返回 (尾序号, 当前链头)：链元数据缺失/
                # 矛盾、事件被改动一律上抛（HTTP 边界转 503）。
                tail_count = self._audit.integrity(wallet_id)[0]
                # 4) 边界超过当前审计尾序号：404（边界内尚无事件的
                #    空钱包同样落在此处）。按位数/文本比较，避免对
                #    超长数字串做 int 转换；未越界的小值随后再转 int。
                tail_text = str(tail_count)
                beyond_tail = (
                    len(boundary_text) > len(tail_text)
                    or (
                        len(boundary_text) == len(tail_text)
                        and boundary_text > tail_text
                    )
                )
                if beyond_tail:
                    raise ServiceError(
                        404, "at_seq beyond the audit tail"
                    )
                boundary = int(boundary_text)
                evidence = self._audit.range_evidence(
                    wallet_id, 1, boundary
                )
                head = evidence["end_head"]
                committed = None
                for event in evidence["events"]:
                    event_type = event.get("type")
                    if event_type == audit.TYPE_ASSET_OPERATION_COMMITTED:
                        details = event.get("details")
                        # 资产生效点只能是形状合法的 R：形状矛盾与
                        # audit-evidence 不可对账同等级，绝不猜读。
                        if not self._committed_details_shape_ok(details):
                            raise RecoveryError(
                                f"wallet {wallet_id!r} committed event at "
                                f"seq {event.get('seq')!r} is malformed"
                            )
                        if details["asset_id"] == asset_id:
                            committed = details
                        continue
                    if event_type == audit.TYPE_ASSET_TRANSFER_COMMITTED:
                        # 转账事件同序同时是来源与目标两个资产的生效点：
                        # 命中任一侧即按该侧 R 更新历史状态。
                        details = event.get("details")
                        if not self._transfer_details_shape_ok(details):
                            raise RecoveryError(
                                f"wallet {wallet_id!r} transfer event at "
                                f"seq {event.get('seq')!r} is malformed"
                            )
                        if details["from_asset_id"] == asset_id:
                            committed = {
                                "balance": details["from_balance"],
                                "version": details["from_version"],
                            }
                        if details["to_asset_id"] == asset_id:
                            committed = {
                                "balance": details["to_balance"],
                                "version": details["to_version"],
                            }
                        continue
                # 5) 边界前无该资产已提交操作：404，绝不以当前余额
                #    或零余额代替
                if committed is None:
                    raise ServiceError(
                        404, f"asset {asset_id!r} not found"
                    )
                # 6) expected_head 与边界 head 不符：409（先于 200，
                #    后于边界/资产 404）
                if (
                    expected_head is not None
                    and expected_head != head
                ):
                    raise ServiceError(
                        409, "expected_head does not match chain head"
                    )
                return {
                    "asset_id": asset_id,
                    "balance": committed["balance"],
                    "version": committed["version"],
                    "at_seq": boundary,
                    "head": head,
                }
        except CorruptDataError:
            raise
        except ValueError:
            raise ServiceError(400, "invalid wallet_id")

    def _get_asset_current(
        self, wallet_id: str, asset_id: str
    ) -> dict:
        """at_seq 缺省时的既有当前账本读取（语义与错误保持不变）。"""
        try:
            with self._wallet_lock(wallet_id):
                # 查询前先自愈他进程崩溃遗留的提交意图，绝不返回半完成余额
                self._heal_wallet(wallet_id)
                # 404 优先于 400：存在性先于 asset_id 校验
                self._get_wallet_or_404(wallet_id)
                self._validate_asset_id(asset_id)
                asset = self._store.get_asset(wallet_id, asset_id)
                if asset is None:
                    raise ServiceError(404, f"asset {asset_id!r} not found")
                return {
                    "asset_id": asset_id,
                    "balance": asset["balance"],
                    "version": asset["version"],
                }
        except CorruptDataError:
            raise
        except ValueError:
            raise ServiceError(400, "invalid wallet_id")

    #: at_seq 只接受由 ASCII 数字组成的字符串
    _ASSET_AT_SEQ_RE = re.compile(r"^[0-9]+$")

    @classmethod
    def _asset_at_seq_text(cls, value: object) -> str:
        """历史边界 at_seq 形状校验：仅接受 ASCII 数字组成的正整数，
        返回去掉前导零的归一化文本（至少一位，且不全部为零）。

        不做 strip：空串、纯空白、带符号/小数点/指数、Unicode 数字
        （str.isdigit 会放行的非 ASCII 码点）一律拒绝；全零（0、
        00…）非正整数。非法抛 ServiceError(400)。调用方须先完成重复
        参数判定。int 转换由调用方在尾序号文本比较确认未越界后再做，
        超长数字串因而不会触发 Python 的 int 转换上限。"""
        if not isinstance(value, str) or not cls._ASSET_AT_SEQ_RE.fullmatch(
            value
        ):
            raise ServiceError(400, "invalid at_seq")
        normalized = value.lstrip("0")
        if not normalized:
            raise ServiceError(400, "invalid at_seq")
        return normalized

    @staticmethod
    def _committed_details_shape_ok(details: object) -> bool:
        """历史重放判定的提交事件 R 形状：恰含 R 六键，asset_id 为
        字符串，delta 为非布尔非零整数，state 恒 committed，balance/
        version 为非布尔整数。形状矛盾属不可对账现场（503），绝不
        任取或跳过。"""
        if not isinstance(details, dict) or set(details) != {
            "operation_id",
            "asset_id",
            "delta",
            "state",
            "balance",
            "version",
        }:
            return False
        if not isinstance(details["asset_id"], str):
            return False
        if (
            not isinstance(details["delta"], int)
            or isinstance(details["delta"], bool)
            or details["delta"] == 0
        ):
            return False
        if details["state"] != "committed":
            return False
        for key in ("balance", "version"):
            if not isinstance(details[key], int) or isinstance(
                details[key], bool
            ):
                return False
        return True

    #: 钱包级资产清单单页默认/最大条数
    ASSET_LIST_DEFAULT_LIMIT = 100
    ASSET_LIST_MAX_LIMIT = 1000

    def list_assets(
        self,
        wallet_id: str,
        at_seq: object = None,
        expected_head: object = None,
        limit: object = None,
        after: object = None,
    ) -> dict:
        """钱包级资产清单分页查询（GET /v1/wallets/{id}/assets）。

        返回 ``{wallet_id,at_seq,head,assets,next_after}``：assets 每项
        仅含 ``asset_id,balance,version``，按 asset_id 的 ASCII 序升序；
        只列出边界内已有已提交变化的资产（余额归零仍保留，只有
        pending/cancelled 操作的资产不出现），同一资产不重复，余额与
        版本取边界内该资产最后一条 ``asset_operation_committed`` 或
        ``asset_transfer_committed`` 事件的 R——与同一边界的单资产历史
        查询一致。

        ``at_seq`` 缺省取本次查询的一致审计尾序号；显式给定时接受
        ASCII 数字组成的非负整数（0 表示空前缀：assets 为空、head 为
        64 个零）。``head`` 为整个钱包该边界后的审计摘要链头，正边界与
        audit-evidence 同一 ``to_seq`` 的 ``end_head`` 一致。
        ``expected_head`` 只允许随显式 at_seq 使用，须为 64 位小写十六
        进制且与该边界 head 一致（不符 409）。``limit`` 接受 ASCII 数字
        组成的 1..1000 整数，缺省 100。``after`` 沿用资产标识规则，表示
        排除该值及之前的资产，不要求该标识实际存在。只有仍有后续资产时
        ``next_after`` 才返回本页最后一个标识，否则为 null。后续页带回
        相同 at_seq 与 head（作为 expected_head）时，新增事件不改变
        分页集合与数值。

        四个参数接受 parse_qs 的字符串列表（None 表示缺参，长度 >1 即
        重复参数）。参数校验次序（钱包存在性 404 之后）：重复 → at_seq
        非法 → expected_head 缺 at_seq/格式非法 → limit 非法/越界 →
        after 非法 → 边界越尾 404 → expected_head 不符 409。空钱包、
        零边界或游标之后无资产均返回 200 空数组（仍校验摘要）。

        纯只读：沿用既有恢复检查（_heal_wallet）与 audit-evidence 同一
        套 DKG 重放对账和整条摘要链完整性校验；审计链、账本或恢复现场
        损坏及读取失败一律上抛（HTTP 边界转 503），不返回部分结果。
        查询不写文件、不触发审批懒过期、不新增审计事件，不改变余额或
        version；钱包与资产冻结期间仍可查询。
        """
        try:
            with self._wallet_lock(wallet_id):
                # 查询前先自愈他进程崩溃遗留的提交意图，绝不基于半完成
                # 余额/审计现场回答清单。
                self._heal_wallet(wallet_id)
                # 404 优先于查询参数 400：与单资产历史查询同一次序。
                self._get_wallet_or_404(wallet_id)
                # 1) 重复参数：按 at_seq、expected_head、limit、after
                #    次序报
                if isinstance(at_seq, list) and len(at_seq) > 1:
                    raise ServiceError(400, "duplicate at_seq parameters")
                if (
                    isinstance(expected_head, list)
                    and len(expected_head) > 1
                ):
                    raise ServiceError(
                        400, "duplicate expected_head parameters"
                    )
                if isinstance(limit, list) and len(limit) > 1:
                    raise ServiceError(400, "duplicate limit parameters")
                if isinstance(after, list) and len(after) > 1:
                    raise ServiceError(400, "duplicate after parameters")
                if isinstance(at_seq, list):
                    at_seq = at_seq[0]
                # 2) at_seq：仅接受 ASCII 数字组成的非负整数（0 表示空
                #    前缀；空值、空白、带符号、小数、Unicode 数字一律
                #    拒绝）。只做形状校验并保留归一化文本，int 转换推迟
                #    到尾序号比较之后，避免超长数字串触发 int 转换上限
                #    被误当 400——它仍是合法非负整数，超尾应 404。
                boundary_text = (
                    None
                    if at_seq is None
                    else self._asset_list_at_seq_text(at_seq)
                )
                if isinstance(expected_head, list):
                    expected_head = expected_head[0]
                # 3) expected_head 只能随显式 at_seq 使用：缺 at_seq
                #    或 expected_head 非 64 位小写十六进制均 400
                if expected_head is not None:
                    if at_seq is None:
                        raise ServiceError(
                            400, "expected_head requires at_seq"
                        )
                    if (
                        not isinstance(expected_head, str)
                        or not self._EXPECTED_HEAD_RE.match(expected_head)
                    ):
                        raise ServiceError(400, "invalid expected_head")
                # 4) limit：ASCII 数字组成的 1..1000 整数，缺省 100
                page_limit = self._asset_list_limit(limit)
                # 5) after：沿用资产标识规则，不要求该标识实际存在
                if isinstance(after, list):
                    after = after[0]
                if after is not None and (
                    not isinstance(after, str)
                    or not ROTATION_ID_RE.match(after)
                ):
                    raise ServiceError(400, "invalid after")
                # 与 audit-evidence 同一套严格 DKG 对账与摘要链完整
                # 性校验：链元数据缺失/矛盾、事件被改动等不可对账
                # 现场 fail-closed，绝不静默出证。
                self._reconcile_dkg_events_locked(wallet_id)
                tail_count = self._audit.integrity(wallet_id)[0]
                # 6) 边界：缺省取本次查询的一致审计尾序号；显式边界
                #    超过当前审计尾序号 404（按位数/文本比较，避免对
                #    超长数字串做 int 转换）。
                if boundary_text is None:
                    boundary = tail_count
                else:
                    tail_text = str(tail_count)
                    beyond_tail = (
                        len(boundary_text) > len(tail_text)
                        or (
                            len(boundary_text) == len(tail_text)
                            and boundary_text > tail_text
                        )
                    )
                    if beyond_tail:
                        raise ServiceError(
                            404, "at_seq beyond the audit tail"
                        )
                    boundary = int(boundary_text)
                # 7) 边界内逐资产取最后一条已提交事件的 R：人工提交、
                #    链上确认、多源仲裁、派发最终性结算、重组补偿与原子
                #    转账六类提交点统一适用，同一资产不重复；转账事件
                #    同序同时更新来源与目标两个资产。零边界为空前缀：
                #    head 为 64 个零、无资产。
                committed_by_asset: dict[str, dict] = {}
                if boundary == 0:
                    head = audit.GENESIS_HEAD
                else:
                    evidence = self._audit.range_evidence(
                        wallet_id, 1, boundary
                    )
                    head = evidence["end_head"]
                    for event in evidence["events"]:
                        event_type = event.get("type")
                        if event_type == (
                            audit.TYPE_ASSET_OPERATION_COMMITTED
                        ):
                            details = event.get("details")
                            # 资产生效点只能是形状合法的 R：形状矛盾与
                            # audit-evidence 不可对账同等级，绝不猜读。
                            if not self._committed_details_shape_ok(details):
                                raise RecoveryError(
                                    f"wallet {wallet_id!r} committed event at "
                                    f"seq {event.get('seq')!r} is malformed"
                                )
                            committed_by_asset[details["asset_id"]] = details
                            continue
                        if event_type == audit.TYPE_ASSET_TRANSFER_COMMITTED:
                            details = event.get("details")
                            if not self._transfer_details_shape_ok(details):
                                raise RecoveryError(
                                    f"wallet {wallet_id!r} transfer event at "
                                    f"seq {event.get('seq')!r} is malformed"
                                )
                            committed_by_asset[details["from_asset_id"]] = {
                                "balance": details["from_balance"],
                                "version": details["from_version"],
                            }
                            committed_by_asset[details["to_asset_id"]] = {
                                "balance": details["to_balance"],
                                "version": details["to_version"],
                            }
                            continue
                # 8) expected_head 与边界 head 不符：409（后于边界
                #    404；空钱包、零边界与空页同样校验摘要）
                if expected_head is not None and expected_head != head:
                    raise ServiceError(
                        409, "expected_head does not match chain head"
                    )
                # 9) 按 asset_id 的 ASCII 序升序分页：after 排除该值及
                #    之前的资产；仍有后续资产时 next_after 为本页最后
                #    一个标识，否则为 None。
                asset_ids = sorted(committed_by_asset)
                if after is not None:
                    asset_ids = [aid for aid in asset_ids if aid > after]
                page = asset_ids[:page_limit]
                next_after = (
                    page[-1] if len(asset_ids) > page_limit else None
                )
                return {
                    "wallet_id": wallet_id,
                    "at_seq": boundary,
                    "head": head,
                    "assets": [
                        {
                            "asset_id": aid,
                            "balance": committed_by_asset[aid]["balance"],
                            "version": committed_by_asset[aid]["version"],
                        }
                        for aid in page
                    ],
                    "next_after": next_after,
                }
        except CorruptDataError:
            raise
        except ValueError:
            raise ServiceError(400, "invalid wallet_id")

    @classmethod
    def _asset_list_at_seq_text(cls, value: object) -> str:
        """清单查询的 at_seq 形状校验：仅接受 ASCII 数字组成的非负整数，
        返回去掉前导零的归一化文本（全零归一为 "0"，表示空前缀）。

        与单资产历史查询的唯一差异是 0 合法；空串、纯空白、带符号/
        小数点/指数、Unicode 数字一律拒绝。非法抛 ServiceError(400)。
        调用方须先完成重复参数判定；int 转换由调用方在尾序号文本比较
        确认未越界后再做。"""
        if not isinstance(value, str) or not cls._ASSET_AT_SEQ_RE.fullmatch(
            value
        ):
            raise ServiceError(400, "invalid at_seq")
        normalized = value.lstrip("0")
        return normalized if normalized else "0"

    @classmethod
    def _asset_list_limit(cls, value: object) -> int:
        """清单查询的 limit 校验：缺省 100；显式给定时仅接受 ASCII 数字
        组成的 1..1000 整数（空值、空白、带符号、小数、Unicode 数字、
        0 与越界一律 400）。先按归一化文本位数挡掉超长数字串，避免
        触发 Python int 转换上限。"""
        if value is None:
            return cls.ASSET_LIST_DEFAULT_LIMIT
        if isinstance(value, list):
            value = value[0]
        if not isinstance(value, str) or not cls._ASSET_AT_SEQ_RE.fullmatch(
            value
        ):
            raise ServiceError(400, "invalid limit")
        normalized = value.lstrip("0")
        if not normalized or len(normalized) > 4:
            raise ServiceError(400, "invalid limit")
        limit = int(normalized)
        if limit < 1 or limit > cls.ASSET_LIST_MAX_LIMIT:
            raise ServiceError(400, "invalid limit")
        return limit

    def check_asset_consistency(
        self,
        wallet_id: str,
        body: object,
        at_seq: object = None,
        expected_head: object = None,
        body_error: "ServiceError | None" = None,
    ) -> dict:
        """资产一致性校验（POST /v1/wallets/{id}/asset-consistency）。

        托管方按 ``{"assets":[{asset_id,balance,version},...]}`` 快照
        核对服务在审计边界 ``at_seq`` 处的资产状态，返回
        ``{wallet_id,at_seq,head,state_root,matched,missing,
        mismatched,unexpected}``。

        请求体恰含 ``assets`` 一键；``assets`` 为数组（可空），每项恰含
        ``asset_id,balance,version`` 三键，asset_id 沿用资产安全标识
        规则，balance/version 为非布尔非负整数，asset_id 不得重复；
        键集错误、形状错误或标识重复一律 400。``at_seq``/``expected_head``
        为查询参数，沿用资产清单语义：at_seq 缺省取本次校验的一致审计
        尾序号，0 表示空前缀；expected_head 只能随显式 at_seq 提供且
        须为 64 位小写十六进制。

        实际状态按清单同一套边界重放重建：边界内每个资产最后一条
        ``asset_operation_committed``/``asset_transfer_committed``
        事件的 R。``state_root`` 为按 asset_id ASCII 升序排列的固定
        字段 asset_id/balance/version 记录数组，经紧凑 UTF-8 JSON
        （无空白、非 ASCII 不转义）计算的 SHA-256 小写十六进制。
        ``missing`` 为快照有而实际无的资产标识（仅标识，升序）；
        ``unexpected`` 为实际有而快照无的资产（实际三字段记录，升序）；
        ``mismatched`` 为两侧都有但 balance/version 不符的资产，同时
        给出期望与实际值（升序）；三者全空时 ``matched`` 为 true。

        校验次序：钱包存在性 404 优先于一切请求校验（请求体读取/解析
        错误由 HTTP 层延迟到此之后重抛）；随后依次为重复查询参数 400
        （duplicate query parameters）→ at_seq 非法 400 → expected_head
        缺 at_seq/格式非法 400 → 请求体形状/键集/标识/取值/重复 400 →
        边界越尾 404 → expected_head 不符 409。

        纯只读：沿用既有恢复检查（_heal_wallet）与 audit-evidence 同一
        套 DKG 重放对账和整条摘要链完整性校验；审计链、账本或恢复现场
        损坏及读取失败一律上抛（HTTP 边界转 503），不返回部分结果。
        校验不写文件、不新增审计事件、不改变余额或 version；钱包与资产
        冻结期间仍可校验；同一 at_seq 的结果在重启或备份恢复后一致。
        """
        try:
            with self._wallet_lock(wallet_id):
                # 校验前先自愈他进程崩溃遗留的提交意图，绝不基于半完成
                # 余额/审计现场回答一致性报告。
                self._heal_wallet(wallet_id)
                # 钱包 404 优先于一切请求校验（含请求体与查询参数）。
                self._get_wallet_or_404(wallet_id)
                # 1) 重复查询参数：at_seq/expected_head 任一重复即 400
                if isinstance(at_seq, list) and len(at_seq) > 1:
                    raise ServiceError(400, "duplicate query parameters")
                if (
                    isinstance(expected_head, list)
                    and len(expected_head) > 1
                ):
                    raise ServiceError(400, "duplicate query parameters")
                if isinstance(at_seq, list):
                    at_seq = at_seq[0]
                # 2) at_seq：与资产清单同一规则（ASCII 数字组成的非负
                #    整数，0 表示空前缀；空值、空白、带符号、小数、
                #    Unicode 数字一律 400）。只做形状校验并保留归一化
                #    文本，int 转换推迟到尾序号比较之后。
                boundary_text = (
                    None
                    if at_seq is None
                    else self._asset_list_at_seq_text(at_seq)
                )
                if isinstance(expected_head, list):
                    expected_head = expected_head[0]
                # 3) expected_head 只能随显式 at_seq 使用：缺 at_seq
                #    或 expected_head 非 64 位小写十六进制均 400
                if expected_head is not None:
                    if at_seq is None:
                        raise ServiceError(400, "invalid expected_head")
                    if (
                        not isinstance(expected_head, str)
                        or not self._EXPECTED_HEAD_RE.match(expected_head)
                    ):
                        raise ServiceError(400, "invalid expected_head")
                # 4) 请求体：HTTP 层读取/解析错误在此重抛（钱包 404
                #    优先），随后校验键集与每项形状/标识/取值/重复。
                if body_error is not None:
                    raise body_error
                expected_assets = self._consistency_body_assets(body)
                # 与 audit-evidence 同一套严格 DKG 对账与摘要链完整
                # 性校验：链元数据缺失/矛盾、事件被改动等不可对账
                # 现场 fail-closed，绝不静默出证。
                self._reconcile_dkg_events_locked(wallet_id)
                tail_count = self._audit.integrity(wallet_id)[0]
                # 5) 边界：缺省取本次校验的一致审计尾序号；显式边界
                #    超过当前审计尾序号 404（按位数/文本比较，避免对
                #    超长数字串做 int 转换）。
                if boundary_text is None:
                    boundary = tail_count
                else:
                    tail_text = str(tail_count)
                    beyond_tail = (
                        len(boundary_text) > len(tail_text)
                        or (
                            len(boundary_text) == len(tail_text)
                            and boundary_text > tail_text
                        )
                    )
                    if beyond_tail:
                        raise ServiceError(
                            404, "at_seq beyond the audit tail"
                        )
                    boundary = int(boundary_text)
                # 6) 边界内逐资产取最后一条已提交事件的 R（与资产清单
                #    同一套重放）；零边界为空前缀：head 为 64 个零、
                #    无资产。
                committed_by_asset: dict[str, dict] = {}
                if boundary == 0:
                    head = audit.GENESIS_HEAD
                else:
                    evidence = self._audit.range_evidence(
                        wallet_id, 1, boundary
                    )
                    head = evidence["end_head"]
                    for event in evidence["events"]:
                        event_type = event.get("type")
                        if event_type == (
                            audit.TYPE_ASSET_OPERATION_COMMITTED
                        ):
                            details = event.get("details")
                            # 资产生效点只能是形状合法的 R：形状矛盾与
                            # audit-evidence 不可对账同等级，绝不猜读。
                            if not self._committed_details_shape_ok(details):
                                raise RecoveryError(
                                    f"wallet {wallet_id!r} committed event at "
                                    f"seq {event.get('seq')!r} is malformed"
                                )
                            committed_by_asset[details["asset_id"]] = details
                            continue
                        if event_type == audit.TYPE_ASSET_TRANSFER_COMMITTED:
                            details = event.get("details")
                            if not self._transfer_details_shape_ok(details):
                                raise RecoveryError(
                                    f"wallet {wallet_id!r} transfer event at "
                                    f"seq {event.get('seq')!r} is malformed"
                                )
                            committed_by_asset[details["from_asset_id"]] = {
                                "balance": details["from_balance"],
                                "version": details["from_version"],
                            }
                            committed_by_asset[details["to_asset_id"]] = {
                                "balance": details["to_balance"],
                                "version": details["to_version"],
                            }
                            continue
                # 7) expected_head 与边界 head 不符：409（后于边界
                #    404；空钱包、零边界同样校验摘要）
                if expected_head is not None and expected_head != head:
                    raise ServiceError(
                        409, "expected_head does not match chain head"
                    )
                # 8) 状态根：按 asset_id ASCII 升序的固定字段记录数组，
                #    紧凑 UTF-8 JSON 的 SHA-256 小写十六进制。
                actual_ids = sorted(committed_by_asset)
                actual_records = [
                    {
                        "asset_id": aid,
                        "balance": committed_by_asset[aid]["balance"],
                        "version": committed_by_asset[aid]["version"],
                    }
                    for aid in actual_ids
                ]
                state_root = hashlib.sha256(
                    json.dumps(
                        actual_records,
                        separators=(",", ":"),
                        ensure_ascii=False,
                        allow_nan=False,
                    ).encode("utf-8")
                ).hexdigest()
                # 9) 快照比对：missing 仅标识、unexpected 为实际三字段
                #    记录、mismatched 同时给出期望与实际值，均按标识
                #    升序；三者全空时 matched 为 true。
                missing = sorted(
                    aid
                    for aid in expected_assets
                    if aid not in committed_by_asset
                )
                unexpected = [
                    record
                    for record in actual_records
                    if record["asset_id"] not in expected_assets
                ]
                mismatched = []
                for aid in sorted(expected_assets):
                    actual = committed_by_asset.get(aid)
                    if actual is None:
                        continue
                    expected = expected_assets[aid]
                    if (
                        expected["balance"] != actual["balance"]
                        or expected["version"] != actual["version"]
                    ):
                        mismatched.append(
                            {
                                "asset_id": aid,
                                "expected_balance": expected["balance"],
                                "expected_version": expected["version"],
                                "actual_balance": actual["balance"],
                                "actual_version": actual["version"],
                            }
                        )
                return {
                    "wallet_id": wallet_id,
                    "at_seq": boundary,
                    "head": head,
                    "state_root": state_root,
                    "matched": not missing and not mismatched and not unexpected,
                    "missing": missing,
                    "mismatched": mismatched,
                    "unexpected": unexpected,
                }
        except CorruptDataError:
            raise
        except ValueError:
            raise ServiceError(400, "invalid wallet_id")

    @classmethod
    def _consistency_body_assets(cls, body: object) -> dict[str, dict]:
        """一致性校验请求体：恰含 ``assets`` 一键，值为数组（可空）；
        每项恰含 asset_id/balance/version 三键，asset_id 沿用资产安全
        标识规则且不得重复，balance/version 为非布尔非负整数。任何键集
        错误、形状错误或标识重复一律 400。返回 {asset_id: {balance,
        version}}（校验后绝无重复键）。"""
        if not isinstance(body, dict) or set(body) != {"assets"}:
            raise ServiceError(400, "body must contain exactly assets")
        assets = body["assets"]
        if not isinstance(assets, list):
            raise ServiceError(400, "assets must be an array")
        expected: dict[str, dict] = {}
        for item in assets:
            if not isinstance(item, dict) or set(item) != {
                "asset_id",
                "balance",
                "version",
            }:
                raise ServiceError(
                    400,
                    "each asset must contain exactly asset_id, balance "
                    "and version",
                )
            asset_id = item["asset_id"]
            cls._validate_asset_id(asset_id)
            for key in ("balance", "version"):
                value = item[key]
                if (
                    not isinstance(value, int)
                    or isinstance(value, bool)
                    or value < 0
                ):
                    raise ServiceError(
                        400, f"{key} must be a non-negative integer"
                    )
            if asset_id in expected:
                raise ServiceError(400, "duplicate asset_id")
            expected[asset_id] = {
                "balance": item["balance"],
                "version": item["version"],
            }
        return expected

    def get_asset_operation(
        self, wallet_id: str, operation_id: object
    ) -> dict:
        """只读查询单条资产操作及其取消信息。

        返回固定键序的既有操作视图，并在末键附带 cancellation：
        cancelled 操作为
        ``{cancel_id,approval_request_id,seq}``，其余状态为 None。

        查询在每钱包事务锁和崩溃恢复之后读取；冻结钱包允许查询。查询不
        触发审批懒过期、不追加事件、不分配 seq，也不改变余额、version、
        操作状态或摘要链。钱包存在性先于 operation_id 校验；账本、意图、
        取消事件或摘要链矛盾时保留现场并由 HTTP 层返回 503。
        """
        try:
            with self._wallet_lock(wallet_id):
                self._heal_wallet(wallet_id)
                self._get_wallet_or_404(wallet_id)
                self._validate_operation_id(operation_id)
                record = self._store.get_asset_operation(
                    wallet_id, operation_id
                )
                if record is None:
                    raise ServiceError(
                        404, f"asset operation {operation_id!r} not found"
                    )

                self._reconcile_asset_cancelled_events(wallet_id)
                view = self._asset_operation_view(record)
                cancellation = None
                if record["state"] == "cancelled":
                    event = next(
                        event
                        for event in self._audit.events_by_type(
                            wallet_id,
                            audit.TYPE_ASSET_OPERATION_CANCELLED,
                        )
                        if event.get("details", {}).get("operation_id")
                        == operation_id
                    )
                    cancellation = {
                        "cancel_id": event["request_id"],
                        "approval_request_id": event["actor_id"],
                        "seq": event["seq"],
                    }
                view["cancellation"] = cancellation
                return view
        except CorruptDataError:
            raise
        except ValueError:
            raise ServiceError(400, "invalid wallet_id")

    # ---- 跨链资产确认 -----------------------------------------------------

    @staticmethod
    def _validate_chain_id(chain_id: object) -> None:
        if not isinstance(chain_id, str) or not ROTATION_ID_RE.match(
            chain_id
        ):
            raise ServiceError(
                400, "chain_id must match [A-Za-z0-9_-]{1,128}"
            )

    @staticmethod
    def _validate_hex_32(value: object, name: str) -> None:
        if not _is_lower_hex_32(value):
            raise ServiceError(
                400, f"{name} must be 64 lowercase hex characters"
            )

    @staticmethod
    def _validate_non_negative_int(value: object, name: str) -> None:
        # bool 是 int 的子类，必须先排除
        if not isinstance(value, int) or isinstance(value, bool) or value < 0:
            raise ServiceError(
                400, f"{name} must be a non-negative integer"
            )

    @staticmethod
    def _chain_policy_shape(wallet_id: str, event: dict) -> tuple[str, dict]:
        """严格校验一条 chain_policy 事件，返回 (资产标识, 策略 Q)。

        request_id 为资产标识（安全 id），actor_id/reason 为 null，
        details 恰含 {chain_id, enabled, required_confirmations,
        reorg_window} 且值合法；任何畸形都是不可对账现场
        （RecoveryError，fail-closed）。"""
        if (
            event.get("actor_id") is not None
            or event.get("reason") is not None
        ):
            raise RecoveryError(
                f"wallet {wallet_id!r} has a chain_policy event with "
                "actor/reason set"
            )
        asset_id = event.get("request_id")
        if not isinstance(asset_id, str) or not ROTATION_ID_RE.match(
            asset_id
        ):
            raise RecoveryError(
                f"wallet {wallet_id!r} has a chain_policy event without "
                "an asset id"
            )
        details = event.get("details")
        if not isinstance(details, dict) or set(details) != {
            "chain_id",
            "enabled",
            "required_confirmations",
            "reorg_window",
        }:
            raise RecoveryError(
                f"wallet {wallet_id!r} has a malformed chain_policy event"
            )
        chain_id = details["chain_id"]
        enabled = details["enabled"]
        required = details["required_confirmations"]
        window = details["reorg_window"]
        if (
            not isinstance(chain_id, str)
            or not ROTATION_ID_RE.match(chain_id)
            or not isinstance(enabled, bool)
            or not isinstance(required, int)
            or isinstance(required, bool)
            or required <= 0
            or not isinstance(window, int)
            or isinstance(window, bool)
            or window < 0
        ):
            raise RecoveryError(
                f"wallet {wallet_id!r} has a malformed chain_policy event"
            )
        return asset_id, dict(details)

    @staticmethod
    def _chain_report_shape(wallet_id: str, event: dict) -> tuple[str, dict]:
        """严格校验一条 chain_report 事件，返回 (操作 id, 报告 B)。

        request_id 为资产操作 id，actor_id/reason 为 null，details 恰含
        {chain_id, tx_id, block_height, block_hash, confirmations} 且值
        合法；任何畸形都是不可对账现场（RecoveryError，fail-closed）。"""
        if (
            event.get("actor_id") is not None
            or event.get("reason") is not None
        ):
            raise RecoveryError(
                f"wallet {wallet_id!r} has a chain_report event with "
                "actor/reason set"
            )
        operation_id = event.get("request_id")
        if not isinstance(operation_id, str) or not ROTATION_ID_RE.match(
            operation_id
        ):
            raise RecoveryError(
                f"wallet {wallet_id!r} has a chain_report event without "
                "an operation id"
            )
        details = event.get("details")
        if not isinstance(details, dict) or set(details) != {
            "chain_id",
            "tx_id",
            "block_height",
            "block_hash",
            "confirmations",
        }:
            raise RecoveryError(
                f"wallet {wallet_id!r} has a malformed chain_report event"
            )
        if (
            not isinstance(details["chain_id"], str)
            or not ROTATION_ID_RE.match(details["chain_id"])
            or not _is_lower_hex_32(details["tx_id"])
            or not _is_lower_hex_32(details["block_hash"])
            or not isinstance(details["block_height"], int)
            or isinstance(details["block_height"], bool)
            or details["block_height"] < 0
            or not isinstance(details["confirmations"], int)
            or isinstance(details["confirmations"], bool)
            or details["confirmations"] < 0
        ):
            raise RecoveryError(
                f"wallet {wallet_id!r} has a malformed chain_report event"
            )
        return operation_id, dict(details)

    def _chain_policy_snapshot_events_locked(
        self, wallet_id: str
    ) -> list[tuple[int, str, dict]]:
        """链确认策略的全部配置快照（按 seq 升序）：既有的 chain_policy
        事件与 target=chain-policy 的 policy_change_applied 事件统一为
        ``(seq, asset_id, 策略Q)`` 流。后者是变更控制启用后链策略的唯一
        提交点，与 legacy 事件同样作为全量快照参与按 seq 的折叠（GET、
        报告/观察/派发门控与各恢复对账）。两类事件均先经严格校验。
        纯只读，不分配 seq。"""
        snapshots: list[tuple[int, str, dict]] = []
        for event in self._audit.events_by_type(
            wallet_id, audit.TYPE_CHAIN_POLICY
        ):
            asset_id, policy = self._chain_policy_shape(wallet_id, event)
            snapshots.append((event["seq"], asset_id, policy))
        for event in self._policy_change_events_strict(wallet_id):
            details = event["details"]
            if details["target"] == "chain-policy":
                snapshots.append(
                    (
                        event["seq"],
                        details["asset_id"],
                        dict(details["after"]),
                    )
                )
        snapshots.sort(key=lambda item: item[0])
        return snapshots

    def _chain_policies(self, wallet_id: str) -> dict[str, dict]:
        """从链策略快照流恢复各资产当前的链确认策略（每资产按 seq 取最后
        一条）。

        策略只由审计事件持久化（legacy chain_policy 与 target=chain-policy
        的 policy_change_applied 合并流，事件之外不写任何状态文件）；畸形
        事件 fail-closed（RecoveryError），绝不静默按缺省处理。纯只读，
        不分配 seq。"""
        policies: dict[str, dict] = {}
        for _seq, asset_id, policy in (
            self._chain_policy_snapshot_events_locked(wallet_id)
        ):
            policies[asset_id] = policy
        return policies

    def _chain_reports(self, wallet_id: str) -> dict[str, dict]:
        """从 chain_report 事件序列恢复各操作的最后一条报告。

        报告状态只由审计事件持久化；畸形事件 fail-closed
        （RecoveryError）。纯只读，不分配 seq。"""
        reports: dict[str, dict] = {}
        for event in self._audit.events_by_type(
            wallet_id, audit.TYPE_CHAIN_REPORT
        ):
            operation_id, report = self._chain_report_shape(wallet_id, event)
            reports[operation_id] = report
        return reports

    @staticmethod
    def _report_transition_error(
        policy: dict, last: dict | None, report: dict
    ) -> str | None:
        """新报告相对上一条报告的状态机校验；合法返回 None，否则返回错误信息。

        首报绑定 tx_id 与 chain_id：后续报告换 tx/换链一律冲突；同块
        （高度与哈希均同）确认数只增不减，且低于门槛的同体重放不应产生
        事件（对账时据此识别篡改）；换块的高度回退不得超过策略
        reorg_window，换块后确认数可降。"""
        if last is None:
            return None
        if report["tx_id"] != last["tx_id"]:
            return "tx_id conflicts with the reported transaction"
        if report["chain_id"] != last["chain_id"]:
            return "chain_id conflicts with the reported chain"
        same_block = (
            report["block_height"] == last["block_height"]
            and report["block_hash"] == last["block_hash"]
        )
        if same_block:
            if report["confirmations"] < last["confirmations"]:
                return "confirmations must not decrease on the same block"
            if (
                report == last
                and report["confirmations"] < policy["required_confirmations"]
            ):
                # 低于门槛的同体重放在线只回 200 不记事件：日志里出现
                # 这样的重复报告事件即矛盾现场（达门槛的重复报告是崩溃
                # 重试补齐提交的合法残留，不在此列）
                return "duplicate report below the required confirmations"
            return None
        if (
            last["block_height"] - report["block_height"]
            > policy["reorg_window"]
        ):
            return "block height regression exceeds the reorg window"
        return None

    def put_chain_policy(
        self,
        wallet_id: str,
        asset_id: object,
        chain_id: object,
        enabled: object,
        required_confirmations: object,
        reorg_window: object,
    ) -> dict:
        """设置（或覆盖）某资产的跨链确认策略。成功 200 返回 Q。

        钱包不存在 404；标识/值非法 400（键集由 HTTP 边界校验）。双人变更
        控制启用后本入口一律 409 change control required 且零副作用（在
        参数校验与任何写入之前判定），链确认策略只能经 policy-changes 的
        chain-policy 目标变更。策略仅由 chain_policy 审计事件持久化
        （request_id 为资产标识，actor_id/reason 为 null，details 即 Q），
        **同值更新也记事件**，不写任何策略状态文件。恢复检查、存在性判定、
        校验与事件追加全部在每钱包跨进程事务锁内完成。"""
        try:
            with self._wallet_lock(wallet_id):
                self._heal_wallet(wallet_id)
                # 404 优先于 400：存在性在锁内、heal 之后先判定
                self._get_wallet_or_404(wallet_id)
                self._assert_wallet_active_locked(wallet_id)
                # 双人变更控制启用后受控 PUT 统一 409（零副作用，在参数校验
                # 与任何写入之前）；链确认策略只能经 policy-changes 的
                # chain-policy 目标变更。
                self._assert_change_control_not_required_locked(wallet_id)
                self._validate_asset_id(asset_id)
                self._validate_chain_id(chain_id)
                # 资产粒度冻结闸门：frozen 资产的确认策略写入（含同值
                # 更新）一律 409 且零事件。
                self._assert_asset_active_locked(wallet_id, asset_id)
                if not isinstance(enabled, bool):
                    raise ServiceError(400, "enabled must be a boolean")
                if (
                    not isinstance(required_confirmations, int)
                    or isinstance(required_confirmations, bool)
                    or required_confirmations <= 0
                ):
                    raise ServiceError(
                        400,
                        "required_confirmations must be a positive integer",
                    )
                if (
                    not isinstance(reorg_window, int)
                    or isinstance(reorg_window, bool)
                    or reorg_window < 0
                ):
                    raise ServiceError(
                        400, "reorg_window must be a non-negative integer"
                    )
                policy = {
                    "chain_id": chain_id,
                    "enabled": enabled,
                    "required_confirmations": required_confirmations,
                    "reorg_window": reorg_window,
                }
                self._emit(
                    wallet_id,
                    self._audit_event(
                        audit.TYPE_CHAIN_POLICY,
                        request_id=asset_id,
                        details=policy,
                    ),
                )
        except CorruptDataError:
            raise
        except ValueError:
            # wallet_id 含非法字符（构造锁路径时抛出）
            raise ServiceError(400, "invalid wallet_id")
        return policy

    def get_chain_policy(self, wallet_id: str, asset_id: str) -> dict:
        """读取某资产的跨链确认策略：已配置 200 同体，未配置 404。

        策略纯由事件恢复；损坏/矛盾事件 fail-closed（由 HTTP 边界转
        503）。钱包不存在 404。"""
        try:
            with self._wallet_lock(wallet_id):
                self._heal_wallet(wallet_id)
                # 404 优先：锁内先判定钱包存在，再判定策略是否已配置
                self._get_wallet_or_404(wallet_id)
                self._validate_asset_id(asset_id)
                policy = self._chain_policies(wallet_id).get(asset_id)
        except CorruptDataError:
            raise
        except ValueError:
            raise ServiceError(400, "invalid wallet_id")
        if policy is None:
            raise ServiceError(
                404,
                f"wallet {wallet_id!r} has no chain confirmation policy "
                f"for asset {asset_id!r}",
            )
        return policy

    # ---- 跨链适配器健康熔断 ----------------------------------------------

    def _normalize_adapters_body(self, adapters: object) -> dict:
        """校验 PUT chain-adapters 请求体 Q 的 adapters 表并归一。

        adapters 须为非空对象，键匹配 [A-Za-z0-9_-]{1,128}（dict 天然
        唯一）且**请求体内已按 ASCII 升序排列**（顺序错 400，不替客户端
        重排）；每值须为字符串 ``up|down``（拒绝布尔等非字符串）。返回按
        ASCII 升序的表（合法输入本就有序）。非法抛 ServiceError(400)。"""
        if not isinstance(adapters, dict) or not adapters:
            raise ServiceError(
                400,
                "adapters must be a non-empty object keyed by adapter id",
            )
        # 先确认键全为合法标识，再判定顺序与取值（混合类型键会让 sorted
        # 抛 TypeError，必须在排序前拦住，统一落 400 而非 503）。
        for adapter_id in adapters:
            if not isinstance(adapter_id, str) or not ROTATION_ID_RE.match(
                adapter_id
            ):
                raise ServiceError(
                    400, "adapter id must match [A-Za-z0-9_-]{1,128}"
                )
        keys = list(adapters)
        if keys != sorted(keys):
            raise ServiceError(
                400, "adapters must be listed in ASCII ascending order"
            )
        normalized: dict[str, str] = {}
        for adapter_id in keys:
            state = adapters[adapter_id]
            if not isinstance(state, str) or state not in CHAIN_ADAPTER_STATES:
                raise ServiceError(
                    400,
                    "adapter state must be one of "
                    + ", ".join(CHAIN_ADAPTER_STATES),
                )
            normalized[adapter_id] = state
        return normalized

    def _chain_adapter_health_events_strict(
        self, wallet_id: str
    ) -> list[dict]:
        """返回该钱包全部 chain_adapter_health 事件（按 seq 升序）并逐条
        严格校验**形状**：

        - 外层七字段须为落盘规范序
          （actor_id,at,details,reason,request_id,seq,type）；
        - request_id/actor_id/reason 必须为 null；
        - details 恰含 ``adapters``（单键）；
        - adapters 非空、键为安全标识且按 ASCII **升序唯一**；
        - 每个值恰为字符串 ``up|down``。

        重排、形状或取值矛盾都是不可对账现场（RecoveryError）；审计 JSON
        损坏抛 CorruptDataError、文件 I/O 失败抛 OSError。纯只读，不分配
        seq。"""
        events = self._audit.events_by_type(
            wallet_id, audit.TYPE_CHAIN_ADAPTER_HEALTH
        )
        for event in events:
            if list(event) != list(_AUDIT_OUTER_KEY_ORDER):
                raise RecoveryError(
                    f"wallet {wallet_id!r} has a chain_adapter_health event "
                    "whose outer fields are out of the canonical order"
                )
            if (
                event.get("request_id") is not None
                or event.get("actor_id") is not None
                or event.get("reason") is not None
            ):
                raise RecoveryError(
                    f"wallet {wallet_id!r} has a chain_adapter_health event "
                    "with request_id/actor/reason set"
                )
            details = event.get("details")
            if not isinstance(details, dict) or list(details) != ["adapters"]:
                raise RecoveryError(
                    f"wallet {wallet_id!r} has a malformed "
                    "chain_adapter_health event"
                )
            adapters = details["adapters"]
            if not isinstance(adapters, dict) or not adapters:
                raise RecoveryError(
                    f"wallet {wallet_id!r} has an empty or malformed "
                    "chain_adapter_health adapters table"
                )
            # 排序前先确认键全为字符串（损坏现场可能含非字符串键）。
            if any(not isinstance(k, str) for k in adapters):
                raise RecoveryError(
                    f"wallet {wallet_id!r} chain_adapter_health has a "
                    "non-string adapter id"
                )
            keys = list(adapters)
            if keys != sorted(keys) or len(set(keys)) != len(keys):
                raise RecoveryError(
                    f"wallet {wallet_id!r} chain_adapter_health adapters are "
                    "not in strictly ascending order"
                )
            for adapter_id, state in adapters.items():
                if (
                    not ROTATION_ID_RE.match(adapter_id)
                    or not isinstance(state, str)
                    or state not in CHAIN_ADAPTER_STATES
                ):
                    raise RecoveryError(
                        f"wallet {wallet_id!r} chain_adapter_health has a "
                        f"malformed entry for adapter {adapter_id!r}"
                    )
        return events

    def _chain_adapters_locked(self, wallet_id: str) -> Optional[dict]:
        """当前适配器健康表（调用方须持钱包事务锁）：取合并快照流（既有
        chain_adapter_health 事件与变更控制下 target=chain-adapters 的
        policy_change_applied）按 seq 的最后一条归一表；从未配置返回 None。

        每条事件均经严格形状校验（矛盾抛 RecoveryError）。"""
        events = self._adapter_health_snapshot_events_locked(wallet_id)
        if not events:
            return None
        adapters = events[-1]["details"]["adapters"]
        return {key: adapters[key] for key in adapters}

    def put_chain_adapters(self, wallet_id: str, adapters: object) -> dict:
        """设置跨链适配器健康熔断表，请求/成功响应（200）同为
        Q={"adapters": {A: "up"|"down"}}。

        adapters 非空、键匹配 [A-Za-z0-9_-]{1,128} 且请求体已按 ASCII
        升序排列，值仅 up|down；键集/类型/顺序/值错 400，钱包不存在 404，
        可首建。
        **首配/变更记一条 chain_adapter_health 事件；同值不记**
        （request_id/actor_id/reason 均为 null，details 恰为 Q）。健康表
        纯由审计事件持久化，不写状态文件。存在性判定、校验、比对与事件
        追加全部在每钱包跨进程事务锁内线性化：并发同参只有一个首配、其余
        同值不记。"""
        try:
            with self._wallet_lock(wallet_id):
                self._heal_wallet(wallet_id)
                # 404 优先于 400：锁内先判定钱包存在性，再校验请求体
                self._get_wallet_or_404(wallet_id)
                self._assert_wallet_active_locked(wallet_id)
                # 双人变更控制启用后受控 PUT 统一 409（零副作用）。
                self._assert_change_control_not_required_locked(wallet_id)
                normalized = self._normalize_adapters_body(adapters)
                body = {"adapters": normalized}
                current = self._chain_adapters_locked(wallet_id)
                # 同值（归一后逐键相等）不记事件；首配或任何差异才记。
                if current != normalized:
                    self._emit(
                        wallet_id,
                        self._audit_event(
                            audit.TYPE_CHAIN_ADAPTER_HEALTH,
                            details=body,
                        ),
                    )
        except CorruptDataError:
            raise
        except ValueError:
            # wallet_id 含非法字符（构造锁路径时抛出）
            raise ServiceError(400, "invalid wallet_id")
        return body

    def get_chain_adapters(self, wallet_id: str) -> dict:
        """读取跨链适配器健康表：已配置 200 返回 Q，从未配置 404。

        健康表纯由事件恢复（取最后一条）；损坏/矛盾事件 fail-closed（由
        HTTP 边界转 503）。钱包不存在 404。"""
        try:
            with self._wallet_lock(wallet_id):
                self._heal_wallet(wallet_id)
                # 404 优先：锁内先判定钱包存在，再判定健康表是否已配置
                self._get_wallet_or_404(wallet_id)
                adapters = self._chain_adapters_locked(wallet_id)
        except CorruptDataError:
            raise
        except ValueError:
            raise ServiceError(400, "invalid wallet_id")
        if adapters is None:
            raise ServiceError(
                404,
                f"wallet {wallet_id!r} has no configured chain adapter health",
            )
        return {"adapters": adapters}

    def post_chain_report(
        self,
        wallet_id: str,
        operation_id: object,
        chain_id: object,
        tx_id: object,
        block_height: object,
        block_hash: object,
        confirmations: object,
    ) -> tuple[int, dict]:
        """上报某资产操作的链上确认数。返回 (HTTP 状态码, 报告 B)。

        首报/采纳的新报告 201，同体幂等重放 200；键集（HTTP 边界）/值
        非法 400；钱包/操作未知 404；策略未启用、链或 tx 冲突、同块
        确认数下降、高度回退越界、终态后异体报告一律 409。报告达
        required_confirmations 时按既有 commit 契约提交一次：报告事件
        与紧邻的唯一提交事件同批原子落盘构成提交点（seq 为 n、n+1），
        提交失败（如余额不足）报告不落盘。恢复检查、校验、状态判定与
        事件追加全部在锁内完成。"""
        try:
            with self._wallet_lock(wallet_id):
                self._heal_wallet(wallet_id)
                # 404 优先于 400：存在性在锁内、heal 之后先判定
                self._get_wallet_or_404(wallet_id)
                self._assert_wallet_active_locked(wallet_id)
                # 持锁访问先重放策略、票、报告、操作与相邻提交事件
                # （heal 仅在账本文件存在时覆盖）：矛盾现场 fail-closed，
                # 优先于参数 400/404 判定。
                self._reconcile_chain_state_locked(wallet_id)
                self._validate_operation_id(operation_id)
                self._validate_chain_id(chain_id)
                self._validate_hex_32(tx_id, "tx_id")
                self._validate_non_negative_int(block_height, "block_height")
                self._validate_hex_32(block_hash, "block_hash")
                self._validate_non_negative_int(confirmations, "confirmations")
                record = self._store.get_asset_operation(
                    wallet_id, operation_id
                )
                if record is None:
                    raise ServiceError(
                        404, f"asset operation {operation_id!r} not found"
                    )
                # 资产粒度冻结闸门：先于终态同体重放与一切状态机判定，
                # frozen 时重放也 409、不产生懒过期/事件/现场变化。
                self._assert_asset_active_locked(
                    wallet_id, record["asset_id"]
                )
                policy = self._chain_policies(wallet_id).get(
                    record["asset_id"]
                )
                if policy is None or not policy["enabled"]:
                    raise ServiceError(
                        409,
                        f"chain confirmation policy for asset "
                        f"{record['asset_id']!r} is not enabled",
                    )
                if chain_id != policy["chain_id"]:
                    raise ServiceError(
                        409,
                        f"chain_id {chain_id!r} does not match the "
                        "policy chain",
                    )
                report = {
                    "chain_id": chain_id,
                    "tx_id": tx_id,
                    "block_height": block_height,
                    "block_hash": block_hash,
                    "confirmations": confirmations,
                }
                last = self._chain_reports(wallet_id).get(operation_id)
                if record["state"] == "committed":
                    # 终态：仅同体幂等重放，异体一律冲突
                    if last is not None and report == last:
                        return 200, report
                    raise ServiceError(
                        409,
                        f"asset operation {operation_id!r} is already "
                        "committed",
                    )
                # 该资产启用多源仲裁后，pending 操作只能经 observe 达
                # quorum 提交：链上确认报告一律 409（committed 重放不受
                # 影响，已在上方终态分支返回）。
                if (
                    self._chain_arbitration_policies(wallet_id).get(
                        record["asset_id"]
                    )
                    is not None
                ):
                    raise ServiceError(
                        409,
                        f"asset {record['asset_id']!r} requires multi-source "
                        "arbitration observations to commit",
                    )
                if last is not None and report == last:
                    # 同体重放不记事件。达门槛报告与提交事件同批原子落盘：
                    # 能走到这里（heal 通过、操作仍 pending）说明该报告
                    # 未达门槛——达门槛的同体报告必然伴随已落盘的提交事件，
                    # 恢复早已前滚为 committed 或对矛盾现场 fail-closed。
                    return 200, report
                error = self._report_transition_error(policy, last, report)
                if error is not None:
                    raise ServiceError(409, error)
                if confirmations >= policy["required_confirmations"]:
                    # 达门槛：按既有 commit 契约提交一次，报告事件与
                    # 提交事件紧邻；提交失败则报告不落盘
                    self._commit_asset_operation_locked(
                        wallet_id,
                        operation_id,
                        record,
                        report_details=report,
                    )
                else:
                    self._emit(
                        wallet_id,
                        self._audit_event(
                            audit.TYPE_CHAIN_REPORT,
                            request_id=operation_id,
                            details=report,
                        ),
                    )
                return 201, report
        except CorruptDataError:
            raise
        except ValueError:
            # wallet_id 含非法字符（构造锁路径时抛出）
            raise ServiceError(400, "invalid wallet_id")

    def _reconcile_chain_events(self, wallet_id: str) -> None:
        """链确认事件（chain_policy/chain_report）与资产提交的严格对账
        （调用方须持钱包事务锁；意图残留须已先恢复清零）。

        按 seq 重放全部事件，逐事件核对在线规则：

        - chain_policy/chain_report 事件形状必须合法（标识、hex、整数）；
          链确认策略按 legacy chain_policy 与 target=chain-policy 的
          policy_change_applied 合并流折叠；
        - 报告必须指向账本中存在的操作，且当时该资产策略已启用、链一致；
        - 报告状态机（tx/链绑定、同块确认数不降、换块回退不超窗、低于
          门槛的同体报告不产生事件、终态后不再有报告）逐事件成立；
        - 达门槛的报告事件必须紧邻同操作的 asset_operation_committed
          （两事件同批原子落盘，孤立达门槛报告即矛盾现场）；
        - 策略启用时的资产提交事件必须紧邻一条达门槛的 chain_report、
          一条同操作的 chain_dispatch_settled 或一条同操作的
          chain_dispatch_reorged（启用时人工提交 pending 在线被 409
          拒绝，日志里出现即矛盾）。

        任一矛盾抛 RecoveryError（fail-closed，保留现场）。纯只读，
        不写状态、不记事件、不改 seq。
        """
        ledger = self._store.check_asset_ledger_semantics(wallet_id)
        operations = ledger["operations"]
        policies: dict[str, dict] = {}
        reports: dict[str, dict] = {}
        committed: set[str] = set()
        prev: dict | None = None
        # target=chain-policy 的 policy_change_applied 与 legacy
        # chain_policy 事件按 seq 合并折叠（均先经严格校验）。
        policy_changes = {
            event["seq"]: (
                event["details"]["asset_id"],
                dict(event["details"]["after"]),
            )
            for event in self._policy_change_events_strict(wallet_id)
            if event["details"]["target"] == "chain-policy"
        }
        events = self._audit.all_events(wallet_id)
        for index, event in enumerate(events):
            event_type = event.get("type")
            if event_type == audit.TYPE_CHAIN_POLICY:
                asset_id, policy = self._chain_policy_shape(
                    wallet_id, event
                )
                policies[asset_id] = policy
            elif event_type == audit.TYPE_POLICY_CHANGE_APPLIED:
                change = policy_changes.get(event.get("seq"))
                if change is not None:
                    policies[change[0]] = change[1]
            elif event_type == audit.TYPE_CHAIN_REPORT:
                operation_id, report = self._chain_report_shape(
                    wallet_id, event
                )
                record = operations.get(operation_id)
                if record is None:
                    raise RecoveryError(
                        f"wallet {wallet_id!r} has a chain_report event "
                        f"for unknown asset operation {operation_id!r}"
                    )
                if operation_id in committed:
                    raise RecoveryError(
                        f"wallet {wallet_id!r} has a chain_report event "
                        f"for committed asset operation {operation_id!r}"
                    )
                policy = policies.get(record["asset_id"])
                if policy is None or not policy["enabled"]:
                    raise RecoveryError(
                        f"wallet {wallet_id!r} has a chain_report event "
                        f"for {operation_id!r} without an enabled policy"
                    )
                if report["chain_id"] != policy["chain_id"]:
                    raise RecoveryError(
                        f"wallet {wallet_id!r} has a chain_report event "
                        f"for {operation_id!r} on a different chain"
                    )
                error = self._report_transition_error(
                    policy, reports.get(operation_id), report
                )
                if error is not None:
                    raise RecoveryError(
                        f"wallet {wallet_id!r} has an inconsistent "
                        f"chain_report event for {operation_id!r}: {error}"
                    )
                if report["confirmations"] >= policy["required_confirmations"]:
                    # 达门槛报告与提交事件同批原子落盘：下一条必须紧邻同
                    # 操作的提交事件，否则是崩溃窗口外的矛盾现场（外部
                    # 篡改/半写），fail-closed 保留现场、拒绝就绪
                    follower = (
                        events[index + 1] if index + 1 < len(events) else None
                    )
                    if (
                        follower is None
                        or follower.get("type")
                        != audit.TYPE_ASSET_OPERATION_COMMITTED
                        or follower.get("request_id") != operation_id
                    ):
                        raise RecoveryError(
                            f"wallet {wallet_id!r} has a threshold "
                            f"chain_report event for {operation_id!r} "
                            "without an adjacent committed event"
                        )
                reports[operation_id] = report
            elif event_type == audit.TYPE_ASSET_OPERATION_COMMITTED:
                operation_id = event.get("request_id")
                record = (
                    operations.get(operation_id)
                    if isinstance(operation_id, str)
                    else None
                )
                if record is not None:
                    policy = policies.get(record["asset_id"])
                    if policy is not None and policy["enabled"]:
                        # 启用时只能经链上触发提交：提交事件必须紧邻一条
                        # 达门槛的 chain_report（确认数报告自动提交），或
                        # 紧邻一条同操作的 chain_dispatch_settled（跨链
                        # 派发最终性结算），或紧邻一条同操作的
                        # chain_dispatch_reorged（已结算派发重组补偿）。
                        prev_details = (
                            prev.get("details")
                            if isinstance(prev, dict)
                            else None
                        )
                        settle_trigger = (
                            prev is not None
                            and prev.get("type")
                            == audit.TYPE_CHAIN_DISPATCH_SETTLED
                            and isinstance(prev_details, dict)
                            and prev_details.get("operation_id")
                            == operation_id
                        )
                        reorg_trigger = (
                            prev is not None
                            and prev.get("type")
                            == audit.TYPE_CHAIN_DISPATCH_REORGED
                            and isinstance(prev_details, dict)
                            and prev_details.get("operation_id")
                            == operation_id
                        )
                        report_trigger = (
                            prev_details
                            if prev is not None
                            and prev.get("type") == audit.TYPE_CHAIN_REPORT
                            and prev.get("request_id") == operation_id
                            else None
                        )
                        if (
                            not settle_trigger
                            and not reorg_trigger
                            and (
                                not isinstance(report_trigger, dict)
                                or report_trigger.get("confirmations")
                                < policy["required_confirmations"]
                            )
                        ):
                            raise RecoveryError(
                                f"wallet {wallet_id!r} committed asset "
                                f"operation {operation_id!r} without a "
                                "preceding threshold chain report or "
                                "dispatch settlement"
                            )
                    committed.add(operation_id)
            prev = event

    # ---- 跨链派发（dispatch）-------------------------------------------------

    #: dispatch 审批单 message / 事件 details V 的固定键序
    _DISPATCH_VIEW_KEY_ORDER = (
        "dispatch_id",
        "operation_id",
        "adapter_id",
        "chain_id",
        "state",
    )

    #: dispatch 结果回执视图 V / chain_dispatch_result 事件 details 的固定
    #: 键序
    _DISPATCH_RESULT_VIEW_KEY_ORDER = (
        "dispatch_id",
        "operation_id",
        "adapter_id",
        "chain_id",
        "state",
        "tx_id",
    )

    #: 接管响应 / chain_dispatch_taken_over 事件 details 的固定键序
    _DISPATCH_TAKEN_OVER_VIEW_KEY_ORDER = (
        "dispatch_id",
        "adapter_id",
        "state",
    )

    #: 隔离响应 / chain_dispatch_isolated 事件 details 的固定键序
    _DISPATCH_ISOLATED_VIEW_KEY_ORDER = (
        "dispatch_id",
        "adapter_id",
        "state",
    )

    @staticmethod
    def _takeover_approval_message(
        dispatch_id: str, adapter_id: str
    ) -> str:
        """接管审批单 message 必须逐字一致的紧凑 JSON（无空格、键序固定为
        dispatch_id,adapter_id）。"""
        return json.dumps(
            {
                "dispatch_id": dispatch_id,
                "adapter_id": adapter_id,
            },
            ensure_ascii=False,
            separators=(",", ":"),
        )

    def _dispatch_taken_over_view(
        self, dispatch_id: str, adapter_id: str
    ) -> dict:
        """接管成功/重放响应体 V（键序固定，state 恒为 requested）。"""
        return {
            "dispatch_id": dispatch_id,
            "adapter_id": adapter_id,
            "state": "requested",
        }

    def _dispatch_takeover_event_locked(
        self, wallet_id: str, dispatch_id: str
    ) -> Optional[dict]:
        """返回某派发唯一的 chain_dispatch_taken_over 事件（调用方持锁）；
        未接管返回 None；重复接管事件是不可对账现场（RecoveryError）。"""
        grouped = self._audit.chain_dispatch_taken_over_events(
            wallet_id
        ).get(dispatch_id)
        if not grouped:
            return None
        if len(grouped) != 1:
            raise RecoveryError(
                f"wallet {wallet_id!r} has multiple "
                f"chain_dispatch_taken_over events for {dispatch_id!r}"
            )
        return grouped[0]

    def _effective_broadcasted_result_locked(
        self, wallet_id: str, dispatch_id: str
    ) -> tuple[Optional[dict], Optional[dict]]:
        """返回某派发当前生效适配器的 broadcasted 结果与接管事件
        （调用方持锁）。

        未接管时返回 (唯一 broadcasted 结果或 None, None)；接管后返回
        （接管之后新适配器的 broadcasted 结果或 None, 接管事件）。原适配器
        的 failed 结果在接管后不作为 broadcasted 结果。"""
        takeover_event = self._dispatch_takeover_event_locked(
            wallet_id, dispatch_id
        )
        result_group = (
            self._audit.chain_dispatch_result_events(wallet_id).get(
                dispatch_id
            )
            or []
        )
        if takeover_event is None:
            if (
                len(result_group) == 1
                and result_group[0]["details"]["state"] == "broadcasted"
            ):
                return result_group[0], None
            return None, None
        takeover_seq = takeover_event["seq"]
        post = [
            event
            for event in result_group
            if event["seq"] > takeover_seq
        ]
        if (
            len(post) == 1
            and post[0]["details"]["state"] == "broadcasted"
        ):
            return post[0], takeover_event
        return None, takeover_event

    @staticmethod
    def _dispatch_approval_message(
        operation_id: str,
        dispatch_id: str,
        adapter_id: str,
        chain_id: str,
    ) -> str:
        """审批单 message 必须逐字一致的紧凑 JSON（无空格、键序固定为
        operation_id,dispatch_id,adapter_id,chain_id）。"""
        return json.dumps(
            {
                "operation_id": operation_id,
                "dispatch_id": dispatch_id,
                "adapter_id": adapter_id,
                "chain_id": chain_id,
            },
            ensure_ascii=False,
            separators=(",", ":"),
        )

    @staticmethod
    def _dispatch_auto_approval_message(
        operation_id: str,
        dispatch_id: str,
        chain_id: str,
    ) -> str:
        """自动派发审批单 message 必须逐字一致的紧凑 JSON（无空格、键序
        固定为 operation_id,dispatch_id,chain_id；适配器由服务端按健康
        快照选择，故不入 message）。"""
        return json.dumps(
            {
                "operation_id": operation_id,
                "dispatch_id": dispatch_id,
                "chain_id": chain_id,
            },
            ensure_ascii=False,
            separators=(",", ":"),
        )

    def _dispatch_view(
        self,
        dispatch_id: str,
        operation_id: str,
        adapter_id: str,
        chain_id: str,
    ) -> dict:
        """dispatch 成功/重放响应体 V（键序固定，state 恒为 requested）。"""
        return {
            "dispatch_id": dispatch_id,
            "operation_id": operation_id,
            "adapter_id": adapter_id,
            "chain_id": chain_id,
            "state": "requested",
        }

    def _dispatch_events_strict(self, wallet_id: str) -> list[dict]:
        """返回该钱包全部 chain_dispatch_requested 事件（按 seq 升序）并
        逐条严格校验**形状**（外层七字段键序、request_id==dispatch_id、
        actor_id 为安全标识、reason 为 null、details 恰为五键 V 且键序
        固定、各值合法）。

        这里只做与现场无关的形状校验；与账本/策略/审批单的语义复核在
        :meth:`_reconcile_chain_dispatch_events` 按事件 seq 完成。任何
        形状畸形都是不可对账现场（RecoveryError）。纯只读，不分配 seq。"""
        return self._dispatch_request_events_strict_of_type(
            wallet_id, audit.TYPE_CHAIN_DISPATCH_REQUESTED
        )

    def _dispatch_auto_events_strict(self, wallet_id: str) -> list[dict]:
        """返回该钱包全部 chain_dispatch_auto_requested 事件（按 seq 升序）
        并逐条严格校验**形状**。自动派发与手工派发同形（外层七字段键序、
        request_id==dispatch_id、actor_id 为安全标识、reason 为 null、
        details 恰为五键 V 且键序固定、各值合法）。

        形状无关现场；与账本/策略/审批单/**事前健康快照与首选适配器**的
        语义复核在 :meth:`_reconcile_chain_dispatch_auto_events` 按事件
        seq 完成。任何形状畸形都是不可对账现场（RecoveryError）。纯只读，
        不分配 seq。"""
        return self._dispatch_request_events_strict_of_type(
            wallet_id, audit.TYPE_CHAIN_DISPATCH_AUTO_REQUESTED
        )

    def _dispatch_request_events_strict_of_type(
        self, wallet_id: str, event_type: str
    ) -> list[dict]:
        """手工/自动派发请求事件共用的严格形状校验：两种事件的七字段外层
        序、request_id/actor_id/reason 与 details 五键 V 的形状完全同构，
        仅事件类型不同。逐条核对，畸形即 RecoveryError，纯只读。"""
        # 用 events_by_type 而非按 request_id 分组：后者会丢掉 request_id
        # 为 null/非字符串的畸形事件，必须让它们也进入严格校验而非被静默
        # 忽略。
        events = self._audit.events_by_type(wallet_id, event_type)
        seen: set[str] = set()
        for event in events:
            if list(event) != list(_AUDIT_OUTER_KEY_ORDER):
                raise RecoveryError(
                    f"wallet {wallet_id!r} has a {event_type} event whose "
                    "outer fields are out of the canonical order"
                )
            dispatch_id = event.get("request_id")
            actor_id = event.get("actor_id")
            if (
                not isinstance(dispatch_id, str)
                or not ROTATION_ID_RE.match(dispatch_id)
            ):
                raise RecoveryError(
                    f"wallet {wallet_id!r} has a {event_type} event with a "
                    "malformed dispatch_id"
                )
            if dispatch_id in seen:
                raise RecoveryError(
                    f"wallet {wallet_id!r} has multiple {event_type} events "
                    f"for {dispatch_id!r}"
                )
            seen.add(dispatch_id)
            if not (
                isinstance(actor_id, str) and ROTATION_ID_RE.match(actor_id)
            ):
                raise RecoveryError(
                    f"wallet {wallet_id!r} {event_type} {dispatch_id!r} has "
                    "a malformed approval_request_id"
                )
            if event.get("reason") is not None:
                raise RecoveryError(
                    f"wallet {wallet_id!r} {event_type} {dispatch_id!r} has "
                    "a non-null reason"
                )
            details = event.get("details")
            if (
                not isinstance(details, dict)
                or list(details) != list(self._DISPATCH_VIEW_KEY_ORDER)
            ):
                raise RecoveryError(
                    f"wallet {wallet_id!r} {event_type} {dispatch_id!r} has "
                    "malformed details"
                )
            if details["dispatch_id"] != dispatch_id:
                raise RecoveryError(
                    f"wallet {wallet_id!r} {event_type} {dispatch_id!r} "
                    "details dispatch_id disagrees with its request_id"
                )
            for name in ("operation_id", "adapter_id", "chain_id"):
                value = details[name]
                if not isinstance(value, str) or not ROTATION_ID_RE.match(
                    value
                ):
                    raise RecoveryError(
                        f"wallet {wallet_id!r} {event_type} {dispatch_id!r} "
                        f"has a malformed {name}"
                    )
            if details["state"] != "requested":
                raise RecoveryError(
                    f"wallet {wallet_id!r} {event_type} {dispatch_id!r} has "
                    "a state other than requested"
                )
        return events

    def _dispatch_all_request_events_strict(self, wallet_id: str) -> list[dict]:
        """手工与自动派发请求事件合并后的严格视图（按 seq 升序）。

        下游派发生命周期（result/confirm/finality/settle/takeover/
        isolate）的"派发请求"既可是 chain_dispatch_requested，也可是
        chain_dispatch_auto_requested：两种事件同形、互不分叉。这里先逐条
        完成两种事件的形状校验，再保证同一 dispatch_id 不跨类型重复；每
        个操作至多一条派发（两种类型合计）由手工/自动各自的语义对账交叉
        保证。任何矛盾都是不可对账现场（RecoveryError）。纯只读。"""
        manual = self._dispatch_events_strict(wallet_id)
        auto = self._dispatch_auto_events_strict(wallet_id)
        manual_ids = {event["request_id"] for event in manual}
        for event in auto:
            if event["request_id"] in manual_ids:
                raise RecoveryError(
                    f"wallet {wallet_id!r} has both manual and auto chain "
                    f"dispatch request events for {event['request_id']!r}"
                )
        return sorted(manual + auto, key=lambda event: event["seq"])

    def _dispatch_requests_grouped_locked(
        self, wallet_id: str
    ) -> dict[str, list[dict]]:
        """持锁在线视图：手工与自动派发请求事件合并、按 dispatch_id 分组
        （组内按 seq 升序）。形状/跨类型重复已由持锁前的
        _reconcile_chain_state_locked 严格对账，这里只合并读取。"""
        grouped: dict[str, list[dict]] = {
            dispatch_id: list(events)
            for dispatch_id, events in
            self._audit.chain_dispatch_requested_events(wallet_id).items()
        }
        for dispatch_id, events in (
            self._audit.chain_dispatch_auto_requested_events(wallet_id).items()
        ):
            if dispatch_id in grouped:
                raise RecoveryError(
                    f"wallet {wallet_id!r} has both manual and auto chain "
                    f"dispatch request events for {dispatch_id!r}"
                )
            grouped[dispatch_id] = list(events)
        return grouped

    def _reconcile_chain_dispatch_events(self, wallet_id: str) -> None:
        """按 seq 严格复核全部 chain_dispatch_requested 事件（调用方须持
        钱包事务锁）。

        每条事件都以其**提交之前**的现场复核在线首提的全部前置：

        - 操作在账本中存在、提交点之前无该操作的
          asset_operation_committed（当时为 pending）；
        - 每个操作至多一条派发事件（同 dispatch_id 重复已在形状校验
          拦截）；
        - 事前该资产跨链确认策略（该事件 seq 之前最后一条 chain_policy）
          已启用且 chain_id 与 details 一致；
        - 同钱包审批单 actor_id 存在，message 逐字为按
          operation_id,dispatch_id,adapter_id,chain_id 序的紧凑 JSON，
          状态为 approved（其后经 /sign 推进为 signed 亦认可）。

        任一不满足都是不可对账现场（RecoveryError，fail-closed，保留
        现场）。纯只读，不记事件、不改 seq、不写状态。"""
        events = self._dispatch_events_strict(wallet_id)
        # 自动派发与手工派发共享每个操作"至多一条派发"：先把自动事件的
        # 操作集合计入，自动对账再对称地把手工事件计入。
        auto_events = self._dispatch_auto_events_strict(wallet_id)
        self._reconcile_dispatch_request_events(
            wallet_id,
            events,
            seeded_operations={
                event["details"]["operation_id"] for event in auto_events
            },
            require_health_snapshot=False,
        )

    def _reconcile_chain_dispatch_auto_events(self, wallet_id: str) -> None:
        """按 seq 严格复核全部 chain_dispatch_auto_requested 事件（调用方
        须持钱包事务锁）。

        每条自动派发都以其**提交之前**的现场复核在线首提的全部前置（手工
        派发的前置之外，另加健康快照与首选适配器复核）：

        - 操作在账本中存在、提交点之前无该操作的
          asset_operation_committed（当时为 pending）；
        - 每个操作在手工/自动两类派发事件合计中至多一条；
        - 事前该资产跨链确认策略已启用且 chain_id 与 details 一致；
        - 事前**存在**健康快照（该事件 seq 之前最后一条
          chain_adapter_health），且 details.adapter_id 恰为该快照中状态
          为 ``up`` 的适配器里 ASCII 最小者（快照缺失、无 up、所选适配器
          不符都矛盾）；
        - 同钱包审批单 actor_id 存在，message 逐字为按
          operation_id,dispatch_id,chain_id 序的紧凑 JSON（无
          adapter_id），状态为 approved（其后经 /sign 推进为 signed 亦
          认可）。

        任一矛盾都 fail-closed（RecoveryError）；审计 JSON 损坏抛
        CorruptDataError、审计文件 I/O 失败抛 OSError。纯只读，不记事件、
        不改 seq。"""
        events = self._dispatch_auto_events_strict(wallet_id)
        manual_events = self._dispatch_events_strict(wallet_id)
        self._reconcile_dispatch_request_events(
            wallet_id,
            events,
            seeded_operations={
                event["details"]["operation_id"] for event in manual_events
            },
            require_health_snapshot=True,
        )

    def _reconcile_dispatch_request_events(
        self,
        wallet_id: str,
        events: list[dict],
        seeded_operations: set[str],
        require_health_snapshot: bool,
    ) -> None:
        """手工/自动派发请求事件共用的按 seq 语义对账。

        require_health_snapshot 为真时（自动派发），额外复核事前健康快照
        存在、至少一个 up 适配器、details.adapter_id 恰为 ASCII 最小的
        up；审批 message 也按无 adapter_id 的三键紧凑 JSON 核对。"""
        if not events:
            return
        # 手工/自动两类事件合并形状校验，并拦截同一 dispatch_id 跨类型
        # 重复（即使该派发没有任何下游事件也要 fail-closed）。
        self._dispatch_all_request_events_strict(wallet_id)
        ledger = self._store.check_asset_ledger_semantics(wallet_id)
        operations = ledger["operations"]
        # 重放全部事件，取各操作的提交 seq；各资产的策略历史（seq 升序）
        # 取 legacy chain_policy 与 target=chain-policy 的
        # policy_change_applied 合并流（均经严格校验）。
        committed_seq: dict[str, int] = {}
        policy_history: dict[str, list[tuple[int, dict]]] = {}
        for snap_seq, snap_asset, snap_policy in (
            self._chain_policy_snapshot_events_locked(wallet_id)
        ):
            policy_history.setdefault(snap_asset, []).append(
                (snap_seq, snap_policy)
            )
        for event in self._audit.all_events(wallet_id):
            event_type = event.get("type")
            if event_type == audit.TYPE_ASSET_OPERATION_COMMITTED:
                request_id = event.get("request_id")
                if isinstance(request_id, str):
                    committed_seq[request_id] = event["seq"]
        # 健康快照按 seq 升序（chain_adapter_health 与变更控制下
        # target=chain-adapters 的 policy_change_applied 合并流，均经严格
        # 形状校验）：自动派发取其事件 seq 之前的最后一条。
        health_events = (
            self._adapter_health_snapshot_events_locked(wallet_id)
            if require_health_snapshot
            else []
        )
        dispatched_operations: set[str] = set(seeded_operations)
        for event in events:
            details = event["details"]
            seq = event["seq"]
            operation_id = details["operation_id"]
            record = operations.get(operation_id)
            if record is None:
                raise RecoveryError(
                    f"wallet {wallet_id!r} has a {event['type']} event for "
                    f"unknown asset operation {operation_id!r}"
                )
            if operation_id in dispatched_operations:
                raise RecoveryError(
                    f"wallet {wallet_id!r} has multiple dispatch request "
                    f"events for asset operation {operation_id!r}"
                )
            dispatched_operations.add(operation_id)
            commit_seq = committed_seq.get(operation_id)
            if commit_seq is not None and commit_seq < seq:
                raise RecoveryError(
                    f"wallet {wallet_id!r} has a {event['type']} event for "
                    f"already committed asset operation {operation_id!r}"
                )
            # 事前策略：该事件 seq 之前最后一条该资产链确认策略（legacy
            # chain_policy 与 chain-policy 变更事件的合并流）。
            policy = None
            for policy_seq, candidate in policy_history.get(
                record["asset_id"], []
            ):
                if policy_seq < seq:
                    policy = candidate
            if policy is None or not policy["enabled"]:
                raise RecoveryError(
                    f"wallet {wallet_id!r} has a {event['type']} event for "
                    f"{operation_id!r} without an enabled policy"
                )
            if policy["chain_id"] != details["chain_id"]:
                raise RecoveryError(
                    f"wallet {wallet_id!r} has a {event['type']} event for "
                    f"{operation_id!r} on a different chain"
                )
            if require_health_snapshot:
                # 事前健康表：seq 之前最后一条快照必须存在，且首选适配器
                # 恰为快照中 ASCII 最小的 up；无快照、无 up 或选择不符都
                # 是矛盾现场。
                health_table = None
                for health_event in health_events:
                    if health_event["seq"] < seq:
                        health_table = health_event["details"]["adapters"]
                    else:
                        break
                if health_table is None:
                    raise RecoveryError(
                        f"wallet {wallet_id!r} has a {event['type']} event "
                        f"for {operation_id!r} without a preceding adapter "
                        "health snapshot"
                    )
                up_adapters = sorted(
                    adapter_id
                    for adapter_id, state in health_table.items()
                    if state == "up"
                )
                if not up_adapters:
                    raise RecoveryError(
                        f"wallet {wallet_id!r} has a {event['type']} event "
                        f"for {operation_id!r} with no up adapter in the "
                        "preceding health snapshot"
                    )
                if details["adapter_id"] != up_adapters[0]:
                    raise RecoveryError(
                        f"wallet {wallet_id!r} {event['type']} "
                        f"{details['dispatch_id']!r} picked "
                        f"{details['adapter_id']!r} but the ASCII-smallest up "
                        f"adapter was {up_adapters[0]!r}"
                    )
            # 按 actor_id 复核同钱包审批单：存在、message 逐字一致、状态
            # 为 approved（其后经 /sign 推进为 signed 亦认可）。
            actor_id = event["actor_id"]
            try:
                approval = self._store.get_request(wallet_id, actor_id)
            except CorruptDataError:
                raise
            except ValueError as exc:
                raise RecoveryError(
                    f"wallet {wallet_id!r} chain dispatch approval record "
                    "is unreadable"
                ) from exc
            if not isinstance(approval, dict):
                raise RecoveryError(
                    f"wallet {wallet_id!r} {event['type']} "
                    f"{details['dispatch_id']!r} refers to an unknown "
                    "approval request"
                )
            if require_health_snapshot:
                expected_message = self._dispatch_auto_approval_message(
                    operation_id,
                    details["dispatch_id"],
                    details["chain_id"],
                )
            else:
                expected_message = self._dispatch_approval_message(
                    operation_id,
                    details["dispatch_id"],
                    details["adapter_id"],
                    details["chain_id"],
                )
            if approval.get("message") != expected_message:
                raise RecoveryError(
                    f"wallet {wallet_id!r} {event['type']} "
                    f"{details['dispatch_id']!r} approval message does not "
                    "match"
                )
            if approval.get("state") not in ("approved", "signed"):
                raise RecoveryError(
                    f"wallet {wallet_id!r} {event['type']} "
                    f"{details['dispatch_id']!r} approval request is not "
                    "approved"
                )

    def post_chain_dispatch(
        self,
        wallet_id: str,
        operation_id: object,
        dispatch_id: object,
        adapter_id: object,
        approval_request_id: object,
    ) -> tuple[int, dict]:
        """请求把某 pending 资产操作派发到链上适配器，返回
        (HTTP 状态码, 视图 V={dispatch_id,operation_id,adapter_id,
        chain_id,state})。

        请求体恰含 dispatch_id,adapter_id,approval_request_id 三键
        （HTTP 边界拦键集），各值须为安全标识，非法 400；钱包/操作/
        该资产跨链确认策略/同钱包审批单任一未知 404。首提前置：操作
        为 pending、策略已启用、审批单经锁内懒过期后为 approved 且
        message 逐字为按 operation_id,dispatch_id,adapter_id,chain_id
        序的紧凑 JSON；任一不满足 409 且现场不变。

        首提 201；同 dispatch_id 同参（含路径操作与审批单）重放 200
        返回同一 V（优先于状态与审批判定，不复查现状）；同 dispatch_id
        异参、或该操作已有其他 dispatch_id 的派发，一律 409。
        chain_dispatch_requested 是唯一提交点
        （request_id=dispatch_id、actor_id=approval_request_id、
        reason=null、details=V）；锁内并发只有一个 201，失败/重放不记
        事件。恢复检查、校验、状态判定与事件追加全部在锁内完成。"""
        try:
            with self._wallet_lock(wallet_id):
                self._heal_wallet(wallet_id)
                # 404 优先于 400：存在性在锁内、heal 之后先判定
                self._get_wallet_or_404(wallet_id)
                self._assert_wallet_active_locked(wallet_id)
                # 持锁访问先重放策略、报告、票、派发、操作与相邻提交事件
                # （heal 仅在账本文件存在时覆盖）：矛盾现场 fail-closed，
                # 优先于参数 400/404 判定。
                self._reconcile_chain_state_locked(wallet_id)
                # 类型/取值校验（400）
                self._validate_operation_id(operation_id)
                for name, value in (
                    ("dispatch_id", dispatch_id),
                    ("adapter_id", adapter_id),
                    ("approval_request_id", approval_request_id),
                ):
                    if not isinstance(value, str) or not ROTATION_ID_RE.match(
                        value
                    ):
                        raise ServiceError(
                            400,
                            f"{name} must match [A-Za-z0-9_-]{{1,128}}",
                        )

                # 404 与资产冻结闸门先于幂等重放：frozen 资产的派发请求
                # 即便同参重放也一律 409 且零副作用。
                record = self._store.get_asset_operation(
                    wallet_id, operation_id
                )
                if record is None:
                    raise ServiceError(
                        404, f"asset operation {operation_id!r} not found"
                    )
                self._assert_asset_active_locked(
                    wallet_id, record["asset_id"]
                )

                dispatches = self._dispatch_requests_grouped_locked(wallet_id)
                # 幂等优先于 404/状态判定：已提交的同 dispatch_id 重放。
                # 手工与自动派发事件合并查找：同一 dispatch_id 若由自动
                # 派发提交，其 actor/参数不可能与手工请求全等，落入下方
                # 异参 409。
                committed_groups = dispatches.get(dispatch_id)
                if committed_groups:
                    if len(committed_groups) != 1:
                        raise RecoveryError(
                            f"wallet {wallet_id!r} has multiple dispatch "
                            f"request events for {dispatch_id!r}"
                        )
                    committed_event = committed_groups[0]
                    saved = committed_event["details"]
                    if (
                        committed_event["type"]
                        == audit.TYPE_CHAIN_DISPATCH_REQUESTED
                        and saved["operation_id"] == operation_id
                        and saved["adapter_id"] == adapter_id
                        and committed_event["actor_id"]
                        == approval_request_id
                    ):
                        # 同参（含审批单标识）重放：200 同 V，不复查现状
                        return 200, dict(saved)
                    raise ServiceError(
                        409,
                        f"dispatch {dispatch_id!r} already exists with "
                        "different parameters",
                    )

                # 404：操作 / 该资产跨链确认策略 / 同钱包审批单未知
                record = self._store.get_asset_operation(
                    wallet_id, operation_id
                )
                if record is None:
                    raise ServiceError(
                        404, f"asset operation {operation_id!r} not found"
                    )
                policy = self._chain_policies(wallet_id).get(
                    record["asset_id"]
                )
                if policy is None:
                    raise ServiceError(
                        404,
                        f"wallet {wallet_id!r} has no chain confirmation "
                        f"policy for asset {record['asset_id']!r}",
                    )
                approval = self._store.get_request(
                    wallet_id, approval_request_id
                )
                if approval is None:
                    raise ServiceError(
                        404,
                        f"approval request {approval_request_id!r} not found",
                    )

                # 409：操作非 pending
                if record["state"] != "pending":
                    raise ServiceError(
                        409,
                        f"asset operation {operation_id!r} is "
                        f"{record['state']}, not pending",
                    )
                # 409：策略停用
                if not policy["enabled"]:
                    raise ServiceError(
                        409,
                        f"chain confirmation policy for asset "
                        f"{record['asset_id']!r} is not enabled",
                    )
                # 409：该操作已有其他 dispatch_id 的派发
                for grouped in dispatches.values():
                    for prior in grouped:
                        if prior["details"]["operation_id"] == operation_id:
                            raise ServiceError(
                                409,
                                f"asset operation {operation_id!r} already "
                                "has a dispatch",
                            )

                # 适配器健康熔断：仅作用于**首提**（同参重放已在上方
                # 优先 200 返回，不复查健康表）。健康表未配置或该适配器
                # 缺席一律视为 up；仅显式 down 才 409，且零副作用（在
                # 任何事件追加之前）。健康事后变化不改写、不终止也不自动
                # 接管既有派发——这里没有任何按健康表遍历既有派发的逻辑。
                adapters = self._chain_adapters_locked(wallet_id)
                if adapters is not None and adapters.get(adapter_id) == "down":
                    raise ServiceError(
                        409,
                        f"chain adapter {adapter_id!r} is down (circuit "
                        "breaker open)",
                    )

                # 审批门控：同钱包既有 approved 审批单，message 逐字一致。
                # 按既有契约懒过期（可能原子记一次 request_expired）。
                approval = self._expire_if_needed(wallet_id, approval)
                expected_message = self._dispatch_approval_message(
                    operation_id, dispatch_id, adapter_id, policy["chain_id"]
                )
                if approval["message"] != expected_message:
                    raise ServiceError(
                        409,
                        "approval request message does not match this "
                        "dispatch",
                    )
                if approval["state"] != "approved":
                    raise ServiceError(
                        409,
                        f"approval request {approval_request_id!r} is "
                        f"{approval['state']}, not approved",
                    )

                # chain_dispatch_requested 是唯一提交点：在跨进程事务锁内
                # 追加事件；事件之外不写任何派发状态文件。
                view = self._dispatch_view(
                    dispatch_id, operation_id, adapter_id, policy["chain_id"]
                )
                self._emit(
                    wallet_id,
                    self._audit_event(
                        audit.TYPE_CHAIN_DISPATCH_REQUESTED,
                        request_id=dispatch_id,
                        actor_id=approval_request_id,
                        reason=None,
                        details=view,
                    ),
                )
                return 201, view
        except CorruptDataError:
            raise
        except ValueError:
            # wallet_id 含非法字符（构造锁路径时抛出）
            raise ServiceError(400, "invalid wallet_id")

    def post_chain_dispatch_auto(
        self,
        wallet_id: str,
        operation_id: object,
        dispatch_id: object,
        approval_request_id: object,
    ) -> tuple[int, dict]:
        """健康感知自动派发：把某 pending 资产操作按当前适配器健康熔断表
        自动派发到 ASCII 最小的 up 适配器，返回 (HTTP 状态码, 视图
        V={dispatch_id,operation_id,adapter_id,chain_id,state})。

        请求体恰含 dispatch_id,approval_request_id 两键（HTTP 边界拦键
        集），两值与路径操作均须为安全标识，非法 400；钱包/操作/该资产
        跨链确认策略/同钱包审批单任一未知 404。首提前置：操作为 pending、
        策略已启用、健康表已配置且至少一个 up 适配器（锁内取当前快照中
        ASCII 最小的 up）、审批单经锁内懒过期后为 approved 且 message
        逐字为按 operation_id,dispatch_id,chain_id 序的紧凑 JSON（无
        adapter_id）；任一不满足 409 且现场不变。

        首提 201；同 dispatch_id 同参（路径操作与审批单全同）重放 200
        返回同一 V（优先于状态/健康/审批判定，不复查现状）；同
        dispatch_id 异参、或该操作已有其他 dispatch_id 的派发（手工或
        自动），一律 409。chain_dispatch_auto_requested 是唯一提交点
        （request_id=dispatch_id、actor_id=approval_request_id、
        reason=null、details=V）；后续 result/confirm/finality/settle
        沿用 dispatch 契约。锁内并发只有一个 201，失败/重放不记事件。"""
        try:
            with self._wallet_lock(wallet_id):
                self._heal_wallet(wallet_id)
                # 404 优先于 400：存在性在锁内、heal 之后先判定
                self._get_wallet_or_404(wallet_id)
                self._assert_wallet_active_locked(wallet_id)
                # 持锁访问先重放策略、报告、票、手工/自动派发、操作与相邻
                # 提交事件：矛盾现场 fail-closed，优先于参数 400/404 判定。
                self._reconcile_chain_state_locked(wallet_id)
                # 类型/取值校验（400）
                self._validate_operation_id(operation_id)
                for name, value in (
                    ("dispatch_id", dispatch_id),
                    ("approval_request_id", approval_request_id),
                ):
                    if not isinstance(value, str) or not ROTATION_ID_RE.match(
                        value
                    ):
                        raise ServiceError(
                            400,
                            f"{name} must match [A-Za-z0-9_-]{{1,128}}",
                        )

                dispatches = self._dispatch_requests_grouped_locked(wallet_id)
                # 幂等优先于 404/状态/健康判定：已提交的同 dispatch_id
                # 重放。手工与自动派发事件合并查找：手工提交的 dispatch_id
                # 不可能与自动请求全等，落入异参 409。
                committed_groups = dispatches.get(dispatch_id)
                if committed_groups:
                    if len(committed_groups) != 1:
                        raise RecoveryError(
                            f"wallet {wallet_id!r} has multiple dispatch "
                            f"request events for {dispatch_id!r}"
                        )
                    committed_event = committed_groups[0]
                    saved = committed_event["details"]
                    if (
                        committed_event["type"]
                        == audit.TYPE_CHAIN_DISPATCH_AUTO_REQUESTED
                        and saved["operation_id"] == operation_id
                        and committed_event["actor_id"]
                        == approval_request_id
                    ):
                        # 同参（路径操作 + 审批单标识）重放：200 同 V，
                        # 不复查现状（事后健康翻转、审批单推进不影响）。
                        # 但资产粒度冻结闸门先于幂等：frozen 资产的自动
                        # 派发同参重放也一律 409 且零副作用。
                        replay_record = self._store.get_asset_operation(
                            wallet_id, operation_id
                        )
                        if replay_record is None:
                            raise ServiceError(
                                404,
                                f"asset operation {operation_id!r} not found",
                            )
                        self._assert_asset_active_locked(
                            wallet_id, replay_record["asset_id"]
                        )
                        return 200, dict(saved)
                    raise ServiceError(
                        409,
                        f"dispatch {dispatch_id!r} already exists with "
                        "different parameters",
                    )

                # 404：操作 / 该资产跨链确认策略 / 同钱包审批单未知
                record = self._store.get_asset_operation(
                    wallet_id, operation_id
                )
                if record is None:
                    raise ServiceError(
                        404, f"asset operation {operation_id!r} not found"
                    )
                policy = self._chain_policies(wallet_id).get(
                    record["asset_id"]
                )
                if policy is None:
                    raise ServiceError(
                        404,
                        f"wallet {wallet_id!r} has no chain confirmation "
                        f"policy for asset {record['asset_id']!r}",
                    )
                approval = self._store.get_request(
                    wallet_id, approval_request_id
                )
                if approval is None:
                    raise ServiceError(
                        404,
                        f"approval request {approval_request_id!r} not found",
                    )

                # 409：操作非 pending
                if record["state"] != "pending":
                    raise ServiceError(
                        409,
                        f"asset operation {operation_id!r} is "
                        f"{record['state']}, not pending",
                    )
                # 409：策略停用
                if not policy["enabled"]:
                    raise ServiceError(
                        409,
                        f"chain confirmation policy for asset "
                        f"{record['asset_id']!r} is not enabled",
                    )
                # 409：该操作已有其他 dispatch_id 的派发（手工或自动）
                for grouped in dispatches.values():
                    for prior in grouped:
                        if prior["details"]["operation_id"] == operation_id:
                            raise ServiceError(
                                409,
                                f"asset operation {operation_id!r} already "
                                "has a dispatch",
                            )

                # 健康感知选适配器：仅作用于**首提**（同参重放已在上方
                # 优先 200 返回）。健康表未配置或无 up 适配器一律 409，
                # 且零副作用（在任何事件追加之前）。选择在钱包锁内按当前
                # 快照完成：ASCII 最小的 up 适配器，确定性、无随机性。
                self._assert_asset_active_locked(
                    wallet_id, record["asset_id"]
                )
                adapters = self._chain_adapters_locked(wallet_id)
                if adapters is None:
                    raise ServiceError(
                        409,
                        "no chain adapter health table configured for "
                        "automatic dispatch",
                    )
                up_adapters = sorted(
                    adapter_id
                    for adapter_id, state in adapters.items()
                    if state == "up"
                )
                if not up_adapters:
                    raise ServiceError(
                        409,
                        "no up chain adapter available for automatic "
                        "dispatch",
                    )
                adapter_id = up_adapters[0]

                # 审批门控：同钱包既有 approved 审批单，message 逐字一致。
                # 适配器由服务端选择，message 不含 adapter_id。按既有契约
                # 懒过期（可能原子记一次 request_expired）。
                approval = self._expire_if_needed(wallet_id, approval)
                expected_message = self._dispatch_auto_approval_message(
                    operation_id, dispatch_id, policy["chain_id"]
                )
                if approval["message"] != expected_message:
                    raise ServiceError(
                        409,
                        "approval request message does not match this "
                        "automatic dispatch",
                    )
                if approval["state"] != "approved":
                    raise ServiceError(
                        409,
                        f"approval request {approval_request_id!r} is "
                        f"{approval['state']}, not approved",
                    )

                # chain_dispatch_auto_requested 是唯一提交点：在跨进程
                # 事务锁内追加事件；事件之外不写任何派发状态文件。
                view = self._dispatch_view(
                    dispatch_id, operation_id, adapter_id, policy["chain_id"]
                )
                self._emit(
                    wallet_id,
                    self._audit_event(
                        audit.TYPE_CHAIN_DISPATCH_AUTO_REQUESTED,
                        request_id=dispatch_id,
                        actor_id=approval_request_id,
                        reason=None,
                        details=view,
                    ),
                )
                return 201, view
        except CorruptDataError:
            raise
        except ValueError:
            # wallet_id 含非法字符（构造锁路径时抛出）
            raise ServiceError(400, "invalid wallet_id")

    # ---- 跨链派发结果回执 -------------------------------------------------

    def _dispatch_result_view(
        self,
        dispatch_id: str,
        operation_id: str,
        adapter_id: str,
        chain_id: str,
        state: str,
        tx_id,
    ) -> dict:
        """dispatch 结果回执成功/重放响应体 V（六键固定序）。"""
        return {
            "dispatch_id": dispatch_id,
            "operation_id": operation_id,
            "adapter_id": adapter_id,
            "chain_id": chain_id,
            "state": state,
            "tx_id": tx_id,
        }

    def _dispatch_result_events_strict(self, wallet_id: str) -> list[dict]:
        """返回该钱包全部 chain_dispatch_result 事件（按 seq 升序）并逐条
        严格校验**形状**（外层七字段键序、request_id==dispatch_id、
        actor_id 为安全标识且与 details.adapter_id 一致、reason 为 null、
        details 恰为六键 V 且键序固定、state/tx_id 取值合法）。

        与请求事件一致，这里只做与现场无关的形状校验；与派发请求的归属/
        先后语义复核在 :meth:`_reconcile_chain_dispatch_result_events` 按
        事件 seq 完成。任何形状畸形都是不可对账现场（RecoveryError）。纯
        只读，不分配 seq。"""
        events = self._audit.events_by_type(
            wallet_id, audit.TYPE_CHAIN_DISPATCH_RESULT
        )
        # 接管（chain_dispatch_taken_over）允许该派发在失败结果之后再接收
        # 新适配器的恰好一条结果：接管前至多一条、接管后至多一条；无接管
        # 的派发维持至多一条。接管事件形状独立（不依赖结果），这里直接取
        # 严格形状后的接管映射。
        takeover_by_dispatch = {
            event["request_id"]: event
            for event in self._dispatch_taken_over_events_strict(wallet_id)
        }
        result_seqs: dict[str, list[int]] = {}
        for event in events:
            if list(event) != list(_AUDIT_OUTER_KEY_ORDER):
                raise RecoveryError(
                    f"wallet {wallet_id!r} has a chain_dispatch_result "
                    "event whose outer fields are out of the canonical order"
                )
            dispatch_id = event.get("request_id")
            actor_id = event.get("actor_id")
            if (
                not isinstance(dispatch_id, str)
                or not ROTATION_ID_RE.match(dispatch_id)
            ):
                raise RecoveryError(
                    f"wallet {wallet_id!r} has a chain_dispatch_result "
                    "event with a malformed dispatch_id"
                )
            result_seqs.setdefault(dispatch_id, []).append(event["seq"])
            if not (
                isinstance(actor_id, str) and ROTATION_ID_RE.match(actor_id)
            ):
                raise RecoveryError(
                    f"wallet {wallet_id!r} chain_dispatch_result "
                    f"{dispatch_id!r} has a malformed adapter_id"
                )
            if event.get("reason") is not None:
                raise RecoveryError(
                    f"wallet {wallet_id!r} chain_dispatch_result "
                    f"{dispatch_id!r} has a non-null reason"
                )
            details = event.get("details")
            if (
                not isinstance(details, dict)
                or list(details)
                != list(self._DISPATCH_RESULT_VIEW_KEY_ORDER)
            ):
                raise RecoveryError(
                    f"wallet {wallet_id!r} chain_dispatch_result "
                    f"{dispatch_id!r} has malformed details"
                )
            if details["dispatch_id"] != dispatch_id:
                raise RecoveryError(
                    f"wallet {wallet_id!r} chain_dispatch_result "
                    f"{dispatch_id!r} details dispatch_id disagrees with "
                    "its request_id"
                )
            for name in ("operation_id", "adapter_id", "chain_id"):
                value = details[name]
                if not isinstance(value, str) or not ROTATION_ID_RE.match(
                    value
                ):
                    raise RecoveryError(
                        f"wallet {wallet_id!r} chain_dispatch_result "
                        f"{dispatch_id!r} has a malformed {name}"
                    )
            if details["adapter_id"] != actor_id:
                raise RecoveryError(
                    f"wallet {wallet_id!r} chain_dispatch_result "
                    f"{dispatch_id!r} details adapter_id disagrees with its "
                    "actor_id"
                )
            state = details["state"]
            tx_id = details["tx_id"]
            if state == "broadcasted":
                if not _is_lower_hex_32(tx_id):
                    raise RecoveryError(
                        f"wallet {wallet_id!r} chain_dispatch_result "
                        f"{dispatch_id!r} broadcasted result has a malformed "
                        "tx_id"
                    )
            elif state == "failed":
                if tx_id is not None:
                    raise RecoveryError(
                        f"wallet {wallet_id!r} chain_dispatch_result "
                        f"{dispatch_id!r} failed result has a non-null tx_id"
                    )
            else:
                raise RecoveryError(
                    f"wallet {wallet_id!r} chain_dispatch_result "
                    f"{dispatch_id!r} has an invalid state"
                )
        # 多重性：无接管的派发至多一条结果；已接管的派发在接管事件两侧
        # 各至多一条（接管前一条失败结果、接管后至多一条新适配器结果）。
        for dispatch_id, seqs in result_seqs.items():
            takeover = takeover_by_dispatch.get(dispatch_id)
            takeover_seq = takeover["seq"] if takeover is not None else None
            if takeover is None:
                if len(seqs) > 1:
                    raise RecoveryError(
                        f"wallet {wallet_id!r} has multiple "
                        f"chain_dispatch_result events for {dispatch_id!r}"
                    )
                continue
            before = [s for s in seqs if s < takeover_seq]
            after = [s for s in seqs if s > takeover_seq]
            if len(before) > 1 or len(after) > 1 or any(
                s == takeover_seq for s in seqs
            ):
                raise RecoveryError(
                    f"wallet {wallet_id!r} has malformed "
                    f"chain_dispatch_result events around the takeover of "
                    f"{dispatch_id!r}"
                )
        return events

    def _reconcile_chain_dispatch_result_events(
        self, wallet_id: str
    ) -> None:
        """按 seq 严格复核全部 chain_dispatch_result 事件（调用方须持钱包
        事务锁）。

        每条结果都以其**提交之前**的现场复核：

        - 存在同一 dispatch_id 的 chain_dispatch_requested，且其 seq 严格
          早于结果事件（请求先于结果）；
        - 归属一致：结果的 operation_id/adapter_id/chain_id 与请求 V 完全
          相同；
        - 每个派发至多一条结果（同 dispatch_id 重复已在形状校验拦截）。

        任一不满足都是不可对账现场（RecoveryError，fail-closed，保留
        现场）。纯只读，不记事件、不改 seq、不写状态。"""
        events = self._dispatch_result_events_strict(wallet_id)
        if not events:
            return
        requests = self._dispatch_all_request_events_strict(wallet_id)
        request_by_dispatch: dict[str, dict] = {}
        for event in requests:
            # 重复 dispatch_id 已在 _dispatch_events_strict 拦截。
            request_by_dispatch[event["request_id"]] = event
        takeover_by_dispatch = {
            event["request_id"]: event
            for event in self._dispatch_taken_over_events_strict(wallet_id)
        }
        for event in events:
            details = event["details"]
            dispatch_id = details["dispatch_id"]
            request = request_by_dispatch.get(dispatch_id)
            if request is None:
                raise RecoveryError(
                    f"wallet {wallet_id!r} has a chain_dispatch_result "
                    f"event for {dispatch_id!r} without a preceding dispatch "
                    "request"
                )
            if request["seq"] >= event["seq"]:
                raise RecoveryError(
                    f"wallet {wallet_id!r} chain_dispatch_result "
                    f"{dispatch_id!r} does not follow its dispatch request"
                )
            saved = request["details"]
            takeover = takeover_by_dispatch.get(dispatch_id)
            after_takeover = (
                takeover is not None and event["seq"] > takeover["seq"]
            )
            if after_takeover:
                # 接管后的结果：operation_id/chain_id 仍取自原派发请求，
                # adapter_id 取自接管事件（新适配器），且必须与原适配器不同。
                if (
                    details["operation_id"] != saved["operation_id"]
                    or details["chain_id"] != saved["chain_id"]
                ):
                    raise RecoveryError(
                        f"wallet {wallet_id!r} post-takeover "
                        f"chain_dispatch_result {dispatch_id!r} disagrees "
                        "with its dispatch request"
                    )
                new_adapter = takeover["details"]["adapter_id"]
                if details["adapter_id"] != new_adapter:
                    raise RecoveryError(
                        f"wallet {wallet_id!r} post-takeover "
                        f"chain_dispatch_result {dispatch_id!r} does not use "
                        "the takeover adapter"
                    )
            else:
                for name in ("operation_id", "adapter_id", "chain_id"):
                    if details[name] != saved[name]:
                        raise RecoveryError(
                            f"wallet {wallet_id!r} chain_dispatch_result "
                            f"{dispatch_id!r} {name} disagrees with its "
                            "dispatch request"
                        )

    def post_chain_dispatch_result(
        self,
        wallet_id: str,
        dispatch_id: object,
        adapter_id: object,
        state: object,
        tx_id: object,
    ) -> tuple[int, dict]:
        """上报跨链派发结果回执，返回 (HTTP 状态码, 视图
        V={dispatch_id,operation_id,adapter_id,chain_id,state,tx_id})。

        请求体恰含 adapter_id,state,tx_id 三键（HTTP 边界拦键集）；路径
        D 与 adapter_id 须为安全标识；state=broadcasted 时 tx_id 为 64 位
        小写 hex，state=failed 时 tx_id 为 null；键集/类型/值错 400；钱包
        /派发未知 404；adapter 与派发不符、或同 dispatch_id 异参重报 409。

        首提 201；同参（adapter_id/state/tx_id 全同）重放 200 返回同一 V
        （优先于一切现状判定）。chain_dispatch_result 是唯一提交点
        （request_id=dispatch_id、actor_id=adapter_id、reason=null、
        details=V）；锁内并发只有一个 201，重放不记事件。恢复检查、校验、
        状态判定与事件追加全部在锁内完成。"""
        try:
            with self._wallet_lock(wallet_id):
                self._heal_wallet(wallet_id)
                # 404 优先于 400：存在性在锁内、heal 之后先判定
                self._get_wallet_or_404(wallet_id)
                self._assert_wallet_active_locked(wallet_id)
                # 持锁访问先重放策略、报告、票、派发请求/结果、操作与相邻
                # 提交事件：矛盾现场 fail-closed，优先于参数 400/404 判定。
                self._reconcile_chain_state_locked(wallet_id)
                # 类型/取值校验（400）
                for name, value in (
                    ("dispatch_id", dispatch_id),
                    ("adapter_id", adapter_id),
                ):
                    if not isinstance(value, str) or not ROTATION_ID_RE.match(
                        value
                    ):
                        raise ServiceError(
                            400,
                            f"{name} must match [A-Za-z0-9_-]{{1,128}}",
                        )
                if state not in DISPATCH_RESULT_STATES:
                    raise ServiceError(
                        400,
                        "state must be broadcasted or failed",
                    )
                if state == "broadcasted":
                    if not _is_lower_hex_32(tx_id):
                        raise ServiceError(
                            400,
                            "tx_id must be 64 lowercase hex characters when "
                            "state is broadcasted",
                        )
                elif tx_id is not None:
                    raise ServiceError(
                        400,
                        "tx_id must be null when state is failed",
                    )

                results = self._audit.chain_dispatch_result_events(wallet_id)
                # 资产粒度冻结闸门先于幂等重放：派发存在但其资产 frozen 时
                # 同参重放也一律 409；派发未知则留给下方既有 404。
                self._assert_dispatch_asset_active_locked(
                    wallet_id, dispatch_id
                )
                # 幂等优先于派发存在性/现状判定：任一已提交结果与全参
                # （adapter_id/state/tx_id）相同即 200 返回同一 V。接管前后
                # 可有两条结果（旧适配器 failed、新适配器一条），两者
                # adapter_id 必不同，同参匹配绝不会有歧义。
                committed = results.get(dispatch_id) or []
                for prior in committed:
                    saved = prior["details"]
                    if (
                        saved["adapter_id"] == adapter_id
                        and saved["state"] == state
                        and saved["tx_id"] == tx_id
                    ):
                        return 200, dict(saved)

                # 404：派发请求未知
                requests = self._dispatch_requests_grouped_locked(
                    wallet_id
                )
                grouped = requests.get(dispatch_id)
                if not grouped:
                    raise ServiceError(
                        404, f"dispatch {dispatch_id!r} not found"
                    )
                if len(grouped) != 1:
                    raise RecoveryError(
                        f"wallet {wallet_id!r} has multiple "
                        f"chain_dispatch_requested events for "
                        f"{dispatch_id!r}"
                    )
                request_details = grouped[0]["details"]

                takeover_event = self._dispatch_takeover_event_locked(
                    wallet_id, dispatch_id
                )
                if takeover_event is None:
                    # 已隔离（尚未接管）：旧适配器的任何结果一律 409——
                    # 隔离即冻结原适配器回执，只允许随后由**新适配器**
                    # takeover 再播链。
                    if (
                        self._dispatch_isolate_event_locked(
                            wallet_id, dispatch_id
                        )
                        is not None
                    ):
                        raise ServiceError(
                            409,
                            f"dispatch {dispatch_id!r} is isolated; its old "
                            "adapter can no longer report results",
                        )
                    # 未接管：上报方适配器须与派发归属一致，且每派发至多
                    # 一条结果（异参重报落入此分支即 409）。
                    if committed:
                        raise ServiceError(
                            409,
                            f"dispatch {dispatch_id!r} already has a result "
                            "with different parameters",
                        )
                    if request_details["adapter_id"] != adapter_id:
                        raise ServiceError(
                            409,
                            f"dispatch {dispatch_id!r} belongs to another "
                            "adapter",
                        )
                else:
                    # 已接管：result 此后只接受新适配器的恰好一条结果。
                    new_adapter = takeover_event["details"]["adapter_id"]
                    if adapter_id != new_adapter:
                        raise ServiceError(
                            409,
                            f"dispatch {dispatch_id!r} was taken over by "
                            "another adapter",
                        )
                    takeover_seq = takeover_event["seq"]
                    post_results = [
                        event
                        for event in committed
                        if event["seq"] > takeover_seq
                    ]
                    if post_results:
                        # 新适配器已有一条结果且非同参（同参已在上方按 200
                        # 回放）：第二次/异参结果一律 409。
                        raise ServiceError(
                            409,
                            f"dispatch {dispatch_id!r} already has a "
                            "post-takeover result with different parameters",
                        )

                view = self._dispatch_result_view(
                    dispatch_id,
                    request_details["operation_id"],
                    adapter_id,
                    request_details["chain_id"],
                    state,
                    tx_id,
                )
                # chain_dispatch_result 是唯一提交点：在跨进程事务锁内追加
                # 事件；事件之外不写任何派发结果状态文件。
                self._emit(
                    wallet_id,
                    self._audit_event(
                        audit.TYPE_CHAIN_DISPATCH_RESULT,
                        request_id=dispatch_id,
                        actor_id=adapter_id,
                        reason=None,
                        details=view,
                    ),
                )
                return 201, view
        except CorruptDataError:
            raise
        except ValueError:
            # wallet_id 含非法字符（构造锁路径时抛出）
            raise ServiceError(400, "invalid wallet_id")

    # ---- 跨链派发确认进展（confirm）----------------------------------------

    #: dispatch 确认进展视图 V / chain_dispatch_confirmation 事件 details
    #: 的固定键序（dispatch_id 后接请求体 B 各键，末键 state）
    _DISPATCH_CONFIRMATION_VIEW_KEY_ORDER = (
        "dispatch_id",
        "adapter_id",
        "tx_id",
        "block_height",
        "block_hash",
        "confirmations",
        "state",
    )

    #: 确认请求体 B 的各键（V 中 dispatch_id 与 state 之外的部分）
    _DISPATCH_CONFIRMATION_BODY_KEYS = (
        "adapter_id",
        "tx_id",
        "block_height",
        "block_hash",
        "confirmations",
    )

    def _dispatch_confirmation_view(
        self,
        dispatch_id: str,
        adapter_id: str,
        tx_id: str,
        block_height: int,
        block_hash: str,
        confirmations: int,
        state: str,
    ) -> dict:
        """dispatch 确认进展成功/重放响应体 V（七键固定序）。"""
        return {
            "dispatch_id": dispatch_id,
            "adapter_id": adapter_id,
            "tx_id": tx_id,
            "block_height": block_height,
            "block_hash": block_hash,
            "confirmations": confirmations,
            "state": state,
        }

    def _dispatch_confirmation_events_strict(
        self, wallet_id: str
    ) -> list[dict]:
        """返回该钱包全部 chain_dispatch_confirmation 事件（按 seq 升序）
        并逐条严格校验**形状**（外层七字段键序、request_id==dispatch_id、
        actor_id 为安全标识且与 details.adapter_id 一致、reason 为 null、
        details 恰为七键 V 且键序固定、各值合法、state 为
        confirming|finalized）。

        这里只做与现场无关的形状校验；与派发请求/结果/策略的先后、归属
        及迁移语义复核在
        :meth:`_reconcile_chain_dispatch_confirmation_events` 按事件 seq
        完成。任何形状畸形都是不可对账现场（RecoveryError）。纯只读，
        不分配 seq。"""
        events = self._audit.events_by_type(
            wallet_id, audit.TYPE_CHAIN_DISPATCH_CONFIRMATION
        )
        for event in events:
            if list(event) != list(_AUDIT_OUTER_KEY_ORDER):
                raise RecoveryError(
                    f"wallet {wallet_id!r} has a chain_dispatch_confirmation "
                    "event whose outer fields are out of the canonical order"
                )
            dispatch_id = event.get("request_id")
            actor_id = event.get("actor_id")
            if (
                not isinstance(dispatch_id, str)
                or not ROTATION_ID_RE.match(dispatch_id)
            ):
                raise RecoveryError(
                    f"wallet {wallet_id!r} has a chain_dispatch_confirmation "
                    "event with a malformed dispatch_id"
                )
            if not (
                isinstance(actor_id, str) and ROTATION_ID_RE.match(actor_id)
            ):
                raise RecoveryError(
                    f"wallet {wallet_id!r} chain_dispatch_confirmation "
                    f"{dispatch_id!r} has a malformed adapter_id"
                )
            if event.get("reason") is not None:
                raise RecoveryError(
                    f"wallet {wallet_id!r} chain_dispatch_confirmation "
                    f"{dispatch_id!r} has a non-null reason"
                )
            details = event.get("details")
            if (
                not isinstance(details, dict)
                or list(details)
                != list(self._DISPATCH_CONFIRMATION_VIEW_KEY_ORDER)
            ):
                raise RecoveryError(
                    f"wallet {wallet_id!r} chain_dispatch_confirmation "
                    f"{dispatch_id!r} has malformed details"
                )
            if details["dispatch_id"] != dispatch_id:
                raise RecoveryError(
                    f"wallet {wallet_id!r} chain_dispatch_confirmation "
                    f"{dispatch_id!r} details dispatch_id disagrees with "
                    "its request_id"
                )
            if details["adapter_id"] != actor_id:
                raise RecoveryError(
                    f"wallet {wallet_id!r} chain_dispatch_confirmation "
                    f"{dispatch_id!r} details adapter_id disagrees with its "
                    "actor_id"
                )
            if (
                not _is_lower_hex_32(details["tx_id"])
                or not _is_lower_hex_32(details["block_hash"])
            ):
                raise RecoveryError(
                    f"wallet {wallet_id!r} chain_dispatch_confirmation "
                    f"{dispatch_id!r} has a malformed tx_id or block_hash"
                )
            for name in ("block_height", "confirmations"):
                value = details[name]
                if (
                    not isinstance(value, int)
                    or isinstance(value, bool)
                    or value < 0
                ):
                    raise RecoveryError(
                        f"wallet {wallet_id!r} chain_dispatch_confirmation "
                        f"{dispatch_id!r} has a malformed {name}"
                    )
            if details["state"] not in DISPATCH_CONFIRMATION_STATES:
                raise RecoveryError(
                    f"wallet {wallet_id!r} chain_dispatch_confirmation "
                    f"{dispatch_id!r} has an invalid state"
                )
        return events

    def _chain_policy_before(
        self, wallet_id: str, asset_id: str, seq: int
    ) -> dict | None:
        """该资产在指定 seq 之前最后一条链确认策略（无则 None）：legacy
        chain_policy 事件与 target=chain-policy 的 policy_change_applied
        合并流按 seq 折叠（派发后的确认/结算/重组据此沿用派发前策略）。

        纯只读；畸形策略事件 fail-closed（RecoveryError），绝不静默按
        缺省处理。"""
        policy = None
        for snap_seq, snap_asset, candidate in (
            self._chain_policy_snapshot_events_locked(wallet_id)
        ):
            if snap_seq >= seq:
                continue
            if snap_asset == asset_id:
                policy = candidate
        return policy

    @staticmethod
    def _confirmation_transition_error(
        policy: dict, last: dict | None, report: dict
    ) -> str | None:
        """新确认进展相对上一条进展的状态机校验；合法返回 None，否则返回
        错误信息。

        同块（高度与哈希均同）确认数只增不减；换块（迁移）仅限确认中
        （终态在调用方先行拦截）且高度回退须满足
        0 <= 旧高度 - 新高度 <= reorg_window。"""
        if last is None:
            return None
        same_block = (
            report["block_height"] == last["block_height"]
            and report["block_hash"] == last["block_hash"]
        )
        if same_block:
            if report["confirmations"] < last["confirmations"]:
                return "confirmations must not decrease on the same block"
            return None
        regression = last["block_height"] - report["block_height"]
        if not 0 <= regression <= policy["reorg_window"]:
            return "block migration outside the reorg window"
        return None

    def _reconcile_chain_dispatch_confirmation_events(
        self, wallet_id: str
    ) -> None:
        """按 seq 严格复核全部 chain_dispatch_confirmation 事件（调用方须
        持钱包事务锁）。

        每条确认进展都以其**提交之前**的现场复核：

        - 同一 dispatch_id 的 chain_dispatch_requested 与
          chain_dispatch_result 都必须**先于**本事件提交，且结果为
          broadcasted（无 broadcasted 结果的确认即矛盾）；
        - 归属一致：actor_id/adapter_id 与派发请求相同，tx_id 与
          broadcasted 结果相同；
        - 迁移：按派发请求提交之前该资产的策略（阈值/窗口）逐条重放确认
          链——同块确认数不降、换块仅确认中且高度回退在 reorg_window 内、
          达 required_confirmations 的进展 state 恰为 finalized、否则
          恰为 confirming；终态（finalized）之后不得再有新进展事件，
          唯一的例外是已结算派发的重组进展（state=reorged）：派发须在
          本事件之前已结算，相对上一条（finalized）进展 tx 或区块改变、
          确认数低于阈值、高度回退 <= reorg_window，且与紧邻的
          chain_dispatch_reorged、asset_operation_committed 构成三事件
          同批提交点；reorged 同为终态，其后不得再有新进展；
        - 同体进展在线只幂等重放不记事件：日志中出现同 B 重复事件即
          矛盾现场。

        任一不满足都是不可对账现场（RecoveryError，fail-closed，保留
        现场、不改账本、不写旁路文件、不重记）。纯只读，不记事件、不改
        seq、不写状态。"""
        events = self._dispatch_confirmation_events_strict(wallet_id)
        if not events:
            return
        requests = self._dispatch_all_request_events_strict(wallet_id)
        results = self._dispatch_result_events_strict(wallet_id)
        request_by_dispatch = {
            event["request_id"]: event for event in requests
        }
        results_by_dispatch: dict[str, list[dict]] = {}
        for event in results:
            results_by_dispatch.setdefault(
                event["request_id"], []
            ).append(event)
        takeover_by_dispatch = {
            event["request_id"]: event
            for event in self._dispatch_taken_over_events_strict(wallet_id)
        }
        settled_by_dispatch = {
            event["request_id"]: event
            for event in self._dispatch_settled_events_strict(wallet_id)
        }
        by_seq = {
            event["seq"]: event
            for event in self._audit.all_events(wallet_id)
        }
        ledger = self._store.check_asset_ledger_semantics(wallet_id)
        operations = ledger["operations"]
        last_by_dispatch: dict[str, dict] = {}
        seen_bodies: dict[str, list[dict]] = {}
        for event in events:
            details = event["details"]
            dispatch_id = details["dispatch_id"]
            request = request_by_dispatch.get(dispatch_id)
            if request is None or request["seq"] >= event["seq"]:
                raise RecoveryError(
                    f"wallet {wallet_id!r} has a chain_dispatch_confirmation "
                    f"event for {dispatch_id!r} without a preceding dispatch "
                    "request"
                )
            takeover = takeover_by_dispatch.get(dispatch_id)
            after_takeover = (
                takeover is not None and event["seq"] > takeover["seq"]
            )
            # 确认进展只能对应先于本事件的 broadcasted 结果。接管后取新
            # 适配器在接管之后的 broadcasted 结果；无接管取原适配器唯一的
            # broadcasted 结果。
            prior_results = [
                result
                for result in results_by_dispatch.get(dispatch_id, [])
                if result["seq"] < event["seq"]
                and (
                    takeover is None
                    or (
                        result["seq"] > takeover["seq"]
                        if after_takeover
                        else result["seq"] < takeover["seq"]
                    )
                )
            ]
            result = (
                prior_results[-1] if prior_results else None
            )
            if result is None or result["details"]["state"] != "broadcasted":
                raise RecoveryError(
                    f"wallet {wallet_id!r} has a chain_dispatch_confirmation "
                    f"event for {dispatch_id!r} without a preceding "
                    "broadcasted result"
                )
            saved_request = request["details"]
            effective_adapter = (
                takeover["details"]["adapter_id"]
                if after_takeover
                else saved_request["adapter_id"]
            )
            if details["adapter_id"] != effective_adapter:
                raise RecoveryError(
                    f"wallet {wallet_id!r} chain_dispatch_confirmation "
                    f"{dispatch_id!r} adapter_id disagrees with the effective "
                    "dispatch adapter"
                )
            if (
                details["state"] != "reorged"
                and details["tx_id"] != result["details"]["tx_id"]
            ):
                raise RecoveryError(
                    f"wallet {wallet_id!r} chain_dispatch_confirmation "
                    f"{dispatch_id!r} tx_id disagrees with its broadcasted "
                    "result"
                )
            # 阈值/窗口取派发请求提交之前该资产的策略快照。
            operation_id = saved_request["operation_id"]
            record = operations.get(operation_id)
            if record is None:
                raise RecoveryError(
                    f"wallet {wallet_id!r} has a chain_dispatch_confirmation "
                    f"event for {dispatch_id!r} whose asset operation "
                    f"{operation_id!r} is unknown"
                )
            policy = self._chain_policy_before(
                wallet_id, record["asset_id"], request["seq"]
            )
            if policy is None:
                raise RecoveryError(
                    f"wallet {wallet_id!r} has a chain_dispatch_confirmation "
                    f"event for {dispatch_id!r} without a preceding chain "
                    "policy"
                )
            body = {
                key: details[key]
                for key in self._DISPATCH_CONFIRMATION_BODY_KEYS
            }
            bodies = seen_bodies.setdefault(dispatch_id, [])
            if any(prior == body for prior in bodies):
                raise RecoveryError(
                    f"wallet {wallet_id!r} has duplicate "
                    f"chain_dispatch_confirmation events for {dispatch_id!r} "
                    "with an identical report"
                )
            bodies.append(body)
            last = last_by_dispatch.get(dispatch_id)
            if details["state"] == "reorged":
                # 重组进展：仅当派发在本事件之前已结算、上一条进展为
                # finalized，且相对上一条 tx 或区块改变、确认数低于
                # 阈值、高度回退 <= reorg_window；并须与紧邻的
                # chain_dispatch_reorged、asset_operation_committed
                # 构成三事件同批提交点（残缺即矛盾现场）。
                if last is None or last["state"] != "finalized":
                    raise RecoveryError(
                        f"wallet {wallet_id!r} has a reorged "
                        f"chain_dispatch_confirmation event for "
                        f"{dispatch_id!r} whose previous progress is not "
                        "finalized"
                    )
                settled = settled_by_dispatch.get(dispatch_id)
                if settled is None or settled["seq"] >= event["seq"]:
                    raise RecoveryError(
                        f"wallet {wallet_id!r} has a reorged "
                        f"chain_dispatch_confirmation event for "
                        f"{dispatch_id!r} without a preceding "
                        "chain_dispatch_settled event"
                    )
                moved = (
                    details["tx_id"] != last["tx_id"]
                    or details["block_height"] != last["block_height"]
                    or details["block_hash"] != last["block_hash"]
                )
                regression = last["block_height"] - details["block_height"]
                if (
                    not moved
                    or details["confirmations"]
                    >= policy["required_confirmations"]
                    or not 0 <= regression <= policy["reorg_window"]
                ):
                    raise RecoveryError(
                        f"wallet {wallet_id!r} has an inconsistent reorged "
                        f"chain_dispatch_confirmation event for "
                        f"{dispatch_id!r}"
                    )
                follower1 = by_seq.get(event["seq"] + 1)
                follower2 = by_seq.get(event["seq"] + 2)
                if (
                    follower1 is None
                    or follower1.get("type")
                    != audit.TYPE_CHAIN_DISPATCH_REORGED
                    or follower1.get("request_id") != dispatch_id
                    or follower2 is None
                    or follower2.get("type")
                    != audit.TYPE_ASSET_OPERATION_COMMITTED
                    or follower2.get("request_id") != dispatch_id
                ):
                    raise RecoveryError(
                        f"wallet {wallet_id!r} has a reorged "
                        f"chain_dispatch_confirmation event for "
                        f"{dispatch_id!r} without adjacent reorged and "
                        "committed events"
                    )
                last_by_dispatch[dispatch_id] = details
                continue
            if last is not None and last["state"] in (
                "finalized",
                "reorged",
            ):
                raise RecoveryError(
                    f"wallet {wallet_id!r} has a chain_dispatch_confirmation "
                    f"event for {dispatch_id!r} after it finalized"
                )
            error = self._confirmation_transition_error(
                policy, last, details
            )
            if error is not None:
                raise RecoveryError(
                    f"wallet {wallet_id!r} has an inconsistent "
                    f"chain_dispatch_confirmation event for {dispatch_id!r}: "
                    f"{error}"
                )
            expected_state = (
                "finalized"
                if details["confirmations"] >= policy["required_confirmations"]
                else "confirming"
            )
            if details["state"] != expected_state:
                raise RecoveryError(
                    f"wallet {wallet_id!r} chain_dispatch_confirmation "
                    f"{dispatch_id!r} has state {details['state']!r}, "
                    f"expected {expected_state!r}"
                )
            last_by_dispatch[dispatch_id] = details

    def post_chain_dispatch_confirmation(
        self,
        wallet_id: str,
        dispatch_id: object,
        adapter_id: object,
        tx_id: object,
        block_height: object,
        block_hash: object,
        confirmations: object,
    ) -> tuple[int, dict]:
        """上报跨链派发的链上确认进展，返回 (HTTP 状态码, 视图
        V={dispatch_id,adapter_id,tx_id,block_height,block_hash,
        confirmations,state})。

        请求体恰含 adapter_id,tx_id,block_height,block_hash,confirmations
        五键（HTTP 边界拦键集）；路径 D 与 adapter_id 须为安全标识，
        tx_id/block_hash 为 64 位小写 hex，block_height/confirmations 为
        非布尔非负整数；键集/类型/值错 400；钱包/派发未知 404；无
        broadcasted 结果、归属（adapter/tx）或迁移冲突一律 409。

        阈值/窗口取派发请求提交之前该资产的策略：同块确认数不降；换块
        仅限确认中且 0 <= 旧高度 - 新高度 <= reorg_window；达
        required_confirmations 转 finalized（终态），终态仅许历史同体
        重放。已结算（settled）派发例外：仅接受重组形态的新 B（adapter
        匹配、tx 或区块改变、confirmations 低于阈值且高度回退
        <= reorg_window），接受时以 D 为 operation_id 创建同资产、反向
        delta 的补偿操作并原子提交（chain_dispatch_confirmation
        [state=reorged] + chain_dispatch_reorged +
        asset_operation_committed 三事件同批连续落盘），成功 201 返回
        state=reorged 的 V；补偿 id 占用或余额将负 409 且零副作用。
        新进展 201；历史同体（B 全同）重放优先返回 200 与原 V，
        不复查现状。chain_dispatch_confirmation 是唯一提交点
        （request_id=dispatch_id、actor_id=adapter_id、reason=null、
        details=V）；锁内并发只有一个 201，重放不记事件。恢复检查、
        校验、状态判定与事件追加全部在锁内完成。"""
        try:
            with self._wallet_lock(wallet_id):
                self._heal_wallet(wallet_id)
                # 404 优先于 400：存在性在锁内、heal 之后先判定
                self._get_wallet_or_404(wallet_id)
                self._assert_wallet_active_locked(wallet_id)
                # 持锁访问先重放策略、报告、票、派发请求/结果/确认、操作
                # 与相邻提交事件：矛盾现场 fail-closed，优先于参数
                # 400/404 判定。
                self._reconcile_chain_state_locked(wallet_id)
                # 类型/取值校验（400）
                for name, value in (
                    ("dispatch_id", dispatch_id),
                    ("adapter_id", adapter_id),
                ):
                    if not isinstance(value, str) or not ROTATION_ID_RE.match(
                        value
                    ):
                        raise ServiceError(
                            400,
                            f"{name} must match [A-Za-z0-9_-]{{1,128}}",
                        )
                self._validate_hex_32(tx_id, "tx_id")
                self._validate_hex_32(block_hash, "block_hash")
                self._validate_non_negative_int(block_height, "block_height")
                self._validate_non_negative_int(confirmations, "confirmations")

                body = {
                    "adapter_id": adapter_id,
                    "tx_id": tx_id,
                    "block_height": block_height,
                    "block_hash": block_hash,
                    "confirmations": confirmations,
                }
                groups = self._audit.chain_dispatch_confirmation_events(
                    wallet_id
                ).get(dispatch_id) or []
                # 资产粒度冻结闸门先于历史同体重放（含已结算派发的重组
                # 补偿写账）：派发存在但资产 frozen 时一律 409；派发未知
                # 留给下方既有 404。
                self._assert_dispatch_asset_active_locked(
                    wallet_id, dispatch_id
                )
                # 历史同体重放优先于一切现状判定：200 返回原 V，不记事件。
                for prior in groups:
                    saved = prior["details"]
                    if all(
                        saved[key] == body[key]
                        for key in self._DISPATCH_CONFIRMATION_BODY_KEYS
                    ):
                        return 200, dict(saved)

                # 404：派发请求未知
                requests = self._dispatch_requests_grouped_locked(
                    wallet_id
                )
                grouped = requests.get(dispatch_id)
                if not grouped:
                    raise ServiceError(
                        404, f"dispatch {dispatch_id!r} not found"
                    )
                if len(grouped) != 1:
                    raise RecoveryError(
                        f"wallet {wallet_id!r} has multiple "
                        f"chain_dispatch_requested events for {dispatch_id!r}"
                    )
                request_event = grouped[0]
                request_details = request_event["details"]

                # 409：无当前生效适配器的 broadcasted 结果。未接管时结果须
                # 为原适配器唯一一条 broadcasted；接管后须存在接管之后新
                # 适配器的 broadcasted 结果（原适配器结果为 failed）。
                broadcasted_result, takeover_event = (
                    self._effective_broadcasted_result_locked(
                        wallet_id, dispatch_id
                    )
                )
                if broadcasted_result is None:
                    raise ServiceError(
                        409,
                        f"dispatch {dispatch_id!r} has no broadcasted result",
                    )
                result_details = broadcasted_result["details"]
                effective_adapter_id = (
                    takeover_event["details"]["adapter_id"]
                    if takeover_event is not None
                    else request_details["adapter_id"]
                )

                # 409：归属冲突（上报方适配器与当前生效适配器不符）
                if effective_adapter_id != adapter_id:
                    raise ServiceError(
                        409,
                        f"dispatch {dispatch_id!r} belongs to another adapter",
                    )

                # 已结算派发的重组补偿：仅接受 adapter 匹配（已判定）、
                # tx 或区块改变、confirmations 低于阈值且高度回退
                # <= reorg_window 的新 B，其余一律 409；历史同体重放已在
                # 上方拦截（200 同 V，不记事件）。
                settled_groups = self._audit.chain_dispatch_settled_events(
                    wallet_id
                ).get(dispatch_id)
                if settled_groups:
                    if len(settled_groups) != 1:
                        raise RecoveryError(
                            f"wallet {wallet_id!r} has multiple "
                            f"chain_dispatch_settled events for "
                            f"{dispatch_id!r}"
                        )
                    return self._confirm_settled_reorg(
                        wallet_id,
                        dispatch_id,
                        adapter_id,
                        tx_id,
                        block_height,
                        block_hash,
                        confirmations,
                        request_event,
                        groups,
                    )

                if result_details["tx_id"] != tx_id:
                    raise ServiceError(
                        409,
                        f"dispatch {dispatch_id!r} was broadcasted as another "
                        "transaction",
                    )

                # 阈值/窗口取派发请求提交之前该资产的策略快照。
                record = self._store.get_asset_operation(
                    wallet_id, request_details["operation_id"]
                )
                if record is None:
                    raise RecoveryError(
                        f"wallet {wallet_id!r} dispatch {dispatch_id!r} "
                        "refers to an unknown asset operation"
                    )
                policy = self._chain_policy_before(
                    wallet_id, record["asset_id"], request_event["seq"]
                )
                if policy is None:
                    raise RecoveryError(
                        f"wallet {wallet_id!r} dispatch {dispatch_id!r} has "
                        "no preceding chain policy"
                    )

                # 409：终态后只许历史同体重放（已在上方拦截），新进展一律
                # 冲突；迁移校验（同块不降/换块窗口）相对最后一条进展。
                last = groups[-1]["details"] if groups else None
                if last is not None and last["state"] in (
                    "finalized",
                    "reorged",
                ):
                    raise ServiceError(
                        409,
                        f"dispatch {dispatch_id!r} is already finalized",
                    )
                error = self._confirmation_transition_error(
                    policy, last, body
                )
                if error is not None:
                    raise ServiceError(409, error)

                state = (
                    "finalized"
                    if confirmations >= policy["required_confirmations"]
                    else "confirming"
                )
                view = self._dispatch_confirmation_view(
                    dispatch_id,
                    adapter_id,
                    tx_id,
                    block_height,
                    block_hash,
                    confirmations,
                    state,
                )
                # chain_dispatch_confirmation 是唯一提交点：在跨进程事务锁
                # 内追加事件；事件之外不写任何确认状态文件。
                self._emit(
                    wallet_id,
                    self._audit_event(
                        audit.TYPE_CHAIN_DISPATCH_CONFIRMATION,
                        request_id=dispatch_id,
                        actor_id=adapter_id,
                        reason=None,
                        details=view,
                    ),
                )
                return 201, view
        except CorruptDataError:
            raise
        except ValueError:
            # wallet_id 含非法字符（构造锁路径时抛出）
            raise ServiceError(400, "invalid wallet_id")

    def _confirm_settled_reorg(
        self,
        wallet_id: str,
        dispatch_id: str,
        adapter_id: str,
        tx_id: str,
        block_height: int,
        block_hash: str,
        confirmations: int,
        request_event: dict,
        groups: list[dict],
    ) -> tuple[int, dict]:
        """已结算派发的重组补偿（调用方须持锁、已对账、已判定钱包/派发
        存在、结果为 broadcasted 且 adapter 归属一致）。

        仅接受重组形态的新 B：相对最后一条（finalized）进展 tx 或区块
        改变、confirmations 低于阈值、高度回退 <= reorg_window；其余
        一律 409。接受时以 D 为 operation_id 创建同资产、反向 delta 的
        补偿操作并在锁内原子提交：连续追加
        chain_dispatch_confirmation（details=V，state=reorged）、
        chain_dispatch_reorged（details={dispatch_id: D,
        operation_id: D}）、asset_operation_committed（details=R）
        三事件（request_id=D、actor_id=adapter_id、reason=null），
        三事件俱在前滚、俱无回滚。补偿操作 id 被占用或补偿后余额将负
        一律 409 且零副作用（意图/账本/事件均未写）。成功 201 返回 V。"""
        request_details = request_event["details"]
        record = self._store.get_asset_operation(
            wallet_id, request_details["operation_id"]
        )
        if record is None:
            raise RecoveryError(
                f"wallet {wallet_id!r} dispatch {dispatch_id!r} "
                "refers to an unknown asset operation"
            )
        # 阈值/窗口取派发请求提交之前该资产的策略快照（与在线确认一致）。
        policy = self._chain_policy_before(
            wallet_id, record["asset_id"], request_event["seq"]
        )
        if policy is None:
            raise RecoveryError(
                f"wallet {wallet_id!r} dispatch {dispatch_id!r} has "
                "no preceding chain policy"
            )
        last = groups[-1]["details"] if groups else None
        if not (
            last is not None
            and last["state"] == "finalized"
            and (
                tx_id != last["tx_id"]
                or block_height != last["block_height"]
                or block_hash != last["block_hash"]
            )
            and confirmations < policy["required_confirmations"]
            and 0
            <= last["block_height"] - block_height
            <= policy["reorg_window"]
        ):
            raise ServiceError(
                409,
                f"dispatch {dispatch_id!r} is settled and the report is "
                "not a valid reorg",
            )
        # 409：补偿操作 id（即 D）已被占用——零副作用（意图/账本/事件
        # 均未写）。
        if (
            self._store.get_asset_operation(wallet_id, dispatch_id)
            is not None
        ):
            raise ServiceError(
                409,
                f"asset operation {dispatch_id!r} already exists",
            )
        view = self._dispatch_confirmation_view(
            dispatch_id,
            adapter_id,
            tx_id,
            block_height,
            block_hash,
            confirmations,
            "reorged",
        )
        # 锁内原子补偿提交：余额将负在此抛 409 且无任何副作用。成功时
        # 三事件同批原子落盘，崩溃按事件俱在/俱无前滚或回滚。
        self._commit_reorg_compensation_locked(
            wallet_id,
            dispatch_id,
            adapter_id,
            record["asset_id"],
            -record["delta"],
            view,
        )
        return 201, view

    # ---- 跨链派发最终性查询与资产结算（finality / settle）------------------

    #: finality 成功响应 F 的固定键序
    #: operation_id,chain_id,confirmation（末值为 confirm 既有七键 V）
    _DISPATCH_FINALITY_VIEW_KEY_ORDER = (
        "operation_id",
        "chain_id",
        "confirmation",
    )

    #: chain_dispatch_settled 事件 details 的固定键序
    _DISPATCH_SETTLED_DETAILS_KEY_ORDER = (
        "dispatch_id",
        "operation_id",
    )

    #: 资产操作视图 R 的固定键序（settle 的 201/200 统一按此序返回；
    #: 与 README 既定 R={operation_id,asset_id,delta,state,balance,
    #: version} 一致）
    _ASSET_OPERATION_VIEW_KEY_ORDER = (
        "operation_id",
        "asset_id",
        "delta",
        "state",
        "balance",
        "version",
    )

    @classmethod
    def _asset_operation_view(cls, record: dict) -> dict:
        """把账本/提交记录归一为固定键序的 R 视图（纯重排，不改值）。"""
        return {
            key: record[key] for key in cls._ASSET_OPERATION_VIEW_KEY_ORDER
        }

    def _dispatch_finality_view(
        self, request_details: dict, confirmation: dict
    ) -> dict:
        """finality 成功响应体 F（三键固定序 operation_id,chain_id,
        confirmation，末值为 confirm 既有七键 V；键序见
        _DISPATCH_FINALITY_VIEW_KEY_ORDER）。"""
        return {
            "operation_id": request_details["operation_id"],
            "chain_id": request_details["chain_id"],
            "confirmation": dict(confirmation),
        }

    def get_chain_dispatch_finality(
        self, wallet_id: str, dispatch_id: object
    ) -> dict:
        """查询跨链派发最终性，返回
        F={operation_id,chain_id,confirmation}，末值为 confirm 既有七键 V。

        纯只读：不写文件、不记事件、不分配 seq。路径 D 非法 400；钱包或
        派发未知 404；无 broadcasted 结果（无结果或 failed）或尚无任何
        确认进展一律 409。存在确认进展即返回最后一条进展 V（含其
        confirming|finalized 状态）；是否达 finalized 由结算（settle）
        另行门控。恢复检查、存在性与状态判定全部在锁内完成。"""
        try:
            with self._wallet_lock(wallet_id):
                self._heal_wallet(wallet_id)
                # 404 优先于 400：存在性在锁内、heal 之后先判定
                self._get_wallet_or_404(wallet_id)
                # 持锁访问先重放策略、报告、票、派发请求/结果/确认/结算、
                # 操作与相邻提交事件：矛盾现场 fail-closed。
                self._reconcile_chain_state_locked(wallet_id)
                if (
                    not isinstance(dispatch_id, str)
                    or not ROTATION_ID_RE.match(dispatch_id)
                ):
                    raise ServiceError(
                        400,
                        "dispatch_id must match [A-Za-z0-9_-]{1,128}",
                    )

                requests = self._dispatch_requests_grouped_locked(
                    wallet_id
                )
                grouped = requests.get(dispatch_id)
                if not grouped:
                    raise ServiceError(
                        404, f"dispatch {dispatch_id!r} not found"
                    )
                if len(grouped) != 1:
                    raise RecoveryError(
                        f"wallet {wallet_id!r} has multiple "
                        f"chain_dispatch_requested events for {dispatch_id!r}"
                    )
                request_details = grouped[0]["details"]

                broadcasted_result, _ = (
                    self._effective_broadcasted_result_locked(
                        wallet_id, dispatch_id
                    )
                )
                if broadcasted_result is None:
                    raise ServiceError(
                        409,
                        f"dispatch {dispatch_id!r} has no broadcasted result",
                    )

                groups = self._audit.chain_dispatch_confirmation_events(
                    wallet_id
                ).get(dispatch_id) or []
                # 接管前结果为 failed，不可能有确认进展；接管后的进展归属
                # 新适配器，确认链整体属于当前生效适配器。
                if not groups:
                    raise ServiceError(
                        409,
                        f"dispatch {dispatch_id!r} has no confirmation yet",
                    )
                return self._dispatch_finality_view(
                    request_details, groups[-1]["details"]
                )
        except CorruptDataError:
            raise
        except ValueError:
            # wallet_id 含非法字符（构造锁路径时抛出）
            raise ServiceError(400, "invalid wallet_id")

    def _dispatch_settled_events_strict(
        self, wallet_id: str
    ) -> list[dict]:
        """返回该钱包全部 chain_dispatch_settled 事件（按 seq 升序）并逐条
        严格校验**形状**（外层七字段键序、request_id==dispatch_id、
        actor_id 为安全标识、reason 为 null、details 恰为
        dispatch_id,operation_id 两键且键序固定、各值合法）。

        与派发请求/结果/确认/账本的先后、归属及紧邻提交语义复核在
        :meth:`_reconcile_chain_dispatch_settled_events` 按事件 seq 完成。
        任何形状畸形都是不可对账现场（RecoveryError）。纯只读，不分配
        seq。"""
        events = self._audit.events_by_type(
            wallet_id, audit.TYPE_CHAIN_DISPATCH_SETTLED
        )
        seen: set[str] = set()
        for event in events:
            if list(event) != list(_AUDIT_OUTER_KEY_ORDER):
                raise RecoveryError(
                    f"wallet {wallet_id!r} has a chain_dispatch_settled "
                    "event whose outer fields are out of the canonical order"
                )
            dispatch_id = event.get("request_id")
            actor_id = event.get("actor_id")
            if (
                not isinstance(dispatch_id, str)
                or not ROTATION_ID_RE.match(dispatch_id)
            ):
                raise RecoveryError(
                    f"wallet {wallet_id!r} has a chain_dispatch_settled "
                    "event with a malformed dispatch_id"
                )
            if dispatch_id in seen:
                raise RecoveryError(
                    f"wallet {wallet_id!r} has multiple "
                    f"chain_dispatch_settled events for {dispatch_id!r}"
                )
            seen.add(dispatch_id)
            if not (
                isinstance(actor_id, str) and ROTATION_ID_RE.match(actor_id)
            ):
                raise RecoveryError(
                    f"wallet {wallet_id!r} chain_dispatch_settled "
                    f"{dispatch_id!r} has a malformed adapter_id"
                )
            if event.get("reason") is not None:
                raise RecoveryError(
                    f"wallet {wallet_id!r} chain_dispatch_settled "
                    f"{dispatch_id!r} has a non-null reason"
                )
            details = event.get("details")
            if (
                not isinstance(details, dict)
                or list(details)
                != list(self._DISPATCH_SETTLED_DETAILS_KEY_ORDER)
            ):
                raise RecoveryError(
                    f"wallet {wallet_id!r} chain_dispatch_settled "
                    f"{dispatch_id!r} has malformed details"
                )
            if details["dispatch_id"] != dispatch_id:
                raise RecoveryError(
                    f"wallet {wallet_id!r} chain_dispatch_settled "
                    f"{dispatch_id!r} details dispatch_id disagrees with its "
                    "request_id"
                )
            if not (
                isinstance(details["operation_id"], str)
                and ROTATION_ID_RE.match(details["operation_id"])
            ):
                raise RecoveryError(
                    f"wallet {wallet_id!r} chain_dispatch_settled "
                    f"{dispatch_id!r} has a malformed operation_id"
                )
        return events

    def _reconcile_chain_dispatch_settled_events(
        self, wallet_id: str
    ) -> None:
        """按 seq 严格复核全部 chain_dispatch_settled 事件（调用方须持钱包
        事务锁）。

        每条结算都以其**提交之前**的现场复核在线首提的全部前置：

        - 同一 dispatch_id 的 chain_dispatch_requested、broadcasted 的
          chain_dispatch_result 必须先于结算事件提交，且存在一条先于结算
          的 finalized 确认进展（归属、tx 一致性已由请求/结果/确认各自的
          对账保证，这里复核 actor_id 即请求适配器、operation_id 与请求
          相同）；
        - 结算时操作尚为 pending（该操作的 asset_operation_committed 不
          得早于结算事件）；
        - 结算事件必须紧邻一条同操作的 asset_operation_committed
          （两事件同批原子落盘，孤立结算事件即矛盾现场）；该提交事件与
          账本的逐字段一致由 _reconcile_asset_committed_events 全局对账。

        任一矛盾都 fail-closed（RecoveryError，保留现场）。纯只读，不记
        事件、不改 seq、不写状态。"""
        events = self._dispatch_settled_events_strict(wallet_id)
        if not events:
            return
        requests = self._dispatch_all_request_events_strict(wallet_id)
        results = self._dispatch_result_events_strict(wallet_id)
        confirmations = self._dispatch_confirmation_events_strict(wallet_id)
        takeovers = self._dispatch_taken_over_events_strict(wallet_id)
        request_by_dispatch = {
            event["request_id"]: event for event in requests
        }
        results_by_dispatch: dict[str, list[dict]] = {}
        for event in results:
            results_by_dispatch.setdefault(
                event["request_id"], []
            ).append(event)
        takeover_by_dispatch = {
            event["request_id"]: event for event in takeovers
        }
        ledger = self._store.check_asset_ledger_semantics(wallet_id)
        operations = ledger["operations"]
        all_events = self._audit.all_events(wallet_id)
        committed_seq: dict[str, int] = {}
        for event in all_events:
            if event.get("type") == audit.TYPE_ASSET_OPERATION_COMMITTED:
                request_id = event.get("request_id")
                if isinstance(request_id, str):
                    committed_seq[request_id] = event["seq"]
        for index, event in enumerate(all_events):
            if event.get("type") != audit.TYPE_CHAIN_DISPATCH_SETTLED:
                continue
            details = event["details"]
            dispatch_id = details["dispatch_id"]
            operation_id = details["operation_id"]
            seq = event["seq"]
            request = request_by_dispatch.get(dispatch_id)
            if request is None or request["seq"] >= seq:
                raise RecoveryError(
                    f"wallet {wallet_id!r} has a chain_dispatch_settled "
                    f"event for {dispatch_id!r} without a preceding dispatch "
                    "request"
                )
            saved_request = request["details"]
            if operation_id != saved_request["operation_id"]:
                raise RecoveryError(
                    f"wallet {wallet_id!r} chain_dispatch_settled "
                    f"{dispatch_id!r} operation_id disagrees with its "
                    "dispatch request"
                )
            takeover = takeover_by_dispatch.get(dispatch_id)
            if takeover is not None and takeover["seq"] < seq:
                effective_adapter = takeover["details"]["adapter_id"]
            else:
                effective_adapter = saved_request["adapter_id"]
            if event["actor_id"] != effective_adapter:
                raise RecoveryError(
                    f"wallet {wallet_id!r} chain_dispatch_settled "
                    f"{dispatch_id!r} adapter_id disagrees with the effective "
                    "dispatch adapter"
                )
            # 结算前必须存在当前生效适配器的 broadcasted 结果：未接管时即
            # 原适配器唯一结果；接管后须为接管之后新适配器的结果。
            prior_broadcasted = [
                result
                for result in results_by_dispatch.get(dispatch_id, [])
                if result["seq"] < seq
                and result["details"]["state"] == "broadcasted"
                and (
                    takeover is None
                    or takeover["seq"] >= seq
                    or result["seq"] > takeover["seq"]
                )
            ]
            if not prior_broadcasted:
                raise RecoveryError(
                    f"wallet {wallet_id!r} has a chain_dispatch_settled "
                    f"event for {dispatch_id!r} without a preceding "
                    "broadcasted result"
                )
            finalized_prior = any(
                confirmation["seq"] < seq
                and confirmation["request_id"] == dispatch_id
                and confirmation["details"]["state"] == "finalized"
                for confirmation in confirmations
            )
            if not finalized_prior:
                raise RecoveryError(
                    f"wallet {wallet_id!r} has a chain_dispatch_settled "
                    f"event for {dispatch_id!r} without a preceding "
                    "finalized confirmation"
                )
            record = operations.get(operation_id)
            if record is None:
                raise RecoveryError(
                    f"wallet {wallet_id!r} has a chain_dispatch_settled "
                    f"event for {dispatch_id!r} whose asset operation "
                    f"{operation_id!r} is unknown"
                )
            prior_commit = committed_seq.get(operation_id)
            if prior_commit is not None and prior_commit < seq:
                raise RecoveryError(
                    f"wallet {wallet_id!r} has a chain_dispatch_settled "
                    f"event for already committed asset operation "
                    f"{operation_id!r}"
                )
            follower = (
                all_events[index + 1] if index + 1 < len(all_events) else None
            )
            if (
                follower is None
                or follower.get("type")
                != audit.TYPE_ASSET_OPERATION_COMMITTED
                or follower.get("request_id") != operation_id
            ):
                raise RecoveryError(
                    f"wallet {wallet_id!r} has a chain_dispatch_settled "
                    f"event for {dispatch_id!r} without an adjacent "
                    "committed event"
                )

    def _dispatch_reorged_events_strict(
        self, wallet_id: str
    ) -> list[dict]:
        """返回该钱包全部 chain_dispatch_reorged 事件（按 seq 升序）并逐条
        严格校验**形状**（外层七字段键序、request_id==dispatch_id、
        actor_id 为安全标识、reason 为 null、details 恰为
        dispatch_id,operation_id 两键且键序固定、两值相等且恰为
        request_id——补偿操作以 D 为 operation_id）。

        与派发请求/结算/确认/账本的先后、归属及三事件紧邻语义复核在
        :meth:`_reconcile_chain_dispatch_reorged_events` 按事件 seq 完成。
        任何形状畸形都是不可对账现场（RecoveryError）。纯只读，不分配
        seq。"""
        events = self._audit.events_by_type(
            wallet_id, audit.TYPE_CHAIN_DISPATCH_REORGED
        )
        seen: set[str] = set()
        for event in events:
            if list(event) != list(_AUDIT_OUTER_KEY_ORDER):
                raise RecoveryError(
                    f"wallet {wallet_id!r} has a chain_dispatch_reorged "
                    "event whose outer fields are out of the canonical order"
                )
            dispatch_id = event.get("request_id")
            actor_id = event.get("actor_id")
            if (
                not isinstance(dispatch_id, str)
                or not ROTATION_ID_RE.match(dispatch_id)
            ):
                raise RecoveryError(
                    f"wallet {wallet_id!r} has a chain_dispatch_reorged "
                    "event with a malformed dispatch_id"
                )
            if dispatch_id in seen:
                raise RecoveryError(
                    f"wallet {wallet_id!r} has multiple "
                    f"chain_dispatch_reorged events for {dispatch_id!r}"
                )
            seen.add(dispatch_id)
            if not (
                isinstance(actor_id, str) and ROTATION_ID_RE.match(actor_id)
            ):
                raise RecoveryError(
                    f"wallet {wallet_id!r} chain_dispatch_reorged "
                    f"{dispatch_id!r} has a malformed adapter_id"
                )
            if event.get("reason") is not None:
                raise RecoveryError(
                    f"wallet {wallet_id!r} chain_dispatch_reorged "
                    f"{dispatch_id!r} has a non-null reason"
                )
            details = event.get("details")
            if (
                not isinstance(details, dict)
                or list(details)
                != list(self._DISPATCH_SETTLED_DETAILS_KEY_ORDER)
            ):
                raise RecoveryError(
                    f"wallet {wallet_id!r} chain_dispatch_reorged "
                    f"{dispatch_id!r} has malformed details"
                )
            if (
                details["dispatch_id"] != dispatch_id
                or details["operation_id"] != dispatch_id
            ):
                raise RecoveryError(
                    f"wallet {wallet_id!r} chain_dispatch_reorged "
                    f"{dispatch_id!r} details disagree with its request_id"
                )
        return events

    def _reconcile_chain_dispatch_reorged_events(
        self, wallet_id: str
    ) -> None:
        """按 seq 严格复核全部 chain_dispatch_reorged 事件（调用方须持钱包
        事务锁）。

        每条重组都以其**提交之前**的现场复核在线首提的全部前置：

        - 同一 dispatch_id 的 chain_dispatch_requested 必须先于重组事件
          提交，且 actor_id 即请求适配器；
        - 派发须在重组事件之前已结算（chain_dispatch_settled 在先）；
        - 重组事件必须紧邻一条同派发、state=reorged 的
          chain_dispatch_confirmation（seq-1，在先）与一条同
          request_id（即补偿操作 D）的 asset_operation_committed
          （seq+1，收尾）——三事件同批原子落盘，残缺即矛盾现场；
        - 补偿操作（operation_id=D）与原操作同资产、delta 恰为反向；
          提交事件与账本的逐字段一致由
          _reconcile_asset_committed_events 全局对账。

        任一矛盾都 fail-closed（RecoveryError，保留现场）。纯只读，不记
        事件、不改 seq、不写状态。"""
        events = self._dispatch_reorged_events_strict(wallet_id)
        if not events:
            return
        requests = self._dispatch_all_request_events_strict(wallet_id)
        request_by_dispatch = {
            event["request_id"]: event for event in requests
        }
        takeover_by_dispatch = {
            event["request_id"]: event
            for event in self._dispatch_taken_over_events_strict(wallet_id)
        }
        settled_by_dispatch = {
            event["request_id"]: event
            for event in self._dispatch_settled_events_strict(wallet_id)
        }
        ledger = self._store.check_asset_ledger_semantics(wallet_id)
        operations = ledger["operations"]
        all_events = self._audit.all_events(wallet_id)
        by_seq = {event["seq"]: event for event in all_events}
        for event in events:
            dispatch_id = event["request_id"]
            seq = event["seq"]
            request = request_by_dispatch.get(dispatch_id)
            if request is None or request["seq"] >= seq:
                raise RecoveryError(
                    f"wallet {wallet_id!r} has a chain_dispatch_reorged "
                    f"event for {dispatch_id!r} without a preceding dispatch "
                    "request"
                )
            saved_request = request["details"]
            # 失败派发可经接管由新适配器播链、结算后再重组：重组事件的
            # actor 取当前生效适配器（接管在先时为新适配器）。
            takeover = takeover_by_dispatch.get(dispatch_id)
            if takeover is not None and takeover["seq"] < seq:
                effective_adapter = takeover["details"]["adapter_id"]
            else:
                effective_adapter = saved_request["adapter_id"]
            if event["actor_id"] != effective_adapter:
                raise RecoveryError(
                    f"wallet {wallet_id!r} chain_dispatch_reorged "
                    f"{dispatch_id!r} adapter_id disagrees with the effective "
                    "dispatch adapter"
                )
            settled = settled_by_dispatch.get(dispatch_id)
            if settled is None or settled["seq"] >= seq:
                raise RecoveryError(
                    f"wallet {wallet_id!r} has a chain_dispatch_reorged "
                    f"event for {dispatch_id!r} without a preceding "
                    "chain_dispatch_settled event"
                )
            predecessor = by_seq.get(seq - 1)
            pred_details = (
                predecessor.get("details")
                if isinstance(predecessor, dict)
                else None
            )
            if (
                predecessor is None
                or predecessor.get("type")
                != audit.TYPE_CHAIN_DISPATCH_CONFIRMATION
                or predecessor.get("request_id") != dispatch_id
                or not isinstance(pred_details, dict)
                or pred_details.get("state") != "reorged"
            ):
                raise RecoveryError(
                    f"wallet {wallet_id!r} has a chain_dispatch_reorged "
                    f"event for {dispatch_id!r} without an adjacent reorged "
                    "confirmation event"
                )
            follower = by_seq.get(seq + 1)
            follower_details = (
                follower.get("details")
                if isinstance(follower, dict)
                else None
            )
            if (
                follower is None
                or follower.get("type") != audit.TYPE_ASSET_OPERATION_COMMITTED
                or follower.get("request_id") != dispatch_id
                or not isinstance(follower_details, dict)
            ):
                raise RecoveryError(
                    f"wallet {wallet_id!r} has a chain_dispatch_reorged "
                    f"event for {dispatch_id!r} without an adjacent "
                    "committed event"
                )
            # 补偿操作与原操作同资产、delta 恰为反向。
            original = operations.get(saved_request["operation_id"])
            if original is None:
                raise RecoveryError(
                    f"wallet {wallet_id!r} has a chain_dispatch_reorged "
                    f"event for {dispatch_id!r} whose asset operation "
                    f"{saved_request['operation_id']!r} is unknown"
                )
            if (
                follower_details.get("asset_id") != original["asset_id"]
                or follower_details.get("delta") != -original["delta"]
            ):
                raise RecoveryError(
                    f"wallet {wallet_id!r} chain_dispatch_reorged "
                    f"{dispatch_id!r} committed details are not the inverse "
                    "of its settled operation"
                )

    # ---- 跨链派发失败接管 -------------------------------------------------

    def _dispatch_taken_over_events_strict(
        self, wallet_id: str
    ) -> list[dict]:
        """返回该钱包全部 chain_dispatch_taken_over 事件（按 seq 升序）并
        逐条严格校验**形状**（外层七字段键序、request_id==dispatch_id、
        actor_id 为安全标识（approval_request_id）、reason 为 null、details
        恰为三键 V 且键序固定 dispatch_id,adapter_id,state、state 恒为
        requested、adapter_id 为安全标识）。

        这里只做与现场无关的形状校验；与派发请求/失败结果/审批单的先后、
        归属及 message 语义复核在
        :meth:`_reconcile_chain_dispatch_taken_over_events` 按事件 seq 完成。
        任何形状畸形都是不可对账现场（RecoveryError）。纯只读，不分配
        seq。"""
        events = self._audit.events_by_type(
            wallet_id, audit.TYPE_CHAIN_DISPATCH_TAKEN_OVER
        )
        seen: set[str] = set()
        for event in events:
            if list(event) != list(_AUDIT_OUTER_KEY_ORDER):
                raise RecoveryError(
                    f"wallet {wallet_id!r} has a chain_dispatch_taken_over "
                    "event whose outer fields are out of the canonical order"
                )
            dispatch_id = event.get("request_id")
            actor_id = event.get("actor_id")
            if (
                not isinstance(dispatch_id, str)
                or not ROTATION_ID_RE.match(dispatch_id)
            ):
                raise RecoveryError(
                    f"wallet {wallet_id!r} has a chain_dispatch_taken_over "
                    "event with a malformed dispatch_id"
                )
            if dispatch_id in seen:
                raise RecoveryError(
                    f"wallet {wallet_id!r} has multiple "
                    f"chain_dispatch_taken_over events for {dispatch_id!r}"
                )
            seen.add(dispatch_id)
            if not (
                isinstance(actor_id, str) and ROTATION_ID_RE.match(actor_id)
            ):
                raise RecoveryError(
                    f"wallet {wallet_id!r} chain_dispatch_taken_over "
                    f"{dispatch_id!r} has a malformed approval_request_id"
                )
            if event.get("reason") is not None:
                raise RecoveryError(
                    f"wallet {wallet_id!r} chain_dispatch_taken_over "
                    f"{dispatch_id!r} has a non-null reason"
                )
            details = event.get("details")
            if (
                not isinstance(details, dict)
                or list(details)
                != list(self._DISPATCH_TAKEN_OVER_VIEW_KEY_ORDER)
            ):
                raise RecoveryError(
                    f"wallet {wallet_id!r} chain_dispatch_taken_over "
                    f"{dispatch_id!r} has malformed details"
                )
            if details["dispatch_id"] != dispatch_id:
                raise RecoveryError(
                    f"wallet {wallet_id!r} chain_dispatch_taken_over "
                    f"{dispatch_id!r} details dispatch_id disagrees with its "
                    "request_id"
                )
            if not (
                isinstance(details["adapter_id"], str)
                and ROTATION_ID_RE.match(details["adapter_id"])
            ):
                raise RecoveryError(
                    f"wallet {wallet_id!r} chain_dispatch_taken_over "
                    f"{dispatch_id!r} has a malformed adapter_id"
                )
            if details["state"] != "requested":
                raise RecoveryError(
                    f"wallet {wallet_id!r} chain_dispatch_taken_over "
                    f"{dispatch_id!r} has a state other than requested"
                )
        return events

    def _reconcile_chain_dispatch_taken_over_events(
        self, wallet_id: str
    ) -> None:
        """按 seq 严格复核全部 chain_dispatch_taken_over 事件（调用方须持
        钱包事务锁）。

        每条接管都以其**提交之前**的现场复核在线首提的全部前置：

        - 同一 dispatch_id 的 chain_dispatch_requested 必须先于接管事件
          提交（请求先于接管）；
        - 接管提交之前该派发的前置为互斥二者之一：

          * 已有唯一 chain_dispatch_result 且为 failed（failed 接管）；
          * 已有 chain_dispatch_isolated 且没有任何 result（isolated
            接管）；

          两种情形都要求接管时尚未接管；隔离与 failed 结果并存、或两者
          皆无都属矛盾现场；
        - 接管 adapter_id 与原请求适配器不同；
        - actor_id 指向同钱包审批单，存在、message 逐字为按
          dispatch_id,adapter_id（新适配器）序的紧凑 JSON、状态为
          approved（其后经 /sign 推进为 signed 亦认可）。

        任一矛盾都 fail-closed（RecoveryError，保留现场）。纯只读，不记
        事件、不改 seq、不写状态。接管之后新适配器结果与确认进展的归属
        复核在结果/确认各自的对账中按接管事件完成。"""
        events = self._dispatch_taken_over_events_strict(wallet_id)
        if not events:
            return
        requests = self._dispatch_all_request_events_strict(wallet_id)
        request_by_dispatch = {
            event["request_id"]: event for event in requests
        }
        # 各资产操作的提交 seq：接管时操作必须仍为 pending（提交点不得早
        # 于接管事件；接管后新适配器成功播链再结算是允许的）。
        committed_seq: dict[str, int] = {}
        for committed in self._audit.events_by_type(
            wallet_id, audit.TYPE_ASSET_OPERATION_COMMITTED
        ):
            request_id = committed.get("request_id")
            if isinstance(request_id, str):
                committed_seq[request_id] = committed["seq"]
        # 接管提交之前的失败结果：按 seq 逐条收集（每派发至多一条由结果
        # 形状校验保证；接管后允许新适配器再提交一条结果，故这里不能直接
        # 用按 request 分组的"至多一条"断言，而按 seq 取接管前的最后一条
        # 结果）。
        result_events = self._audit.events_by_type(
            wallet_id, audit.TYPE_CHAIN_DISPATCH_RESULT
        )
        results_by_dispatch: dict[str, list[dict]] = {}
        for event in result_events:
            results_by_dispatch.setdefault(
                event["request_id"], []
            ).append(event)
        for event in events:
            details = event["details"]
            dispatch_id = details["dispatch_id"]
            seq = event["seq"]
            request = request_by_dispatch.get(dispatch_id)
            if request is None or request["seq"] >= seq:
                raise RecoveryError(
                    f"wallet {wallet_id!r} has a chain_dispatch_taken_over "
                    f"event for {dispatch_id!r} without a preceding dispatch "
                    "request"
                )
            saved_request = request["details"]
            # 接管时资产操作必须仍为 pending（提交点不得先于接管）。
            operation_id = saved_request["operation_id"]
            operation_commit_seq = committed_seq.get(operation_id)
            if operation_commit_seq is not None and operation_commit_seq < seq:
                raise RecoveryError(
                    f"wallet {wallet_id!r} chain_dispatch_taken_over "
                    f"{dispatch_id!r} follows a committed asset operation"
                )
            # 接管前置（互斥二者之一）：
            #   a) 接管前恰有一条 failed 结果且无隔离；
            #   b) 接管前有一条隔离事件且无任何 result。
            prior_results = [
                result
                for result in results_by_dispatch.get(dispatch_id, [])
                if result["seq"] < seq
            ]
            isolated_groups = (
                self._audit.chain_dispatch_isolated_events(wallet_id).get(
                    dispatch_id
                )
                or []
            )
            prior_isolations = [
                isolated
                for isolated in isolated_groups
                if isolated["seq"] < seq
            ]
            if prior_isolations:
                # 形状/隔离对账已保证每派发至多一条；隔离接管前不得有
                # result，隔离适配器须与原派发适配器一致。
                if len(prior_isolations) != 1 or prior_results:
                    raise RecoveryError(
                        f"wallet {wallet_id!r} chain_dispatch_taken_over "
                        f"{dispatch_id!r} follows both an isolation and a "
                        "result"
                    )
                if (
                    prior_isolations[0]["details"]["adapter_id"]
                    != saved_request["adapter_id"]
                ):
                    raise RecoveryError(
                        f"wallet {wallet_id!r} chain_dispatch_taken_over "
                        f"{dispatch_id!r} follows an isolation on a different "
                        "adapter"
                    )
            else:
                if (
                    not prior_results
                    or prior_results[-1]["details"]["state"] != "failed"
                ):
                    raise RecoveryError(
                        f"wallet {wallet_id!r} chain_dispatch_taken_over "
                        f"{dispatch_id!r} has neither a preceding failed "
                        "result nor an isolation"
                    )
            # 新适配器必须不同于原适配器
            if details["adapter_id"] == saved_request["adapter_id"]:
                raise RecoveryError(
                    f"wallet {wallet_id!r} chain_dispatch_taken_over "
                    f"{dispatch_id!r} keeps the original adapter"
                )
            # 审批单复核：同钱包、存在、message 逐字一致、approved/signed
            approval_request_id = event["actor_id"]
            try:
                approval = self._store.get_request(
                    wallet_id, approval_request_id
                )
            except CorruptDataError:
                raise
            except ValueError as exc:
                raise RecoveryError(
                    f"wallet {wallet_id!r} chain dispatch takeover approval "
                    "record is unreadable"
                ) from exc
            if not isinstance(approval, dict):
                raise RecoveryError(
                    f"wallet {wallet_id!r} chain_dispatch_taken_over "
                    f"{dispatch_id!r} refers to an unknown approval request"
                )
            expected_message = self._takeover_approval_message(
                dispatch_id, details["adapter_id"]
            )
            if approval.get("message") != expected_message:
                raise RecoveryError(
                    f"wallet {wallet_id!r} chain_dispatch_taken_over "
                    f"{dispatch_id!r} approval message does not match"
                )
            if approval.get("state") not in ("approved", "signed"):
                raise RecoveryError(
                    f"wallet {wallet_id!r} chain_dispatch_taken_over "
                    f"{dispatch_id!r} approval request is not approved"
                )

    def post_chain_dispatch_takeover(
        self,
        wallet_id: str,
        dispatch_id: object,
        adapter_id: object,
        approval_request_id: object,
    ) -> tuple[int, dict]:
        """对一笔失败（result=failed）的跨链派发申请由新适配器接管，返回
        (HTTP 状态码, 视图 V={dispatch_id,adapter_id,state})。

        请求体恰含 adapter_id,approval_request_id 两键（HTTP 边界拦键集），
        两值与路径 D 均须匹配安全标识；键集/值错 400；钱包/派发/审批单
        未知 404。仅当派发所属资产操作仍 pending 时可首提，且前置为下列
        二者之一（互斥）：该派发恰有一条 ``failed`` 结果且尚无隔离；或该
        派发已隔离（chain_dispatch_isolated）且尚无结果——即接管可从
        failed 或 isolated 发起；新 adapter_id 必须不同于原适配器，且其在
        **当前**健康表中不得显式为 ``down``（未配置/缺席视为 up；显式
        down 一律 409）；审批单须为同钱包既有 approved 审批单，其 message
        逐字等于按 dispatch_id,adapter_id 序的紧凑 JSON。任一不满足 409 且
        零副作用。

        成功 201 返回 V（state="requested"）；同参（adapter_id 与
        approval_request_id 全同）重放优先 200 返回同一 V（不复查现状）；
        异参或对已接管派发再次接管一律 409。
        chain_dispatch_taken_over 是唯一提交点（request_id=dispatch_id、
        actor_id=approval_request_id、reason=null、details=V）；锁内并发
        只有一个 201，重放不记事件。接管后 result 只接受新适配器的恰好一
        条结果，confirm 只承接新适配器 broadcasted 交易的确认进展。恢复
        检查、校验、状态判定与事件追加全部在锁内完成。"""
        try:
            with self._wallet_lock(wallet_id):
                self._heal_wallet(wallet_id)
                # 404 优先于 400：存在性在锁内、heal 之后先判定
                self._get_wallet_or_404(wallet_id)
                self._assert_wallet_active_locked(wallet_id)
                # 持锁访问先重放策略、票、派发请求/结果/确认/结算/重组/
                # 接管、操作与相邻提交事件：矛盾现场 fail-closed，优先于
                # 参数 400/404 判定。
                self._reconcile_chain_state_locked(wallet_id)
                # 类型/取值校验（400）
                for name, value in (
                    ("dispatch_id", dispatch_id),
                    ("adapter_id", adapter_id),
                    ("approval_request_id", approval_request_id),
                ):
                    if not isinstance(value, str) or not ROTATION_ID_RE.match(
                        value
                    ):
                        raise ServiceError(
                            400,
                            f"{name} must match [A-Za-z0-9_-]{{1,128}}",
                        )

                # 资产粒度冻结闸门先于幂等/再次接管：派发存在但资产
                # frozen 时，接管同参重放也一律 409；派发未知留给下方 404。
                self._assert_dispatch_asset_active_locked(
                    wallet_id, dispatch_id
                )

                # 幂等/再次接管优先于派发存在性等现状判定：已提交的接管只
                # 按全参（adapter_id、approval_request_id）比较回放。
                takeover_event = self._dispatch_takeover_event_locked(
                    wallet_id, dispatch_id
                )
                if takeover_event is not None:
                    saved = takeover_event["details"]
                    if (
                        saved["adapter_id"] == adapter_id
                        and takeover_event["actor_id"]
                        == approval_request_id
                    ):
                        return 200, self._dispatch_taken_over_view(
                            dispatch_id, adapter_id
                        )
                    raise ServiceError(
                        409,
                        f"dispatch {dispatch_id!r} has already been taken over",
                    )

                # 404：派发请求未知
                requests = self._dispatch_requests_grouped_locked(
                    wallet_id
                )
                grouped = requests.get(dispatch_id)
                if not grouped:
                    raise ServiceError(
                        404, f"dispatch {dispatch_id!r} not found"
                    )
                if len(grouped) != 1:
                    raise RecoveryError(
                        f"wallet {wallet_id!r} has multiple "
                        f"chain_dispatch_requested events for "
                        f"{dispatch_id!r}"
                    )
                request_details = grouped[0]["details"]

                # 404：同钱包审批单未知
                approval = self._store.get_request(
                    wallet_id, approval_request_id
                )
                if approval is None:
                    raise ServiceError(
                        404,
                        f"approval request {approval_request_id!r} not found",
                    )

                # 409：资产操作必须仍为 pending
                record = self._store.get_asset_operation(
                    wallet_id, request_details["operation_id"]
                )
                if record is None:
                    raise RecoveryError(
                        f"wallet {wallet_id!r} dispatch {dispatch_id!r} "
                        "refers to an unknown asset operation"
                    )
                if record["state"] != "pending":
                    raise ServiceError(
                        409,
                        f"asset operation "
                        f"{request_details['operation_id']!r} is "
                        f"{record['state']}, not pending",
                    )

                # 409：接管前置为互斥二者之一——
                #   a) 恰一条 failed 结果且未隔离（既有 failed 接管）；
                #   b) 已隔离（chain_dispatch_isolated）且尚无结果。
                # broadcasted 结果、failed 与隔离并存等其余情形一律 409
                # （后者在线正常流程不可达：恢复对账已把隔离后的旧适配器
                # 结果判为矛盾现场 503；此处为防御性 409）。
                result_group = (
                    self._audit.chain_dispatch_result_events(wallet_id).get(
                        dispatch_id
                    )
                    or []
                )
                isolated = self._dispatch_isolate_event_locked(
                    wallet_id, dispatch_id
                )
                has_failed_result = (
                    len(result_group) == 1
                    and result_group[0]["details"]["state"] == "failed"
                )
                if isolated is not None:
                    if result_group:
                        raise ServiceError(
                            409,
                            f"dispatch {dispatch_id!r} is isolated but also "
                            "has a result",
                        )
                elif not has_failed_result:
                    raise ServiceError(
                        409,
                        f"dispatch {dispatch_id!r} has neither a failed "
                        "result nor an isolation to take over",
                    )

                # 409：新适配器必须不同于原适配器
                if adapter_id == request_details["adapter_id"]:
                    raise ServiceError(
                        409,
                        f"dispatch {dispatch_id!r} takeover adapter must "
                        "differ from the original adapter",
                    )

                # 409：新适配器在**当前**健康表中不得显式 down（未配置/
                # 缺席视为 up；熔断表只阻止派发到显式 down 的适配器）。
                adapters = self._chain_adapters_locked(wallet_id)
                if adapters is not None and adapters.get(adapter_id) == "down":
                    raise ServiceError(
                        409,
                        f"chain adapter {adapter_id!r} is down (circuit "
                        "breaker open)",
                    )

                # 审批门控：同钱包既有 approved 审批单，message 逐字一致。
                # 按既有契约懒过期（可能原子记一次 request_expired）。
                approval = self._expire_if_needed(wallet_id, approval)
                expected_message = self._takeover_approval_message(
                    dispatch_id, adapter_id
                )
                if approval["message"] != expected_message:
                    raise ServiceError(
                        409,
                        "approval request message does not match this "
                        "takeover",
                    )
                if approval["state"] != "approved":
                    raise ServiceError(
                        409,
                        f"approval request {approval_request_id!r} is "
                        f"{approval['state']}, not approved",
                    )

                view = self._dispatch_taken_over_view(
                    dispatch_id, adapter_id
                )
                # chain_dispatch_taken_over 是唯一提交点：在跨进程事务锁内
                # 追加事件；事件之外不写任何接管状态文件。
                self._emit(
                    wallet_id,
                    self._audit_event(
                        audit.TYPE_CHAIN_DISPATCH_TAKEN_OVER,
                        request_id=dispatch_id,
                        actor_id=approval_request_id,
                        reason=None,
                        details=view,
                    ),
                )
                return 201, view
        except CorruptDataError:
            raise
        except ValueError:
            # wallet_id 含非法字符（构造锁路径时抛出）
            raise ServiceError(400, "invalid wallet_id")

    def _dispatch_isolated_view(
        self, dispatch_id: str, adapter_id: str
    ) -> dict:
        """隔离成功/重放响应体 V（三键固定序，state 恒为 isolated）。"""
        return {
            "dispatch_id": dispatch_id,
            "adapter_id": adapter_id,
            "state": "isolated",
        }

    def _dispatch_isolate_event_locked(
        self, wallet_id: str, dispatch_id: str
    ) -> Optional[dict]:
        """返回某派发唯一的 chain_dispatch_isolated 事件（调用方持锁）；
        未隔离返回 None；重复隔离事件是不可对账现场（RecoveryError）。"""
        grouped = self._audit.chain_dispatch_isolated_events(
            wallet_id
        ).get(dispatch_id)
        if not grouped:
            return None
        if len(grouped) != 1:
            raise RecoveryError(
                f"wallet {wallet_id!r} has multiple "
                f"chain_dispatch_isolated events for {dispatch_id!r}"
            )
        return grouped[0]

    def _dispatch_isolated_events_strict(
        self, wallet_id: str
    ) -> list[dict]:
        """返回该钱包全部 chain_dispatch_isolated 事件（按 seq 升序）并
        逐条严格校验**形状**（外层七字段键序、request_id==dispatch_id、
        actor_id/reason 恒为 null、details 恰为三键 V 且键序固定
        dispatch_id,adapter_id,state、state 恒为 isolated、adapter_id 为
        安全标识）。

        这里只做与现场无关的形状校验；与派发请求/健康表/操作/结果/接管的
        语义复核在 :meth:`_reconcile_chain_dispatch_isolated_events` 按事件
        seq 完成。任何形状畸形都是不可对账现场（RecoveryError）。纯只读，
        不分配 seq。"""
        events = self._audit.events_by_type(
            wallet_id, audit.TYPE_CHAIN_DISPATCH_ISOLATED
        )
        seen: set[str] = set()
        for event in events:
            if list(event) != list(_AUDIT_OUTER_KEY_ORDER):
                raise RecoveryError(
                    f"wallet {wallet_id!r} has a chain_dispatch_isolated "
                    "event whose outer fields are out of the canonical order"
                )
            dispatch_id = event.get("request_id")
            if (
                not isinstance(dispatch_id, str)
                or not ROTATION_ID_RE.match(dispatch_id)
            ):
                raise RecoveryError(
                    f"wallet {wallet_id!r} has a chain_dispatch_isolated "
                    "event with a malformed dispatch_id"
                )
            if dispatch_id in seen:
                raise RecoveryError(
                    f"wallet {wallet_id!r} has multiple "
                    f"chain_dispatch_isolated events for {dispatch_id!r}"
                )
            seen.add(dispatch_id)
            # 隔离无审批/无操作人：actor_id 与 reason 恒为 null。
            if (
                event.get("actor_id") is not None
                or event.get("reason") is not None
            ):
                raise RecoveryError(
                    f"wallet {wallet_id!r} chain_dispatch_isolated "
                    f"{dispatch_id!r} has a non-null actor_id or reason"
                )
            details = event.get("details")
            if (
                not isinstance(details, dict)
                or list(details)
                != list(self._DISPATCH_ISOLATED_VIEW_KEY_ORDER)
            ):
                raise RecoveryError(
                    f"wallet {wallet_id!r} chain_dispatch_isolated "
                    f"{dispatch_id!r} has malformed details"
                )
            if details["dispatch_id"] != dispatch_id:
                raise RecoveryError(
                    f"wallet {wallet_id!r} chain_dispatch_isolated "
                    f"{dispatch_id!r} details dispatch_id disagrees with its "
                    "request_id"
                )
            if not (
                isinstance(details["adapter_id"], str)
                and ROTATION_ID_RE.match(details["adapter_id"])
            ):
                raise RecoveryError(
                    f"wallet {wallet_id!r} chain_dispatch_isolated "
                    f"{dispatch_id!r} has a malformed adapter_id"
                )
            if details["state"] != "isolated":
                raise RecoveryError(
                    f"wallet {wallet_id!r} chain_dispatch_isolated "
                    f"{dispatch_id!r} has a state other than isolated"
                )
        return events

    def _reconcile_chain_dispatch_isolated_events(
        self, wallet_id: str
    ) -> None:
        """按 seq 严格复核全部 chain_dispatch_isolated 事件（调用方须持
        钱包事务锁）。

        每条隔离都以其**提交之前**的现场复核在线首提的全部前置：

        - 同一 dispatch_id 的 chain_dispatch_requested 必须先于隔离事件
          提交（派发在先）；
        - 隔离提交之前最近一条 chain_adapter_health 快照必须存在，且派发
          原适配器在该快照中显式为 ``down``（无快照/缺席/up 都矛盾）；
        - 隔离时资产操作仍为 pending（该操作的提交点不得早于隔离）；
        - 隔离之前该派发没有任何 chain_dispatch_result 与
          chain_dispatch_taken_over（result/takeover/isolate 互斥在前）；
        - 隔离之后、接管之前同样不得有 result（隔离只允许后续 takeover
          由新适配器重新播链）；未接管的隔离派发之后不得再有任何 result；
        - actor_id/reason 为 null、每派发至多一条隔离（形状校验保证）。

        任一矛盾都 fail-closed（RecoveryError，保留现场）。纯只读，不记
        事件、不改 seq、不写状态。"""
        events = self._dispatch_isolated_events_strict(wallet_id)
        if not events:
            return
        requests = self._dispatch_all_request_events_strict(wallet_id)
        request_by_dispatch = {
            event["request_id"]: event for event in requests
        }
        # 适配器健康快照按 seq 升序（chain_adapter_health 与变更控制下
        # target=chain-adapters 的 policy_change_applied 合并流，均经严格
        # 形状校验）：隔离前置取其 seq 之前的最后一条。
        health_events = self._adapter_health_snapshot_events_locked(wallet_id)
        # 各资产操作的提交 seq。
        committed_seq: dict[str, int] = {}
        for committed in self._audit.events_by_type(
            wallet_id, audit.TYPE_ASSET_OPERATION_COMMITTED
        ):
            request_id = committed.get("request_id")
            if isinstance(request_id, str):
                committed_seq[request_id] = committed["seq"]
        result_events = self._audit.events_by_type(
            wallet_id, audit.TYPE_CHAIN_DISPATCH_RESULT
        )
        results_by_dispatch: dict[str, list[dict]] = {}
        for event in result_events:
            results_by_dispatch.setdefault(
                event["request_id"], []
            ).append(event)
        takeover_by_dispatch = {
            event["request_id"]: event
            for event in self._dispatch_taken_over_events_strict(wallet_id)
        }
        for event in events:
            details = event["details"]
            dispatch_id = details["dispatch_id"]
            seq = event["seq"]
            adapter_id = details["adapter_id"]
            request = request_by_dispatch.get(dispatch_id)
            if request is None or request["seq"] >= seq:
                raise RecoveryError(
                    f"wallet {wallet_id!r} has a chain_dispatch_isolated "
                    f"event for {dispatch_id!r} without a preceding dispatch "
                    "request"
                )
            saved_request = request["details"]
            if saved_request["adapter_id"] != adapter_id:
                raise RecoveryError(
                    f"wallet {wallet_id!r} chain_dispatch_isolated "
                    f"{dispatch_id!r} adapter disagrees with its dispatch "
                    "request"
                )
            # 事前健康表：seq 之前最后一条快照必须存在且原适配器显式 down。
            health_table = None
            for health_event in health_events:
                if health_event["seq"] < seq:
                    health_table = health_event["details"]["adapters"]
                else:
                    break
            if (
                health_table is None
                or health_table.get(adapter_id) != "down"
            ):
                raise RecoveryError(
                    f"wallet {wallet_id!r} chain_dispatch_isolated "
                    f"{dispatch_id!r} has no preceding health snapshot with "
                    "its adapter explicitly down"
                )
            # 隔离时操作必须仍为 pending。
            operation_id = saved_request["operation_id"]
            operation_commit_seq = committed_seq.get(operation_id)
            if operation_commit_seq is not None and operation_commit_seq < seq:
                raise RecoveryError(
                    f"wallet {wallet_id!r} chain_dispatch_isolated "
                    f"{dispatch_id!r} follows a committed asset operation"
                )
            # 与 result/takeover 的先后互斥：隔离之前不得有 result 或接管；
            # 隔离之后只允许 takeover（其后新适配器 result 由结果对账复核）。
            takeover = takeover_by_dispatch.get(dispatch_id)
            for result in results_by_dispatch.get(dispatch_id, []):
                if result["seq"] < seq:
                    raise RecoveryError(
                        f"wallet {wallet_id!r} chain_dispatch_isolated "
                        f"{dispatch_id!r} follows an earlier dispatch result"
                    )
                if takeover is None or result["seq"] < takeover["seq"]:
                    raise RecoveryError(
                        f"wallet {wallet_id!r} has a dispatch result between "
                        f"isolation and takeover for {dispatch_id!r}"
                    )
            if takeover is not None and takeover["seq"] < seq:
                raise RecoveryError(
                    f"wallet {wallet_id!r} chain_dispatch_isolated "
                    f"{dispatch_id!r} follows an earlier takeover"
                )

    def post_chain_dispatch_isolate(
        self, wallet_id: str, dispatch_id: object
    ) -> tuple[int, dict]:
        """隔离一笔尚在途但原适配器已显式熔断的派发，返回
        (HTTP 状态码, 视图 V={dispatch_id,adapter_id,state})。

        请求体恰为空 JSON 对象 ``{}``（HTTP 边界拦键集）；路径 D 须匹配
        安全标识，非法 400；钱包/派发未知 404。首提前置：派发所属资产
        操作仍为 pending；该派发尚无 result、无 takeover、无 isolate；派
        发原适配器（dispatch 请求中的 adapter_id）在**当前**健康表中显式
        为 ``down``（健康表未配置、适配器缺席或为 up 一律 409）。任一不
        满足 409 且零副作用（不追加事件、现场不变）。

        首提 201 返回 V（state="isolated"）；同 D 重放优先 200 返回同一
        V（不复查健康表与现状）。chain_dispatch_isolated 是唯一提交事件
        （request_id=D、actor_id/reason=null、details=V）；钱包锁内并发
        只有一个 201，重放不记事件。隔离后旧适配器 result 一律 409；该派
        发可再经 takeover 由新适配器接管（failed/isolate 二选一前置）。
        """
        try:
            with self._wallet_lock(wallet_id):
                self._heal_wallet(wallet_id)
                # 404 优先于 400：存在性在锁内、heal 之后先判定
                self._get_wallet_or_404(wallet_id)
                self._assert_wallet_active_locked(wallet_id)
                # 持锁访问先重放策略、票、派发请求/结果/确认/结算/重组/
                # 接管/隔离、操作与相邻提交事件：矛盾现场 fail-closed。
                self._reconcile_chain_state_locked(wallet_id)
                if (
                    not isinstance(dispatch_id, str)
                    or not ROTATION_ID_RE.match(dispatch_id)
                ):
                    raise ServiceError(
                        400,
                        "dispatch_id must match [A-Za-z0-9_-]{1,128}",
                    )

                # 资产粒度冻结闸门先于同 D 重放：派发存在但资产 frozen 时
                # 隔离同参重放也一律 409；派发未知留给下方 404。
                self._assert_dispatch_asset_active_locked(
                    wallet_id, dispatch_id
                )

                # 同 D 重放优先于一切现状判定：已隔离即 200 返回同一 V，
                # 不复查健康表（事后把适配器翻回 up 不影响幂等重放）。
                isolate_event = self._dispatch_isolate_event_locked(
                    wallet_id, dispatch_id
                )
                if isolate_event is not None:
                    return 200, dict(isolate_event["details"])

                # 404：派发请求未知
                requests = self._dispatch_requests_grouped_locked(
                    wallet_id
                )
                grouped = requests.get(dispatch_id)
                if not grouped:
                    raise ServiceError(
                        404, f"dispatch {dispatch_id!r} not found"
                    )
                if len(grouped) != 1:
                    raise RecoveryError(
                        f"wallet {wallet_id!r} has multiple "
                        f"chain_dispatch_requested events for "
                        f"{dispatch_id!r}"
                    )
                request_details = grouped[0]["details"]
                adapter_id = request_details["adapter_id"]

                # 409：资产操作必须仍为 pending
                record = self._store.get_asset_operation(
                    wallet_id, request_details["operation_id"]
                )
                if record is None:
                    raise RecoveryError(
                        f"wallet {wallet_id!r} dispatch {dispatch_id!r} "
                        "refers to an unknown asset operation"
                    )
                if record["state"] != "pending":
                    raise ServiceError(
                        409,
                        f"asset operation "
                        f"{request_details['operation_id']!r} is "
                        f"{record['state']}, not pending",
                    )

                # 409：已有 result / takeover，不能隔离
                result_group = (
                    self._audit.chain_dispatch_result_events(wallet_id).get(
                        dispatch_id
                    )
                    or []
                )
                if result_group:
                    raise ServiceError(
                        409,
                        f"dispatch {dispatch_id!r} already has a result",
                    )
                if (
                    self._dispatch_takeover_event_locked(
                        wallet_id, dispatch_id
                    )
                    is not None
                ):
                    raise ServiceError(
                        409,
                        f"dispatch {dispatch_id!r} has already been taken over",
                    )

                # 409：原适配器必须在**当前**健康表中显式 down；健康表
                # 未配置或该适配器缺席视为 up（不熔断/不可隔离）。
                adapters = self._chain_adapters_locked(wallet_id)
                if adapters is None or adapters.get(adapter_id) != "down":
                    raise ServiceError(
                        409,
                        f"chain adapter {adapter_id!r} is not explicitly "
                        "down in the current health table",
                    )

                view = self._dispatch_isolated_view(
                    dispatch_id, adapter_id
                )
                # chain_dispatch_isolated 是唯一提交点：跨进程事务锁内追加
                # 事件；事件之外不写任何隔离状态文件。actor_id/reason 恒为
                # null（隔离无审批、无操作人）。
                self._emit(
                    wallet_id,
                    self._audit_event(
                        audit.TYPE_CHAIN_DISPATCH_ISOLATED,
                        request_id=dispatch_id,
                        actor_id=None,
                        reason=None,
                        details=view,
                    ),
                )
                return 201, view
        except CorruptDataError:
            raise
        except ValueError:
            # wallet_id 含非法字符（构造锁路径时抛出）
            raise ServiceError(400, "invalid wallet_id")

    def settle_chain_dispatch(
        self, wallet_id: str, dispatch_id: object
    ) -> tuple[int, dict]:
        """对已 finalize 的跨链派发做资产结算（空体 POST），返回
        (HTTP 状态码, committed 视图 R)。

        仅当派发归属（adapter）、播链交易（tx）与事件链一致、最后一条
        确认进展 V 已 finalized、资产操作仍 pending 时才在每钱包跨进程
        事务锁内原子结算：chain_dispatch_settled 与紧邻的唯一
        asset_operation_committed 两事件一次原子落盘（seq 为 n、n+1，
        两事件俱在前滚、俱无回滚，否则 RecoveryError 留现场）。confirming
        、余额不足或操作已在别处提交一律 409 且无副作用。

        首提 201 返回既有 R；同 dispatch_id 重放优先 200 返回同一 R
        （不复查现状）；201/200 的 R 键序统一为
        operation_id,asset_id,delta,state,balance,version；锁内并发
        只有一个 201，其余 200，重放不记事件。非法 D 400；钱包/派发
        未知 404。恢复检查、校验、状态判定与事件追加全部在锁内完成。"""
        try:
            with self._wallet_lock(wallet_id):
                self._heal_wallet(wallet_id)
                # 404 优先于 400：存在性在锁内、heal 之后先判定
                self._get_wallet_or_404(wallet_id)
                self._assert_wallet_active_locked(wallet_id)
                # 持锁访问先重放策略、报告、票、派发请求/结果/确认/结算、
                # 操作与相邻提交事件：矛盾现场 fail-closed。
                self._reconcile_chain_state_locked(wallet_id)
                if (
                    not isinstance(dispatch_id, str)
                    or not ROTATION_ID_RE.match(dispatch_id)
                ):
                    raise ServiceError(
                        400,
                        "dispatch_id must match [A-Za-z0-9_-]{1,128}",
                    )

                # 资产粒度冻结闸门先于已结算重放：派发存在但资产 frozen 时
                # 同 dispatch_id 重放也一律 409；派发未知留给下方 404。
                self._assert_dispatch_asset_active_locked(
                    wallet_id, dispatch_id
                )

                # 重放优先于一切现状判定：已结算的同 dispatch_id 一律
                # 200 返回同一 R（紧邻提交事件的 details），不复查现状。
                settled_groups = self._audit.chain_dispatch_settled_events(
                    wallet_id
                ).get(dispatch_id)
                if settled_groups:
                    if len(settled_groups) != 1:
                        raise RecoveryError(
                            f"wallet {wallet_id!r} has multiple "
                            f"chain_dispatch_settled events for "
                            f"{dispatch_id!r}"
                        )
                    settled_event = settled_groups[0]
                    operation_id = settled_event["details"]["operation_id"]
                    replay = self._store.get_asset_operation(
                        wallet_id, operation_id
                    )
                    if replay is None or replay["state"] != "committed":
                        raise RecoveryError(
                            f"wallet {wallet_id!r} chain_dispatch_settled "
                            f"{dispatch_id!r} has no committed ledger "
                            "operation"
                        )
                    return 200, self._asset_operation_view(replay)

                # 404：派发请求未知
                requests = self._dispatch_requests_grouped_locked(
                    wallet_id
                )
                grouped = requests.get(dispatch_id)
                if not grouped:
                    raise ServiceError(
                        404, f"dispatch {dispatch_id!r} not found"
                    )
                if len(grouped) != 1:
                    raise RecoveryError(
                        f"wallet {wallet_id!r} has multiple "
                        f"chain_dispatch_requested events for {dispatch_id!r}"
                    )
                request_event = grouped[0]
                request_details = request_event["details"]
                operation_id = request_details["operation_id"]

                # 409：无当前生效适配器的 broadcasted 结果（接管后取新
                # 适配器接管之后的 broadcasted 结果）。
                broadcasted_result, takeover_event = (
                    self._effective_broadcasted_result_locked(
                        wallet_id, dispatch_id
                    )
                )
                if broadcasted_result is None:
                    raise ServiceError(
                        409,
                        f"dispatch {dispatch_id!r} has no broadcasted result",
                    )
                adapter_id = broadcasted_result["details"]["adapter_id"]

                # 409：最后一条确认进展必须已 finalized（无确认/确认中
                # 均不可结算）。
                confirmation_groups = (
                    self._audit.chain_dispatch_confirmation_events(
                        wallet_id
                    ).get(dispatch_id)
                    or []
                )
                if (
                    not confirmation_groups
                    or confirmation_groups[-1]["details"]["state"]
                    != "finalized"
                ):
                    raise ServiceError(
                        409,
                        f"dispatch {dispatch_id!r} is not finalized",
                    )

                record = self._store.get_asset_operation(
                    wallet_id, operation_id
                )
                if record is None:
                    raise RecoveryError(
                        f"wallet {wallet_id!r} dispatch {dispatch_id!r} "
                        "refers to an unknown asset operation"
                    )
                # 409：操作已在别处提交（链上确认自动提交、人工提交或
                # 其他结算）。
                if record["state"] != "pending":
                    raise ServiceError(
                        409,
                        f"asset operation {operation_id!r} is "
                        f"{record['state']}, not pending",
                    )

                # 锁内原子结算：余额不足在此抛 409 且无任何副作用
                # （意图/账本/事件均未写）。成功时
                # chain_dispatch_settled 与 asset_operation_committed
                # 两事件同批原子落盘，崩溃按事件俱在/俱无前滚或回滚。
                committed_record = self._commit_asset_operation_locked(
                    wallet_id,
                    operation_id,
                    record,
                    settle_dispatch_id=dispatch_id,
                    settle_adapter_id=adapter_id,
                )
                return 201, self._asset_operation_view(committed_record)
        except CorruptDataError:
            raise
        except ValueError:
            # wallet_id 含非法字符（构造锁路径时抛出）
            raise ServiceError(400, "invalid wallet_id")

    # ---- 多源仲裁 ---------------------------------------------------------

    @staticmethod
    def _arbitration_policy_shape(wallet_id: str, event: dict) -> tuple[str, dict]:
        """严格校验一条**新形**多源仲裁策略事件，返回 (资产标识, 策略 Q)。

        新策略只写七字段 ``chain_vote`` 事件：request_id 为资产标识
        （安全 id），actor_id/reason 为 null，details 按**精确键集**
        ``{sources, quorum}`` 与观察票（``{source, report, state}``）
        区分。sources 为 ID 升序的 ``{安全ID: bool}``（至少一个启用源），
        quorum 为 [2, 启用数] 内的非布尔整数。任何畸形都是不可对账现场
        （RecoveryError，fail-closed）。"""
        return WalletService._arbitration_policy_event_shape(
            wallet_id, event, "chain_vote policy event"
        )

    @staticmethod
    def _legacy_arbitration_policy_shape(
        wallet_id: str, event: dict
    ) -> tuple[str, dict]:
        """严格校验一条**合法旧** ``chain_arbitration`` 策略事件。

        旧事件仅只读兼容：恢复时与新形 chain_vote 策略事件等价参与按
        seq 的"每资产取最后一条"重放，在线 PUT 不再写此类型。形状规则
        与新形事件一致（request_id 为资产标识、actor_id/reason 为 null、
        details 恰含 {sources, quorum}）。"""
        return WalletService._arbitration_policy_event_shape(
            wallet_id, event, "chain_arbitration event"
        )

    @staticmethod
    def _arbitration_policy_event_shape(
        wallet_id: str, event: dict, what: str
    ) -> tuple[str, dict]:
        """新旧策略事件共用的严格形状校验，返回 (资产标识, 策略 Q)。"""
        if (
            event.get("actor_id") is not None
            or event.get("reason") is not None
        ):
            raise RecoveryError(
                f"wallet {wallet_id!r} has a {what} with actor/reason set"
            )
        asset_id = event.get("request_id")
        if not isinstance(asset_id, str) or not ROTATION_ID_RE.match(
            asset_id
        ):
            raise RecoveryError(
                f"wallet {wallet_id!r} has a {what} without an asset id"
            )
        sources, quorum = WalletService._arbitration_details_shape(
            wallet_id, event.get("details"), what
        )
        return asset_id, {"sources": sources, "quorum": quorum}

    @staticmethod
    def _arbitration_details_shape(
        wallet_id: str, details: object, what: str
    ) -> tuple[dict[str, bool], int]:
        """校验仲裁策略 details ``{sources, quorum}``，返回归一的
        （ID 升序）sources 与 quorum。畸形抛 RecoveryError。"""
        if not isinstance(details, dict) or set(details) != {
            "sources",
            "quorum",
        }:
            raise RecoveryError(
                f"wallet {wallet_id!r} has a malformed {what}"
            )
        sources = details["sources"]
        quorum = details["quorum"]
        if not isinstance(sources, dict) or not sources:
            raise RecoveryError(
                f"wallet {wallet_id!r} has a malformed {what}"
            )
        normalized: dict[str, bool] = {}
        enabled = 0
        for source in sorted(sources):
            value = sources[source]
            if (
                not isinstance(source, str)
                or not ROTATION_ID_RE.match(source)
                or not isinstance(value, bool)
            ):
                raise RecoveryError(
                    f"wallet {wallet_id!r} has a malformed {what}"
                )
            normalized[source] = value
            if value:
                enabled += 1
        if (
            not isinstance(quorum, int)
            or isinstance(quorum, bool)
            or quorum < 2
            or quorum > enabled
        ):
            raise RecoveryError(
                f"wallet {wallet_id!r} has a malformed {what}"
            )
        return normalized, quorum

    @staticmethod
    def _vote_shape(wallet_id: str, event: dict) -> tuple[str, dict]:
        """严格校验一条 chain_vote 事件，返回 (操作 id, 票 details)。

        request_id 为资产操作 id，actor_id/reason 为 null，details 恰含
        {source, report, state}：source 为安全标识，report 为达门槛链上
        报告 B（chain_report 同形五字段），state 为
        collecting|conflict|adopted。任何畸形都是不可对账现场
        （RecoveryError，fail-closed）。"""
        if (
            event.get("actor_id") is not None
            or event.get("reason") is not None
        ):
            raise RecoveryError(
                f"wallet {wallet_id!r} has a chain_vote event with "
                "actor/reason set"
            )
        operation_id = event.get("request_id")
        if not isinstance(operation_id, str) or not ROTATION_ID_RE.match(
            operation_id
        ):
            raise RecoveryError(
                f"wallet {wallet_id!r} has a chain_vote event without an "
                "operation id"
            )
        details = event.get("details")
        if not isinstance(details, dict) or set(details) != {
            "source",
            "report",
            "state",
        }:
            raise RecoveryError(
                f"wallet {wallet_id!r} has a malformed chain_vote event"
            )
        source = details["source"]
        report = details["report"]
        state = details["state"]
        if not isinstance(source, str) or not ROTATION_ID_RE.match(source):
            raise RecoveryError(
                f"wallet {wallet_id!r} has a malformed chain_vote event"
            )
        if state not in ("collecting", "conflict", "adopted"):
            raise RecoveryError(
                f"wallet {wallet_id!r} has a malformed chain_vote event"
            )
        try:
            WalletService._assert_chain_report_body(report)
        except ServiceError:
            raise RecoveryError(
                f"wallet {wallet_id!r} has a malformed chain_vote event"
            )
        return operation_id, {
            "source": source,
            "report": dict(report),
            "state": state,
        }

    @staticmethod
    def _chain_vote_event_kind(event: object) -> Optional[str]:
        """按 details 的**精确键集**区分一条 chain_vote 事件的语义：

        - ``"policy"``：多源仲裁策略事件（details 恰为 {sources,quorum}，
          request_id 为资产标识）；
        - ``"vote"``：观察票事件（details 恰为 {source,report,state}，
          request_id 为资产操作标识）；
        - ``None``：键集/形状无法归入任一语义的畸形事件。

        两种语义共用 chain_vote 事件类型，仅靠精确键集区分；任何额外键
        或缺键都不得被猜成其中一种。
        """
        if not isinstance(event, dict):
            return None
        details = event.get("details")
        if not isinstance(details, dict):
            return None
        keys = set(details)
        if keys == {"sources", "quorum"}:
            return "policy"
        if keys == {"source", "report", "state"}:
            return "vote"
        return None

    def _chain_arbitration_policies(
        self, wallet_id: str
    ) -> dict[str, dict]:
        """从审计事件序列恢复各资产的多源仲裁策略（按 seq 升序重放，
        每资产取最后一条）。

        新策略只写 chain_vote 事件（details 键集 {sources,quorum}）；
        合法旧 chain_arbitration 事件仅只读兼容，与新事件一同按 seq
        参与"每资产取最后一条"。策略只由审计事件持久化；畸形事件
        fail-closed（RecoveryError）。纯只读，不分配 seq。"""
        policies: dict[str, dict] = {}
        for event in self._audit.all_events(wallet_id):
            etype = event.get("type")
            if etype == audit.TYPE_CHAIN_ARBITRATION:
                asset_id, policy = self._legacy_arbitration_policy_shape(
                    wallet_id, event
                )
                policies[asset_id] = policy
            elif etype == audit.TYPE_CHAIN_VOTE:
                kind = self._chain_vote_event_kind(event)
                if kind == "policy":
                    asset_id, policy = self._arbitration_policy_shape(
                        wallet_id, event
                    )
                    policies[asset_id] = policy
                elif kind is None:
                    # 键集既非策略也非票的 chain_vote：畸形事件，绝不
                    # 静默忽略后继续服务。
                    raise RecoveryError(
                        f"wallet {wallet_id!r} has a malformed chain_vote "
                        "event"
                    )
                # 观察票由 _chain_votes 严格校验，这里不解释
        return policies

    @staticmethod
    def _assert_chain_report_body(body: object) -> dict:
        """校验并归一 observe/source vote 随附的达门槛链上报告 B
        （chain_report 同形五字段）。非法抛 ServiceError(400)，合法返回
        键序固定的 B 副本。"""
        if not isinstance(body, dict) or set(body) != {
            "chain_id",
            "tx_id",
            "block_height",
            "block_hash",
            "confirmations",
        }:
            raise ServiceError(
                400,
                "report must contain exactly chain_id, tx_id, "
                "block_height, block_hash and confirmations",
            )
        chain_id = body["chain_id"]
        tx_id = body["tx_id"]
        block_height = body["block_height"]
        block_hash = body["block_hash"]
        confirmations = body["confirmations"]
        WalletService._validate_chain_id(chain_id)
        WalletService._validate_hex_32(tx_id, "tx_id")
        WalletService._validate_hex_32(block_hash, "block_hash")
        WalletService._validate_non_negative_int(block_height, "block_height")
        WalletService._validate_non_negative_int(
            confirmations, "confirmations"
        )
        return {
            "chain_id": chain_id,
            "tx_id": tx_id,
            "block_height": block_height,
            "block_hash": block_hash,
            "confirmations": confirmations,
        }

    def put_chain_arbitration(
        self,
        wallet_id: str,
        asset_id: object,
        sources: object,
        quorum: object,
    ) -> dict:
        """设置（或覆盖）某资产的多源仲裁策略。成功 200 返回 Q。

        PUT 仅收 ``Q={sources, quorum}``（键集由 HTTP 边界校验）。
        sources 为 ID 升序的 ``{安全ID: bool}``（至少一个启用源），
        quorum 为 [2, 启用数] 内的非布尔整数；标识/值非法 400，钱包
        未知 404。该资产**只要存在任一 pending 资产操作**即 409——
        即使尚无任何观察票也不得改策略，且不改变策略、审计或 seq。
        新策略只写七字段 chain_vote 审计事件（request_id 为资产标识，
        actor_id/reason 为 null，details 键序 sources,quorum），每个资产
        取最后一条恢复；观察票同为 chain_vote（details 键序
        source,report,state），恢复按精确键集区分。**同值更新也记事件**，
        不写策略状态文件。合法旧 chain_arbitration 事件仅只读兼容。"""
        try:
            with self._wallet_lock(wallet_id):
                self._heal_wallet(wallet_id)
                # 404 优先于 400：存在性在锁内、heal 之后先判定
                self._get_wallet_or_404(wallet_id)
                self._assert_wallet_active_locked(wallet_id)
                # 持锁访问先重放策略、票、操作与相邻提交事件：heal 仅在
                # 账本文件存在时覆盖链/仲裁事件，PUT 不要求账本存在（纯
                # 策略配置），故在此显式只读重放——账本缺失却残留
                # report/vote/committed 事件、或既有策略/票畸形矛盾，都
                # fail-closed（RecoveryError/CorruptDataError/OSError），
                # 优先于参数 400/409，绝不向不可对账现场追加事件。
                ledger = self._reconcile_chain_state_locked(wallet_id)
                self._validate_asset_id(asset_id)
                # 资产粒度冻结闸门：frozen 资产的仲裁策略写入（含同值
                # 更新）一律 409 且零事件、seq 不变。
                self._assert_asset_active_locked(wallet_id, asset_id)
                normalized_sources, normalized_quorum = (
                    self._validate_arbitration_body(sources, quorum)
                )
                # 该资产存在任一 pending 资产操作即冻结策略：即使尚无
                # 观察票也一律 409（pending 操作的提交门控依赖一个稳定的
                # 仲裁策略），策略、票现场、审计与 seq 均不变。committed
                # 操作已是终态，不阻塞策略更新。
                if any(
                    record["asset_id"] == asset_id
                    and record["state"] == "pending"
                    for record in ledger["operations"].values()
                ):
                    raise ServiceError(
                        409,
                        f"asset {asset_id!r} has a pending asset operation; "
                        "arbitration policy is frozen",
                    )
                policy = {
                    "sources": normalized_sources,
                    "quorum": normalized_quorum,
                }
                self._emit(
                    wallet_id,
                    self._audit_event(
                        audit.TYPE_CHAIN_VOTE,
                        request_id=asset_id,
                        details=policy,
                    ),
                )
        except CorruptDataError:
            raise
        except ValueError:
            # wallet_id 含非法字符（构造锁路径时抛出）
            raise ServiceError(400, "invalid wallet_id")
        return policy

    @staticmethod
    def _validate_arbitration_body(
        sources: object, quorum: object
    ) -> tuple[dict[str, bool], int]:
        """校验 PUT 请求的 sources/quorum，返回归一（ID 升序）sources 与
        quorum；非法抛 ServiceError(400)。"""
        if not isinstance(sources, dict) or not sources:
            raise ServiceError(
                400, "sources must be a non-empty object of source booleans"
            )
        normalized: dict[str, bool] = {}
        enabled = 0
        for source in sorted(sources):
            value = sources[source]
            if (
                not isinstance(source, str)
                or not ROTATION_ID_RE.match(source)
            ):
                raise ServiceError(
                    400,
                    "sources keys must match [A-Za-z0-9_-]{1,128}",
                )
            if not isinstance(value, bool):
                raise ServiceError(
                    400, "sources values must be booleans"
                )
            normalized[source] = value
            if value:
                enabled += 1
        if (
            not isinstance(quorum, int)
            or isinstance(quorum, bool)
            or quorum < 2
            or quorum > enabled
        ):
            raise ServiceError(
                400,
                f"quorum must be an integer in [2, {enabled}] "
                "(the number of enabled sources)",
            )
        return normalized, quorum

    def get_chain_arbitration(
        self, wallet_id: str, asset_id: str
    ) -> dict:
        """读取某资产的多源仲裁策略：已配置 200 同体，未配置 404。

        策略纯由事件恢复；损坏/矛盾事件 fail-closed（由 HTTP 边界转
        503）。钱包不存在 404。持锁访问须重放策略、票、操作与相邻提交
        事件：heal 在账本文件存在时已重放；账本文件缺失（纯策略查询不
        要求账本）时显式只读重放链/仲裁事件，绝不带矛盾现场返回策略。"""
        try:
            with self._wallet_lock(wallet_id):
                self._heal_wallet(wallet_id)
                # 404 优先：锁内先判定钱包存在，再判定策略是否已配置
                self._get_wallet_or_404(wallet_id)
                # 账本文件缺失时 heal 不重放链/仲裁事件：显式只读重放，
                # 使残留票/报告/提交矛盾与畸形事件同样 fail-closed，
                # 优先于参数 400/404 判定。
                self._reconcile_chain_state_locked(wallet_id)
                self._validate_asset_id(asset_id)
                policy = self._chain_arbitration_policies(wallet_id).get(
                    asset_id
                )
        except CorruptDataError:
            raise
        except ValueError:
            raise ServiceError(400, "invalid wallet_id")
        if policy is None:
            raise ServiceError(
                404,
                f"wallet {wallet_id!r} has no chain arbitration policy "
                f"for asset {asset_id!r}",
            )
        return policy

    def _chain_votes(self, wallet_id: str) -> dict[str, list[dict]]:
        """从 chain_vote 事件序列恢复各操作的**观察票**（按 seq 升序的
        票列表）。

        chain_vote 事件按 details 精确键集区分语义：只有
        ``{source, report, state}`` 的是观察票；``{sources, quorum}`` 的
        是仲裁策略（由 _chain_arbitration_policies 恢复）；键集两者皆非
        即畸形事件，fail-closed（RecoveryError）。票只由审计事件持久化。
        纯只读，不分配 seq。"""
        votes: dict[str, list[dict]] = {}
        for event in self._audit.events_by_type(
            wallet_id, audit.TYPE_CHAIN_VOTE
        ):
            kind = self._chain_vote_event_kind(event)
            if kind == "policy":
                continue
            if kind is None:
                raise RecoveryError(
                    f"wallet {wallet_id!r} has a malformed chain_vote event"
                )
            operation_id, vote = self._vote_shape(wallet_id, event)
            votes.setdefault(operation_id, []).append(vote)
        return votes

    @staticmethod
    def _arbitration_state(votes: list[dict]) -> str:
        """由票序列推导仲裁状态：任一 adopted 票即 adopted；存在异体票
        （report 体不同）即 conflict；否则 collecting。"""
        if any(vote["state"] == "adopted" for vote in votes):
            return "adopted"
        bodies = {json.dumps(vote["report"], sort_keys=True) for vote in votes}
        if len(bodies) > 1:
            return "conflict"
        return "collecting"

    def observe(
        self,
        wallet_id: str,
        operation_id: object,
        body: object,
    ) -> tuple[int, dict]:
        """多源观察上报。返回 (HTTP 状态码, ``{"state": ...}``)。

        body 恰为 ``{source, report}``（键集由 HTTP 边界校验）：source 为
        安全 ID，report 为达门槛链上报告 B（chain_report 同形五字段）。

        - 各源首收 201；同源同体 200；改报、未知/停用源、终态后新增票
          一律 409 且不改变现场；异体票并存为 conflict；
        - 达 quorum 时决定性 adopted 票、chain_report(B) 与资产提交在
          锁内一次原子提交；启用仲裁后该 pending 操作的 chain report
          一律 409；
        - 仲裁仅由 chain_vote/chain_report/asset_operation_committed
          审计事件持久化，重放（同源同体）不记事件。恢复检查、存在性、
          校验、状态判定与事件追加全部在每钱包跨进程事务锁内完成。"""
        try:
            with self._wallet_lock(wallet_id):
                self._heal_wallet(wallet_id)
                # 404 优先于 400：存在性在锁内、heal 之后先判定
                self._get_wallet_or_404(wallet_id)
                self._assert_wallet_active_locked(wallet_id)
                # 持锁访问先重放策略、票、操作与相邻提交事件：账本文件
                # 缺失时 heal 未覆盖的矛盾现场也在此 fail-closed（503），
                # 优先于任何参数 400/404 判定，绝不据锁外快照继续。
                self._reconcile_chain_state_locked(wallet_id)
                self._validate_operation_id(operation_id)
                if not isinstance(body, dict) or set(body) != {
                    "source",
                    "report",
                }:
                    raise ServiceError(
                        400, "body must contain exactly source and report"
                    )
                source = body["source"]
                if not isinstance(source, str) or not ROTATION_ID_RE.match(
                    source
                ):
                    raise ServiceError(
                        400, "source must match [A-Za-z0-9_-]{1,128}"
                    )
                report = self._assert_chain_report_body(body["report"])
                record = self._store.get_asset_operation(
                    wallet_id, operation_id
                )
                if record is None:
                    raise ServiceError(
                        404,
                        f"asset operation {operation_id!r} not found",
                    )
                # 资产粒度冻结闸门：先于仲裁/链策略判定、同源同体重放与
                # quorum 提交，frozen 时一律 409、票不落盘、不记事件。
                self._assert_asset_active_locked(
                    wallet_id, record["asset_id"]
                )
                policy = self._chain_arbitration_policies(wallet_id).get(
                    record["asset_id"]
                )
                if policy is None:
                    raise ServiceError(
                        404,
                        f"wallet {wallet_id!r} has no chain arbitration "
                        f"policy for asset {record['asset_id']!r}",
                    )
                if not policy["sources"].get(source, False):
                    raise ServiceError(
                        409,
                        f"source {source!r} is unknown or disabled for "
                        "this arbitration policy",
                    )
                # 仲裁票的报告链必须与该资产跨链确认策略链一致：跨链
                # 策略缺失或未启用时不接受观察（无链可绑定）。
                chain_policy = self._chain_policies(wallet_id).get(
                    record["asset_id"]
                )
                if (
                    chain_policy is None
                    or not chain_policy["enabled"]
                    or report["chain_id"] != chain_policy["chain_id"]
                ):
                    raise ServiceError(
                        409,
                        "report chain_id does not match an enabled chain "
                        "policy",
                    )
                # 仲裁票只承载达门槛报告（report=达门槛 B）：确认数不足
                # required_confirmations 的观察不接受。
                if report["confirmations"] < chain_policy["required_confirmations"]:
                    raise ServiceError(
                        409,
                        "observed report has not reached the required "
                        "confirmations",
                    )
                votes = self._chain_votes(wallet_id).get(operation_id, [])
                # 同源票：首收记入，同体幂等，改报冲突
                same_source = [
                    vote for vote in votes if vote["source"] == source
                ]
                if same_source:
                    last = same_source[-1]
                    if last["report"] == report:
                        # 同源同体重放：不记事件，回当前状态（200）
                        return 200, {
                            "state": self._arbitration_state(votes)
                        }
                    raise ServiceError(
                        409,
                        f"source {source!r} already reported a different body",
                    )
                # 终态（已 adopted 或操作已 committed）后不接受新源票
                current_state = self._arbitration_state(votes)
                if current_state == "adopted" or record["state"] == "committed":
                    raise ServiceError(
                        409,
                        f"asset operation {operation_id!r} arbitration is "
                        "already adopted",
                    )
                # 达 quorum（含本票的同体票计数）即 adopted；否则异体票
                # 并存为 conflict，余为 collecting。
                agreeing = [
                    vote for vote in votes if vote["report"] == report
                ]
                reaches_quorum = len(agreeing) + 1 >= policy["quorum"]
                if reaches_quorum:
                    # 仲裁 adopted 会把 B 作为 chain_report 与提交紧邻落盘：
                    # 若该操作在启用仲裁前已有直接 chain_report（旧 pending
                    # 操作迁移到仲裁的现场），B 必须是其合法顺延，否则重启
                    # 后的链状态机对账会判矛盾——在线提前 409，票不落盘。
                    last_report = self._chain_reports(wallet_id).get(
                        operation_id
                    )
                    transition_error = self._report_transition_error(
                        chain_policy, last_report, report
                    )
                    if transition_error is not None:
                        raise ServiceError(409, transition_error)
                    state = "adopted"
                elif votes and any(
                    vote["report"] != report for vote in votes
                ):
                    state = "conflict"
                else:
                    state = "collecting"
                vote_details = {
                    "source": source,
                    "report": report,
                    "state": state,
                }
                if reaches_quorum:
                    # 决定性票 + chain_report(B) + 资产提交在锁内一次
                    # 原子提交（三事件同批落盘，seq n、n+1、n+2）；
                    # 提交失败（如余额不足）票不落盘（409，可重试）。
                    self._commit_asset_operation_locked(
                        wallet_id,
                        operation_id,
                        record,
                        report_details=report,
                        vote_details=vote_details,
                    )
                else:
                    self._emit(
                        wallet_id,
                        self._audit_event(
                            audit.TYPE_CHAIN_VOTE,
                            request_id=operation_id,
                            details=vote_details,
                        ),
                    )
                return 201, {"state": state}
        except CorruptDataError:
            raise
        except ValueError:
            # wallet_id 含非法字符（构造锁路径时抛出）
            raise ServiceError(400, "invalid wallet_id")

    def _reconcile_chain_arbitration_events(self, wallet_id: str) -> None:
        """多源仲裁事件（chain_vote 策略/票、合法旧 chain_arbitration）与
        资产提交的严格对账（调用方须持钱包事务锁；意图残留须已先恢复清零）。

        按 seq 重放全部事件，逐事件核对在线规则：

        - chain_vote 事件按 details 精确键集区分语义：{sources,quorum}
          为仲裁策略（request_id 为资产标识），{source,report,state} 为
          观察票（request_id 为资产操作标识）；键集两者皆非即畸形事件；
          合法旧 chain_arbitration 事件仅只读兼容为策略；
        - 票必须指向账本中存在的操作，且该资产当时已配置仲裁策略、
          source 在策略中启用，报告链与跨链策略链一致；
        - 同源不重复票（重放不记事件）、不接受改报；终态（adopted/
          committed）后不再有新源票；
        - state（collecting/conflict/adopted）必须与重算一致；
        - 达 quorum 的 adopted 票必须与同操作的 chain_report、
          asset_operation_committed 紧邻构成三事件提交点；
        - 启用仲裁的资产不得出现孤立 chain_report（无紧邻 adopted 票）。

        任一矛盾抛 RecoveryError（fail-closed，保留现场）。纯只读，
        不写状态、不记事件、不改 seq。
        """
        ledger = self._store.check_asset_ledger_semantics(wallet_id)
        operations = ledger["operations"]
        arb_policies: dict[str, dict] = {}
        chain_policies: dict[str, dict] = {}
        votes_by_op: dict[str, list[dict]] = {}
        # target=chain-policy 的 policy_change_applied 与 legacy
        # chain_policy 事件按 seq 合并折叠（均先经严格校验）。
        policy_changes = {
            event["seq"]: (
                event["details"]["asset_id"],
                dict(event["details"]["after"]),
            )
            for event in self._policy_change_events_strict(wallet_id)
            if event["details"]["target"] == "chain-policy"
        }
        events = self._audit.all_events(wallet_id)
        for index, event in enumerate(events):
            etype = event.get("type")
            if etype == audit.TYPE_CHAIN_POLICY:
                asset_id, policy = self._chain_policy_shape(wallet_id, event)
                chain_policies[asset_id] = policy
            elif etype == audit.TYPE_POLICY_CHANGE_APPLIED:
                change = policy_changes.get(event.get("seq"))
                if change is not None:
                    chain_policies[change[0]] = change[1]
            elif etype == audit.TYPE_CHAIN_ARBITRATION:
                # 合法旧策略事件：仅只读兼容，与新形事件一同按 seq 重放
                asset_id, policy = self._legacy_arbitration_policy_shape(
                    wallet_id, event
                )
                arb_policies[asset_id] = policy
            elif etype == audit.TYPE_CHAIN_VOTE:
                kind = self._chain_vote_event_kind(event)
                if kind is None:
                    raise RecoveryError(
                        f"wallet {wallet_id!r} has a malformed chain_vote "
                        "event"
                    )
                if kind == "policy":
                    asset_id, policy = self._arbitration_policy_shape(
                        wallet_id, event
                    )
                    arb_policies[asset_id] = policy
                    continue
                operation_id, vote = self._vote_shape(wallet_id, event)
                record = operations.get(operation_id)
                if record is None:
                    raise RecoveryError(
                        f"wallet {wallet_id!r} has a chain_vote event for "
                        f"unknown asset operation {operation_id!r}"
                    )
                policy = arb_policies.get(record["asset_id"])
                if policy is None:
                    raise RecoveryError(
                        f"wallet {wallet_id!r} has a chain_vote event for "
                        f"{operation_id!r} without an arbitration policy"
                    )
                source = vote["source"]
                if not policy["sources"].get(source, False):
                    raise RecoveryError(
                        f"wallet {wallet_id!r} has a chain_vote event from "
                        f"a disabled source {source!r}"
                    )
                report = vote["report"]
                chain_policy = chain_policies.get(record["asset_id"])
                if (
                    chain_policy is None
                    or not chain_policy["enabled"]
                    or report["chain_id"] != chain_policy["chain_id"]
                ):
                    raise RecoveryError(
                        f"wallet {wallet_id!r} has a chain_vote event for "
                        f"{operation_id!r} without a matching enabled chain "
                        "policy"
                    )
                if (
                    report["confirmations"]
                    < chain_policy["required_confirmations"]
                ):
                    raise RecoveryError(
                        f"wallet {wallet_id!r} has a chain_vote event for "
                        f"{operation_id!r} below the required confirmations"
                    )
                prior = votes_by_op.setdefault(operation_id, [])
                if any(past["state"] == "adopted" for past in prior):
                    raise RecoveryError(
                        f"wallet {wallet_id!r} has a chain_vote event for "
                        f"{operation_id!r} after its arbitration was adopted"
                    )
                if any(past["source"] == source for past in prior):
                    raise RecoveryError(
                        f"wallet {wallet_id!r} has duplicate chain_vote "
                        f"events for source {source!r} on {operation_id!r}"
                    )
                agreeing = [
                    past for past in prior if past["report"] == report
                ]
                reaches = len(agreeing) + 1 >= policy["quorum"]
                expected_state = "adopted" if reaches else (
                    "conflict"
                    if prior
                    and any(past["report"] != report for past in prior)
                    else "collecting"
                )
                if vote["state"] != expected_state:
                    raise RecoveryError(
                        f"wallet {wallet_id!r} chain_vote event state "
                        f"{vote['state']!r} does not match the reconciled "
                        f"state {expected_state!r}"
                    )
                if reaches:
                    # adopted 票必须紧邻 chain_report(B) 再紧邻
                    # asset_operation_committed（三事件一次原子提交）
                    follower1 = (
                        events[index + 1] if index + 1 < len(events) else None
                    )
                    follower2 = (
                        events[index + 2] if index + 2 < len(events) else None
                    )
                    if (
                        follower1 is None
                        or follower1.get("type") != audit.TYPE_CHAIN_REPORT
                        or follower1.get("request_id") != operation_id
                        or follower1.get("details") != report
                        or follower2 is None
                        or follower2.get("type")
                        != audit.TYPE_ASSET_OPERATION_COMMITTED
                        or follower2.get("request_id") != operation_id
                    ):
                        raise RecoveryError(
                            f"wallet {wallet_id!r} has an adopted chain_vote "
                            f"for {operation_id!r} without adjacent report "
                            "and committed events"
                        )
                prior.append(vote)
            elif etype == audit.TYPE_CHAIN_REPORT:
                operation_id = event.get("request_id")
                record = (
                    operations.get(operation_id)
                    if isinstance(operation_id, str)
                    else None
                )
                if (
                    record is not None
                    and arb_policies.get(record["asset_id"]) is not None
                ):
                    # 启用仲裁的资产：chain_report 只能作为 adopted 票的
                    # 紧邻随附报告出现，其前一条必须是同操作的**观察票**
                    # chain_vote（details 键集 {source,report,state}，
                    # state=adopted）；策略形 chain_vote 不算。
                    predecessor = (
                        events[index - 1] if index - 1 >= 0 else None
                    )
                    pred_details = (
                        predecessor.get("details")
                        if isinstance(predecessor, dict)
                        else None
                    )
                    if (
                        predecessor is None
                        or predecessor.get("type") != audit.TYPE_CHAIN_VOTE
                        or self._chain_vote_event_kind(predecessor) != "vote"
                        or predecessor.get("request_id") != operation_id
                        or not isinstance(pred_details, dict)
                        or pred_details.get("state") != "adopted"
                    ):
                        raise RecoveryError(
                            f"wallet {wallet_id!r} has a chain_report event "
                            f"for arbitration-enabled {operation_id!r} "
                            "without an adjacent adopted vote"
                        )

    # ---- 批准 / 拒绝 -----------------------------------------------------

    @staticmethod
    def _validate_approver_id(approver_id: object) -> None:
        if (
            not isinstance(approver_id, str)
            or isinstance(approver_id, bool)
            or not approver_id
            or not approver_id.strip()
        ):
            raise ServiceError(
                400, "approver_id must be a non-empty string"
            )

    @staticmethod
    def _validate_reason(reason: object) -> None:
        if reason is None:
            return
        if not isinstance(reason, str) or isinstance(reason, bool):
            raise ServiceError(400, "reason must be a string")
        if not reason.strip():
            raise ServiceError(400, "reason must be non-blank")
        if len(reason) > MAX_REASON_LENGTH:
            raise ServiceError(
                400, f"reason must be at most {MAX_REASON_LENGTH} characters"
            )

    def _decide(
        self,
        wallet_id: str,
        request_id: str,
        approver_id: object,
        reason: object,
        action: str,
    ) -> dict:
        try:
            with self._wallet_lock(wallet_id):
                self._heal_wallet(wallet_id)
                # 404 优先于 400：存在性先于 approver/reason 参数校验
                self._get_wallet_or_404(wallet_id)
                self._assert_wallet_active_locked(wallet_id)
                self._validate_approver_id(approver_id)
                self._validate_reason(reason)
                record = self._fetch_request_or_404(wallet_id, request_id)
                # 懒过期可能在此原子记一次 E；过期后操作落入终态分支（409、不记 A/R）
                record = self._expire_if_needed(wallet_id, record)
                if record["state"] == "cancelled":
                    raise ServiceError(
                        409,
                        f"signing request {request_id!r} is cancelled, "
                        "not pending",
                    )
                roster = self._effective_roster_locked(wallet_id)
                # 同人同决定重放优先，返回 200、不计数、不复查当前名单：
                # 批准人已在审批单 approvers 中即同批准重放；拒绝重放由
                # request_rejected 事件的 actor_id 认定。
                if (
                    action == "approve"
                    and approver_id in record["approvers"]
                ):
                    return self._request_view(record)
                if (
                    action == "reject"
                    and record["state"] == "rejected"
                    and any(
                        event.get("request_id") == request_id
                        and event.get("actor_id") == approver_id
                        for event in self._audit.events_by_type(
                            wallet_id,
                            audit.TYPE_REQUEST_REJECTED,
                        )
                    )
                ):
                    return self._request_view(record)
                if record["state"] != "pending":
                    raise ServiceError(
                        409,
                        f"signing request {request_id!r} is {record['state']}, "
                        "not pending",
                    )
                if roster and approver_id not in roster:
                    raise ServiceError(
                        409, "approver is not in the wallet approval roster"
                    )

                if action == "approve":
                    new_record = dict(record)
                    new_record["approvers"] = list(record["approvers"])
                    new_record["approvers"].append(approver_id)
                    if reason is not None:
                        new_record["reason"] = reason
                    reached = len(new_record["approvers"]) >= new_record["req"]
                    if reached:
                        new_record["state"] = "approved"
                    self._store.update_request(wallet_id, request_id, new_record)
                    event = self._audit_event(
                        audit.TYPE_REQUEST_APPROVED,
                        request_id=request_id,
                        actor_id=approver_id,
                        reason=reason,
                        details={
                            "count": len(new_record["approvers"]),
                            "req": new_record["req"],
                            "state": new_record["state"],
                        },
                    )
                    try:
                        self._emit(wallet_id, event)
                    except BaseException:
                        self._store.update_request(wallet_id, request_id, record)
                        raise
                    return self._request_view(new_record)

                # reject：任何一名审批人拒绝即终态（首批）
                new_record = dict(record)
                new_record["state"] = "rejected"
                if reason is not None:
                    new_record["reason"] = reason
                self._store.update_request(wallet_id, request_id, new_record)
                event = self._audit_event(
                    audit.TYPE_REQUEST_REJECTED,
                    request_id=request_id,
                    actor_id=approver_id,
                    reason=reason,
                    details={
                        "count": len(new_record["approvers"]),
                        "req": new_record["req"],
                        "state": "rejected",
                    },
                )
                try:
                    self._emit(wallet_id, event)
                except BaseException:
                    self._store.update_request(wallet_id, request_id, record)
                    raise
                return self._request_view(new_record)
        except CorruptDataError:
            raise
        except ValueError:
            # wallet_id 含非法字符（构造锁路径时抛出）
            raise ServiceError(400, "invalid wallet_id")

    def approve(
        self,
        wallet_id: str,
        request_id: str,
        approver_id: object,
        reason: object = None,
    ) -> dict:
        return self._decide(wallet_id, request_id, approver_id, reason, "approve")

    def reject(
        self,
        wallet_id: str,
        request_id: str,
        approver_id: object,
        reason: object = None,
    ) -> dict:
        return self._decide(wallet_id, request_id, approver_id, reason, "reject")

    # ---- 份额签名聚合 ---------------------------------------------------

    def _signing_approval_gate(
        self, wallet_id: str, signing_request_id: str, message: str
    ) -> dict | None:
        """既有 /sign 与可恢复签名会话共用的审批 + 冷热门控。

        调用方须持有钱包事务锁。返回 approved 审批单记录（无审批要求时
        返回 None），门控不通过抛 ServiceError(409/404)。可能原子地把超时
        pending 单懒过期为 expired 并记一次 request_expired 事件。

        - cold 模式：首签必须存在同 id、同 message 且 approved 的审批单。
          未配置审批策略（无法建单）、无单或未 approved 一律 409；
        - hot（或未配交易策略）且配置了审批策略：沿用原审批规则
          （无单 404，message 不符/未 approved 409）；
        - 其余情形不要求审批单。
        """
        approval_record = None
        approval_policy = self._store.get_policy(wallet_id)
        transaction_policy = self._store.get_transaction_policy(wallet_id)
        cold_mode = (
            transaction_policy is not None
            and transaction_policy.get("mode") == "cold"
        )
        if cold_mode:
            try:
                approval_record = self._store.get_request(
                    wallet_id, signing_request_id
                )
            except CorruptDataError:
                raise
            except ValueError:
                raise ServiceError(400, "invalid signing_request_id")
            if approval_record is None:
                raise ServiceError(
                    409,
                    f"cold wallet requires an approved signing request "
                    f"{signing_request_id!r}",
                )
        elif approval_policy is not None:
            approval_record = self._fetch_request_or_404(
                wallet_id, signing_request_id
            )

        if approval_record is not None:
            approval_record = self._expire_if_needed(
                wallet_id, approval_record
            )
            if approval_record["message"] != message:
                raise ServiceError(
                    409, "message does not match the signing request"
                )
            if approval_record["state"] != "approved":
                raise ServiceError(
                    409,
                    f"signing request {signing_request_id!r} is "
                    f"{approval_record['state']}, not approved",
                )
        return approval_record

    def sign(
        self,
        wallet_id: str,
        signing_request_id: object,
        message: object,
        signatures: object,
    ) -> tuple[int, dict]:
        """返回 (HTTP 状态码, 响应体)。

        恢复检查、钱包存在性、字段校验、当前份额/公钥读取、幂等查重、
        策略/审批单读取与签名提交全部在同一把每钱包跨进程事务锁内完成：
        绝不基于锁外快照决定 404/400/409 或幂等重放；轮换激活与首签
        交错时，未首签请求只能用当前 share_ids/公钥校验，重放直接返回
        磁盘上已提交的签名。
        """
        try:
            return self._sign_tx(
                wallet_id, signing_request_id, message, signatures
            )
        except CorruptDataError:
            raise
        except ValueError:
            # wallet_id 含非法字符（构造锁路径时抛出）
            raise ServiceError(400, "invalid wallet_id")

    def _sign_tx(
        self,
        wallet_id: str,
        signing_request_id: object,
        message: object,
        signatures: object,
    ) -> tuple[int, dict]:
        with self._wallet_lock(wallet_id):
            # 先自愈他进程崩溃遗留的激活/提交现场，绝不基于半完成的钱包
            # 公钥或份额做校验。
            self._heal_wallet(wallet_id)
            # 404 优先于 400：锁内、heal 之后先判定钱包存在性
            wallet = self._store.get_wallet(wallet_id)
            if wallet is None:
                raise ServiceError(404, f"wallet {wallet_id!r} not found")
            self._assert_wallet_active_locked(wallet_id)
            # 字段校验也在锁内：存在性确认后再判，杜绝锁外快照先行
            if (
                not isinstance(signing_request_id, str)
                or not signing_request_id
            ):
                raise ServiceError(
                    400, "signing_request_id must be a non-empty string"
                )
            if not isinstance(message, str):
                raise ServiceError(400, "message must be a string")
            if not isinstance(signatures, list) or len(signatures) != REQUIRED_SHARES:
                raise ServiceError(
                    400, f"exactly {REQUIRED_SHARES} share signatures are required"
                )
            # 锁内当前在用份额：份额轮换激活后，未首签的请求必须用新的
            # share_ids 与公钥校验，旧份额一律 400。
            expected_share_ids = [s["share_id"] for s in wallet["shares"]]
            share_pub = {s["share_id"]: s["public_key"] for s in wallet["shares"]}
            # 幂等查重的唯一检查点：必须在每钱包事务锁内、且在任何份额校验
            # 之前。重放直接返回磁盘上已提交的签名，不校验签名、不触发懒
            # 过期、不记事件。这把锁同时挡住首签事务尚未提交完成的并发
            # 请求，使重放永远读不到“签名已落盘但审批单/事件未提交”的
            # 半完成数据，保证并发重放只有一个首次结果。
            try:
                existing = self._store.get_signature(
                    wallet_id, signing_request_id
                )
            except CorruptDataError:
                raise
            except ValueError:
                raise ServiceError(400, "invalid signing_request_id")
            if existing is not None:
                return 200, {"signature": existing["signature"]}

            submitted: dict[str, bytes] = {}
            for index, item in enumerate(signatures):
                if not isinstance(item, dict):
                    raise ServiceError(400, f"signatures[{index}] must be an object")
                share_id = item.get("share_id")
                signature_hex = item.get("signature")
                if not isinstance(share_id, str) or share_id not in share_pub:
                    raise ServiceError(400, f"signatures[{index}] has unknown share_id")
                if not isinstance(signature_hex, str):
                    raise ServiceError(400, f"signatures[{index}].signature must be hex")
                try:
                    signature_bytes = bytes.fromhex(signature_hex)
                except ValueError:
                    raise ServiceError(
                        400, f"signatures[{index}].signature must be hex"
                    )
                if share_id in submitted:
                    raise ServiceError(400, "duplicate share_id in signatures")
                submitted[share_id] = signature_bytes

            # 两份必须齐备，且不能夹带未知份额
            if set(submitted) != set(expected_share_ids):
                raise ServiceError(400, "signatures from both share_ids are required")

            payload = crypto.build_payload(signing_request_id, message)
            verified: dict[str, bytes] = {}
            for share_id in expected_share_ids:
                public_bytes = bytes.fromhex(share_pub[share_id])
                if not crypto.verify_share(
                    public_bytes, payload, submitted[share_id]
                ):
                    raise ServiceError(400, f"signature verification failed for {share_id}")
                verified[share_id] = submitted[share_id]

            aggregate = crypto.combine_signatures(
                [verified[sid] for sid in expected_share_ids]
            )
            record = {"message": message, "signature": aggregate.hex()}

            # 审批与冷热门控：与既有 /sign 完全同一套规则（见
            # _signing_approval_gate）。这一步可能原子地把超时 pending 单
            # 记一次 E 并转为 expired。
            approval_record = self._signing_approval_gate(
                wallet_id, signing_request_id, message
            )

            # 事务提交：签名记录、审批单 signed 状态与 request_signed 事件
            # 必须在本钱包事务锁内一致落盘。任一写入或事件追加失败，都
            # 删除本次签名并把审批单恢复为原 approved，绝不留下半完成数据。
            committed = False
            try:
                existing = self._store.save_signature(
                    wallet_id, signing_request_id, record
                )
                if existing is not None:
                    # 兜底：锁内查重已保证不会到达；万一到达按重放处理，
                    # 不动审批单、不记事件。
                    return 200, {"signature": existing["signature"]}

                if approval_record is not None:
                    signed_record = dict(approval_record)
                    signed_record["state"] = "signed"
                    self._store.update_request(
                        wallet_id, signing_request_id, signed_record
                    )

                self._emit(
                    wallet_id,
                    self._audit_event(
                        audit.TYPE_REQUEST_SIGNED,
                        request_id=signing_request_id,
                        details={"message": message, "state": "signed"},
                    ),
                )
                committed = True
            except BaseException:
                if not committed:
                    self._store.delete_signature(
                        wallet_id, signing_request_id
                    )
                    if approval_record is not None:
                        self._store.update_request(
                            wallet_id, signing_request_id, approval_record
                        )
                raise
        return 201, {"signature": aggregate.hex()}

    # ---- 可恢复签名会话 ---------------------------------------------------

    @staticmethod
    def _session_view(record: dict) -> dict:
        """签名会话对外视图：原文、状态、已收/缺失份额、到期时间；
        aggregate_signature 仅在 signed 时出现；cancellation（恰含
        cancel_id/reason）仅在 cancelled 时出现。绝不返回份额签名本身。

        collecting/ready 会话在轮换后由持锁恢复迁移到当前在用快照（旧份额
        已从 shares 剔除），故视图只需按记录的 share_ids 计数。"""
        current_ids = list(record["share_ids"])
        received_set = {entry["share_id"] for entry in record["shares"]}
        received = [sid for sid in current_ids if sid in received_set]
        missing = [sid for sid in current_ids if sid not in received_set]
        view = {
            "id": record["id"],
            "message": record["message"],
            "state": record["state"],
            "received_shares": received,
            "missing_shares": missing,
            "expires_at": record["expires_at"],
        }
        if record["state"] == "signed":
            view["aggregate_signature"] = record["aggregate_signature"]
        if record["state"] == "cancelled":
            view["cancellation"] = {
                "cancel_id": record["cancellation"]["cancel_id"],
                "reason": record["cancellation"]["reason"],
            }
        return view

    @staticmethod
    def _validate_session_id(session_id: object) -> None:
        if not isinstance(session_id, str) or not ROTATION_ID_RE.match(
            session_id
        ):
            raise ServiceError(400, "id must match [A-Za-z0-9_-]{1,128}")

    @staticmethod
    def _validate_session_message(message: object) -> None:
        if not isinstance(message, str) or not message:
            raise ServiceError(400, "message must be a non-empty string")

    @staticmethod
    def _validate_session_timeout(timeout_seconds: object) -> None:
        # bool 是 int 的子类，必须先排除
        if (
            not isinstance(timeout_seconds, int)
            or isinstance(timeout_seconds, bool)
            or timeout_seconds <= 0
        ):
            raise ServiceError(
                400, "timeout_seconds must be a positive integer"
            )

    @staticmethod
    def _validate_share_signature(signature_hex: object) -> bytes:
        if not isinstance(signature_hex, str):
            raise ServiceError(400, "signature must be hex")
        try:
            signature = bytes.fromhex(signature_hex)
        except ValueError:
            raise ServiceError(400, "signature must be hex")
        if len(signature) != 64:
            raise ServiceError(
                400, "signature must be a 64-byte Ed25519 signature"
            )
        return signature

    # -- 会话历史公钥解析（轮换后恢复重验 / signed 旧份额重放）--------------

    def _session_share_public_keys(
        self, wallet_id: str, share_ids: list[str], current_meta: dict
    ) -> dict[str, str]:
        """收集给定份额 id 对应的份额公钥。

        当前在用份额取自钱包元数据；已轮换失效的旧份额公钥从轮换记录链
        获取（每个轮换记录带其在用时的有序 share_ids 与钱包 public_key），
        确保 signed 会话旧份额同值重放与启动恢复的逐份重验有权威公钥，
        而不是信任请求自报或猜写。

        - 轮换 R 的两份新份额公钥＝R.public_key 的前/后 32 字节，顺序按
          R.share_ids；
        - 最初的 share-1/share-2 公钥＝"创世旧公钥"（任一激活记录的
          previous_public_key 中不等于任何轮换 public_key 的那一个）的
          前/后 32 字节。
        任一份额找不到权威公钥或记录自相矛盾即 fail-closed。
        """
        public: dict[str, str] = {}
        rotations = self._store.list_rotations(wallet_id)
        rotation_pubkeys: set[str] = set()

        def halves(pub_hex: str, where: str) -> tuple[str, str]:
            try:
                raw = bytes.fromhex(pub_hex)
            except ValueError as exc:
                raise RecoveryError(
                    f"wallet {wallet_id!r} {where} is not hex"
                ) from exc
            if len(raw) != 64:
                raise RecoveryError(
                    f"wallet {wallet_id!r} {where} is not 64 bytes"
                )
            return raw[:32].hex(), raw[32:].hex()

        # 当前在用份额：钱包元数据 shares 有序，公钥两半按其顺序
        current_list = current_meta.get("shares")
        if (
            isinstance(current_list, list)
            and len(current_list) == 2
            and isinstance(current_meta.get("public_key"), str)
        ):
            first, second = halves(
                current_meta["public_key"], "wallet public_key"
            )
            ordered_current = [first, second]
            for index, entry in enumerate(current_list):
                if (
                    isinstance(entry, dict)
                    and isinstance(entry.get("share_id"), str)
                    and isinstance(entry.get("public_key"), str)
                    and entry["public_key"] == ordered_current[index]
                ):
                    public[entry["share_id"]] = ordered_current[index]
                else:
                    raise RecoveryError(
                        f"wallet {wallet_id!r} metadata shares are inconsistent"
                    )
        else:
            raise RecoveryError(
                f"wallet {wallet_id!r} metadata is malformed"
            )

        # 各已激活轮换在用时的份额公钥（prepared 未激活的暂存份额绝不能
        # 成为重验依据）
        previous_pubkeys: set[str] = set()
        for rotation in rotations:
            rid = rotation.get("rotation_id")
            rids = rotation.get("share_ids")
            pub_hex = rotation.get("public_key")
            if (
                not isinstance(rid, str)
                or not isinstance(rids, list)
                or len(rids) != 2
                or not all(isinstance(sid, str) for sid in rids)
                or not isinstance(pub_hex, str)
            ):
                raise RecoveryError(
                    f"wallet {wallet_id!r} rotation record {rid!r} is malformed"
                )
            if rotation.get("state") != "active":
                # prepared/activating（未提交激活）的份额绝不能成为重验依据
                continue
            rotation_pubkeys.add(pub_hex)
            previous = rotation.get("previous_public_key")
            if isinstance(previous, str):
                previous_pubkeys.add(previous)
            first, second = halves(
                pub_hex, f"rotation {rid!r} public_key"
            )
            public.setdefault(rids[0], first)
            public.setdefault(rids[1], second)

        # 创世旧公钥：previous 链顶端（不等于任何轮换在用公钥）
        genesis_candidates = previous_pubkeys - rotation_pubkeys - {
            current_meta["public_key"]
        }
        if len(genesis_candidates) == 1:
            genesis = next(iter(genesis_candidates))
            first, second = halves(genesis, "genesis previous public_key")
            public.setdefault("share-1", first)
            public.setdefault("share-2", second)
        elif genesis_candidates:
            raise RecoveryError(
                f"wallet {wallet_id!r} has ambiguous rotation history"
            )

        # 会话参与者替换份额（<replacement_id>-share）：公钥的权威来源是
        # 其份额文件（shares/<wallet_id>/<share_id>.json），并做完整密码学
        # 自洽校验；缺失/损坏/矛盾一律 fail-closed。
        for sid in share_ids:
            if sid not in public and REPLACEMENT_SHARE_ID_RE.match(sid):
                public[sid] = self._validated_replacement_share(
                    wallet_id, sid
                )["public_key"]

        absent = [sid for sid in share_ids if sid not in public]
        if absent:
            raise RecoveryError(
                f"wallet {wallet_id!r} sign session references shares "
                f"{absent!r} with no resolvable public key"
            )
        return {sid: public[sid] for sid in share_ids}

    def _validated_replacement_share(
        self, wallet_id: str, share_id: str
    ) -> dict:
        """读取并严格校验一份会话参与者替换份额（调用方须持钱包事务锁）。

        份额文件必须恰含 private_key/public_key/share_id 三键，share_id
        与文件名一致，两个 hex 值均为 64 位小写（32 字节），且私钥能推出
        记录的公钥。文件缺失、损坏或任何一项不符都抛 RecoveryError
        （fail-closed，保留现场），绝不猜写密钥。"""
        try:
            share = self._store.get_share(wallet_id, share_id)
        except ValueError as exc:
            raise RecoveryError(
                f"wallet {wallet_id!r} replacement share {share_id!r} is "
                "unreadable"
            ) from exc
        if (
            not isinstance(share, dict)
            or set(share) != {"private_key", "public_key", "share_id"}
            or share.get("share_id") != share_id
        ):
            raise RecoveryError(
                f"wallet {wallet_id!r} replacement share {share_id!r} is "
                "malformed"
            )
        public_hex = share["public_key"]
        private_hex = share["private_key"]
        if not (
            _is_lower_hex_32(public_hex) and _is_lower_hex_32(private_hex)
        ):
            raise RecoveryError(
                f"wallet {wallet_id!r} replacement share {share_id!r} has "
                "malformed key material"
            )
        public_bytes = bytes.fromhex(public_hex)
        private_bytes = bytes.fromhex(private_hex)
        try:
            derived = crypto.public_key_from_private(private_bytes)
        except (ValueError, TypeError) as exc:
            raise RecoveryError(
                f"wallet {wallet_id!r} replacement share {share_id!r} has "
                "an invalid private key"
            ) from exc
        if derived != public_bytes:
            raise RecoveryError(
                f"wallet {wallet_id!r} replacement share {share_id!r} "
                "private/public key mismatch"
            )
        return share

    @staticmethod
    def _session_expires_at(record: dict):
        return parse_utc_iso(record["expires_at"])

    def _session_expire_if_needed(
        self, wallet_id: str, record: dict
    ) -> dict:
        """懒过期：collecting 与 ready 会话都受 expires_at 约束。

        到点则原子持久化为 expired 并只记一次 action=expired 的
        session_event；投递路径随后返回 409，终态不再聚合。signed/expired
        不再受到期时间影响。调用方须持钱包事务锁。"""
        if record["state"] not in ("collecting", "ready"):
            return record
        expires_at = self._session_expires_at(record)
        if expires_at is None or datetime.now(timezone.utc) < expires_at:
            return record
        expired = dict(record)
        expired["state"] = "expired"
        expired.pop("aggregate_signature", None)
        self._store.update_sign_session(wallet_id, record["id"], expired)
        try:
            self._emit(
                wallet_id,
                self._audit_event(
                    audit.TYPE_SESSION_EVENT,
                    request_id=record["id"],
                    details={"action": "expired", "state": "expired"},
                ),
            )
        except BaseException:
            # 状态/事件原子：事件未落盘恢复原状态
            self._store.update_sign_session(wallet_id, record["id"], record)
            raise
        return expired

    def create_sign_session(
        self,
        wallet_id: str,
        session_id: object,
        message: object,
        timeout_seconds: object,
    ) -> tuple[int, dict]:
        """创建可恢复签名会话，返回 (状态码, 视图)。

        首建 201；同 id 且 message/timeout_seconds 同参重放 200；同 id
        异参 409；参数非法 400；钱包不存在 404。会话状态与 created 事件在
        每钱包跨进程事务锁内原子持久化，事件追加失败回滚会话记录。
        创建重放不触发懒过期。
        """
        record: dict | None = None
        try:
            with self._wallet_lock(wallet_id):
                self._heal_wallet(wallet_id)
                # 404 优先于 400：钱包存在性在锁内先于参数校验
                wallet = self._get_wallet_or_404(wallet_id)
                self._assert_wallet_active_locked(wallet_id)
                self._validate_session_id(session_id)
                self._validate_session_message(message)
                self._validate_session_timeout(timeout_seconds)
                existing = self._store.get_sign_session(wallet_id, session_id)
                if existing is not None:
                    # 重放前先自愈"会话记录已落盘但 created 事件未落盘"的
                    # 他进程创建崩溃残留：按未提交处理，删除后走首次创建。
                    if self._audit.find_session_event(
                        wallet_id, session_id, "created"
                    ) is None:
                        self._store.delete_sign_session(wallet_id, session_id)
                    else:
                        # 同参（message 与 timeout_seconds）重放 200；异参 409。
                        # 原样返回磁盘状态，重放不触发懒过期、不记事件。
                        if (
                            existing["message"] != message
                            or existing["timeout_seconds"] != timeout_seconds
                        ):
                            raise ServiceError(
                                409,
                                f"sign session {session_id!r} already exists "
                                "with different parameters",
                            )
                        return 200, self._session_view(existing)
                now = datetime.now(timezone.utc)
                share_ids = [s["share_id"] for s in wallet["shares"]]
                record = {
                    "id": session_id,
                    "message": message,
                    "timeout_seconds": timeout_seconds,
                    "created_at": now.isoformat().replace("+00:00", "Z"),
                    "expires_at": (
                        now + timedelta(seconds=timeout_seconds)
                    )
                    .isoformat()
                    .replace("+00:00", "Z"),
                    "state": "collecting",
                    "share_ids": share_ids,
                    "shares": [],
                }
                self._store.create_sign_session(wallet_id, session_id, record)
                try:
                    self._emit(
                        wallet_id,
                        self._audit_event(
                            audit.TYPE_SESSION_EVENT,
                            request_id=session_id,
                            details={
                                "action": "created",
                                "message": message,
                                "timeout_seconds": timeout_seconds,
                            },
                        ),
                    )
                except BaseException:
                    self._store.delete_sign_session(wallet_id, session_id)
                    raise
        except CorruptDataError:
            raise
        except ValueError:
            # wallet_id 含非法字符（构造锁路径时抛出）
            raise ServiceError(400, "invalid wallet_id")
        return 201, self._session_view(record)

    def get_sign_session(self, wallet_id: str, session_id: str) -> dict:
        """查询会话视图；未知 404。查询时对到点 collecting/ready 会话懒过期。"""
        try:
            with self._wallet_lock(wallet_id):
                self._heal_wallet(wallet_id)
                # 404 优先于 400
                self._get_wallet_or_404(wallet_id)
                self._validate_session_id(session_id)
                record = self._store.get_sign_session(wallet_id, session_id)
                if record is None:
                    raise ServiceError(
                        404, f"sign session {session_id!r} not found"
                    )
                # 冻结期间查询仍可用但不允许任何写入：跳过懒过期（不记
                # session_event expired），按磁盘现状返回，解冻后再到期。
                if (
                    self._security_state_locked(wallet_id)["state"]
                    != WALLET_STATE_FROZEN
                ):
                    record = self._session_expire_if_needed(
                        wallet_id, record
                    )
                return self._session_view(record)
        except CorruptDataError:
            raise
        except ValueError:
            raise ServiceError(400, "invalid wallet_id")

    @staticmethod
    def _session_shares_map(record: dict) -> dict[str, bytes]:
        return {
            entry["share_id"]: bytes.fromhex(entry["signature"])
            for entry in record["shares"]
        }

    @staticmethod
    def _aggregate_session_shares(record: dict) -> bytes:
        """按会话记录的 share_ids 顺序拼接两份已存份额签名（128 字节）。"""
        received = {
            entry["share_id"]: bytes.fromhex(entry["signature"])
            for entry in record["shares"]
        }
        return crypto.combine_signatures(
            [received[sid] for sid in record["share_ids"]]
        )

    def _commit_session_signed(
        self,
        wallet_id: str,
        ready_record: dict,
    ) -> dict:
        """ready 会话聚合提交：转 signed 并原子记 action=signed 事件。

        审批/hot-cold 门控由调用方在只读校验中完成；本方法只负责会话状态
        与唯一 signed 事件的原子落盘。任一写入失败，以 signed 事件是否真正
        落盘为唯一判据：事件在则前滚补齐为唯一 signed；事件不在则回滚为
        ready（两份份额保留，可重试），并向上抛出。"""
        aggregate = self._aggregate_session_shares(ready_record)
        signed_record = dict(ready_record)
        signed_record["state"] = "signed"
        signed_record["aggregate_signature"] = aggregate.hex()
        try:
            self._store.update_sign_session(
                wallet_id, ready_record["id"], signed_record
            )
            self._emit(
                wallet_id,
                self._audit_event(
                    audit.TYPE_SESSION_EVENT,
                    request_id=ready_record["id"],
                    details={"action": "signed", "state": "signed"},
                ),
            )
        except BaseException:
            landed = self._audit.find_session_event(
                wallet_id, ready_record["id"], "signed"
            )
            if landed is not None:
                # 事件已落盘：前滚补齐，绝不回滚、不重复记事件
                self._store.update_sign_session(
                    wallet_id, ready_record["id"], signed_record
                )
                return signed_record
            self._store.update_sign_session(
                wallet_id, ready_record["id"], ready_record
            )
            raise
        return signed_record

    def submit_sign_session_share(
        self,
        wallet_id: str,
        session_id: str,
        share_id: object,
        signature_hex: object,
        node: object = _NO_NODE,
    ) -> tuple[int, dict]:
        """向会话投递一份额签名，返回 (状态码, 视图)。

        - 首收 201；同份额同值重放 200、异值 409；签名非法/份额已因轮换
          失效或不属于当前在用快照 400；
        - 未知会话 404；expired（含投递时懒过期，collecting 与 ready 均可
          到期）409；
        - 两份齐备转 ready，按既有审批及 hot/cold 门控聚合；门控失败 409
          并保留 ready 供重试（重放在用份额即重试门控）；成功转 signed；
        - 轮换激活后，collecting/ready 会话改用钱包当前两份在用份额：
          已收旧份额在持锁恢复中被剔除，视图只反映当前快照，新份额可继续
          投递；signed 会话冻结创建时快照与聚合结果。
        - 钱包存在已激活的份额槽位绑定（share_participant_reinstated）后，
          仅**被绑定的当前在用份额**受额外约束：其请求体必须恰含
          node/share_id/signature 且 node 与绑定的复职节点一致（node 缺失
          /类型错 400、不一致 409）；未绑定份额体恰含 share_id/signature，
          夹带 node 一律 400；/sign 与 share-sign 不变。
        """
        try:
            return self._submit_sign_session_share_tx(
                wallet_id, session_id, share_id, signature_hex, node
            )
        except CorruptDataError:
            raise
        except ValueError:
            # wallet_id 含非法字符（构造锁路径时抛出）
            raise ServiceError(400, "invalid wallet_id")

    def _submit_sign_session_share_tx(
        self,
        wallet_id: str,
        session_id: str,
        share_id: object,
        signature_hex: object,
        node: object = _NO_NODE,
    ) -> tuple[int, dict]:
        with self._wallet_lock(wallet_id):
            self._heal_wallet(wallet_id)
            # 404 优先于 400：锁内先判定钱包存在性
            wallet = self._store.get_wallet(wallet_id)
            if wallet is None:
                raise ServiceError(404, f"wallet {wallet_id!r} not found")
            self._assert_wallet_active_locked(wallet_id)
            self._validate_session_id(session_id)
            record = self._store.get_sign_session(wallet_id, session_id)
            if record is None:
                raise ServiceError(
                    404, f"sign session {session_id!r} not found"
                )
            # 投递时懒过期：collecting/ready 到点原子转 expired（仅一次事件）
            record = self._session_expire_if_needed(wallet_id, record)
            if record["state"] == "expired":
                # 状态判定优先于载荷校验：已过期一律 409（含畸形载荷）
                raise ServiceError(
                    409, f"sign session {session_id!r} has expired"
                )
            if record["state"] == "cancelled":
                # 已撤销是终态：任何投递（含已收份额重放）一律 409，
                # 状态判定优先于载荷校验
                raise ServiceError(
                    409, f"sign session {session_id!r} has been cancelled"
                )
            state = record["state"]

            # 会话存在且未过期后再校验载荷：share_id 非空、signature 为
            # 64 字节 hex，非法 400
            if not isinstance(share_id, str) or not share_id:
                raise ServiceError(
                    400, "share_id must be a non-empty string"
                )
            signature = self._validate_share_signature(signature_hex)

            # collecting/ready 已在 heal 中完成轮换迁移：record.share_ids
            # 即钱包当前在用份额；signed 冻结创建时快照。
            share_pub = {
                s["share_id"]: s["public_key"] for s in wallet["shares"]
            }
            session_ids = list(record["share_ids"])
            # 会话参与者替换份额（<replacement_id>-share）不在钱包元数据
            # 中：其公钥从份额文件解析（heal 已按替换事件对账，缺失/损坏/
            # 矛盾在此 fail-closed 为 503）。
            for sid in session_ids:
                if sid not in share_pub and REPLACEMENT_SHARE_ID_RE.match(
                    sid
                ):
                    share_pub[sid] = self._validated_replacement_share(
                        wallet_id, sid
                    )["public_key"]

            # 已激活的份额槽位绑定（share_participant_reinstated）只约束
            # **被绑定份额**：投递该份额时请求体必须恰含 node 且与绑定的
            # 复职节点一致。node 缺失/类型错为载荷错误 400；不一致为冲突
            # 409。绑定随份额身份存在（份额 id 全局唯一），故冻结了被绑定
            # 份额的 signed 会话在后续轮换后重放仍须三键体。未绑定份额不得
            # 夹带 node（键集错 400）。
            bound = self._share_binding_for_share_locked(wallet_id, share_id)
            if bound is not None:
                if node is self._NO_NODE or not isinstance(node, str) or not node:
                    raise ServiceError(
                        400,
                        "body must contain exactly node, share_id and "
                        "signature for a bound share",
                    )
                if node != bound["node"]:
                    raise ServiceError(
                        409,
                        f"share {share_id!r} is bound to a different node",
                    )
            elif node is not self._NO_NODE:
                raise ServiceError(
                    400, "body must contain exactly share_id and signature"
                )
            received = self._session_shares_map(record)

            # 已收份额的重放分支必须先于"在用份额"判定：signed 会话冻结
            # 旧快照，轮换后旧份额同值重放仍 200 同体，与既有 /sign 的
            # "已首签请求重放不受轮换影响"一致。
            if share_id in received:
                if signature != received[share_id]:
                    raise ServiceError(
                        409,
                        f"share {share_id!r} was already submitted with a "
                        "different signature",
                    )
                if state == "ready":
                    # ready 上重放在用份额即重试门控/聚合；signed 成功 200，
                    # 门控失败 409（ready 保留）。聚合只拼接收齐时已校验的
                    # 存量份额。
                    return self._retry_session_aggregation(wallet_id, record)
                # collecting 重复投递 / signed 重放：200 同体，不记事件
                return 200, self._session_view(record)

            # 未收过的新份额：collecting/ready 仅接受当前在用快照中的份额；
            # 轮换后失效旧份额与不属于本会话快照的份额一律 400。signed 为
            # 终态，其两份份额必在 received 中，故走到这里的必为非法份额。
            if share_id not in session_ids or share_id not in share_pub:
                raise ServiceError(
                    400, f"unknown or inactive share_id {share_id!r}"
                )

            # 新份额：必须是在用份额私钥对 id 与 message 直接拼接载荷的
            # 有效 Ed25519 签名
            payload = crypto.build_payload(session_id, record["message"])
            if not crypto.verify_share(
                bytes.fromhex(share_pub[share_id]), payload, signature
            ):
                raise ServiceError(
                    400, f"signature verification failed for {share_id}"
                )

            new_shares = list(record["shares"]) + [
                {"share_id": share_id, "signature": signature.hex()}
            ]
            completes = len(new_shares) == 2
            updated = dict(record)
            updated["shares"] = new_shares
            updated["state"] = "ready" if completes else "collecting"
            # 提交点 1：份额落盘（齐备时转 ready）+ share_received 事件原子
            self._store.update_sign_session(wallet_id, session_id, updated)
            try:
                self._emit(
                    wallet_id,
                    self._audit_event(
                        audit.TYPE_SESSION_EVENT,
                        request_id=session_id,
                        details={
                            "action": "share_received",
                            "share_id": share_id,
                            "state": updated["state"],
                        },
                    ),
                )
            except BaseException:
                self._store.update_sign_session(
                    wallet_id, session_id, record
                )
                raise
            record = updated

            if not completes:
                return 201, self._session_view(record)

            # 两份齐备：按既有审批及 hot/cold 门控聚合。门控失败 409 且
            # 保留 ready 供重试（可能原子懒过期审批单）。会话聚合只读取
            # 门控结果，不改动审批单状态（签名对象是会话本身）。
            try:
                self._signing_approval_gate(
                    wallet_id, session_id, record["message"]
                )
            except ServiceError:
                return 409, self._session_view(record)
            signed_record = self._commit_session_signed(wallet_id, record)
            return 201, self._session_view(signed_record)

    def _retry_session_aggregation(
        self, wallet_id: str, record: dict
    ) -> tuple[int, dict]:
        """ready 会话重试门控与聚合（重放在用份额触发）。

        门控失败 409、ready 保留；成功转 signed 返回 200（非首次收份额，
        故不是 201），signed 事件只在首次聚合成功时记一次。ready 到点已在
        投递入口原子转 expired（409），终态不会进入本方法。"""
        try:
            self._signing_approval_gate(
                wallet_id, record["id"], record["message"]
            )
        except ServiceError:
            return 409, self._session_view(record)
        signed_record = self._commit_session_signed(wallet_id, record)
        return 200, self._session_view(signed_record)

    # -- 会话主动撤销 ------------------------------------------------------

    @staticmethod
    def _validate_cancel_reason(reason: object) -> str:
        """撤销请求体 reason：1..1024 字符非空白字符串，原文保留。
        非法抛 ServiceError(400)。"""
        if not isinstance(reason, str) or isinstance(reason, bool):
            raise ServiceError(400, "reason must be a string")
        if len(reason) < 1 or len(reason) > MAX_REASON_LENGTH:
            raise ServiceError(
                400,
                f"reason must be 1 to {MAX_REASON_LENGTH} characters long",
            )
        if not reason.strip():
            raise ServiceError(400, "reason must be non-blank")
        return reason

    @staticmethod
    def _validate_session_cancel_reason(reason: object) -> str:
        """会话撤销请求体 reason：与轮换撤销同一契约（1..1024 字符非空白
        字符串，原文保留）。非法抛 ServiceError(400)。"""
        return WalletService._validate_cancel_reason(reason)

    def cancel_sign_session(
        self,
        wallet_id: str,
        session_id: object,
        cancel_id: object,
        reason: object,
    ) -> tuple[int, dict]:
        """主动撤销签名会话，返回 (状态码, 视图)。

        - 钱包/会话未知 404；冻结钱包一律 409（含重放）且零副作用；
        - cancel_id 须匹配安全标识、reason 须为 1..1024 字符非空白字符串
          （原文保留），非法 400；
        - 仅未到期的 collecting/ready 可首次撤销：成功 201 并原子转
          cancelled，记录携带恰含 cancel_id/reason 的 cancellation 快照；
          signed/expired（含撤销时懒过期）409；
        - cancelled 为终态：已收/缺失份额快照冻结于撤销时刻，后续轮换
          不再迁移；视图不出现聚合签名；
        - cancel_id 只在同钱包的会话撤销之间判重：同会话同标识同原因
          重放 200 同体（不再检查期限、不记事件）；异参、复用到其他会话
          或对已撤销会话以新标识再撤销均 409；
        - session_event（action=cancelled）是唯一提交点：事件未落盘则
          回滚记录，落盘（含异常但已落盘）则前滚补齐；重放不追加事件。
        """
        record: dict | None = None
        try:
            with self._wallet_lock(wallet_id):
                self._heal_wallet(wallet_id)
                # 404 优先于 400：锁内先判定钱包存在性
                if self._store.get_wallet(wallet_id) is None:
                    raise ServiceError(404, f"wallet {wallet_id!r} not found")
                self._assert_wallet_active_locked(wallet_id)
                self._validate_session_id(session_id)
                if not isinstance(
                    cancel_id, str
                ) or not ROTATION_ID_RE.match(cancel_id):
                    raise ServiceError(
                        400, "cancel_id must match [A-Za-z0-9_-]{1,128}"
                    )
                reason = self._validate_session_cancel_reason(reason)
                record = self._store.get_sign_session(wallet_id, session_id)
                if record is None:
                    raise ServiceError(
                        404, f"sign session {session_id!r} not found"
                    )
                # 已提交重放优先于一切状态/期限判定：cancelled 事件是唯一
                # 提交点；cancel_id 只在同钱包的会话撤销之间判重。
                own_event = None
                for sid, events in self._audit.session_events(
                    wallet_id
                ).items():
                    for event in events:
                        details = event.get("details")
                        if (
                            not isinstance(details, dict)
                            or details.get("action") != "cancelled"
                            or details.get("cancel_id") != cancel_id
                        ):
                            continue
                        if sid != session_id:
                            raise ServiceError(
                                409,
                                f"cancel {cancel_id!r} is already in use",
                            )
                        own_event = event
                if own_event is not None:
                    if own_event["details"].get("reason") != reason:
                        raise ServiceError(
                            409,
                            f"cancel {cancel_id!r} was committed with "
                            "different parameters",
                        )
                    # 同会话同标识同原因重放：200 同体，不再检查期限、
                    # 不追加事件
                    return 200, self._session_view(record)
                # 懒过期：collecting/ready 到点原子转 expired（仅一次事件）
                record = self._session_expire_if_needed(wallet_id, record)
                if record["state"] == "expired":
                    raise ServiceError(
                        409, f"sign session {session_id!r} has expired"
                    )
                if record["state"] == "cancelled":
                    # 已以其他标识撤销：再次以新标识撤销一律 409
                    raise ServiceError(
                        409,
                        f"sign session {session_id!r} has been cancelled",
                    )
                if record["state"] not in ("collecting", "ready"):
                    raise ServiceError(
                        409,
                        f"sign session {session_id!r} is not collecting "
                        "or ready",
                    )
                cancelled = dict(record)
                cancelled["state"] = "cancelled"
                cancelled["cancellation"] = {
                    "cancel_id": cancel_id,
                    "reason": reason,
                }
                # 提交点：状态落盘 + cancelled 事件原子。任一写入失败以
                # 事件是否真正落盘为唯一判据：事件在则前滚补齐为唯一
                # cancelled；事件不在则回滚为撤销前状态并向上抛出。
                self._store.update_sign_session(
                    wallet_id, session_id, cancelled
                )
                try:
                    self._emit(
                        wallet_id,
                        self._audit_event(
                            audit.TYPE_SESSION_EVENT,
                            request_id=session_id,
                            details={
                                "action": "cancelled",
                                "cancel_id": cancel_id,
                                "reason": reason,
                                "state": "cancelled",
                            },
                        ),
                    )
                except BaseException:
                    landed = self._audit.find_session_event(
                        wallet_id, session_id, "cancelled"
                    )
                    if landed is not None:
                        # 事件已落盘：前滚补齐，绝不回滚、不重复记事件
                        self._store.update_sign_session(
                            wallet_id, session_id, cancelled
                        )
                        return 201, self._session_view(cancelled)
                    self._store.update_sign_session(
                        wallet_id, session_id, record
                    )
                    raise
                record = cancelled
        except CorruptDataError:
            raise
        except ValueError:
            # wallet_id 含非法字符（构造锁路径时抛出）
            raise ServiceError(400, "invalid wallet_id")
        return 201, self._session_view(record)

    # -- 会话单节点参与者替换 ----------------------------------------------

    def _find_replacement_event(
        self, wallet_id: str, session_id: str, new_share_id: str
    ) -> dict | None:
        """查找某会话已提交的、生成指定新份额的替换事件（纯只读）。"""
        events = self._audit.session_participant_replaced_events(wallet_id)
        for event in events.get(session_id, []):
            details = event.get("details")
            if (
                isinstance(details, dict)
                and details.get("new_share_id") == new_share_id
            ):
                return event
        return None

    def replace_sign_session_participant(
        self,
        wallet_id: str,
        session_id: object,
        replacement_id: object,
        offline_share_id: object,
    ) -> tuple[int, dict]:
        """替换签名会话的单个参与方份额，返回 (状态码, 会话视图)。

        - 钱包/会话未知 404；replacement_id/offline_share_id 非法 400；
        - 会话非 collecting/ready（含到期懒过期）、目标不是该会话当前在
          用份额 409；
        - 生成 <replacement_id>-share 新 Ed25519 份额替换原槽位：移除旧
          份额已投递签名、保留另一份；旧份额再投递 400，新份额按既有
          Ed25519 校验与审批/hot-cold 门控投递；
        - 首次替换 201；同 replacement_id 同参重放 200、异参 409；
          replacement_id 被其他会话占用 409；已提交重放优先于状态判定；
        - session_participant_replaced 事件为唯一提交点：事件未落盘则
          回滚并删除新份额文件，落盘则前滚迁移会话记录。
        """
        try:
            with self._wallet_lock(wallet_id):
                self._heal_wallet(wallet_id)
                # 404 优先于 400：锁内先判定钱包存在性
                wallet = self._store.get_wallet(wallet_id)
                if wallet is None:
                    raise ServiceError(404, f"wallet {wallet_id!r} not found")
                self._assert_wallet_active_locked(wallet_id)
                self._validate_session_id(session_id)
                if not isinstance(
                    replacement_id, str
                ) or not ROTATION_ID_RE.match(replacement_id):
                    raise ServiceError(
                        400, "replacement_id must match [A-Za-z0-9_-]{1,128}"
                    )
                if not isinstance(
                    offline_share_id, str
                ) or not ROTATION_ID_RE.match(offline_share_id):
                    raise ServiceError(
                        400, "offline_share_id must match [A-Za-z0-9_-]{1,128}"
                    )
                record = self._store.get_sign_session(wallet_id, session_id)
                if record is None:
                    raise ServiceError(
                        404, f"sign session {session_id!r} not found"
                    )
                new_share_id = f"{replacement_id}-share"
                # 已提交重放优先：替换事件是唯一提交点。同 id 同参 200、
                # 异参 409；被其他会话占用 409。
                committed = self._audit.session_participant_replaced_events(
                    wallet_id
                )
                own_event = None
                for sid, events in committed.items():
                    for event in events:
                        details = event.get("details")
                        if (
                            not isinstance(details, dict)
                            or details.get("new_share_id") != new_share_id
                        ):
                            continue
                        if sid == session_id:
                            own_event = event
                        else:
                            raise ServiceError(
                                409,
                                f"replacement {replacement_id!r} is already "
                                "in use",
                            )
                if own_event is not None:
                    if own_event["details"].get(
                        "old_share_id"
                    ) != offline_share_id:
                        raise ServiceError(
                            409,
                            f"replacement {replacement_id!r} was committed "
                            "with different parameters",
                        )
                    # 同参重放：原样返回磁盘视图，不触发懒过期、不记事件
                    return 200, self._session_view(record)
                # 懒过期：collecting/ready 到点原子转 expired（仅一次事件）
                record = self._session_expire_if_needed(wallet_id, record)
                if record["state"] == "expired":
                    raise ServiceError(
                        409, f"sign session {session_id!r} has expired"
                    )
                if record["state"] not in ("collecting", "ready"):
                    raise ServiceError(
                        409,
                        f"sign session {session_id!r} is not collecting "
                        "or ready",
                    )
                current_ids = list(record["share_ids"])
                if offline_share_id not in current_ids:
                    raise ServiceError(
                        409,
                        f"share {offline_share_id!r} is not an in-use share "
                        f"of sign session {session_id!r}",
                    )
                if (
                    self._store.get_share(wallet_id, new_share_id)
                    is not None
                ):
                    # 无提交事件的份额文件残留应由持锁自愈清理；仍存在即
                    # 占用/矛盾，绝不覆盖来路不明的私钥。
                    raise ServiceError(
                        409,
                        f"replacement {replacement_id!r} is already in use",
                    )
                # 生成新份额：仅该份额自己的私钥落盘（shares/<W>/<新id>.json，
                # 恰含 private_key/public_key/share_id，64 位小写 hex），
                # 系统中不存在完整私钥。
                key = crypto.generate_share_key(new_share_id)
                self._store.save_share(
                    wallet_id,
                    {
                        "share_id": new_share_id,
                        "public_key": key.public_bytes.hex(),
                        "private_key": key.private_bytes.hex(),
                    },
                )
                # 提交点：session_participant_replaced 事件。事件未落盘则
                # 回滚并删除新份额文件；落盘（含异常但已落盘）则前滚迁移。
                try:
                    self._emit(
                        wallet_id,
                        self._audit_event(
                            audit.TYPE_SESSION_PARTICIPANT_REPLACED,
                            request_id=session_id,
                            details={
                                "session_id": session_id,
                                "old_share_id": offline_share_id,
                                "new_share_id": new_share_id,
                            },
                        ),
                    )
                except BaseException:
                    landed = self._find_replacement_event(
                        wallet_id, session_id, new_share_id
                    )
                    if landed is None:
                        self._store.delete_share(wallet_id, new_share_id)
                        raise
                # 事件已落盘：前滚迁移会话记录——新份额替换原槽位、移除旧
                # 份额已投递签名、保留另一份；份数不足两份回到 collecting。
                migrated = self._migrate_session_participant(
                    record, offline_share_id, new_share_id
                )
                self._store.update_sign_session(
                    wallet_id, session_id, migrated
                )
                return 201, self._session_view(migrated)
        except CorruptDataError:
            raise
        except ValueError:
            # wallet_id 含非法字符（构造锁路径时抛出）
            raise ServiceError(400, "invalid wallet_id")

    # -- 会话两阶段参与者接管 ----------------------------------------------

    @staticmethod
    def _takeover_stage_share_id(takeover_id: str, stage: int) -> str:
        return f"{takeover_id}-{stage}-share"

    @staticmethod
    def _validate_takeover_stage(stage: object) -> None:
        # bool 是 int 的子类，必须先排除；stage 只能是整数 1 或 2
        if (
            not isinstance(stage, int)
            or isinstance(stage, bool)
            or stage not in TAKEOVER_STAGES
        ):
            raise ServiceError(400, "stage must be the integer 1 or 2")

    def takeover_sign_session_participant(
        self,
        wallet_id: str,
        session_id: object,
        takeover_id: object,
        stage: object,
        offline_share_id: object,
    ) -> tuple[int, dict]:
        """两阶段接管签名会话的两个参与方份额，返回 (状态码, 会话视图)。

        请求体恰含 ``takeover_id/stage/offline_share_id``：stage 必须从 1
        起按序提交，两阶段替换会话的**不同槽位**，分别生成
        ``<takeover_id>-1-share``、``<takeover_id>-2-share``。其余迁移、
        私钥落盘边界与单节点替换一致。

        - takeover_id/offline_share_id 非法、stage 非（非布尔）整数 1/2：
          400；钱包/会话未知 404；
        - 阶段首提 201；同阶段同参重放 200 当前视图；异参、跳号（stage 2
          无已提交 stage 1）、终态/到期、offline_share_id 非当前在用份额、
          两阶段命中同一槽位、takeover_id 被其他会话占用或新份额 id 已被
          替换/接管占用：409；已提交重放优先于一切状态判定；
        - session_takeover 事件为唯一提交点（request_id=会话 id，
          actor_id/reason=null，details 恰含
          {takeover_id,stage,old_share_id,new_share_id}）：事件落盘前
          崩溃回滚删新份额，落盘后前滚迁移会话记录。
        """
        try:
            with self._wallet_lock(wallet_id):
                self._heal_wallet(wallet_id)
                # 404 优先于 400：锁内先判定钱包存在性
                wallet = self._store.get_wallet(wallet_id)
                if wallet is None:
                    raise ServiceError(404, f"wallet {wallet_id!r} not found")
                self._assert_wallet_active_locked(wallet_id)
                self._validate_session_id(session_id)
                if not isinstance(
                    takeover_id, str
                ) or not ROTATION_ID_RE.match(takeover_id):
                    raise ServiceError(
                        400, "takeover_id must match [A-Za-z0-9_-]{1,128}"
                    )
                self._validate_takeover_stage(stage)
                if not isinstance(
                    offline_share_id, str
                ) or not ROTATION_ID_RE.match(offline_share_id):
                    raise ServiceError(
                        400, "offline_share_id must match [A-Za-z0-9_-]{1,128}"
                    )
                record = self._store.get_sign_session(wallet_id, session_id)
                if record is None:
                    raise ServiceError(
                        404, f"sign session {session_id!r} not found"
                    )
                new_share_id = self._takeover_stage_share_id(
                    takeover_id, stage
                )
                stage1_share_id = self._takeover_stage_share_id(
                    takeover_id, 1
                )
                # 已提交重放优先：接管事件是唯一提交点。同会话同阶段同参
                # 200、异参 409；同 takeover_id 被其他会话占用 409。
                takeover_events = self._audit.session_takeover_events(
                    wallet_id
                )
                committed_replacements = (
                    self._audit.session_participant_replaced_events(wallet_id)
                )
                own_event = None
                own_stage1_event = None
                for sid, events in takeover_events.items():
                    for event in events:
                        details = event.get("details")
                        if not isinstance(details, dict):
                            continue
                        committed_new = details.get("new_share_id")
                        committed_takeover = details.get("takeover_id")
                        if committed_new == new_share_id:
                            if sid == session_id:
                                own_event = event
                            else:
                                raise ServiceError(
                                    409,
                                    f"takeover {takeover_id!r} is already "
                                    "in use",
                                )
                        if (
                            committed_takeover == takeover_id
                            and sid != session_id
                        ):
                            # 同接管的另一阶段也占用该 takeover_id
                            raise ServiceError(
                                409,
                                f"takeover {takeover_id!r} is already in use",
                            )
                        if (
                            sid == session_id
                            and committed_new == stage1_share_id
                        ):
                            own_stage1_event = event
                # 替换事件同样占用新份额 id 命名空间（replacement_id
                # "<id>-<stage>" 的替换份额恰为 <id>-<stage>-share）
                for sid, events in committed_replacements.items():
                    for event in events:
                        details = event.get("details")
                        if (
                            isinstance(details, dict)
                            and details.get("new_share_id") == new_share_id
                        ):
                            raise ServiceError(
                                409,
                                f"share {new_share_id!r} is already in use",
                            )
                if own_event is not None:
                    if own_event["details"].get(
                        "old_share_id"
                    ) != offline_share_id:
                        raise ServiceError(
                            409,
                            f"takeover {takeover_id!r} stage {stage} was "
                            "committed with different parameters",
                        )
                    # 同阶段同参重放：原样返回磁盘视图，不触发懒过期、
                    # 不记事件（优先于终态/到期判定）
                    return 200, self._session_view(record)
                # 懒过期：collecting/ready 到点原子转 expired（仅一次事件）
                record = self._session_expire_if_needed(wallet_id, record)
                if record["state"] == "expired":
                    raise ServiceError(
                        409, f"sign session {session_id!r} has expired"
                    )
                if record["state"] not in ("collecting", "ready"):
                    raise ServiceError(
                        409,
                        f"sign session {session_id!r} is not collecting "
                        "or ready",
                    )
                # stage 必须从 1 起按序提交：stage 2 必须存在同 takeover_id
                # 的已提交 stage 1（跳号 409）。两阶段必须替换不同槽位
                # （槽位按有序位置追踪，见下方 current_ids 计算）。
                if stage == 2 and own_stage1_event is None:
                    raise ServiceError(
                        409,
                        f"takeover {takeover_id!r} stage 1 must be "
                        "committed before stage 2",
                    )
                current_ids = list(record["share_ids"])
                if offline_share_id not in current_ids:
                    raise ServiceError(
                        409,
                        f"share {offline_share_id!r} is not an in-use share "
                        f"of sign session {session_id!r}",
                    )
                if stage == 2:
                    # 归并本会话全部已提交换槽事件（含 stage 1 及期间可能
                    # 穿插的普通替换），按位置判定 stage 2 是否命中 stage 1
                    # 已替换的同一物理槽位。
                    merged_cuts = sorted(
                        list(
                            committed_replacements.get(session_id, [])
                        )
                        + list(takeover_events.get(session_id, [])),
                        key=lambda event: event.get("seq", 0),
                    )
                    boundary_sets = self._participant_cut_chain(
                        merged_cuts, current_ids
                    )
                    stage1_index = next(
                        index
                        for index, event in enumerate(merged_cuts)
                        if event is own_stage1_event
                    )
                    stage1_old = own_stage1_event["details"]["old_share_id"]
                    before_stage1 = boundary_sets[stage1_index]
                    if stage1_old not in before_stage1:
                        # 持锁自愈已按事件序列对账，正常不可达；矛盾现场
                        # 绝不静默继续（fail-closed）
                        raise RecoveryError(
                            f"wallet {wallet_id!r} sign session "
                            f"{session_id!r} takeover {takeover_id!r} "
                            "stage 1 slot cannot be reconciled"
                        )
                    stage1_slot = before_stage1.index(stage1_old)
                    if current_ids.index(offline_share_id) == stage1_slot:
                        raise ServiceError(
                            409,
                            "takeover stage 2 must replace a different slot",
                        )
                if (
                    self._store.get_share(wallet_id, new_share_id)
                    is not None
                ):
                    # 无提交事件的份额文件残留应由持锁自愈清理；仍存在即
                    # 占用/矛盾，绝不覆盖来路不明的私钥。
                    raise ServiceError(
                        409, f"share {new_share_id!r} is already in use"
                    )
                # 生成新阶段份额：仅该份额自己的私钥落盘
                # （shares/<W>/<takeover_id>-<stage>-share.json，恰含
                # private_key/public_key/share_id，64 位小写 hex），
                # 系统中不存在完整私钥。
                key = crypto.generate_share_key(new_share_id)
                self._store.save_share(
                    wallet_id,
                    {
                        "share_id": new_share_id,
                        "public_key": key.public_bytes.hex(),
                        "private_key": key.private_bytes.hex(),
                    },
                )
                # 提交点：session_takeover 事件。事件未落盘则回滚并删除
                # 新份额文件；落盘（含异常但已落盘）则前滚迁移。
                try:
                    self._emit(
                        wallet_id,
                        self._audit_event(
                            audit.TYPE_SESSION_TAKEOVER,
                            request_id=session_id,
                            details={
                                "takeover_id": takeover_id,
                                "stage": stage,
                                "old_share_id": offline_share_id,
                                "new_share_id": new_share_id,
                            },
                        ),
                    )
                except BaseException:
                    landed = self._find_takeover_event(
                        wallet_id, session_id, new_share_id
                    )
                    if landed is None:
                        self._store.delete_share(wallet_id, new_share_id)
                        raise
                # 事件已落盘：前滚迁移会话记录——新份额替换原槽位、移除
                # 旧份额已投递签名、保留另一份；份数不足两份回到 collecting。
                migrated = self._migrate_session_participant(
                    record, offline_share_id, new_share_id
                )
                self._store.update_sign_session(
                    wallet_id, session_id, migrated
                )
                return 201, self._session_view(migrated)
        except CorruptDataError:
            raise
        except ValueError:
            # wallet_id 含非法字符（构造锁路径时抛出）
            raise ServiceError(400, "invalid wallet_id")

    def _find_takeover_event(
        self, wallet_id: str, session_id: str, new_share_id: str
    ) -> dict | None:
        """查找某会话已提交的、生成指定新份额的接管事件（纯只读）。"""
        for event in self._audit.session_takeover_events(wallet_id).get(
            session_id, []
        ):
            details = event.get("details")
            if (
                isinstance(details, dict)
                and details.get("new_share_id") == new_share_id
            ):
                return event
        return None

    @staticmethod
    def _migrate_session_participant(
        record: dict, offline_share_id: str, new_share_id: str
    ) -> dict:
        """参与者替换/接管提交后的会话前滚：新份额顶替原槽位、剔除旧份额
        已投递签名、保留另一份；不足两份回到 collecting。"""
        current_ids = list(record["share_ids"])
        migrated = dict(record)
        migrated["share_ids"] = [
            new_share_id if sid == offline_share_id else sid
            for sid in current_ids
        ]
        migrated["shares"] = [
            entry
            for entry in record["shares"]
            if entry["share_id"] != offline_share_id
        ]
        migrated["state"] = (
            "ready" if len(migrated["shares"]) == 2 else "collecting"
        )
        migrated.pop("aggregate_signature", None)
        return migrated

    @staticmethod
    def _participant_cut_chain(
        merged_events: list[dict], final_ids: list[str]
    ) -> list[list[str]]:
        """按有序换槽事件（每项 details 含 old/new_share_id）与最终有序
        份额集合，反推后正演出每个换槽边界上的有序份额集合。

        返回长度为 ``len(merged_events)+1`` 的列表：首项为首个换槽之前的
        集合，其后依次为每条事件换槽后的集合，末项即 ``final_ids``。
        槽位按下标追踪，用于判定两次换槽（如接管两阶段）是否命中同一
        物理槽位——即使中间穿插了对该槽的普通替换。"""
        initial = list(final_ids)
        for event in reversed(merged_events):
            details = event["details"]
            initial = [
                details["old_share_id"]
                if sid == details["new_share_id"]
                else sid
                for sid in initial
            ]
        boundary_sets = [initial]
        current = initial
        for event in merged_events:
            details = event["details"]
            current = [
                details["new_share_id"]
                if sid == details["old_share_id"]
                else sid
                for sid in current
            ]
            boundary_sets.append(current)
        return boundary_sets

    # -- 签名会话严格加载与崩溃恢复 ----------------------------------------

    def _rotation_timeline(self, wallet_id: str) -> list[tuple[int, tuple[str, str]]]:
        """返回按 seq 升序的份额轮换激活时间线 [(seq, (share-1, share-2))]。

        恢复据此判定任一审计 seq 时刻"在用两份份额"的快照：首个激活之前
        为创世份额 ("share-1", "share-2")，之后取最近一次激活的 share_ids。
        """
        timeline: list[tuple[int, tuple[str, str]]] = []
        events = self._audit.activated_rotation_events(wallet_id)
        for rotation_id, event in events.items():
            details = event.get("details")
            seq = event.get("seq")
            if not isinstance(details, dict) or not isinstance(seq, int):
                raise RecoveryError(
                    f"wallet {wallet_id!r} rotation activation event for "
                    f"{rotation_id!r} is malformed"
                )
            share_ids = details.get("share_ids")
            if (
                not isinstance(share_ids, list)
                or len(share_ids) != 2
                or not all(isinstance(sid, str) for sid in share_ids)
            ):
                raise RecoveryError(
                    f"wallet {wallet_id!r} rotation activation event for "
                    f"{rotation_id!r} has malformed share_ids"
                )
            timeline.append((seq, (share_ids[0], share_ids[1])))
        timeline.sort(key=lambda item: item[0])
        return timeline

    @staticmethod
    def _active_share_set_at(
        timeline: list[tuple[int, tuple[str, str]]], seq: int
    ) -> tuple[str, str]:
        active = ("share-1", "share-2")
        for activation_seq, share_ids in timeline:
            if activation_seq <= seq:
                active = share_ids
            else:
                break
        return active

    def _validated_replacement_events(
        self, wallet_id: str
    ) -> dict[str, list[dict]]:
        """读取并严格校验该钱包全部 session_participant_replaced 事件。

        每条事件必须：request_id 为会话 id 且与 details.session_id 一致、
        actor_id/reason 为 null、details 恰含
        {session_id, old_share_id, new_share_id} 三键、old/new 为合法
        份额标识且不同、new 形如 <replacement_id>-share 且全钱包唯一
        （同一新份额不得被两条提交事件引用）。任一不符抛 RecoveryError
        （fail-closed），绝不静默跳过或任取一条。"""
        grouped = self._audit.session_participant_replaced_events(wallet_id)
        seen_new: set[str] = set()
        for session_id, events in grouped.items():
            for event in events:
                if (
                    event.get("actor_id") is not None
                    or event.get("reason") is not None
                ):
                    raise RecoveryError(
                        f"wallet {wallet_id!r} sign session {session_id!r} "
                        "has a participant replacement event with "
                        "actor/reason set"
                    )
                details = event.get("details")
                if not isinstance(details, dict) or set(details) != {
                    "session_id",
                    "old_share_id",
                    "new_share_id",
                }:
                    raise RecoveryError(
                        f"wallet {wallet_id!r} sign session {session_id!r} "
                        "has a malformed participant replacement event"
                    )
                if details["session_id"] != session_id:
                    raise RecoveryError(
                        f"wallet {wallet_id!r} participant replacement event "
                        "session_id does not match its request_id"
                    )
                old = details["old_share_id"]
                new = details["new_share_id"]
                if not isinstance(old, str) or not _SAFE_SHARE_ID.match(old):
                    raise RecoveryError(
                        f"wallet {wallet_id!r} sign session {session_id!r} "
                        "replacement event has a malformed old_share_id"
                    )
                if not isinstance(
                    new, str
                ) or not REPLACEMENT_SHARE_ID_RE.match(new):
                    raise RecoveryError(
                        f"wallet {wallet_id!r} sign session {session_id!r} "
                        "replacement event has a malformed new_share_id"
                    )
                if old == new:
                    raise RecoveryError(
                        f"wallet {wallet_id!r} sign session {session_id!r} "
                        "replacement event replaces a share with itself"
                    )
                if new in seen_new:
                    raise RecoveryError(
                        f"wallet {wallet_id!r} replacement share {new!r} is "
                        "committed by more than one event"
                    )
                seen_new.add(new)
        return grouped

    def _validated_takeover_events(
        self, wallet_id: str
    ) -> dict[str, list[dict]]:
        """读取并严格校验该钱包全部 session_takeover 事件。

        每条事件必须：request_id 为会话 id、actor_id/reason 为 null、
        details 恰含 {takeover_id, stage, old_share_id, new_share_id}
        四键、takeover_id 为安全标识、stage 为非布尔整数 1/2、old 为合法
        份额标识、new 恰为 <takeover_id>-<stage>-share、old != new、
        new 全钱包唯一、同一 takeover_id 不跨会话。同一 takeover_id 的
        阶段必须按 seq 从 1 起连续（stage 2 之前必有 stage 1、不重复、
        不跳号）；两阶段必须替换不同物理槽位（按提交时刻有序快照下标
        判定，见 _recover_one_sign_session）。任一不符抛 RecoveryError
        （fail-closed），绝不静默跳过。"""
        grouped = self._audit.session_takeover_events(wallet_id)
        seen_new: set[str] = set()
        seen_takeover_sessions: dict[str, str] = {}
        for session_id, events in grouped.items():
            stages_by_takeover: dict[str, list[dict]] = {}
            for event in events:
                if (
                    event.get("actor_id") is not None
                    or event.get("reason") is not None
                ):
                    raise RecoveryError(
                        f"wallet {wallet_id!r} sign session {session_id!r} "
                        "has a takeover event with actor/reason set"
                    )
                details = event.get("details")
                if not isinstance(details, dict) or set(details) != {
                    "takeover_id",
                    "stage",
                    "old_share_id",
                    "new_share_id",
                }:
                    raise RecoveryError(
                        f"wallet {wallet_id!r} sign session {session_id!r} "
                        "has a malformed takeover event"
                    )
                takeover_id = details["takeover_id"]
                stage = details["stage"]
                old = details["old_share_id"]
                new = details["new_share_id"]
                if not isinstance(
                    takeover_id, str
                ) or not ROTATION_ID_RE.match(takeover_id):
                    raise RecoveryError(
                        f"wallet {wallet_id!r} sign session {session_id!r} "
                        "takeover event has a malformed takeover_id"
                    )
                # 同一 takeover_id 不得跨会话占用（在线 409 已挡住，落盘
                # 仍出现即外部篡改/矛盾现场，fail-closed）。
                owner = seen_takeover_sessions.get(takeover_id)
                if owner is not None and owner != session_id:
                    raise RecoveryError(
                        f"wallet {wallet_id!r} takeover {takeover_id!r} is "
                        "committed for more than one session"
                    )
                seen_takeover_sessions[takeover_id] = session_id
                if (
                    not isinstance(stage, int)
                    or isinstance(stage, bool)
                    or stage not in TAKEOVER_STAGES
                ):
                    raise RecoveryError(
                        f"wallet {wallet_id!r} sign session {session_id!r} "
                        "takeover event has a malformed stage"
                    )
                if not isinstance(old, str) or not _SAFE_SHARE_ID.match(old):
                    raise RecoveryError(
                        f"wallet {wallet_id!r} sign session {session_id!r} "
                        "takeover event has a malformed old_share_id"
                    )
                if (
                    not isinstance(new, str)
                    or new != self._takeover_stage_share_id(takeover_id, stage)
                ):
                    raise RecoveryError(
                        f"wallet {wallet_id!r} sign session {session_id!r} "
                        "takeover event has a malformed new_share_id"
                    )
                if old == new:
                    raise RecoveryError(
                        f"wallet {wallet_id!r} sign session {session_id!r} "
                        "takeover event replaces a share with itself"
                    )
                if new in seen_new:
                    raise RecoveryError(
                        f"wallet {wallet_id!r} takeover share {new!r} is "
                        "committed by more than one event"
                    )
                seen_new.add(new)
                stages_by_takeover.setdefault(takeover_id, []).append(event)
            for takeover_id, takeover_events in stages_by_takeover.items():
                # 事件已按 seq 升序：阶段序列必须恰为 [1] 或 [1, 2]
                stages = [
                    event["details"]["stage"] for event in takeover_events
                ]
                if stages not in ([1], [1, 2]):
                    raise RecoveryError(
                        f"wallet {wallet_id!r} sign session {session_id!r} "
                        f"takeover {takeover_id!r} has a non-contiguous "
                        "stage sequence"
                    )
        return grouped

    def _recover_sign_sessions(self, wallet_id: str) -> None:
        """启动/持锁恢复签名会话崩溃现场（调用方须持钱包事务锁）。

        形状/UTC 时间严格校验由存储层完成（损坏即 CorruptDataError ->
        503/阻止就绪，保留现场）。对账以 session_event 为唯一提交点：

        - 无 created 事件：创建未提交，删除残留会话记录；有 created 事件
          却无记录：矛盾现场，fail-closed；
        - 动作序列严格校验：created 首个且唯一；share_received 的份额必须
          属于该事件时刻的在用快照、不重复，details.state 与当时有效已收
          份数一致（齐份 ready，否则 collecting）；expired/signed/cancelled
          至多一次且互斥、其后不得再有事件；signed 时两份份额必已齐；
          cancelled 事件的 cancel_id 在同钱包会话撤销间不得重复，记录
          携带的 cancellation 必须与事件一致；created 的
          message/timeout_seconds 必须与记录一致；
        - 已存份额若无对应 share_received 事件：份额提交未完成，回滚丢弃；
          有事件却无已存份额：仅当该份额已被后续轮换激活淘汰（剔除旧份额
          的迁移）才合法，否则 fail-closed；
        - 每份已存签名用其对应历史公钥重新校验；signed 按有序快照重算
          128 字节聚合签名，必须与记录一致，否则 fail-closed；
        - signed 事件：前滚为唯一 signed；expired 事件（collecting 与
          ready 到点均可过期）：前滚 expired；cancelled 事件（collecting
          与 ready 均可撤销）：前滚 cancelled 并按事件补齐 cancellation；
          否则按当前在用快照迁移并据已提交份额恢复 collecting/ready——
          磁盘误写的终态随事件回滚；
        - collecting/ready 记录若停留在旧快照，按钱包当前在用份额迁移：
          剔除已收旧份额（其 share_received 事件保留在仅追加审计中）。
        恢复本身不记事件、不分配 seq。
        """
        records = self._store.list_sign_sessions(wallet_id)
        # 仅当会话文件存在时才做审计对账：文件不存在是正常空状态，绝不
        # 触碰审计日志（使审计文件损坏时不依赖审计的路由仍可用）；但文件
        # 存在（即使为 {}）而审计里有 created 事件，属于“记录丢失/被清空”
        # 的矛盾现场，必须读取审计并 fail-closed。
        file_exists = self._store.sign_session_file_exists(wallet_id)
        if not file_exists:
            return
        events_by_session = self._audit.session_events(wallet_id)
        replacement_events = self._validated_replacement_events(wallet_id)
        takeover_events = self._validated_takeover_events(wallet_id)
        timeline = self._rotation_timeline(wallet_id)
        wallet = self._store.get_wallet(wallet_id)
        if records and not isinstance(wallet, dict):
            raise RecoveryError(
                f"wallet {wallet_id!r} metadata missing during session recovery"
            )
        current_ids: tuple[str, str] | None = None
        if isinstance(wallet, dict):
            shares = wallet.get("shares")
            if (
                not isinstance(shares, list)
                or len(shares) != 2
                or not all(isinstance(s, dict) for s in shares)
            ):
                raise RecoveryError(
                    f"wallet {wallet_id!r} metadata shares are malformed"
                )
            current_ids = (shares[0]["share_id"], shares[1]["share_id"])

        recorded_ids = {record["id"] for record in records}
        for session_id, session_events in events_by_session.items():
            ordered = sorted(session_events, key=lambda e: e.get("seq", 0))
            if any(
                isinstance(e.get("details"), dict)
                and e["details"].get("action") == "created"
                for e in ordered
            ) and session_id not in recorded_ids:
                raise RecoveryError(
                    f"wallet {wallet_id!r} sign session {session_id!r} has a "
                    "created event but no session record"
                )

        # cancel_id 只在同钱包的会话撤销之间判重：同一取消标识被两个会话的
        # 已提交撤销事件引用属于矛盾现场，fail-closed。
        cancel_owners: dict[str, str] = {}
        for session_id, session_events in events_by_session.items():
            for event in session_events:
                details = event.get("details")
                if (
                    not isinstance(details, dict)
                    or details.get("action") != "cancelled"
                ):
                    continue
                cancel_id = details.get("cancel_id")
                if not isinstance(cancel_id, str):
                    # 形状交由 _recover_one_sign_session 严格校验
                    continue
                owner = cancel_owners.get(cancel_id)
                if owner is not None and owner != session_id:
                    raise RecoveryError(
                        f"wallet {wallet_id!r} cancel {cancel_id!r} is "
                        "committed by more than one sign session"
                    )
                cancel_owners[cancel_id] = session_id

        # 已提交替换/接管事件引用的会话必须存在；其新份额文件必须密码学
        # 自洽（缺失/损坏/矛盾 fail-closed，保留现场）。两类事件共享新份额
        # id 命名空间，任一 new_share_id 被两类事件重复引用均属矛盾现场。
        committed_new_share_ids: set[str] = set()
        participant_events = {
            "replacement": replacement_events,
            "takeover": takeover_events,
        }
        for kind, grouped in participant_events.items():
            for session_id, events in grouped.items():
                if session_id not in recorded_ids:
                    raise RecoveryError(
                        f"wallet {wallet_id!r} sign session {session_id!r} "
                        f"has a participant {kind} event but no session record"
                    )
                for event in events:
                    new_id = event["details"]["new_share_id"]
                    if new_id in committed_new_share_ids:
                        raise RecoveryError(
                            f"wallet {wallet_id!r} participant share "
                            f"{new_id!r} is committed by more than one event"
                        )
                    committed_new_share_ids.add(new_id)
                    self._validated_replacement_share(wallet_id, new_id)
        # 无提交事件引用的 *-share 份额文件是替换/接管提交点（事件）落盘
        # 前的崩溃残留：回滚删除。
        for share_id in self._store.list_share_files(wallet_id):
            if (
                share_id.endswith("-share")
                and share_id not in committed_new_share_ids
            ):
                self._store.delete_share(wallet_id, share_id)

        for record in records:
            self._recover_one_sign_session(
                wallet_id,
                record,
                events_by_session,
                timeline,
                current_ids,
                wallet,
                replacement_events.get(record["id"], []),
                takeover_events.get(record["id"], []),
            )

    def _recover_one_sign_session(
        self,
        wallet_id: str,
        record: dict,
        events_by_session: dict[str, list[dict]],
        timeline: list[tuple[int, tuple[str, str]]],
        current_ids: tuple[str, str] | None,
        wallet: dict,
        replacements: list[dict] | None = None,
        takeovers: list[dict] | None = None,
    ) -> None:
        session_id = record["id"]
        replacements = replacements or []
        takeovers = takeovers or []
        raw_events = sorted(
            events_by_session.get(session_id, []),
            key=lambda event: event.get("seq", 0),
        )
        session_events: list[dict] = []
        for event in raw_events:
            details = event.get("details")
            if not isinstance(details, dict):
                raise RecoveryError(
                    f"wallet {wallet_id!r} sign session {session_id!r} has a "
                    "session_event without object details"
                )
            session_events.append(event)

        actions = [event["details"].get("action") for event in session_events]
        if not session_events or actions[0] != "created" or actions.count(
            "created"
        ) != 1:
            # created 必须是首个动作且唯一；无 created 事件 -> 创建未提交，
            # 回滚删除残留记录（事件未落盘的残留记录重启即清）。
            if "created" not in actions:
                if replacements or takeovers:
                    # 创建未提交却有已提交替换/接管事件：矛盾现场，绝不删除
                    raise RecoveryError(
                        f"wallet {wallet_id!r} sign session {session_id!r} "
                        "has participant replacement/takeover events but no "
                        "created event"
                    )
                self._store.delete_sign_session(wallet_id, session_id)
                return
            raise RecoveryError(
                f"wallet {wallet_id!r} sign session {session_id!r} has a "
                "malformed created action sequence"
            )

        created_details = session_events[0]["details"]
        if (
            created_details.get("message") != record["message"]
            or created_details.get("timeout_seconds")
            != record["timeout_seconds"]
        ):
            raise RecoveryError(
                f"wallet {wallet_id!r} sign session {session_id!r} created "
                "event does not match the record"
            )

        # 已提交参与者替换/接管事件：必须发生在创建之后、终态之前；每次
        # 换槽的 old 必须是该事件时刻会话快照内的在用份额、new 不得已在
        # 快照中。首个替换/接管之后会话快照与钱包轮换解耦（轮换不再迁移
        # 该会话）。两类事件共享同一条换槽序列，按 seq 归并。
        participant_cuts: list[tuple[int, str, str]] = []
        merged_participant_events = sorted(
            list(replacements) + list(takeovers),
            key=lambda event: event.get("seq", 0),
        )
        if merged_participant_events:
            created_seq = session_events[0].get("seq")
            current_set = list(
                self._active_share_set_at(
                    timeline, merged_participant_events[0]["seq"]
                )
            )
            last_seq = created_seq
            for event in merged_participant_events:
                seq = event.get("seq")
                if (
                    not isinstance(seq, int)
                    or isinstance(seq, bool)
                    or not isinstance(last_seq, int)
                    or seq <= last_seq
                ):
                    raise RecoveryError(
                        f"wallet {wallet_id!r} sign session {session_id!r} "
                        "has an out-of-order participant replacement/"
                        "takeover event"
                    )
                last_seq = seq
                details = event["details"]
                old, new = details["old_share_id"], details["new_share_id"]
                if old not in current_set or new in current_set:
                    raise RecoveryError(
                        f"wallet {wallet_id!r} sign session {session_id!r} "
                        f"replacement of {old!r} by {new!r} does not match "
                        "the session share set at its seq"
                    )
                current_set = [
                    new if sid == old else sid for sid in current_set
                ]
                participant_cuts.append((seq, old, new))

        def session_set_at(seq: int) -> tuple[str, str]:
            """该会话在指定审计 seq 时刻的在用份额快照。

            首个替换/接管事件之前跟随钱包轮换时间线；之后与轮换解耦，按
            换槽事件逐次换槽（冻结于最后一次替换/接管后的快照）。"""
            if not participant_cuts or seq < participant_cuts[0][0]:
                return self._active_share_set_at(timeline, seq)
            current = list(
                self._active_share_set_at(timeline, participant_cuts[0][0])
            )
            for cut_seq, old, new in participant_cuts:
                if cut_seq > seq:
                    break
                current = [new if sid == old else sid for sid in current]
            return (current[0], current[1])

        # 两阶段接管的槽位约束：同一 takeover_id 的两个阶段必须替换不同
        # 物理槽位（按各自提交时刻的有序快照下标判定；其间该槽位可能又
        # 被普通替换/其他接管换过份额，故必须按位置而不是按份额 id 判定）。
        takeover_by_id: dict[str, list[dict]] = {}
        for event in takeovers:
            takeover_by_id.setdefault(
                event["details"]["takeover_id"], []
            ).append(event)
        for takeover_id, tid_events in takeover_by_id.items():
            if len(tid_events) != 2:
                continue
            first, second = tid_events
            first_seq = first.get("seq")
            second_seq = second.get("seq")
            first_old = first["details"]["old_share_id"]
            second_old = second["details"]["old_share_id"]
            before_first = session_set_at(first_seq - 1)
            before_second = session_set_at(second_seq - 1)
            if (
                first_old not in before_first
                or second_old not in before_second
            ):
                # 通用换槽校验已保证 old 属于其提交时刻快照，此处为防御
                raise RecoveryError(
                    f"wallet {wallet_id!r} sign session {session_id!r} "
                    f"takeover {takeover_id!r} does not match the session "
                    "share set at its seq"
                )
            if before_first.index(first_old) == before_second.index(
                second_old
            ):
                raise RecoveryError(
                    f"wallet {wallet_id!r} sign session {session_id!r} "
                    f"takeover {takeover_id!r} replaces the same slot twice"
                )

        # 严格校验动作顺序，并重建各动作提交时刻的已收份额序列。
        # committed_events: 按 seq 顺序的 share_received 事件（跨轮换）。
        committed_events: list[dict] = []
        terminal: str | None = None
        for event in session_events[1:]:
            details = event["details"]
            action = details.get("action")
            seq = event.get("seq")
            if terminal is not None:
                raise RecoveryError(
                    f"wallet {wallet_id!r} sign session {session_id!r} has an "
                    f"action {action!r} after terminal {terminal!r}"
                )
            if action == "share_received":
                sid = details.get("share_id")
                state_detail = details.get("state")
                if state_detail not in ("collecting", "ready"):
                    raise RecoveryError(
                        f"wallet {wallet_id!r} sign session {session_id!r} "
                        "share_received event has malformed state"
                    )
                if not isinstance(sid, str) or not sid:
                    raise RecoveryError(
                        f"wallet {wallet_id!r} sign session {session_id!r} "
                        "share_received event has malformed share_id"
                    )
                active_set = session_set_at(seq)
                if sid not in active_set:
                    raise RecoveryError(
                        f"wallet {wallet_id!r} sign session {session_id!r} "
                        f"received share {sid!r} that was not active at seq "
                        f"{seq!r}"
                    )
                if any(
                    e["details"].get("share_id") == sid
                    for e in committed_events
                ):
                    raise RecoveryError(
                        f"wallet {wallet_id!r} sign session {session_id!r} "
                        f"recorded share {sid!r} twice"
                    )
                committed_events.append(event)
                # details.state 必须与该时刻有效快照内已收份数一致：
                # 轮换淘汰旧份额后份数重新计数。
                effective = [
                    e
                    for e in committed_events
                    if e["details"]["share_id"]
                    in session_set_at(seq)
                ]
                expected_state = (
                    "ready" if len(effective) == 2 else "collecting"
                )
                if state_detail != expected_state:
                    raise RecoveryError(
                        f"wallet {wallet_id!r} sign session {session_id!r} "
                        f"share_received state {state_detail!r} does not match "
                        f"the effective share count"
                    )
            elif action == "signed":
                if details.get("state") != "signed":
                    raise RecoveryError(
                        f"wallet {wallet_id!r} sign session {session_id!r} "
                        "signed event has malformed state"
                    )
                active_set = session_set_at(seq)
                effective = [
                    e
                    for e in committed_events
                    if e["details"]["share_id"] in active_set
                ]
                if len(effective) != 2:
                    raise RecoveryError(
                        f"wallet {wallet_id!r} sign session {session_id!r} "
                        "signed event without both shares committed"
                    )
                terminal = "signed"
            elif action == "expired":
                if details.get("state") != "expired":
                    raise RecoveryError(
                        f"wallet {wallet_id!r} sign session {session_id!r} "
                        "expired event has malformed state"
                    )
                terminal = "expired"
            elif action == "cancelled":
                cancel_id = details.get("cancel_id")
                cancel_reason = details.get("reason")
                if (
                    details.get("state") != "cancelled"
                    or not isinstance(cancel_id, str)
                    or not ROTATION_ID_RE.match(cancel_id)
                    or not isinstance(cancel_reason, str)
                    or isinstance(cancel_reason, bool)
                    or not 1 <= len(cancel_reason) <= MAX_REASON_LENGTH
                    or not cancel_reason.strip()
                ):
                    raise RecoveryError(
                        f"wallet {wallet_id!r} sign session {session_id!r} "
                        "cancelled event has malformed details"
                    )
                terminal = "cancelled"
            else:
                raise RecoveryError(
                    f"wallet {wallet_id!r} sign session {session_id!r} has "
                    f"unknown action {action!r}"
                )

        if (
            actions.count("signed")
            + actions.count("expired")
            + actions.count("cancelled")
            > 1
        ):
            raise RecoveryError(
                f"wallet {wallet_id!r} sign session {session_id!r} has multiple "
                "terminal actions"
            )

        signed_seq = next(
            (
                e["seq"]
                for e in session_events
                if e["details"].get("action") == "signed"
            ),
            None,
        )
        expired_seq = next(
            (
                e["seq"]
                for e in session_events
                if e["details"].get("action") == "expired"
            ),
            None,
        )
        cancelled_seq = next(
            (
                e["seq"]
                for e in session_events
                if e["details"].get("action") == "cancelled"
            ),
            None,
        )

        # 终态冻结其提交时刻的在用快照；非终态以钱包当前在用份额为准
        # （有替换/接管事件的会话冻结于最后一次换槽后的快照，不再随轮换
        # 迁移）。
        terminal_seq = signed_seq or expired_seq or cancelled_seq
        for cut_seq, _old, _new in participant_cuts:
            if terminal_seq is not None and cut_seq > terminal_seq:
                raise RecoveryError(
                    f"wallet {wallet_id!r} sign session {session_id!r} has a "
                    "participant replacement/takeover event after its "
                    "terminal action"
                )
        if terminal == "signed":
            effective_ids = session_set_at(signed_seq)
        elif terminal == "expired":
            effective_ids = session_set_at(expired_seq)
        elif terminal == "cancelled":
            effective_ids = session_set_at(cancelled_seq)
        elif participant_cuts:
            effective_ids = session_set_at(participant_cuts[-1][0])
        else:
            if current_ids is None:
                raise RecoveryError(
                    f"wallet {wallet_id!r} metadata missing during session "
                    "recovery"
                )
            effective_ids = current_ids

        committed_ids = [
            event["details"]["share_id"] for event in committed_events
        ]
        committed_set = set(committed_ids)
        stored_all = {entry["share_id"]: entry for entry in record["shares"]}

        # 已存份额若无提交事件：份额落盘先于事件追加，这是收份额崩溃
        # 窗口内"状态已写、提交点（事件）未落盘"的现场 -> 确定回滚，
        # rebuilt 时自然剔除该未提交份额（不留孤立份额）。
        stored = {
            sid: entry
            for sid, entry in stored_all.items()
            if sid in committed_set
        }

        # 已提交却未存储的份额：唯一合法解释是该份额在投递落事件之后、
        # 会话终态（若有）之前，被某次轮换激活或参与者替换从在用快照中
        # 淘汰（迁移时剔除已收旧份额，仅追加审计保留其 share_received
        # 事件）。终态之后的轮换/替换不能解释终态记录中的缺失。
        for sid in committed_ids:
            if sid in stored:
                continue
            if sid in effective_ids:
                raise RecoveryError(
                    f"wallet {wallet_id!r} sign session {session_id!r} has a "
                    f"committed share {sid!r} but no stored signature"
                )
            event_seq = next(
                e["seq"]
                for e in committed_events
                if e["details"]["share_id"] == sid
            )
            evicted = False
            for act_seq, act_ids in timeline:
                if act_seq <= event_seq:
                    continue
                if terminal_seq is not None and act_seq > terminal_seq:
                    continue
                if (
                    sid not in act_ids
                    and sid
                    in self._active_share_set_at(timeline, act_seq - 1)
                ):
                    evicted = True
                    break
            if not evicted:
                for cut_seq, old, _new in participant_cuts:
                    if cut_seq <= event_seq:
                        continue
                    if terminal_seq is not None and cut_seq > terminal_seq:
                        continue
                    if old == sid:
                        evicted = True
                        break
            if not evicted:
                raise RecoveryError(
                    f"wallet {wallet_id!r} sign session {session_id!r} "
                    f"committed share {sid!r} vanished without a rotation "
                    "or participant replacement/takeover"
                )

        # 非终态记录的 share_ids 必须等于某一历史时刻的在用快照；终态记录
        # 的 share_ids 必须冻结为终态提交时刻快照。
        historical_sets = {("share-1", "share-2")}
        for act_seq, act_ids in timeline:
            historical_sets.add(
                self._active_share_set_at(timeline, act_seq)
            )
        if participant_cuts:
            current_set = list(
                self._active_share_set_at(timeline, participant_cuts[0][0])
            )
            for _cut_seq, old, new in participant_cuts:
                current_set = [
                    new if sid == old else sid for sid in current_set
                ]
                historical_sets.add((current_set[0], current_set[1]))
        recorded_ids = tuple(record["share_ids"])
        if recorded_ids not in historical_sets:
            raise RecoveryError(
                f"wallet {wallet_id!r} sign session {session_id!r} snapshot "
                f"{recorded_ids!r} matches no known share set"
            )
        if terminal is not None and recorded_ids != effective_ids:
            raise RecoveryError(
                f"wallet {wallet_id!r} sign session {session_id!r} terminal "
                "snapshot does not match the active shares at commit time"
            )

        # 用相应公钥重新校验每份已存签名（历史份额公钥沿轮换记录链解析）。
        verify_ids = sorted(stored)
        public_map = self._session_share_public_keys(
            wallet_id, verify_ids, wallet
        )
        payload = crypto.build_payload(session_id, record["message"])
        for sid, entry in stored.items():
            signature = bytes.fromhex(entry["signature"])
            if not crypto.verify_share(
                bytes.fromhex(public_map[sid]), payload, signature
            ):
                raise RecoveryError(
                    f"wallet {wallet_id!r} sign session {session_id!r} stored "
                    f"signature for {sid!r} fails public-key verification"
                )

        rebuilt = dict(record)
        rebuilt["share_ids"] = list(effective_ids)
        rebuilt["shares"] = [
            stored[sid]
            for sid in effective_ids
            if sid in stored
        ]
        rebuilt.pop("aggregate_signature", None)
        rebuilt.pop("cancellation", None)

        if terminal == "signed":
            if len(rebuilt["shares"]) != 2:
                raise RecoveryError(
                    f"wallet {wallet_id!r} sign session {session_id!r} signed "
                    "without both stored shares"
                )
            rebuilt["state"] = "signed"
            rebuilt["aggregate_signature"] = (
                self._aggregate_session_shares(rebuilt).hex()
            )
            # 记录带有聚合签名时，重算结果必须一致（被篡改即 fail-closed）；
            # 记录恰缺聚合签名（signed 已提交、状态写盘不完整的崩溃现场）
            # 时按事件前滚补齐即可。
            recorded_aggregate = record.get("aggregate_signature")
            if (
                isinstance(recorded_aggregate, str)
                and recorded_aggregate != rebuilt["aggregate_signature"]
            ):
                raise RecoveryError(
                    f"wallet {wallet_id!r} sign session {session_id!r} "
                    "aggregate signature does not recompute to the record"
                )
        elif terminal == "expired":
            # collecting 与 ready 到点均可过期：终态不再聚合。
            rebuilt["state"] = "expired"
        elif terminal == "cancelled":
            # 主动撤销：collecting 与 ready 均可撤销，终态冻结撤销时刻
            # 快照；撤销快照以事件为权威来源前滚补齐。
            cancelled_event = next(
                e
                for e in session_events
                if e["details"].get("action") == "cancelled"
            )
            rebuilt["state"] = "cancelled"
            rebuilt["cancellation"] = {
                "cancel_id": cancelled_event["details"]["cancel_id"],
                "reason": cancelled_event["details"]["reason"],
            }
            # 记录已带撤销快照时必须与事件一致（被篡改即 fail-closed）；
            # 恰缺快照（事件已落盘、状态写盘不完整的崩溃现场）按事件
            # 前滚补齐即可。
            recorded_cancellation = record.get("cancellation")
            if (
                recorded_cancellation is not None
                and recorded_cancellation != rebuilt["cancellation"]
            ):
                raise RecoveryError(
                    f"wallet {wallet_id!r} sign session {session_id!r} "
                    "cancellation does not match the cancelled event"
                )
        else:
            # 轮换迁移后的非终态：旧份额已剔除，按当前快照内已提交份数恢复
            rebuilt["state"] = (
                "ready" if len(rebuilt["shares"]) == 2 else "collecting"
            )

        if rebuilt != record:
            self._store.update_sign_session(
                wallet_id, session_id, rebuilt
            )

    # -- 可恢复两方 DKG ------------------------------------------------------

    @staticmethod
    def _validate_dkg_id(dkg_id: object) -> None:
        if not isinstance(dkg_id, str) or not ROTATION_ID_RE.match(dkg_id):
            raise ServiceError(
                400, "dkg id must match [A-Za-z0-9_-]{1,128}"
            )

    @staticmethod
    def _validate_dkg_node(node: object) -> None:
        if not isinstance(node, str) or not ROTATION_ID_RE.match(node):
            raise ServiceError(
                400, "node must match [A-Za-z0-9_-]{1,128}"
            )

    @staticmethod
    def _dkg_state(
        nodes: list, commits: dict, shared: dict
    ) -> str:
        """由已推进的注册/承诺/份额确认计数推导会话阶段。"""
        if len(shared) == 2:
            return "done"
        if len(commits) == 2:
            return "share"
        if len(nodes) == 2:
            return "commit"
        return "register"

    @staticmethod
    def _dkg_view(session: dict, round_no: int) -> dict:
        """DKG 会话某一轮的对外视图（GET/POST/failover 同形，键序固定）。

        三个数组均按注册序；完成公钥为两份注册 key 按注册序拼接，
        非 done 为 null。视图只含标识/轮次/公钥/哈希，绝不含私钥
        或份额正文。"""
        round_state = session["rounds"][round_no]
        nodes = round_state["nodes"]
        public_key = None
        if round_state["state"] == "done":
            public_key = nodes[0][1] + nodes[1][1]
        return {
            "id": session["id"],
            "round": round_no,
            "state": round_state["state"],
            "nodes": [node for node, _ in nodes],
            "committed": [
                node for node, _ in nodes if node in round_state["commits"]
            ],
            "shared": [
                node for node, _ in nodes if node in round_state["shared"]
            ],
            "public_key": public_key,
        }

    @staticmethod
    def _parse_dkg_request_id(
        wallet_id: str, request_id: str, failover: bool
    ) -> tuple[str, int]:
        """把 DKG 事件的 request_id 解析为 (会话 id, 轮次)。

        基线轮（第 1 轮）的 request_id 即会话 id 本身；派生轮（第 R≥2
        轮）为 ``<会话id>/<R>``。dkg_failover 事件必须指向派生轮；
        dkg_stage 事件的轮次后缀不得为 1（基线轮无后缀）。任何畸形
        （空段、多斜杠、非规范轮次、非法会话 id）都不可对账。"""
        parts = request_id.split("/")
        round_no = 1
        if len(parts) == 1:
            if failover:
                raise RecoveryError(
                    f"wallet {wallet_id!r} has a dkg_failover event whose "
                    "request_id does not name a derived round"
                )
            dkg_id = parts[0]
        elif len(parts) == 2:
            dkg_id, suffix = parts
            if (
                not suffix.isascii()
                or not suffix.isdigit()
            ):
                raise RecoveryError(
                    f"wallet {wallet_id!r} has a dkg event with a "
                    "malformed round suffix"
                )
            try:
                round_no = int(suffix)
            except ValueError:
                raise RecoveryError(
                    f"wallet {wallet_id!r} has a dkg event with a "
                    "malformed round suffix"
                )
            if round_no < 1 or str(round_no) != suffix:
                raise RecoveryError(
                    f"wallet {wallet_id!r} has a dkg event with a "
                    "non-canonical round suffix"
                )
            if failover:
                if round_no < 2:
                    raise RecoveryError(
                        f"wallet {wallet_id!r} has a dkg_failover event "
                        "for the baseline round"
                    )
            elif round_no == 1:
                raise RecoveryError(
                    f"wallet {wallet_id!r} has a dkg_stage event whose "
                    "round suffix names the baseline round"
                )
        else:
            raise RecoveryError(
                f"wallet {wallet_id!r} has a dkg event with a malformed "
                "request_id"
            )
        if not ROTATION_ID_RE.match(dkg_id):
            raise RecoveryError(
                f"wallet {wallet_id!r} has a dkg event with a "
                "malformed session id"
            )
        return dkg_id, round_no

    def _dkg_sessions(
        self, wallet_id: str, until_seq: Optional[int] = None
    ) -> dict[str, dict]:
        """从 dkg_stage / dkg_failover 事件重建并严格校验该钱包全部 DKG 会话。

        ``until_seq`` 给定时只重放 ``seq <= until_seq`` 的事件（恢复复核
        node_rejoined 提交时刻现场用），该路径**不**再重跑全量 rejoin
        复核（复核内部按各 rejoin seq 前缀反复调用本方法，避免递归）；
        全量（``until_seq is None``）访问先严格复核 node_rejoined 事件，
        使 DKG 路由同样在 rejoin 现场矛盾时 fail-closed，绝不绕过对账。

        事件是 DKG 状态的唯一持久化与提交点：基线轮（第 1 轮）由
        request_id 为会话 id 的 dkg_stage 事件重放；每个派生轮（第
        R≥2 轮）由 request_id 为 ``<id>/<R>`` 的唯一 dkg_failover 事件
        从上一轮派生，再由同 request_id 的 dkg_stage 事件推进。任何矛盾
        （形状、字段约束、轮次缺口/重复、阶段顺序、承诺不一致、
        details.state 与重算不符）都抛 RecoveryError（fail-closed：
        常驻 503、serve 拒绝就绪），绝不静默跳过或任取一条。

        node_state 事件序列在此一并严格校验：auto 故障（details 八键、
        mode=auto）重建时须以其事件提交之前最近的健康快照核验自动选择，
        故即使尚无 DKG 会话，健康表畸形也在此 fail-closed。纯只读，
        不分配 seq、不写任何状态。"""
        if until_seq is None:
            self._reconcile_node_rejoins(wallet_id)
        return self._build_dkg_sessions(wallet_id, until_seq)

    def _build_dkg_sessions(
        self, wallet_id: str, until_seq: Optional[int]
    ) -> dict[str, dict]:
        """只按事件重建 DKG 会话（不触发 rejoin 全量复核）。"""
        # 健康快照流（node_state + 变更控制下 target=nodes 的
        # policy_change_applied）先严格校验，供各 auto 故障按事件 seq 取事前
        # 快照核验；前缀重放只取 seq < 事件 seq 的快照，故含更晚快照无影响。
        node_events = self._node_health_snapshot_events_locked(wallet_id)

        def _accepted(ev: dict) -> bool:
            return until_seq is None or ev["seq"] <= until_seq

        stage_rounds: dict[str, dict[int, list[dict]]] = {}
        for request_id, events in self._audit.dkg_stage_events(
            wallet_id
        ).items():
            dkg_id, round_no = self._parse_dkg_request_id(
                wallet_id, request_id, failover=False
            )
            stage_rounds.setdefault(dkg_id, {}).setdefault(
                round_no, []
            ).extend(ev for ev in events if _accepted(ev))
        failover_rounds: dict[str, dict[int, list[dict]]] = {}
        for request_id, events in self._audit.dkg_failover_events(
            wallet_id
        ).items():
            dkg_id, round_no = self._parse_dkg_request_id(
                wallet_id, request_id, failover=True
            )
            accepted = [ev for ev in events if _accepted(ev)]
            if not accepted:
                continue
            failover_rounds.setdefault(dkg_id, {}).setdefault(
                round_no, []
            ).extend(accepted)
        sessions: dict[str, dict] = {}
        # reinstate 故障的恢复复核需要全部 node_rejoined 事件（仅形状严格
        # 校验；语义复核由 _reconcile_node_rejoins 负责）：在各 reinstate
        # 事件处按 seq 过滤出更早提交的 rejoin。until_seq 前缀重放下，
        # reinstate 必在其 rejoin 之后，故引用的 rejoin 必也在前缀内。
        rejoin_events = self._rejoin_events_strict(wallet_id)
        for dkg_id in sorted(set(stage_rounds) | set(failover_rounds)):
            accepted_stage = {
                r: evs for r, evs in stage_rounds.get(dkg_id, {}).items()
                if evs
            }
            accepted_failover = failover_rounds.get(dkg_id, {})
            # 前缀重放（rejoin 复核按 seq 截断）下，某会话的全部事件都
            # 可能落在截断点之后：分组键来自 request_id 仍会出现在映射
            # 里，但其 accepted 事件为空。这样的会话在该前缀中尚不存在，
            # 必须整体跳过——否则会被当成"缺基线轮"的损坏现场误判。
            if not accepted_stage and not accepted_failover:
                continue
            sessions[dkg_id] = self._rebuild_dkg_session(
                wallet_id,
                dkg_id,
                accepted_stage,
                accepted_failover,
                node_events,
                rejoin_events,
            )
        return sessions

    def _rebuild_dkg_session(
        self,
        wallet_id: str,
        dkg_id: str,
        stage_rounds: dict[int, list[dict]],
        failover_rounds: dict[int, list[dict]],
        node_events: list[dict],
        rejoin_events: list[dict],
    ) -> dict:
        """按轮次链重建某 DKG 会话并严格校验。

        轮次链必须连续：基线轮（第 1 轮）必有 dkg_stage 事件；第 R≥2
        轮必有且仅有一条 dkg_failover 事件从第 R-1 轮派生。派生轮不
        接受 register，aborted 轮不接受任何阶段事件。

        auto 故障（details 八键 mode=auto）还须用其事件**提交之前**最近
        的 node_state 健康快照核验：node 当时 down|ban、被选替补当时为
        首个 up 的非参与节点且 key 与记录一致；快照缺失、无候选或任何
        不符都 fail-closed（RecoveryError）。

        reinstate 故障用其事件提交之前的**生效**健康表（最近快照折叠其
        间更早 rejoin 翻转）核验：replacement 当时为 up 的非参与节点、
        key 一致，且有更早提交的 node_rejoined 与之对应；另按 actor_id
        复核同钱包审批单。"""
        baseline_events = stage_rounds.get(1, [])
        if not baseline_events:
            raise RecoveryError(
                f"wallet {wallet_id!r} dkg session {dkg_id!r} has no "
                "baseline round events"
            )
        rounds: dict[int, dict] = {
            1: self._replay_dkg_round(
                wallet_id, dkg_id, 1, baseline_events, seed=None
            )
        }
        failovers: dict[int, dict] = {}
        derived = [r for r in stage_rounds if r >= 2]
        max_round = max([1, *failover_rounds, *derived])
        for round_no in range(2, max_round + 1):
            events = failover_rounds.get(round_no, [])
            if len(events) != 1:
                raise RecoveryError(
                    f"wallet {wallet_id!r} dkg session {dkg_id!r} round "
                    f"{round_no} does not have exactly one dkg_failover "
                    "event"
                )
            event = events[0]
            health_before = self._health_snapshot_before(
                node_events, event["seq"]
            )
            effective_health_before = self._folded_health_before(
                node_events, rejoin_events, event["seq"]
            )
            new_round, committed = self._apply_dkg_failover(
                wallet_id,
                dkg_id,
                round_no,
                event,
                rounds[round_no - 1],
                health_before,
                effective_health_before,
                rejoin_events,
            )
            failovers[round_no] = committed
            rounds[round_no] = self._replay_dkg_round(
                wallet_id,
                dkg_id,
                round_no,
                stage_rounds.get(round_no, []),
                seed=new_round,
            )
        return {
            "id": dkg_id,
            "rounds": rounds,
            "current": max_round,
            "failovers": failovers,
        }

    @staticmethod
    def _folded_health_before(
        node_events: list[dict],
        rejoin_events: list[dict],
        seq: int,
    ) -> Optional[dict]:
        """seq 之前最近 node_state 快照，再折叠 seq 之前（且在该快照之后）
        的 node_rejoined 翻转后的生效健康表；无快照返回 None。"""
        snapshot = None
        snapshot_seq = 0
        for event in node_events:
            if event["seq"] < seq:
                snapshot = event["details"]["nodes"]
                snapshot_seq = event["seq"]
        if snapshot is None:
            return None
        folded = {n: dict(entry) for n, entry in snapshot.items()}
        for event in rejoin_events:
            eseq = event["seq"]
            if eseq >= seq or eseq <= snapshot_seq:
                continue
            n = event["details"]["node"]
            if n in folded:
                folded[n] = {"key": folded[n]["key"], "state": "up"}
        return folded

    @staticmethod
    def _health_snapshot_before(
        node_events: list[dict], seq: int
    ) -> Optional[dict]:
        """node_state 事件序列中 seq 之前最近的健康表；无则 None。"""
        latest = None
        for event in node_events:
            if event["seq"] < seq:
                latest = event["details"]["nodes"]
        return latest

    def _apply_dkg_failover(
        self,
        wallet_id: str,
        dkg_id: str,
        round_no: int,
        event: dict,
        prev_round: dict,
        health_before: Optional[dict],
        effective_health_before: Optional[dict],
        rejoin_events: list[dict],
    ) -> tuple[dict, dict]:
        """校验一条 dkg_failover 事件并从上一轮派生新轮次。

        返回 (新轮次状态, 已提交参数)。abort 仅限非终态轮、后三值
        （node/replacement/key）必须为 null，派生出 aborted 空轮；
        replace 仅限两方已注册的 commit|share 轮，key 为 64 位小写
        hex、node 在用、replacement 空闲，换槽并清空后两数组后回到
        commit。任何矛盾都抛 RecoveryError。

        details 两种精确键集：旧/手工为既有七键；auto 替补为既有七键加
        末键 mode（mode 恰为 "auto"、仅 replace）。auto 事件还须用其
        提交前最近的 node_state 健康快照核验：node 当时 down|ban、被选
        替补当时为首个 up 的非参与节点、记录的 replacement/key 与快照
        一致；快照缺失、无候选或任何不符都 RecoveryError。

        reinstate 事件（details 同为手工七键、action=reinstate，无 mode）
        是唯一 actor_id 非 null 的 dkg_failover：actor_id 须为安全标识并
        指向同钱包 approved/signed 审批单，message 逐字为
        dkg_id 后接 K=(round,action,node,replacement,key) 的紧凑 JSON；
        replacement 还须在事件提交前的生效健康表（最近快照折叠其间 rejoin
        翻转）中为 up 空闲节点、key 一致，且有一条更早提交的
        node_rejoined 与之对应。abort/replace（含 auto）actor_id 必须为
        null。任何矛盾都 RecoveryError。"""
        actor_id = event.get("actor_id")
        if event.get("reason") is not None:
            raise RecoveryError(
                f"wallet {wallet_id!r} dkg session {dkg_id!r} has a "
                "dkg_failover event with reason set"
            )
        details = event.get("details")
        manual_keys = {
            "id",
            "round",
            "action",
            "node",
            "replacement",
            "key",
            "state",
        }
        auto_keys = manual_keys | {"mode"}
        if not isinstance(details, dict) or set(details) not in (
            manual_keys,
            auto_keys,
        ):
            raise RecoveryError(
                f"wallet {wallet_id!r} dkg session {dkg_id!r} has a "
                "malformed dkg_failover event"
            )
        is_auto = set(details) == auto_keys
        mode = details.get("mode") if is_auto else None
        if is_auto and mode != "auto":
            raise RecoveryError(
                f"wallet {wallet_id!r} dkg session {dkg_id!r} has a "
                "dkg_failover event with an unknown mode"
            )
        if details["id"] != dkg_id:
            raise RecoveryError(
                f"wallet {wallet_id!r} dkg_failover event id does not "
                "match its request_id"
            )
        recorded_round = details["round"]
        if (
            not isinstance(recorded_round, int)
            or isinstance(recorded_round, bool)
            or recorded_round != round_no
        ):
            raise RecoveryError(
                f"wallet {wallet_id!r} dkg_failover event round does not "
                "match its request_id"
            )
        action = details["action"]
        node = details["node"]
        replacement = details["replacement"]
        key = details["key"]
        if action not in ("abort", "replace", "reinstate"):
            raise RecoveryError(
                f"wallet {wallet_id!r} dkg session {dkg_id!r} has an "
                "unknown failover action"
            )
        if is_auto and action != "replace":
            raise RecoveryError(
                f"wallet {wallet_id!r} dkg session {dkg_id!r} has an auto "
                "failover that is not a replace"
            )
        # 仅 reinstate 的 actor_id 非 null；abort/replace（含 auto）恒为
        # null。
        is_reinstate = action == "reinstate"
        if is_reinstate:
            if not (
                isinstance(actor_id, str) and ROTATION_ID_RE.match(actor_id)
            ):
                raise RecoveryError(
                    f"wallet {wallet_id!r} dkg session {dkg_id!r} has a "
                    "reinstate failover with a missing or malformed "
                    "approval id"
                )
        elif actor_id is not None:
            raise RecoveryError(
                f"wallet {wallet_id!r} dkg session {dkg_id!r} has a "
                "dkg_failover event with actor set"
            )
        prev_state = prev_round["state"]
        committed = {
            "action": action,
            "node": node,
            "replacement": replacement,
            "key": key,
            "mode": mode,
            "approval": actor_id,
        }
        if action == "abort":
            if (
                node is not None
                or replacement is not None
                or key is not None
            ):
                raise RecoveryError(
                    f"wallet {wallet_id!r} dkg session {dkg_id!r} has a "
                    "malformed abort failover event"
                )
            if prev_state in ("done", "aborted"):
                raise RecoveryError(
                    f"wallet {wallet_id!r} dkg session {dkg_id!r} aborts "
                    "a terminal round"
                )
            if details["state"] != "aborted":
                raise RecoveryError(
                    f"wallet {wallet_id!r} dkg session {dkg_id!r} "
                    "failover state does not match the aborted round"
                )
            new_round = {
                "round": round_no,
                "nodes": [],
                "commits": {},
                "shared": {},
                "state": "aborted",
            }
        elif action == "reinstate":
            # 形状沿用手工 replace：key 为 64 位小写 hex、node/replacement
            # 为安全标识；不允许 mode 键（is_auto 为 False）。
            if not _is_lower_hex_32(key):
                raise RecoveryError(
                    f"wallet {wallet_id!r} dkg session {dkg_id!r} has a "
                    "malformed reinstate failover key"
                )
            if not isinstance(node, str) or not ROTATION_ID_RE.match(node):
                raise RecoveryError(
                    f"wallet {wallet_id!r} dkg session {dkg_id!r} has a "
                    "malformed reinstate failover node"
                )
            if (
                not isinstance(replacement, str)
                or not ROTATION_ID_RE.match(replacement)
            ):
                raise RecoveryError(
                    f"wallet {wallet_id!r} dkg session {dkg_id!r} has a "
                    "malformed reinstate failover replacement"
                )
            if is_auto:
                raise RecoveryError(
                    f"wallet {wallet_id!r} dkg session {dkg_id!r} has a "
                    "reinstate failover carrying a mode"
                )
            if prev_state not in ("commit", "share"):
                raise RecoveryError(
                    f"wallet {wallet_id!r} dkg session {dkg_id!r} "
                    "reinstates a node outside the commit/share stage"
                )
            node_ids = [n for n, _ in prev_round["nodes"]]
            if node not in node_ids:
                raise RecoveryError(
                    f"wallet {wallet_id!r} dkg session {dkg_id!r} "
                    "reinstates a node that is not active"
                )
            if replacement in node_ids:
                raise RecoveryError(
                    f"wallet {wallet_id!r} dkg session {dkg_id!r} "
                    "reinstates with a node that is not free"
                )
            # replacement 须为该故障**提交之前**已 rejoin、且在事前生效
            # 健康表中当前 up 的空闲节点，key 与健康表一致。
            if effective_health_before is None:
                raise RecoveryError(
                    f"wallet {wallet_id!r} dkg session {dkg_id!r} has a "
                    "reinstate failover without a prior node_state snapshot"
                )
            reinstate_entry = effective_health_before.get(replacement)
            if (
                not isinstance(reinstate_entry, dict)
                or reinstate_entry.get("state") != "up"
            ):
                raise RecoveryError(
                    f"wallet {wallet_id!r} dkg session {dkg_id!r} "
                    "reinstate replacement is not up in the prior health "
                    "table"
                )
            if reinstate_entry.get("key") != key:
                raise RecoveryError(
                    f"wallet {wallet_id!r} dkg session {dkg_id!r} "
                    "reinstate key does not match the replacement node's key"
                )
            if not any(
                re_event["seq"] < event["seq"]
                and re_event["details"]["node"] == replacement
                for re_event in rejoin_events
            ):
                raise RecoveryError(
                    f"wallet {wallet_id!r} dkg session {dkg_id!r} "
                    "reinstate replacement has no prior node_rejoined event"
                )
            # 按 actor_id 复核同钱包审批单：存在、message 逐字一致、状态
            # 为 approved（其后经 /sign 推进为 signed 亦认可）。
            try:
                approval = self._store.get_request(wallet_id, actor_id)
            except CorruptDataError:
                raise
            except ValueError as exc:
                raise RecoveryError(
                    f"wallet {wallet_id!r} reinstate failover approval "
                    "record is unreadable"
                ) from exc
            if not isinstance(approval, dict):
                raise RecoveryError(
                    f"wallet {wallet_id!r} dkg session {dkg_id!r} "
                    "reinstate refers to an unknown approval request"
                )
            expected_message = self._dkg_failover_approval_message(
                dkg_id, round_no, action, node, replacement, key
            )
            if approval.get("message") != expected_message:
                raise RecoveryError(
                    f"wallet {wallet_id!r} dkg session {dkg_id!r} "
                    "reinstate approval message does not match"
                )
            if approval.get("state") not in ("approved", "signed"):
                raise RecoveryError(
                    f"wallet {wallet_id!r} dkg session {dkg_id!r} "
                    "reinstate approval request is not approved"
                )
            new_nodes = [
                (replacement, key) if n == node else (n, k)
                for n, k in prev_round["nodes"]
            ]
            if details["state"] != "commit":
                raise RecoveryError(
                    f"wallet {wallet_id!r} dkg session {dkg_id!r} "
                    "failover state does not match the reinstated round"
                )
            new_round = {
                "round": round_no,
                "nodes": new_nodes,
                "commits": {},
                "shared": {},
                "state": "commit",
            }
        elif action == "replace":
            if not _is_lower_hex_32(key):
                raise RecoveryError(
                    f"wallet {wallet_id!r} dkg session {dkg_id!r} has a "
                    "malformed replace failover key"
                )
            if not isinstance(node, str) or not ROTATION_ID_RE.match(node):
                raise RecoveryError(
                    f"wallet {wallet_id!r} dkg session {dkg_id!r} has a "
                    "malformed replace failover node"
                )
            if (
                not isinstance(replacement, str)
                or not ROTATION_ID_RE.match(replacement)
            ):
                raise RecoveryError(
                    f"wallet {wallet_id!r} dkg session {dkg_id!r} has a "
                    "malformed replace failover replacement"
                )
            if prev_state not in ("commit", "share"):
                raise RecoveryError(
                    f"wallet {wallet_id!r} dkg session {dkg_id!r} replaces "
                    "a node outside the commit/share stage"
                )
            node_ids = [n for n, _ in prev_round["nodes"]]
            if node not in node_ids:
                raise RecoveryError(
                    f"wallet {wallet_id!r} dkg session {dkg_id!r} replaces "
                    "a node that is not active"
                )
            if replacement in node_ids:
                raise RecoveryError(
                    f"wallet {wallet_id!r} dkg session {dkg_id!r} replaces "
                    "with a node that is not free"
                )
            if is_auto:
                # 以事件提交前最近健康快照核验自动选择：node 当时
                # down|ban；候选为非参与且 up 的节点，取 ID 升序首个，
                # 记录的 replacement/key 必须与该候选完全一致。快照缺失、
                # node 缺记录/未故障、无候选或记录不符都不可对账。
                if health_before is None:
                    raise RecoveryError(
                        f"wallet {wallet_id!r} dkg session {dkg_id!r} has "
                        "an auto failover without a prior node_state "
                        "snapshot"
                    )
                failed_entry = health_before.get(node)
                if not isinstance(failed_entry, dict) or failed_entry.get(
                    "state"
                ) not in ("down", "ban"):
                    raise RecoveryError(
                        f"wallet {wallet_id!r} dkg session {dkg_id!r} auto "
                        "failover node is not down or banned in the prior "
                        "health snapshot"
                    )
                candidates = [
                    cand
                    for cand in sorted(health_before)
                    if cand not in node_ids
                    and isinstance(health_before[cand], dict)
                    and health_before[cand].get("state") == "up"
                ]
                if not candidates:
                    raise RecoveryError(
                        f"wallet {wallet_id!r} dkg session {dkg_id!r} auto "
                        "failover has no eligible up replacement node"
                    )
                chosen = candidates[0]
                if replacement != chosen:
                    raise RecoveryError(
                        f"wallet {wallet_id!r} dkg session {dkg_id!r} auto "
                        "failover replacement does not match the first up "
                        "non-participant node"
                    )
                chosen_entry = health_before.get(chosen)
                if (
                    not isinstance(chosen_entry, dict)
                    or chosen_entry.get("key") != key
                ):
                    raise RecoveryError(
                        f"wallet {wallet_id!r} dkg session {dkg_id!r} auto "
                        "failover key does not match the chosen node's key"
                    )
            new_nodes = [
                (replacement, key) if n == node else (n, k)
                for n, k in prev_round["nodes"]
            ]
            if details["state"] != "commit":
                raise RecoveryError(
                    f"wallet {wallet_id!r} dkg session {dkg_id!r} "
                    "failover state does not match the replaced round"
                )
            new_round = {
                "round": round_no,
                "nodes": new_nodes,
                "commits": {},
                "shared": {},
                "state": "commit",
            }
        else:
            raise RecoveryError(
                f"wallet {wallet_id!r} dkg session {dkg_id!r} has an "
                "unknown failover action"
            )
        return new_round, committed

    def _replay_dkg_round(
        self,
        wallet_id: str,
        dkg_id: str,
        round_no: int,
        events: list[dict],
        seed: dict | None,
    ) -> dict:
        """按 seq 升序重放某轮次的 dkg_stage 事件并严格校验。

        seed 为 None 时是基线轮（允许 register 建立两方）；否则为故障
        派生轮（节点槽位已由 dkg_failover 确定，不接受 register；
        aborted 轮不接受任何阶段事件）。"""
        if seed is None:
            nodes: list[tuple[str, str]] = []
            commits: dict[str, str] = {}
            shared: dict[str, tuple[str, str]] = {}
        else:
            if events and seed["state"] == "aborted":
                raise RecoveryError(
                    f"wallet {wallet_id!r} dkg session {dkg_id!r} has "
                    "stage events on an aborted round"
                )
            nodes = list(seed["nodes"])
            commits = dict(seed["commits"])
            shared = dict(seed["shared"])
        for event in events:
            if (
                event.get("actor_id") is not None
                or event.get("reason") is not None
            ):
                raise RecoveryError(
                    f"wallet {wallet_id!r} dkg session {dkg_id!r} has a "
                    "dkg_stage event with actor/reason set"
                )
            details = event.get("details")
            if not isinstance(details, dict) or set(details) != {
                "id",
                "op",
                "node",
                "key",
                "hash",
                "peer",
                "state",
            }:
                raise RecoveryError(
                    f"wallet {wallet_id!r} dkg session {dkg_id!r} has a "
                    "malformed dkg_stage event"
                )
            if details["id"] != dkg_id:
                raise RecoveryError(
                    f"wallet {wallet_id!r} dkg_stage event id does not "
                    "match its request_id"
                )
            op = details["op"]
            node = details["node"]
            key = details["key"]
            hash_value = details["hash"]
            peer = details["peer"]
            if op not in DKG_OPS:
                raise RecoveryError(
                    f"wallet {wallet_id!r} dkg session {dkg_id!r} has an "
                    "unknown op"
                )
            if seed is not None and op == "register":
                raise RecoveryError(
                    f"wallet {wallet_id!r} dkg session {dkg_id!r} has a "
                    "register event on a derived round"
                )
            if not isinstance(node, str) or not ROTATION_ID_RE.match(node):
                raise RecoveryError(
                    f"wallet {wallet_id!r} dkg session {dkg_id!r} has a "
                    "malformed node"
                )
            node_ids = [n for n, _ in nodes]
            if op == "register":
                if (
                    not _is_lower_hex_32(key)
                    or hash_value is not None
                    or peer is not None
                ):
                    raise RecoveryError(
                        f"wallet {wallet_id!r} dkg session {dkg_id!r} has a "
                        "malformed register event"
                    )
                if node in node_ids or len(nodes) == 2:
                    raise RecoveryError(
                        f"wallet {wallet_id!r} dkg session {dkg_id!r} has a "
                        "contradictory register sequence"
                    )
                nodes.append((node, key))
            elif op == "commit":
                if (
                    key is not None
                    or not _is_lower_hex_32(hash_value)
                    or peer is not None
                ):
                    raise RecoveryError(
                        f"wallet {wallet_id!r} dkg session {dkg_id!r} has a "
                        "malformed commit event"
                    )
                if (
                    len(nodes) != 2
                    or node not in node_ids
                    or node in commits
                ):
                    raise RecoveryError(
                        f"wallet {wallet_id!r} dkg session {dkg_id!r} has a "
                        "contradictory commit sequence"
                    )
                commits[node] = hash_value
            else:  # share
                if (
                    key is not None
                    or not _is_lower_hex_32(hash_value)
                    or not isinstance(peer, str)
                    or not ROTATION_ID_RE.match(peer)
                ):
                    raise RecoveryError(
                        f"wallet {wallet_id!r} dkg session {dkg_id!r} has a "
                        "malformed share event"
                    )
                if (
                    len(nodes) != 2
                    or len(commits) != 2
                    or node not in node_ids
                    or node in shared
                ):
                    raise RecoveryError(
                        f"wallet {wallet_id!r} dkg session {dkg_id!r} has a "
                        "contradictory share sequence"
                    )
                if peer == node or peer not in node_ids:
                    raise RecoveryError(
                        f"wallet {wallet_id!r} dkg session {dkg_id!r} share "
                        "event has an invalid peer"
                    )
                if commits[peer] != hash_value:
                    raise RecoveryError(
                        f"wallet {wallet_id!r} dkg session {dkg_id!r} share "
                        "hash does not match the peer commitment"
                    )
                shared[node] = (hash_value, peer)
            state = self._dkg_state(nodes, commits, shared)
            if details["state"] != state:
                raise RecoveryError(
                    f"wallet {wallet_id!r} dkg session {dkg_id!r} event "
                    "state does not match the replayed stage"
                )
        if seed is not None and seed["state"] == "aborted":
            state = "aborted"
        else:
            state = self._dkg_state(nodes, commits, shared)
        return {
            "round": round_no,
            "nodes": nodes,
            "commits": commits,
            "shared": shared,
            "state": state,
        }

    @staticmethod
    def _parse_round_param(round_param: object) -> int:
        """解析 ?round= 查询参数：须为规范十进制正整数，否则 400。"""
        if (
            not isinstance(round_param, str)
            or not round_param.isascii()
            or not round_param.isdigit()
        ):
            raise ServiceError(400, "round must be a positive integer")
        try:
            round_no = int(round_param)
        except ValueError:
            raise ServiceError(400, "round must be a positive integer")
        if round_no < 1 or str(round_no) != round_param:
            raise ServiceError(400, "round must be a positive integer")
        return round_no

    def _resolve_dkg_round(
        self, session: dict | None, round_param: object
    ) -> int:
        """把 ?round= 参数解析为要操作的轮次号。

        无任何故障轮次时 P 无需参照轮次（行为与旧版一致，显式
        ?round=1 亦接受）；存在故障轮次后必须显式给出当前轮：缺参
        409、旧轮 409、未知轮 404、非法参数 400。"""
        requested = (
            self._parse_round_param(round_param)
            if round_param is not None
            else None
        )
        if session is None:
            # 会话尚不存在：仅 register 可经第 1 轮创建
            if requested is None or requested == 1:
                return 1
            raise ServiceError(404, f"round {requested} not found")
        current = session["current"]
        if requested is None:
            if current > 1:
                raise ServiceError(
                    409, "round query parameter is required"
                )
            return 1
        if requested > current:
            raise ServiceError(404, f"round {requested} not found")
        if requested < current:
            raise ServiceError(
                409, f"round {requested} is not the current round"
            )
        return requested

    def get_dkg_session(
        self, wallet_id: str, dkg_id: str, round_param: object = None
    ) -> dict:
        """查询 DKG 会话当前轮视图；钱包/会话未知 404，dkg id 非法 400。

        存在故障轮次后必须带 ?round= 当前轮（缺参/旧轮 409、未知轮
        404、非法 400）；aborted 轮一律 409。"""
        try:
            with self._wallet_lock(wallet_id):
                self._heal_wallet(wallet_id)
                # 404 优先于 400：锁内先判定钱包存在性
                self._get_wallet_or_404(wallet_id)
                self._validate_dkg_id(dkg_id)
                session = self._dkg_sessions(wallet_id).get(dkg_id)
                if session is None:
                    raise ServiceError(
                        404, f"dkg session {dkg_id!r} not found"
                    )
                round_no = self._resolve_dkg_round(session, round_param)
                if session["rounds"][round_no]["state"] == "aborted":
                    raise ServiceError(
                        409,
                        f"dkg session {dkg_id!r} round {round_no} is "
                        "aborted",
                    )
                return self._dkg_view(session, round_no)
        except CorruptDataError:
            raise
        except ValueError:
            # wallet_id 含非法字符（构造锁路径时抛出）
            raise ServiceError(400, "invalid wallet_id")

    def post_dkg_stage(
        self,
        wallet_id: str,
        dkg_id: object,
        op: object,
        node: object,
        key: object,
        hash_value: object,
        peer: object,
        round_param: object = None,
    ) -> tuple[int, dict]:
        """推进两方 DKG 会话当前轮一个阶段，返回 (状态码, 会话视图)。

        - 钱包未知 404；非 register 的未知会话 404；参数非法 400；
        - 首提 201；同值重放 200（优先于阶段判定）；异值/错阶段/第三
          节点 409；
        - 双方依序推进 register→commit→share→done：register 仅 key
          非 null（64 位小写 hex），commit 仅 hash 非 null（64 位小写
          sha256），share 仅 hash/peer 非 null 且 hash 等于 peer 承诺
          （份额链下交换，后端不收正文）；
        - 存在故障轮次后必须带 ?round= 当前轮（缺参/旧轮 409、未知轮
          404、非法 400）；aborted 轮一律 409；派生轮不接受 register，
          commit/share 沿用旧约；
        - dkg_stage 事件（request_id 为会话 id 或 ``<id>/<轮次>``，
          details 依次 id,op,node,key,hash,peer,state，未用值 null）
          是唯一持久化与提交点：首提在跨进程事务锁内追加，重放不记；
          事件之外不写任何状态，崩溃后由事件序列重建。
        """
        try:
            with self._wallet_lock(wallet_id):
                self._heal_wallet(wallet_id)
                # 404 优先于 400：锁内先判定钱包存在性
                self._get_wallet_or_404(wallet_id)
                self._assert_wallet_active_locked(wallet_id)
                self._validate_dkg_id(dkg_id)
                if op not in DKG_OPS:
                    raise ServiceError(
                        400,
                        "op must be one of " + ", ".join(DKG_OPS),
                    )
                self._validate_dkg_node(node)
                if op == "register":
                    if not _is_lower_hex_32(key):
                        raise ServiceError(
                            400, "key must be 64 lowercase hex characters"
                        )
                    if hash_value is not None or peer is not None:
                        raise ServiceError(
                            400, "register accepts only a non-null key"
                        )
                elif op == "commit":
                    if not _is_lower_hex_32(hash_value):
                        raise ServiceError(
                            400, "hash must be 64 lowercase hex characters"
                        )
                    if key is not None or peer is not None:
                        raise ServiceError(
                            400, "commit accepts only a non-null hash"
                        )
                else:  # share
                    if not _is_lower_hex_32(hash_value):
                        raise ServiceError(
                            400, "hash must be 64 lowercase hex characters"
                        )
                    if key is not None:
                        raise ServiceError(
                            400, "share accepts only non-null hash and peer"
                        )
                    self._validate_dkg_node(peer)
                sessions = self._dkg_sessions(wallet_id)
                session = sessions.get(dkg_id)
                if session is None:
                    if op != "register":
                        # 非 register 的未知流程 404
                        raise ServiceError(
                            404, f"dkg session {dkg_id!r} not found"
                        )
                    round_no = self._resolve_dkg_round(None, round_param)
                    session = {
                        "id": dkg_id,
                        "rounds": {
                            1: {
                                "round": 1,
                                "nodes": [],
                                "commits": {},
                                "shared": {},
                                "state": "register",
                            }
                        },
                        "current": 1,
                        "failovers": {},
                    }
                else:
                    round_no = self._resolve_dkg_round(session, round_param)
                round_state = session["rounds"][round_no]
                if round_state["state"] == "aborted":
                    # aborted 轮一律 409
                    raise ServiceError(
                        409,
                        f"dkg session {dkg_id!r} round {round_no} is "
                        "aborted",
                    )
                if round_no >= 2 and op == "register":
                    # 派生轮的节点槽位由故障轮次确定，不接受 register
                    raise ServiceError(
                        409,
                        f"dkg session {dkg_id!r} round {round_no} does "
                        "not accept register",
                    )
                if op == "register":
                    registered = dict(round_state["nodes"])
                    if node in registered:
                        # 同值重放 200 优先；异值 409
                        if registered[node] != key:
                            raise ServiceError(
                                409,
                                f"node {node!r} already registered a "
                                "different key",
                            )
                        return 200, self._dkg_view(session, round_no)
                    if len(round_state["nodes"]) >= 2:
                        # 已有两方后的新注册即第三节点
                        raise ServiceError(
                            409,
                            f"dkg session {dkg_id!r} already has "
                            "two nodes",
                        )
                else:
                    node_ids = [n for n, _ in round_state["nodes"]]
                    if op == "commit":
                        if node in round_state["commits"]:
                            # 同值重放 200 优先；异值 409
                            if round_state["commits"][node] != hash_value:
                                raise ServiceError(
                                    409,
                                    f"node {node!r} already committed a "
                                    "different hash",
                                )
                            return 200, self._dkg_view(session, round_no)
                        if node not in node_ids:
                            raise ServiceError(
                                409, f"node {node!r} is not a participant"
                            )
                        if round_state["state"] != "commit":
                            raise ServiceError(
                                409,
                                f"dkg session {dkg_id!r} is not in the "
                                "commit stage",
                            )
                    else:  # share
                        if node in round_state["shared"]:
                            # 同值重放 200 优先；异值 409
                            if round_state["shared"][node] != (
                                hash_value,
                                peer,
                            ):
                                raise ServiceError(
                                    409,
                                    f"node {node!r} already shared with "
                                    "different parameters",
                                )
                            return 200, self._dkg_view(session, round_no)
                        if node not in node_ids:
                            raise ServiceError(
                                409, f"node {node!r} is not a participant"
                            )
                        if round_state["state"] != "share":
                            raise ServiceError(
                                409,
                                f"dkg session {dkg_id!r} is not in the "
                                "share stage",
                            )
                        if peer == node or peer not in node_ids:
                            raise ServiceError(
                                409, f"peer {peer!r} is not the other node"
                            )
                        if round_state["commits"][peer] != hash_value:
                            raise ServiceError(
                                409,
                                "hash does not match the peer commitment",
                            )
                # 首次提交：应用阶段推进并以 dkg_stage 事件为唯一提交点
                # （在跨进程事务锁内追加；事件之外无任何状态落盘，崩溃后
                # 由事件序列重建，无需回滚）。
                if op == "register":
                    round_state["nodes"].append((node, key))
                elif op == "commit":
                    round_state["commits"][node] = hash_value
                else:
                    round_state["shared"][node] = (hash_value, peer)
                round_state["state"] = self._dkg_state(
                    round_state["nodes"],
                    round_state["commits"],
                    round_state["shared"],
                )
                request_id = (
                    dkg_id if round_no == 1 else f"{dkg_id}/{round_no}"
                )
                self._emit(
                    wallet_id,
                    self._audit_event(
                        audit.TYPE_DKG_STAGE,
                        request_id=request_id,
                        details={
                            "id": dkg_id,
                            "op": op,
                            "node": node,
                            "key": key,
                            "hash": hash_value,
                            "peer": peer,
                            "state": round_state["state"],
                        },
                    ),
                )
                return 201, self._dkg_view(session, round_no)
        except CorruptDataError:
            raise
        except ValueError:
            # wallet_id 含非法字符（构造锁路径时抛出）
            raise ServiceError(400, "invalid wallet_id")

    def post_dkg_failover(
        self,
        wallet_id: str,
        dkg_id: object,
        round_no: object,
        action: object,
        node: object,
        replacement: object,
        key: object,
        approval_request_id: object = _NO_APPROVAL,
    ) -> tuple[int, dict]:
        """为两方 DKG 会话提交一个故障轮次，返回 (状态码, 新轮视图)。

        - 钱包/会话未知 404；参数非法 400；
        - 首轮故障基于基线轮，后续基于当前轮：round 必须恰为当前轮 +1；
        - 首提 201；同参重放 200（优先于状态判定）；异参 409；
        - abort 仅限非终态轮，node/replacement/key 必须全为 null，
          派生轮为 aborted 且三数组为空；
        - replace 手工模式：replacement/key 双非 null，仅限两方已注册的
          commit|share 轮，key 为 64 位小写 hex、node 在用、
          replacement 空闲，换槽并清空 committed/shared 后回到 commit；
          一项为 null 另一项非 null 一律 400；
        - replace 自动替补（auto）：replacement/key 双 null 即请求自动
          选择，且首提要求故障审批开关关闭。当前轮须为 commit|share、
          node 在用且在当前健康表中 down|ban；取健康表中首个 up 的非
          参与节点（按节点 ID 升序）及其 key 实写替补；健康表缺失、
          node 未故障或无候选 409。auto 事件 details 为既有七键加末键
          mode（mode=auto），replacement/key 写实值；
        - auto 重放：同 round/action/node 的双 null 请求优先 200 返回
          视图，不查审批开关、审批单、健康表、候选与阶段（审批事后开启
          亦同）；其余一律 409；
        - reinstate：请求体恰为旧五键及 approval_request_id 六键（审批
          开关**不豁免**——关闭时同样强制），沿用 replace 的换槽派生，
          但 replacement 额外须为已提交 node_rejoined 事件对应的当前 up
          空闲节点、key 与健康表一致；审批单须同钱包 approved、message
          逐字为 dkg_id 后接 K=(round,action,node,replacement,key) 的
          紧凑 JSON。未批准/message 不符/未 rejoin/非 up/key 不符/阶段
          槽位不满足均 409；
        - reinstate 重放：须六字段（K 及 approval_request_id）全同才
          200（优先于状态与审批判定，不复查审批单现状）；更换审批单或
          任一值一律 409；
        - 故障审批策略（仅由 dkg_failover_policy_updated 事件恢复，缺省
          关闭）：禁用时沿用旧五键；启用时恰收旧五键及安全标识
          approval_request_id，该单须为同钱包既有且 approved 的审批单，
          message 逐字为既定紧凑 JSON（轮次即本次 round）。未知/挂起/
          拒绝/过期/非 approved、message 不符或轮次已变化均 409 且
          DKG 状态不变；已提交故障的旧五键同参重放优先 200、不复查
          审批（reinstate 不在此列，恒按六字段重放）；
        - dkg_failover 事件（request_id 为 ``<id>/<轮次>``，手工 details
          依次 id,round,action,node,replacement,key,state，auto 末尾加
          mode）：abort/replace（含 auto）actor_id 为 null、不含审批
          标识；唯独 reinstate 的 actor_id=approval_request_id 非 null、
          state=commit，恢复按 actor_id 复核同钱包审批单。事件是唯一
          持久化与提交点：首提在跨进程事务锁内追加，重放不记；事件之外
          不写任何状态，崩溃后由事件序列重建。
        """
        try:
            with self._wallet_lock(wallet_id):
                self._heal_wallet(wallet_id)
                # 404 优先于 400：锁内先判定钱包存在性
                self._get_wallet_or_404(wallet_id)
                self._assert_wallet_active_locked(wallet_id)
                self._validate_dkg_id(dkg_id)
                if (
                    not isinstance(round_no, int)
                    or isinstance(round_no, bool)
                    or round_no < 1
                ):
                    raise ServiceError(
                        400, "round must be a positive integer"
                    )
                if action not in DKG_FAILOVER_ACTIONS:
                    raise ServiceError(
                        400,
                        "action must be one of "
                        + ", ".join(DKG_FAILOVER_ACTIONS),
                    )
                auto_request = False
                reinstate_request = action == "reinstate"
                if action == "abort":
                    if (
                        node is not None
                        or replacement is not None
                        or key is not None
                    ):
                        raise ServiceError(
                            400,
                            "abort accepts only null node, replacement "
                            "and key",
                        )
                elif reinstate_request:
                    # reinstate 沿用 replace 的手工双实值形态：node/
                    # replacement 为安全标识、key 为 64 位小写 hex，且不
                    # 支持双 null 自动替补（是否对应已 rejoin 的当前 up
                    # 空闲节点在锁内按现场判定）。
                    self._validate_dkg_node(node)
                    self._validate_dkg_node(replacement)
                    if not _is_lower_hex_32(key):
                        raise ServiceError(
                            400,
                            "key must be 64 lowercase hex characters",
                        )
                else:  # replace
                    self._validate_dkg_node(node)
                    both_null = replacement is None and key is None
                    both_set = replacement is not None and key is not None
                    if not (both_null or both_set):
                        # 一项 null 另一项非 null：非法
                        raise ServiceError(
                            400,
                            "replace requires replacement and key both set "
                            "or both null (null means automatic failover)",
                        )
                    if both_null:
                        auto_request = True
                    else:
                        self._validate_dkg_node(replacement)
                        if not _is_lower_hex_32(key):
                            raise ServiceError(
                                400,
                                "key must be 64 lowercase hex characters",
                            )
                sessions = self._dkg_sessions(wallet_id)
                session = sessions.get(dkg_id)
                if session is None:
                    raise ServiceError(
                        404, f"dkg session {dkg_id!r} not found"
                    )
                # 已提交故障轮次的同参重放优先 200 且不复查。
                # - auto（双 null）：仅比对 action/node 且已提交事件须为
                #   auto；不查审批开关/审批单、健康表、候选与阶段，审批
                #   事后开启亦同；不符一律 409。
                # - reinstate：恰比对六字段（action/node/replacement/key
                #   与 approval_request_id），全同方 200、不复查审批单
                #   现状；更换审批单或任一值一律 409。
                # - 手工 abort/replace（双实值）：比对四值，且仅对同类手工
                #   已提交事件成立；approval_request_id 不参与重放比对。
                committed = session["failovers"].get(round_no)
                if committed is not None:
                    if auto_request:
                        if (
                            committed.get("mode") == "auto"
                            and committed["action"] == action
                            and committed["node"] == node
                        ):
                            return 200, self._dkg_view(session, round_no)
                        raise ServiceError(
                            409,
                            f"round {round_no} already failed over with "
                            "different parameters",
                        )
                    if reinstate_request:
                        if (
                            committed.get("mode") is None
                            and committed["action"] == "reinstate"
                            and committed["node"] == node
                            and committed["replacement"] == replacement
                            and committed["key"] == key
                            and committed.get("approval")
                            == approval_request_id
                        ):
                            return 200, self._dkg_view(session, round_no)
                        raise ServiceError(
                            409,
                            f"round {round_no} already failed over with "
                            "different parameters",
                        )
                    if (
                        committed.get("mode") is None
                        and committed["action"] == action
                        and committed["node"] == node
                        and committed["replacement"] == replacement
                        and committed["key"] == key
                    ):
                        return 200, self._dkg_view(session, round_no)
                    raise ServiceError(
                        409,
                        f"round {round_no} already failed over with "
                        "different parameters",
                    )
                approval_required = self._effective_dkg_failover_enabled_locked(
                    wallet_id
                )
                # reinstate 不享受审批开关豁免：开关关闭时仍必须带同钱包
                # approved 审批单（其 rejoin 已走过一次审批，换入是又一次
                # 授权动作）。
                needs_approval = approval_required or reinstate_request
                # 首提路径才按当前策略校验请求体键集：
                # - 手工 + 审批启用 / reinstate（恒须审批）：恰收六键，
                #   approval_request_id 为安全标识（缺失/非法 400），随后走
                #   审批门控；
                # - auto（双 null）+ 审批启用：请求体形态合法但自动替补
                #   首提要求审批关，属策略违例，409 且不落事件；
                # - 审批关闭且非 reinstate：夹带 approval_request_id 一律
                #   400（手工/auto 皆然）。
                if approval_required and auto_request:
                    raise ServiceError(
                        409,
                        "automatic failover requires the DKG failover "
                        "approval policy to be disabled",
                    )
                if needs_approval and not auto_request:
                    if (
                        not isinstance(approval_request_id, str)
                        or not ROTATION_ID_RE.match(approval_request_id)
                    ):
                        raise ServiceError(
                            400,
                            "approval_request_id must match "
                            "[A-Za-z0-9_-]{1,128}",
                        )
                elif (
                    not needs_approval
                    and approval_request_id is not self._NO_APPROVAL
                ):
                    raise ServiceError(
                        400,
                        "body must contain exactly round, action, node, "
                        "replacement and key",
                    )
                current = session["current"]
                if needs_approval and not auto_request:
                    # 审批门控（sign-requests 契约：可能懒过期并原子记一次
                    # request_expired）：未知/挂起/拒绝/过期/非 approved、
                    # message 不符或轮次已变化均 409，且不落事件、不改 DKG
                    # 现场。
                    try:
                        approval_record = self._store.get_request(
                            wallet_id, approval_request_id
                        )
                    except ValueError:
                        raise ServiceError(
                            400, "invalid approval_request_id"
                        )
                    if approval_record is None:
                        raise ServiceError(
                            409,
                            f"approval request {approval_request_id!r} "
                            "not found",
                        )
                    approval_record = self._expire_if_needed(
                        wallet_id, approval_record
                    )
                    expected_message = self._dkg_failover_approval_message(
                        dkg_id, round_no, action, node, replacement, key
                    )
                    if approval_record["message"] != expected_message:
                        raise ServiceError(
                            409,
                            "approval request message does not match this "
                            "failover",
                        )
                    if approval_record["state"] != "approved":
                        raise ServiceError(
                            409,
                            f"approval request {approval_request_id!r} is "
                            f"{approval_record['state']}, not approved",
                        )
                if round_no != current + 1:
                    # 审批通过但轮次已变化：409 且不变
                    raise ServiceError(
                        409, f"round must be {current + 1}"
                    )
                current_round = session["rounds"][current]
                state = current_round["state"]
                # mode 仅 auto replace 为 "auto"；abort/手工为 None。
                mode = None
                if action == "abort":
                    if state in ("done", "aborted"):
                        raise ServiceError(
                            409,
                            f"dkg session {dkg_id!r} round {current} is "
                            "terminal",
                        )
                    new_round = {
                        "round": round_no,
                        "nodes": [],
                        "commits": {},
                        "shared": {},
                        "state": "aborted",
                    }
                elif reinstate_request:
                    # reinstate：沿用 replace 的换槽派生（限 commit|share、
                    # node 在用、replacement 空闲），但 replacement 额外须
                    # 为已提交 node_rejoined 事件对应的**当前 up** 空闲节
                    # 点，且 key 与该节点健康表公钥一致。任一不满足 409，
                    # 不落事件、DKG 现场不变。
                    if state not in ("commit", "share"):
                        raise ServiceError(
                            409,
                            "reinstate requires the current round to be in "
                            "the commit or share stage",
                        )
                    node_ids = [n for n, _ in current_round["nodes"]]
                    if node not in node_ids:
                        raise ServiceError(
                            409,
                            f"node {node!r} is not active in the "
                            "current round",
                        )
                    if replacement in node_ids:
                        raise ServiceError(
                            409,
                            f"replacement {replacement!r} is not free",
                        )
                    health = self._health_table_folding_rejoins_locked(
                        wallet_id
                    )
                    if health is None:
                        raise ServiceError(
                            409,
                            "reinstate requires a configured node health "
                            "table",
                        )
                    reinstate_entry = health.get(replacement)
                    if not isinstance(reinstate_entry, dict) or (
                        reinstate_entry.get("state") != "up"
                    ):
                        raise ServiceError(
                            409,
                            f"replacement {replacement!r} is not a current "
                            "up node",
                        )
                    if reinstate_entry.get("key") != key:
                        raise ServiceError(
                            409,
                            "reinstate key does not match the replacement "
                            "node's key",
                        )
                    rejoined_nodes = {
                        event["details"]["node"]
                        for grouped in self._audit.node_rejoined_events(
                            wallet_id
                        ).values()
                        for event in grouped
                    }
                    if replacement not in rejoined_nodes:
                        raise ServiceError(
                            409,
                            f"replacement {replacement!r} has no committed "
                            "node_rejoined event",
                        )
                    new_round = {
                        "round": round_no,
                        "nodes": [
                            (replacement, key) if n == node else (n, k)
                            for n, k in current_round["nodes"]
                        ],
                        "commits": {},
                        "shared": {},
                        "state": "commit",
                    }
                else:  # replace
                    if state not in ("commit", "share"):
                        raise ServiceError(
                            409,
                            "replace requires the current round to be in "
                            "the commit or share stage",
                        )
                    node_ids = [n for n, _ in current_round["nodes"]]
                    if node not in node_ids:
                        raise ServiceError(
                            409,
                            f"node {node!r} is not active in the "
                            "current round",
                        )
                    if auto_request:
                        # 自动替补：用当前**生效**健康表（最新 node_state
                        # 快照折叠其后的 node_rejoined 翻转；恢复核验改用
                        # 事件提交前快照）选择。node 在用且 down|ban，候选
                        # 为非参与且 up 的节点，取 ID 升序首个并实写其
                        # key。健康表缺失/node 未故障/无候选一律 409，不落
                        # 事件、DKG 现场不变。
                        health = self._health_table_folding_rejoins_locked(
                            wallet_id
                        )
                        if health is None:
                            raise ServiceError(
                                409,
                                "automatic failover requires a configured "
                                "node health table",
                            )
                        failed_entry = health.get(node)
                        if not isinstance(failed_entry, dict) or (
                            failed_entry.get("state") not in ("down", "ban")
                        ):
                            raise ServiceError(
                                409,
                                f"node {node!r} is not down or banned in "
                                "the current node health table",
                            )
                        candidates = [
                            cand
                            for cand in sorted(health)
                            if cand not in node_ids
                            and isinstance(health[cand], dict)
                            and health[cand].get("state") == "up"
                        ]
                        if not candidates:
                            raise ServiceError(
                                409,
                                "no up non-participant node is eligible to "
                                "replace the failed node",
                            )
                        replacement = candidates[0]
                        key = health[replacement]["key"]
                        mode = "auto"
                    elif replacement in node_ids:
                        raise ServiceError(
                            409,
                            f"replacement {replacement!r} is not free",
                        )
                    new_round = {
                        "round": round_no,
                        "nodes": [
                            (replacement, key) if n == node else (n, k)
                            for n, k in current_round["nodes"]
                        ],
                        "commits": {},
                        "shared": {},
                        "state": "commit",
                    }
                # 首次提交：应用轮次派生并以 dkg_failover 事件为唯一
                # 提交点（在跨进程事务锁内追加；事件之外无任何状态落盘，
                # 崩溃后由事件序列重建，无需回滚）。
                details = {
                    "id": dkg_id,
                    "round": round_no,
                    "action": action,
                    "node": node,
                    "replacement": replacement,
                    "key": key,
                    "state": new_round["state"],
                }
                # auto 替补在既有七键末尾加 mode（=auto）；手工/旧事件为
                # 既有七键，恢复按精确键集区分、只对手工事件走手工恢复。
                if action == "replace" and mode == "auto":
                    details["mode"] = "auto"
                # 仅 reinstate 的 actor_id 非 null（=审批单标识）；
                # abort/replace（含 auto）恒为 null。恢复按 actor_id 复核
                # reinstate 审批单。
                actor_id = (
                    approval_request_id if reinstate_request else None
                )
                session["rounds"][round_no] = new_round
                session["current"] = round_no
                session["failovers"][round_no] = {
                    "action": action,
                    "node": node,
                    "replacement": replacement,
                    "key": key,
                    "mode": mode,
                    "approval": actor_id,
                }
                self._emit(
                    wallet_id,
                    self._audit_event(
                        audit.TYPE_DKG_FAILOVER,
                        request_id=f"{dkg_id}/{round_no}",
                        actor_id=actor_id,
                        details=details,
                    ),
                )
                return 201, self._dkg_view(session, round_no)
        except CorruptDataError:
            raise
        except ValueError:
            # wallet_id 含非法字符（构造锁路径时抛出）
            raise ServiceError(400, "invalid wallet_id")
