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

#: DKG 故障轮次允许的动作（abort 中止当前轮并派生空轮；replace 换槽派生新轮）
DKG_FAILOVER_ACTIONS = ("abort", "replace")


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

        任一钱包恢复失败（RecoveryError/OSError）都向上抛出，由调用方阻止
        服务就绪（fail-closed）：绝不静默跳过带着损坏现场对外服务。"""
        wallet_ids = sorted(
            set(self._store.list_rotation_wallet_ids())
            | set(self._store.list_staging_wallet_ids())
            | set(self._store.list_asset_intent_wallet_ids())
            | set(self._store.list_asset_ledger_wallet_ids())
            | set(self._store.list_sign_session_wallet_ids())
            | set(self._audit.list_audit_wallet_ids())
            | set(self._list_restore_txn_wallet_ids())
            | set(self._list_restore_records_wallet_ids())
        )
        for wallet_id in wallet_ids:
            with self._wallet_lock(wallet_id):
                try:
                    self._recover_wallet(wallet_id)
                except CorruptDataError as exc:
                    # 启动恢复统一以 RecoveryError 阻止就绪（fail-closed）；
                    # 损坏的审计/账本 JSON 现场原样保留，不猜写
                    raise RecoveryError(
                        f"wallet {wallet_id!r} cannot be reconciled: {exc}"
                    ) from exc

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

    def _recover_wallet(self, wallet_id: str) -> None:
        """在已持有该钱包事务锁的前提下，恢复轮换现场与未完成的资产提交。

        两者以同一把钱包锁串行，任何一个失败都向上抛出（RecoveryError/
        CorruptDataError/OSError），由调用方决定阻止就绪或把请求转成
        503，绝不静默。

        损坏 JSON / 形状异常在存储层表现为 CorruptDataError（ValueError
        子类）：损坏现场原样向上抛出，保持调用方的异常类型边界
        （损坏＝CorruptDataError、无法对账＝RecoveryError）；其余
        ValueError 同样无法对账，统一转成 RecoveryError，绝不把
        ValueError 漏给调用方当成普通参数错误。"""
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
            # 先校验资产账本（形状 + 语义）：账本损坏时任何对账都不可信，
            # 直接 fail-closed。
            self._store.check_asset_ledger_semantics(wallet_id)
            self._store.recover_wallet_rotation(
                wallet_id,
                self._activated_rotations(wallet_id),
                self._prepared_rotations(wallet_id),
            )
            self._recover_wallet_asset_commits(wallet_id)
            # 意图清零后再做账本 ↔ asset_operation_committed 事件的双向
            # 对账：提交事件与 committed 操作必须一一对应、details 即 R。
            self._reconcile_asset_committed_events(wallet_id)
            # 链确认事件（chain_policy/chain_report）与提交门控对账：
            # 报告状态机逐事件重放，矛盾/损坏 fail-closed；纯只读。
            self._reconcile_chain_events(wallet_id)
            # 多源仲裁事件（chain_arbitration/chain_vote）与票/报告/提交
            # 三事件提交点对账：逐事件重放，矛盾/损坏 fail-closed；纯只读。
            self._reconcile_chain_arbitration_events(wallet_id)
            self._recover_sign_sessions(wallet_id)
            # DKG 会话仅由 dkg_stage 事件持久化：严格重建校验即对账，
            # 矛盾/损坏 fail-closed；对账不写任何状态、不记事件、不改 seq。
            self._dkg_sessions(wallet_id)
            # DKG 故障审批开关仅由 dkg_failover_policy_updated 事件
            # 持久化：逐事件严格校验（三 id 字段为 null、details 恰含
            # 布尔 enabled），损坏/矛盾 fail-closed；读取即对账，恢复不
            # 写任何状态、不记事件、不改 seq。
            self._dkg_failover_policy_enabled(wallet_id)
        except (RecoveryError, CorruptDataError):
            # 无法对账 / 损坏的审计或账本 JSON：保持异常类型边界向上抛出
            raise
        except (OSError, ValueError) as exc:
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
                # 链确认报告/策略事件与账本提交门控同属账本一致性：
                # 账本存在时一并按 seq 重放对账，矛盾即 fail-closed。
                self._reconcile_chain_events(wallet_id)
                # 多源仲裁票/策略事件与三事件提交点同属账本一致性：
                # 账本存在时一并按 seq 重放对账，矛盾即 fail-closed。
                self._reconcile_chain_arbitration_events(wallet_id)
            self._recover_sign_sessions(wallet_id)
        except (RecoveryError, CorruptDataError):
            # 无法对账 / 损坏的审计或账本 JSON：保持异常类型边界向上抛出
            raise
        except (OSError, ValueError) as exc:
            # 检测/对账阶段读到无法解析的现场：不能假定静止，fail-closed
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

    def _emit(self, wallet_id: str, event: dict) -> None:
        self._audit.append_event(wallet_id, event)

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
                enabled = self._dkg_failover_policy_enabled(wallet_id)
        except CorruptDataError:
            raise
        except ValueError:
            raise ServiceError(400, "invalid wallet_id")
        return {"enabled": enabled}

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
                record = self._expire_if_needed(wallet_id, record)
                return self._request_view(record)
        except CorruptDataError:
            raise
        except ValueError:
            raise ServiceError(400, "invalid wallet_id")

    # ---- 审计事件查询 ---------------------------------------------------

    #: 审计事件查询每页上限与默认条数
    AUDIT_DEFAULT_LIMIT = 1000
    AUDIT_MAX_LIMIT = 1000

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

    def get_audit_events(
        self,
        wallet_id: str,
        from_seq: object = None,
        limit: object = None,
    ) -> dict:
        """返回 {wallet_id, events}（seq 升序）。

        纯只读：不触发 pending 审批单懒过期、不写任何状态/事件、不分配
        seq。但与其他所有访问钱包状态的路由一致，必须在该钱包事务锁内
        先自愈他进程崩溃遗留的轮换/资产提交残留，再读取审计：恢复无法
        对账（RecoveryError/OSError/CorruptDataError）时由调用方转 503，
        绝不返回可能半完成的公钥/余额/version 之外的不一致现场。

        存在性判定、分页参数校验与审计读取全部在锁内：绝不先用锁外
        快照决定 404/400，也读不到并发事务半完成状态。"""
        try:
            with self._wallet_lock(wallet_id):
                self._heal_wallet(wallet_id)
                # 404 优先于 400：锁内先判定钱包存在，再校验分页参数
                self._get_wallet_or_404(wallet_id)
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
                # 只读自愈：把可恢复的崩溃现场对账到一致，但绝不记事件、
                # 绝不触发审批单懒过期。
                events = self._audit.list_events(
                    wallet_id, from_seq=seq, limit=size
                )
        except CorruptDataError:
            raise
        except ValueError:
            # wallet_id 含非法字符（构造锁路径时抛出）；from_seq/limit 的
            # 非法值已在锁内转成 ServiceError(400)
            raise ServiceError(400, "invalid wallet_id")
        return {"wallet_id": wallet_id, "events": events}

    # ---- 份额轮换 ---------------------------------------------------------

    @staticmethod
    def _rotation_view(record: dict) -> dict:
        """轮换记录对外视图（只含公钥与标识，绝不含私钥）。"""
        return {
            "rotation_id": record["rotation_id"],
            "state": record["state"],
            "share_ids": list(record["share_ids"]),
            "public_key": record["public_key"],
        }

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
                self._validate_operation_id(operation_id)
                self._validate_asset_id(asset_id)
                self._validate_delta(delta)
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
        pending = intent["pending"]
        asset_id = intent["asset_id"]
        old_asset = intent["old_asset"]
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
        # 策略取该资产最后一条仲裁策略（与在线一致）；逐历史票重放校验。
        arb_policies: dict[str, dict] = {}
        for event in self._audit.events_by_type(
            wallet_id, audit.TYPE_CHAIN_ARBITRATION
        ):
            asset_id, policy = self._arbitration_policy_shape(wallet_id, event)
            arb_policies[asset_id] = policy
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

    def commit_asset_operation(
        self, wallet_id: str, operation_id: str
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

        恢复检查、钱包存在性、operation_id 校验、幂等/状态判定与整个
        提交事务全部在锁内：绝不基于锁外快照决定 404/409 或重放。
        """
        try:
            return self._commit_asset_operation_tx(wallet_id, operation_id)
        except CorruptDataError:
            raise
        except ValueError:
            # wallet_id 含非法字符（构造锁路径时抛出）
            raise ServiceError(400, "invalid wallet_id")

    def _commit_asset_operation_tx(
        self, wallet_id: str, operation_id: str
    ) -> tuple[int, dict]:
        with self._wallet_lock(wallet_id):
            # 先自愈他进程崩溃遗留的任何提交意图，再基于一致账本判定，
            # 绝不基于半完成状态提交。
            self._heal_wallet(wallet_id)
            # 404 优先于 400：锁内先判定钱包存在，再校验 operation_id
            self._get_wallet_or_404(wallet_id)
            self._validate_operation_id(operation_id)

            record = self._store.get_asset_operation(wallet_id, operation_id)
            if record is None:
                raise ServiceError(
                    404, f"asset operation {operation_id!r} not found"
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

    def _commit_asset_operation_locked(
        self,
        wallet_id: str,
        operation_id: str,
        record: dict,
        report_details: dict | None = None,
        vote_details: dict | None = None,
    ) -> dict:
        """在每钱包事务锁内提交一条 pending 操作，返回 committed 视图 R。

        调用方须已持锁、已 heal、已判定 record 为 pending。事务顺序：

            1. 写提交意图（记录 committed 结果 R 与提交前资产快照；
               报告触发的提交另随附达门槛报告 B，多源仲裁触发的提交
               另随附达成 quorum 的 adopted 票）
            2. 原子提交账本：操作转 committed、balance 改、version+1
            3. 追加提交事件（report_details/vote_details 非 None 时，
               触发事件 chain_report/chain_vote 与
               asset_operation_committed 两事件同批一次原子落盘，
               seq 为 n、n+1，触发事件在先）
            4. 删除提交意图

        链上确认报告达门槛触发的提交传入 report_details；多源仲裁
        quorum 达成触发的提交传入 vote_details（两者互斥）：触发事件
        与提交事件紧邻同批落盘，构成"触发事件后紧邻唯一提交事件"的
        单一提交点，崩溃窗口内绝不出现孤立触发事件或 seq 缺口。崩溃
        恢复以提交事件是否落盘为准：事件在则前滚补齐（并核对紧邻触发
        事件与意图随附内容一致），事件不在则整体回滚 pending 与提交前
        余额/版本。
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
            if report_details is not None or vote_details is not None:
                # 触发事件与提交事件同批一次原子落盘：要么全部在
                # （seq n、n+1、…），要么都不在，绝不留下孤立触发事件。
                # 多源仲裁达 quorum 时票事件在先、链上报告事件次之、
                # 提交事件收尾（三事件一次原子提交）。
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

    def get_asset(self, wallet_id: str, asset_id: str) -> dict:
        """查询某资产的账本状态（balance/version）。

        在每钱包事务锁内读取：提交事务进行中（账本已改、事件尚未落盘）的
        查询会被挡到事务结束，绝不会读到随后可能回滚的半完成余额。

        恢复检查、钱包存在性、asset_id 校验与余额读取全部在锁内：绝不
        先用锁外快照决定 404/400。
        """
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

    def _chain_policies(self, wallet_id: str) -> dict[str, dict]:
        """从 chain_policy 事件序列恢复各资产的链确认策略（每资产取最后一条）。

        策略只由审计事件持久化（事件之外不写任何状态文件）；畸形事件
        fail-closed（RecoveryError），绝不静默按缺省处理。纯只读，
        不分配 seq。"""
        policies: dict[str, dict] = {}
        for event in self._audit.events_by_type(
            wallet_id, audit.TYPE_CHAIN_POLICY
        ):
            asset_id, policy = self._chain_policy_shape(wallet_id, event)
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

        钱包不存在 404；标识/值非法 400（键集由 HTTP 边界校验）。策略
        仅由 chain_policy 审计事件持久化（request_id 为资产标识，
        actor_id/reason 为 null，details 即 Q），**同值更新也记事件**，
        不写任何策略状态文件。恢复检查、存在性判定、校验与事件追加全部
        在每钱包跨进程事务锁内完成。"""
        try:
            with self._wallet_lock(wallet_id):
                self._heal_wallet(wallet_id)
                # 404 优先于 400：存在性在锁内、heal 之后先判定
                self._get_wallet_or_404(wallet_id)
                self._validate_asset_id(asset_id)
                self._validate_chain_id(chain_id)
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
        - 报告必须指向账本中存在的操作，且当时该资产策略已启用、链一致；
        - 报告状态机（tx/链绑定、同块确认数不降、换块回退不超窗、低于
          门槛的同体报告不产生事件、终态后不再有报告）逐事件成立；
        - 达门槛的报告事件必须紧邻同操作的 asset_operation_committed
          （两事件同批原子落盘，孤立达门槛报告即矛盾现场）；
        - 策略启用时的资产提交事件必须紧邻一条达门槛的 chain_report
          （启用时人工提交 pending 在线被 409 拒绝，日志里出现即矛盾）。

        任一矛盾抛 RecoveryError（fail-closed，保留现场）。纯只读，
        不写状态、不记事件、不改 seq。
        """
        ledger = self._store.check_asset_ledger_semantics(wallet_id)
        operations = ledger["operations"]
        policies: dict[str, dict] = {}
        reports: dict[str, dict] = {}
        committed: set[str] = set()
        prev: dict | None = None
        events = self._audit.all_events(wallet_id)
        for index, event in enumerate(events):
            event_type = event.get("type")
            if event_type == audit.TYPE_CHAIN_POLICY:
                asset_id, policy = self._chain_policy_shape(
                    wallet_id, event
                )
                policies[asset_id] = policy
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
                        # 启用时只能经报告提交：提交事件必须紧邻一条
                        # 达门槛的 chain_report
                        trigger = (
                            prev.get("details")
                            if prev is not None
                            and prev.get("type") == audit.TYPE_CHAIN_REPORT
                            and prev.get("request_id") == operation_id
                            else None
                        )
                        if (
                            not isinstance(trigger, dict)
                            or trigger.get("confirmations")
                            < policy["required_confirmations"]
                        ):
                            raise RecoveryError(
                                f"wallet {wallet_id!r} committed asset "
                                f"operation {operation_id!r} without a "
                                "preceding threshold chain report"
                            )
                    committed.add(operation_id)
            prev = event

    # ---- 多源仲裁 ---------------------------------------------------------

    @staticmethod
    def _arbitration_policy_shape(wallet_id: str, event: dict) -> tuple[str, dict]:
        """严格校验一条 chain_arbitration 事件，返回 (资产标识, 策略 Q)。

        request_id 为资产标识（安全 id），actor_id/reason 为 null，
        details 恰含 {sources, quorum}：sources 为 ID 升序的
        ``{安全ID: bool}``（至少一个启用源），quorum 为 [2, 启用数] 内的
        非布尔整数。任何畸形都是不可对账现场（RecoveryError，fail-closed）。"""
        if (
            event.get("actor_id") is not None
            or event.get("reason") is not None
        ):
            raise RecoveryError(
                f"wallet {wallet_id!r} has a chain_arbitration event with "
                "actor/reason set"
            )
        asset_id = event.get("request_id")
        if not isinstance(asset_id, str) or not ROTATION_ID_RE.match(
            asset_id
        ):
            raise RecoveryError(
                f"wallet {wallet_id!r} has a chain_arbitration event without "
                "an asset id"
            )
        sources, quorum = WalletService._arbitration_details_shape(
            wallet_id, event.get("details"), "chain_arbitration event"
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

    def _chain_arbitration_policies(
        self, wallet_id: str
    ) -> dict[str, dict]:
        """从 chain_arbitration 事件序列恢复各资产的多源仲裁策略（每资产
        取最后一条）。策略只由审计事件持久化；畸形事件 fail-closed
        （RecoveryError）。纯只读，不分配 seq。"""
        policies: dict[str, dict] = {}
        for event in self._audit.events_by_type(
            wallet_id, audit.TYPE_CHAIN_ARBITRATION
        ):
            asset_id, policy = self._arbitration_policy_shape(wallet_id, event)
            policies[asset_id] = policy
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
        未知 404。该资产操作已有未决仲裁（collecting/conflict 票）时
        409，策略与票现场均不变。策略仅由 chain_arbitration 审计事件
        持久化（request_id 为资产标识，actor_id/reason 为 null，
        details 即 Q，每个资产取最后一条恢复），**同值更新也记事件**，
        不写策略状态文件。"""
        try:
            with self._wallet_lock(wallet_id):
                self._heal_wallet(wallet_id)
                # 404 优先于 400：存在性在锁内、heal 之后先判定
                self._get_wallet_or_404(wallet_id)
                self._validate_asset_id(asset_id)
                normalized_sources, normalized_quorum = (
                    self._validate_arbitration_body(sources, quorum)
                )
                # 未决仲裁期间冻结策略：该资产任一操作仍有
                # collecting/conflict 的票即 409（adopted 已终态）。
                pending_assets = {
                    operation_id: self._arbitration_state(op_votes)
                    for operation_id, op_votes in self._chain_votes(
                        wallet_id
                    ).items()
                }
                for operation_id, state in pending_assets.items():
                    if state not in ("collecting", "conflict"):
                        continue
                    record = self._store.get_asset_operation(
                        wallet_id, operation_id
                    )
                    if (
                        record is not None
                        and record["asset_id"] == asset_id
                    ):
                        raise ServiceError(
                            409,
                            f"asset {asset_id!r} has an unresolved "
                            "arbitration",
                        )
                policy = {
                    "sources": normalized_sources,
                    "quorum": normalized_quorum,
                }
                self._emit(
                    wallet_id,
                    self._audit_event(
                        audit.TYPE_CHAIN_ARBITRATION,
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
        503）。钱包不存在 404。"""
        try:
            with self._wallet_lock(wallet_id):
                self._heal_wallet(wallet_id)
                # 404 优先：锁内先判定钱包存在，再判定策略是否已配置
                self._get_wallet_or_404(wallet_id)
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
        """从 chain_vote 事件序列恢复各操作的票（按 seq 升序的票列表）。

        票只由审计事件持久化；畸形事件 fail-closed（RecoveryError）。
        纯只读，不分配 seq。"""
        votes: dict[str, list[dict]] = {}
        for event in self._audit.events_by_type(
            wallet_id, audit.TYPE_CHAIN_VOTE
        ):
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
        """多源仲裁事件（chain_arbitration/chain_vote）与资产提交的严格
        对账（调用方须持钱包事务锁；意图残留须已先恢复清零）。

        按 seq 重放全部事件，逐事件核对在线规则：

        - chain_arbitration/chain_vote 事件形状必须合法；
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
        events = self._audit.all_events(wallet_id)
        for index, event in enumerate(events):
            etype = event.get("type")
            if etype == audit.TYPE_CHAIN_POLICY:
                asset_id, policy = self._chain_policy_shape(wallet_id, event)
                chain_policies[asset_id] = policy
            elif etype == audit.TYPE_CHAIN_ARBITRATION:
                asset_id, policy = self._arbitration_policy_shape(
                    wallet_id, event
                )
                arb_policies[asset_id] = policy
            elif etype == audit.TYPE_CHAIN_VOTE:
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
                    # 紧邻随附报告出现，其前一条必须是同操作 adopted 票。
                    predecessor = (
                        events[index - 1] if index - 1 >= 0 else None
                    )
                    if (
                        predecessor is None
                        or predecessor.get("type") != audit.TYPE_CHAIN_VOTE
                        or predecessor.get("request_id") != operation_id
                        or predecessor.get("details", {}).get("state")
                        != "adopted"
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
                self._validate_approver_id(approver_id)
                self._validate_reason(reason)
                record = self._fetch_request_or_404(wallet_id, request_id)
                # 懒过期可能在此原子记一次 E；过期后操作落入终态分支（409、不记 A/R）
                record = self._expire_if_needed(wallet_id, record)
                if record["state"] != "pending":
                    raise ServiceError(
                        409,
                        f"signing request {request_id!r} is {record['state']}, "
                        "not pending",
                    )

                if action == "approve":
                    # 同一 approver 重复批准不计数、不记事件（幂等 200）
                    if approver_id in record["approvers"]:
                        return self._request_view(record)
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
        aggregate_signature 仅在 signed 时出现。绝不返回份额签名本身。

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
                record = self._session_expire_if_needed(wallet_id, record)
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
        """
        try:
            return self._submit_sign_session_share_tx(
                wallet_id, session_id, share_id, signature_hex
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
    ) -> tuple[int, dict]:
        with self._wallet_lock(wallet_id):
            self._heal_wallet(wallet_id)
            # 404 优先于 400：锁内先判定钱包存在性
            wallet = self._store.get_wallet(wallet_id)
            if wallet is None:
                raise ServiceError(404, f"wallet {wallet_id!r} not found")
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
          份数一致（齐份 ready，否则 collecting）；expired/signed 至多一次
          且互斥、其后不得再有事件；signed 时两份份额必已齐；created 的
          message/timeout_seconds 必须与记录一致；
        - 已存份额若无对应 share_received 事件：份额提交未完成，回滚丢弃；
          有事件却无已存份额：仅当该份额已被后续轮换激活淘汰（剔除旧份额
          的迁移）才合法，否则 fail-closed；
        - 每份已存签名用其对应历史公钥重新校验；signed 按有序快照重算
          128 字节聚合签名，必须与记录一致，否则 fail-closed；
        - signed 事件：前滚为唯一 signed；expired 事件（collecting 与
          ready 到点均可过期）：前滚 expired；否则按当前在用快照迁移并据
          已提交份额恢复 collecting/ready——磁盘误写的终态随事件回滚；
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
            else:
                raise RecoveryError(
                    f"wallet {wallet_id!r} sign session {session_id!r} has "
                    f"unknown action {action!r}"
                )

        if actions.count("signed") + actions.count("expired") > 1:
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

        # 终态冻结其提交时刻的在用快照；非终态以钱包当前在用份额为准
        # （有替换/接管事件的会话冻结于最后一次换槽后的快照，不再随轮换
        # 迁移）。
        terminal_seq = signed_seq or expired_seq
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

    def _dkg_sessions(self, wallet_id: str) -> dict[str, dict]:
        """从 dkg_stage / dkg_failover 事件重建并严格校验该钱包全部 DKG 会话。

        事件是 DKG 状态的唯一持久化与提交点：基线轮（第 1 轮）由
        request_id 为会话 id 的 dkg_stage 事件重放；每个派生轮（第
        R≥2 轮）由 request_id 为 ``<id>/<R>`` 的唯一 dkg_failover 事件
        从上一轮派生，再由同 request_id 的 dkg_stage 事件推进。任何矛盾
        （形状、字段约束、轮次缺口/重复、阶段顺序、承诺不一致、
        details.state 与重算不符）都抛 RecoveryError（fail-closed：
        常驻 503、serve 拒绝就绪），绝不静默跳过或任取一条。纯只读，
        不分配 seq、不写任何状态。"""
        stage_rounds: dict[str, dict[int, list[dict]]] = {}
        for request_id, events in self._audit.dkg_stage_events(
            wallet_id
        ).items():
            dkg_id, round_no = self._parse_dkg_request_id(
                wallet_id, request_id, failover=False
            )
            stage_rounds.setdefault(dkg_id, {}).setdefault(
                round_no, []
            ).extend(events)
        failover_rounds: dict[str, dict[int, list[dict]]] = {}
        for request_id, events in self._audit.dkg_failover_events(
            wallet_id
        ).items():
            dkg_id, round_no = self._parse_dkg_request_id(
                wallet_id, request_id, failover=True
            )
            failover_rounds.setdefault(dkg_id, {}).setdefault(
                round_no, []
            ).extend(events)
        sessions: dict[str, dict] = {}
        for dkg_id in sorted(set(stage_rounds) | set(failover_rounds)):
            sessions[dkg_id] = self._rebuild_dkg_session(
                wallet_id,
                dkg_id,
                stage_rounds.get(dkg_id, {}),
                failover_rounds.get(dkg_id, {}),
            )
        return sessions

    def _rebuild_dkg_session(
        self,
        wallet_id: str,
        dkg_id: str,
        stage_rounds: dict[int, list[dict]],
        failover_rounds: dict[int, list[dict]],
    ) -> dict:
        """按轮次链重建某 DKG 会话并严格校验。

        轮次链必须连续：基线轮（第 1 轮）必有 dkg_stage 事件；第 R≥2
        轮必有且仅有一条 dkg_failover 事件从第 R-1 轮派生。派生轮不
        接受 register，aborted 轮不接受任何阶段事件。"""
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
            new_round, committed = self._apply_dkg_failover(
                wallet_id, dkg_id, round_no, events[0], rounds[round_no - 1]
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

    def _apply_dkg_failover(
        self,
        wallet_id: str,
        dkg_id: str,
        round_no: int,
        event: dict,
        prev_round: dict,
    ) -> tuple[dict, dict]:
        """校验一条 dkg_failover 事件并从上一轮派生新轮次。

        返回 (新轮次状态, 已提交参数)。abort 仅限非终态轮、后三值
        （node/replacement/key）必须为 null，派生出 aborted 空轮；
        replace 仅限两方已注册的 commit|share 轮，key 为 64 位小写
        hex、node 在用、replacement 空闲，换槽并清空后两数组后回到
        commit。任何矛盾都抛 RecoveryError。"""
        if (
            event.get("actor_id") is not None
            or event.get("reason") is not None
        ):
            raise RecoveryError(
                f"wallet {wallet_id!r} dkg session {dkg_id!r} has a "
                "dkg_failover event with actor/reason set"
            )
        details = event.get("details")
        if not isinstance(details, dict) or set(details) != {
            "id",
            "round",
            "action",
            "node",
            "replacement",
            "key",
            "state",
        }:
            raise RecoveryError(
                f"wallet {wallet_id!r} dkg session {dkg_id!r} has a "
                "malformed dkg_failover event"
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
        prev_state = prev_round["state"]
        committed = {
            "action": action,
            "node": node,
            "replacement": replacement,
            "key": key,
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
          派生轮为 aborted 且三数组为空；replace 仅限两方已注册的
          commit|share 轮，key 为 64 位小写 hex、node 在用、
          replacement 空闲，换槽并清空 committed/shared 后回到 commit；
        - 故障审批策略（仅由 dkg_failover_policy_updated 事件恢复，缺省
          关闭）：禁用时沿用旧五键；启用时恰收旧五键及安全标识
          approval_request_id，该单须为同钱包既有且 approved 的审批单，
          message 逐字为既定紧凑 JSON（轮次即本次 round）。未知/挂起/
          拒绝/过期/非 approved、message 不符或轮次已变化均 409 且
          DKG 状态不变；已提交故障的旧五键同参重放优先 200、不复查
          审批；
        - dkg_failover 事件（request_id 为 ``<id>/<轮次>``，details
          依次 id,round,action,node,replacement,key,state，不含审批
          标识）是唯一持久化与提交点：首提在跨进程事务锁内追加，重放
          不记；事件之外不写任何状态，崩溃后由事件序列重建。
        """
        try:
            with self._wallet_lock(wallet_id):
                self._heal_wallet(wallet_id)
                # 404 优先于 400：锁内先判定钱包存在性
                self._get_wallet_or_404(wallet_id)
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
                else:  # replace
                    self._validate_dkg_node(node)
                    self._validate_dkg_node(replacement)
                    if not _is_lower_hex_32(key):
                        raise ServiceError(
                            400, "key must be 64 lowercase hex characters"
                        )
                approval_required = self._dkg_failover_policy_enabled(
                    wallet_id
                )
                sessions = self._dkg_sessions(wallet_id)
                session = sessions.get(dkg_id)
                if session is None:
                    raise ServiceError(
                        404, f"dkg session {dkg_id!r} not found"
                    )
                # 已提交故障轮次的同参重放优先 200 且不复查（不复查审批
                # 开关、approval_request_id 与审批单现状）；异参 409。
                # 重放只比对旧五键，approval_request_id 不参与：禁用/启用
                # 策略切换、审批单事后终态化都不影响已提交故障的幂等重放。
                committed = session["failovers"].get(round_no)
                if committed is not None:
                    if (
                        committed["action"] == action
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
                # 首提路径才按当前策略校验请求体键集：启用时恰收六键
                # （approval_request_id 为安全标识）；禁用时沿用旧五键。
                if approval_required:
                    if (
                        not isinstance(approval_request_id, str)
                        or not ROTATION_ID_RE.match(approval_request_id)
                    ):
                        raise ServiceError(
                            400,
                            "approval_request_id must match "
                            "[A-Za-z0-9_-]{1,128}",
                        )
                elif approval_request_id is not self._NO_APPROVAL:
                    raise ServiceError(
                        400,
                        "body must contain exactly round, action, node, "
                        "replacement and key",
                    )
                current = session["current"]
                if approval_required:
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
                    if replacement in node_ids:
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
                session["rounds"][round_no] = new_round
                session["current"] = round_no
                session["failovers"][round_no] = {
                    "action": action,
                    "node": node,
                    "replacement": replacement,
                    "key": key,
                }
                self._emit(
                    wallet_id,
                    self._audit_event(
                        audit.TYPE_DKG_FAILOVER,
                        request_id=f"{dkg_id}/{round_no}",
                        details={
                            "id": dkg_id,
                            "round": round_no,
                            "action": action,
                            "node": node,
                            "replacement": replacement,
                            "key": key,
                            "state": new_round["state"],
                        },
                    ),
                )
                return 201, self._dkg_view(session, round_no)
        except CorruptDataError:
            raise
        except ValueError:
            # wallet_id 含非法字符（构造锁路径时抛出）
            raise ServiceError(400, "invalid wallet_id")
