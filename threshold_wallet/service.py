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

import re
import threading
from datetime import datetime, timedelta, timezone

from . import audit, crypto
from .audit import AuditStore
from .flock import FileLock, wallet_lock_path
from .store import DuplicateWalletError, RecoveryError, WalletStore

#: 两方门限：份额数固定为 2
REQUIRED_SHARES = 2

#: 服务端为两个份额生成的固定标识（按此顺序聚合公钥与签名）
SHARE_IDS = ("share-1", "share-2")

#: 审批策略允许的 required_approvals 取值
ALLOWED_REQUIRED_APPROVALS = (1, 2)

#: approve/reject 附言 reason 的最大长度
MAX_REASON_LENGTH = 1024

#: rotation_id 允许的字符（与存储层安全 id 一致）
ROTATION_ID_RE = re.compile(r"^[A-Za-z0-9_-]{1,128}$")


class ServiceError(Exception):
    """业务错误，携带 HTTP 状态码与错误信息。"""

    def __init__(self, status: int, message: str) -> None:
        super().__init__(message)
        self.status = status
        self.message = message


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


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

    def __init__(self, store: WalletStore) -> None:
        self._store = store
        self._audit = AuditStore(store.data_dir)
        # 每钱包一把事务锁：串行化同一钱包的"状态变更 + 审计事件"，
        # ThreadingHTTPServer 并发下保证状态与事件原子、懒过期只记一次。
        self._wallet_locks: dict[str, threading.Lock] = {}
        self._wallet_locks_guard = threading.Lock()
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

    def _find_activation_event(self, wallet_id: str, rotation_id: str):
        """查询某轮换的激活事件是否已落盘（激活事务的唯一提交判据）。"""
        return self._audit.find_rotation_event(wallet_id, rotation_id)

    def _activation_event_lookup(self, wallet_id: str):
        """返回基于同一快照的 (wallet_id, rotation_id) -> event 查询闭包。

        一次锁内恢复要为该钱包全部轮换记录判定提交点，统一读一次审计日志
        形成 {rotation_id: event}，既避免逐条读盘，也保证各记录的判定基于
        一致的事件快照。
        """
        events = self._audit.rotation_events(wallet_id)
        return lambda wid, rid: events.get(rid)

    def _heal_wallet(self, wallet_id: str) -> None:
        """拿到钱包事务锁后、任何业务读写前：自愈他进程崩溃遗留的现场。

        - 轮换：以 share_rotation_activated 事件是否落盘为判据，把停在
          activating/active 的未完成激活回滚为 prepared，或把已提交激活
          前滚为 active 并清残留；清理孤立暂存；
        - 资产提交：对残留提交意图按资产提交事件是否落盘前滚/回滚。

        两者均不产生审计事件。无法对账（恢复失败）时抛 ServiceError(500)，
        宁可让本次操作失败也绝不向外暴露半完成状态。调用方必须已持有该
        钱包的跨进程事务锁。
        """
        try:
            self._store.recover_wallet_rotation(
                wallet_id, self._activation_event_lookup(wallet_id)
            )
            self._heal_asset_intents(wallet_id)
        except RecoveryError as exc:
            raise ServiceError(500, f"recovery failed: {exc}") from exc
        except OSError as exc:
            # 对账时磁盘不可用：本次请求失败，绝不返回可能半完成的数据
            raise ServiceError(500, f"recovery I/O failure: {exc}") from exc

    def _recover_on_startup(self) -> None:
        """启动恢复编排：逐个钱包在其跨进程事务锁内恢复轮换现场与未完成
        的资产提交事务。对外服务前必须完成，使任何查询/重放都读不到
        半完成状态。

        任一钱包恢复失败（现场无法对账为一致状态）都向上抛出
        RecoveryError，阻止 WalletService 构造完成、从而阻止服务就绪，
        绝不静默跳过。"""
        wallet_ids = sorted(
            set(self._store.list_rotation_wallet_ids())
            | set(self._store.list_staging_wallet_ids())
            | set(self._store.list_asset_intent_wallet_ids())
        )
        for wallet_id in wallet_ids:
            with self._wallet_lock(wallet_id):
                # recover_wallet_rotation 在无法调和现场时抛 RecoveryError；
                # _recover_wallet_asset_commits 对单条暂时无法处理的意图会
                # 保留并下次再对账，二者都不会静默吞掉轮换的半完成状态。
                self._store.recover_wallet_rotation(
                    wallet_id, self._activation_event_lookup(wallet_id)
                )
                self._recover_wallet_asset_commits(wallet_id)

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
                # 锁内自愈后再读：他进程崩溃在激活窗口时，绝不把半切换
                # 的公钥/份额对外暴露。
                self._heal_wallet(wallet_id)
                record = self._store.get_wallet(wallet_id)
        except ValueError:
            raise ServiceError(400, "invalid wallet_id")
        if record is None:
            raise ServiceError(404, f"wallet {wallet_id!r} not found")
        return {
            "wallet_id": record["wallet_id"],
            "public_key": record["public_key"],
            "created_at": record["created_at"],
        }

    # ---- 审批策略 -------------------------------------------------------

    def _get_wallet_or_404(self, wallet_id: str) -> dict:
        try:
            wallet = self._store.get_wallet(wallet_id)
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
            raise ServiceError(400, "timeout_seconds must be a positive integer")
        policy = {
            "wallet_id": wallet_id,
            "required_approvals": required_approvals,
            "timeout_seconds": timeout_seconds,
        }
        # 同值更新也成功并记录（operation 区分首设/更新）
        old_policy = self._store.get_policy(wallet_id)
        operation = "created" if old_policy is None else "updated"
        with self._wallet_lock(wallet_id):
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
        return policy

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
        """返回 (HTTP 状态码, 响应体)。"""
        self._get_wallet_or_404(wallet_id)
        self._validate_request_body(request_id, message)
        try:
            self._store.get_request(wallet_id, request_id)
        except ValueError:
            raise ServiceError(400, "invalid signing_request_id")
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
        with self._wallet_lock(wallet_id):
            existing = self._store.create_request(wallet_id, request_id, record)
            if existing is not None:
                # 重放（无论同文幂等还是异文 409）均不记事件、不改状态。
                # POST 不是懒过期触发点：原样返回磁盘中持久化的状态
                # （pending/approved/rejected/expired/signed），绝不在响应里
                # 把磁盘仍是 pending 的单临时呈现成 expired。
                if existing["message"] != message:
                    raise ServiceError(
                        409,
                        f"signing request {request_id!r} already exists "
                        "with a different message",
                    )
                # 同 id 同文：幂等重放
                return 200, self._request_view(existing)
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
        return 201, self._request_view(record)

    def get_sign_request(self, wallet_id: str, request_id: str) -> dict:
        self._get_wallet_or_404(wallet_id)
        with self._wallet_lock(wallet_id):
            record = self._fetch_request_or_404(wallet_id, request_id)
            record = self._expire_if_needed(wallet_id, record)
            return self._request_view(record)

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
        """返回 {wallet_id, events}（seq 升序）。纯只读：不触发懒过期。"""
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
        events = self._audit.list_events(wallet_id, from_seq=seq, limit=size)
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
        """
        self._get_wallet_or_404(wallet_id)
        self._validate_rotation_id(rotation_id)
        with self._wallet_lock(wallet_id):
            # 先自愈他进程崩溃在激活窗口的现场，再判定是否已有 prepared
            self._heal_wallet(wallet_id)
            existing = self._store.get_rotation(wallet_id, rotation_id)
            if existing is not None:
                # 幂等重放：原样返回，不重新生成、不记事件
                return 200, self._rotation_view(existing)
            for record in self._store.list_rotations(wallet_id):
                if record.get("state") in ("prepared", "activating"):
                    raise ServiceError(
                        409,
                        f"wallet {wallet_id!r} already has a prepared "
                        "share rotation",
                    )
            share_ids = [
                f"{rotation_id}-share-1",
                f"{rotation_id}-share-2",
            ]
            share_keys = [crypto.generate_share_key(sid) for sid in share_ids]
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
        return 201, self._rotation_view(record)

    def get_share_rotation(self, wallet_id: str, rotation_id: str) -> dict:
        self._get_wallet_or_404(wallet_id)
        with self._wallet_lock(wallet_id):
            # 锁内自愈：并发激活/他进程崩溃期间不会读到瞬态 activating
            # 或"active 已写但事件未落盘"的半完成状态。
            self._heal_wallet(wallet_id)
            try:
                record = self._store.get_rotation(wallet_id, rotation_id)
            except ValueError:
                raise ServiceError(400, "invalid rotation_id")
            if record is None:
                raise ServiceError(
                    404, f"share rotation {rotation_id!r} not found"
                )
            return self._rotation_view(record)

    def activate_share_rotation(
        self, wallet_id: str, rotation_id: str
    ) -> tuple[int, dict]:
        """激活一次已准备的轮换：锁内替换份额文件、钱包公钥与轮换状态。

        仅 prepared 可激活（201）；active 重放返回 200；其余状态 409。
        失败时回滚份额文件、公钥与状态并清理备份；激活成功后删除暂存。
        """
        self._get_wallet_or_404(wallet_id)
        self._validate_rotation_id(rotation_id)
        with self._wallet_lock(wallet_id):
            # 先自愈他进程崩溃在激活窗口内的现场（以激活事件是否落盘为
            # 判据），绝不基于半完成的 activating/active 状态判定。
            self._heal_wallet(wallet_id)
            record = self._store.get_rotation(wallet_id, rotation_id)
            if record is None:
                raise ServiceError(
                    404, f"share rotation {rotation_id!r} not found"
                )
            # 激活事件已落盘（恢复后记录必为 active）：幂等重放，不重复
            # 替换、不重复记事件。
            if self._find_activation_event(wallet_id, rotation_id) is not None:
                active_view = self._store.get_rotation(wallet_id, rotation_id)
                return 200, self._rotation_view(active_view)
            if record["state"] == "active":
                # active 状态在但事件不在：理论上已被锁内自愈回滚为
                # prepared；到达这里仍按非 prepared 冲突处理，不放行。
                raise ServiceError(
                    409,
                    f"share rotation {rotation_id!r} is "
                    f"{record['state']}, not prepared",
                )
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
                        409, f"wallet {wallet_id!r} share files are incomplete"
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
                {"share_id": r["share_id"], "public_key": r["public_key"]}
                for r in new_share_records
            ]
            new_meta["public_key"] = record["public_key"]
            active_record = dict(record)
            active_record["state"] = "active"
            active_record["previous_public_key"] = previous_public_key

            try:
                # 先落 activating 标记与旧份额/元数据备份：若在事件落盘
                # 前崩溃，启动/锁内恢复据此回滚为 prepared。
                activating = dict(record)
                activating["state"] = "activating"
                activating["previous_public_key"] = previous_public_key
                self._store.update_rotation(wallet_id, rotation_id, activating)
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
                # 失效点：激活事件唯一一次落盘。事件在则激活已提交。
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
                # 以事件是否真正落盘为唯一判据对账，不依赖状态文件。
                landed = self._find_activation_event(wallet_id, rotation_id)
                try:
                    if landed is not None:
                        # 事件已落盘（如落盘成功但返回阶段报错）：激活已提交，
                        # 确定性前滚为唯一 active 结果并清残留，绝不重复记事件。
                        self._store._roll_forward_activation(
                            wallet_id, active_record, landed
                        )
                        return 201, self._rotation_view(
                            self._store.get_rotation(wallet_id, rotation_id)
                        )
                    # 事件未落盘：回滚份额文件、公钥与状态为 prepared，并清理
                    # 激活备份（保留暂存的新份额文件，可重试激活）。
                    self._store._roll_back_activation(wallet_id, record)
                except RecoveryError as exc:
                    # 现场无法对账为一致状态：返回 500，绝不暴露半完成态
                    raise ServiceError(
                        500, f"activation recovery failed: {exc}"
                    ) from exc
                raise
            # 激活事件已提交：清理暂存的新份额文件与备份。此步失败不影响
            # 已提交结果——残留由下次锁内访问的自愈安全清除，不重放事件。
            try:
                self._store.delete_staging(wallet_id, rotation_id)
            except OSError:
                pass
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
        不重复记事件）；同 operation_id 异参数 409。创建本身不记审计事件。
        """
        self._get_wallet_or_404(wallet_id)
        self._validate_operation_id(operation_id)
        self._validate_asset_id(asset_id)
        self._validate_delta(delta)
        with self._wallet_lock(wallet_id):
            # 快照前先自愈他进程崩溃遗留的轮换现场与提交意图，
            # balance/version 与在用份额才准确
            self._heal_wallet(wallet_id)
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
            existing = self._store.create_asset_operation(
                wallet_id, operation_id, record
            )
            if existing is not None:
                if (
                    existing.get("asset_id") != asset_id
                    or existing.get("delta") != delta
                ):
                    raise ServiceError(
                        409,
                        f"asset operation {operation_id!r} already exists "
                        "with different parameters",
                    )
                # 同参重放：原样返回磁盘中的当前记录，不改状态、不记事件
                return 200, existing
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
        恢复本身不记任何审计事件。
        """
        for operation_id, intent in self._store.list_asset_intents(wallet_id):
            try:
                self._resolve_asset_commit_intent(wallet_id, operation_id, intent)
            except (ValueError, OSError):
                # 单条意图恢复失败不阻断同钱包其他事务；该意图保留在盘上，
                # 下次重启或该操作再次提交时在锁内自愈
                continue

    def _heal_asset_intents(self, wallet_id: str) -> None:
        """持锁后自愈他进程崩溃遗留的提交意图（懒恢复）。

        常驻进程不会重跑启动恢复；为使查询/创建/提交永远读不到他进程
        留下的半完成提交，任何资产读写在拿到钱包事务锁后先调用本方法：
        若盘上存在意图，说明持锁者之外没有在途事务（在途必持同锁），
        这些意图只能来自崩溃进程，按事件是否落盘对账补齐或回滚。
        """
        if self._store.list_asset_intents(wallet_id):
            self._recover_wallet_asset_commits(wallet_id)

    def _resolve_asset_commit_intent(
        self, wallet_id: str, operation_id: str, intent: object
    ) -> Optional[dict]:
        """对账单条提交意图，返回 committed 视图 R（前滚）或 None（回滚）。"""
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
            # 仅当前滚目标是形状完整的 R 时才补齐；否则保留意图不强改
            # （原子写使正常崩溃不会产生损坏事件，此处只防御外部篡改）。
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
                return None
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

        # 事件未持久化：提交未生效，回滚为 pending 与提交前资产状态
        if not isinstance(intent, dict):
            # 意图不可解析（正常原子写不会出现）：若账本仍是 pending/无操作，
            # 说明本就处于中止态，仅清理意图；否则保留现场不强改。
            op = self._store.get_asset_operation(wallet_id, operation_id)
            if op is None or op.get("state") == "pending":
                self._store.delete_asset_commit_intent(wallet_id, operation_id)
            return None
        pending = intent.get("pending")
        asset_id = intent.get("asset_id")
        old_asset = intent.get("old_asset")
        if not isinstance(pending, dict) or not isinstance(asset_id, str):
            return None
        self._store.restore_asset_operation(
            wallet_id,
            operation_id,
            pending,
            asset_id,
            old_asset if isinstance(old_asset, dict) else None,
        )
        self._store.delete_asset_commit_intent(wallet_id, operation_id)
        return None

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
        """
        self._get_wallet_or_404(wallet_id)
        self._validate_operation_id(operation_id)
        with self._wallet_lock(wallet_id):
            # 先自愈他进程崩溃遗留的轮换现场与任何提交意图，再基于一致
            # 账本判定，绝不基于半完成状态提交。
            self._heal_wallet(wallet_id)

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
            asset_id = record["asset_id"]
            asset = self._store.get_asset(wallet_id, asset_id)
            old_balance = asset["balance"] if asset is not None else 0
            old_version = asset["version"] if asset is not None else 0
            new_balance = old_balance + record["delta"]
            if new_balance < 0:
                # 余额不足：状态不变（仍 pending），可重试，不记事件
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
                # 绝不重复记事件；事件不在则回滚 pending 与提交前余额/版本，
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
                    return 201, committed_record
                self._store.restore_asset_operation(
                    wallet_id, operation_id, record, asset_id, asset
                )
                self._store.delete_asset_commit_intent(wallet_id, operation_id)
                raise
            self._store.delete_asset_commit_intent(wallet_id, operation_id)
        return 201, committed_record

    def get_asset(self, wallet_id: str, asset_id: str) -> dict:
        """查询某资产的账本状态（balance/version）。

        在每钱包事务锁内读取：提交事务进行中（账本已改、事件尚未落盘）的
        查询会被挡到事务结束，绝不会读到随后可能回滚的半完成余额。
        """
        self._get_wallet_or_404(wallet_id)
        self._validate_asset_id(asset_id)
        with self._wallet_lock(wallet_id):
            # 查询前先自愈他进程崩溃遗留的轮换现场与提交意图，
            # 绝不返回半切换公钥或半完成余额
            self._heal_wallet(wallet_id)
            asset = self._store.get_asset(wallet_id, asset_id)
            if asset is None:
                raise ServiceError(404, f"asset {asset_id!r} not found")
            return {
                "asset_id": asset_id,
                "balance": asset["balance"],
                "version": asset["version"],
            }

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
        self._get_wallet_or_404(wallet_id)
        self._validate_approver_id(approver_id)
        self._validate_reason(reason)
        with self._wallet_lock(wallet_id):
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

    def sign(
        self,
        wallet_id: str,
        signing_request_id: object,
        message: object,
        signatures: object,
    ) -> tuple[int, dict]:
        """返回 (HTTP 状态码, 响应体)。"""
        try:
            wallet = self._store.get_wallet(wallet_id)
        except ValueError:
            raise ServiceError(400, "invalid wallet_id")
        if wallet is None:
            raise ServiceError(404, f"wallet {wallet_id!r} not found")

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

        with self._wallet_lock(wallet_id):
            # 锁内自愈后重读钱包元数据：他进程崩溃的激活现场先被对账，
            # 份额轮换激活后未首签的请求必须用新的 share_ids 与公钥校验。
            self._heal_wallet(wallet_id)
            wallet = self._store.get_wallet(wallet_id)
            if wallet is None:
                raise ServiceError(404, f"wallet {wallet_id!r} not found")
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

            # 启用审批策略时：必须存在同 id、同 message 且已 approved 的审批单。
            # 这一步可能原子地把超时 pending 单记一次 E 并转为 expired。
            approval_record = None
            if self._store.get_policy(wallet_id) is not None:
                approval_record = self._fetch_request_or_404(
                    wallet_id, signing_request_id
                )
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
