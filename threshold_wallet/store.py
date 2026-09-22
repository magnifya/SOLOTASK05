"""钱包持久化：只保存份额，磁盘上不存在完整私钥。

磁盘布局（data_dir 下）::

    wallets/<wallet_id>.json        钱包元数据 + 份额公钥（无私钥）
    shares/<wallet_id>/<share_id>.json
                                    单个份额（份额私钥以 hex 保存），一份一个文件
    signatures/<wallet_id>.json     该钱包已完成的签名请求（幂等去重）
    policies/<wallet_id>.json       该钱包的审批策略（required_approvals 等）
    requests/<wallet_id>.json       该钱包的签名请求审批单（状态机）
    rotations/<wallet_id>.json      该钱包的份额轮换记录（prepared/activating/active）
    rotation-staging/<wallet_id>/<rotation_id>/
                                    轮换暂存目录：新份额私钥文件（<share_id>.json），
                                    激活期间的旧份额/钱包元数据备份（*.bak.json），
                                    激活成功后整目录删除
    audit/<wallet_id>.json          该钱包的审计事件日志（seq 从 1 起仅追加，
                                    由 audit.AuditStore 维护）
    assets/<wallet_id>.json         该钱包的资产账本：asset-operations（操作
                                    状态机 pending/committed）与 assets（每个
                                    资产的 balance/version），同一文件原子写入
    asset-intents/<wallet_id>/<operation_id>.json
                                    资产提交的"提交意图"（可恢复事务日志）：
                                    仅在 commit 事务窗口内存在，提交完成即删；
                                    崩溃后启动恢复据此判定提交是否已落事件，
                                    决定补齐账本或回滚为 pending
    transaction-policies/<wallet_id>.json
                                    该钱包的冷热钱包交易策略
                                    （mode/max_delta/allowed_assets），
                                    只含标识与整数，不含任何私钥材料
    sign-sessions/<wallet_id>.json  该钱包的可恢复签名会话（状态机
                                    collecting/ready/signed/expired）：
                                    原文、到期时间、已收份额签名（每份一个
                                    64 字节 Ed25519 签名，绝无私钥）与
                                    signed 时的 128 字节聚合签名

关键安全性质：
- 元数据文件不含任何私钥材料；
- 每个文件至多包含一个 32 字节份额私钥，两个份额分文件存放，
  任何位置都不保存拼接/聚合后的完整私钥；
- 写入采用同目录临时文件 + os.replace 原子替换；
- 进程内用一把锁串行化写操作（ThreadingHTTPServer 下安全）。
"""

from __future__ import annotations

import json
import os
import re
import shutil
import tempfile
import threading
from datetime import datetime, timedelta, timezone
from typing import Optional

from .crypto import ShareKey, combine_public_keys, public_key_from_private

#: wallet_id / rotation_id / signing_request_id 允许的字符（同时杜绝路径穿越）
_SAFE_ID = re.compile(r"^[A-Za-z0-9_-]{1,128}$")

#: share_id 允许的字符：轮换份额 id 为 <rotation_id>-share-N，最长 128+8
_SAFE_SHARE_ID = re.compile(r"^[A-Za-z0-9_-]{1,136}$")


def _check_id(kind: str, value: str) -> None:
    if not isinstance(value, str) or not _SAFE_ID.match(value):
        raise ValueError(f"invalid {kind}: {value!r}")


def _check_share_id(value: str) -> None:
    if not isinstance(value, str) or not _SAFE_SHARE_ID.match(value):
        raise ValueError(f"invalid share_id: {value!r}")


def _is_plain_int(value: object) -> bool:
    """真·整数：bool 是 int 子类，必须排除（余额/版本/delta 均不接受布尔）。"""
    return isinstance(value, int) and not isinstance(value, bool)


def _valid_safe_id(value: object) -> bool:
    return isinstance(value, str) and bool(_SAFE_ID.match(value))


def parse_utc_iso(value: object) -> Optional[datetime]:
    """严格解析 UTC 时间戳字符串。

    仅接受带时区信息的 ISO-8601 字符串（服务自身始终写 ``...Z``）；
    朴素时间（无 tz）、非字符串、不可解析或偏移非零固定值之外的内容
    一律返回 None。返回统一到 UTC 的 aware datetime，便于严格比较。
    """
    if not isinstance(value, str) or not value:
        return None
    text = value
    try:
        if text.endswith(("Z", "z")):
            text = text[:-1] + "+00:00"
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        # 朴素时间无法判定时区，绝不按本地时间猜测
        return None
    if parsed.utcoffset() != timedelta(0):
        # 只接受 UTC（零偏移），其他时区不做隐式换算
        return None
    return parsed.astimezone(timezone.utc)


def approval_policy_shape_ok(policy: object) -> bool:
    """审批策略条目形状：wallet_id 为合法标识、required_approvals 为
    非布尔整数 1/2、timeout_seconds 为非布尔正整数。"""
    if not isinstance(policy, dict):
        return False
    if not _valid_safe_id(policy.get("wallet_id")):
        return False
    required = policy.get("required_approvals")
    if not _is_plain_int(required) or required not in (1, 2):
        return False
    timeout = policy.get("timeout_seconds")
    return _is_plain_int(timeout) and timeout > 0


def transaction_policy_shape_ok(policy: object) -> bool:
    """交易策略条目形状：mode 仅 hot/cold、max_delta 为非布尔正整数、
    allowed_assets 为非空数组且每项匹配安全 id。"""
    if not isinstance(policy, dict):
        return False
    if policy.get("mode") not in ("hot", "cold"):
        return False
    if not _is_plain_int(policy.get("max_delta")) or policy["max_delta"] <= 0:
        return False
    assets = policy.get("allowed_assets")
    if not isinstance(assets, list) or not assets:
        return False
    return all(_valid_safe_id(asset) for asset in assets)


def _asset_entry_shape_ok(entry: object) -> bool:
    """资产条目形状：恰需非布尔整数 balance/version。"""
    if not isinstance(entry, dict):
        return False
    return _is_plain_int(entry.get("balance")) and _is_plain_int(
        entry.get("version")
    )


def _asset_operation_shape_ok(key: str, record: object) -> bool:
    """资产操作条目形状：必须含合法 operation_id/asset_id、非布尔整数
    delta、state 只能为 pending/committed；服务正常写入还带非布尔整数
    balance/version 快照，若存在则同样必须为非布尔整数。"""
    if not isinstance(record, dict):
        return False
    operation_id = record.get("operation_id")
    asset_id = record.get("asset_id")
    if not _valid_safe_id(operation_id) or operation_id != key:
        return False
    if not _valid_safe_id(asset_id):
        return False
    if not _is_plain_int(record.get("delta")) or record.get("delta") == 0:
        return False
    if record.get("state") not in ("pending", "committed"):
        return False
    for optional_int in ("balance", "version"):
        if optional_int in record and not _is_plain_int(
            record[optional_int]
        ):
            return False
    return True


class DuplicateWalletError(Exception):
    """wallet_id 已存在。"""


class RecoveryError(Exception):
    """启动/运行时恢复无法把磁盘现场对账到一致状态。

    触发即说明数据目录损坏或被外部篡改，继续服务可能暴露半完成状态或
    写错密钥，因此调用方必须阻止服务就绪（fail-closed），不得静默跳过。
    """


class CorruptDataError(ValueError):
    """本应是 JSON 对象的持久化文件无法解析（损坏或被外部篡改）。

    是 ValueError 的子类：既有的宽松 ``except ValueError``（如把不可解析
    意图纳入对账、把损坏暂存判为无效）行为不变；业务/HTTP 边界则可据此
    把"解析异常"与"非法 id"区分开——前者 fail-closed（503/阻止就绪），
    后者才是 400。
    """


class WalletStore:
    """钱包、份额与已完成签名请求的文件存储。"""

    def __init__(self, data_dir: str) -> None:
        self._data_dir = data_dir
        self._wallets_dir = os.path.join(data_dir, "wallets")
        self._shares_dir = os.path.join(data_dir, "shares")
        self._signatures_dir = os.path.join(data_dir, "signatures")
        self._policies_dir = os.path.join(data_dir, "policies")
        self._requests_dir = os.path.join(data_dir, "requests")
        self._rotations_dir = os.path.join(data_dir, "rotations")
        self._rotation_staging_dir = os.path.join(data_dir, "rotation-staging")
        self._assets_dir = os.path.join(data_dir, "assets")
        self._asset_intents_dir = os.path.join(data_dir, "asset-intents")
        self._transaction_policies_dir = os.path.join(
            data_dir, "transaction-policies"
        )
        self._sign_sessions_dir = os.path.join(data_dir, "sign-sessions")
        os.makedirs(self._wallets_dir, exist_ok=True)
        os.makedirs(self._shares_dir, exist_ok=True)
        os.makedirs(self._signatures_dir, exist_ok=True)
        os.makedirs(self._policies_dir, exist_ok=True)
        os.makedirs(self._requests_dir, exist_ok=True)
        os.makedirs(self._rotations_dir, exist_ok=True)
        os.makedirs(self._rotation_staging_dir, exist_ok=True)
        os.makedirs(self._assets_dir, exist_ok=True)
        os.makedirs(self._asset_intents_dir, exist_ok=True)
        os.makedirs(self._transaction_policies_dir, exist_ok=True)
        os.makedirs(self._sign_sessions_dir, exist_ok=True)
        self._lock = threading.Lock()

    @property
    def data_dir(self) -> str:
        return self._data_dir

    # ---- 内部工具 -------------------------------------------------------

    def _wallet_path(self, wallet_id: str) -> str:
        _check_id("wallet_id", wallet_id)
        return os.path.join(self._wallets_dir, wallet_id + ".json")

    def _share_path(self, wallet_id: str, share_id: str) -> str:
        _check_id("wallet_id", wallet_id)
        _check_share_id(share_id)
        return os.path.join(
            self._shares_dir, wallet_id, share_id + ".json"
        )

    def _signatures_path(self, wallet_id: str) -> str:
        _check_id("wallet_id", wallet_id)
        return os.path.join(self._signatures_dir, wallet_id + ".json")

    def _policy_path(self, wallet_id: str) -> str:
        _check_id("wallet_id", wallet_id)
        return os.path.join(self._policies_dir, wallet_id + ".json")

    def _requests_path(self, wallet_id: str) -> str:
        _check_id("wallet_id", wallet_id)
        return os.path.join(self._requests_dir, wallet_id + ".json")

    @staticmethod
    def _atomic_write(path: str, data: dict) -> None:
        directory = os.path.dirname(path)
        os.makedirs(directory, exist_ok=True)
        fd, tmp_path = tempfile.mkstemp(dir=directory, prefix=".tmp-", suffix=".json")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False, indent=2, sort_keys=True)
                f.write("\n")
            os.replace(tmp_path, path)
        except BaseException:
            try:
                os.unlink(tmp_path)
            except FileNotFoundError:
                pass
            raise

    @staticmethod
    def _read_json(path: str) -> Optional[dict]:
        try:
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
        except FileNotFoundError:
            return None
        except json.JSONDecodeError as exc:
            # 文件存在但损坏/被外部篡改：区别于"文件不存在"，按不可对账
            # 的数据损坏处理（CorruptDataError 是 ValueError 子类）。
            raise CorruptDataError(
                f"cannot parse JSON file {path!r}: {exc.msg}"
            ) from exc

    # ---- 钱包与份额 -----------------------------------------------------

    def create_wallet(
        self, wallet_id: str, shares: list[ShareKey], created_at: str
    ) -> None:
        """原子创建钱包元数据与各份额文件；重复时抛 DuplicateWalletError。"""
        meta_path = self._wallet_path(wallet_id)
        meta = {
            "wallet_id": wallet_id,
            "created_at": created_at,
            "public_key": b"".join(s.public_bytes for s in shares).hex(),
            "shares": [
                {"share_id": s.share_id, "public_key": s.public_bytes.hex()}
                for s in shares
            ],
        }
        share_records = [
            (
                self._share_path(wallet_id, s.share_id),
                {
                    "share_id": s.share_id,
                    "public_key": s.public_bytes.hex(),
                    # 仅该份额自己的私钥；系统中不存在完整私钥
                    "private_key": s.private_bytes.hex(),
                },
            )
            for s in shares
        ]
        with self._lock:
            if os.path.exists(meta_path):
                raise DuplicateWalletError(wallet_id)
            for path, record in share_records:
                self._atomic_write(path, record)
            self._atomic_write(meta_path, meta)

    def get_wallet(self, wallet_id: str) -> Optional[dict]:
        """返回钱包元数据（不含私钥），不存在返回 None。"""
        return self._read_json(self._wallet_path(wallet_id))

    def has_wallet(self, wallet_id: str) -> bool:
        return os.path.exists(self._wallet_path(wallet_id))

    def get_share(self, wallet_id: str, share_id: str) -> Optional[dict]:
        """返回单个份额记录（含该份额私钥 hex），不存在返回 None。"""
        return self._read_json(self._share_path(wallet_id, share_id))

    # ---- 签名请求 -------------------------------------------------------

    def save_signature(
        self, wallet_id: str, signing_request_id: str, record: dict
    ) -> Optional[dict]:
        """原子地保存一条已完成签名。

        在同一把锁内先查重：若该 signing_request_id 已有结果，则不覆盖、
        直接返回已有记录；否则写入并返回 None。
        """
        _check_id("signing_request_id", signing_request_id)
        path = self._signatures_path(wallet_id)
        with self._lock:
            all_records = self._read_json(path) or {}
            existing = all_records.get(signing_request_id)
            if existing is not None:
                return existing
            all_records[signing_request_id] = record
            self._atomic_write(path, all_records)
            return None

    def get_signature(
        self, wallet_id: str, signing_request_id: str
    ) -> Optional[dict]:
        """返回某签名请求的已有结果，不存在返回 None。"""
        _check_id("signing_request_id", signing_request_id)
        all_records = self._read_json(self._signatures_path(wallet_id))
        if not all_records:
            return None
        return all_records.get(signing_request_id)

    # ---- 审批策略 -------------------------------------------------------

    def save_policy(self, wallet_id: str, policy: dict) -> None:
        """原子地写入（或覆盖）钱包的审批策略。"""
        path = self._policy_path(wallet_id)
        with self._lock:
            self._atomic_write(path, policy)

    def get_policy(self, wallet_id: str) -> Optional[dict]:
        """返回钱包的审批策略，未设置返回 None。

        文件存在但形状损坏（标识/整数字段缺失或类型非法）时抛
        CorruptDataError（ValueError 子类），绝不返回残缺策略让下游
        读到“旧/坏策略”后按 KeyError/TypeError 继续判定。"""
        policy = self._read_json(self._policy_path(wallet_id))
        if policy is not None and not approval_policy_shape_ok(policy):
            raise CorruptDataError(
                f"approval policy for wallet {wallet_id!r} is malformed"
            )
        return policy

    # ---- 签名请求审批单 ---------------------------------------------------

    def create_request(
        self, wallet_id: str, signing_request_id: str, record: dict
    ) -> Optional[dict]:
        """原子地创建一条签名请求审批单。

        在同一把锁内先查重：若该 signing_request_id 已存在，则不覆盖、
        直接返回已有记录；否则写入并返回 None。
        """
        _check_id("signing_request_id", signing_request_id)
        path = self._requests_path(wallet_id)
        with self._lock:
            all_records = self._read_json(path) or {}
            existing = all_records.get(signing_request_id)
            if existing is not None:
                return existing
            all_records[signing_request_id] = record
            self._atomic_write(path, all_records)
            return None

    def get_request(
        self, wallet_id: str, signing_request_id: str
    ) -> Optional[dict]:
        """返回某条签名请求审批单，不存在返回 None。"""
        _check_id("signing_request_id", signing_request_id)
        all_records = self._read_json(self._requests_path(wallet_id))
        if not all_records:
            return None
        return all_records.get(signing_request_id)

    def update_request(
        self, wallet_id: str, signing_request_id: str, record: dict
    ) -> None:
        """原子地覆盖一条已存在的签名请求审批单（状态机推进用）。"""
        _check_id("signing_request_id", signing_request_id)
        path = self._requests_path(wallet_id)
        with self._lock:
            all_records = self._read_json(path) or {}
            all_records[signing_request_id] = record
            self._atomic_write(path, all_records)

    # ---- 回滚（状态/事件原子性用）----------------------------------------

    def delete_policy(self, wallet_id: str) -> None:
        """删除钱包的审批策略文件（策略事件追加失败时回滚用）。"""
        path = self._policy_path(wallet_id)
        with self._lock:
            try:
                os.unlink(path)
            except FileNotFoundError:
                pass

    # ---- 冷热钱包交易策略 -----------------------------------------------

    def _transaction_policy_path(self, wallet_id: str) -> str:
        _check_id("wallet_id", wallet_id)
        return os.path.join(
            self._transaction_policies_dir, wallet_id + ".json"
        )

    def save_transaction_policy(self, wallet_id: str, policy: dict) -> None:
        """原子地写入（或覆盖）钱包的冷热钱包交易策略。

        文件只含 mode/max_delta/allowed_assets（标识与整数/字符串），
        不含任何私钥材料。
        """
        path = self._transaction_policy_path(wallet_id)
        with self._lock:
            self._atomic_write(path, policy)

    def get_transaction_policy(self, wallet_id: str) -> Optional[dict]:
        """返回钱包的冷热钱包交易策略，未设置返回 None。

        文件存在但形状损坏时抛 CorruptDataError：绝不把残缺策略交给
        上层用于白名单/冷热判定或直接回显，统一 fail-closed（503）。"""
        policy = self._read_json(self._transaction_policy_path(wallet_id))
        if policy is not None and not transaction_policy_shape_ok(policy):
            raise CorruptDataError(
                f"transaction policy for wallet {wallet_id!r} is malformed"
            )
        return policy

    def delete_transaction_policy(self, wallet_id: str) -> None:
        """删除钱包的交易策略文件（首设时事件追加失败回滚用）。"""
        path = self._transaction_policy_path(wallet_id)
        with self._lock:
            try:
                os.unlink(path)
            except FileNotFoundError:
                pass

    def delete_request(self, wallet_id: str, signing_request_id: str) -> None:
        """删除一条签名请求审批单（创建事件追加失败时回滚用）。"""
        _check_id("signing_request_id", signing_request_id)
        path = self._requests_path(wallet_id)
        with self._lock:
            all_records = self._read_json(path)
            if not all_records or signing_request_id not in all_records:
                return
            del all_records[signing_request_id]
            if all_records:
                self._atomic_write(path, all_records)
            else:
                try:
                    os.unlink(path)
                except FileNotFoundError:
                    pass

    def delete_signature(self, wallet_id: str, signing_request_id: str) -> None:
        """删除一条已完成签名记录（签名事件追加失败时回滚用）。"""
        _check_id("signing_request_id", signing_request_id)
        path = self._signatures_path(wallet_id)
        with self._lock:
            all_records = self._read_json(path)
            if not all_records or signing_request_id not in all_records:
                return
            del all_records[signing_request_id]
            if all_records:
                self._atomic_write(path, all_records)
            else:
                try:
                    os.unlink(path)
                except FileNotFoundError:
                    pass

    # ---- 可恢复签名会话 ---------------------------------------------------

    def _sign_sessions_path(self, wallet_id: str) -> str:
        _check_id("wallet_id", wallet_id)
        return os.path.join(self._sign_sessions_dir, wallet_id + ".json")

    @staticmethod
    def _session_share_shape_ok(entry: object) -> bool:
        """已收份额条目形状：share_id 为合法标识、signature 为 hex 字符串
        且解码恰为 64 字节 Ed25519 份额签名。"""
        if not isinstance(entry, dict):
            return False
        share_id = entry.get("share_id")
        signature_hex = entry.get("signature")
        if not isinstance(share_id, str) or not _SAFE_SHARE_ID.match(share_id):
            return False
        if not isinstance(signature_hex, str):
            return False
        try:
            signature = bytes.fromhex(signature_hex)
        except ValueError:
            return False
        return len(signature) == 64

    def _session_record_shape_ok(self, key: str, record: object) -> bool:
        """签名会话记录形状的严格校验（损坏文件 fail-closed 用）。

        要求：id 为安全标识且与键一致；message 为非空字符串；
        timeout_seconds 为非布尔正整数；expires_at/created_at 为可解析的
        UTC 时间字符串；state 仅 collecting/ready/signed/expired；
        share_ids 恰为两个不重复的合法份额标识；shares 为条目数组，
        share_id 不重复且属于 share_ids 快照，每份签名恰为 64 字节；
        signed 必须带恰两份份额与 128 字节聚合签名；ready 必须恰两份；
        collecting/expired 可有 0~2 份——ready 到点同样会原子转 expired，
        故 expired 允许保留齐备份额；这两个非终态/终态不得携带聚合签名。

        状态、事件序列与份额集合的语义一致性（含逐份公钥重验与 signed
        聚合重算）由 service 层恢复对账完成：崩溃窗口内磁盘可能短暂出现
        “事件未落盘的终态”，形状合法即可加载，由恢复按提交点前滚/回滚。
        """
        if not isinstance(record, dict):
            return False
        if record.get("id") != key or not _valid_safe_id(key):
            return False
        message = record.get("message")
        if not isinstance(message, str) or not message:
            return False
        timeout = record.get("timeout_seconds")
        if not _is_plain_int(timeout) or timeout <= 0:
            return False
        if parse_utc_iso(record.get("expires_at")) is None:
            return False
        if not isinstance(record.get("created_at"), str):
            return False
        state = record.get("state")
        if state not in ("collecting", "ready", "signed", "expired"):
            return False
        expected = record.get("share_ids")
        if not isinstance(expected, list) or len(expected) != 2:
            return False
        if any(
            not isinstance(sid, str) or not _SAFE_SHARE_ID.match(sid)
            for sid in expected
        ):
            return False
        if len(set(expected)) != 2:
            return False
        shares = record.get("shares")
        if not isinstance(shares, list) or len(shares) > 2:
            return False
        seen: set[str] = set()
        for entry in shares:
            if not self._session_share_shape_ok(entry):
                return False
            sid = entry["share_id"]
            if sid in seen or sid not in expected:
                return False
            seen.add(sid)
        aggregate_hex = record.get("aggregate_signature")
        if state == "signed":
            if len(seen) != 2:
                return False
            if not isinstance(aggregate_hex, str):
                return False
            try:
                aggregate = bytes.fromhex(aggregate_hex)
            except ValueError:
                return False
            if len(aggregate) != 128:
                return False
        elif state == "ready":
            # ready 必须两份齐备；不到两份的 ready 是矛盾状态
            if len(seen) != 2:
                return False
            if aggregate_hex is not None:
                return False
        else:
            # collecting / expired：0~2 份（ready 到点同样转 expired），
            # 但不得携带聚合签名
            if aggregate_hex is not None:
                return False
        return True

    def _read_sign_sessions(self, wallet_id: str) -> dict:
        """读取并严格校验全部签名会话；文件不存在为空映射。

        文件存在但 JSON 损坏、顶层不是对象、键非安全标识或任一会话记录
        形状非法时抛 CorruptDataError：绝不静默归一为空会话，保留现场由
        上层 fail-closed（503/阻止就绪）。"""
        path = self._sign_sessions_path(wallet_id)
        data = self._read_json(path)
        if data is None:
            return {}
        if not isinstance(data, dict):
            raise CorruptDataError(
                f"sign sessions file {path!r} top-level value is not an object"
            )
        for session_id, record in data.items():
            if not _valid_safe_id(session_id) or not self._session_record_shape_ok(
                session_id, record
            ):
                raise CorruptDataError(
                    f"sign sessions file {path!r} has malformed session "
                    f"{session_id!r}"
                )
        return data

    def check_sign_sessions(self, wallet_id: str) -> None:
        """只读校验签名会话文件形状；损坏时抛 CorruptDataError/OSError。
        文件不存在（尚无会话）视为正常空状态。"""
        _check_id("wallet_id", wallet_id)
        self._read_sign_sessions(wallet_id)

    def sign_session_file_exists(self, wallet_id: str) -> bool:
        """该钱包的签名会话文件是否存在（存在即需与审计对账，哪怕为空）。"""
        return os.path.exists(self._sign_sessions_path(wallet_id))

    def list_sign_session_wallet_ids(self) -> list[str]:
        """返回存在签名会话文件的全部 wallet_id（启动恢复扫描用）。"""
        try:
            names = os.listdir(self._sign_sessions_dir)
        except FileNotFoundError:
            return []
        return sorted(
            name[: -len(".json")]
            for name in names
            if name.endswith(".json")
            and _SAFE_ID.match(name[: -len(".json")])
        )

    def create_sign_session(
        self, wallet_id: str, session_id: str, record: dict
    ) -> Optional[dict]:
        """原子地创建一条签名会话（调用方须持钱包事务锁并已查重）。

        同 id 已存在则不覆盖、直接返回已有记录；否则写入并返回 None。
        """
        _check_id("session_id", session_id)
        path = self._sign_sessions_path(wallet_id)
        with self._lock:
            all_records = self._read_sign_sessions(wallet_id)
            existing = all_records.get(session_id)
            if existing is not None:
                return existing
            all_records[session_id] = record
            self._atomic_write(path, all_records)
            return None

    def get_sign_session(
        self, wallet_id: str, session_id: str
    ) -> Optional[dict]:
        """返回某条签名会话记录（严格校验），不存在返回 None。"""
        _check_id("session_id", session_id)
        return self._read_sign_sessions(wallet_id).get(session_id)

    def list_sign_sessions(self, wallet_id: str) -> list[dict]:
        """返回某钱包全部签名会话记录（严格校验，按 id 排序）。"""
        records = self._read_sign_sessions(wallet_id)
        return [dict(records[key]) for key in sorted(records)]

    def update_sign_session(
        self, wallet_id: str, session_id: str, record: dict
    ) -> None:
        """原子覆盖一条已存在的签名会话（收份额/懒过期/聚合提交用）。"""
        _check_id("session_id", session_id)
        path = self._sign_sessions_path(wallet_id)
        with self._lock:
            all_records = self._read_sign_sessions(wallet_id)
            all_records[session_id] = record
            self._atomic_write(path, all_records)

    def delete_sign_session(self, wallet_id: str, session_id: str) -> None:
        """删除一条签名会话（创建事件追加失败回滚用）。"""
        _check_id("session_id", session_id)
        path = self._sign_sessions_path(wallet_id)
        with self._lock:
            all_records = self._read_sign_sessions(wallet_id)
            if session_id not in all_records:
                return
            del all_records[session_id]
            if all_records:
                self._atomic_write(path, all_records)
            else:
                try:
                    os.unlink(path)
                except FileNotFoundError:
                    pass

    # ---- 资产账本（asset-operations 与 assets）-----------------------------
    def _assets_path(self, wallet_id: str) -> str:
        _check_id("wallet_id", wallet_id)
        return os.path.join(self._assets_dir, wallet_id + ".json")

    def _read_asset_ledger(self, wallet_id: str) -> dict:
        """读取并**严格校验**资产账本（无文件时返回空结构）。

        文件存在但出现以下任一情况都视为数据损坏，抛 CorruptDataError
        （ValueError 子类），绝不把文件静默归一为空账本：
        JSON 不可解析、顶层不是对象、缺少 operations/assets、二者类型
        不是对象、操作条目字段形状非法（operation_id/asset_id 合法、
        delta/balance/version 为非布尔整数、state 仅 pending/committed）、
        资产条目 balance/version 不是非布尔整数。
        """
        path = self._assets_path(wallet_id)
        ledger = self._read_json(path)
        if ledger is None:
            # 文件尚不存在：正常的空状态（与"存在但损坏"严格区分）
            return {"operations": {}, "assets": {}}
        if not isinstance(ledger, dict):
            raise CorruptDataError(
                f"asset ledger {path!r} top-level value is not an object"
            )
        operations = ledger.get("operations")
        assets = ledger.get("assets")
        if "operations" not in ledger or not isinstance(operations, dict):
            raise CorruptDataError(
                f"asset ledger {path!r} has no object-valued 'operations'"
            )
        if "assets" not in ledger or not isinstance(assets, dict):
            raise CorruptDataError(
                f"asset ledger {path!r} has no object-valued 'assets'"
            )
        for operation_id, record in operations.items():
            if not _valid_safe_id(operation_id) or not (
                _asset_operation_shape_ok(operation_id, record)
            ):
                raise CorruptDataError(
                    f"asset ledger {path!r} has malformed operation "
                    f"{operation_id!r}"
                )
        for asset_id, entry in assets.items():
            if not _valid_safe_id(asset_id) or not _asset_entry_shape_ok(entry):
                raise CorruptDataError(
                    f"asset ledger {path!r} has malformed asset {asset_id!r}"
                )
        return {"operations": operations, "assets": assets}

    def check_asset_ledger(self, wallet_id: str) -> None:
        """只读校验资产账本形状；损坏时抛 CorruptDataError/OSError。
        文件不存在（尚无账本）视为正常空状态，不报错。"""
        _check_id("wallet_id", wallet_id)
        self._read_asset_ledger(wallet_id)

    def list_asset_ledger_wallet_ids(self) -> list[str]:
        """返回存在资产账本文件的全部 wallet_id（启动恢复扫描用）。

        只纳入匹配安全 id 的正式账本文件，忽略原子写残留的临时文件，
        避免把临时文件名当成 wallet_id。
        """
        try:
            names = os.listdir(self._assets_dir)
        except FileNotFoundError:
            return []
        return sorted(
            name[: -len(".json")]
            for name in names
            if name.endswith(".json")
            and _SAFE_ID.match(name[: -len(".json")])
        )

    def create_asset_operation(
        self, wallet_id: str, operation_id: str, record: dict
    ) -> Optional[dict]:
        """原子地创建一条资产操作记录。

        在同一把锁内先查重：若该 operation_id 已存在，则不覆盖、
        直接返回已有记录；否则写入并返回 None。
        """
        _check_id("operation_id", operation_id)
        path = self._assets_path(wallet_id)
        with self._lock:
            ledger = self._read_asset_ledger(wallet_id)
            existing = ledger["operations"].get(operation_id)
            if isinstance(existing, dict):
                return existing
            ledger["operations"][operation_id] = record
            self._atomic_write(path, ledger)
            return None

    def get_asset_operation(
        self, wallet_id: str, operation_id: str
    ) -> Optional[dict]:
        """返回某条资产操作记录，不存在返回 None。"""
        _check_id("operation_id", operation_id)
        record = self._read_asset_ledger(wallet_id)["operations"].get(
            operation_id
        )
        return dict(record) if isinstance(record, dict) else None

    def get_asset(self, wallet_id: str, asset_id: str) -> Optional[dict]:
        """返回某资产的账本记录（balance/version），不存在返回 None。"""
        _check_id("asset_id", asset_id)
        record = self._read_asset_ledger(wallet_id)["assets"].get(asset_id)
        return dict(record) if isinstance(record, dict) else None

    def commit_asset_operation(
        self,
        wallet_id: str,
        operation_id: str,
        operation_record: dict,
        asset_id: str,
        asset_record: dict,
    ) -> None:
        """原子地提交一条资产操作：操作记录与资产 balance/version 同文件
        一次写入（调用方须持有该钱包事务锁）。"""
        _check_id("operation_id", operation_id)
        _check_id("asset_id", asset_id)
        path = self._assets_path(wallet_id)
        with self._lock:
            ledger = self._read_asset_ledger(wallet_id)
            ledger["operations"][operation_id] = operation_record
            ledger["assets"][asset_id] = asset_record
            self._atomic_write(path, ledger)

    def restore_asset_operation(
        self,
        wallet_id: str,
        operation_id: str,
        operation_record: dict,
        asset_id: str,
        asset_record: Optional[dict],
    ) -> None:
        """提交事件追加失败时回滚：恢复操作记录与资产记录
        （asset_record 为 None 表示提交前该资产无账本记录，直接删除）。"""
        _check_id("operation_id", operation_id)
        _check_id("asset_id", asset_id)
        path = self._assets_path(wallet_id)
        with self._lock:
            ledger = self._read_asset_ledger(wallet_id)
            ledger["operations"][operation_id] = operation_record
            if asset_record is None:
                ledger["assets"].pop(asset_id, None)
            else:
                ledger["assets"][asset_id] = asset_record
            self._atomic_write(path, ledger)

    # ---- 资产提交意图（可恢复事务日志）-----------------------------------

    def _asset_intent_path(self, wallet_id: str, operation_id: str) -> str:
        _check_id("wallet_id", wallet_id)
        _check_id("operation_id", operation_id)
        return os.path.join(
            self._asset_intents_dir, wallet_id, operation_id + ".json"
        )

    def write_asset_commit_intent(
        self, wallet_id: str, operation_id: str, intent: dict
    ) -> None:
        """原子写入一条资产提交意图（commit 事务第一步）。

        意图记录只含标识与整数（operation_id/asset_id/delta、提交前后
        balance/version、事件 seq），不含任何私钥材料。
        """
        path = self._asset_intent_path(wallet_id, operation_id)
        with self._lock:
            self._atomic_write(path, intent)

    def get_asset_commit_intent(
        self, wallet_id: str, operation_id: str
    ) -> Optional[dict]:
        """返回某操作的提交意图，不存在返回 None。"""
        return self._read_json(self._asset_intent_path(wallet_id, operation_id))

    def delete_asset_commit_intent(
        self, wallet_id: str, operation_id: str
    ) -> None:
        """删除提交意图（commit 事务完成/中止的最后一步）。"""
        path = self._asset_intent_path(wallet_id, operation_id)
        with self._lock:
            try:
                os.unlink(path)
            except FileNotFoundError:
                pass

    def list_asset_intent_wallet_ids(self) -> list[str]:
        """返回存在提交意图目录的全部 wallet_id。"""
        try:
            names = os.listdir(self._asset_intents_dir)
        except FileNotFoundError:
            return []
        return sorted(
            name
            for name in names
            if _SAFE_ID.match(name)
            and os.path.isdir(os.path.join(self._asset_intents_dir, name))
        )

    @staticmethod
    def valid_asset_commit_intent(operation_id: str, intent: object) -> bool:
        """校验提交意图是否具备安全回滚/前滚所需的全部标识与整数。

        正常提交写入的意图含 operation_id/asset_id/delta、提交前资产
        快照 old_asset（None 或 {balance,version}）、pending 操作记录、
        提交结果 new_balance/new_version。任一字段缺失、类型错误、布尔
        冒整、标识不匹配或前后账目不守恒都判定为无效：调用方必须
        fail-closed（保留意图现场，不回滚/前滚/清理），绝不把损坏意图
        当成空意图继续。
        """
        if not isinstance(intent, dict):
            return False
        if intent.get("operation_id") != operation_id:
            return False
        asset_id = intent.get("asset_id")
        if not _valid_safe_id(asset_id):
            return False
        delta = intent.get("delta")
        if not _is_plain_int(delta) or delta == 0:
            return False
        new_balance = intent.get("new_balance")
        new_version = intent.get("new_version")
        if not _is_plain_int(new_balance) or not _is_plain_int(new_version):
            return False
        old_asset = intent.get("old_asset")
        if old_asset is not None and not _asset_entry_shape_ok(old_asset):
            return False
        pending = intent.get("pending")
        if not _asset_operation_shape_ok(operation_id, pending):
            return False
        # pending 是创建时刻的操作快照 R，服务正常写入必带非布尔整数
        # balance/version；恢复据此还原操作，缺失即不可安全对账。
        if not _is_plain_int(pending.get("balance")) or not (
            _is_plain_int(pending.get("version"))
        ):
            return False
        if pending["state"] != "pending" or pending["asset_id"] != asset_id:
            return False
        if pending["delta"] != delta:
            return False
        old_balance = old_asset["balance"] if old_asset is not None else 0
        old_version = old_asset["version"] if old_asset is not None else 0
        return (
            new_balance == old_balance + delta
            and new_version == old_version + 1
        )

    def list_asset_intents(self, wallet_id: str) -> list[tuple[str, Optional[dict]]]:
        """返回某钱包全部提交意图 (operation_id, intent|None)。

        intent 为 None 表示文件存在但 JSON 不可解析或不是对象（原子写使
        正常流程不会出现，仅外部损坏时）：调用方必须按不可对账处理
        （fail-closed、保留现场），不得把它当成空意图清理。
        """
        _check_id("wallet_id", wallet_id)
        base = os.path.join(self._asset_intents_dir, wallet_id)
        try:
            names = os.listdir(base)
        except (FileNotFoundError, NotADirectoryError):
            return []
        result: list[tuple[str, Optional[dict]]] = []
        for name in names:
            if not name.endswith(".json"):
                continue
            operation_id = name[: -len(".json")]
            if not _SAFE_ID.match(operation_id):
                # 非预期文件：不纳入恢复，也不删除业务数据
                continue
            try:
                data = self._read_json(os.path.join(base, name))
            except ValueError:
                # JSON 不可解析（原子写使正常流程不会出现，仅外部损坏）
                data = None
            result.append((operation_id, data if isinstance(data, dict) else None))
        return sorted(result, key=lambda item: item[0])

    # ---- 份额文件与钱包元数据（轮换激活用）--------------------------------

    def save_share(self, wallet_id: str, record: dict) -> None:
        """原子地写入（或覆盖）一个份额文件（含该份额私钥 hex）。"""
        path = self._share_path(wallet_id, record["share_id"])
        with self._lock:
            self._atomic_write(path, record)

    def delete_share(self, wallet_id: str, share_id: str) -> None:
        """删除一个份额文件（轮换激活换下旧份额 / 回滚清理新份额用）。"""
        path = self._share_path(wallet_id, share_id)
        with self._lock:
            try:
                os.unlink(path)
            except FileNotFoundError:
                pass

    def save_wallet_meta(self, wallet_id: str, meta: dict) -> None:
        """原子地覆盖钱包元数据文件（无私钥；轮换激活/回滚用）。"""
        path = self._wallet_path(wallet_id)
        with self._lock:
            self._atomic_write(path, meta)

    # ---- 份额轮换记录 -----------------------------------------------------

    def _rotations_path(self, wallet_id: str) -> str:
        _check_id("wallet_id", wallet_id)
        return os.path.join(self._rotations_dir, wallet_id + ".json")

    def create_rotation(
        self, wallet_id: str, rotation_id: str, record: dict
    ) -> Optional[dict]:
        """原子地创建一条份额轮换记录。

        在同一把锁内先查重：若该 rotation_id 已存在，则不覆盖、
        直接返回已有记录；否则写入并返回 None。
        """
        _check_id("rotation_id", rotation_id)
        path = self._rotations_path(wallet_id)
        with self._lock:
            all_records = self._read_json(path) or {}
            existing = all_records.get(rotation_id)
            if existing is not None:
                return existing
            all_records[rotation_id] = record
            self._atomic_write(path, all_records)
            return None

    def get_rotation(
        self, wallet_id: str, rotation_id: str
    ) -> Optional[dict]:
        """返回某条份额轮换记录，不存在返回 None。"""
        _check_id("rotation_id", rotation_id)
        all_records = self._read_json(self._rotations_path(wallet_id))
        if not all_records:
            return None
        return all_records.get(rotation_id)

    def list_rotations(self, wallet_id: str) -> list[dict]:
        """返回该钱包的全部份额轮换记录（无文件时返回 []）。"""
        _check_id("wallet_id", wallet_id)
        all_records = self._read_json(self._rotations_path(wallet_id))
        if not all_records:
            return []
        return [
            dict(record)
            for record in all_records.values()
            if isinstance(record, dict)
        ]

    def update_rotation(
        self, wallet_id: str, rotation_id: str, record: dict
    ) -> None:
        """原子地覆盖一条已存在的份额轮换记录（状态机推进用）。"""
        _check_id("rotation_id", rotation_id)
        path = self._rotations_path(wallet_id)
        with self._lock:
            all_records = self._read_json(path) or {}
            all_records[rotation_id] = record
            self._atomic_write(path, all_records)

    def delete_rotation(self, wallet_id: str, rotation_id: str) -> None:
        """删除一条份额轮换记录（准备事件追加失败时回滚用）。"""
        _check_id("rotation_id", rotation_id)
        path = self._rotations_path(wallet_id)
        with self._lock:
            all_records = self._read_json(path)
            if not all_records or rotation_id not in all_records:
                return
            del all_records[rotation_id]
            if all_records:
                self._atomic_write(path, all_records)
            else:
                try:
                    os.unlink(path)
                except FileNotFoundError:
                    pass

    # ---- 轮换暂存目录（新份额私钥 + 激活备份）------------------------------

    def _staging_dir(self, wallet_id: str, rotation_id: str) -> str:
        _check_id("wallet_id", wallet_id)
        _check_id("rotation_id", rotation_id)
        return os.path.join(
            self._rotation_staging_dir, wallet_id, rotation_id
        )

    def _staging_share_path(
        self, wallet_id: str, rotation_id: str, share_id: str
    ) -> str:
        _check_share_id(share_id)
        return os.path.join(
            self._staging_dir(wallet_id, rotation_id), share_id + ".json"
        )

    def _staging_backup_path(
        self, wallet_id: str, rotation_id: str, share_id: str
    ) -> str:
        _check_share_id(share_id)
        return os.path.join(
            self._staging_dir(wallet_id, rotation_id),
            share_id + ".bak.json",
        )

    def _staging_wallet_backup_path(
        self, wallet_id: str, rotation_id: str
    ) -> str:
        return os.path.join(
            self._staging_dir(wallet_id, rotation_id), "wallet.bak.json"
        )

    def save_staging_share(
        self, wallet_id: str, rotation_id: str, record: dict
    ) -> None:
        """把一个新份额（含私钥）写入轮换暂存目录，一份一个文件。"""
        path = self._staging_share_path(
            wallet_id, rotation_id, record["share_id"]
        )
        with self._lock:
            self._atomic_write(path, record)

    def get_staging_share(
        self, wallet_id: str, rotation_id: str, share_id: str
    ) -> Optional[dict]:
        """返回暂存的新份额记录，不存在返回 None。"""
        return self._read_json(
            self._staging_share_path(wallet_id, rotation_id, share_id)
        )

    def save_activation_backups(
        self,
        wallet_id: str,
        rotation_id: str,
        old_shares: list[dict],
        wallet_meta: dict,
    ) -> None:
        """激活前把旧份额文件与钱包元数据备份进暂存目录（回滚依据）。"""
        with self._lock:
            for record in old_shares:
                self._atomic_write(
                    self._staging_backup_path(
                        wallet_id, rotation_id, record["share_id"]
                    ),
                    record,
                )
            self._atomic_write(
                self._staging_wallet_backup_path(wallet_id, rotation_id),
                wallet_meta,
            )

    def delete_activation_backups(
        self, wallet_id: str, rotation_id: str
    ) -> None:
        """删除激活备份（*.bak.json），保留暂存的新份额文件。"""
        staging = self._staging_dir(wallet_id, rotation_id)
        with self._lock:
            try:
                names = os.listdir(staging)
            except FileNotFoundError:
                return
            for name in names:
                if name.endswith(".bak.json"):
                    try:
                        os.unlink(os.path.join(staging, name))
                    except FileNotFoundError:
                        pass

    def delete_staging(self, wallet_id: str, rotation_id: str) -> None:
        """删除整个轮换暂存目录（激活成功后清理暂存与备份）。"""
        staging = self._staging_dir(wallet_id, rotation_id)
        with self._lock:
            shutil.rmtree(staging, ignore_errors=True)

    # ---- 启动恢复：未完成的激活先回滚，轮换残留按有效性判定 --------------

    def list_rotation_wallet_ids(self) -> list[str]:
        """返回拥有轮换记录文件的全部 wallet_id。

        只纳入匹配安全 id 的正式记录文件，忽略原子写残留的
        ``.tmp-*.json`` 等临时文件，避免把临时文件名当成 wallet_id。
        """
        try:
            names = os.listdir(self._rotations_dir)
        except FileNotFoundError:
            return []
        return sorted(
            name[: -len(".json")]
            for name in names
            if name.endswith(".json")
            and _SAFE_ID.match(name[: -len(".json")])
        )

    def list_staging_wallet_ids(self) -> list[str]:
        """返回轮换暂存根目录下出现过的全部 wallet_id（含无记录文件的）。
        只纳入匹配安全 id 的目录名，忽略任何杂项目录。"""
        try:
            names = os.listdir(self._rotation_staging_dir)
        except FileNotFoundError:
            return []
        return sorted(
            name
            for name in names
            if _SAFE_ID.match(name)
            and os.path.isdir(os.path.join(self._rotation_staging_dir, name))
        )

    def list_staging_rotation_ids(self, wallet_id: str) -> list[str]:
        """返回某钱包暂存目录下的全部 rotation_id 目录名。"""
        _check_id("wallet_id", wallet_id)
        base = os.path.join(self._rotation_staging_dir, wallet_id)
        try:
            names = os.listdir(base)
        except (FileNotFoundError, NotADirectoryError):
            return []
        return sorted(
            name
            for name in names
            if _SAFE_ID.match(name)
            and os.path.isdir(os.path.join(base, name))
        )

    def list_rotation_entries(self, wallet_id: str) -> list[tuple[str, dict]]:
        """返回 (记录键, 记录) 对；记录键即删除时使用的 rotation_id。"""
        _check_id("wallet_id", wallet_id)
        all_records = self._read_json(self._rotations_path(wallet_id))
        if not isinstance(all_records, dict):
            return []
        return [
            (key, record)
            for key, record in all_records.items()
            if isinstance(key, str) and isinstance(record, dict)
        ]

    def rollback_activation_files(
        self, wallet_id: str, rotation_record: dict
    ) -> None:
        """用暂存目录中的备份恢复钱包元数据与旧份额文件，并删除已换入的
        新份额文件。备份缺失（崩溃发生在备份写入前）时各步自动跳过。"""
        rotation_id = rotation_record["rotation_id"]
        wallet_backup = self._read_json(
            self._staging_wallet_backup_path(wallet_id, rotation_id)
        )
        if wallet_backup is not None:
            self.save_wallet_meta(wallet_id, wallet_backup)
        staging = self._staging_dir(wallet_id, rotation_id)
        try:
            names = os.listdir(staging)
        except FileNotFoundError:
            names = []
        for name in names:
            if name.endswith(".bak.json") and name != "wallet.bak.json":
                share_record = self._read_json(os.path.join(staging, name))
                if isinstance(share_record, dict) and isinstance(
                    share_record.get("share_id"), str
                ):
                    self.save_share(wallet_id, share_record)
        for share_id in rotation_record.get("share_ids", []):
            if isinstance(share_id, str):
                self.delete_share(wallet_id, share_id)

    @staticmethod
    def _rotation_record_shape_ok(record: dict) -> bool:
        """轮换记录的基本形状校验（启动恢复判定"无效记录"用）。"""
        rotation_id = record.get("rotation_id")
        if not isinstance(rotation_id, str) or not _SAFE_ID.match(rotation_id):
            return False
        if record.get("state") not in ("prepared", "activating", "active"):
            return False
        share_ids = record.get("share_ids")
        if (
            not isinstance(share_ids, list)
            or len(share_ids) != 2
            or any(
                not isinstance(sid, str) or not _SAFE_SHARE_ID.match(sid)
                for sid in share_ids
            )
        ):
            return False
        public_key = record.get("public_key")
        if not isinstance(public_key, str):
            return False
        try:
            if len(bytes.fromhex(public_key)) != 64:
                return False
        except ValueError:
            return False
        return True

    def _prepared_staging_valid(self, wallet_id: str, record: dict) -> bool:
        """判定 prepared 轮换的暂存目录是否完整有效。

        仅当全部满足时保留：目录名与 rotation_id 一致（由路径构造保证）、
        目录内恰有记录中两个 share_ids 对应的份额文件（无多无缺）、每个
        文件 JSON 可解析、share_id 与记录一致、public_key 恰为 32 字节、
        私钥恰为 32 字节且能推导出该 public_key、两个份额公钥按序拼接
        等于记录中的钱包 public_key。
        """
        rotation_id = record["rotation_id"]
        share_ids = list(record["share_ids"])
        staging = self._staging_dir(wallet_id, rotation_id)
        try:
            names = set(os.listdir(staging))
        except (FileNotFoundError, NotADirectoryError):
            return False
        if names != {sid + ".json" for sid in share_ids}:
            return False
        share_public_keys: list[bytes] = []
        for share_id in share_ids:
            try:
                data = self._read_json(
                    os.path.join(staging, share_id + ".json")
                )
            except (ValueError, OSError):
                # JSON 不可解析 / 读取失败
                return False
            if not isinstance(data, dict) or data.get("share_id") != share_id:
                return False
            public_hex = data.get("public_key")
            private_hex = data.get("private_key")
            if not isinstance(public_hex, str) or not isinstance(
                private_hex, str
            ):
                return False
            try:
                public_bytes = bytes.fromhex(public_hex)
                private_bytes = bytes.fromhex(private_hex)
            except ValueError:
                return False
            if len(public_bytes) != 32 or len(private_bytes) != 32:
                return False
            try:
                if public_key_from_private(private_bytes) != public_bytes:
                    return False
            except ValueError:
                return False
            share_public_keys.append(public_bytes)
        return (
            combine_public_keys(share_public_keys).hex()
            == record["public_key"]
        )

    def _load_backup_wallet_meta(
        self, wallet_id: str, rotation_id: str
    ) -> Optional[dict]:
        return self._read_json(
            self._staging_wallet_backup_path(wallet_id, rotation_id)
        )

    @staticmethod
    def _share_record_ok(record: object, share_id: str, public_hex: str) -> bool:
        """份额文件是否为可前滚的权威私钥份额：share_id 一致、公钥/私钥
        均为 32 字节 hex，且私钥推导出的公钥恰为给定权威份额公钥。"""
        if not isinstance(record, dict) or record.get("share_id") != share_id:
            return False
        public_field = record.get("public_key")
        private_field = record.get("private_key")
        if not isinstance(public_field, str) or not isinstance(
            private_field, str
        ):
            return False
        try:
            public_bytes = bytes.fromhex(public_field)
            private_bytes = bytes.fromhex(private_field)
        except ValueError:
            return False
        if (
            len(public_bytes) != 32
            or len(private_bytes) != 32
            or public_field != public_hex
        ):
            return False
        try:
            return public_key_from_private(private_bytes) == public_bytes
        except ValueError:
            return False

    def _rotation_records(
        self,
        wallet_id: str,
        activated_ids: Optional[set[str]] = None,
    ) -> dict[str, dict]:
        """读取轮换记录映射。

        形状非法或键不符的条目：若该 rotation_id 已有 share_rotation_
        activated 事件，删除它会破坏已提交链，必须 fail-closed
        （RecoveryError）；仅当不存在激活事件（准备从未提交）时才按公开
        契约连记录带暂存安全删除，审计中的孤立 prepared 事件保留。
        ``activated_ids`` 为 None（不读审计的快速探测）时遇到畸形条目
        抛 CorruptDataError，由调用方转入读审计的恢复路径处理。
        JSON 不可解析同样抛 CorruptDataError。"""
        path = self._rotations_path(wallet_id)
        data = self._read_json(path)
        if data is None:
            return {}
        if not isinstance(data, dict):
            raise CorruptDataError(
                f"rotation records {path!r} top-level value is not an object"
            )
        valid: dict[str, dict] = {}
        malformed: list[tuple[str, object]] = []
        for key, record in data.items():
            if (
                isinstance(key, str)
                and isinstance(record, dict)
                and self._rotation_record_shape_ok(record)
                and record.get("rotation_id") == key
            ):
                valid[key] = dict(record)
            else:
                malformed.append((key, record))
        for key, record in malformed:
            rotation_id = (
                record.get("rotation_id")
                if isinstance(record, dict) else None
            )
            candidate_ids = {
                x for x in (key, rotation_id)
                if isinstance(x, str) and _SAFE_ID.match(x)
            }
            if activated_ids is None:
                raise CorruptDataError(
                    f"rotation records {path!r} contain a malformed entry "
                    f"{key!r}"
                )
            if candidate_ids & activated_ids:
                # 已提交激活的记录畸形/被篡改：无法安全对账，fail-closed
                raise RecoveryError(
                    f"wallet {wallet_id!r} rotation {key!r} record is "
                    "malformed but its activation event is committed"
                )
            data.pop(key, None)
            for rid in candidate_ids:
                self.delete_staging(wallet_id, rid)
        if malformed:
            if data:
                self._atomic_write(path, data)
            else:
                try:
                    os.unlink(path)
                except FileNotFoundError:
                    pass
        return valid

    def rotation_timeline_is_static(
        self,
        wallet_id: str,
        timeline: "RotationTimeline",
        staging_ids: set[str],
    ) -> bool:
        """已读审计严格校验后，判断轮换现场是否静止（无需任何写恢复）。

        静止条件：没有激活事件未落盘的 activating/active 记录；已激活
        记录全部 active 且标识/previous_public_key 与事件一致；钱包元数据
        公钥与两份份额等于时间线链尖（链尖份额文件必须就位）；暂存目录
        恰为保留的未激活 prepared 尝试（不多不少）。"""
        records = self._rotation_records(wallet_id)
        latest = timeline.latest
        wallet = self.get_wallet(wallet_id)
        if not isinstance(wallet, dict):
            return False
        for rotation_id, record in records.items():
            attempts = [
                a
                for a in timeline.attempts
                if a.rotation_id == rotation_id
            ]
            if not attempts:
                return False
            attempt = attempts[-1]
            if attempt.activated_seq is None:
                if record.get("state") != "prepared":
                    return False
                continue
            if record.get("state") != "active":
                return False
            if record.get("previous_public_key") != attempt.previous_public_key:
                return False
        if latest is not None:
            if wallet.get("public_key") != latest.public_key:
                return False
            meta_ids = [
                s.get("share_id")
                for s in wallet.get("shares", [])
                if isinstance(s, dict)
            ]
            if meta_ids != list(latest.share_ids):
                return False
            for sid in latest.share_ids:
                if self.get_share(wallet_id, sid) is None:
                    return False
        # 暂存目录：已激活轮换不应残留；未激活 prepared 暂存按其记录存在
        committed_ids = {a.rotation_id for a in timeline.committed}
        prepared_ids = {
            a.rotation_id
            for a in timeline.attempts
            if a.activated_seq is None
            and records.get(a.rotation_id, {}).get("state") == "prepared"
        }
        if staging_ids & committed_ids:
            return False
        if staging_ids - prepared_ids - set(records):
            return False
        return True

    def rotation_recovery_needed(self, wallet_id: str) -> bool:
        """不读审计、只看磁盘现场判断是否需要持锁恢复（常驻自愈触发用）。

        以下任一成立即视为他进程崩溃残留：activating 记录；active 记录
        仍带暂存目录；暂存目录无对应 prepared 记录（孤儿）；钱包元数据
        与激活记录链尖不一致（链尖＝公钥不等于任何其他 active 记录
        previous_public_key 的那一条）。静止现场（干净 prepared /
        干净 active 且暂存已清空）返回 False，使审计文件损坏时不依赖
        审计的路由仍可服务。"""
        try:
            records = self._rotation_records(wallet_id)
        except CorruptDataError:
            # 畸形记录是否可安全删除取决于审计（是否已激活）：转入读审计
            # 的恢复路径判定，绝不在探测阶段擅自删除或放过。
            return True
        if not records and not self.list_staging_rotation_ids(wallet_id):
            return False
        staging_ids = set(self.list_staging_rotation_ids(wallet_id))
        active = [r for r in records.values() if r.get("state") == "active"]
        activating = [
            r for r in records.values() if r.get("state") == "activating"
        ]
        if activating:
            return True
        prepared_ids = {
            r["rotation_id"]
            for r in records.values()
            if r.get("state") == "prepared"
        }
        if staging_ids - set(records):
            # 无任何记录对应的暂存目录
            return True
        for record in active:
            if record["rotation_id"] in staging_ids:
                return True
        # 依据记录自带的 previous_public_key 找链尖（不读审计）
        previous_pubs = {
            r.get("previous_public_key")
            for r in active
            if isinstance(r.get("previous_public_key"), str)
        }
        tips = [
            r for r in active if r.get("public_key") not in previous_pubs
        ]
        if len(tips) > 1:
            # 记录链本身分叉：必须进入恢复按审计严格对账
            return True
        if tips:
            wallet = self.get_wallet(wallet_id)
            if not isinstance(wallet, dict):
                return True
            tip = tips[0]
            if wallet.get("public_key") != tip.get("public_key"):
                return True
            meta_ids = [
                s.get("share_id")
                for s in wallet.get("shares", [])
                if isinstance(s, dict)
            ]
            if meta_ids != list(tip.get("share_ids", [])):
                return True
            for sid in tip["share_ids"]:
                if self.get_share(wallet_id, sid) is None:
                    return True
        # 暂存目录没有对应 prepared 记录（active/activating 已覆盖）
        if staging_ids - prepared_ids - {
            r["rotation_id"] for r in active
        }:
            return True
        return False

    def _rollback_uncommitted_attempt(
        self,
        wallet_id: str,
        attempt: "RotationAttempt",
        predecessor_public: Optional[str],
        predecessor_share_ids: Optional[tuple[str, str]],
    ) -> dict:
        """激活事件未落盘的尝试：恢复上一轮完整份额与公钥、置回 prepared。

        ``predecessor_public``/``predecessor_share_ids`` 为时间线上该尝试
        之前的在用公钥与两份份额；首轮换且时间线尚无已激活链时两者为
        None，此时从激活备份（wallet.bak.json）解析创世状态；备份也不存在
        时，仅当换入尚未发生（当前元数据不指向新公钥且两份旧份额完整）
        才允许恢复。恢复后严格校验元数据公钥与两份旧份额私钥一致；无法
        安全对账抛 RecoveryError，绝不猜写密钥。返回置回 prepared 的记录。"""
        rotation_id = attempt.rotation_id
        backup_meta = self._load_backup_wallet_meta(wallet_id, rotation_id)
        current = self.get_wallet(wallet_id)
        if not isinstance(current, dict):
            raise RecoveryError(
                f"wallet {wallet_id!r} metadata missing during rollback"
            )
        swapped = current.get("public_key") == attempt.public_key
        if predecessor_public is None:
            # 首轮换、时间线无已激活链：创世公钥以激活备份为权威；无备份
            # 且换入未发生时，当前元数据就是创世状态。
            if backup_meta is not None:
                predecessor_public = backup_meta.get("public_key")
                backup_shares = backup_meta.get("shares")
                if (
                    not isinstance(predecessor_public, str)
                    or not isinstance(backup_shares, list)
                    or len(backup_shares) != 2
                ):
                    raise RecoveryError(
                        f"wallet {wallet_id!r} rotation {rotation_id!r} backup "
                        "metadata is malformed"
                    )
                predecessor_share_ids = tuple(
                    s.get("share_id")
                    for s in backup_shares
                    if isinstance(s, dict)
                )
            elif not swapped:
                predecessor_public = current.get("public_key")
                current_shares = current.get("shares")
                if (
                    not isinstance(predecessor_public, str)
                    or not isinstance(current_shares, list)
                    or len(current_shares) != 2
                ):
                    raise RecoveryError(
                        f"wallet {wallet_id!r} rotation {rotation_id!r} cannot "
                        "locate the genesis wallet state"
                    )
                predecessor_share_ids = tuple(
                    s.get("share_id")
                    for s in current_shares
                    if isinstance(s, dict)
                )
            else:
                raise RecoveryError(
                    f"wallet {wallet_id!r} rotation {rotation_id!r} has no "
                    "activation backup to roll back"
                )
            if (
                not isinstance(predecessor_public, str)
                or predecessor_share_ids is None
                or any(not isinstance(sid, str) for sid in predecessor_share_ids)
            ):
                raise RecoveryError(
                    f"wallet {wallet_id!r} rotation {rotation_id!r} cannot "
                    "determine the previous wallet state"
                )
        if swapped and backup_meta is None:
            raise RecoveryError(
                f"wallet {wallet_id!r} rotation {rotation_id!r} has no "
                "activation backup to roll back"
            )
        if (
            backup_meta is not None
            and backup_meta.get("public_key") != predecessor_public
        ):
            raise RecoveryError(
                f"wallet {wallet_id!r} rotation {rotation_id!r} backup does "
                "not match the previous public key in the timeline"
            )
        if not swapped:
            # 换入未发生：元数据必须仍指向上一轮公钥；若指向别的公钥，
            # 无备份可依，fail-closed。
            if current.get("public_key") != predecessor_public:
                if backup_meta is None:
                    raise RecoveryError(
                        f"wallet {wallet_id!r} rotation {rotation_id!r} "
                        "cannot locate the previous wallet state"
                    )
            missing = [
                sid
                for sid in predecessor_share_ids
                if self.get_share(wallet_id, sid) is None
            ]
            if missing and backup_meta is None:
                raise RecoveryError(
                    f"wallet {wallet_id!r} rotation {rotation_id!r} lost "
                    f"in-use shares {list(missing)!r} without backup"
                )
        # 恢复备份（若有）、删除已换入的新份额文件
        self.rollback_activation_files(
            wallet_id,
            {
                "rotation_id": rotation_id,
                "share_ids": list(attempt.share_ids),
            },
        )
        restored_meta = self.get_wallet(wallet_id)
        if (
            not isinstance(restored_meta, dict)
            or restored_meta.get("public_key") != predecessor_public
        ):
            raise RecoveryError(
                f"wallet {wallet_id!r} rotation {rotation_id!r} rollback did "
                "not restore the previous public key"
            )
        first, second = RotationTimeline._pubkey_halves(
            predecessor_public,
            f"rotation {rotation_id!r} previous public key",
        )
        expected = {
            predecessor_share_ids[0]: first,
            predecessor_share_ids[1]: second,
        }
        for sid, public_hex in expected.items():
            share_record = self.get_share(wallet_id, sid)
            if not self._share_record_ok(share_record, sid, public_hex):
                raise RecoveryError(
                    f"wallet {wallet_id!r} rotation {rotation_id!r} previous "
                    f"share {sid!r} is missing or invalid after rollback"
                )
        # 换入的新份额不得残留
        for sid in attempt.share_ids:
            if self.get_share(wallet_id, sid) is not None:
                raise RecoveryError(
                    f"wallet {wallet_id!r} rotation {rotation_id!r} swapped "
                    f"share {sid!r} survived rollback"
                )
        record = self.get_rotation(wallet_id, rotation_id)
        if record is None:
            raise RecoveryError(
                f"wallet {wallet_id!r} rotation {rotation_id!r} record "
                "vanished during rollback"
            )
        prepared_record = {
            k: v
            for k, v in record.items()
            if k != "previous_public_key"
        }
        prepared_record["state"] = "prepared"
        self.update_rotation(wallet_id, rotation_id, prepared_record)
        self.delete_activation_backups(wallet_id, rotation_id)
        return prepared_record

    def _forward_committed_chain(
        self, wallet_id: str, timeline: "RotationTimeline"
    ) -> None:
        """激活事件链已提交：把钱包元数据/在用份额/全部轮换记录前滚为
        时间线唯一终态，并清掉已提交轮换的全部暂存/备份残留。

        只有时间线最近一次激活的两份私钥必须就位（在用份额目录或其暂存
        目录），逐份密码学校验；历史轮次份额本应已被后续激活删除。
        缺最新份额、私钥与事件公钥不符或元数据无法构造时抛 RecoveryError
        （fail-closed），绝不猜写密钥。"""
        latest = timeline.latest
        current = self.get_wallet(wallet_id)
        if latest is None:
            return
        if not isinstance(current, dict):
            raise RecoveryError(
                f"wallet {wallet_id!r} metadata missing during roll-forward"
            )
        rotation_id = latest.rotation_id
        first, second = RotationTimeline._pubkey_halves(
            latest.public_key,
            f"rotation {rotation_id!r} committed public key",
        )
        expected = {
            latest.share_ids[0]: first,
            latest.share_ids[1]: second,
        }
        new_share_records: list[dict] = []
        for sid in latest.share_ids:
            record = self.get_share(wallet_id, sid)
            if not self._share_record_ok(record, sid, expected[sid]):
                # 崩溃可能发生在新份额全部换入前：暂存里仍有新份额
                record = self.get_staging_share(wallet_id, rotation_id, sid)
                if not self._share_record_ok(record, sid, expected[sid]):
                    raise RecoveryError(
                        f"rotation {rotation_id!r} missing valid new share "
                        f"{sid!r} to roll forward"
                    )
            new_share_records.append(dict(record))
        # 两份公钥按序拼接必须恰为事件提交的钱包公钥
        combined = combine_public_keys(
            [bytes.fromhex(expected[sid]) for sid in latest.share_ids]
        ).hex()
        if combined != latest.public_key:
            raise RecoveryError(
                f"rotation {rotation_id!r} share halves do not match the "
                "committed public key"
            )
        new_meta = dict(current)
        new_meta["wallet_id"] = wallet_id
        new_meta["shares"] = [
            {"share_id": sid, "public_key": expected[sid]}
            for sid in latest.share_ids
        ]
        new_meta["public_key"] = latest.public_key

        # 前滚写盘：新份额、元数据、淘汰份额清理
        for share_record in new_share_records:
            self.save_share(wallet_id, share_record)
        self.save_wallet_meta(wallet_id, new_meta)
        for sid in timeline.retired_share_ids():
            if _SAFE_SHARE_ID.match(sid):
                self.delete_share(wallet_id, sid)
        # 全部已提交轮换记录置为唯一 active（含从 activating 前滚），
        # previous_public_key 以事件链为准，并清掉它们的暂存/备份残留。
        for attempt in timeline.committed:
            record = self.get_rotation(wallet_id, attempt.rotation_id)
            if record is None:
                raise RecoveryError(
                    f"rotation {attempt.rotation_id!r} record missing during "
                    "roll-forward"
                )
            active_record = dict(record)
            active_record["state"] = "active"
            active_record["share_ids"] = list(attempt.share_ids)
            active_record["public_key"] = attempt.public_key
            active_record["previous_public_key"] = attempt.previous_public_key
            if active_record != record:
                self.update_rotation(
                    wallet_id, attempt.rotation_id, active_record
                )
            self.delete_staging(wallet_id, attempt.rotation_id)

    def recover_wallet_rotation(
        self,
        wallet_id: str,
        events: Optional[list[dict]] = None,
    ) -> "RotationTimeline":
        """按审计 seq 时间线恢复该钱包的全部轮换现场（调用方须持锁）。

        以仅追加审计中的 prepared/activated 事件序列为唯一权威：

        1. 先按 prepared seq **逆序回滚**所有激活事件未落盘的尝试
           （prepared/activating/active 状态但无对应 activated 事件），
           恢复时间线上紧邻的上一轮公钥与两份份额、置回 prepared、
           保留经校验有效的暂存新份额；无法安全对账则 fail-closed；
        2. 再按激活 seq **顺序前滚**已提交链：校验轮换记录、share_ids、
           公钥、previous_public_key 与两份私钥后，把在用份额/钱包元数据
           /轮换状态补齐为唯一 active 终态，清掉全部暂存/备份；
        3. 保留的 prepared 暂存逐份密码学校验，失效则连记录带暂存安全
           删除（审计中的 prepared 事件作为孤立历史保留）；无 prepared
           事件的 prepared 残留同样安全删除；孤儿暂存目录安全删除。

        恢复不新增审计事件、不分配 seq；返回校验后的时间线供会话恢复
        复用。审计/记录无法解析或时间线不一致时抛 RecoveryError/
        CorruptDataError，保留现场、fail-closed。
        """
        _check_id("wallet_id", wallet_id)
        if events is None:
            from .audit import AuditStore

            events = AuditStore(self.data_dir).rotation_events(wallet_id)
        activated_ids = {
            e["details"]["rotation_id"]
            for e in events
            if e.get("type") == "share_rotation_activated"
            and isinstance(e.get("details"), dict)
        }
        # 已激活记录畸形 -> RecoveryError；未激活畸形记录按契约安全删除
        records = self._rotation_records(wallet_id, activated_ids)
        timeline = build_rotation_timeline(events, records)

        # 1. 无 prepared 事件的残留：prepared 状态安全删除（准备未提交）；
        #    activating/active 却无 prepared 事件无法对账，fail-closed。
        for rotation_id in sorted(timeline.residue_ids):
            record = records.get(rotation_id) or self.get_rotation(
                wallet_id, rotation_id
            )
            if record is not None and record.get("state") != "prepared":
                raise RecoveryError(
                    f"wallet {wallet_id!r} rotation {rotation_id!r} is "
                    f"{record.get('state')} without a prepared event"
                )
            self.delete_rotation(wallet_id, rotation_id)
            self.delete_staging(wallet_id, rotation_id)
            # 换入残留（正常流程不会出现）不属于任何已提交份额，安全删除
            if record is not None:
                for sid in record.get("share_ids", []):
                    if (
                        isinstance(sid, str)
                        and _SAFE_SHARE_ID.match(sid)
                        and sid not in timeline.live_share_ids()
                    ):
                        self.delete_share(wallet_id, sid)

        # 2. 逆序回滚激活事件未落盘的尝试（先回滚最新的，逐级恢复上一轮）
        uncommitted = [
            a
            for a in reversed(timeline.attempts)
            if a.activated_seq is None
        ]
        for attempt in uncommitted:
            index = timeline.attempts.index(attempt)
            prior_committed = [
                a for a in timeline.attempts[:index]
                if a.activated_seq is not None
            ]
            if prior_committed:
                predecessor = prior_committed[-1]
                predecessor_public: Optional[str] = predecessor.public_key
                predecessor_share_ids: Optional[tuple[str, str]] = (
                    predecessor.share_ids
                )
            else:
                # 首轮换且此前无已激活链：创世公钥/份额从激活备份或未换入
                # 的当前元数据解析，由 _rollback_uncommitted_attempt 完成。
                predecessor_public = None
                predecessor_share_ids = None
            record = self.get_rotation(wallet_id, attempt.rotation_id)
            if record is None:
                continue
            # 同名轮换可能被放弃后重新准备：记录只属于最近一次尝试。记录
            # 三元组与本未提交尝试不符时，它属于更新的尝试，跳过。
            if (
                record.get("public_key") != attempt.public_key
                or tuple(record.get("share_ids") or ()) != attempt.share_ids
            ):
                continue
            current = self.get_wallet(wallet_id)
            swapped = (
                isinstance(current, dict)
                and current.get("public_key") == attempt.public_key
            )
            lingering = any(
                self.get_share(wallet_id, sid) is not None
                for sid in attempt.share_ids
            )
            if (
                record.get("state") == "prepared"
                and not swapped
                and not lingering
            ):
                # 静止 prepared：仅暂存校验在第 4 步处理
                continue
            # 记录停在 activating/active、或记录已置 prepared 但换入仍发生
            # （元数据指向新公钥/新份额文件残留）的窗口：统一按事件未落盘
            # 回滚——恢复上一轮公钥与两份份额、删除换入份额、置回 prepared；
            # 无备份且无法对账时由回滚方法 fail-closed。
            self._rollback_uncommitted_attempt(
                wallet_id,
                attempt,
                predecessor_public,
                predecessor_share_ids,
            )

        # 3. 顺序前滚已提交激活链（回滚后历史轮次份额已由备份逐级恢复，
        #    最近一次激活的两份份额必定可在用/暂存中找到）
        self._forward_committed_chain(wallet_id, timeline)

        # 4. 保留的 prepared 轮换：暂存逐份密码学校验，失效安全删除。
        #    仅处理记录三元组与最近一次尝试一致的轮换；同名旧尝试的记录
        #    已不存在（放弃时随暂存一起删除），审计中只留孤立 prepared。
        kept_prepared: set[str] = set()
        for attempt in timeline.attempts:
            if attempt.activated_seq is not None:
                continue
            record = self.get_rotation(wallet_id, attempt.rotation_id)
            if record is None:
                continue
            if (
                record.get("public_key") != attempt.public_key
                or tuple(record.get("share_ids") or ()) != attempt.share_ids
            ):
                continue
            if self._prepared_staging_valid(wallet_id, record):
                kept_prepared.add(attempt.rotation_id)
            else:
                self.delete_rotation(wallet_id, attempt.rotation_id)
                self.delete_staging(wallet_id, attempt.rotation_id)
                # 该放弃尝试的份额绝不能留在在用目录（私钥隔离）；当前在用
                # 两份不在其中，删除安全。
                for sid in attempt.share_ids:
                    if sid not in timeline.live_share_ids():
                        self.delete_share(wallet_id, sid)

        # 5. 孤儿暂存目录：不属于任何保留 prepared 的一律安全删除
        for rotation_id in self.list_staging_rotation_ids(wallet_id):
            if rotation_id not in kept_prepared:
                self.delete_staging(wallet_id, rotation_id)
        return timeline

    def load_rotation_timeline(
        self,
        wallet_id: str,
        events: Optional[list[dict]] = None,
    ) -> "RotationTimeline":
        """只读构建轮换时间线（不做任何前滚/回滚/清理）。

        轮换恢复已先于会话恢复完成，故此处遇到形状非法记录按数据损坏
        fail-closed，绝不跳过。会话恢复据此解析历史份额公钥与各 seq
        时刻的在用快照。"""
        _check_id("wallet_id", wallet_id)
        if events is None:
            from .audit import AuditStore

            events = AuditStore(self.data_dir).rotation_events(wallet_id)
        # 严格只读：任何畸形记录都视为数据损坏抛 CorruptDataError，绝不
        # 写盘删除；heal 捕获后转入完整恢复（未激活畸形由恢复安全删除，
        # 已激活畸形 fail-closed）。
        records: dict[str, dict] = {}
        for key, record in self.list_rotation_entries(wallet_id):
            if (
                self._rotation_record_shape_ok(record)
                and record.get("rotation_id") == key
            ):
                records[key] = record
            else:
                raise CorruptDataError(
                    f"rotation records for wallet {wallet_id!r} contain a "
                    f"malformed entry {key!r}"
                )
        return build_rotation_timeline(events, records)

    def recover_incomplete_activations(self) -> None:
        """启动恢复（无跨进程锁的独立入口；serve 使用 service 层的加锁
        编排）。从各钱包审计日志读取轮换事件并按时间线恢复。恢复失败
        向上抛出 RecoveryError/OSError，由调用方阻止服务就绪。"""
        from .audit import AuditStore

        audit_store = AuditStore(self.data_dir)
        wallet_ids = sorted(
            set(self.list_rotation_wallet_ids())
            | set(self.list_staging_wallet_ids())
        )
        for wallet_id in wallet_ids:
            self.recover_wallet_rotation(
                wallet_id, audit_store.rotation_events(wallet_id)
            )



class RotationAttempt:
    """一次份额轮换尝试（同一 rotation_id 被放弃后重新准备会产生新尝试）。

    尝试由审计事件唯一标识：prepared 事件确定
    ``(rotation_id, share_ids, public_key)``；随后的 activated 事件要么
    属于且仅属于同一尝试（三个标识一致），要么该尝试从未激活（暂存失效
    的 prepared 记录会被恢复安全删除，仅审计留下孤立 prepared 事件）。
    """

    __slots__ = (
        "rotation_id",
        "prepared_seq",
        "activated_seq",
        "share_ids",
        "public_key",
        "previous_public_key",
    )

    def __init__(
        self,
        rotation_id: str,
        prepared_seq: int,
        share_ids: tuple[str, str],
        public_key: str,
    ) -> None:
        self.rotation_id = rotation_id
        self.prepared_seq = prepared_seq
        self.activated_seq: Optional[int] = None
        self.share_ids = share_ids
        self.public_key = public_key
        self.previous_public_key: Optional[str] = None


class RotationTimeline:
    """按审计 seq 严格校验后的连续份额轮换时间线（纯内存，不触盘）。

    - ``attempts`` 为全部 prepared 尝试，按 prepared 事件 seq 升序；从未
      激活的孤立 prepared（记录已安全删除）只存在于审计历史中；
    - ``committed`` 为已激活尝试，按激活事件 seq 升序，其
      previous_public_key 必须构成连续公钥链（首条之前为创世公钥
      ``genesis_public_key``），相邻轮次公钥不同、份额集合互不相交；
    - ``residue_ids`` 为有轮换记录却匹配不到任何 prepared 尝试的
      rotation_id（准备事件未落盘的崩溃残留，恢复时连记录带暂存安全
      删除）。

    严格拒绝：seq 缺失/重复/乱序、事件形状非法、activated 没有对应
    prepared（缺失）、同一尝试 prepared/activated 重复、prepared 与
    activated 标识不一致、激活链 previous_public_key 断链、跨轮份额 id
    复用、已激活尝试缺少记录或记录与事件不一致。从未激活的孤立 prepared
    不影响激活链，按公开契约容忍。
    """

    def __init__(
        self,
        attempts: list[RotationAttempt],
        residue_ids: set[str],
    ) -> None:
        self.attempts = attempts
        self.residue_ids = residue_ids
        self.committed = [
            a for a in attempts if a.activated_seq is not None
        ]
        self.genesis_public_key: Optional[str] = (
            self.committed[0].previous_public_key
            if self.committed
            else None
        )

    @property
    def latest(self) -> Optional[RotationAttempt]:
        """最近一次已提交激活的尝试；从未激活过时为 None。"""
        return self.committed[-1] if self.committed else None

    def live_share_ids(self) -> tuple[str, str]:
        """时间线当前在用两份份额（无激活时为创世份额）。"""
        if self.committed:
            return self.committed[-1].share_ids
        return ("share-1", "share-2")

    def live_public_key(self, fallback: Optional[str] = None) -> Optional[str]:
        """当前在用钱包公钥：最近激活的公钥；无激活时用调用方给出的
        （钱包元数据中的）创世公钥。"""
        if self.committed:
            return self.committed[-1].public_key
        return fallback

    @staticmethod
    def _pubkey_halves(pubkey_hex: str, where: str) -> tuple[str, str]:
        try:
            raw = bytes.fromhex(pubkey_hex)
        except ValueError as exc:
            raise RecoveryError(f"{where} is not hex") from exc
        if len(raw) != 64:
            raise RecoveryError(f"{where} is not 64 bytes")
        return raw[:32].hex(), raw[32:].hex()

    def share_public_keys(self) -> dict[str, str]:
        """沿创世公钥与已激活链解析每个份额 id 的权威 32 字节公钥（hex）。

        同一 share_id 在链上被解析出不同公钥（外部篡改/跨链不相容）即
        fail-closed，绝不静默选一个。"""
        result: dict[str, str] = {}

        def put(share_id: str, public_hex: str, where: str) -> None:
            existing = result.get(share_id)
            if existing is not None and existing != public_hex:
                raise RecoveryError(
                    f"share {share_id!r} resolves to conflicting public keys "
                    f"in the rotation timeline ({where})"
                )
            result[share_id] = public_hex

        if self.genesis_public_key is not None:
            first, second = self._pubkey_halves(
                self.genesis_public_key, "genesis public_key"
            )
            put("share-1", first, "genesis")
            put("share-2", second, "genesis")
        for attempt in self.committed:
            first, second = self._pubkey_halves(
                attempt.public_key,
                f"rotation {attempt.rotation_id!r} public_key",
            )
            put(attempt.share_ids[0], first, attempt.rotation_id)
            put(attempt.share_ids[1], second, attempt.rotation_id)
        return result

    def public_key_for(self, share_id: str) -> str:
        """份额 id 的权威历史公钥；解析不出即 RecoveryError。"""
        public = self.share_public_keys().get(share_id)
        if public is None:
            raise RecoveryError(
                f"share {share_id!r} has no resolvable public key in the "
                "rotation timeline"
            )
        return public

    def active_share_set_at(self, seq: int) -> tuple[str, str]:
        """审计 seq 时刻的在用两份份额（首个激活之前为创世份额）。"""
        active = ("share-1", "share-2")
        for attempt in self.committed:
            if attempt.activated_seq <= seq:
                active = attempt.share_ids
            else:
                break
        return active

    def retired_share_ids(self) -> set[str]:
        """已被已提交轮换淘汰、当前不应再留在在用份额目录中的份额 id。"""
        retired: set[str] = set()
        if self.committed:
            retired.update(("share-1", "share-2"))
            for attempt in self.committed[:-1]:
                retired.update(attempt.share_ids)
        retired.difference_update(self.live_share_ids())
        return retired


def _rotation_event_detail_ok(details: object, *, with_previous: bool) -> bool:
    if not isinstance(details, dict):
        return False
    rotation_id = details.get("rotation_id")
    if not _valid_safe_id(rotation_id):
        return False
    share_ids = details.get("share_ids")
    if (
        not isinstance(share_ids, list)
        or len(share_ids) != 2
        or len(set(share_ids)) != 2
        or any(not isinstance(sid, str) or not _SAFE_SHARE_ID.match(sid)
               for sid in share_ids)
    ):
        return False
    public_key = details.get("public_key")
    if not isinstance(public_key, str):
        return False
    try:
        if len(bytes.fromhex(public_key)) != 64:
            return False
    except ValueError:
        return False
    if with_previous:
        previous = details.get("previous_public_key")
        if not isinstance(previous, str):
            return False
        try:
            if len(bytes.fromhex(previous)) != 64:
                return False
        except ValueError:
            return False
    return True


def build_rotation_timeline(
    events: list[dict], records: dict[str, dict]
) -> RotationTimeline:
    """以仅追加审计中的轮换事件序列为权威，构建连续公钥/份额时间线。

    ``events`` 为 prepared/activated 轮换事件（按 seq 升序）；``records``
    为轮换记录文件中 rotation_id -> record 的映射。

    每次 prepared 事件产生一个尝试，由
    ``(rotation_id, share_ids, public_key)`` 标识；同一 rotation_id 在旧
    尝试从未激活（暂存失效、记录被安全删除）后重新准备是公开契约允许的
    历史，旧 prepared 事件作为孤立尝试保留在审计中，不进入激活链。严格
    拒绝：

    - seq 非正整数、布尔、重复或乱序；事件 details 形状非法；
    - activated 没有对应 prepared（缺失）、同一尝试 activated 重复、
      activated 与该 rotation 最近一次 prepared 标识不一致；
    - 激活链断链：previous_public_key 不等于上一已激活公钥（首条激活
      确立创世公钥），或新旧公钥相同；
    - 跨已激活轮次份额集合相交（同一 id 被两轮已激活轮换复用）；
    - 已激活尝试缺少记录，或记录的 state/share_ids/public_key/
      previous_public_key 与事件不一致。
    """
    attempts: list[RotationAttempt] = []
    attempts_by_rotation: dict[str, list[RotationAttempt]] = {}
    last_committed_public: Optional[str] = None
    committed_share_sets: set[tuple[str, str]] = set()
    last_seq = 0
    open_attempt: Optional[RotationAttempt] = None

    def record_matches(attempt: RotationAttempt) -> bool:
        record = records.get(attempt.rotation_id)
        return (
            isinstance(record, dict)
            and record.get("public_key") == attempt.public_key
            and tuple(record.get("share_ids") or ()) == attempt.share_ids
        )

    for event in events:
        seq = event.get("seq")
        if not isinstance(seq, int) or isinstance(seq, bool) or seq < 1:
            raise RecoveryError("rotation event has an illegal seq")
        if seq <= last_seq:
            raise RecoveryError("rotation events are missing or out of order")
        last_seq = seq
        event_type = event.get("type")
        with_previous = event_type == "share_rotation_activated"
        details = event.get("details")
        if not _rotation_event_detail_ok(details, with_previous=with_previous):
            raise RecoveryError("rotation event has malformed details")
        rotation_id = details["rotation_id"]
        share_ids = (details["share_ids"][0], details["share_ids"][1])
        public_key = details["public_key"]
        prior = attempts_by_rotation.get(rotation_id, [])

        if event_type == "share_rotation_prepared":
            if any(
                a.share_ids == share_ids
                and a.public_key == public_key
                for a in prior
            ):
                raise RecoveryError(
                    f"rotation {rotation_id!r} prepared event is duplicated"
                )
            if open_attempt is not None and record_matches(open_attempt):
                # 上一轮换仍未激活且记录仍在（既可能是同 id 也可能是不同
                # id）：业务上每钱包同时只允许一个 prepared，这是乱序现场；
                # 仅当上一轮记录已被恢复安全删除（孤立 prepared）时才允许
                # 后续准备。
                raise RecoveryError(
                    f"rotation {rotation_id!r} prepared while rotation "
                    f"{open_attempt.rotation_id!r} is still open"
                )
            attempt = RotationAttempt(rotation_id, seq, share_ids, public_key)
            attempts.append(attempt)
            prior.append(attempt)
            attempts_by_rotation[rotation_id] = prior
            open_attempt = attempt
            continue

        # activated：必须对应该 rotation 最近一次 prepared 尝试，且它就是
        # 当前未关闭尝试（不同 id 的尝试仍开着即乱序）。
        if not prior:
            raise RecoveryError(
                f"rotation {rotation_id!r} activated without a prepared event"
            )
        attempt = prior[-1]
        if open_attempt is not attempt:
            raise RecoveryError(
                f"rotation {rotation_id!r} activated while another rotation "
                "is still open"
            )
        if attempt.activated_seq is not None:
            raise RecoveryError(
                f"rotation {rotation_id!r} activated event is duplicated"
            )
        if (
            attempt.share_ids != share_ids
            or attempt.public_key != public_key
        ):
            raise RecoveryError(
                f"rotation {rotation_id!r} activated event does not match its "
                "latest prepared event"
            )
        event_previous = details["previous_public_key"]
        if public_key == event_previous:
            raise RecoveryError(
                f"rotation {rotation_id!r} activates the same public key"
            )
        if last_committed_public is None:
            # 首条激活确立创世公钥
            last_committed_public = event_previous
        if event_previous != last_committed_public:
            raise RecoveryError(
                f"rotation {rotation_id!r} previous_public_key breaks the "
                "continuous public-key chain"
            )
        if share_ids in committed_share_sets:
            raise RecoveryError(
                f"rotation {rotation_id!r} reuses share ids from an earlier "
                "committed rotation"
            )
        attempt.activated_seq = seq
        attempt.previous_public_key = event_previous
        committed_share_sets.add(share_ids)
        last_committed_public = public_key
        open_attempt = None

    # 事件 vs 记录一致性
    residue_ids: set[str] = set()
    for key, record in records.items():
        rotation_id = record.get("rotation_id") if isinstance(record, dict) else None
        if not isinstance(rotation_id, str) or rotation_id != key:
            # 形状/键不符由调用方按无效记录处理，不进入时间线
            continue
        prior = attempts_by_rotation.get(rotation_id, ())
        if not prior:
            # 有记录却无任何 prepared 事件：准备事件未落盘的崩溃残留
            residue_ids.add(rotation_id)
            continue
        attempt = prior[-1]
        share_ids = record.get("share_ids")
        record_ids = (
            (share_ids[0], share_ids[1])
            if isinstance(share_ids, list) and len(share_ids) == 2
            else None
        )
        if record_ids != attempt.share_ids:
            raise RecoveryError(
                f"rotation {rotation_id!r} record share_ids do not match its "
                "latest prepared event"
            )
        if record.get("public_key") != attempt.public_key:
            raise RecoveryError(
                f"rotation {rotation_id!r} record public_key does not match "
                "its latest prepared event"
            )
        state = record.get("state")
        if state not in ("prepared", "activating", "active"):
            raise RecoveryError(
                f"rotation {rotation_id!r} record has illegal state {state!r}"
            )
        if attempt.activated_seq is not None:
            if state == "prepared":
                raise RecoveryError(
                    f"rotation {rotation_id!r} is activated in audit but its "
                    "record state is prepared"
                )
            if record.get("previous_public_key") != attempt.previous_public_key:
                raise RecoveryError(
                    f"rotation {rotation_id!r} record previous_public_key does "
                    "not match the activated event"
                )

    # 已激活尝试必须有匹配记录（孤立 prepared 不需要）
    record_triples = {
        (
            r.get("rotation_id"),
            (
                tuple(r["share_ids"])
                if isinstance(r.get("share_ids"), list)
                and len(r["share_ids"]) == 2
                else None
            ),
            r.get("public_key"),
        )
        for r in records.values()
        if isinstance(r, dict)
    }
    for attempt in attempts:
        if attempt.activated_seq is None:
            continue
        triple = (
            attempt.rotation_id,
            attempt.share_ids,
            attempt.public_key,
        )
        if triple not in record_triples:
            raise RecoveryError(
                f"rotation {attempt.rotation_id!r} is activated in audit but "
                "has no matching rotation record"
            )

    return RotationTimeline(attempts, residue_ids)


