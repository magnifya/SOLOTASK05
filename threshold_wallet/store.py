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


def _is_replacement_share_id(value: object) -> bool:
    """会话参与者替换份额的 id 形态：``<replacement_id>-share``。

    钱包/轮换份额（share-1、share-2、<rotation_id>-share-N）从不以
    ``-share`` 结尾，故 shares/<wallet_id>/ 下以 ``-share`` 结尾的正式
    份额文件只会来自会话参与者替换；轮换现场对账对它们豁免（其有无与
    自洽性由签名会话恢复按 session_participant_replaced 事件对账）。
    """
    return isinstance(value, str) and value.endswith("-share")


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


def _is_lower_hex_32(value: object) -> bool:
    """恰为 64 位小写 hex（32 字节）的字符串判定。"""
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(c in "0123456789abcdef" for c in value)
    )


def chain_report_shape_ok(report: object) -> bool:
    """链上确认数报告 B 的形状：恰含 chain_id/tx_id/block_height/
    block_hash/confirmations 五键，chain_id 为安全标识，tx_id 与
    block_hash 为 64 位小写 hex，block_height/confirmations 为非布尔
    非负整数。"""
    if not isinstance(report, dict):
        return False
    if set(report) != {
        "chain_id",
        "tx_id",
        "block_height",
        "block_hash",
        "confirmations",
    }:
        return False
    if not _valid_safe_id(report["chain_id"]):
        return False
    if not _is_lower_hex_32(report["tx_id"]):
        return False
    if not _is_lower_hex_32(report["block_hash"]):
        return False
    if not _is_plain_int(report["block_height"]) or report["block_height"] < 0:
        return False
    return _is_plain_int(report["confirmations"]) and report["confirmations"] >= 0


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

    def asset_ledger_file_exists(self, wallet_id: str) -> bool:
        """该钱包的账本文件是否存在（存在即需语义/事件对账，哪怕为空）。"""
        return os.path.exists(self._assets_path(wallet_id))

    def check_asset_ledger_semantics(self, wallet_id: str) -> dict:
        """在形状合法的前提下，对账本做**语义**对账（纯账本，不读审计）。

        形状合法只能保证字段类型正确，无法发现 JSON 可解析但自相矛盾的
        现场；本方法按正常服务只会写出的不变量重算：

        - 每条操作（pending/committed）都必须携带非布尔整数
          balance/version 快照（服务落盘的 R 恒含这两项）；
        - 对每个资产，按 version 升序的 committed 操作必须恰为
          version 1..K（不缺号、不重号、起点为 1），且余额从 0 起按
          delta 逐条累加，每个前缀余额都必须非负、与记录快照一致；
        - K>=1 时资产条目必须恰为 {balance: 末态, version: K}；
          K=0（只有/没有 pending）时不得存在资产条目；
        - pending 操作的 (balance, version) 快照必须等于该资产某条已提交
          前缀（version 在 0..K 内且余额与重算前缀一致）——快照是创建
          时刻的账本状态，提交交错时它可能落后于当前末态。

        任一矛盾抛 CorruptDataError（fail-closed，保留现场），绝不带
        矛盾账本继续创建/提交/查询。返回校验后的账本供上层与审计对账。
        """
        _check_id("wallet_id", wallet_id)
        ledger = self._read_asset_ledger(wallet_id)
        operations = ledger["operations"]
        assets = ledger["assets"]

        asset_ids: set[str] = set()
        pending_by_asset: dict[str, list[dict]] = {}
        committed_by_asset: dict[str, list[dict]] = {}
        for record in operations.values():
            asset_id = record["asset_id"]
            asset_ids.add(asset_id)
            if (
                not _is_plain_int(record.get("balance"))
                or not _is_plain_int(record.get("version"))
            ):
                raise CorruptDataError(
                    f"asset ledger for wallet {wallet_id!r} operation "
                    f"{record.get('operation_id')!r} lacks a snapshot"
                )
            if record["state"] == "committed":
                committed_by_asset.setdefault(asset_id, []).append(record)
            else:
                pending_by_asset.setdefault(asset_id, []).append(record)

        for asset_id, entry in assets.items():
            asset_ids.add(asset_id)

        prefix_balances: dict[str, list[int]] = {}
        for asset_id in asset_ids:
            commits = committed_by_asset.get(asset_id, [])
            ordered = sorted(commits, key=lambda r: r["version"])
            versions = [r["version"] for r in ordered]
            k_total = len(ordered)
            if versions != list(range(1, k_total + 1)):
                raise CorruptDataError(
                    f"asset ledger for wallet {wallet_id!r} asset "
                    f"{asset_id!r} has non-contiguous committed versions"
                )
            balances = [0]
            balance = 0
            for ordinal, record in enumerate(ordered, start=1):
                if record["version"] != ordinal:
                    raise CorruptDataError(
                        f"asset ledger for wallet {wallet_id!r} asset "
                        f"{asset_id!r} version ordering is inconsistent"
                    )
                balance += record["delta"]
                if balance < 0:
                    # 余额不足的提交在正常流程会被 409 拒绝：负余额前缀
                    # 只可能是外部篡改/丢失操作
                    raise CorruptDataError(
                        f"asset ledger for wallet {wallet_id!r} asset "
                        f"{asset_id!r} goes negative"
                    )
                if record["balance"] != balance:
                    raise CorruptDataError(
                        f"asset ledger for wallet {wallet_id!r} asset "
                        f"{asset_id!r} balance does not recompute"
                    )
                balances.append(balance)
            prefix_balances[asset_id] = balances

            entry = assets.get(asset_id)
            if k_total == 0:
                if entry is not None:
                    # 无任何已提交操作却存在资产条目：半完成/矛盾现场
                    raise CorruptDataError(
                        f"asset ledger for wallet {wallet_id!r} asset "
                        f"{asset_id!r} exists without committed operations"
                    )
            elif entry != {"balance": balance, "version": k_total}:
                raise CorruptDataError(
                    f"asset ledger for wallet {wallet_id!r} asset "
                    f"{asset_id!r} entry does not match its committed tail"
                )

        for asset_id, pendings in pending_by_asset.items():
            balances = prefix_balances[asset_id]
            k_total = len(balances) - 1
            for record in pendings:
                version = record["version"]
                if not 0 <= version <= k_total:
                    raise CorruptDataError(
                        f"asset ledger for wallet {wallet_id!r} operation "
                        f"{record['operation_id']!r} snapshot version is out "
                        "of the committed prefix range"
                    )
                if record["balance"] != balances[version]:
                    # pending 快照必须等于创建时刻（某条已提交前缀）的余额
                    raise CorruptDataError(
                        f"asset ledger for wallet {wallet_id!r} operation "
                        f"{record['operation_id']!r} snapshot balance does not "
                        "match the committed prefix"
                    )
        return ledger

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
        提交结果 new_balance/new_version；链上确认报告触发的提交另带
        可选键 report（达门槛报告 B）。任一字段缺失、类型错误、布尔
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
        # 链上确认报告触发的提交在意图中随附达门槛报告 B（可选键）：
        # 存在即按"报告事件 + 紧邻提交事件"的链报告提交点严格对账
        # （合法前缀回滚 / 紧邻同体前滚 / 无法判定保留现场），形状必须
        # 合法，否则无法安全对账。
        report = intent.get("report")
        if report is not None and not chain_report_shape_ok(report):
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

    def list_share_files(self, wallet_id: str) -> list[str]:
        """列出 shares/<wallet_id>/ 目录内全部份额文件对应的 share_id
        （仅纳入形如 <合法 share_id>.json 的正式文件，忽略临时残留）。"""
        base = os.path.join(self._shares_dir, wallet_id)
        try:
            names = os.listdir(base)
        except (FileNotFoundError, NotADirectoryError):
            return []
        result = []
        for name in names:
            if not name.endswith(".json"):
                continue
            share_id = name[: -len(".json")]
            if _SAFE_SHARE_ID.match(share_id):
                result.append(share_id)
        return sorted(result)

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
            or len(set(share_ids)) != 2
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
        # previous_public_key 仅 activating/active 携带；一旦存在必须是
        # 64 字节公钥 hex（链对账用），形状非法即不可对账。
        previous = record.get("previous_public_key")
        if previous is not None:
            if not isinstance(previous, str):
                return False
            try:
                if len(bytes.fromhex(previous)) != 64:
                    return False
            except ValueError:
                return False
        created_at = record.get("created_at")
        if created_at is not None and not isinstance(created_at, str):
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

    def _assert_rollback_possible(
        self,
        wallet_id: str,
        record: dict,
        expected_previous: Optional[str] = None,
    ) -> None:
        """事件未落盘的激活回滚前，确认能安全恢复旧钱包与旧份额。

        - 钱包元数据仍指向旧公钥（换入尚未发生）：只要当前元数据里的
          旧份额文件都还在即可，换入的新份额会在回滚时删除，无需备份；
        - 元数据已指向新公钥（换入已发生）：必须有激活前的钱包/份额
          备份作为权威回滚依据；
        - 元数据旧但旧份额缺失：同样必须有备份。
        expected_preversed 为审计激活链中该轮换的前一轮在用公钥（无激活
        历史时为 None）：记录自报的 previous_public_key 必须与之相容，
        否则属于跨轮次不相容现场，fail-closed。无法安全恢复时抛
        RecoveryError，绝不猜写旧密钥。
        """
        rotation_id = record["rotation_id"]
        current = self.get_wallet(wallet_id)
        if not isinstance(current, dict):
            raise RecoveryError(
                f"wallet {wallet_id!r} metadata missing during rollback"
            )
        backup_meta = self._load_backup_wallet_meta(wallet_id, rotation_id)
        recorded_previous = record.get("previous_public_key")
        # 记录/备份/链上的 previous 必须互相一致
        authoritative_previous = expected_previous
        if isinstance(backup_meta, dict) and isinstance(
            backup_meta.get("public_key"), str
        ):
            backup_previous = backup_meta["public_key"]
            if authoritative_previous is None:
                authoritative_previous = backup_previous
            elif backup_previous != authoritative_previous:
                raise RecoveryError(
                    f"wallet {wallet_id!r} rotation {rotation_id!r} backup "
                    "public_key is incompatible with the rotation chain"
                )
        if isinstance(recorded_previous, str):
            if authoritative_previous is None:
                authoritative_previous = recorded_previous
            elif recorded_previous != authoritative_previous:
                raise RecoveryError(
                    f"wallet {wallet_id!r} rotation {rotation_id!r} "
                    "previous_public_key is incompatible with the rotation chain"
                )
        if authoritative_previous is not None:
            if current.get("public_key") not in (
                record["public_key"],
                authoritative_previous,
            ):
                # 当前钱包公钥既不是本轮目标、也不是上一轮在用公钥：
                # 属于跨轮次不相容现场，无法判断该回到哪里，fail-closed。
                raise RecoveryError(
                    f"wallet {wallet_id!r} rotation {rotation_id!r} current "
                    "public_key matches neither this nor the previous rotation"
                )

        swapped = current.get("public_key") == record["public_key"]
        if swapped:
            if backup_meta is None:
                raise RecoveryError(
                    f"wallet {wallet_id!r} rotation {rotation_id!r} "
                    "has no activation backup to roll back"
                )
            return
        # 元数据仍旧：旧份额必须完整，否则需备份才能恢复
        shares = current.get("shares")
        old_ids = [
            s.get("share_id")
            for s in shares
            if isinstance(s, dict)
            and s.get("share_id") not in record["share_ids"]
        ] if isinstance(shares, list) else []
        missing = [
            sid
            for sid in old_ids
            if isinstance(sid, str) and self.get_share(wallet_id, sid) is None
        ]
        if missing and backup_meta is None:
            raise RecoveryError(
                f"wallet {wallet_id!r} rotation {rotation_id!r} lost "
                f"in-use shares {missing!r} without backup"
            )

    def _rollback_incomplete_activation(
        self, wallet_id: str, record: dict
    ) -> dict:
        """事件未落盘的激活：回滚旧钱包元数据与旧份额、删除已换入的
        新份额，状态置回 prepared，并清掉激活备份、保留经校验的暂存份额。
        返回置回 prepared 的记录。"""
        self.rollback_activation_files(wallet_id, record)
        rotation_id = record["rotation_id"]
        restored = {
            k: v
            for k, v in record.items()
            if k != "previous_public_key"
        }
        restored["state"] = "prepared"
        self.update_rotation(wallet_id, rotation_id, restored)
        self.delete_activation_backups(wallet_id, rotation_id)
        return restored

    @staticmethod
    def _validated_share_record(
        rotation_id: str, share_id: str, staged: object
    ) -> dict:
        """逐份密码学校验一份新份额：形状/hex/长度/私钥推导公钥必须一致。
        通过返回记录，否则抛 RecoveryError，绝不猜写密钥。"""
        if not isinstance(staged, dict) or staged.get("share_id") != share_id:
            raise RecoveryError(
                f"rotation {rotation_id!r} missing new share {share_id!r}"
            )
        public_hex = staged.get("public_key")
        private_hex = staged.get("private_key")
        if not isinstance(public_hex, str) or not isinstance(private_hex, str):
            raise RecoveryError(
                f"rotation {rotation_id!r} malformed new share"
            )
        try:
            public_bytes = bytes.fromhex(public_hex)
            private_bytes = bytes.fromhex(private_hex)
        except ValueError:
            raise RecoveryError(
                f"rotation {rotation_id!r} non-hex new share"
            )
        if len(public_bytes) != 32 or len(private_bytes) != 32:
            raise RecoveryError(
                f"rotation {rotation_id!r} bad-length new share"
            )
        try:
            if public_key_from_private(private_bytes) != public_bytes:
                raise RecoveryError(
                    f"rotation {rotation_id!r} new share key mismatch"
                )
        except ValueError:
            raise RecoveryError(
                f"rotation {rotation_id!r} invalid new share private key"
            )
        return staged

    def _build_activation_chain(
        self,
        wallet_id: str,
        activated: dict[str, dict],
        records_by_rid: dict[str, dict],
    ) -> list[tuple[int, str, dict]]:
        """按审计 seq 建立已提交激活链 ``[(seq, rotation_id, event)]``。

        拒绝缺失（有激活事件无记录）、重复（同 seq/同公钥/跨轮次份额
        重叠）、乱序（previous_public_key 接不上上一轮 public_key、首项
        前驱指向任一轮在用公钥）、以及事件与记录的 share_ids/public_key/
        previous_public_key 不相容。任一矛盾抛 RecoveryError（fail-closed）。
        """
        ordered = sorted(
            activated.values(), key=lambda event: event.get("seq", 0)
        )
        all_pubkeys = {
            d.get("public_key")
            for d in (
                e.get("details") for e in ordered if isinstance(e.get("details"), dict)
            )
        }
        chain: list[tuple[int, str, dict]] = []
        seen_pubkeys: set[str] = set()
        seen_share_ids: set[str] = set()
        previous_pubkey: Optional[str] = None
        last_seq = 0
        for event in ordered:
            seq = event.get("seq")
            if (
                not isinstance(seq, int)
                or isinstance(seq, bool)
                or seq <= last_seq
            ):
                raise RecoveryError(
                    f"wallet {wallet_id!r} rotation activation events have a "
                    "missing, duplicated or out-of-order seq"
                )
            last_seq = seq
            details = event.get("details")
            if not isinstance(details, dict):
                raise RecoveryError(
                    f"wallet {wallet_id!r} rotation activation event {seq!r} "
                    "has no object details"
                )
            rid = details.get("rotation_id")
            share_ids = details.get("share_ids")
            public_key = details.get("public_key")
            prev_key = details.get("previous_public_key")
            if (
                not isinstance(rid, str)
                or not _SAFE_ID.match(rid)
                or not isinstance(share_ids, list)
                or len(share_ids) != 2
                or len(set(share_ids)) != 2
                or any(
                    not isinstance(sid, str) or not _SAFE_SHARE_ID.match(sid)
                    for sid in share_ids
                )
                or not isinstance(public_key, str)
                or not isinstance(prev_key, str)
            ):
                raise RecoveryError(
                    f"wallet {wallet_id!r} rotation activation event {seq!r} "
                    "is malformed"
                )
            try:
                if len(bytes.fromhex(public_key)) != 64 or len(
                    bytes.fromhex(prev_key)
                ) != 64:
                    raise ValueError
            except ValueError:
                raise RecoveryError(
                    f"wallet {wallet_id!r} rotation activation event {seq!r} "
                    "has a bad-length public key"
                )
            record = records_by_rid.get(rid)
            if record is None:
                # 提交点事件存在却没有轮换记录：缺失，拒绝猜写
                raise RecoveryError(
                    f"wallet {wallet_id!r} has a committed activation for "
                    f"{rid!r} but no rotation record"
                )
            if record["public_key"] != public_key or list(
                record["share_ids"]
            ) != list(share_ids):
                raise RecoveryError(
                    f"wallet {wallet_id!r} rotation {rid!r} record is "
                    "inconsistent with its activated event"
                )
            record_previous = record.get("previous_public_key")
            if (
                isinstance(record_previous, str)
                and record_previous != prev_key
            ):
                raise RecoveryError(
                    f"wallet {wallet_id!r} rotation {rid!r} "
                    "previous_public_key disagrees with its activated event"
                )
            if public_key == prev_key:
                raise RecoveryError(
                    f"wallet {wallet_id!r} rotation {rid!r} does not change "
                    "the wallet public key"
                )
            if previous_pubkey is not None and prev_key != previous_pubkey:
                # 乱序/跨轮次不相容：本轮的 previous 必须恰为上一轮在用公钥
                raise RecoveryError(
                    f"wallet {wallet_id!r} rotation {rid!r} previous_public_key "
                    "does not extend the prior rotation"
                )
            if previous_pubkey is None and prev_key in all_pubkeys:
                # 首项的前驱指向某一轮在用公钥：链被截断或乱序
                raise RecoveryError(
                    f"wallet {wallet_id!r} rotation {rid!r} chains from another "
                    "rotation public key, the chain is incomplete"
                )
            if public_key in seen_pubkeys:
                raise RecoveryError(
                    f"wallet {wallet_id!r} rotation {rid!r} repeats a public key"
                )
            overlap = seen_share_ids.intersection(share_ids)
            if overlap:
                raise RecoveryError(
                    f"wallet {wallet_id!r} rotation {rid!r} reuses shares "
                    f"{sorted(overlap)!r} from an earlier rotation"
                )
            seen_pubkeys.add(public_key)
            seen_share_ids.update(share_ids)
            chain.append((seq, rid, event))
            previous_pubkey = public_key
        return chain

    def _roll_forward_to_tail(
        self,
        wallet_id: str,
        chain: list[tuple[int, str, dict]],
        records_by_rid: dict[str, dict],
    ) -> None:
        """把磁盘现场前滚为激活链链顶（最后一次已提交激活）的唯一结果。

        只有链顶需要对账磁盘份额/钱包元数据：更早的历史激活只把记录校准
        为 active 并清理其暂存私钥残留，绝不重放它们的换入（否则会向后一
        轮已合法删除的份额索要密钥、或把旧公钥写回钱包）。前滚逐份做密码
        学校验，缺份额/对不上时抛 RecoveryError，绝不猜写密钥。
        """
        # 所有已提交激活的记录都校准为 active，previous_public_key 以
        # 提交点事件为准（补齐崩溃窗口里停在 activating/缺字段的记录）。
        for _seq, rid, event in chain:
            record = records_by_rid[rid]
            details = event["details"]
            correct = dict(record)
            correct["state"] = "active"
            correct["share_ids"] = list(details["share_ids"])
            correct["public_key"] = details["public_key"]
            correct["previous_public_key"] = details["previous_public_key"]
            if correct != record:
                self.update_rotation(wallet_id, rid, correct)

        if not chain:
            return
        _tail_seq, tail_rid, tail_event = chain[-1]
        tail_details = tail_event["details"]
        tail_share_ids = list(tail_details["share_ids"])
        tail_public_key = tail_details["public_key"]

        # 链顶两份新份额：在用目录优先，崩溃窗口可能仍在暂存目录。
        tail_share_records: list[dict] = []
        for share_id in tail_share_ids:
            staged = self.get_share(wallet_id, share_id)
            if staged is None:
                staged = self.get_staging_share(
                    wallet_id, tail_rid, share_id
                )
            tail_share_records.append(
                self._validated_share_record(tail_rid, share_id, staged)
            )
        new_public_keys = [
            bytes.fromhex(r["public_key"]) for r in tail_share_records
        ]
        if combine_public_keys(new_public_keys).hex() != tail_public_key:
            raise RecoveryError(
                f"rotation {tail_rid!r} new shares do not match the "
                "committed public key"
            )

        current_meta = self.get_wallet(wallet_id)
        backup_meta = self._read_json(
            self._staging_wallet_backup_path(wallet_id, tail_rid)
        )

        def meta_matches(meta: object) -> bool:
            if not isinstance(meta, dict):
                return False
            if meta.get("public_key") != tail_public_key:
                return False
            entries = meta.get("shares")
            if not isinstance(entries, list) or len(entries) != 2:
                return False
            halves = (
                bytes.fromhex(tail_public_key)[:32].hex(),
                bytes.fromhex(tail_public_key)[32:].hex(),
            )
            for index, entry in enumerate(entries):
                if not isinstance(entry, dict):
                    return False
                if entry.get("share_id") != tail_share_ids[index]:
                    return False
                if entry.get("public_key") != halves[index]:
                    return False
            return True

        if not meta_matches(current_meta):
            base_meta = current_meta if isinstance(current_meta, dict) else backup_meta
            if not isinstance(base_meta, dict):
                raise RecoveryError(
                    f"wallet {wallet_id!r} metadata missing during roll-forward"
                )
            new_meta = dict(base_meta)
            new_meta["wallet_id"] = wallet_id
            new_meta["shares"] = [
                {"share_id": r["share_id"], "public_key": r["public_key"]}
                for r in tail_share_records
            ]
            new_meta["public_key"] = tail_public_key
            self.save_wallet_meta(wallet_id, new_meta)

        # 链顶份额逐份落盘；shares/ 目录最终只能剩链顶两份（清掉创世及
        # 历史各轮残留，也清掉崩溃窗口换入到一半的杂份）。会话参与者替换
        # 份额（*-share）不属于轮换现场，由签名会话恢复对账，这里豁免。
        for share_record in tail_share_records:
            self.save_share(wallet_id, share_record)
        tail_set = set(tail_share_ids)
        for share_id in self.list_share_files(wallet_id):
            if share_id not in tail_set and not _is_replacement_share_id(
                share_id
            ):
                self.delete_share(wallet_id, share_id)

        # 已提交各轮的暂存私钥/备份残留全部清干净（历史轮一般已无目录）。
        for _seq, rid, _event in chain:
            self.delete_staging(wallet_id, rid)

    def forward_complete_activation(
        self, wallet_id: str, record: dict, event: dict
    ) -> None:
        """share_rotation_activated 事件已落盘后的前滚入口（激活事务
        异常分支与恢复共用）。

        不孤立地只处理本轮：而是按审计中的全部已提交激活事件重建链，
        把磁盘对账到真正的链顶，并校验链连续/事件与记录一致。这样连续
        多轮轮换后，任一轮换的异常收尾都不会把历史轮误当未完成轮换重做。
        缺新份额或现场自相矛盾时抛 RecoveryError（fail-closed）。"""
        from .audit import AuditStore

        audit_store = AuditStore(self.data_dir)
        activated = audit_store.activated_rotation_events(wallet_id)
        prepared = audit_store.prepared_rotation_events(wallet_id)
        # 调用方持锁且传入的事件必定已落盘；防御性确保它在链映射中。
        details = event.get("details")
        rid = details.get("rotation_id") if isinstance(details, dict) else None
        if isinstance(rid, str):
            activated.setdefault(rid, event)
        self.recover_wallet_rotation(wallet_id, activated, prepared)

    def verify_rotation_scene_consistent(
        self,
        wallet_id: str,
        activated: dict[str, dict],
        prepared: dict[str, dict],
    ) -> bool:
        """只读判定轮换现场是否静止且与激活链一致（不写盘、不清理）。

        常驻请求的自愈快路径用它在"看似静止"时仍做一次链对账：任一已
        提交激活缺记录、链乱序/跨轮次不相容、链顶公钥/份额与钱包元数据或
        磁盘份额不符、仍有暂存/备份残留，都返回 False，由调用方走完整
        恢复（恢复会在真正矛盾时 fail-closed）。现场完全静止才返回 True。
        """
        try:
            entries = self.list_rotation_entries(wallet_id)
            records_by_rid: dict[str, dict] = {}
            for _key, record in entries:
                rid = record.get("rotation_id")
                if not self._rotation_record_shape_ok(record):
                    return False
                rid = record["rotation_id"]
                if rid in records_by_rid:
                    return False
                records_by_rid[rid] = record
            chain = self._build_activation_chain(
                wallet_id, activated, records_by_rid
            )
            # 有暂存残留（prepared 暂存目录除外）即非静止。这里只判定目录
            # 是否存在（每请求快路径不做暂存份额密码学重验；完整密码学
            # 校验仍由启动恢复/激活事务路径负责）。
            kept_prepared = {
                rid
                for rid, record in records_by_rid.items()
                if rid not in activated
                and record["state"] == "prepared"
                and os.path.isdir(
                    self._staging_dir(wallet_id, rid)
                )
            }
            for staging_rid in self.list_staging_rotation_ids(wallet_id):
                if staging_rid not in kept_prepared:
                    return False
            # 未提交的 activating/active 记录是崩溃现场
            for rid, record in records_by_rid.items():
                if rid not in activated and record["state"] in (
                    "activating",
                    "active",
                ):
                    return False
            if not chain:
                # 无已提交激活：钱包应为创世份额且份额文件齐
                current = self.get_wallet(wallet_id)
                if not isinstance(current, dict):
                    return False
                ids = [
                    s.get("share_id")
                    for s in current.get("shares", [])
                    if isinstance(s, dict)
                ]
                if ids != ["share-1", "share-2"]:
                    return False
                return all(
                    self.get_share(wallet_id, sid) is not None for sid in ids
                )
            tail = chain[-1][2]["details"]
            tail_pub = tail["public_key"]
            tail_ids = list(tail["share_ids"])
            current = self.get_wallet(wallet_id)
            if not isinstance(current, dict):
                return False
            if current.get("public_key") != tail_pub:
                return False
            ids = [
                s.get("share_id")
                for s in current.get("shares", [])
                if isinstance(s, dict)
            ]
            if ids != tail_ids:
                return False
            # shares/ 目录只能有链顶两份，且逐份与链顶公钥密码学一致；
            # 会话参与者替换份额（*-share）由签名会话恢复对账，这里豁免。
            on_disk_shares = set(self.list_share_files(wallet_id))
            if not set(tail_ids) <= on_disk_shares:
                return False
            if any(
                not _is_replacement_share_id(sid)
                for sid in on_disk_shares - set(tail_ids)
            ):
                return False
            halves = (
                bytes.fromhex(tail_pub)[:32],
                bytes.fromhex(tail_pub)[32:],
            )
            for index, sid in enumerate(tail_ids):
                share = self.get_share(wallet_id, sid)
                if not isinstance(share, dict):
                    return False
                try:
                    priv = bytes.fromhex(share.get("private_key", ""))
                    pub = bytes.fromhex(share.get("public_key", ""))
                except ValueError:
                    return False
                if len(priv) != 32 or pub != halves[index]:
                    return False
                if public_key_from_private(priv) != pub:
                    return False
            # 各已提交 active 记录的字段必须与事件一致
            for _seq, rid, event in chain:
                record = records_by_rid[rid]
                d = event["details"]
                if record["state"] != "active":
                    return False
                if record["public_key"] != d["public_key"]:
                    return False
                if list(record["share_ids"]) != list(d["share_ids"]):
                    return False
                if record.get("previous_public_key") != d[
                    "previous_public_key"
                ]:
                    return False
            return True
        except (RecoveryError, OSError, ValueError):
            return False

    def recover_wallet_rotation(
        self,
        wallet_id: str,
        activated: Optional[dict[str, dict]] = None,
        prepared: Optional[dict[str, dict]] = None,
    ) -> None:
        """按钱包恢复轮换现场（调用方须持有该钱包的跨进程事务锁）。

        先按审计 seq 建立连续的已提交激活公钥/份额时间线，再分三类对账：

        - 已提交激活（share_rotation_activated 事件在）：链上各轮记录校准
          为 active，磁盘份额/钱包公钥只前滚到**链顶**一轮并清理全部暂存/
          备份；历史轮不再触碰在用份额。链缺失/重复/乱序/跨轮次不相容/
          事件与记录不一致一律 RecoveryError（fail-closed），绝不猜写；
        - 事件未落盘的 activating/active（含状态已写 active）：恢复上一轮
          完整份额与公钥、置回 prepared，保留经校验有效的暂存份额；缺
          回滚备份或与激活链不相容时 fail-closed；
        - prepared：暂存经密码学校验通过才保留，否则连记录带暂存删除；
          若该轮存在 share_rotation_prepared 事件，其 share_ids/public_key
          必须与记录一致，否则 fail-closed；
        - 形状无效且**无**激活事件的记录、无记录的孤儿暂存：安全删除。

        全程不新增审计事件、不分配 seq；被删除暂存私钥不留副本。
        """
        _check_id("wallet_id", wallet_id)
        activated = activated or {}
        prepared = prepared or {}

        entries = self.list_rotation_entries(wallet_id)
        records_by_rid: dict[str, dict] = {}
        for key, record in entries:
            rid = record.get("rotation_id")
            if not self._rotation_record_shape_ok(record):
                # 形状无效：若该轮已有激活提交点则属"事件与记录不一致"，
                # 绝不能删除提交记录掩盖矛盾，直接 fail-closed。
                if isinstance(rid, str) and rid in activated:
                    raise RecoveryError(
                        f"wallet {wallet_id!r} rotation {rid!r} is committed "
                        "but its record is malformed"
                    )
                self.delete_rotation(wallet_id, key)
                if isinstance(rid, str) and _SAFE_ID.match(rid):
                    self.delete_staging(wallet_id, rid)
                continue
            rid = record["rotation_id"]
            if rid in records_by_rid:
                # 同一 rotation_id 出现两条记录：重复，拒绝猜测保留哪条
                raise RecoveryError(
                    f"wallet {wallet_id!r} has duplicate rotation records for "
                    f"{rid!r}"
                )
            records_by_rid[rid] = record

        # 提交点事件在却没有任何记录（缺失）：链构建内统一 fail-closed。
        chain = self._build_activation_chain(
            wallet_id, activated, records_by_rid
        )
        chain_tail_public = (
            chain[-1][2]["details"]["public_key"] if chain else None
        )

        kept_prepared: set[str] = set()
        for rid, record in records_by_rid.items():
            if rid in activated:
                # 已提交轮：磁盘对账统一在链顶前滚中处理，这里不动。
                continue
            if record["state"] in ("activating", "active"):
                # 激活状态已写但提交点事件未落盘：提交未生效，恢复上一轮
                # 完整份额与公钥、置回 prepared，保留有效暂存。
                self._assert_rollback_possible(
                    wallet_id, record, chain_tail_public
                )
                record = self._rollback_incomplete_activation(
                    wallet_id, record
                )
            # prepared（含刚回滚的）：暂存经密码学校验通过才保留。
            if not self._prepared_staging_valid(wallet_id, record):
                # 暂存缺失/损坏/不匹配：记录与残留一起安全删除，绝不留下
                # 来路不明的私钥副本（此轮无激活事件，删除不丢已提交状态）。
                self.delete_rotation(wallet_id, rid)
                self.delete_staging(wallet_id, rid)
                continue
            # 有 prepared 事件时，事件与记录必须一致；不一致 fail-closed，
            # 绝不带着矛盾现场继续服务。
            prepared_event = prepared.get(rid)
            if prepared_event is not None:
                details = prepared_event.get("details")
                if (
                    not isinstance(details, dict)
                    or details.get("public_key") != record["public_key"]
                    or list(details.get("share_ids") or [])
                    != list(record["share_ids"])
                ):
                    raise RecoveryError(
                        f"wallet {wallet_id!r} rotation {rid!r} record is "
                        "inconsistent with its prepared event"
                    )
            kept_prepared.add(rid)

        # 已提交链：校准记录并把磁盘对账到链顶唯一结果。
        self._roll_forward_to_tail(wallet_id, chain, records_by_rid)

        # 孤儿暂存目录：保留中的 prepared 暂存除外，其余（含历史轮遗留）
        # 一律安全删除；已提交轮的暂存已在链顶前滚中清理，此处删除幂等。
        for rotation_id in self.list_staging_rotation_ids(wallet_id):
            if rotation_id not in kept_prepared:
                self.delete_staging(wallet_id, rotation_id)

    def recover_incomplete_activations(
        self,
        activated: Optional[dict[str, dict]] = None,
    ) -> None:
        """启动恢复（无跨进程锁的独立入口；serve 使用 service 层的加锁
        编排）。activated 为各钱包激活事件映射；为 None 时从审计日志读取。
        恢复失败向上抛出 RecoveryError/OSError，由调用方阻止服务就绪。"""
        from .audit import AuditStore

        wallet_ids = sorted(
            set(self.list_rotation_wallet_ids())
            | set(self.list_staging_wallet_ids())
        )
        for wallet_id in wallet_ids:
            audit_store = AuditStore(self.data_dir)
            wallet_activated = activated
            if wallet_activated is None:
                wallet_activated = audit_store.activated_rotation_events(
                    wallet_id
                )
            wallet_prepared = audit_store.prepared_rotation_events(wallet_id)
            self.recover_wallet_rotation(
                wallet_id, wallet_activated, wallet_prepared
            )
