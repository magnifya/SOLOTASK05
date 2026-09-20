"""钱包持久化：只保存份额，磁盘上不存在完整私钥。

磁盘布局（data_dir 下）::

    wallets/<wallet_id>.json        钱包元数据 + 份额公钥（无私钥）
    shares/<wallet_id>/<share_id>.json
                                    单个份额（份额私钥以 hex 保存），一份一个文件
    signatures/<wallet_id>.json     该钱包已完成的签名请求（幂等去重）
    policies/<wallet_id>.json       该钱包的审批策略（required_approvals 等）
    transaction-policies/<wallet_id>.json
                                    该钱包的冷热钱包交易策略
                                    （mode/max_delta/allowed_assets，只含标识与整数）
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


class DuplicateWalletError(Exception):
    """wallet_id 已存在。"""


class RecoveryError(Exception):
    """启动/运行时恢复无法把磁盘现场对账到一致状态。

    触发即说明数据目录损坏或被外部篡改，继续服务可能暴露半完成状态或
    写错密钥，因此调用方必须阻止服务就绪（fail-closed），不得静默跳过。
    """


class WalletStore:
    """钱包、份额与已完成签名请求的文件存储。"""

    def __init__(self, data_dir: str) -> None:
        self._data_dir = data_dir
        self._wallets_dir = os.path.join(data_dir, "wallets")
        self._shares_dir = os.path.join(data_dir, "shares")
        self._signatures_dir = os.path.join(data_dir, "signatures")
        self._policies_dir = os.path.join(data_dir, "policies")
        self._transaction_policies_dir = os.path.join(
            data_dir, "transaction-policies"
        )
        self._requests_dir = os.path.join(data_dir, "requests")
        self._rotations_dir = os.path.join(data_dir, "rotations")
        self._rotation_staging_dir = os.path.join(data_dir, "rotation-staging")
        self._assets_dir = os.path.join(data_dir, "assets")
        self._asset_intents_dir = os.path.join(data_dir, "asset-intents")
        os.makedirs(self._wallets_dir, exist_ok=True)
        os.makedirs(self._shares_dir, exist_ok=True)
        os.makedirs(self._signatures_dir, exist_ok=True)
        os.makedirs(self._policies_dir, exist_ok=True)
        os.makedirs(self._transaction_policies_dir, exist_ok=True)
        os.makedirs(self._requests_dir, exist_ok=True)
        os.makedirs(self._rotations_dir, exist_ok=True)
        os.makedirs(self._rotation_staging_dir, exist_ok=True)
        os.makedirs(self._assets_dir, exist_ok=True)
        os.makedirs(self._asset_intents_dir, exist_ok=True)
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
        """返回钱包的审批策略，未设置返回 None。"""
        return self._read_json(self._policy_path(wallet_id))

    # ---- 冷热钱包交易策略 -----------------------------------------------

    def _transaction_policy_path(self, wallet_id: str) -> str:
        _check_id("wallet_id", wallet_id)
        return os.path.join(
            self._transaction_policies_dir, wallet_id + ".json"
        )

    def save_transaction_policy(self, wallet_id: str, policy: dict) -> None:
        """原子地写入（或覆盖）钱包的冷热钱包交易策略。

        策略只含 mode/max_delta/allowed_assets（标识与整数），不含任何
        私钥材料。
        """
        path = self._transaction_policy_path(wallet_id)
        with self._lock:
            self._atomic_write(path, policy)

    def get_transaction_policy(self, wallet_id: str) -> Optional[dict]:
        """返回钱包的冷热钱包交易策略，未设置返回 None。"""
        return self._read_json(self._transaction_policy_path(wallet_id))

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

    def delete_transaction_policy(self, wallet_id: str) -> None:
        """删除钱包的冷热钱包交易策略文件（策略事件追加失败时回滚用）。"""
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

    # ---- 资产账本（asset-operations 与 assets）-----------------------------

    def _assets_path(self, wallet_id: str) -> str:
        _check_id("wallet_id", wallet_id)
        return os.path.join(self._assets_dir, wallet_id + ".json")

    def _read_asset_ledger(self, wallet_id: str) -> dict:
        """读取资产账本（无文件时返回空结构）。"""
        ledger = self._read_json(self._assets_path(wallet_id))
        if not isinstance(ledger, dict):
            ledger = {}
        operations = ledger.get("operations")
        if not isinstance(operations, dict):
            operations = {}
        assets = ledger.get("assets")
        if not isinstance(assets, dict):
            assets = {}
        return {"operations": operations, "assets": assets}

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

    def list_asset_intents(self, wallet_id: str) -> list[tuple[str, Optional[dict]]]:
        """返回某钱包全部提交意图 (operation_id, intent|None)。

        intent 为 None 表示文件存在但 JSON 不可解析（原子写使正常流程
        不会出现，仅外部损坏时）：调用方据文件名的 operation_id 与账本/
        审计对账即可，不依赖意图内容。
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

    def _assert_rollback_possible(
        self, wallet_id: str, record: dict
    ) -> None:
        """事件未落盘的激活回滚前，确认能安全恢复旧钱包与旧份额。

        - 钱包元数据仍指向旧公钥（换入尚未发生）：只要当前元数据里的
          旧份额文件都还在即可，换入的新份额会在回滚时删除，无需备份；
        - 元数据已指向新公钥（换入已发生）：必须有激活前的钱包/份额
          备份作为权威回滚依据；
        - 元数据旧但旧份额缺失：同样必须有备份。
        无法安全恢复时抛 RecoveryError（fail-closed），绝不猜写旧密钥。
        """
        rotation_id = record["rotation_id"]
        current = self.get_wallet(wallet_id)
        if not isinstance(current, dict):
            raise RecoveryError(
                f"wallet {wallet_id!r} metadata missing during rollback"
            )
        swapped = current.get("public_key") == record["public_key"]
        if swapped:
            if self._load_backup_wallet_meta(wallet_id, rotation_id) is None:
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
        if missing and self._load_backup_wallet_meta(
            wallet_id, rotation_id
        ) is None:
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

    def forward_complete_activation(
        self, wallet_id: str, record: dict, event: dict
    ) -> None:
        """share_rotation_activated 事件已落盘：提交不可撤回，把现场前滚
        成唯一 active 结果并清理全部暂存/备份残留。缺新份额或现场自相
        矛盾时抛 RecoveryError（fail-closed），绝不猜写密钥。"""
        rotation_id = record["rotation_id"]
        details = event.get("details")
        if not isinstance(details, dict) or details.get("public_key") != record[
            "public_key"
        ]:
            raise RecoveryError(
                f"rotation {rotation_id!r} activated event does not match record"
            )

        new_share_records: list[dict] = []
        for share_id in record["share_ids"]:
            staged = self.get_share(wallet_id, share_id)
            if staged is None:
                # 崩溃可能发生在新份额全部换入前：暂存里仍有新份额
                staged = self.get_staging_share(
                    wallet_id, rotation_id, share_id
                )
            if not isinstance(staged, dict) or staged.get(
                "share_id"
            ) != share_id:
                raise RecoveryError(
                    f"rotation {rotation_id!r} missing new share {share_id!r}"
                )
            new_share_records.append(staged)

        # 前滚绝不猜写密钥：逐份校验 32 字节私钥能推导出对应公钥，
        # 且两份新公钥按序拼接恰为已提交事件里的钱包公钥。
        new_public_keys: list[bytes] = []
        for staged in new_share_records:
            public_hex = staged.get("public_key")
            private_hex = staged.get("private_key")
            if not isinstance(public_hex, str) or not isinstance(
                private_hex, str
            ):
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
            new_public_keys.append(public_bytes)
        if (
            combine_public_keys(new_public_keys).hex()
            != record["public_key"]
        ):
            raise RecoveryError(
                f"rotation {rotation_id!r} new shares do not match "
                "committed public_key"
            )

        current_meta = self.get_wallet(wallet_id)
        backup_meta = self._read_json(
            self._staging_wallet_backup_path(wallet_id, rotation_id)
        )

        # 旧份额 id 集合：激活前备份的 wallet.bak.json 是权威旧清单；
        # 当前元数据若仍指向旧公钥，也纳入待删除集合。
        old_share_ids: set[str] = set()
        if isinstance(backup_meta, dict) and isinstance(
            backup_meta.get("shares"), list
        ):
            for entry in backup_meta["shares"]:
                if isinstance(entry, dict) and isinstance(
                    entry.get("share_id"), str
                ):
                    old_share_ids.add(entry["share_id"])
        if (
            isinstance(current_meta, dict)
            and current_meta.get("public_key") != record["public_key"]
            and isinstance(current_meta.get("shares"), list)
        ):
            for entry in current_meta["shares"]:
                if isinstance(entry, dict) and isinstance(
                    entry.get("share_id"), str
                ):
                    old_share_ids.add(entry["share_id"])
        old_share_ids.difference_update(record["share_ids"])

        previous_public_key = record.get("previous_public_key")
        if not isinstance(previous_public_key, str) and isinstance(
            backup_meta, dict
        ):
            previous_public_key = backup_meta.get("public_key")
        if not isinstance(previous_public_key, str) and isinstance(
            current_meta, dict
        ) and current_meta.get("public_key") != record["public_key"]:
            previous_public_key = current_meta.get("public_key")
        if not isinstance(previous_public_key, str):
            raise RecoveryError(
                f"rotation {rotation_id!r} cannot determine previous_public_key"
            )

        base_meta = current_meta if isinstance(current_meta, dict) else backup_meta
        if not isinstance(base_meta, dict):
            raise RecoveryError(
                f"wallet {wallet_id!r} metadata missing during roll-forward"
            )
        new_meta = dict(base_meta)
        new_meta["wallet_id"] = wallet_id
        new_meta["shares"] = [
            {"share_id": r["share_id"], "public_key": r["public_key"]}
            for r in new_share_records
        ]
        new_meta["public_key"] = record["public_key"]
        active_record = dict(record)
        active_record["state"] = "active"
        active_record["previous_public_key"] = previous_public_key

        # 前滚：新份额、钱包元数据、删除残留旧份额、active 状态
        for share_record in new_share_records:
            self.save_share(wallet_id, share_record)
        self.save_wallet_meta(wallet_id, new_meta)
        for share_id in old_share_ids:
            if _SAFE_SHARE_ID.match(share_id):
                self.delete_share(wallet_id, share_id)
        self.update_rotation(wallet_id, rotation_id, active_record)
        # 激活已生效：暂存的新份额副本与全部备份必须清干净
        self.delete_staging(wallet_id, rotation_id)

    def recover_wallet_rotation(
        self,
        wallet_id: str,
        activated: Optional[dict[str, dict]] = None,
    ) -> None:
        """按钱包恢复轮换现场（调用方须持有该钱包的跨进程事务锁）。

        以 share_rotation_activated 审计事件是否已持久化作为激活是否生效
        的唯一判据（activated 为 {rotation_id: event}）：

        - 事件在：激活已提交，无论记录停在 activating/active、暂存或
          备份是否已清理，都把钱包元数据/在用份额/轮换状态前滚为唯一
          active 结果并清理全部残留，不重复记事件；
        - 事件不在：activating/active 一律回滚为 prepared（恢复旧公钥与
          旧份额、删除换入的新份额），再按 prepared 规则校验暂存；
          缺少回滚所需备份时抛 RecoveryError 阻止就绪，绝不静默；
        - prepared：暂存经密码学校验通过才保留，否则连记录带暂存删除；
        - 无效记录：安全删除记录及其暂存目录；
        - 孤儿暂存目录：安全删除。

        全程不新增审计事件、不分配 seq；被删除暂存私钥不留副本。
        """
        _check_id("wallet_id", wallet_id)
        activated = activated or {}
        kept_prepared: set[str] = set()
        for key, record in self.list_rotation_entries(wallet_id):
            rotation_id = record.get("rotation_id")
            if not self._rotation_record_shape_ok(record):
                # 无效记录：连记录带暂存一起安全删除
                self.delete_rotation(wallet_id, key)
                if isinstance(rotation_id, str) and _SAFE_ID.match(
                    rotation_id
                ):
                    self.delete_staging(wallet_id, rotation_id)
                continue
            rotation_id = record["rotation_id"]
            event = activated.get(rotation_id)
            if event is not None:
                # 激活事件已落盘：保持 active、前滚补齐、清理全部残留
                self.forward_complete_activation(wallet_id, record, event)
                continue
            if record["state"] in ("activating", "active"):
                # 激活状态已写入但事件未落盘：提交未生效，无论记录停在
                # activating 还是 active，都恢复旧公钥与旧份额、置回
                # prepared，保留经校验有效的暂存份额。
                self._assert_rollback_possible(wallet_id, record)
                record = self._rollback_incomplete_activation(
                    wallet_id, record
                )
            # prepared（含刚回滚的）：暂存经密码学校验通过才保留
            if self._prepared_staging_valid(wallet_id, record):
                kept_prepared.add(rotation_id)
            else:
                # 暂存缺失/损坏/不匹配：记录与残留一起安全删除，
                # 绝不留下来路不明的私钥副本
                self.delete_rotation(wallet_id, rotation_id)
                self.delete_staging(wallet_id, rotation_id)
        # 孤儿暂存目录：没有对应有效 prepared 记录的一律安全删除
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
        from .audit import AuditStore, TYPE_SHARE_ROTATION_ACTIVATED

        wallet_ids = sorted(
            set(self.list_rotation_wallet_ids())
            | set(self.list_staging_wallet_ids())
        )
        for wallet_id in wallet_ids:
            wallet_activated = activated
            if wallet_activated is None:
                events = AuditStore(self.data_dir).list_events(wallet_id)
                wallet_activated = {}
                for e in events:
                    if e.get("type") != TYPE_SHARE_ROTATION_ACTIVATED:
                        continue
                    details = e.get("details")
                    rid = (
                        details.get("rotation_id")
                        if isinstance(details, dict)
                        else None
                    )
                    if isinstance(rid, str):
                        wallet_activated[rid] = e
            self.recover_wallet_rotation(wallet_id, wallet_activated)
