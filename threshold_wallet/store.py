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
from typing import Callable, Optional

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
    """启动/锁内恢复无法把现场对账为一致状态。

    与"尽力而为清理孤立残留"不同：出现本异常意味着在用钱包的份额/元数据
    与轮换记录、激活事件无法调和（如备份缺失且公钥既非旧值也非新值）。
    调用方必须让服务启动失败（不就绪），而不是静默跳过对外暴露半完成
    状态。恢复本身绝不产生审计事件。
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
        os.makedirs(self._wallets_dir, exist_ok=True)
        os.makedirs(self._shares_dir, exist_ok=True)
        os.makedirs(self._signatures_dir, exist_ok=True)
        os.makedirs(self._policies_dir, exist_ok=True)
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
            if os.path.isdir(os.path.join(self._asset_intents_dir, name))
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
            data = self._read_json(os.path.join(base, name))
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
        """返回拥有轮换记录文件的全部 wallet_id。"""
        try:
            names = os.listdir(self._rotations_dir)
        except FileNotFoundError:
            return []
        return sorted(
            name[: -len(".json")] for name in names if name.endswith(".json")
        )

    def list_staging_wallet_ids(self) -> list[str]:
        """返回轮换暂存根目录下出现过的全部 wallet_id（含无记录文件的）。"""
        try:
            names = os.listdir(self._rotation_staging_dir)
        except FileNotFoundError:
            return []
        return sorted(
            name
            for name in names
            if os.path.isdir(os.path.join(self._rotation_staging_dir, name))
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
            name for name in names if os.path.isdir(os.path.join(base, name))
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

    @staticmethod
    def _valid_share_record(
        data: object, expected_share_id: Optional[str] = None
    ) -> Optional[dict]:
        """校验一份份额记录（share_id 合法、公钥/私钥各 32 字节且自洽）。

        合法时返回该记录（dict），否则返回 None。expected_share_id 非空时
        还要求记录的 share_id 与之相等。
        """
        if not isinstance(data, dict):
            return None
        share_id = data.get("share_id")
        if not isinstance(share_id, str) or not _SAFE_SHARE_ID.match(share_id):
            return None
        if expected_share_id is not None and share_id != expected_share_id:
            return None
        public_hex = data.get("public_key")
        private_hex = data.get("private_key")
        if not isinstance(public_hex, str) or not isinstance(private_hex, str):
            return None
        try:
            public_bytes = bytes.fromhex(public_hex)
            private_bytes = bytes.fromhex(private_hex)
        except ValueError:
            return None
        if len(public_bytes) != 32 or len(private_bytes) != 32:
            return None
        try:
            if public_key_from_private(private_bytes) != public_bytes:
                return None
        except ValueError:
            return None
        return data

    def _list_inuse_share_ids(self, wallet_id: str) -> list[str]:
        """列出在用份额目录下的全部份额 id（<share_id>.json 的 stem）。"""
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
                # JSON 不可解析 / 读取失败：暂存无效
                return False
            valid = self._valid_share_record(data, expected_share_id=share_id)
            if valid is None:
                # 字段不合法 / 公私钥不自洽
                return False
            share_public_keys.append(bytes.fromhex(valid["public_key"]))
        return (
            combine_public_keys(share_public_keys).hex()
            == record["public_key"]
        )

    @staticmethod
    def _activation_event_targets(event: dict, record: dict) -> Optional[dict]:
        """从激活事件 details 解析前滚目标并与轮换记录交叉校验。

        合法返回 {share_ids, public_key, previous_public_key}；
        形状损坏或与记录冲突时返回 None（调用方据此判 RecoveryError）。
        """
        details = event.get("details")
        if not isinstance(details, dict):
            return None
        rotation_id = details.get("rotation_id")
        share_ids = details.get("share_ids")
        public_key = details.get("public_key")
        previous_public_key = details.get("previous_public_key")
        if rotation_id != record.get("rotation_id"):
            return None
        if (
            not isinstance(share_ids, list)
            or len(share_ids) != 2
            or share_ids != list(record.get("share_ids", []))
            or any(
                not isinstance(sid, str) or not _SAFE_SHARE_ID.match(sid)
                for sid in share_ids
            )
        ):
            return None
        for value in (public_key, previous_public_key):
            if not isinstance(value, str):
                return None
            try:
                if len(bytes.fromhex(value)) != 64:
                    return None
            except ValueError:
                return None
        if public_key != record.get("public_key"):
            return None
        return {
            "share_ids": list(share_ids),
            "public_key": public_key,
            "previous_public_key": previous_public_key,
        }

    def _activation_already_consistent(
        self,
        wallet_id: str,
        record: dict,
        targets: dict,
        rotation_id: str,
    ) -> bool:
        """现场是否已与激活事件的提交结果完全一致（自愈只读快路径用）。"""
        if record.get("state") != "active":
            return False
        wallet = self.get_wallet(wallet_id)
        if not isinstance(wallet, dict):
            return False
        if wallet.get("public_key") != targets["public_key"]:
            return False
        inuse = set(self._list_inuse_share_ids(wallet_id))
        if inuse != set(targets["share_ids"]):
            return False
        for share in wallet.get("shares", []):
            if not isinstance(share, dict):
                return False
        if [s.get("share_id") for s in wallet.get("shares", [])] != targets[
            "share_ids"
        ]:
            return False
        # 暂存目录仍有任何残留（新份额/备份）都算未完成，需清理
        try:
            if os.listdir(self._staging_dir(wallet_id, rotation_id)):
                return False
        except (FileNotFoundError, NotADirectoryError):
            pass
        return True

    def _roll_forward_activation(
        self, wallet_id: str, record: dict, event: dict
    ) -> None:
        """激活事件已落盘：把现场确定性前滚为唯一 active 结果。

        以事件 details 为权威目标：补齐在用新份额文件、把钱包 shares/
        public_key 切到新值、轮换状态置 active（带 previous_public_key），
        然后删除整个暂存目录（新份额暂存 + 备份，全部残留）。不追加事件
        （事件已在）。任一步缺少必要材料（钱包丢失、新份额私钥既不在
        用也不在暂存、事件与记录冲突）抛 RecoveryError，阻止服务就绪。
        """
        targets = self._activation_event_targets(event, record)
        if targets is None:
            raise RecoveryError(
                f"wallet {wallet_id!r} rotation {record.get('rotation_id')!r}: "
                "persisted activation event does not match its rotation record"
            )
        rotation_id = record["rotation_id"]
        new_ids = targets["share_ids"]

        # 快路径：现场已与提交结果一致（active、元数据/在用份额匹配、
        # 暂存已清空）则什么都不写——健康钱包的每次锁内自愈因此是只读的。
        if self._activation_already_consistent(
            wallet_id, record, targets, rotation_id
        ):
            return

        # 新份额记录：优先用已在用的，缺失则用暂存的；都没有则无法前滚
        new_records: list[dict] = []
        for share_id in new_ids:
            valid = self._valid_share_record(
                self.get_share(wallet_id, share_id),
                expected_share_id=share_id,
            )
            if valid is None:
                valid = self._valid_share_record(
                    self.get_staging_share(wallet_id, rotation_id, share_id),
                    expected_share_id=share_id,
                )
            if valid is None:
                raise RecoveryError(
                    f"wallet {wallet_id!r} rotation {rotation_id!r}: "
                    f"activated share {share_id!r} is missing everywhere"
                )
            new_records.append(valid)

        wallet = self.get_wallet(wallet_id)
        if not isinstance(wallet, dict):
            raise RecoveryError(
                f"wallet {wallet_id!r}: activation event exists but wallet "
                "metadata is missing"
            )
        new_meta = dict(wallet)
        new_meta["shares"] = [
            {"share_id": r["share_id"], "public_key": r["public_key"]}
            for r in new_records
        ]
        new_meta["public_key"] = targets["public_key"]
        self.save_wallet_meta(wallet_id, new_meta)
        # 旧份额/任何非当前两份的在用份额文件都是残留，全部清除，
        # 再确保两份新份额就位（杜绝混合公钥）。
        for share_id in self._list_inuse_share_ids(wallet_id):
            if share_id not in new_ids:
                self.delete_share(wallet_id, share_id)
        for share_record in new_records:
            self.save_share(wallet_id, share_record)
        active_record = dict(record)
        active_record["state"] = "active"
        active_record["share_ids"] = new_ids
        active_record["public_key"] = targets["public_key"]
        active_record["previous_public_key"] = targets["previous_public_key"]
        self.update_rotation(wallet_id, rotation_id, active_record)
        # 事件已落盘：暂存的新份额与激活备份都是残留，整目录清除
        self.delete_staging(wallet_id, rotation_id)

    def _roll_back_activation(
        self, wallet_id: str, record: dict
    ) -> None:
        """激活事件未落盘：把现场回滚为 prepared（旧公钥/旧份额）。

        正常崩溃窗口内备份必然先于换份额落盘（事件是最后一步，清理只在
        事件后），故据备份恢复钱包元数据与旧份额、删除已换入的新份额、
        状态回 prepared、删备份但保留暂存新份额。若现场显示钱包/份额确已
        切换却找不到对应备份（无法找回旧私钥），抛 RecoveryError 阻止
        就绪，而不是猜一个半完成状态对外服务。
        """
        rotation_id = record["rotation_id"]
        new_ids = list(record["share_ids"])
        new_public_key = record["public_key"]

        wallet = self.get_wallet(wallet_id)
        switched = (
            isinstance(wallet, dict)
            and wallet.get("public_key") == new_public_key
        )
        wallet_backup = self._read_json(
            self._staging_wallet_backup_path(wallet_id, rotation_id)
        )
        staging = self._staging_dir(wallet_id, rotation_id)
        share_backups: list[dict] = []
        try:
            names = os.listdir(staging)
        except FileNotFoundError:
            names = []
        for name in names:
            if name.endswith(".bak.json") and name != "wallet.bak.json":
                data = self._read_json(os.path.join(staging, name))
                if isinstance(data, dict) and isinstance(
                    data.get("share_id"), str
                ):
                    share_backups.append(data)

        if wallet_backup is not None:
            self.save_wallet_meta(wallet_id, wallet_backup)
        elif switched:
            raise RecoveryError(
                f"wallet {wallet_id!r} rotation {rotation_id!r}: switched to "
                "new shares but wallet backup is missing, cannot restore"
            )
        # 钱包未切换：元数据保持在用旧值，不动

        inuse_new = [
            sid for sid in new_ids if self.get_share(wallet_id, sid) is not None
        ]
        if share_backups:
            for share_record in share_backups:
                self.save_share(wallet_id, share_record)
        elif inuse_new:
            raise RecoveryError(
                f"wallet {wallet_id!r} rotation {rotation_id!r}: new shares "
                "swapped in but old share backups are missing, cannot restore"
            )
        # 旧份额未被替换（备份写入前崩溃）：在用旧份额原样保留
        for share_id in new_ids:
            self.delete_share(wallet_id, share_id)

        restored = {
            key: value
            for key, value in record.items()
            if key != "previous_public_key"
        }
        restored["state"] = "prepared"
        self.update_rotation(wallet_id, rotation_id, restored)
        # 备份已无用；暂存的两份新份额保留，供 prepared 校验与重试
        self.delete_activation_backups(wallet_id, rotation_id)

    def recover_wallet_rotation(
        self,
        wallet_id: str,
        find_activation_event: Optional[
            "Callable[[str, str], Optional[dict]]"
        ] = None,
    ) -> None:
        """按钱包恢复轮换现场（调用方须持有该钱包的跨进程事务锁）。

        以 ``share_rotation_activated`` 事件是否落盘作为唯一提交判据：

        - 激活事件**在**：激活已提交。无论记录停在 prepared/activating/
          active、暂存或备份是否残留，都确定性前滚为唯一 active 结果
          （新份额、新公钥、状态 active），并清理整个暂存目录；不重复
          记事件。
        - 激活事件**不在**且记录为 activating/active：激活未提交。用
          备份恢复旧钱包元数据与旧份额、删除换入的新份额、状态回
          prepared，再按 prepared 规则校验暂存（有效则保留可重试）。
        - prepared：暂存校验通过才保留，否则安全删除记录与暂存目录。
        - 无效记录：安全删除记录及其暂存目录。
        - 孤儿暂存目录（无对应有效 prepared 记录）：安全删除。

        全程不产生审计事件；无法调和的现场抛 RecoveryError，由调用方
        阻止服务就绪，绝不静默跳过。
        """
        _check_id("wallet_id", wallet_id)
        if find_activation_event is None:
            # 延迟导入避免 store <-> audit 模块级循环依赖
            from .audit import AuditStore

            audit_store = AuditStore(self._data_dir)
            find_activation_event = lambda wid, rid: audit_store.find_rotation_event(
                wid, rid
            )
        kept_prepared: set[str] = set()
        for key, record in self.list_rotation_entries(wallet_id):
            rotation_id = record.get("rotation_id")
            if not self._rotation_record_shape_ok(record):
                # 无效记录：连记录带暂存一起安全删除，不触碰在用钱包
                self.delete_rotation(wallet_id, key)
                if isinstance(rotation_id, str) and _SAFE_ID.match(rotation_id):
                    self.delete_staging(wallet_id, rotation_id)
                continue
            event = find_activation_event(wallet_id, rotation_id)
            if event is not None:
                # 提交点已越过：前滚保持 active，清全部残留，不重复记事件
                self._roll_forward_activation(wallet_id, record, event)
                continue
            if record["state"] in ("activating", "active"):
                # 状态写了但事件未落盘：回滚旧公钥/旧份额，回 prepared
                self._roll_back_activation(wallet_id, record)
                record = self.get_rotation(wallet_id, rotation_id)
            # 至此 record 必为 prepared（未切换的 prepared 或刚回滚的）
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

    def recover_incomplete_activations(self) -> None:
        """无锁恢复入口（主要供独立脚本/测试使用）。

        逐个钱包在不加跨进程锁的情况下按激活事件对账。服务进程应使用
        service 层在每钱包事务锁内的加锁编排（见 WalletService 启动恢复
        与锁内懒恢复），多进程共用 data-dir 时切勿直接依赖本方法。
        无法调和的现场会抛 RecoveryError，而不是静默跳过。
        """
        wallet_ids = sorted(
            set(self.list_rotation_wallet_ids())
            | set(self.list_staging_wallet_ids())
        )
        for wallet_id in wallet_ids:
            self.recover_wallet_rotation(wallet_id)
