"""钱包审计事件存储（仅追加）。

磁盘布局（data_dir 下）::

    audit/<wallet_id>.json   该钱包的审计事件日志（seq 从 1 起单调递增）

文件形如::

    {"wallet_id": "w1",
     "next_seq": 4,
     "events": [
       {"seq": 1, "type": "policy_updated", "at": "...Z",
        "request_id": null, "actor_id": null,
        "reason": null, "details": {...}},
       ...
     ]}

关键性质：
- seq 从 1 开始，写入后立即持久化；服务重启后续写，seq 接续文件中的
  next_seq（也兼容仅依据末尾事件 seq 推断的旧文件）；
- 仅追加：只在 events 末尾追加，从不修改/删除历史事件；
- 写入采用同目录临时文件 + os.replace 原子替换；
- 调用方（service）在同一把每钱包事务锁内完成"状态变更 + 事件追加"，
  事件追加失败时回滚状态，保证状态与事件原子。
"""

from __future__ import annotations

import json
import os
import tempfile
import threading
from typing import Optional

from .store import (
    CorruptDataError,
    WalletStore,
    _check_id,
    _SAFE_ID,
    parse_utc_iso,
)


def _safe_id_match(value: str) -> bool:
    return bool(_SAFE_ID.match(value))

#: 审计事件类型
TYPE_POLICY_UPDATED = "policy_updated"
TYPE_REQUEST_CREATED = "request_created"
TYPE_REQUEST_APPROVED = "request_approved"
TYPE_REQUEST_REJECTED = "request_rejected"
TYPE_REQUEST_EXPIRED = "request_expired"
TYPE_REQUEST_SIGNED = "request_signed"
TYPE_SHARE_ROTATION_PREPARED = "share_rotation_prepared"
TYPE_SHARE_ROTATION_ACTIVATED = "share_rotation_activated"
TYPE_ASSET_OPERATION_COMMITTED = "asset_operation_committed"
TYPE_TRANSACTION_POLICY_UPDATED = "transaction_policy_updated"
TYPE_SESSION_EVENT = "session_event"
TYPE_SESSION_PARTICIPANT_REPLACED = "session_participant_replaced"
TYPE_SESSION_TAKEOVER = "session_takeover"

#: 单字母缩写 -> 完整类型（P/C/A/R/E/S）
EVENT_TYPES = {
    "P": TYPE_POLICY_UPDATED,
    "C": TYPE_REQUEST_CREATED,
    "A": TYPE_REQUEST_APPROVED,
    "R": TYPE_REQUEST_REJECTED,
    "E": TYPE_REQUEST_EXPIRED,
    "S": TYPE_REQUEST_SIGNED,
}


class AuditStore:
    """审计事件日志的仅追加文件存储（一个钱包一个文件）。"""

    def __init__(self, data_dir: str) -> None:
        self._data_dir = data_dir
        self._audit_dir = os.path.join(data_dir, "audit")
        self._lock = threading.Lock()

    def _path(self, wallet_id: str) -> str:
        _check_id("wallet_id", wallet_id)
        return os.path.join(self._audit_dir, wallet_id + ".json")

    @staticmethod
    def _event_shape_ok(event: object) -> bool:
        """单条审计事件的严格形状：

        seq 为非布尔正整数；type 为非空字符串；at 为可解析的 UTC 时间；
        request_id/actor_id/reason 为 null 或字符串；details 为对象。
        details 内部各事件类型的语义由相应恢复路径（轮换链/会话动作序列/
        账本对账）负责，全局加载不重复解释。"""
        if not isinstance(event, dict):
            return False
        seq = event.get("seq")
        if not isinstance(seq, int) or isinstance(seq, bool) or seq < 1:
            return False
        if not isinstance(event.get("type"), str) or not event["type"]:
            return False
        if parse_utc_iso(event.get("at")) is None:
            return False
        for key in ("request_id", "actor_id", "reason"):
            value = event.get(key)
            if value is not None and not isinstance(value, str):
                return False
        if not isinstance(event.get("details"), dict):
            return False
        return True

    def _read_strict(self, wallet_id: str) -> Optional[dict]:
        """读取并严格校验审计文件；文件不存在返回 None。

        以下现场一律视为不可对账的数据损坏（CorruptDataError），绝不静默
        归一为空日志后覆盖历史：JSON 不可解析、顶层不是对象、events 缺失
        或不是列表、wallet_id 字段不匹配、任一事件形状非法、seq 不从 1
        起 / 不连续 / 有重号、记录的 next_seq 与实际最大 seq 矛盾。
        """
        path = self._path(wallet_id)
        data = WalletStore._read_json(path)
        if data is None:
            return None
        if not isinstance(data, dict):
            raise CorruptDataError(
                f"audit log {path!r} top-level value is not an object"
            )
        recorded_wallet = data.get("wallet_id")
        if recorded_wallet is not None and recorded_wallet != wallet_id:
            raise CorruptDataError(
                f"audit log {path!r} wallet_id {recorded_wallet!r} does not "
                f"match its file name {wallet_id!r}"
            )
        events = data.get("events")
        if "events" not in data or not isinstance(events, list):
            raise CorruptDataError(
                f"audit log {path!r} has no list-valued 'events'"
            )
        seqs: list[int] = []
        for event in events:
            if not self._event_shape_ok(event):
                raise CorruptDataError(
                    f"audit log {path!r} has a malformed event"
                )
            seqs.append(event["seq"])
        # seq 必须恰为 1..N：不重号、不缺口、单调（物理顺序允许被外部重排，
        # 查询始终按 seq 升序；但 seq 集合本身必须连续）。
        if sorted(seqs) != list(range(1, len(seqs) + 1)):
            raise CorruptDataError(
                f"audit log {path!r} has a non-contiguous or duplicated seq"
            )
        stored_next = data.get("next_seq")
        if stored_next is not None:
            if (
                not isinstance(stored_next, int)
                or isinstance(stored_next, bool)
                or stored_next != len(events) + 1
            ):
                raise CorruptDataError(
                    f"audit log {path!r} next_seq disagrees with its events"
                )
        return data

    def check_log(self, wallet_id: str) -> None:
        """只读严格校验审计文件；损坏抛 CorruptDataError/OSError。
        文件不存在（尚无事件）视为正常空状态。"""
        _check_id("wallet_id", wallet_id)
        self._read_strict(wallet_id)

    def list_audit_wallet_ids(self) -> list[str]:
        """返回存在审计文件的全部 wallet_id（启动恢复扫描用）。"""
        try:
            names = os.listdir(self._audit_dir)
        except FileNotFoundError:
            return []
        return sorted(
            name[: -len(".json")]
            for name in names
            if name.endswith(".json")
            and _safe_id_match(name[: -len(".json")])
        )

    def _read(self, wallet_id: str) -> Optional[dict]:
        return self._read_strict(wallet_id)

    @staticmethod
    def _atomic_write_ordered(path: str, data: dict) -> None:
        """临时文件 + 原子替换（与 WalletStore._atomic_write 同崩溃安全
        语义），但**保留插入键序**：审计事件 details 的键序是契约的一部
        分（如 session_participant_replaced 的
        session_id/old_share_id/new_share_id、session_takeover 的
        takeover_id/stage/old_share_id/new_share_id），落盘与查询响应
        都必须保持该顺序，不做 sort_keys 重排。"""
        directory = os.path.dirname(path)
        os.makedirs(directory, exist_ok=True)
        fd, tmp_path = tempfile.mkstemp(
            dir=directory, prefix=".tmp-", suffix=".json"
        )
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
                f.write("\n")
            os.replace(tmp_path, path)
        except BaseException:
            try:
                os.unlink(tmp_path)
            except FileNotFoundError:
                pass
            raise

    def append_event(self, wallet_id: str, event: dict) -> dict:
        """原子追加一条事件，分配下一个 seq 并持久化，返回含 seq/at 的记录。

        seq 从 1 起；同一 wallet 的写入在此串行化。调用方负责在更大的
        每钱包事务锁内把状态变更与本调用绑定（失败时回滚状态）。

        既有日志损坏 / seq 矛盾时抛 CorruptDataError，绝不把历史清空后
        继续写（那会用一条新事件覆盖全部审计历史）。
        """
        path = self._path(wallet_id)
        with self._lock:
            data = self._read_strict(wallet_id)
            if data is None:
                data = {"wallet_id": wallet_id, "next_seq": 1, "events": []}
            events = data["events"]
            # 严格加载已保证 1..N 连续：下一个 seq 直接取 N+1，
            # 与 next_seq（兼容缺字段的旧文件）一致。
            next_seq = len(events) + 1
            # 事件七字段按契约顺序 seq,type,at,request_id,actor_id,reason,
            # details 落盘；details 内部键序由调用方构造时确定（如有序的
            # session_id/old_share_id/new_share_id），原样保留。
            stamped = {"seq": next_seq, **event}
            events.append(stamped)
            data["next_seq"] = next_seq + 1
            self._atomic_write_ordered(path, data)
            return stamped

    def find_event_by_request(
        self,
        wallet_id: str,
        event_type: str,
        request_id: str,
    ) -> Optional[dict]:
        """按 (类型, request_id) 查找一条已持久化事件，不存在返回 None。

        启动恢复据此判定崩溃前的资产提交事务是否已把事件落盘：事件在
        则补齐账本，事件不在则回滚为 pending。纯只读，不分配 seq。
        """
        data = self._read(wallet_id)
        if not data:
            return None
        for event in data.get("events", []):
            if (
                isinstance(event, dict)
                and event.get("type") == event_type
                and event.get("request_id") == request_id
            ):
                return dict(event)
        return None

    def find_session_event(
        self, wallet_id: str, request_id: str, action: str
    ) -> Optional[dict]:
        """按 (request_id, details.action) 查找一条 session_event。

        签名会话崩溃恢复据此判定创建/签名是否已提交：事件在则状态不可
        撤回（前滚），事件不在则回滚。纯只读，不分配 seq。
        """
        for event in self.session_events(wallet_id).get(request_id, []):
            details = event.get("details")
            if isinstance(details, dict) and details.get("action") == action:
                return dict(event)
        return None

    def session_events(self, wallet_id: str) -> dict[str, list[dict]]:
        """返回该钱包全部 session_event，按 request_id（会话 id）分组。

        签名会话崩溃恢复一次性读取审计文件，据此判定每个会话哪些动作
        （created/share_received/expired/signed）已经提交。纯只读。"""
        data = self._read(wallet_id)
        result: dict[str, list[dict]] = {}
        if not data:
            return result
        for event in data.get("events", []):
            if not isinstance(event, dict):
                continue
            if event.get("type") != TYPE_SESSION_EVENT:
                continue
            request_id = event.get("request_id")
            if isinstance(request_id, str):
                result.setdefault(request_id, []).append(dict(event))
        return result

    def session_participant_replaced_events(
        self, wallet_id: str
    ) -> dict[str, list[dict]]:
        """返回该钱包全部 session_participant_replaced 事件，按 request_id
        （会话 id）分组，组内按 seq 升序。

        会话参与者替换的崩溃恢复与幂等重放据此判定哪些替换已经提交
        （事件在则替换不可撤回）。纯只读，不分配 seq。"""
        data = self._read(wallet_id)
        result: dict[str, list[dict]] = {}
        if not data:
            return result
        for event in data.get("events", []):
            if not isinstance(event, dict):
                continue
            if event.get("type") != TYPE_SESSION_PARTICIPANT_REPLACED:
                continue
            request_id = event.get("request_id")
            if isinstance(request_id, str):
                result.setdefault(request_id, []).append(dict(event))
        for events in result.values():
            events.sort(key=lambda e: e.get("seq", 0))
        return result

    def session_takeover_events(
        self, wallet_id: str
    ) -> dict[str, list[dict]]:
        """返回该钱包全部 session_takeover 事件，按 request_id（会话 id）
        分组，组内按 seq 升序。

        会话两阶段参与者接管的崩溃恢复与幂等重放据此判定哪些接管阶段已
        经提交（事件在则该阶段不可撤回）。纯只读，不分配 seq。"""
        data = self._read(wallet_id)
        result: dict[str, list[dict]] = {}
        if not data:
            return result
        for event in data.get("events", []):
            if not isinstance(event, dict):
                continue
            if event.get("type") != TYPE_SESSION_TAKEOVER:
                continue
            request_id = event.get("request_id")
            if isinstance(request_id, str):
                result.setdefault(request_id, []).append(dict(event))
        for events in result.values():
            events.sort(key=lambda e: e.get("seq", 0))
        return result

    def activated_rotation_events(self, wallet_id: str) -> dict[str, dict]:
        """返回该钱包已落盘的 share_rotation_activated 事件映射
        ``{rotation_id: event}``。

        启动/运行时轮换恢复据此判定激活是否已提交（事件在则前滚为
        active，事件不在则回滚 prepared）。每个 rotation 至多一条激活事件；
        同一 rotation_id 出现两条激活事件属于不可对账的重复提交点，抛
        CorruptDataError（fail-closed），绝不任取一条。纯只读。
        """
        return self._rotation_events(
            wallet_id, TYPE_SHARE_ROTATION_ACTIVATED, "activated"
        )

    def prepared_rotation_events(self, wallet_id: str) -> dict[str, dict]:
        """返回该钱包已落盘的 share_rotation_prepared 事件映射
        ``{rotation_id: event}``。

        恢复据此判定轮换首次准备是否已提交（事件在则 prepared 记录合法；
        记录在但准备事件缺失说明记录是崩溃窗口残留）。准备记录在暂存
        失效被安全删除后允许以同 rotation_id 重新准备，因此同一 id 可能
        有多条准备事件，这里以最后一条为准、不报错；真正唯一的提交点是
        share_rotation_activated。纯只读。
        """
        return self._rotation_events(
            wallet_id, TYPE_SHARE_ROTATION_PREPARED, "prepared",
            strict_unique=False,
        )

    def _rotation_events(
        self,
        wallet_id: str,
        event_type: str,
        kind: str,
        strict_unique: bool = True,
    ) -> dict[str, dict]:
        data = self._read(wallet_id)
        result: dict[str, dict] = {}
        if not data:
            return result
        for event in data.get("events", []):
            if not isinstance(event, dict):
                continue
            if event.get("type") != event_type:
                continue
            details = event.get("details")
            rotation_id = (
                details.get("rotation_id")
                if isinstance(details, dict)
                else None
            )
            if not isinstance(rotation_id, str):
                raise CorruptDataError(
                    f"audit log for wallet {wallet_id!r} has a share rotation "
                    f"{kind} event without a rotation_id"
                )
            if strict_unique and rotation_id in result:
                raise CorruptDataError(
                    f"audit log for wallet {wallet_id!r} has multiple share "
                    f"rotation {kind} events for {rotation_id!r}"
                )
            # 非唯一（prepared）：保留 seq 最大的一条
            existing = result.get(rotation_id)
            if existing is None or (
                isinstance(event.get("seq"), int)
                and (
                    not isinstance(existing.get("seq"), int)
                    or event["seq"] > existing["seq"]
                )
            ):
                result[rotation_id] = dict(event)
        return result

    def list_events(
        self, wallet_id: str, from_seq: int = 1, limit: int = 1000
    ) -> list[dict]:
        """按 seq 升序返回 seq >= from_seq 的至多 limit 条事件。

        无日志文件或范围内无事件时返回 []。返回的是记录副本，
        调用方修改不会影响存储内容。日志损坏抛 CorruptDataError
        （由调用方 fail-closed），绝不静默返回残缺历史。
        """
        data = self._read(wallet_id)
        if not data:
            return []
        # 严格加载已保证 seq 集合为 1..N；仍按 seq 升序输出，避免外部改动
        # 事件物理顺序影响公开响应。
        events = [
            dict(event)
            for event in data["events"]
            if event["seq"] >= from_seq
        ]
        events.sort(key=lambda e: e["seq"])
        return events[:limit]

    def events_by_type(self, wallet_id: str, event_type: str) -> list[dict]:
        """返回某类型的全部事件（按 seq 升序，返回副本）。纯只读。

        账本语义恢复据此与已提交操作做双向对账：committed 事件必须与
        账本一一对应。日志损坏抛 CorruptDataError（fail-closed）。"""
        data = self._read(wallet_id)
        if not data:
            return []
        return [
            dict(event)
            for event in sorted(data["events"], key=lambda e: e["seq"])
            if event.get("type") == event_type
        ]
