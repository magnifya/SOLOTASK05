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

import os
import threading
from typing import Optional

from .store import WalletStore, _check_id

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

    def _read(self, wallet_id: str) -> Optional[dict]:
        return WalletStore._read_json(self._path(wallet_id))

    def append_event(self, wallet_id: str, event: dict) -> dict:
        """原子追加一条事件，分配下一个 seq 并持久化，返回含 seq/at 的记录。

        seq 从 1 起；同一 wallet 的写入在此串行化。调用方负责在更大的
        每钱包事务锁内把状态变更与本调用绑定（失败时回滚状态）。
        """
        path = self._path(wallet_id)
        with self._lock:
            data = self._read(wallet_id)
            if data is None:
                data = {"wallet_id": wallet_id, "next_seq": 1, "events": []}
            events = data.get("events")
            if not isinstance(events, list):
                events = []
                data["events"] = events
            # 重启恢复：以文件中实际最大事件 seq 为准，与记录的 next_seq
            # 互相校准取较大者，保证 seq 单调连续、不重号、不回退
            # （同时兼容缺 next_seq 字段的旧文件）。
            max_seq = 0
            for existing in events:
                seq = existing.get("seq") if isinstance(existing, dict) else None
                if (
                    isinstance(seq, int)
                    and not isinstance(seq, bool)
                    and seq > max_seq
                ):
                    max_seq = seq
            stored_next = data.get("next_seq")
            if (
                not isinstance(stored_next, int)
                or isinstance(stored_next, bool)
                or stored_next < 1
            ):
                stored_next = 1
            next_seq = max(stored_next, max_seq + 1)
            stamped = dict(event)
            stamped["seq"] = next_seq
            events.append(stamped)
            data["next_seq"] = next_seq + 1
            WalletStore._atomic_write(path, data)
            return stamped

    def find_event(
        self, wallet_id: str, event_type: str, request_id: object
    ) -> Optional[dict]:
        """查找指定类型与 request_id 的首条事件，无则返回 None。

        只读，不修改日志；供资产提交的崩溃恢复判定"事件是否已持久化"。
        """
        data = self._read(wallet_id)
        if not data:
            return None
        events = data.get("events")
        if not isinstance(events, list):
            return None
        for event in events:
            if (
                isinstance(event, dict)
                and event.get("type") == event_type
                and event.get("request_id") == request_id
            ):
                return dict(event)
        return None

    def list_events(
        self, wallet_id: str, from_seq: int = 1, limit: int = 1000
    ) -> list[dict]:
        """按 seq 升序返回 seq >= from_seq 的至多 limit 条事件。

        无日志文件或范围内无事件时返回 []。返回的是记录副本，
        调用方修改不会影响存储内容。
        """
        data = self._read(wallet_id)
        if not data:
            return []
        # 按 seq 升序返回；即使历史文件事件顺序异常也保证可读、不乱序。
        events = [
            dict(event)
            for event in data.get("events", [])
            if isinstance(event, dict)
            and isinstance(event.get("seq"), int)
            and event["seq"] >= from_seq
        ]
        events.sort(key=lambda e: e["seq"])
        return events[:limit]
