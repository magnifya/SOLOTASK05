"""签名会话主动撤销 ``POST /v1/wallets/<id>/sign-sessions/<sid>/cancel`` 测试。

覆盖：请求体/标识/reason 校验（400）、未知钱包/会话（404）、其他方法
（405）、collecting/ready 首撤 201 与 cancelled 视图（恰含
cancel_id/reason 的 cancellation、不出现聚合签名、已收/缺失份额冻结）、
signed/expired 409、同参重放 200 不再检查期限、换参/复用/新标识 409、
cancel_id 仅在同钱包会话撤销间判重、撤销后投递/替换/接管 409 与已提交
参与者操作重放保留原语义、创建同参重放返回撤销后视图、冻结钱包 409 零
副作用、唯一 cancelled session_event 与重放不记事件、重启/灾备恢复、
未提交撤销回滚、撤销后矛盾事件 fail-closed、轮换不迁移撤销快照、日志与
响应不含 reason 原文。
"""

from __future__ import annotations

import json
import os
import tempfile
import time
import unittest

from tests.helpers import http_server, make_harness
from threshold_wallet import drbackup
from threshold_wallet.audit import AuditStore
from threshold_wallet.service import WalletService
from threshold_wallet.store import CorruptDataError, RecoveryError, WalletStore


def _session_events(svc, wallet_id, session_id=None):
    events = [
        e
        for e in svc.get_audit_events(wallet_id)["events"]
        if e["type"] == "session_event"
    ]
    if session_id is not None:
        events = [e for e in events if e["request_id"] == session_id]
    return events


def _cancel_events(svc, wallet_id):
    return [
        e
        for e in _session_events(svc, wallet_id)
        if e["details"].get("action") == "cancelled"
    ]


class SignSessionCancelServiceTest(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.h = make_harness(self.d)
        self.svc = self.h.service
        self.svc.create_wallet("w1", 2)

    def _open(self, sid="s1", message="hello", timeout=600, wallet="w1"):
        code, view = self.svc.create_sign_session(wallet, sid, message, timeout)
        self.assertEqual(code, 201)
        return view

    def _cancel(self, sid="s1", cancel_id="cx-1", reason="stop", wallet="w1"):
        return self.svc.cancel_sign_session(
            wallet, sid, {"cancel_id": cancel_id, "reason": reason}
        )

    def _sig(self, share_id, sid="s1", message="hello", wallet="w1"):
        return self.h.share_signature(wallet, share_id, sid, message)

    # ---- 首次撤销与视图 ---------------------------------------------------

    def test_cancel_collecting_returns_201_cancelled_view(self):
        self._open()
        code, view = self._cancel(reason=" 用户 要求 停止 ")
        self.assertEqual(code, 201)
        self.assertEqual(view["state"], "cancelled")
        self.assertEqual(view["id"], "s1")
        self.assertEqual(view["message"], "hello")
        # reason 保留原文（含首尾空白）
        self.assertEqual(
            view["cancellation"],
            {"cancel_id": "cx-1", "reason": " 用户 要求 停止 "},
        )
        self.assertEqual(list(view["cancellation"]), ["cancel_id", "reason"])
        self.assertNotIn("aggregate_signature", view)
        self.assertEqual(view["received_shares"], [])
        self.assertEqual(view["missing_shares"], ["share-1", "share-2"])
        # 视图键集：既有六键 + cancellation
        self.assertEqual(
            set(view),
            {
                "id",
                "message",
                "state",
                "received_shares",
                "missing_shares",
                "expires_at",
                "cancellation",
            },
        )

    def test_cancel_keeps_received_and_missing_snapshot(self):
        self._open()
        self.svc.submit_sign_session_share(
            "w1", "s1", "share-1", self._sig("share-1")
        )
        code, view = self._cancel()
        self.assertEqual(code, 201)
        self.assertEqual(view["received_shares"], ["share-1"])
        self.assertEqual(view["missing_shares"], ["share-2"])
        # 后续查询同形
        got = self.svc.get_sign_session("w1", "s1")
        self.assertEqual(got, view)

    def test_cancel_ready_session(self):
        # ready：两份齐备但审批门控失败（保留 ready）
        self.svc.put_policy("w1", 1, 600)
        self._open()
        for sid in ("share-1", "share-2"):
            code, _ = self.svc.submit_sign_session_share(
                "w1", "s1", sid, self._sig(sid)
            )
        code, view = self.svc.submit_sign_session_share(
            "w1", "s1", "share-1", self._sig("share-1")
        )
        self.assertEqual(code, 409)
        self.assertEqual(view["state"], "ready")
        code, view = self._cancel()
        self.assertEqual(code, 201)
        self.assertEqual(view["state"], "cancelled")
        self.assertEqual(view["received_shares"], ["share-1", "share-2"])
        self.assertEqual(view["missing_shares"], [])
        self.assertNotIn("aggregate_signature", view)

    def test_cancel_signed_session_is_409(self):
        self._open()
        for sid in ("share-1", "share-2"):
            code, view = self.svc.submit_sign_session_share(
                "w1", "s1", sid, self._sig(sid)
            )
        self.assertEqual(code, 201)
        self.assertEqual(view["state"], "signed")
        from threshold_wallet.service import ServiceError

        with self.assertRaises(ServiceError) as ctx:
            self._cancel()
        self.assertEqual(ctx.exception.status, 409)
        # 已签名会话不受影响
        self.assertEqual(self.svc.get_sign_session("w1", "s1")["state"], "signed")
        self.assertEqual(_cancel_events(self.svc, "w1"), [])

    def test_cancel_expired_session_is_409_and_lazy_expires(self):
        self._open(timeout=1)
        time.sleep(1.1)
        from threshold_wallet.service import ServiceError

        with self.assertRaises(ServiceError) as ctx:
            self._cancel()
        self.assertEqual(ctx.exception.status, 409)
        # 沿用懒过期语义：原子转 expired 且只记一次 expired 事件
        self.assertEqual(self.svc.get_sign_session("w1", "s1")["state"], "expired")
        actions = [
            e["details"]["action"] for e in _session_events(self.svc, "w1", "s1")
        ]
        self.assertEqual(actions, ["created", "expired"])

    # ---- 参数校验 ---------------------------------------------------------

    def test_body_shape_errors_are_400(self):
        from threshold_wallet.service import ServiceError

        self._open()
        for body in (
            "not-a-dict",
            42,
            None,
            {},
            {"cancel_id": "cx-1"},
            {"reason": "r"},
            {"cancel_id": "cx-1", "reason": "r", "extra": 1},
        ):
            with self.assertRaises(ServiceError) as ctx:
                self.svc.cancel_sign_session("w1", "s1", body)
            self.assertEqual(ctx.exception.status, 400, body)

    def test_cancel_id_and_reason_validation(self):
        from threshold_wallet.service import ServiceError

        self._open()
        bad = [
            {"cancel_id": "", "reason": "r"},
            {"cancel_id": "bad id", "reason": "r"},
            {"cancel_id": "../x", "reason": "r"},
            {"cancel_id": "x" * 129, "reason": "r"},
            {"cancel_id": 123, "reason": "r"},
            {"cancel_id": None, "reason": "r"},
            {"cancel_id": True, "reason": "r"},
            {"cancel_id": "cx-1", "reason": ""},
            {"cancel_id": "cx-1", "reason": "   "},
            {"cancel_id": "cx-1", "reason": "x" * 1025},
            {"cancel_id": "cx-1", "reason": 7},
            {"cancel_id": "cx-1", "reason": None},
        ]
        for body in bad:
            with self.assertRaises(ServiceError) as ctx:
                self.svc.cancel_sign_session("w1", "s1", body)
            self.assertEqual(ctx.exception.status, 400, body)
        # 边界合法：1 字符与 1024 字符 reason
        self._open(sid="s2")
        code, _ = self._cancel(sid="s2", cancel_id="cx-2", reason="x")
        self.assertEqual(code, 201)
        self._open(sid="s3")
        code, view = self._cancel(sid="s3", cancel_id="cx-3", reason="y" * 1024)
        self.assertEqual(code, 201)
        self.assertEqual(view["cancellation"]["reason"], "y" * 1024)

    def test_unknown_wallet_and_session_are_404(self):
        from threshold_wallet.service import ServiceError

        self._open()
        with self.assertRaises(ServiceError) as ctx:
            self.svc.cancel_sign_session(
                "ghost", "s1", {"cancel_id": "cx-1", "reason": "r"}
            )
        self.assertEqual(ctx.exception.status, 404)
        with self.assertRaises(ServiceError) as ctx:
            self.svc.cancel_sign_session(
                "w1", "ghost", {"cancel_id": "cx-1", "reason": "r"}
            )
        self.assertEqual(ctx.exception.status, 404)

    # ---- 幂等与判重 -------------------------------------------------------

    def test_replay_same_params_200_same_body_no_new_event(self):
        self._open()
        code, first = self._cancel()
        self.assertEqual(code, 201)
        code, second = self._cancel()
        self.assertEqual(code, 200)
        self.assertEqual(second, first)
        self.assertEqual(len(_cancel_events(self.svc, "w1")), 1)

    def test_replay_does_not_check_expiry(self):
        self._open(timeout=2)
        code, first = self._cancel()
        self.assertEqual(code, 201)
        time.sleep(2.1)
        # 已过 expires_at：重放仍 200 同体，不触发懒过期、不记事件
        code, second = self._cancel()
        self.assertEqual(code, 200)
        self.assertEqual(second, first)
        self.assertEqual(
            self.svc.get_sign_session("w1", "s1")["state"], "cancelled"
        )
        self.assertEqual(len(_session_events(self.svc, "w1", "s1")), 2)

    def test_same_session_different_params_is_409(self):
        from threshold_wallet.service import ServiceError

        self._open()
        self._cancel()
        for body in (
            {"cancel_id": "cx-1", "reason": "other"},
            {"cancel_id": "cx-2", "reason": "stop"},
            {"cancel_id": "cx-2", "reason": "other"},
        ):
            with self.assertRaises(ServiceError) as ctx:
                self.svc.cancel_sign_session("w1", "s1", body)
            self.assertEqual(ctx.exception.status, 409, body)
        self.assertEqual(len(_cancel_events(self.svc, "w1")), 1)

    def test_cancel_id_reuse_across_sessions_is_409(self):
        from threshold_wallet.service import ServiceError

        self._open(sid="s1")
        self._open(sid="s2")
        self._cancel(sid="s1", cancel_id="cx-1")
        with self.assertRaises(ServiceError) as ctx:
            self._cancel(sid="s2", cancel_id="cx-1", reason="stop")
        self.assertEqual(ctx.exception.status, 409)
        # 换标识可撤销另一会话
        code, _ = self._cancel(sid="s2", cancel_id="cx-2")
        self.assertEqual(code, 201)

    def test_cancel_id_scoped_per_wallet_and_per_feature(self):
        # 其他钱包可复用同一 cancel_id
        self.svc.create_wallet("w2", 2)
        self._open(sid="s1", wallet="w1")
        self._open(sid="s1", wallet="w2")
        code, _ = self._cancel(sid="s1", cancel_id="cx-1", wallet="w1")
        self.assertEqual(code, 201)
        code, _ = self._cancel(sid="s1", cancel_id="cx-1", wallet="w2")
        self.assertEqual(code, 201)
        # 与审批单撤销的 cancel_id 命名空间互不影响
        self.svc.put_policy("w1", 1, 600)
        self.svc.create_sign_request("w1", "req-1", "m")
        code, _ = self.svc.cancel_sign_request(
            "w1", "req-1", {"cancel_id": "cx-1", "reason": "r"}
        )
        self.assertEqual(code, 201)

    # ---- 撤销后的会话行为 -------------------------------------------------

    def test_submit_share_after_cancel_is_409(self):
        from threshold_wallet.service import ServiceError

        self._open()
        self.svc.submit_sign_session_share(
            "w1", "s1", "share-1", self._sig("share-1")
        )
        self._cancel()
        # 新份额与已收份额同值重放一律 409
        for share_id in ("share-1", "share-2"):
            with self.assertRaises(ServiceError) as ctx:
                self.svc.submit_sign_session_share(
                    "w1", "s1", share_id, self._sig(share_id)
                )
            self.assertEqual(ctx.exception.status, 409)
        # 畸形载荷同样 409（状态判定优先于载荷校验）
        with self.assertRaises(ServiceError) as ctx:
            self.svc.submit_sign_session_share("w1", "s1", "share-1", "zz")
        self.assertEqual(ctx.exception.status, 409)

    def test_new_participant_ops_after_cancel_are_409(self):
        from threshold_wallet.service import ServiceError

        self._open()
        self._cancel()
        with self.assertRaises(ServiceError) as ctx:
            self.svc.replace_sign_session_participant(
                "w1", "s1", "rep-1", "share-1"
            )
        self.assertEqual(ctx.exception.status, 409)
        with self.assertRaises(ServiceError) as ctx:
            self.svc.takeover_sign_session_participant(
                "w1", "s1", "tk-1", 1, "share-1"
            )
        self.assertEqual(ctx.exception.status, 409)

    def test_committed_participant_replay_keeps_original_semantics(self):
        self._open()
        code, _ = self.svc.replace_sign_session_participant(
            "w1", "s1", "rep-1", "share-1"
        )
        self.assertEqual(code, 201)
        self._cancel()
        # 已提交替换的同参重放仍 200（返回撤销后的当前视图）
        code, view = self.svc.replace_sign_session_participant(
            "w1", "s1", "rep-1", "share-1"
        )
        self.assertEqual(code, 200)
        self.assertEqual(view["state"], "cancelled")
        self.assertEqual(view["received_shares"], [])
        self.assertEqual(view["missing_shares"], ["rep-1-share", "share-2"])

    def test_committed_takeover_replay_keeps_original_semantics(self):
        self._open()
        code, _ = self.svc.takeover_sign_session_participant(
            "w1", "s1", "tk-1", 1, "share-1"
        )
        self.assertEqual(code, 201)
        self._cancel()
        code, view = self.svc.takeover_sign_session_participant(
            "w1", "s1", "tk-1", 1, "share-1"
        )
        self.assertEqual(code, 200)
        self.assertEqual(view["state"], "cancelled")
        # 同 takeover 的 stage 2 是新操作：409
        from threshold_wallet.service import ServiceError

        with self.assertRaises(ServiceError) as ctx:
            self.svc.takeover_sign_session_participant(
                "w1", "s1", "tk-1", 2, "share-2"
            )
        self.assertEqual(ctx.exception.status, 409)

    def test_create_replay_returns_cancelled_view(self):
        self._open()
        code, cancelled = self._cancel()
        self.assertEqual(code, 201)
        code, view = self.svc.create_sign_session("w1", "s1", "hello", 600)
        self.assertEqual(code, 200)
        self.assertEqual(view, cancelled)
        # 异参仍 409
        from threshold_wallet.service import ServiceError

        with self.assertRaises(ServiceError) as ctx:
            self.svc.create_sign_session("w1", "s1", "other", 600)
        self.assertEqual(ctx.exception.status, 409)

    def test_cancelled_session_never_lazy_expires(self):
        self._open(timeout=2)
        self._cancel()
        time.sleep(2.1)
        view = self.svc.get_sign_session("w1", "s1")
        self.assertEqual(view["state"], "cancelled")
        actions = [
            e["details"]["action"] for e in _session_events(self.svc, "w1", "s1")
        ]
        self.assertEqual(actions, ["created", "cancelled"])

    # ---- 审计事件 ---------------------------------------------------------

    def test_cancel_appends_exactly_one_session_event(self):
        self._open()
        self._cancel(cancel_id="cx-9", reason="why not")
        events = _cancel_events(self.svc, "w1")
        self.assertEqual(len(events), 1)
        event = events[0]
        self.assertEqual(event["type"], "session_event")
        self.assertEqual(event["request_id"], "s1")
        self.assertIsNone(event["actor_id"])
        self.assertIsNone(event["reason"])
        self.assertEqual(
            event["details"],
            {"action": "cancelled", "cancel_id": "cx-9", "reason": "why not"},
        )
        # seq 连续不重号
        seqs = [e["seq"] for e in self.svc.get_audit_events("w1")["events"]]
        self.assertEqual(seqs, list(range(1, len(seqs) + 1)))

    # ---- 冻结闸门 ---------------------------------------------------------

    def test_frozen_wallet_rejects_cancel_and_replay(self):
        from threshold_wallet.service import ServiceError

        self._open()
        self._cancel()
        self._open(sid="s2")
        self.svc.freeze_wallet("w1", "incident")
        before = self.svc.get_audit_events("w1")["events"]
        # 新撤销与已提交撤销的重放一律 409
        for sid in ("s1", "s2"):
            with self.assertRaises(ServiceError) as ctx:
                self._cancel(sid=sid)
            self.assertEqual(ctx.exception.status, 409)
        # 零副作用：无新事件、会话状态不变（s2 未懒过期、未撤销）
        after = self.svc.get_audit_events("w1")["events"]
        self.assertEqual([e["seq"] for e in after], [e["seq"] for e in before])
        self.assertEqual(
            self.svc.get_sign_session("w1", "s2")["state"], "collecting"
        )
        # 查询仍可用
        self.assertEqual(
            self.svc.get_sign_session("w1", "s1")["state"], "cancelled"
        )
        # 解冻后可撤销
        self.svc.unfreeze_wallet("w1", "incident")
        code, _ = self._cancel(sid="s2", cancel_id="cx-2")
        self.assertEqual(code, 201)

    # ---- 重启 / 崩溃恢复 --------------------------------------------------

    def test_cancelled_view_survives_restart(self):
        self._open()
        self.svc.submit_sign_session_share(
            "w1", "s1", "share-1", self._sig("share-1")
        )
        code, view = self._cancel(reason="restart-check")
        self.assertEqual(code, 201)
        svc2 = WalletService(WalletStore(self.d))
        self.assertEqual(svc2.get_sign_session("w1", "s1"), view)
        # 恢复不补记事件
        self.assertEqual(len(_cancel_events(svc2, "w1")), 1)
        # 重放在重启后仍 200 同体
        code, again = svc2.cancel_sign_session(
            "w1", "s1", {"cancel_id": "cx-1", "reason": "restart-check"}
        )
        self.assertEqual(code, 200)
        self.assertEqual(again, view)

    def test_uncommitted_cancel_rolls_back(self):
        """记录已写 cancelled 但事件未落盘：恢复回滚，不留终态。"""
        self._open()
        record = self.svc._store.get_sign_session("w1", "s1")
        cancelled = dict(record)
        cancelled["state"] = "cancelled"
        cancelled["cancellation"] = {"cancel_id": "cx-1", "reason": "r"}
        self.svc._store.update_sign_session("w1", "s1", cancelled)
        svc2 = WalletService(WalletStore(self.d))
        view = svc2.get_sign_session("w1", "s1")
        self.assertEqual(view["state"], "collecting")
        self.assertNotIn("cancellation", view)
        # 回滚后可正常撤销
        code, _ = svc2.cancel_sign_session(
            "w1", "s1", {"cancel_id": "cx-1", "reason": "r"}
        )
        self.assertEqual(code, 201)

    def test_committed_cancel_rolls_forward(self):
        """事件已落盘但记录仍是撤销前状态：恢复前滚为 cancelled。"""
        self._open()
        code, view = self._cancel(cancel_id="cx-1", reason="forward")
        self.assertEqual(code, 201)
        # 把记录回写成撤销前（事件仍在）
        record = self.svc._store.get_sign_session("w1", "s1")
        stale = dict(record)
        stale["state"] = "collecting"
        del stale["cancellation"]
        self.svc._store.update_sign_session("w1", "s1", stale)
        svc2 = WalletService(WalletStore(self.d))
        self.assertEqual(svc2.get_sign_session("w1", "s1"), view)

    def test_event_emit_failure_rolls_back_record(self):
        """事件追加失败且未落盘：记录回滚，无终态、无 seq 缺口。"""
        self._open()
        original_append = self.svc._audit.append_event

        def boom(wallet_id, event):
            raise OSError("audit disk unavailable")

        self.svc._audit.append_event = boom
        with self.assertRaises(OSError):
            self._cancel()
        self.svc._audit.append_event = original_append
        self.assertEqual(
            self.svc.get_sign_session("w1", "s1")["state"], "collecting"
        )
        self.assertEqual(_cancel_events(self.svc, "w1"), [])
        # 可重试并成功
        code, _ = self._cancel()
        self.assertEqual(code, 201)

    def test_tampered_cancellation_record_refuses_startup(self):
        """记录的 cancellation 与事件不符：不可对账，fail-closed 保留现场。"""
        self._open()
        self._cancel(cancel_id="cx-1", reason="orig")
        record = self.svc._store.get_sign_session("w1", "s1")
        tampered = dict(record)
        tampered["cancellation"] = {"cancel_id": "cx-1", "reason": "forged"}
        self.svc._store.update_sign_session("w1", "s1", tampered)
        with self.assertRaises(RecoveryError):
            WalletService(WalletStore(self.d))
        # 现场保留
        self.assertEqual(
            self.svc._store.get_sign_session("w1", "s1")["cancellation"],
            {"cancel_id": "cx-1", "reason": "forged"},
        )

    def test_events_after_cancel_are_contradictory(self):
        """撤销后出现收份额/签名/参与者变更事件：矛盾现场，fail-closed。"""
        self._open()
        self._cancel()
        audit = AuditStore(self.d)
        audit.append_event(
            "w1",
            {
                "type": "session_event",
                "at": "2026-10-01T00:00:00Z",
                "request_id": "s1",
                "actor_id": None,
                "reason": None,
                "details": {
                    "action": "share_received",
                    "share_id": "share-2",
                    "state": "ready",
                },
            },
        )
        with self.assertRaises(RecoveryError):
            WalletService(WalletStore(self.d))

    def test_participant_event_after_cancel_is_contradictory(self):
        self._open()
        code, _ = self.svc.replace_sign_session_participant(
            "w1", "s1", "rep-1", "share-1"
        )
        self.assertEqual(code, 201)
        self._cancel()
        audit = AuditStore(self.d)
        audit.append_event(
            "w1",
            {
                "type": "session_participant_replaced",
                "at": "2026-10-01T00:00:00Z",
                "request_id": "s1",
                "actor_id": None,
                "reason": None,
                "details": {
                    "session_id": "s1",
                    "old_share_id": "share-2",
                    "new_share_id": "rep-2-share",
                },
            },
        )
        with self.assertRaises(RecoveryError):
            WalletService(WalletStore(self.d))

    def test_multiple_terminal_events_are_contradictory(self):
        """cancelled 与 expired/signed 并存：矛盾现场。"""
        self._open(timeout=600)
        self._cancel()
        audit = AuditStore(self.d)
        audit.append_event(
            "w1",
            {
                "type": "session_event",
                "at": "2026-10-01T00:00:00Z",
                "request_id": "s1",
                "actor_id": None,
                "reason": None,
                "details": {"action": "expired", "state": "expired"},
            },
        )
        with self.assertRaises(RecoveryError):
            WalletService(WalletStore(self.d))

    # ---- 轮换解耦 ---------------------------------------------------------

    def test_rotation_does_not_migrate_cancelled_snapshot(self):
        self._open()
        self.svc.submit_sign_session_share(
            "w1", "s1", "share-1", self._sig("share-1")
        )
        code, view = self._cancel()
        self.assertEqual(code, 201)
        self.svc.create_share_rotation("w1", "rot-1")
        self.svc.activate_share_rotation("w1", "rot-1")
        got = self.svc.get_sign_session("w1", "s1")
        self.assertEqual(got, view)
        self.assertEqual(got["received_shares"], ["share-1"])
        self.assertEqual(got["missing_shares"], ["share-2"])

    # ---- 并发线性化 -------------------------------------------------------

    def test_concurrent_cancel_single_201(self):
        import threading

        self._open()
        results: list = []

        def cancel():
            results.append(self._cancel())

        threads = [threading.Thread(target=cancel) for _ in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(sorted(c for c, _ in results), [200, 200, 200, 201])
        self.assertEqual(len(_cancel_events(self.svc, "w1")), 1)

    def test_concurrent_cancel_vs_final_share_single_terminal(self):
        """撤销与最终签名提交交错：只允许一个终态生效，失败一方 409。"""
        import threading

        from threshold_wallet.service import ServiceError

        outcomes: list = []
        self._open()
        self.svc.submit_sign_session_share(
            "w1", "s1", "share-1", self._sig("share-1")
        )

        def cancel():
            try:
                outcomes.append(
                    ("cancel", self._cancel()[0])
                )
            except ServiceError as exc:
                outcomes.append(("cancel", exc.status))

        def deliver():
            try:
                outcomes.append(
                    (
                        "sign",
                        self.svc.submit_sign_session_share(
                            "w1", "s1", "share-2", self._sig("share-2")
                        )[0],
                    )
                )
            except ServiceError as exc:
                outcomes.append(("sign", exc.status))

        threads = [
            threading.Thread(target=cancel),
            threading.Thread(target=deliver),
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        state = self.svc.get_sign_session("w1", "s1")["state"]
        self.assertIn(state, ("signed", "cancelled"))
        by_name = dict()
        for name, code in outcomes:
            by_name.setdefault(name, []).append(code)
        if state == "signed":
            self.assertEqual(by_name["sign"], [201])
            self.assertEqual(by_name["cancel"], [409])
        else:
            self.assertEqual(by_name["cancel"], [201])
            self.assertEqual(by_name["sign"], [409])
        # 审计与状态一致：恰好一个终态事件
        terminals = [
            e["details"]["action"]
            for e in _session_events(self.svc, "w1", "s1")
            if e["details"]["action"] in ("signed", "cancelled", "expired")
        ]
        self.assertEqual(len(terminals), 1)
        self.assertEqual(terminals[0], state)

    # ---- 灾备 -------------------------------------------------------------

    def test_cancelled_session_survives_backup_restore(self):
        self._open()
        code, view = self._cancel(cancel_id="cx-1", reason="dr")
        self.assertEqual(code, 201)
        out = os.path.join(tempfile.mkdtemp(), "w1.tar")
        body = drbackup.backup(self.d, "w1", "snap-1", out)
        self.assertEqual(body["status"], 201)
        d2 = tempfile.mkdtemp()
        status, _ = drbackup.restore(d2, "w1", out)
        self.assertEqual(status, 201)
        svc2 = WalletService(WalletStore(d2))
        self.assertEqual(svc2.get_sign_session("w1", "s1"), view)
        # 恢复不补记事件
        self.assertEqual(len(_cancel_events(svc2, "w1")), 1)

    # ---- 独立 /sign 与审批单不受影响 ---------------------------------------

    def test_sign_entry_and_approval_requests_unaffected(self):
        self.svc.put_policy("w1", 1, 600)
        self.svc.create_sign_request("w1", "req-1", "pay-1")
        self.svc.approve("w1", "req-1", "approver-1", None)
        self._open(sid="s1", message="pay-1")
        self._cancel(sid="s1")
        # 独立 /sign 入口行为不变：审批单照常推进 signed
        sigs = self.h.two_signatures("w1", "req-1", "pay-1")
        code, result = self.svc.sign("w1", "req-1", "pay-1", sigs)
        self.assertEqual(code, 201)
        self.assertIn("signature", result)
        self.assertEqual(
            self.svc.get_sign_request("w1", "req-1")["state"], "signed"
        )


class SignSessionCancelHttpTest(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()

    def _wallet(self, srv, wallet="w1"):
        code, _ = srv.request(
            "POST", "/v1/wallets", {"wallet_id": wallet, "shares": 2}
        )
        self.assertEqual(code, 201)

    def _session(self, srv, sid="s1", wallet="w1", timeout=600):
        code, _ = srv.request(
            "POST",
            f"/v1/wallets/{wallet}/sign-sessions",
            {"id": sid, "message": "hello", "timeout_seconds": timeout},
        )
        self.assertEqual(code, 201)

    def test_http_cancel_flow_and_405(self):
        with http_server(self.d) as srv:
            self._wallet(srv)
            self._session(srv)
            # 其他方法一律 405
            for method in ("GET", "PUT", "DELETE", "PATCH"):
                code, body = srv.request(
                    method, "/v1/wallets/w1/sign-sessions/s1/cancel"
                )
                self.assertEqual(code, 405, (method, body))
                self.assertEqual(body["error"], "method not allowed")
            # 非对象体 / 缺键 / 夹带键 400
            for raw in ("[]", "1", '"x"'):
                import urllib.error
                import urllib.request

                req = urllib.request.Request(
                    srv.base_url + "/v1/wallets/w1/sign-sessions/s1/cancel",
                    data=raw.encode(),
                    method="POST",
                    headers={"Content-Type": "application/json"},
                )
                with self.assertRaises(urllib.error.HTTPError) as ctx:
                    urllib.request.urlopen(req)
                self.assertEqual(ctx.exception.code, 400)
            for body in (
                {},
                {"cancel_id": "c"},
                {"reason": "r"},
                {"cancel_id": "c", "reason": "r", "x": 1},
                {"cancel_id": "bad id", "reason": "r"},
                {"cancel_id": "c", "reason": "  "},
            ):
                code, _ = srv.request(
                    "POST", "/v1/wallets/w1/sign-sessions/s1/cancel", body
                )
                self.assertEqual(code, 400, body)
            # 未知钱包 / 未知会话 404
            code, _ = srv.request(
                "POST",
                "/v1/wallets/ghost/sign-sessions/s1/cancel",
                {"cancel_id": "c", "reason": "r"},
            )
            self.assertEqual(code, 404)
            code, _ = srv.request(
                "POST",
                "/v1/wallets/w1/sign-sessions/ghost/cancel",
                {"cancel_id": "c", "reason": "r"},
            )
            self.assertEqual(code, 404)
            # 首撤 201、重放 200 同体、GET 视图一致
            code, view = srv.request(
                "POST",
                "/v1/wallets/w1/sign-sessions/s1/cancel",
                {"cancel_id": "c-1", "reason": "stop it"},
            )
            self.assertEqual(code, 201)
            self.assertEqual(view["state"], "cancelled")
            self.assertEqual(
                view["cancellation"],
                {"cancel_id": "c-1", "reason": "stop it"},
            )
            code, replay = srv.request(
                "POST",
                "/v1/wallets/w1/sign-sessions/s1/cancel",
                {"cancel_id": "c-1", "reason": "stop it"},
            )
            self.assertEqual(code, 200)
            self.assertEqual(replay, view)
            code, got = srv.request("GET", "/v1/wallets/w1/sign-sessions/s1")
            self.assertEqual(code, 200)
            self.assertEqual(got, view)

    def test_http_access_log_has_no_reason(self):
        with http_server(self.d) as srv:
            self._wallet(srv)
            self._session(srv)
            secret_reason = "super-secret-reason-9f8e"
            code, _ = srv.request(
                "POST",
                "/v1/wallets/w1/sign-sessions/s1/cancel",
                {"cancel_id": "c-1", "reason": secret_reason},
            )
            self.assertEqual(code, 201)
            for line in srv.logs:
                self.assertNotIn(secret_reason, line)

    def test_http_responses_have_no_private_material(self):
        with http_server(self.d) as srv:
            self._wallet(srv)
            self._session(srv)
            code, view = srv.request(
                "POST",
                "/v1/wallets/w1/sign-sessions/s1/cancel",
                {"cancel_id": "c-1", "reason": "r"},
            )
            self.assertEqual(code, 201)
            blob = json.dumps(view)
            h = srv.harness
            for share_id in ("share-1", "share-2"):
                self.assertNotIn(h.share_private_hex("w1", share_id), blob)


if __name__ == "__main__":
    unittest.main()
