"""签名会话主动撤销 ``POST /v1/wallets/<id>/sign-sessions/<sid>/cancel`` 测试。

覆盖：首次撤销 201 与视图 cancellation、同参重放 200（不再检查期限）、
异参/复用/再撤销 409、signed/expired 409、参数与请求体 400、未知 404、
冻结 409 且无副作用、撤销后投递/替换/接管 409、创建同参重放返回撤销后
视图、事件唯一且重放不追加、重启与 backup/restore 持久化、轮换不迁移
撤销快照、并发撤销与签名仅一个终态、矛盾现场 fail-closed、日志不记录
原因原文。
"""

from __future__ import annotations

import json
import os
import tempfile
import threading
import time
import unittest

from tests.helpers import http_server, make_harness
from threshold_wallet import drbackup
from threshold_wallet.service import ServiceError
from threshold_wallet.store import CorruptDataError, RecoveryError


def _session_events(svc, wallet_id):
    return [
        e
        for e in svc.get_audit_events(wallet_id)["events"]
        if e["type"] == "session_event"
    ]


def _actions(svc, wallet_id):
    return [e["details"]["action"] for e in _session_events(svc, wallet_id)]


class SignSessionCancelServiceTest(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.h = make_harness(self.d)
        self.svc = self.h.service
        self.svc.create_wallet("w1", 2)

    def _open(self, sid="s1", message="hello", timeout=600):
        code, view = self.svc.create_sign_session(
            "w1", sid, message, timeout
        )
        self.assertEqual(code, 201)
        return view

    def _sigs(self, sid="s1", message="hello"):
        return {
            "share-1": self.h.share_signature("w1", "share-1", sid, message),
            "share-2": self.h.share_signature("w1", "share-2", sid, message),
        }

    # ---- 首次撤销与视图 ---------------------------------------------------

    def test_cancel_collecting_returns_201_with_cancellation(self):
        self._open()
        code, view = self.svc.cancel_sign_session(
            "w1", "s1", "c1", " 撤回原因\t"
        )
        self.assertEqual(code, 201)
        self.assertEqual(view["state"], "cancelled")
        # cancellation 恰含 cancel_id/reason，reason 原文保留
        self.assertEqual(
            view["cancellation"], {"cancel_id": "c1", "reason": " 撤回原因\t"}
        )
        self.assertNotIn("aggregate_signature", view)
        self.assertEqual(view["received_shares"], [])
        self.assertEqual(view["missing_shares"], ["share-1", "share-2"])
        # 查询同形
        self.assertEqual(self.svc.get_sign_session("w1", "s1"), view)

    def test_cancel_keeps_received_and_missing_snapshot(self):
        self._open()
        sigs = self._sigs()
        self.svc.submit_sign_session_share(
            "w1", "s1", "share-1", sigs["share-1"]
        )
        code, view = self.svc.cancel_sign_session("w1", "s1", "c1", "r")
        self.assertEqual(code, 201)
        self.assertEqual(view["received_shares"], ["share-1"])
        self.assertEqual(view["missing_shares"], ["share-2"])

    def test_cancel_ready_session_returns_201(self):
        # cold 门控失败使会话停留 ready
        self.svc.put_transaction_policy("w1", "cold", 1000, ["BTC"])
        self._open()
        sigs = self._sigs()
        self.svc.submit_sign_session_share(
            "w1", "s1", "share-1", sigs["share-1"]
        )
        code, view = self.svc.submit_sign_session_share(
            "w1", "s1", "share-2", sigs["share-2"]
        )
        self.assertEqual((code, view["state"]), (409, "ready"))
        code, view = self.svc.cancel_sign_session("w1", "s1", "c1", "r")
        self.assertEqual(code, 201)
        self.assertEqual(view["state"], "cancelled")
        self.assertEqual(view["received_shares"], ["share-1", "share-2"])
        self.assertEqual(view["missing_shares"], [])
        self.assertNotIn("aggregate_signature", view)

    # ---- 幂等与判重 -------------------------------------------------------

    def test_replay_same_params_200_same_body_no_new_event(self):
        self._open()
        code, first = self.svc.cancel_sign_session("w1", "s1", "c1", "r")
        self.assertEqual(code, 201)
        code, second = self.svc.cancel_sign_session("w1", "s1", "c1", "r")
        self.assertEqual(code, 200)
        self.assertEqual(second, first)
        self.assertEqual(_actions(self.svc, "w1"), ["created", "cancelled"])

    def test_replay_skips_expiry_check(self):
        self._open(timeout=1)
        code, first = self.svc.cancel_sign_session("w1", "s1", "c1", "r")
        self.assertEqual(code, 201)
        time.sleep(1.1)
        # 同参重放不再检查期限：仍 200 同体，不补 expired 事件
        code, second = self.svc.cancel_sign_session("w1", "s1", "c1", "r")
        self.assertEqual(code, 200)
        self.assertEqual(second, first)
        self.assertEqual(_actions(self.svc, "w1"), ["created", "cancelled"])

    def test_replay_different_reason_is_409(self):
        self._open()
        self.svc.cancel_sign_session("w1", "s1", "c1", "r1")
        with self.assertRaises(ServiceError) as ctx:
            self.svc.cancel_sign_session("w1", "s1", "c1", "r2")
        self.assertEqual(ctx.exception.status, 409)

    def test_cancel_id_reused_on_other_session_is_409(self):
        self._open(sid="s1")
        self._open(sid="s2")
        self.svc.cancel_sign_session("w1", "s1", "c1", "r")
        with self.assertRaises(ServiceError) as ctx:
            self.svc.cancel_sign_session("w1", "s2", "c1", "r")
        self.assertEqual(ctx.exception.status, 409)
        # 另一个会话未被波及
        self.assertEqual(
            self.svc.get_sign_session("w1", "s2")["state"], "collecting"
        )

    def test_second_cancel_with_new_id_is_409(self):
        self._open()
        self.svc.cancel_sign_session("w1", "s1", "c1", "r")
        with self.assertRaises(ServiceError) as ctx:
            self.svc.cancel_sign_session("w1", "s1", "c2", "r")
        self.assertEqual(ctx.exception.status, 409)

    def test_same_cancel_id_on_different_wallets_is_fine(self):
        self.svc.create_wallet("w2", 2)
        self._open(sid="s1")
        self.svc.create_sign_session("w2", "s1", "hello", 600)
        self.assertEqual(
            self.svc.cancel_sign_session("w1", "s1", "c1", "r")[0], 201
        )
        self.assertEqual(
            self.svc.cancel_sign_session("w2", "s1", "c1", "r")[0], 201
        )

    # ---- 状态约束 ---------------------------------------------------------

    def test_cancel_signed_session_is_409(self):
        self._open()
        sigs = self._sigs()
        self.svc.submit_sign_session_share(
            "w1", "s1", "share-1", sigs["share-1"]
        )
        code, view = self.svc.submit_sign_session_share(
            "w1", "s1", "share-2", sigs["share-2"]
        )
        self.assertEqual((code, view["state"]), (201, "signed"))
        with self.assertRaises(ServiceError) as ctx:
            self.svc.cancel_sign_session("w1", "s1", "c1", "r")
        self.assertEqual(ctx.exception.status, 409)
        # 聚合结果不受影响
        self.assertEqual(
            self.svc.get_sign_session("w1", "s1")["state"], "signed"
        )

    def test_cancel_expired_session_is_409_with_lazy_expiry(self):
        self._open(timeout=1)
        time.sleep(1.1)
        with self.assertRaises(ServiceError) as ctx:
            self.svc.cancel_sign_session("w1", "s1", "c1", "r")
        self.assertEqual(ctx.exception.status, 409)
        # 到期会话沿用懒过期语义：原子转 expired 并记一次事件
        self.assertEqual(
            self.svc.get_sign_session("w1", "s1")["state"], "expired"
        )
        self.assertEqual(
            _actions(self.svc, "w1"), ["created", "expired"]
        )

    # ---- 参数校验 ---------------------------------------------------------

    def test_bad_cancel_id_is_400(self):
        self._open()
        for bad in ("", "bad id", "../x", "a" * 129, 123, None, True):
            with self.assertRaises(ServiceError) as ctx:
                self.svc.cancel_sign_session("w1", "s1", bad, "r")
            self.assertEqual(ctx.exception.status, 400, bad)

    def test_bad_reason_is_400(self):
        self._open()
        for bad in ("", "   ", "x" * 1025, 123, None, True, ["r"]):
            with self.assertRaises(ServiceError) as ctx:
                self.svc.cancel_sign_session("w1", "s1", "c1", bad)
            self.assertEqual(ctx.exception.status, 400, bad)
        # 边界：1 与 1024 字符均合法
        self.assertEqual(
            self.svc.cancel_sign_session("w1", "s1", "c1", "x")[0], 201
        )
        self._open(sid="s2")
        self.assertEqual(
            self.svc.cancel_sign_session("w1", "s2", "c2", "y" * 1024)[0],
            201,
        )

    def test_unknown_wallet_is_404(self):
        with self.assertRaises(ServiceError) as ctx:
            self.svc.cancel_sign_session("ghost", "s1", "c1", "r")
        self.assertEqual(ctx.exception.status, 404)

    def test_unknown_session_is_404(self):
        with self.assertRaises(ServiceError) as ctx:
            self.svc.cancel_sign_session("w1", "ghost", "c1", "r")
        self.assertEqual(ctx.exception.status, 404)

    # ---- 撤销后的其他入口 -------------------------------------------------

    def test_submit_share_after_cancel_is_409(self):
        self._open()
        sigs = self._sigs()
        self.svc.submit_sign_session_share(
            "w1", "s1", "share-1", sigs["share-1"]
        )
        self.svc.cancel_sign_session("w1", "s1", "c1", "r")
        # 新份额投递 409
        with self.assertRaises(ServiceError) as ctx:
            self.svc.submit_sign_session_share(
                "w1", "s1", "share-2", sigs["share-2"]
            )
        self.assertEqual(ctx.exception.status, 409)
        # 已收份额同值重放同样 409
        with self.assertRaises(ServiceError) as ctx:
            self.svc.submit_sign_session_share(
                "w1", "s1", "share-1", sigs["share-1"]
            )
        self.assertEqual(ctx.exception.status, 409)

    def test_participant_ops_after_cancel_are_409(self):
        self._open()
        self.svc.cancel_sign_session("w1", "s1", "c1", "r")
        with self.assertRaises(ServiceError) as ctx:
            self.svc.replace_sign_session_participant(
                "w1", "s1", "rep-1", "share-1"
            )
        self.assertEqual(ctx.exception.status, 409)
        with self.assertRaises(ServiceError) as ctx:
            self.svc.takeover_sign_session_participant(
                "w1", "s1", "to-1", 1, "share-1"
            )
        self.assertEqual(ctx.exception.status, 409)

    def test_committed_participant_replay_survives_cancel(self):
        # 先完成一次替换，再撤销：已完成参与者操作的同参重放保留原语义
        self._open()
        code, _ = self.svc.replace_sign_session_participant(
            "w1", "s1", "rep-1", "share-1"
        )
        self.assertEqual(code, 201)
        self.svc.cancel_sign_session("w1", "s1", "c1", "r")
        code, view = self.svc.replace_sign_session_participant(
            "w1", "s1", "rep-1", "share-1"
        )
        self.assertEqual(code, 200)
        self.assertEqual(view["state"], "cancelled")

    def test_create_replay_returns_cancelled_view(self):
        self._open()
        self.svc.cancel_sign_session("w1", "s1", "c1", "r")
        code, view = self.svc.create_sign_session("w1", "s1", "hello", 600)
        self.assertEqual(code, 200)
        self.assertEqual(view["state"], "cancelled")
        self.assertEqual(
            view["cancellation"], {"cancel_id": "c1", "reason": "r"}
        )

    # ---- 事件 -------------------------------------------------------------

    def test_first_cancel_appends_exactly_one_event(self):
        self._open()
        self.svc.cancel_sign_session("w1", "s1", "c1", "原因")
        events = _session_events(self.svc, "w1")
        self.assertEqual(len(events), 2)
        event = events[-1]
        self.assertEqual(event["request_id"], "s1")
        self.assertEqual(event["details"]["action"], "cancelled")
        self.assertEqual(event["details"]["cancel_id"], "c1")
        self.assertEqual(event["details"]["reason"], "原因")
        # 审计不含份额签名或私钥
        self.assertNotIn("signature", json.dumps(event["details"]))

    # ---- 冻结 -------------------------------------------------------------

    def test_frozen_wallet_rejects_cancel_and_replay(self):
        self._open(sid="s1")
        self._open(sid="s2")
        self.svc.cancel_sign_session("w1", "s2", "c2", "r")
        self.svc.freeze_wallet("w1", "incident")
        # 新撤销 409
        with self.assertRaises(ServiceError) as ctx:
            self.svc.cancel_sign_session("w1", "s1", "c1", "r")
        self.assertEqual(ctx.exception.status, 409)
        # 已提交撤销的重放同样 409
        with self.assertRaises(ServiceError) as ctx:
            self.svc.cancel_sign_session("w1", "s2", "c2", "r")
        self.assertEqual(ctx.exception.status, 409)
        # 无副作用：s1 仍 collecting，无新事件
        self.assertEqual(
            self.svc.get_sign_session("w1", "s1")["state"], "collecting"
        )
        self.assertEqual(
            _actions(self.svc, "w1"),
            ["created", "created", "cancelled"],
        )
        # 查询仍可用
        self.assertEqual(
            self.svc.get_sign_session("w1", "s2")["state"], "cancelled"
        )

    # ---- 持久化 -----------------------------------------------------------

    def test_cancel_persists_across_restart(self):
        self._open()
        self.svc.cancel_sign_session("w1", "s1", "c1", "原因")
        h2 = make_harness(self.d)
        view = h2.service.get_sign_session("w1", "s1")
        self.assertEqual(view["state"], "cancelled")
        self.assertEqual(
            view["cancellation"], {"cancel_id": "c1", "reason": "原因"}
        )
        # 重放仍 200，恢复不补记事件
        code, replay = h2.service.cancel_sign_session("w1", "s1", "c1", "原因")
        self.assertEqual(code, 200)
        self.assertEqual(replay, view)
        self.assertEqual(_actions(h2.service, "w1"), ["created", "cancelled"])

    def test_cancel_survives_backup_restore(self):
        self._open()
        self.svc.cancel_sign_session("w1", "s1", "c1", "撤回")
        out = os.path.join(tempfile.mkdtemp(), "b.tar")
        self.assertEqual(
            drbackup.backup(self.d, "w1", "S1", out)["status"], 201
        )
        dst = tempfile.mkdtemp()
        self.assertEqual(drbackup.restore(dst, "w1", out)[0], 201)
        h2 = make_harness(dst)
        view = h2.service.get_sign_session("w1", "s1")
        self.assertEqual(view["state"], "cancelled")
        self.assertEqual(
            view["cancellation"], {"cancel_id": "c1", "reason": "撤回"}
        )
        # 恢复不补记事件
        self.assertEqual(_actions(h2.service, "w1"), ["created", "cancelled"])

    def test_rotation_does_not_migrate_cancelled_snapshot(self):
        self._open()
        sigs = self._sigs()
        self.svc.submit_sign_session_share(
            "w1", "s1", "share-1", sigs["share-1"]
        )
        self.svc.cancel_sign_session("w1", "s1", "c1", "r")
        _, rot = self.svc.create_share_rotation("w1", "rot-1")
        self.assertEqual(
            self.svc.activate_share_rotation("w1", "rot-1")[0], 201
        )
        view = self.svc.get_sign_session("w1", "s1")
        self.assertEqual(view["state"], "cancelled")
        # 已收/缺失份额标识保持撤销时刻快照
        self.assertEqual(view["received_shares"], ["share-1"])
        self.assertEqual(view["missing_shares"], ["share-2"])
        self.assertEqual(
            view["cancellation"], {"cancel_id": "c1", "reason": "r"}
        )

    # ---- 并发 -------------------------------------------------------------

    def test_concurrent_cancel_and_final_sign_single_terminal(self):
        self._open()
        sigs = self._sigs()
        self.svc.submit_sign_session_share(
            "w1", "s1", "share-1", sigs["share-1"]
        )
        results: list = []

        def cancel():
            try:
                results.append(
                    self.svc.cancel_sign_session("w1", "s1", "c1", "r")
                )
            except ServiceError as exc:
                results.append((exc.status, None))

        def sign():
            try:
                results.append(
                    self.svc.submit_sign_session_share(
                        "w1", "s1", "share-2", sigs["share-2"]
                    )
                )
            except ServiceError as exc:
                results.append((exc.status, None))

        threads = [
            threading.Thread(target=cancel),
            threading.Thread(target=sign),
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        # 只允许一个终态生效：一方 201，另一方 409
        self.assertEqual(sorted(c for c, _ in results), [201, 409])
        state = self.svc.get_sign_session("w1", "s1")["state"]
        self.assertIn(state, ("signed", "cancelled"))
        actions = _actions(self.svc, "w1")
        self.assertEqual(len([a for a in actions if a in ("signed", "cancelled")]), 1)

    def test_concurrent_same_cancel_single_201(self):
        self._open()
        results: list = []

        def cancel():
            try:
                results.append(
                    self.svc.cancel_sign_session("w1", "s1", "c1", "r")
                )
            except ServiceError as exc:
                results.append((exc.status, None))

        threads = [threading.Thread(target=cancel) for _ in range(2)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(sorted(c for c, _ in results), [200, 201])
        self.assertEqual(_actions(self.svc, "w1"), ["created", "cancelled"])


class SignSessionCancelRecoveryTest(unittest.TestCase):
    """撤销相关崩溃窗口与矛盾现场：提交点（cancelled 事件）为唯一判据，
    未提交撤销不留终态，矛盾现场 fail-closed 且保留现场。"""

    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.h = make_harness(self.d)
        self.svc = self.h.service
        self.svc.create_wallet("w1", 2)
        self.svc.create_sign_session("w1", "s1", "m", 600)

    def _sessions_path(self):
        return os.path.join(self.d, "sign-sessions", "w1.json")

    def _audit_path(self):
        return os.path.join(self.d, "audit", "w1.json")

    def _tamper_sessions(self, mutate):
        with open(self._sessions_path(), encoding="utf-8") as f:
            data = json.load(f)
        mutate(data)
        with open(self._sessions_path(), "w", encoding="utf-8") as f:
            json.dump(data, f)

    def _append_event(self, details):
        with open(self._audit_path(), encoding="utf-8") as f:
            audit = json.load(f)
        extra = dict(audit["events"][-1])
        extra["seq"] = audit["next_seq"]
        extra["details"] = details
        audit["events"].append(extra)
        audit["next_seq"] += 1
        with open(self._audit_path(), "w", encoding="utf-8") as f:
            json.dump(audit, f)

    def test_uncommitted_cancel_leaves_no_terminal_state(self):
        # 崩溃窗口：记录已写 cancelled 但事件未落盘 -> 回滚为 collecting
        self._tamper_sessions(
            lambda data: data["s1"].update(
                {
                    "state": "cancelled",
                    "cancellation": {"cancel_id": "c1", "reason": "r"},
                }
            )
        )
        view = make_harness(self.d).service.get_sign_session("w1", "s1")
        self.assertEqual(view["state"], "collecting")
        self.assertNotIn("cancellation", view)
        # 回滚后可正常撤销
        code, view = make_harness(self.d).service.cancel_sign_session(
            "w1", "s1", "c1", "r"
        )
        self.assertEqual(code, 201)
        self.assertEqual(view["state"], "cancelled")

    def test_committed_event_forward_rolls_missing_record_state(self):
        # 崩溃窗口：事件已落盘但记录仍是 collecting -> 前滚补齐 cancelled
        self.svc.cancel_sign_session("w1", "s1", "c1", "r")
        self._tamper_sessions(
            lambda data: (
                data["s1"].__setitem__("state", "collecting"),
                data["s1"].pop("cancellation", None),
            )
        )
        svc = make_harness(self.d).service
        view = svc.get_sign_session("w1", "s1")
        self.assertEqual(view["state"], "cancelled")
        self.assertEqual(
            view["cancellation"], {"cancel_id": "c1", "reason": "r"}
        )
        # 恢复不补记事件
        self.assertEqual(_actions(svc, "w1"), ["created", "cancelled"])

    def test_cancellation_mismatch_with_event_refuses(self):
        self.svc.cancel_sign_session("w1", "s1", "c1", "r")
        self._tamper_sessions(
            lambda data: data["s1"]["cancellation"].__setitem__(
                "reason", "tampered"
            )
        )
        with self.assertRaises((RecoveryError, CorruptDataError)):
            make_harness(self.d)
        # 现场保留
        self.assertTrue(os.path.exists(self._sessions_path()))

    def test_cancel_id_committed_by_two_sessions_refuses(self):
        self.svc.create_sign_session("w1", "s2", "m", 600)
        self.svc.cancel_sign_session("w1", "s1", "c1", "r")
        # 伪造另一会话的同标识撤销事件
        self._append_event(
            {
                "action": "cancelled",
                "cancel_id": "c1",
                "reason": "r",
                "state": "cancelled",
            }
        )
        # 把伪造事件的 request_id 改成 s2
        with open(self._audit_path(), encoding="utf-8") as f:
            audit = json.load(f)
        audit["events"][-1]["request_id"] = "s2"
        with open(self._audit_path(), "w", encoding="utf-8") as f:
            json.dump(audit, f)
        with self.assertRaises((RecoveryError, CorruptDataError)):
            make_harness(self.d)

    def test_share_received_after_cancelled_refuses(self):
        self.svc.cancel_sign_session("w1", "s1", "c1", "r")
        self._append_event(
            {
                "action": "share_received",
                "share_id": "share-1",
                "state": "collecting",
            }
        )
        with self.assertRaises((RecoveryError, CorruptDataError)):
            make_harness(self.d)

    def test_malformed_cancelled_event_refuses(self):
        self.svc.cancel_sign_session("w1", "s1", "c1", "r")
        with open(self._audit_path(), encoding="utf-8") as f:
            audit = json.load(f)
        audit["events"][-1]["details"] = {
            "action": "cancelled",
            "cancel_id": "bad id",
            "reason": "r",
            "state": "cancelled",
        }
        with open(self._audit_path(), "w", encoding="utf-8") as f:
            json.dump(audit, f)
        with self.assertRaises((RecoveryError, CorruptDataError)):
            make_harness(self.d)

    def test_cancelled_record_without_cancellation_is_corrupt(self):
        self.svc.cancel_sign_session("w1", "s1", "c1", "r")
        self._tamper_sessions(
            lambda data: data["s1"].pop("cancellation")
        )
        with self.assertRaises((RecoveryError, CorruptDataError)):
            make_harness(self.d)


class SignSessionCancelHttpTest(unittest.TestCase):
    def test_http_route_status_codes_and_405(self):
        with http_server(tempfile.mkdtemp()) as srv:
            srv.request(
                "POST", "/v1/wallets", {"wallet_id": "w1", "shares": 2}
            )
            s, _ = srv.request(
                "POST",
                "/v1/wallets/w1/sign-sessions",
                {"id": "s1", "message": "hi", "timeout_seconds": 60},
            )
            self.assertEqual(s, 201)
            # 缺键 / 夹带键 400
            s, _ = srv.request(
                "POST",
                "/v1/wallets/w1/sign-sessions/s1/cancel",
                {"cancel_id": "c1"},
            )
            self.assertEqual(s, 400)
            s, _ = srv.request(
                "POST",
                "/v1/wallets/w1/sign-sessions/s1/cancel",
                {"cancel_id": "c1", "reason": "r", "extra": 1},
            )
            self.assertEqual(s, 400)
            # 非对象体 400
            req = srv.request(
                "POST", "/v1/wallets/w1/sign-sessions/s1/cancel", [1, 2]
            )
            self.assertEqual(req[0], 400)
            # 字段值非法 400
            s, _ = srv.request(
                "POST",
                "/v1/wallets/w1/sign-sessions/s1/cancel",
                {"cancel_id": "bad id", "reason": "r"},
            )
            self.assertEqual(s, 400)
            # 未知钱包 / 未知会话 404
            s, _ = srv.request(
                "POST",
                "/v1/wallets/ghost/sign-sessions/s1/cancel",
                {"cancel_id": "c1", "reason": "r"},
            )
            self.assertEqual(s, 404)
            s, _ = srv.request(
                "POST",
                "/v1/wallets/w1/sign-sessions/ghost/cancel",
                {"cancel_id": "c1", "reason": "r"},
            )
            self.assertEqual(s, 404)
            # 首次 201，重放 200
            s, b = srv.request(
                "POST",
                "/v1/wallets/w1/sign-sessions/s1/cancel",
                {"cancel_id": "c1", "reason": "r"},
            )
            self.assertEqual(s, 201)
            self.assertEqual(b["state"], "cancelled")
            self.assertEqual(
                b["cancellation"], {"cancel_id": "c1", "reason": "r"}
            )
            s, b2 = srv.request(
                "POST",
                "/v1/wallets/w1/sign-sessions/s1/cancel",
                {"cancel_id": "c1", "reason": "r"},
            )
            self.assertEqual(s, 200)
            self.assertEqual(b2, b)
            # 其他方法 405
            for method in ("GET", "PUT", "DELETE", "PATCH"):
                s, _ = srv.request(
                    method, "/v1/wallets/w1/sign-sessions/s1/cancel"
                )
                self.assertEqual(s, 405, method)

    def test_access_log_never_contains_reason(self):
        with http_server(tempfile.mkdtemp()) as srv:
            srv.request(
                "POST", "/v1/wallets", {"wallet_id": "w1", "shares": 2}
            )
            srv.request(
                "POST",
                "/v1/wallets/w1/sign-sessions",
                {"id": "s1", "message": "hi", "timeout_seconds": 60},
            )
            marker = "CANCEL-REASON-SECRET-MARKER"
            s, _ = srv.request(
                "POST",
                "/v1/wallets/w1/sign-sessions/s1/cancel",
                {"cancel_id": "c1", "reason": marker},
            )
            self.assertEqual(s, 201)
            self.assertNotIn(marker, "\n".join(srv.logs))


if __name__ == "__main__":
    unittest.main()
