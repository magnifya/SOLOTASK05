"""可恢复签名会话 ``/v1/wallets/<id>/sign-sessions`` 测试。

覆盖：创建/重放/冲突/参数校验、视图字段、份额投递（首收/重放/异值/
非法/未知份额/未知会话）、collecting→ready→signed 聚合与独立验证、
审批与 hot/cold 门控（409 保留 ready 供重试）、懒过期（查询与投递）、
重启持久化、并发仅一个首次聚合、损坏现场 fail-closed 503、审计
session_event（七字段、连续 seq、details 以 action 区分且不含签名）、
轮换兼容，以及磁盘/响应/日志不含私钥。
"""

from __future__ import annotations

import json
import os
import tempfile
import threading
import time
import unittest

from tests.helpers import http_server, make_harness
from threshold_wallet import crypto
from threshold_wallet.service import ServiceError
from threshold_wallet.store import CorruptDataError, RecoveryError


def _session_events(svc, wallet_id):
    return [
        e
        for e in svc.get_audit_events(wallet_id)["events"]
        if e["type"] == "session_event"
    ]


class SignSessionServiceTest(unittest.TestCase):
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

    # ---- 创建与视图 -----------------------------------------------------

    def test_create_returns_201_collecting_view(self):
        before = time.time()
        view = self._open()
        self.assertEqual(view["id"], "s1")
        self.assertEqual(view["message"], "hello")
        self.assertEqual(view["state"], "collecting")
        self.assertEqual(view["received_shares"], [])
        self.assertEqual(view["missing_shares"], ["share-1", "share-2"])
        self.assertNotIn("aggregate_signature", view)
        self.assertIn("expires_at", view)
        # 到期时间约为创建时刻 + timeout
        from datetime import datetime

        expires = datetime.fromisoformat(
            view["expires_at"].replace("Z", "+00:00")
        ).timestamp()
        self.assertGreaterEqual(expires - before, 590)

    def test_create_replay_same_params_200_same_body(self):
        first = self._open()
        code, second = self.svc.create_sign_session("w1", "s1", "hello", 600)
        self.assertEqual(code, 200)
        self.assertEqual(second, first)

    def test_create_different_message_is_409(self):
        self._open()
        with self.assertRaises(ServiceError) as ctx:
            self.svc.create_sign_session("w1", "s1", "other", 600)
        self.assertEqual(ctx.exception.status, 409)

    def test_create_different_timeout_is_409(self):
        self._open()
        with self.assertRaises(ServiceError) as ctx:
            self.svc.create_sign_session("w1", "s1", "hello", 999)
        self.assertEqual(ctx.exception.status, 409)

    def test_create_bad_params_are_400(self):
        for sid, message, timeout in [
            ("", "m", 60),
            (123, "m", 60),
            ("bad id", "m", 60),
            ("../x", "m", 60),
            ("s", "", 60),
            ("s", 123, 60),
            ("s", None, 60),
            ("s", "m", 0),
            ("s", "m", -1),
            ("s", "m", 1.5),
            ("s", "m", True),
            ("s", "m", "60"),
            ("s", "m", None),
        ]:
            with self.assertRaises(ServiceError) as ctx:
                self.svc.create_sign_session("w1", sid, message, timeout)
            self.assertEqual(ctx.exception.status, 400, (sid, message, timeout))

    def test_create_wallet_missing_is_404(self):
        with self.assertRaises(ServiceError) as ctx:
            self.svc.create_sign_session("ghost", "s1", "m", 60)
        self.assertEqual(ctx.exception.status, 404)

    def test_create_replay_does_not_lazy_expire_or_log(self):
        self._open(timeout=1)
        time.sleep(1.1)
        # POST 重放不触发懒过期：磁盘仍呈现 collecting，也不记事件
        code, view = self.svc.create_sign_session("w1", "s1", "hello", 1)
        self.assertEqual(code, 200)
        self.assertEqual(view["state"], "collecting")
        actions = [
            e["details"]["action"] for e in _session_events(self.svc, "w1")
        ]
        self.assertEqual(actions, ["created"])

    # ---- GET 与懒过期 ---------------------------------------------------

    def test_get_unknown_session_is_404(self):
        with self.assertRaises(ServiceError) as ctx:
            self.svc.get_sign_session("w1", "nope")
        self.assertEqual(ctx.exception.status, 404)

    def test_get_lazy_expires_collecting_session(self):
        self._open(timeout=1)
        time.sleep(1.1)
        view = self.svc.get_sign_session("w1", "s1")
        self.assertEqual(view["state"], "expired")
        self.assertNotIn("aggregate_signature", view)
        # 过期持久化：再次查询不再记事件
        self.svc.get_sign_session("w1", "s1")
        actions = [
            e["details"]["action"] for e in _session_events(self.svc, "w1")
        ]
        self.assertEqual(actions, ["created", "expired"])

    # ---- 份额投递 -------------------------------------------------------

    def test_first_share_201_collecting(self):
        self._open()
        sigs = self._sigs()
        code, view = self.svc.submit_sign_session_share(
            "w1", "s1", "share-1", sigs["share-1"]
        )
        self.assertEqual(code, 201)
        self.assertEqual(view["state"], "collecting")
        self.assertEqual(view["received_shares"], ["share-1"])
        self.assertEqual(view["missing_shares"], ["share-2"])

    def test_same_share_same_value_200(self):
        self._open()
        sigs = self._sigs()
        self.svc.submit_sign_session_share(
            "w1", "s1", "share-1", sigs["share-1"]
        )
        code, view = self.svc.submit_sign_session_share(
            "w1", "s1", "share-1", sigs["share-1"]
        )
        self.assertEqual(code, 200)
        self.assertEqual(view["state"], "collecting")
        # 重放不记事件
        actions = [
            e["details"]["action"] for e in _session_events(self.svc, "w1")
        ]
        self.assertEqual(actions, ["created", "share_received"])

    def test_same_share_different_value_409(self):
        self._open()
        sigs = self._sigs()
        self.svc.submit_sign_session_share(
            "w1", "s1", "share-1", sigs["share-1"]
        )
        with self.assertRaises(ServiceError) as ctx:
            self.svc.submit_sign_session_share(
                "w1", "s1", "share-1", "00" * 64
            )
        self.assertEqual(ctx.exception.status, 409)

    def test_invalid_signature_encoding_400(self):
        self._open()
        for bad in ("not-hex", "00" * 32, "00" * 96, 123, None):
            with self.assertRaises(ServiceError) as ctx:
                self.svc.submit_sign_session_share(
                    "w1", "s1", "share-1", bad
                )
            self.assertEqual(ctx.exception.status, 400, bad)

    def test_wrong_signature_400(self):
        self._open()
        with self.assertRaises(ServiceError) as ctx:
            self.svc.submit_sign_session_share(
                "w1", "s1", "share-2", "00" * 64
            )
        self.assertEqual(ctx.exception.status, 400)

    def test_signature_must_be_over_id_concatenated_with_message(self):
        # 份额签的是别的 message / 别的 id：载荷是 id+message 直接拼接
        self._open()
        wrong_msg = self.h.share_signature("w1", "share-1", "s1", "other")
        wrong_id = self.h.share_signature("w1", "share-1", "sx", "hello")
        with self.assertRaises(ServiceError) as ctx:
            self.svc.submit_sign_session_share(
                "w1", "s1", "share-1", wrong_msg
            )
        self.assertEqual(ctx.exception.status, 400)
        with self.assertRaises(ServiceError) as ctx:
            self.svc.submit_sign_session_share(
                "w1", "s1", "share-1", wrong_id
            )
        self.assertEqual(ctx.exception.status, 400)

    def test_unknown_share_id_400(self):
        self._open()
        with self.assertRaises(ServiceError) as ctx:
            self.svc.submit_sign_session_share(
                "w1", "s1", "intruder", "00" * 64
            )
        self.assertEqual(ctx.exception.status, 400)

    def test_share_unknown_session_is_404(self):
        with self.assertRaises(ServiceError) as ctx:
            self.svc.submit_sign_session_share(
                "w1", "nope", "share-1", "00" * 64
            )
        self.assertEqual(ctx.exception.status, 404)

    def test_delivery_lazy_expires_then_409(self):
        self._open(timeout=1)
        sigs = self._sigs()
        time.sleep(1.1)
        with self.assertRaises(ServiceError) as ctx:
            self.svc.submit_sign_session_share(
                "w1", "s1", "share-1", sigs["share-1"]
            )
        self.assertEqual(ctx.exception.status, 409)
        view = self.svc.get_sign_session("w1", "s1")
        self.assertEqual(view["state"], "expired")

    def test_delivery_to_expired_session_is_409(self):
        self._open(timeout=1)
        sigs = self._sigs()
        # 先收一份，再过期；对已收份额的同值重放在终态上同样 409
        self.svc.submit_sign_session_share(
            "w1", "s1", "share-1", sigs["share-1"]
        )
        time.sleep(1.1)
        self.svc.get_sign_session("w1", "s1")  # 懒过期
        with self.assertRaises(ServiceError) as ctx:
            self.svc.submit_sign_session_share(
                "w1", "s1", "share-1", sigs["share-1"]
            )
        self.assertEqual(ctx.exception.status, 409)

    def _ready_session(self, sid="g1", message="msg", timeout=1):
        """构造一个齐份但门控未过的 ready 会话。"""
        self.svc.put_policy("w1", 1, 3600)
        self._open(sid=sid, message=message, timeout=timeout)
        sigs = {
            sid_: self.h.share_signature("w1", sid_, sid, message)
            for sid_ in ("share-1", "share-2")
        }
        self.svc.submit_sign_session_share("w1", sid, "share-1", sigs["share-1"])
        code, view = self.svc.submit_sign_session_share(
            "w1", sid, "share-2", sigs["share-2"]
        )
        self.assertEqual(code, 409)
        self.assertEqual(view["state"], "ready")
        return sigs

    def test_ready_session_lazy_expires_on_get(self):
        sigs = self._ready_session(sid="re1")
        time.sleep(1.1)
        view = self.svc.get_sign_session("w1", "re1")
        self.assertEqual(view["state"], "expired")
        self.assertNotIn("aggregate_signature", view)
        # 再查不重复记 expired
        self.svc.get_sign_session("w1", "re1")
        actions = [
            e["details"]["action"] for e in _session_events(self.svc, "w1")
        ]
        self.assertEqual(
            actions,
            ["created", "share_received", "share_received", "expired"],
        )

    def test_ready_session_expires_on_delivery_and_terminal_wont_aggregate(self):
        sigs = self._ready_session(sid="re2")
        time.sleep(1.1)
        # 投递到点：原子 expired，返回 409
        with self.assertRaises(ServiceError) as ctx:
            self.svc.submit_sign_session_share(
                "w1", "re2", "share-2", sigs["share-2"]
            )
        self.assertEqual(ctx.exception.status, 409)
        self.assertEqual(
            self.svc.get_sign_session("w1", "re2")["state"], "expired"
        )
        # 门控补齐后再投递：终态不再聚合，仍 409
        self.svc.create_sign_request("w1", "re2", "msg")
        self.svc.approve("w1", "re2", "ops-1")
        with self.assertRaises(ServiceError) as ctx:
            self.svc.submit_sign_session_share(
                "w1", "re2", "share-2", sigs["share-2"]
            )
        self.assertEqual(ctx.exception.status, 409)
        actions = [
            e["details"]["action"] for e in _session_events(self.svc, "w1")
        ]
        self.assertEqual(actions.count("expired"), 1)
        self.assertNotIn("signed", actions)

    def test_ready_session_before_timeout_still_retries(self):
        sigs = self._ready_session(sid="re3", timeout=600)
        self.svc.create_sign_request("w1", "re3", "msg")
        self.svc.approve("w1", "re3", "ops-1")
        code, view = self.svc.submit_sign_session_share(
            "w1", "re3", "share-2", sigs["share-2"]
        )
        self.assertEqual(code, 200)
        self.assertEqual(view["state"], "signed")

    def test_ready_session_persists_expired_across_restart(self):
        self._ready_session(sid="re4", timeout=1)
        time.sleep(1.1)
        self.svc.get_sign_session("w1", "re4")
        h2 = make_harness(self.d)
        view = h2.service.get_sign_session("w1", "re4")
        self.assertEqual(view["state"], "expired")
        actions = [
            e["details"]["action"]
            for e in h2.service.get_audit_events("w1")["events"]
            if e["type"] == "session_event"
        ]
        self.assertEqual(actions.count("expired"), 1)

    def test_complete_returns_201_signed_with_valid_aggregate(self):
        wallet = self.svc.get_wallet("w1")
        self._open()
        sigs = self._sigs()
        self.svc.submit_sign_session_share(
            "w1", "s1", "share-1", sigs["share-1"]
        )
        code, view = self.svc.submit_sign_session_share(
            "w1", "s1", "share-2", sigs["share-2"]
        )
        self.assertEqual(code, 201)
        self.assertEqual(view["state"], "signed")
        self.assertEqual(view["received_shares"], ["share-1", "share-2"])
        self.assertEqual(view["missing_shares"], [])
        aggregate = bytes.fromhex(view["aggregate_signature"])
        self.assertEqual(len(aggregate), 128)
        # 用钱包公钥独立验证聚合签名
        pks = crypto.split_public_key(bytes.fromhex(wallet["public_key"]))
        parts = crypto.split_signature(aggregate)
        payload = crypto.build_payload("s1", "hello")
        self.assertTrue(crypto.verify_share(pks[0], payload, parts[0]))
        self.assertTrue(crypto.verify_share(pks[1], payload, parts[1]))

    def test_signed_replay_200_same_body_for_either_share(self):
        self._open()
        sigs = self._sigs()
        self.svc.submit_sign_session_share(
            "w1", "s1", "share-1", sigs["share-1"]
        )
        _, signed = self.svc.submit_sign_session_share(
            "w1", "s1", "share-2", sigs["share-2"]
        )
        for sid in ("share-1", "share-2"):
            code, view = self.svc.submit_sign_session_share(
                "w1", "s1", sid, sigs[sid]
            )
            self.assertEqual(code, 200)
            self.assertEqual(view, signed)
        # signed 后重放不重复记事件
        actions = [
            e["details"]["action"] for e in _session_events(self.svc, "w1")
        ]
        self.assertEqual(
            actions, ["created", "share_received", "share_received", "signed"]
        )

    def test_share_order_independent(self):
        self._open()
        sigs = self._sigs()
        self.svc.submit_sign_session_share(
            "w1", "s1", "share-2", sigs["share-2"]
        )
        code, view = self.svc.submit_sign_session_share(
            "w1", "s1", "share-1", sigs["share-1"]
        )
        self.assertEqual(code, 201)
        self.assertEqual(view["state"], "signed")
        # 聚合顺序恒为 share-1, share-2
        aggregate = bytes.fromhex(view["aggregate_signature"])
        wallet = self.svc.get_wallet("w1")
        pks = crypto.split_public_key(bytes.fromhex(wallet["public_key"]))
        parts = crypto.split_signature(aggregate)
        payload = crypto.build_payload("s1", "hello")
        self.assertTrue(crypto.verify_share(pks[0], payload, parts[0]))
        self.assertTrue(crypto.verify_share(pks[1], payload, parts[1]))

    # ---- 审批与 hot/cold 门控 -------------------------------------------

    def test_hot_gate_failure_keeps_ready_and_retry_succeeds(self):
        self.svc.put_policy("w1", 1, 3600)
        self._open(sid="g1", message="msg")
        sigs = self._sigs("g1", "msg")
        self.svc.submit_sign_session_share(
            "w1", "g1", "share-1", sigs["share-1"]
        )
        # 无审批单：门控失败以 409 返回，ready 保留
        code, view = self.svc.submit_sign_session_share(
            "w1", "g1", "share-2", sigs["share-2"]
        )
        self.assertEqual(code, 409)
        self.assertEqual(view["state"], "ready")
        self.assertEqual(view["missing_shares"], [])
        self.assertNotIn("aggregate_signature", view)
        # ready 不会因到期时间流逝而过期
        # （批准后重放第二份即可继续聚合）
        code, _ = self.svc.create_sign_request("w1", "g1", "msg")
        self.assertEqual(code, 201)
        self.svc.approve("w1", "g1", "ops-1")
        code, view = self.svc.submit_sign_session_share(
            "w1", "g1", "share-2", sigs["share-2"]
        )
        self.assertEqual(code, 200)
        self.assertEqual(view["state"], "signed")
        actions = [
            e["details"]["action"] for e in _session_events(self.svc, "w1")
        ]
        self.assertEqual(actions.count("signed"), 1)

    def test_cold_gate_without_approval_is_409_ready(self):
        self.svc.put_transaction_policy("w1", "cold", 1000, ["BTC"])
        self._open(sid="c1", message="m")
        sigs = self._sigs("c1", "m")
        self.svc.submit_sign_session_share(
            "w1", "c1", "share-1", sigs["share-1"]
        )
        code, view = self.svc.submit_sign_session_share(
            "w1", "c1", "share-2", sigs["share-2"]
        )
        self.assertEqual(code, 409)
        self.assertEqual(view["state"], "ready")
        # 补审批后重放成功
        self.svc.put_policy("w1", 1, 3600)
        self.svc.create_sign_request("w1", "c1", "m")
        self.svc.approve("w1", "c1", "ops-1")
        code, view = self.svc.submit_sign_session_share(
            "w1", "c1", "share-2", sigs["share-2"]
        )
        self.assertEqual(code, 200)
        self.assertEqual(view["state"], "signed")

    def test_cold_gate_approved_completes_201(self):
        self.svc.put_policy("w1", 1, 3600)
        self.svc.put_transaction_policy("w1", "cold", 1000, ["BTC"])
        self.svc.create_sign_request("w1", "x1", "m")
        self.svc.approve("w1", "x1", "ops-1")
        self._open(sid="x1", message="m")
        sigs = self._sigs("x1", "m")
        self.svc.submit_sign_session_share(
            "w1", "x1", "share-1", sigs["share-1"]
        )
        code, view = self.svc.submit_sign_session_share(
            "w1", "x1", "share-2", sigs["share-2"]
        )
        self.assertEqual(code, 201)
        self.assertEqual(view["state"], "signed")

    def test_no_policy_signs_immediately(self):
        # 未配置审批/交易策略时行为与既有 /sign 一致：齐份即签
        self._open(sid="n1", message="m")
        sigs = self._sigs("n1", "m")
        self.svc.submit_sign_session_share(
            "w1", "n1", "share-1", sigs["share-1"]
        )
        code, view = self.svc.submit_sign_session_share(
            "w1", "n1", "share-2", sigs["share-2"]
        )
        self.assertEqual(code, 201)
        self.assertEqual(view["state"], "signed")

    # ---- 审计事件 -------------------------------------------------------

    def test_session_events_seven_fields_continuous_seq(self):
        self._open()
        sigs = self._sigs()
        self.svc.submit_sign_session_share(
            "w1", "s1", "share-1", sigs["share-1"]
        )
        self.svc.submit_sign_session_share(
            "w1", "s1", "share-2", sigs["share-2"]
        )
        events = self.svc.get_audit_events("w1")["events"]
        self.assertEqual(
            [e["seq"] for e in events], [1, 2, 3, 4]
        )
        for event in events:
            self.assertEqual(
                set(event),
                {
                    "seq",
                    "type",
                    "at",
                    "request_id",
                    "actor_id",
                    "reason",
                    "details",
                },
            )
            self.assertEqual(event["request_id"], "s1")
            self.assertIsNone(event["actor_id"])
            self.assertIsNone(event["reason"])
            self.assertTrue(event["at"].endswith("Z"))
        actions = [e["details"] for e in events]
        self.assertEqual(
            actions,
            [
                {"action": "created", "message": "hello", "timeout_seconds": 600},
                {
                    "action": "share_received",
                    "share_id": "share-1",
                    "state": "collecting",
                },
                {"action": "share_received", "share_id": "share-2", "state": "ready"},
                {"action": "signed", "state": "signed"},
            ],
        )

    def test_session_event_details_never_contain_signatures(self):
        self._open()
        sigs = self._sigs()
        self.svc.submit_sign_session_share(
            "w1", "s1", "share-1", sigs["share-1"]
        )
        self.svc.submit_sign_session_share(
            "w1", "s1", "share-2", sigs["share-2"]
        )
        raw = json.dumps(self.svc.get_audit_events("w1")["events"])
        self.assertNotIn(sigs["share-1"], raw)
        self.assertNotIn(sigs["share-2"], raw)

    # ---- 重启持久化 -----------------------------------------------------

    def test_persists_across_restart_and_completes(self):
        self._open(sid="r1", message="m")
        a = self.h.share_signature("w1", "share-1", "r1", "m")
        self.svc.submit_sign_session_share("w1", "r1", "share-1", a)
        # 模拟新进程：同 data-dir 重新构造 service（启动恢复在锁内进行）
        h2 = make_harness(self.d)
        view = h2.service.get_sign_session("w1", "r1")
        self.assertEqual(view["state"], "collecting")
        self.assertEqual(view["received_shares"], ["share-1"])
        b = self.h.share_signature("w1", "share-2", "r1", "m")
        code, signed = h2.service.submit_sign_session_share(
            "w1", "r1", "share-2", b
        )
        self.assertEqual(code, 201)
        self.assertEqual(signed["state"], "signed")
        # 再重启：signed 重放 200 同体，不产生重复事件/seq 缺口
        h3 = make_harness(self.d)
        code, view = h3.service.submit_sign_session_share(
            "w1", "r1", "share-1", a
        )
        self.assertEqual(code, 200)
        self.assertEqual(view, signed)
        events = h3.service.get_audit_events("w1")["events"]
        self.assertEqual([e["seq"] for e in events], list(range(1, 5)))
        actions = [
            e["details"]["action"]
            for e in events
            if e["type"] == "session_event"
        ]
        self.assertEqual(
            actions, ["created", "share_received", "share_received", "signed"]
        )

    def test_expired_session_persists_across_restart(self):
        self._open(timeout=1)
        time.sleep(1.1)
        self.svc.get_sign_session("w1", "s1")
        h2 = make_harness(self.d)
        view = h2.service.get_sign_session("w1", "s1")
        self.assertEqual(view["state"], "expired")

    # ---- 并发 -----------------------------------------------------------

    def test_concurrent_shares_single_first_aggregation(self):
        self._open(sid="cc1", message="m")
        sigs = self._sigs("cc1", "m")
        results: list = []

        def deliver(sid):
            results.append(
                self.svc.submit_sign_session_share(
                    "w1", "cc1", sid, sigs[sid]
                )
            )

        threads = [
            threading.Thread(target=deliver, args=("share-1",)),
            threading.Thread(target=deliver, args=("share-2",)),
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(sorted(c for c, _ in results), [201, 201])
        self.assertEqual(
            self.svc.get_sign_session("w1", "cc1")["state"], "signed"
        )
        actions = [
            e["details"]["action"] for e in _session_events(self.svc, "w1")
        ]
        self.assertEqual(
            actions, ["created", "share_received", "share_received", "signed"]
        )

    def test_concurrent_duplicate_share_one_201_one_200(self):
        self._open(sid="cc2", message="m")
        sig = self.h.share_signature("w1", "share-1", "cc2", "m")
        results: list = []

        def deliver():
            results.append(
                self.svc.submit_sign_session_share("w1", "cc2", "share-1", sig)
            )

        threads = [threading.Thread(target=deliver) for _ in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        codes = sorted(c for c, _ in results)
        self.assertEqual(codes, [200, 200, 200, 201])

    def test_concurrent_ready_retry_single_signed_event(self):
        self.svc.put_policy("w1", 1, 3600)
        self._open(sid="g1", message="m")
        sigs = self._sigs("g1", "m")
        self.svc.submit_sign_session_share(
            "w1", "g1", "share-1", sigs["share-1"]
        )
        code, _ = self.svc.submit_sign_session_share(
            "w1", "g1", "share-2", sigs["share-2"]
        )
        self.assertEqual(code, 409)
        self.svc.create_sign_request("w1", "g1", "m")
        self.svc.approve("w1", "g1", "ops-1")
        results: list = []

        def retry():
            results.append(
                self.svc.submit_sign_session_share(
                    "w1", "g1", "share-2", sigs["share-2"]
                )
            )

        threads = [threading.Thread(target=retry) for _ in range(3)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertTrue(
            all(c == 200 and v["state"] == "signed" for c, v in results)
        )
        actions = [
            e["details"]["action"] for e in _session_events(self.svc, "w1")
        ]
        self.assertEqual(actions.count("signed"), 1)

    # ---- 份额轮换兼容 ---------------------------------------------------

    def test_rotation_migrates_inflight_session_to_current_shares(self):
        # 已 signed 的会话保留原聚合：构成该聚合的旧份额同值重放仍 200 同体
        self._open(sid="done1", message="m")
        a = self.h.share_signature("w1", "share-1", "done1", "m")
        b = self.h.share_signature("w1", "share-2", "done1", "m")
        self.svc.submit_sign_session_share("w1", "done1", "share-1", a)
        signed = self.svc.submit_sign_session_share(
            "w1", "done1", "share-2", b
        )[1]
        # 未齐份的在途会话与旧第二份签名（轮换前生成）
        self._open(sid="infl1", message="m")
        a1 = self.h.share_signature("w1", "share-1", "infl1", "m")
        b_old = self.h.share_signature("w1", "share-2", "infl1", "m")
        self.svc.submit_sign_session_share("w1", "infl1", "share-1", a1)

        _, rot = self.svc.create_share_rotation("w1", "rot-1")
        self.assertEqual(
            self.svc.activate_share_rotation("w1", "rot-1")[0], 201
        )
        new_ids = rot["share_ids"]

        # 已 signed 的会话用构成其聚合的旧份额重放仍 200 同体
        code, view = self.svc.submit_sign_session_share(
            "w1", "done1", "share-1", a
        )
        self.assertEqual(code, 200)
        self.assertEqual(view, signed)
        code, view = self.svc.submit_sign_session_share(
            "w1", "done1", "share-2", b
        )
        self.assertEqual(code, 200)
        self.assertEqual(view, signed)

        # 在途会话迁移到当前在用快照：已收旧份额被剔除，视图同步
        view = self.svc.get_sign_session("w1", "infl1")
        self.assertEqual(view["state"], "collecting")
        self.assertEqual(view["received_shares"], [])
        self.assertEqual(view["missing_shares"], list(new_ids))
        # 旧份额补投一律 400（此前未收的旧份额与已收旧份额的同值重放）
        with self.assertRaises(ServiceError) as ctx:
            self.svc.submit_sign_session_share(
                "w1", "infl1", "share-2", b_old
            )
        self.assertEqual(ctx.exception.status, 400)
        with self.assertRaises(ServiceError) as ctx:
            self.svc.submit_sign_session_share(
                "w1", "infl1", "share-1", a1
            )
        self.assertEqual(ctx.exception.status, 400)

    def test_rotation_inflight_collecting_completes_with_new_shares(self):
        self._open(sid="infl2", message="m")
        a1 = self.h.share_signature("w1", "share-1", "infl2", "m")
        self.svc.submit_sign_session_share("w1", "infl2", "share-1", a1)
        _, rot = self.svc.create_share_rotation("w1", "rot-1")
        self.assertEqual(
            self.svc.activate_share_rotation("w1", "rot-1")[0], 201
        )
        new_ids = rot["share_ids"]
        self.assertEqual(
            self.svc.get_sign_session("w1", "infl2")["missing_shares"],
            list(new_ids),
        )
        x = self.h.share_signature("w1", new_ids[0], "infl2", "m")
        y = self.h.share_signature("w1", new_ids[1], "infl2", "m")
        code, view = self.svc.submit_sign_session_share(
            "w1", "infl2", new_ids[0], x
        )
        self.assertEqual(code, 201)
        self.assertEqual(view["received_shares"], [new_ids[0]])
        code, view = self.svc.submit_sign_session_share(
            "w1", "infl2", new_ids[1], y
        )
        self.assertEqual(code, 201)
        self.assertEqual(view["state"], "signed")
        # 旧 share-1 的投递事件保留在仅追加审计，但不再出现在会话视图；
        # 新聚合只由两份新份额构成，独立验证通过
        wallet = self.svc.get_wallet("w1")
        pks = crypto.split_public_key(bytes.fromhex(wallet["public_key"]))
        parts = crypto.split_signature(bytes.fromhex(view["aggregate_signature"]))
        payload = crypto.build_payload("infl2", "m")
        self.assertTrue(crypto.verify_share(pks[0], payload, parts[0]))
        self.assertTrue(crypto.verify_share(pks[1], payload, parts[1]))
        # 已剔除的旧份额再投 400；旧审计事件不重复
        with self.assertRaises(ServiceError) as ctx:
            self.svc.submit_sign_session_share("w1", "infl2", "share-1", a1)
        self.assertEqual(ctx.exception.status, 400)

    def test_rotation_migrates_ready_session_and_new_shares_complete(self):
        # ready（门控未过）会话在轮换后同样迁移：剔除旧两份，新份额补齐后
        # 门控通过即可聚合
        self.svc.put_policy("w1", 1, 3600)
        self._open(sid="gr1", message="msg")
        old = {
            sid: self.h.share_signature("w1", sid, "gr1", "msg")
            for sid in ("share-1", "share-2")
        }
        self.svc.submit_sign_session_share("w1", "gr1", "share-1", old["share-1"])
        code, view = self.svc.submit_sign_session_share(
            "w1", "gr1", "share-2", old["share-2"]
        )
        self.assertEqual(code, 409)
        self.assertEqual(view["state"], "ready")
        _, rot = self.svc.create_share_rotation("w1", "rot-1")
        self.svc.activate_share_rotation("w1", "rot-1")
        new_ids = rot["share_ids"]
        view = self.svc.get_sign_session("w1", "gr1")
        self.assertEqual(view["state"], "collecting")
        self.assertEqual(view["received_shares"], [])
        self.assertEqual(view["missing_shares"], list(new_ids))
        # 门控补齐
        self.svc.create_sign_request("w1", "gr1", "msg")
        self.svc.approve("w1", "gr1", "ops-1")
        new = {
            sid: self.h.share_signature("w1", sid, "gr1", "msg")
            for sid in new_ids
        }
        self.svc.submit_sign_session_share("w1", "gr1", new_ids[0], new[new_ids[0]])
        code, view = self.svc.submit_sign_session_share(
            "w1", "gr1", new_ids[1], new[new_ids[1]]
        )
        self.assertEqual(code, 201)
        self.assertEqual(view["state"], "signed")

    def test_rotation_signed_old_share_different_value_is_409(self):
        self._open(sid="done2", message="m")
        a = self.h.share_signature("w1", "share-1", "done2", "m")
        b = self.h.share_signature("w1", "share-2", "done2", "m")
        self.svc.submit_sign_session_share("w1", "done2", "share-1", a)
        self.svc.submit_sign_session_share("w1", "done2", "share-2", b)
        _, rot = self.svc.create_share_rotation("w1", "rot-1")
        self.svc.activate_share_rotation("w1", "rot-1")
        with self.assertRaises(ServiceError) as ctx:
            self.svc.submit_sign_session_share(
                "w1", "done2", "share-1", "00" * 64
            )
        self.assertEqual(ctx.exception.status, 409)


class SignSessionCorruptionTest(unittest.TestCase):
    def _session_file(self, d, wallet_id):
        return os.path.join(d, "sign-sessions", wallet_id + ".json")

    def test_corrupt_session_file_operations_raise_corrupt(self):
        d = tempfile.mkdtemp()
        h = make_harness(d)
        h.service.create_wallet("w1", 2)
        h.service.create_sign_session("w1", "s1", "m", 60)
        with open(self._session_file(d, "w1"), "w") as f:
            f.write("{broken json")
        # 同进程读路径 fail-closed：heal 把损坏文件对账为 RecoveryError
        with self.assertRaises((CorruptDataError, RecoveryError)):
            h.service.get_sign_session("w1", "s1")
        a = h.share_signature("w1", "share-1", "s1", "m")
        with self.assertRaises((CorruptDataError, RecoveryError)):
            h.service.submit_sign_session_share("w1", "s1", "share-1", a)

    def test_startup_recovery_refuses_on_corrupt_session_file(self):
        d = tempfile.mkdtemp()
        h = make_harness(d)
        h.service.create_wallet("w1", 2)
        h.service.create_sign_session("w1", "s1", "m", 60)
        with open(self._session_file(d, "w1"), "w") as f:
            f.write("{broken json")
        with self.assertRaises(RecoveryError):
            make_harness(d)
        # 现场保留
        with open(self._session_file(d, "w1")) as f:
            self.assertEqual(f.read(), "{broken json")


class SignSessionStrictRecoveryTest(unittest.TestCase):
    """严格加载：UTC 时间、事件动作顺序、已收份额集合、逐份公钥重验与
    signed 聚合重算一致；JSON 可解析但语义矛盾的现场原样保留、拒绝就绪。"""

    def _sessions_path(self, d):
        return os.path.join(d, "sign-sessions", "w1.json")

    def _audit_path(self, d):
        return os.path.join(d, "audit", "w1.json")

    def _one_share_scene(self):
        d = tempfile.mkdtemp()
        h = make_harness(d)
        h.service.create_wallet("w1", 2)
        h.service.create_sign_session("w1", "s1", "m", 600)
        sig = h.share_signature("w1", "share-1", "s1", "m")
        h.service.submit_sign_session_share("w1", "s1", "share-1", sig)
        return d, h, sig

    def _tamper_sessions(self, d, mutate):
        path = self._sessions_path(d)
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        mutate(data)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f)

    def _assert_refuses_ready(self, d, label):
        with self.assertRaises(RecoveryError, msg=label):
            make_harness(d)
        # 现场原样保留，不归一、不覆盖
        self.assertTrue(os.path.exists(self._sessions_path(d)), label)

    def test_bad_expires_at_refuses(self):
        d, _, _ = self._one_share_scene()
        self._tamper_sessions(
            d, lambda data: data["s1"].__setitem__("expires_at", "nonsense")
        )
        self._assert_refuses_ready(d, "unparseable expires_at")

    def test_naive_expires_at_refuses(self):
        d, _, _ = self._one_share_scene()
        self._tamper_sessions(
            d, lambda data: data["s1"].__setitem__(
                "expires_at", "2026-09-22T00:00:00"
            )
        )
        self._assert_refuses_ready(d, "naive expires_at")

    def test_non_utc_offset_expires_at_refuses(self):
        d, _, _ = self._one_share_scene()
        self._tamper_sessions(
            d, lambda data: data["s1"].__setitem__(
                "expires_at", "2026-09-22T03:00:00+03:00"
            )
        )
        self._assert_refuses_ready(d, "non-UTC offset expires_at")

    def test_forged_stored_signature_refuses(self):
        d, _, _ = self._one_share_scene()
        self._tamper_sessions(
            d,
            lambda data: data["s1"]["shares"][0].__setitem__(
                "signature", "00" * 64
            ),
        )
        self._assert_refuses_ready(d, "forged stored signature")

    def test_committed_share_without_storage_refuses(self):
        d, _, _ = self._one_share_scene()
        # 有 share_received 事件，却删掉已存份额（无轮换可解释）
        self._tamper_sessions(
            d, lambda data: data["s1"].__setitem__("shares", [])
        )
        self._assert_refuses_ready(d, "event without stored share")

    def test_signed_aggregate_mismatch_refuses(self):
        d = tempfile.mkdtemp()
        h = make_harness(d)
        h.service.create_wallet("w1", 2)
        h.service.create_sign_session("w1", "s1", "m", 600)
        for sid in ("share-1", "share-2"):
            h.service.submit_sign_session_share(
                "w1", "s1", sid,
                h.share_signature("w1", sid, "s1", "m"),
            )
        self._tamper_sessions(
            d, lambda data: data["s1"].__setitem__(
                "aggregate_signature", "ab" * 128
            )
        )
        self._assert_refuses_ready(d, "aggregate mismatch")

    def test_event_after_terminal_refuses(self):
        d = tempfile.mkdtemp()
        h = make_harness(d)
        h.service.create_wallet("w1", 2)
        h.service.create_sign_session("w1", "s1", "m", 1)
        time.sleep(1.1)
        h.service.get_sign_session("w1", "s1")  # expired
        with open(self._audit_path(d), encoding="utf-8") as f:
            audit = json.load(f)
        extra = dict(audit["events"][-1])
        extra["seq"] = audit["next_seq"]
        extra["details"] = {
            "action": "share_received",
            "share_id": "share-1",
            "state": "collecting",
        }
        audit["events"].append(extra)
        audit["next_seq"] += 1
        with open(self._audit_path(d), "w", encoding="utf-8") as f:
            json.dump(audit, f)
        self._assert_refuses_ready(d, "action after terminal")

    def test_duplicate_share_received_event_refuses(self):
        d, _, _ = self._one_share_scene()
        with open(self._audit_path(d), encoding="utf-8") as f:
            audit = json.load(f)
        src = next(
            e for e in audit["events"]
            if isinstance(e.get("details"), dict)
            and e["details"].get("action") == "share_received"
        )
        extra = dict(src)
        extra["seq"] = audit["next_seq"]
        audit["events"].append(extra)
        audit["next_seq"] += 1
        with open(self._audit_path(d), "w", encoding="utf-8") as f:
            json.dump(audit, f)
        self._assert_refuses_ready(d, "duplicate share_received")

    def test_created_event_without_record_refuses(self):
        # 文件存在但被清空成 {}，而审计里留有 created 事件：JSON 可解析、
        # 事件与记录矛盾，原样保留并拒绝就绪（区别于“文件不存在”的空状态）。
        d, _, _ = self._one_share_scene()
        with open(self._sessions_path(d), "w", encoding="utf-8") as f:
            json.dump({}, f)
        self._assert_refuses_ready(d, "created event without record")

    def test_missing_session_file_is_normal_empty_state(self):
        # 文件整体缺失即正常空状态（创建回滚正是删除文件）：不读审计、
        # 不阻止就绪，未知会话 404。
        d, h, _ = self._one_share_scene()
        os.unlink(self._sessions_path(d))
        h2 = make_harness(d)
        with self.assertRaises(ServiceError) as ctx:
            h2.service.get_sign_session("w1", "s1")
        self.assertEqual(ctx.exception.status, 404)

    def test_stored_share_without_event_is_rolled_back(self):
        # 崩溃窗口：份额落盘、share_received 事件未落 -> 重启剔除该份额
        d, h, sig = self._one_share_scene()
        with open(self._audit_path(d), encoding="utf-8") as f:
            audit = json.load(f)
        audit["events"] = [
            e for e in audit["events"]
            if not (
                isinstance(e.get("details"), dict)
                and e["details"].get("action") == "share_received"
            )
        ]
        for i, event in enumerate(audit["events"], 1):
            event["seq"] = i
        audit["next_seq"] = len(audit["events"]) + 1
        with open(self._audit_path(d), "w", encoding="utf-8") as f:
            json.dump(audit, f)
        h2 = make_harness(d)
        view = h2.service.get_sign_session("w1", "s1")
        self.assertEqual(view["state"], "collecting")
        self.assertEqual(view["received_shares"], [])
        # 该份额可再次首收 201（无孤立状态）
        code, _ = h2.service.submit_sign_session_share(
            "w1", "s1", "share-1", sig
        )
        self.assertEqual(code, 201)

    def test_signed_event_forward_rolls_ready_record(self):
        # signed 事件在、记录退回 ready（聚合状态丢失）-> 前滚 signed 重算
        d = tempfile.mkdtemp()
        h = make_harness(d)
        h.service.create_wallet("w1", 2)
        h.service.create_sign_session("w1", "s1", "m", 600)
        for sid in ("share-1", "share-2"):
            h.service.submit_sign_session_share(
                "w1", "s1", sid,
                h.share_signature("w1", sid, "s1", "m"),
            )
        signed = h.service.get_sign_session("w1", "s1")
        self._tamper_sessions(
            d,
            lambda data: (
                data["s1"].__setitem__("state", "ready"),
                data["s1"].pop("aggregate_signature", None),
            ),
        )
        h2 = make_harness(d)
        view = h2.service.get_sign_session("w1", "s1")
        self.assertEqual(view["state"], "signed")
        self.assertEqual(
            view["aggregate_signature"], signed["aggregate_signature"]
        )

    def test_recovered_sessions_have_continuous_seq(self):
        # 多次恢复不产生重复事件或 seq 缺口
        d, _, _ = self._one_share_scene()
        for _ in range(3):
            make_harness(d).service.get_sign_session("w1", "s1")
        h = make_harness(d)
        seqs = [e["seq"] for e in h.service.get_audit_events("w1")["events"]]
        self.assertEqual(seqs, list(range(1, len(seqs) + 1)))


class SignSessionHttpTest(unittest.TestCase):
    def test_http_status_codes_and_503_corruption(self):
        with http_server(tempfile.mkdtemp()) as srv:
            s, _ = srv.request(
                "POST", "/v1/wallets", {"wallet_id": "w1", "shares": 2}
            )
            self.assertEqual(s, 201)
            s, b = srv.request(
                "POST",
                "/v1/wallets/w1/sign-sessions",
                {"id": "s1", "message": "hi", "timeout_seconds": 60},
            )
            self.assertEqual(s, 201)
            self.assertEqual(b["state"], "collecting")
            # 重放 200
            s, _ = srv.request(
                "POST",
                "/v1/wallets/w1/sign-sessions",
                {"id": "s1", "message": "hi", "timeout_seconds": 60},
            )
            self.assertEqual(s, 200)
            # 异参 409
            s, _ = srv.request(
                "POST",
                "/v1/wallets/w1/sign-sessions",
                {"id": "s1", "message": "xx", "timeout_seconds": 60},
            )
            self.assertEqual(s, 409)
            # 非法 400
            s, _ = srv.request(
                "POST",
                "/v1/wallets/w1/sign-sessions",
                {"id": "s2", "message": "hi", "timeout_seconds": -1},
            )
            self.assertEqual(s, 400)
            # 钱包 404
            s, _ = srv.request(
                "POST",
                "/v1/wallets/nope/sign-sessions",
                {"id": "s1", "message": "hi", "timeout_seconds": 60},
            )
            self.assertEqual(s, 404)
            # 未知会话 GET 404
            s, _ = srv.request("GET", "/v1/wallets/w1/sign-sessions/ghost")
            self.assertEqual(s, 404)

            h = srv.harness
            a = h.share_signature("w1", "share-1", "s1", "hi")
            c = h.share_signature("w1", "share-2", "s1", "hi")
            s, b = srv.request(
                "POST",
                "/v1/wallets/w1/sign-sessions/s1/shares",
                {"share_id": "share-1", "signature": a},
            )
            self.assertEqual(s, 201)
            s, b = srv.request(
                "POST",
                "/v1/wallets/w1/sign-sessions/s1/shares",
                {"share_id": "share-1", "signature": a},
            )
            self.assertEqual(s, 200)
            s, _ = srv.request(
                "POST",
                "/v1/wallets/w1/sign-sessions/s1/shares",
                {"share_id": "share-1", "signature": "00" * 64},
            )
            self.assertEqual(s, 409)
            s, _ = srv.request(
                "POST",
                "/v1/wallets/w1/sign-sessions/s1/shares",
                {"share_id": "share-2", "signature": "00" * 64},
            )
            self.assertEqual(s, 400)
            s, b = srv.request(
                "POST",
                "/v1/wallets/w1/sign-sessions/s1/shares",
                {"share_id": "share-2", "signature": c},
            )
            self.assertEqual(s, 201)
            self.assertEqual(b["state"], "signed")
            s, b = srv.request("GET", "/v1/wallets/w1/sign-sessions/s1")
            self.assertEqual(s, 200)
            self.assertIn("aggregate_signature", b)

            # 损坏 -> 统一 503 泛化文案
            path = os.path.join(
                h.tmpdir, "sign-sessions", "w1.json"
            )
            with open(path, "w") as f:
                f.write("{broken")
            s, b = srv.request("GET", "/v1/wallets/w1/sign-sessions/s1")
            self.assertEqual(s, 503)
            self.assertEqual(b, {"error": "service temporarily unavailable"})

    def test_responses_files_and_logs_contain_no_private_key(self):
        with http_server(tempfile.mkdtemp()) as srv:
            srv.request(
                "POST", "/v1/wallets", {"wallet_id": "w-audit", "shares": 2}
            )
            marker = "SESSION-SECRET-Q7KX-MARKER"
            s, b = srv.request(
                "POST",
                "/v1/wallets/w-audit/sign-sessions",
                {"id": "s1", "message": marker, "timeout_seconds": 60},
            )
            self.assertEqual(s, 201)
            a = srv.harness.share_signature(
                "w-audit", "share-1", "s1", marker
            )
            c = srv.harness.share_signature(
                "w-audit", "share-2", "s1", marker
            )
            srv.request(
                "POST",
                "/v1/wallets/w-audit/sign-sessions/s1/shares",
                {"share_id": "share-1", "signature": a},
            )
            s, b = srv.request(
                "POST",
                "/v1/wallets/w-audit/sign-sessions/s1/shares",
                {"share_id": "share-2", "signature": c},
            )
            self.assertEqual(s, 201)
            # 响应只回聚合签名（本就是两份份额签名的有序拼接），不含任何
            # 份额私钥；份额签名只作为聚合签名的两半出现。
            priv1 = srv.harness.share_private_hex("w-audit", "share-1")
            priv2 = srv.harness.share_private_hex("w-audit", "share-2")
            self.assertNotIn(priv1, json.dumps(b))
            self.assertNotIn(priv2, json.dumps(b))
            for base, _, files in os.walk(srv.harness.tmpdir):
                for name in files:
                    with open(os.path.join(base, name), "rb") as f:
                        raw = f.read()
                    self.assertNotIn((priv1 + priv2).encode(), raw, name)
                    self.assertNotIn((priv2 + priv1).encode(), raw, name)
                    # 任何文件都不含份额私钥 hex 之外的私钥汇集；会话文件
                    # 只能出现份额签名，不能出现份额私钥
                    if "sign-sessions" in base:
                        self.assertNotIn(priv1.encode(), raw, name)
                        self.assertNotIn(priv2.encode(), raw, name)
            # 日志不含 message、份额签名或私钥
            logs = "\n".join(srv.logs)
            self.assertNotIn(marker, logs)
            self.assertNotIn(a, logs)
            self.assertNotIn(c, logs)
            self.assertNotIn(priv1, logs)
            self.assertNotIn(priv2, logs)


if __name__ == "__main__":
    unittest.main()
