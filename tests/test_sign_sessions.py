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
        # ready 在到期前一直保留（批准后重放第二份即可继续聚合）
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

    # ---- ready 会话过期 -------------------------------------------------

    def _open_ready(self, sid="r1", message="m", timeout=600):
        """创建一个被门控拦在 ready 的会话（两份已收、未聚合）。"""
        self.svc.put_policy("w1", 1, 3600)
        self._open(sid=sid, message=message, timeout=timeout)
        sigs = self._sigs(sid, message)
        self.svc.submit_sign_session_share("w1", sid, "share-1", sigs["share-1"])
        code, view = self.svc.submit_sign_session_share(
            "w1", sid, "share-2", sigs["share-2"]
        )
        self.assertEqual(code, 409)
        self.assertEqual(view["state"], "ready")
        return sigs

    def test_ready_session_lazy_expires_on_get(self):
        self._open_ready(timeout=1)
        time.sleep(1.1)
        view = self.svc.get_sign_session("w1", "r1")
        self.assertEqual(view["state"], "expired")
        # 已收两份原样保留，但终态无聚合签名
        self.assertEqual(view["received_shares"], ["share-1", "share-2"])
        self.assertEqual(view["missing_shares"], [])
        self.assertNotIn("aggregate_signature", view)
        # 再次查询不再重复记事件
        self.svc.get_sign_session("w1", "r1")
        actions = [
            e["details"]["action"] for e in _session_events(self.svc, "w1")
        ]
        self.assertEqual(
            actions,
            ["created", "share_received", "share_received", "expired"],
        )

    def test_ready_session_delivery_at_expiry_is_409(self):
        sigs = self._open_ready(timeout=1)
        time.sleep(1.1)
        # 投递到点：原子转 expired 并记一次事件，投递 409
        with self.assertRaises(ServiceError) as ctx:
            self.svc.submit_sign_session_share(
                "w1", "r1", "share-1", sigs["share-1"]
            )
        self.assertEqual(ctx.exception.status, 409)
        self.assertEqual(
            self.svc.get_sign_session("w1", "r1")["state"], "expired"
        )
        actions = [
            e["details"]["action"] for e in _session_events(self.svc, "w1")
        ]
        self.assertEqual(actions.count("expired"), 1)
        # 终态不再聚合：补审批后重放仍 409
        self.svc.create_sign_request("w1", "r1", "m")
        self.svc.approve("w1", "r1", "ops-1")
        with self.assertRaises(ServiceError) as ctx:
            self.svc.submit_sign_session_share(
                "w1", "r1", "share-2", sigs["share-2"]
            )
        self.assertEqual(ctx.exception.status, 409)
        self.assertEqual(
            self.svc.get_sign_session("w1", "r1")["state"], "expired"
        )

    def test_ready_expired_persists_across_restart(self):
        self._open_ready(timeout=1)
        time.sleep(1.1)
        self.svc.get_sign_session("w1", "r1")  # 懒过期落盘
        h2 = make_harness(self.d)
        view = h2.service.get_sign_session("w1", "r1")
        self.assertEqual(view["state"], "expired")
        self.assertEqual(view["received_shares"], ["share-1", "share-2"])
        actions = [
            e["details"]["action"]
            for e in h2.service.get_audit_events("w1")["events"]
            if e["type"] == "session_event"
        ]
        self.assertEqual(actions.count("expired"), 1)

    # ---- 份额轮换兼容（补充） --------------------------------------------

    def test_rotation_ready_session_switches_to_new_shares(self):
        sigs = self._open_ready(sid="rot1", message="m")
        _, rot = self.svc.create_share_rotation("w1", "rot-1")
        self.assertEqual(
            self.svc.activate_share_rotation("w1", "rot-1")[0], 201
        )
        new_ids = rot["share_ids"]
        # ready 掉回 collecting：已收旧份额剔除，视图同步为当前在用份额
        view = self.svc.get_sign_session("w1", "rot1")
        self.assertEqual(view["state"], "collecting")
        self.assertEqual(view["received_shares"], [])
        self.assertEqual(view["missing_shares"], list(new_ids))
        # 失效旧份额投递 400（同值重放也不再接受）
        with self.assertRaises(ServiceError) as ctx:
            self.svc.submit_sign_session_share(
                "w1", "rot1", "share-1", sigs["share-1"]
            )
        self.assertEqual(ctx.exception.status, 400)
        # 新份额继续投递并完成
        self.svc.create_sign_request("w1", "rot1", "m")
        self.svc.approve("w1", "rot1", "ops-1")
        x = self.h.share_signature("w1", new_ids[0], "rot1", "m")
        y = self.h.share_signature("w1", new_ids[1], "rot1", "m")
        code, view = self.svc.submit_sign_session_share(
            "w1", "rot1", new_ids[0], x
        )
        self.assertEqual(code, 201)
        self.assertEqual(view["received_shares"], [new_ids[0]])
        code, view = self.svc.submit_sign_session_share(
            "w1", "rot1", new_ids[1], y
        )
        self.assertEqual(code, 201)
        self.assertEqual(view["state"], "signed")
        # 重启后 signed 重放 200 同体（恢复用历代公钥重验签名）
        h2 = make_harness(self.d)
        code, replay = h2.service.submit_sign_session_share(
            "w1", "rot1", new_ids[0], x
        )
        self.assertEqual(code, 200)
        self.assertEqual(replay, view)

    def test_signed_session_replay_after_rotation_and_restart(self):
        self._open(sid="done1", message="m")
        sigs = self._sigs("done1", "m")
        self.svc.submit_sign_session_share(
            "w1", "done1", "share-1", sigs["share-1"]
        )
        _, signed = self.svc.submit_sign_session_share(
            "w1", "done1", "share-2", sigs["share-2"]
        )
        _, rot = self.svc.create_share_rotation("w1", "rot-1")
        self.assertEqual(
            self.svc.activate_share_rotation("w1", "rot-1")[0], 201
        )
        # 重启：恢复须用轮换前公钥重验 signed 会话的两份旧份额签名
        h2 = make_harness(self.d)
        # signed 会话保留原份额快照与聚合结果：同值重放 200 同体
        code, view = h2.service.submit_sign_session_share(
            "w1", "done1", "share-1", sigs["share-1"]
        )
        self.assertEqual(code, 200)
        self.assertEqual(view, signed)
        # 异值 409
        with self.assertRaises(ServiceError) as ctx:
            h2.service.submit_sign_session_share(
                "w1", "done1", "share-1", "00" * 64
            )
        self.assertEqual(ctx.exception.status, 409)


    # ---- 份额轮换兼容 ---------------------------------------------------

    def test_rotation_signed_replay_survives_old_share_rejected(self):
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

        # 已 signed 的会话用旧份额重放仍 200 同体
        code, view = self.svc.submit_sign_session_share(
            "w1", "done1", "share-1", a
        )
        self.assertEqual(code, 200)
        self.assertEqual(view, signed)
        # 在途会话：轮换激活后剔除已收旧份额，视图同步为当前在用份额
        view = self.svc.get_sign_session("w1", "infl1")
        self.assertEqual(view["state"], "collecting")
        self.assertEqual(view["received_shares"], [])
        self.assertEqual(view["missing_shares"], list(new_ids))
        # 失效旧份额投递 400
        with self.assertRaises(ServiceError) as ctx:
            self.svc.submit_sign_session_share(
                "w1", "infl1", "share-2", b_old
            )
        self.assertEqual(ctx.exception.status, 400)
        # 新份额可继续投递并完成在途会话
        x = self.h.share_signature("w1", new_ids[0], "infl1", "m")
        b_new = self.h.share_signature("w1", new_ids[1], "infl1", "m")
        code, view = self.svc.submit_sign_session_share(
            "w1", "infl1", new_ids[0], x
        )
        self.assertEqual(code, 201)
        self.assertEqual(view["received_shares"], [new_ids[0]])
        code, view = self.svc.submit_sign_session_share(
            "w1", "infl1", new_ids[1], b_new
        )
        self.assertEqual(code, 201)
        self.assertEqual(view["state"], "signed")
        # 轮换后的新会话用新份额正常聚合
        self._open(sid="after1", message="m")
        x = self.h.share_signature("w1", new_ids[0], "after1", "m")
        y = self.h.share_signature("w1", new_ids[1], "after1", "m")
        self.svc.submit_sign_session_share("w1", "after1", new_ids[0], x)
        code, view = self.svc.submit_sign_session_share(
            "w1", "after1", new_ids[1], y
        )
        self.assertEqual(code, 201)
        self.assertEqual(view["state"], "signed")


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
    """持久化加载的严格校验：JSON 可解析但时间/事件/份额/聚合矛盾的
    现场一律 fail-closed（启动恢复拒绝就绪、常驻请求 503），现场原样保留。"""

    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.h = make_harness(self.d)
        self.svc = self.h.service
        self.svc.create_wallet("w1", 2)
        self.svc.create_sign_session("w1", "s1", "m", 600)
        self.sig1 = self.h.share_signature("w1", "share-1", "s1", "m")
        self.svc.submit_sign_session_share("w1", "s1", "share-1", self.sig1)

    def _session_file(self):
        return os.path.join(self.d, "sign-sessions", "w1.json")

    def _audit_file(self):
        return os.path.join(self.d, "audit", "w1.json")

    def _read(self, path):
        with open(path) as f:
            return json.load(f)

    def _write(self, path, data):
        with open(path, "w") as f:
            json.dump(data, f)

    def _tamper_session(self, mutate):
        path = self._session_file()
        data = self._read(path)
        mutate(data["s1"])
        self._write(path, data)

    def _tamper_audit(self, mutate):
        path = self._audit_file()
        data = self._read(path)
        mutate(data["events"])
        self._write(path, data)

    def _assert_fails_closed_and_preserved(self, path):
        raw = self._read(path)
        # 启动恢复拒绝就绪
        with self.assertRaises(RecoveryError):
            make_harness(self.d)
        # 常驻请求同样 fail-closed（同进程持锁访问）
        with self.assertRaises((CorruptDataError, RecoveryError)):
            self.svc.get_sign_session("w1", "s1")
        # 现场原样保留
        self.assertEqual(self._read(path), raw)

    # ---- 时间矛盾 -------------------------------------------------------

    def test_unparseable_expires_at_fails_closed(self):
        self._tamper_session(lambda r: r.update(expires_at="not-a-time"))
        self._assert_fails_closed_and_preserved(self._session_file())

    def test_non_utc_expires_at_fails_closed(self):
        self._tamper_session(
            lambda r: r.update(expires_at="2026-09-22T00:00:00+08:00")
        )
        self._assert_fails_closed_and_preserved(self._session_file())

    def test_naive_expires_at_fails_closed(self):
        self._tamper_session(
            lambda r: r.update(expires_at="2026-09-22T00:00:00")
        )
        self._assert_fails_closed_and_preserved(self._session_file())

    # ---- 事件顺序矛盾 ---------------------------------------------------

    def test_share_received_before_created_fails_closed(self):
        def mutate(events):
            events[0]["seq"], events[1]["seq"] = 2, 1

        self._tamper_audit(mutate)
        self._assert_fails_closed_and_preserved(self._audit_file())

    def test_duplicate_share_received_event_fails_closed(self):
        def mutate(events):
            events.append(dict(events[1], seq=3))

        self._tamper_audit(mutate)
        self._assert_fails_closed_and_preserved(self._audit_file())

    def test_event_after_terminal_fails_closed(self):
        sig2 = self.h.share_signature("w1", "share-2", "s1", "m")
        self.svc.submit_sign_session_share("w1", "s1", "share-2", sig2)

        def mutate(events):
            events.append(
                {
                    "seq": 5,
                    "type": "session_event",
                    "at": "2026-09-22T00:00:00Z",
                    "request_id": "s1",
                    "actor_id": None,
                    "reason": None,
                    "details": {
                        "action": "share_received",
                        "share_id": "share-9",
                        "state": "collecting",
                    },
                }
            )

        self._tamper_audit(mutate)
        self._assert_fails_closed_and_preserved(self._audit_file())

    def test_unknown_action_fails_closed(self):
        def mutate(events):
            events[1]["details"]["action"] = "tampered"

        self._tamper_audit(mutate)
        self._assert_fails_closed_and_preserved(self._audit_file())

    # ---- 份额与聚合矛盾 -------------------------------------------------

    def test_tampered_stored_signature_fails_closed(self):
        def mutate(record):
            sig = record["shares"][0]["signature"]
            record["shares"][0]["signature"] = (
                "00" if sig[:2] != "00" else "01"
            ) + sig[2:]

        self._tamper_session(mutate)
        self._assert_fails_closed_and_preserved(self._session_file())

    def test_committed_share_without_stored_signature_fails_closed(self):
        self._tamper_session(lambda r: r.update(shares=[]))
        self._assert_fails_closed_and_preserved(self._session_file())

    def test_tampered_aggregate_fails_closed(self):
        sig2 = self.h.share_signature("w1", "share-2", "s1", "m")
        self.svc.submit_sign_session_share("w1", "s1", "share-2", sig2)

        def mutate(record):
            agg = record["aggregate_signature"]
            record["aggregate_signature"] = (
                "00" if agg[:2] != "00" else "01"
            ) + agg[2:]

        self._tamper_session(mutate)
        self._assert_fails_closed_and_preserved(self._session_file())

    # ---- 崩溃残留仍可确定回滚（非矛盾） ---------------------------------

    def test_crash_remnant_share_without_event_rolls_back(self):
        # 份额落盘但 share_received 事件未落盘：回滚为未收该份额
        self._tamper_audit(
            lambda events: events.__setitem__(
                slice(None),
                [
                    e
                    for e in events
                    if e["details"].get("action") != "share_received"
                ],
            )
        )
        h2 = make_harness(self.d)
        view = h2.service.get_sign_session("w1", "s1")
        self.assertEqual(view["state"], "collecting")
        self.assertEqual(view["received_shares"], [])

    def test_crash_remnant_expired_without_event_rolls_back(self):
        # expired 落盘但 expired 事件未落盘：回滚为 collecting，到点后由
        # 下一次访问重新懒过期，且全程只记一次 expired 事件
        self._tamper_session(lambda r: r.update(state="expired"))
        h2 = make_harness(self.d)
        view = h2.service.get_sign_session("w1", "s1")
        self.assertEqual(view["state"], "collecting")
        self.assertEqual(view["received_shares"], ["share-1"])
        # 到点后重新懒过期，只记一次事件
        self._tamper_session(
            lambda r: r.update(expires_at="2000-01-01T00:00:00Z")
        )
        view = h2.service.get_sign_session("w1", "s1")
        self.assertEqual(view["state"], "expired")
        actions = [
            e["details"]["action"]
            for e in h2.service.get_audit_events("w1")["events"]
            if e["type"] == "session_event"
        ]
        self.assertEqual(actions.count("expired"), 1)

    def test_crash_remnant_signed_without_event_rolls_back_to_ready(self):
        # signed+aggregate 落盘但 signed 事件未落盘：回滚为 ready 可重试，
        # 重试聚合成功后只记一次 signed 事件
        sig2 = self.h.share_signature("w1", "share-2", "s1", "m")
        self.svc.submit_sign_session_share("w1", "s1", "share-2", sig2)
        self._tamper_audit(
            lambda events: events.__setitem__(
                slice(None),
                [
                    e
                    for e in events
                    if e["details"].get("action") != "signed"
                ],
            )
        )
        h2 = make_harness(self.d)
        view = h2.service.get_sign_session("w1", "s1")
        self.assertEqual(view["state"], "ready")
        self.assertNotIn("aggregate_signature", view)
        code, view = h2.service.submit_sign_session_share(
            "w1", "s1", "share-2", sig2
        )
        self.assertEqual(code, 200)
        self.assertEqual(view["state"], "signed")
        actions = [
            e["details"]["action"]
            for e in h2.service.get_audit_events("w1")["events"]
            if e["type"] == "session_event"
        ]
        self.assertEqual(actions.count("signed"), 1)
        self.assertEqual(
            actions, ["created", "share_received", "share_received", "signed"]
        )

    def test_http_requests_are_503_on_contradictory_scene(self):
        with http_server(self.d) as srv:
            self._tamper_session(lambda r: r.update(expires_at="bad"))
            for method, path, body in [
                ("GET", "/v1/wallets/w1/sign-sessions/s1", None),
                (
                    "POST",
                    "/v1/wallets/w1/sign-sessions/s1/shares",
                    {"share_id": "share-2", "signature": "00" * 64},
                ),
                (
                    "POST",
                    "/v1/wallets/w1/sign-sessions",
                    {"id": "s2", "message": "m", "timeout_seconds": 60},
                ),
            ]:
                status, resp_body = srv.request(method, path, body)
                self.assertEqual(status, 503, (method, path))
                self.assertEqual(
                    resp_body, {"error": "service temporarily unavailable"}
                )


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
