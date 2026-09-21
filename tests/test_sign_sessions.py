"""可恢复签名会话（sign-sessions）端到端与单元测试。

覆盖任务契约：
- POST /v1/wallets/{w}/sign-sessions：非法 400、钱包 404、首建 201、
  同参重放 200、异参 409；
- 视图含原文、collecting|ready|signed|expired 状态、已收/缺失份额、
  到期时间，聚合签名仅 signed 时存在；
- GET .../sign-sessions/{id}：200/未知 404，查询或投递时懒过期；
- POST .../sign-sessions/{id}/shares：仅在用份额对 id||message 直接拼接
  载荷的有效 Ed25519 签名；首收 201、同份额同值 200、异值 409、非法 400、
  expired 409；两份齐备转 ready 后按既有审批/hot-cold 门控聚合，门控失败
  409 且保留 ready 可重试，成功转 signed 后重放 200 同体；
- session_event 七字段、连续 seq、details 以 action 区分且不含签名、
  重放不记；
- 钱包跨进程锁内持久化、重启续作、并发仅一个首次聚合；
- 损坏状态 503 并保留现场 / 启动恢复阻止就绪；
- 文件、响应、日志均不含私钥；轮换兼容。
"""

from __future__ import annotations

import json
import multiprocessing
import os
import shutil
import tempfile
import threading
import time
import unittest

from tests.helpers import http_server
from threshold_wallet import crypto
from threshold_wallet.service import WalletService
from threshold_wallet.store import CorruptDataError, RecoveryError, WalletStore


def _sessions_path(tmp: str, wallet: str = "w1") -> str:
    return os.path.join(tmp, "sign-sessions", wallet + ".json")


def _write(path: str, payload: str) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(payload)


def _local_share_hex(tmp: str, wallet: str, share_id: str,
                     sess: str, message: str) -> str:
    store = WalletStore(tmp)
    share = store.get_share(wallet, share_id)
    return crypto.sign_share(
        bytes.fromhex(share["private_key"]),
        crypto.build_payload(sess, message),
    ).hex()


def _child_deliver(data_dir, share_id, sess, message, barrier, queue):
    """跨进程 worker：各自构造独立 WalletService（进程内锁不共享），在
    屏障释放后并发投递同一份额，依赖 fcntl.flock 串行化首次聚合。"""
    try:
        svc = WalletService(WalletStore(data_dir))
        signature = _local_share_hex(data_dir, "w1", share_id, sess, message)
        barrier.wait()
        status, body = svc.deliver_session_share(
            "w1", sess, share_id, signature
        )
        queue.put((status, body.get("state"), body.get("signature")))
    except Exception as exc:  # 不应有未预期异常
        queue.put(("ERR", repr(exc), None))


class SignSessionHttpTest(unittest.TestCase):
    def setUp(self):
        self._ctx = http_server(tempfile.mkdtemp())
        self.srv = self._ctx.__enter__()
        self.tmp = self.srv.harness.tmpdir
        self.srv.request(
            "POST", "/v1/wallets", {"wallet_id": "w1", "shares": 2}
        )
        self.S = "/v1/wallets/w1/sign-sessions"

    def tearDown(self):
        self._ctx.__exit__(None, None, None)

    def _create(self, sid="s1", message="pay-100", timeout=60):
        return self.srv.request(
            "POST",
            self.S,
            {"id": sid, "message": message, "timeout_seconds": timeout},
        )

    def _share(self, sid, sess="s1", message="pay-100", wallet="w1"):
        return self.srv.harness.share_signature(wallet, sid, sess, message)

    def _deliver(self, share_id, signature, sess="s1"):
        return self.srv.request(
            "POST",
            f"{self.S}/{sess}/shares",
            {"share_id": share_id, "signature": signature},
        )

    # ---- 创建 -----------------------------------------------------------

    def test_create_201_view_shape(self):
        status, body = self._create()
        self.assertEqual(status, 201, body)
        self.assertEqual(body["id"], "s1")
        self.assertEqual(body["message"], "pay-100")
        self.assertEqual(body["state"], "collecting")
        self.assertEqual(body["received_shares"], [])
        self.assertEqual(body["missing_shares"], ["share-1", "share-2"])
        self.assertTrue(body["expires_at"].endswith("Z") or "+" in body["expires_at"])
        self.assertNotIn("signature", body)

    def test_wallet_not_found_is_404(self):
        status, body = self.srv.request(
            "POST",
            "/v1/wallets/ghost/sign-sessions",
            {"id": "s1", "message": "m", "timeout_seconds": 5},
        )
        self.assertEqual(status, 404)
        self.assertIn("error", body)

    def test_invalid_bodies_are_400(self):
        bad = [
            {"id": "", "message": "m", "timeout_seconds": 5},
            {"id": "   ", "message": "m", "timeout_seconds": 5},
            {"id": "bad id", "message": "m", "timeout_seconds": 5},
            {"id": 123, "message": "m", "timeout_seconds": 5},
            {"id": "s", "message": "", "timeout_seconds": 5},
            {"id": "s", "message": "   ", "timeout_seconds": 5},
            {"id": "s", "message": 4, "timeout_seconds": 5},
            {"id": "s", "message": "m", "timeout_seconds": 0},
            {"id": "s", "message": "m", "timeout_seconds": -1},
            {"id": "s", "message": "m", "timeout_seconds": 1.5},
            {"id": "s", "message": "m", "timeout_seconds": True},
            {"id": "s", "message": "m"},
            {"id": "s", "timeout_seconds": 5},
        ]
        for body in bad:
            with self.subTest(body=body):
                status, resp = self.srv.request("POST", self.S, body)
                self.assertEqual(status, 400, body)

    def test_same_params_replay_200_no_event(self):
        self.assertEqual(self._create()[0], 201)
        status, body = self._create()
        self.assertEqual(status, 200)
        self.assertEqual(body["state"], "collecting")
        ev = self.srv.request("GET", "/v1/wallets/w1/audit-events")[1]["events"]
        self.assertEqual(
            [e["details"].get("action") for e in ev if e["type"] == "session_event"],
            ["created"],
        )

    def test_different_message_is_409(self):
        self._create()
        status, body = self._create(message="other")
        self.assertEqual(status, 409)
        self.assertIn("error", body)

    def test_different_timeout_is_409(self):
        self._create(timeout=60)
        status, _ = self._create(timeout=120)
        self.assertEqual(status, 409)

    # ---- 查询 -----------------------------------------------------------

    def test_get_session(self):
        self._create()
        status, body = self.srv.request("GET", f"{self.S}/s1")
        self.assertEqual(status, 200)
        self.assertEqual(body["id"], "s1")
        self.assertEqual(body["state"], "collecting")

    def test_get_unknown_is_404(self):
        status, _ = self.srv.request("GET", f"{self.S}/ghost")
        self.assertEqual(status, 404)

    # ---- 投递份额 --------------------------------------------------------

    def test_deliver_first_share_201_collecting(self):
        self._create()
        status, body = self._deliver("share-1", self._share("share-1"))
        self.assertEqual(status, 201, body)
        self.assertEqual(body["state"], "collecting")
        self.assertEqual(body["received_shares"], ["share-1"])
        self.assertEqual(body["missing_shares"], ["share-2"])

    def test_deliver_unknown_session_404(self):
        status, _ = self._deliver("share-1", "00" * 64, sess="ghost")
        self.assertEqual(status, 404)

    def test_deliver_unknown_share_400(self):
        self._create()
        status, _ = self._deliver("share-9", self._share("share-1"))
        self.assertEqual(status, 400)

    def test_deliver_bad_signature_400(self):
        self._create()
        for sig in ("not-hex", "00", "00" * 32, "zz" * 64, 123, None):
            with self.subTest(sig=sig):
                status, _ = self._deliver("share-1", sig)
                self.assertEqual(status, 400)

    def test_signature_must_be_over_id_message_concat(self):
        self._create(message="pay-100")
        # 用不同 message 的载荷签名 -> 校验失败 400
        wrong = self._share("share-1", sess="s1", message="pay-999")
        status, _ = self._deliver("share-1", wrong)
        self.assertEqual(status, 400)
        # 用不同 id 的载荷签名 -> 校验失败 400
        wrong2 = self.srv.harness.share_signature("w1", "share-1", "other", "pay-100")
        status, _ = self._deliver("share-1", wrong2)
        self.assertEqual(status, 400)

    def test_same_share_same_value_replay_200(self):
        self._create()
        self.assertEqual(self._deliver("share-1", self._share("share-1"))[0], 201)
        status, body = self._deliver("share-1", self._share("share-1"))
        self.assertEqual(status, 200)
        self.assertEqual(body["state"], "collecting")

    def test_same_share_different_value_409(self):
        self._create()
        good = self._share("share-1")
        self.assertEqual(self._deliver("share-1", good)[0], 201)
        # 同份额再次投递"另一个值"（64 字节但翻转一个字节）：存储值冲突
        # 判定（409）先于密码学校验（400），故返回 409。
        raw = bytearray(bytes.fromhex(good))
        raw[0] ^= 0xFF
        status, body = self._deliver("share-1", bytes(raw).hex())
        self.assertEqual(status, 409)
        self.assertIn("error", body)
        # 原签名仍有效、状态不变
        view = self.srv.request("GET", f"{self.S}/s1")[1]
        self.assertEqual(view["state"], "collecting")
        self.assertEqual(view["received_shares"], ["share-1"])

    # ---- 齐备 -> 聚合 ----------------------------------------------------

    def test_both_shares_aggregate_to_signed(self):
        self._create()
        self._deliver("share-1", self._share("share-1"))
        status, body = self._deliver("share-2", self._share("share-2"))
        self.assertEqual(status, 201, body)
        self.assertEqual(body["state"], "signed")
        self.assertEqual(body["received_shares"], ["share-1", "share-2"])
        self.assertEqual(body["missing_shares"], [])
        self.assertIn("signature", body)
        self.assertEqual(len(bytes.fromhex(body["signature"])), 128)
        # 用聚合公钥独立拆半验证
        wallet = self.srv.request("GET", "/v1/wallets/w1")[1]
        pub1, pub2 = crypto.split_public_key(bytes.fromhex(wallet["public_key"]))
        s1, s2 = crypto.split_signature(bytes.fromhex(body["signature"]))
        payload = crypto.build_payload("s1", "pay-100")
        self.assertTrue(crypto.verify_share(pub1, payload, s1))
        self.assertTrue(crypto.verify_share(pub2, payload, s2))

    def test_ready_then_signed_view_has_signature_only_when_signed(self):
        self._create()
        self._deliver("share-1", self._share("share-1"))
        # 构造 ready：配置审批策略使齐备时门控失败、保留 ready
        self.srv.request(
            "PUT",
            "/v1/wallets/w1/approval-policy",
            {"required_approvals": 1, "timeout_seconds": 60},
        )
        status, body = self._deliver("share-2", self._share("share-2"))
        self.assertEqual(status, 409)
        view = self.srv.request("GET", f"{self.S}/s1")[1]
        self.assertEqual(view["state"], "ready")
        self.assertEqual(view["received_shares"], ["share-1", "share-2"])
        self.assertEqual(view["missing_shares"], [])
        self.assertNotIn("signature", view)

    def test_signed_replay_200_same_body(self):
        self._create()
        self._deliver("share-1", self._share("share-1"))
        _, signed = self._deliver("share-2", self._share("share-2"))
        for _ in range(3):
            status, body = self._deliver("share-2", self._share("share-2"))
            self.assertEqual(status, 200)
            self.assertEqual(body, signed)
        # GET 也返回同体
        status, body = self.srv.request("GET", f"{self.S}/s1")
        self.assertEqual(status, 200)
        self.assertEqual(body["signature"], signed["signature"])

    # ---- 懒过期 ----------------------------------------------------------

    def test_lazy_expiry_on_get_and_deliver(self):
        self._create(timeout=1)
        self.assertEqual(
            self.srv.request("GET", f"{self.S}/s1")[1]["state"], "collecting"
        )
        time.sleep(1.1)
        status, body = self.srv.request("GET", f"{self.S}/s1")
        self.assertEqual(status, 200)
        self.assertEqual(body["state"], "expired")
        # 过期只记一次：再查仍 expired，不重复事件
        self.srv.request("GET", f"{self.S}/s1")
        status, _ = self._deliver("share-1", self._share("share-1"))
        self.assertEqual(status, 409)
        expired_events = [
            e for e in self._events()
            if e["type"] == "session_event" and e["details"].get("action") == "expired"
        ]
        self.assertEqual(len(expired_events), 1)

    def test_ready_session_can_expire(self):
        self._create(timeout=1)
        self._deliver("share-1", self._share("share-1"))
        self.srv.request(
            "PUT",
            "/v1/wallets/w1/approval-policy",
            {"required_approvals": 1, "timeout_seconds": 60},
        )
        self._deliver("share-2", self._share("share-2"))  # 门控 409 -> ready
        time.sleep(1.1)
        view = self.srv.request("GET", f"{self.S}/s1")[1]
        self.assertEqual(view["state"], "expired")
        self.assertNotIn("signature", view)

    def _events(self):
        return self.srv.request("GET", "/v1/wallets/w1/audit-events")[1]["events"]

    # ---- 审批 / hot-cold 门控 --------------------------------------------

    def test_approval_gate_blocks_then_retry_succeeds(self):
        self.srv.request(
            "PUT",
            "/v1/wallets/w1/approval-policy",
            {"required_approvals": 1, "timeout_seconds": 60},
        )
        self._create()
        self._deliver("share-1", self._share("share-1"))
        # 齐备但未审批：409 且 ready 保留
        status, _ = self._deliver("share-2", self._share("share-2"))
        self.assertEqual(status, 409)
        self.assertEqual(
            self.srv.request("GET", f"{self.S}/s1")[1]["state"], "ready"
        )
        # 补建审批单并批准
        self.srv.request(
            "POST",
            "/v1/wallets/w1/sign-requests",
            {"id": "s1", "message": "pay-100"},
        )
        self.srv.request(
            "POST",
            "/v1/wallets/w1/sign-requests/s1/approve",
            {"approver_id": "a1"},
        )
        # 重放 share-2 -> 200 signed（ready 重试聚合）
        status, body = self._deliver("share-2", self._share("share-2"))
        self.assertEqual(status, 200)
        self.assertEqual(body["state"], "signed")
        # 审批单仅作门控：会话聚合不改写审批单状态（仍 approved）
        req = self.srv.request("GET", "/v1/wallets/w1/sign-requests/s1")[1]
        self.assertEqual(req["state"], "approved")

    def test_cold_gate_requires_approved_request(self):
        self.srv.request(
            "PUT",
            "/v1/wallets/w1/transaction-policy",
            {"mode": "cold", "max_delta": 100, "allowed_assets": ["BTC"]},
        )
        self.srv.request(
            "PUT",
            "/v1/wallets/w1/approval-policy",
            {"required_approvals": 1, "timeout_seconds": 60},
        )
        self._create()
        self._deliver("share-1", self._share("share-1"))
        status, body = self._deliver("share-2", self._share("share-2"))
        self.assertEqual(status, 409)
        self.assertEqual(
            self.srv.request("GET", f"{self.S}/s1")[1]["state"], "ready"
        )
        # 审批后成功
        self.srv.request(
            "POST", "/v1/wallets/w1/sign-requests",
            {"id": "s1", "message": "pay-100"},
        )
        self.srv.request(
            "POST", "/v1/wallets/w1/sign-requests/s1/approve",
            {"approver_id": "a1"},
        )
        status, body = self._deliver("share-1", self._share("share-1"))
        self.assertEqual(status, 200)
        self.assertEqual(body["state"], "signed")

    def test_gate_message_mismatch_is_409(self):
        self.srv.request(
            "PUT",
            "/v1/wallets/w1/approval-policy",
            {"required_approvals": 1, "timeout_seconds": 60},
        )
        self._create(message="pay-100")
        self._deliver("share-1", self._share("share-1"))
        # 审批单 message 不同
        self.srv.request(
            "POST", "/v1/wallets/w1/sign-requests",
            {"id": "s1", "message": "different"},
        )
        self.srv.request(
            "POST", "/v1/wallets/w1/sign-requests/s1/approve",
            {"approver_id": "a1"},
        )
        status, _ = self._deliver("share-2", self._share("share-2"))
        self.assertEqual(status, 409)

    # ---- 审计事件 --------------------------------------------------------

    def test_session_events_seven_fields_continuous_seq_no_signature(self):
        self._create(timeout=1)
        self._deliver("share-1", self._share("share-1"))
        time.sleep(1.1)
        self.srv.request("GET", f"{self.S}/s1")  # 触发懒过期
        events = self._events()
        self.assertTrue(events)
        seqs = [e["seq"] for e in events]
        self.assertEqual(seqs, list(range(1, len(seqs) + 1)))
        for e in events:
            self.assertEqual(
                set(e),
                {"seq", "type", "at", "request_id", "actor_id", "reason",
                 "details"},
            )
            self.assertEqual(e["type"], "session_event")
            self.assertEqual(e["request_id"], "s1")
            self.assertIsNone(e["actor_id"])
            self.assertIsNone(e["reason"])
            # details 绝不含签名
            self.assertNotIn("signature", json.dumps(e))
        actions = [e["details"]["action"] for e in events]
        self.assertEqual(actions, ["created", "share_received", "expired"])
        # share_received 事件带 share_id 但不含签名
        sr = events[1]["details"]
        self.assertEqual(sr["share_id"], "share-1")

    def test_signed_event_sequence_and_replay_not_logged(self):
        self._create()
        self._deliver("share-1", self._share("share-1"))
        self._deliver("share-2", self._share("share-2"))  # 201 signed
        self._deliver("share-1", self._share("share-1"))  # 200 重放
        self._create()  # 200 重放创建
        actions = [
            e["details"]["action"]
            for e in self._events()
            if e["type"] == "session_event"
        ]
        self.assertEqual(
            actions,
            ["created", "share_received", "share_received", "signed"],
        )

    # ---- 并发：仅一个首次聚合 ---------------------------------------------

    def test_concurrent_completion_single_first_aggregate(self):
        self._create()
        # share-1 先收一份
        self._deliver("share-1", self._share("share-1"))
        results: list[tuple[int, str]] = []
        lock = threading.Lock()

        def fire(share_id):
            status, body = self._deliver(share_id, self._share(share_id))
            with lock:
                results.append((status, body.get("signature")))

        threads = []
        # 大量并发投递 share-2（齐备）与 share-1（重放）
        for i in range(24):
            threads.append(
                threading.Thread(target=fire, args=("share-2" if i % 2 else "share-1",))
            )
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        sig201 = {sig for st, sig in results if st == 201}
        # share-1 都是重放(200)；share-2 中恰一个 201，其余 200
        statuses = sorted(st for st, _ in results)
        self.assertEqual(statuses.count(201), 1)
        self.assertTrue(all(st in (200, 201) for st in statuses))
        self.assertEqual(len(sig201), 1)
        # 所有 200 与唯一 201 返回同一聚合签名
        signatures = {sig for _, sig in results if sig}
        self.assertEqual(len(signatures), 1)
        # 恰一个 signed 事件
        signed = [
            e for e in self._events()
            if e["type"] == "session_event"
            and e["details"].get("action") == "signed"
        ]
        self.assertEqual(len(signed), 1)

    # ---- 轮换兼容 --------------------------------------------------------

    def test_signed_session_survives_rotation_replay(self):
        self._create()
        old1 = self._share("share-1")
        self._deliver("share-1", old1)
        self._deliver("share-2", self._share("share-2"))
        agg = self.srv.request("GET", f"{self.S}/s1")[1]["signature"]
        self.srv.request(
            "POST", "/v1/wallets/w1/share-rotations", {"rotation_id": "r1"}
        )
        self.srv.request(
            "POST", "/v1/wallets/w1/share-rotations/r1/activate", {}
        )
        # 旧份额签名重放仍 200 同体
        status, body = self._deliver("share-1", old1)
        self.assertEqual(status, 200)
        self.assertEqual(body["state"], "signed")
        self.assertEqual(body["signature"], agg)
        view = self.srv.request("GET", f"{self.S}/s1")[1]
        self.assertEqual(view["received_shares"], ["share-1", "share-2"])

    def test_collecting_session_after_rotation_needs_new_shares(self):
        old1 = self._share("share-1")
        self._create()
        self._deliver("share-1", old1)
        self.srv.request(
            "POST", "/v1/wallets/w1/share-rotations", {"rotation_id": "r"}
        )
        self.srv.request(
            "POST", "/v1/wallets/w1/share-rotations/r/activate", {}
        )
        view = self.srv.request("GET", f"{self.S}/s1")[1]
        self.assertEqual(view["received_shares"], [])
        self.assertEqual(view["missing_shares"], ["r-share-1", "r-share-2"])
        # 旧份额同值重放仍幂等 200（会话投影到新份额，尚 collecting）
        status, body = self._deliver("share-1", old1)
        self.assertEqual(status, 200)
        self.assertEqual(body["state"], "collecting")
        # 收第一份新在用份额：旧份额被剪枝
        status, body = self._deliver("r-share-1", self._share("r-share-1"))
        self.assertEqual(status, 201)
        self.assertEqual(body["received_shares"], ["r-share-1"])
        # 剪枝后旧份额不再受理（非重放 + 已不在用）-> 400
        status, _ = self._deliver("share-1", old1)
        self.assertEqual(status, 400)
        # 用第二份新份额完成
        status, body = self._deliver("r-share-2", self._share("r-share-2"))
        self.assertEqual(status, 201)
        self.assertEqual(body["state"], "signed")


# ---- 跨进程并发：fcn.flock 串行化首次聚合 ---------------------------------


class SignSessionCrossProcessTest(unittest.TestCase):
    N = 8

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.ctx = multiprocessing.get_context("fork")

    def test_concurrent_completing_share_single_first_aggregate(self):
        svc = WalletService(WalletStore(self.tmp))
        svc.create_wallet("w1", 2)
        st, _ = svc.create_sign_session("w1", "p1", "m", 300)
        self.assertEqual(st, 201)
        # share-1 先收一份（collecting）
        st, _ = svc.deliver_session_share(
            "w1", "p1", "share-1",
            _local_share_hex(self.tmp, "w1", "share-1", "p1", "m"),
        )
        self.assertEqual(st, 201)

        queue = self.ctx.Queue()
        barrier = self.ctx.Barrier(self.N)
        procs = [
            self.ctx.Process(
                target=_child_deliver,
                args=(self.tmp, "share-2", "p1", "m", barrier, queue),
            )
            for _ in range(self.N)
        ]
        for p in procs:
            p.start()
        results = [queue.get(timeout=30) for _ in range(self.N)]
        for p in procs:
            p.join(timeout=30)
            self.assertEqual(p.exitcode, 0)

        statuses = [r[0] for r in results]
        self.assertEqual(statuses.count(201), 1, results)
        self.assertEqual(statuses.count(200), self.N - 1, results)
        signatures = {r[2] for r in results if r[2]}
        self.assertEqual(len(signatures), 1, results)
        states = {r[1] for r in results}
        self.assertEqual(states, {"signed"})

        # 重启后续作：重放 200 同体，仅一条 signed 事件，seq 连续无缺口
        svc2 = WalletService(WalletStore(self.tmp))
        st, body = svc2.deliver_session_share(
            "w1", "p1", "share-2",
            _local_share_hex(self.tmp, "w1", "share-2", "p1", "m"),
        )
        self.assertEqual(st, 200)
        self.assertEqual(body["state"], "signed")
        self.assertEqual(body["signature"], next(iter(signatures)))
        from threshold_wallet.audit import AuditStore

        events = AuditStore(self.tmp).list_events("w1")
        seqs = [e["seq"] for e in events]
        self.assertEqual(seqs, list(range(1, len(seqs) + 1)))
        actions = [
            e["details"].get("action") for e in events
            if e["type"] == "session_event"
        ]
        self.assertEqual(
            actions,
            ["created", "share_received", "share_received", "signed"],
        )


# ---- 重启持久化 ------------------------------------------------------------


class SignSessionPersistenceTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)

    def _sig(self, sid, sess, msg, wallet="w1"):
        store = WalletStore(self.tmp)
        share = store.get_share(wallet, sid)
        payload = crypto.build_payload(sess, msg)
        return crypto.sign_share(
            bytes.fromhex(share["private_key"]), payload
        ).hex()

    def test_resume_collecting_after_restart(self):
        with http_server(self.tmp) as srv:
            srv.request("POST", "/v1/wallets", {"wallet_id": "w1", "shares": 2})
            srv.request(
                "POST", "/v1/wallets/w1/sign-sessions",
                {"id": "s1", "message": "m", "timeout_seconds": 300},
            )
            srv.request(
                "POST", "/v1/wallets/w1/sign-sessions/s1/shares",
                {"share_id": "share-1", "signature": self._sig("share-1", "s1", "m")},
            )
        with http_server(self.tmp) as srv:
            view = srv.request("GET", "/v1/wallets/w1/sign-sessions/s1")[1]
            self.assertEqual(view["state"], "collecting")
            self.assertEqual(view["received_shares"], ["share-1"])
            self.assertEqual(view["missing_shares"], ["share-2"])
            status, body = srv.request(
                "POST", "/v1/wallets/w1/sign-sessions/s1/shares",
                {"share_id": "share-2", "signature": self._sig("share-2", "s1", "m")},
            )
            self.assertEqual(status, 201)
            self.assertEqual(body["state"], "signed")
            agg = body["signature"]
        with http_server(self.tmp) as srv:
            view = srv.request("GET", "/v1/wallets/w1/sign-sessions/s1")[1]
            self.assertEqual(view["state"], "signed")
            self.assertEqual(view["signature"], agg)
            events = srv.request("GET", "/v1/wallets/w1/audit-events")[1]["events"]
            seqs = [e["seq"] for e in events]
            self.assertEqual(seqs, list(range(1, len(seqs) + 1)))
            actions = [
                e["details"].get("action") for e in events
                if e["type"] == "session_event"
            ]
            self.assertEqual(
                actions, ["created", "share_received", "share_received", "signed"]
            )

    def test_ready_gated_survives_restart(self):
        with http_server(self.tmp) as srv:
            srv.request("POST", "/v1/wallets", {"wallet_id": "w1", "shares": 2})
            srv.request(
                "PUT", "/v1/wallets/w1/approval-policy",
                {"required_approvals": 1, "timeout_seconds": 300},
            )
            srv.request(
                "POST", "/v1/wallets/w1/sign-sessions",
                {"id": "s1", "message": "m", "timeout_seconds": 300},
            )
            srv.request(
                "POST", "/v1/wallets/w1/sign-sessions/s1/shares",
                {"share_id": "share-1", "signature": self._sig("share-1", "s1", "m")},
            )
            status, _ = srv.request(
                "POST", "/v1/wallets/w1/sign-sessions/s1/shares",
                {"share_id": "share-2", "signature": self._sig("share-2", "s1", "m")},
            )
            self.assertEqual(status, 409)
        with http_server(self.tmp) as srv:
            view = srv.request("GET", "/v1/wallets/w1/sign-sessions/s1")[1]
            self.assertEqual(view["state"], "ready")
            # 审批并重试
            srv.request("POST", "/v1/wallets/w1/sign-requests",
                        {"id": "s1", "message": "m"})
            srv.request("POST", "/v1/wallets/w1/sign-requests/s1/approve",
                        {"approver_id": "a1"})
            status, body = srv.request(
                "POST", "/v1/wallets/w1/sign-sessions/s1/shares",
                {"share_id": "share-2", "signature": self._sig("share-2", "s1", "m")},
            )
            self.assertEqual(status, 200)
            self.assertEqual(body["state"], "signed")


# ---- 损坏 fail-closed ------------------------------------------------------


class SignSessionCorruptionTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)

    def _seed(self):
        svc = WalletService(WalletStore(self.tmp))
        svc.create_wallet("w1", 2)
        st, _ = svc.create_sign_session("w1", "s1", "m", 60)
        self.assertEqual(st, 201)
        return svc

    def test_store_shape_validation(self):
        bad_payloads = [
            "{broken",
            "[1,2]",
            "42",
            json.dumps({"s1": {"id": "other", "message": "m", "state":
                       "collecting", "timeout_seconds": 60,
                       "expires_at": "2026-09-22T00:00:00Z", "shares": []}}),
            json.dumps({"s1": {"id": "s1", "message": "", "state":
                       "collecting", "timeout_seconds": 60,
                       "expires_at": "x", "shares": []}}),
            json.dumps({"s1": {"id": "s1", "message": "m", "state": "weird",
                       "timeout_seconds": 60, "expires_at": "x", "shares": []}}),
            json.dumps({"s1": {"id": "s1", "message": "m", "state":
                       "collecting", "timeout_seconds": 0,
                       "expires_at": "x", "shares": []}}),
            # collecting 不允许两份
            json.dumps({"s1": {"id": "s1", "message": "m", "state":
                       "collecting", "timeout_seconds": 60,
                       "expires_at": "x", "shares": [
                           {"share_id": "share-1", "signature": "00" * 64},
                           {"share_id": "share-2", "signature": "00" * 64}]}}),
            # 份额签名长度非法
            json.dumps({"s1": {"id": "s1", "message": "m", "state":
                       "collecting", "timeout_seconds": 60,
                       "expires_at": "x", "shares": [
                           {"share_id": "share-1", "signature": "00" * 32}]}}),
            # signed 缺聚合签名
            json.dumps({"s1": {"id": "s1", "message": "m", "state": "signed",
                       "timeout_seconds": 60, "expires_at": "x", "shares": [
                           {"share_id": "share-1", "signature": "00" * 64},
                           {"share_id": "share-2", "signature": "00" * 64}]}}),
        ]
        for payload in bad_payloads:
            _write(_sessions_path(self.tmp), payload)
            with self.subTest(payload=payload[:30]):
                with self.assertRaises(CorruptDataError):
                    WalletStore(self.tmp).check_sign_sessions("w1")

    def test_valid_shape_passes(self):
        good = json.dumps({"s1": {"id": "s1", "message": "m", "state":
                         "collecting", "timeout_seconds": 60,
                         "expires_at": "2026-09-22T00:00:00Z", "shares": []}})
        _write(_sessions_path(self.tmp), good)
        WalletStore(self.tmp).check_sign_sessions("w1")  # 不抛即可

    def test_runtime_corruption_returns_503_and_preserves_scene(self):
        raw = "{broken"
        with http_server(self.tmp) as srv:
            srv.request("POST", "/v1/wallets", {"wallet_id": "w1", "shares": 2})
            srv.request(
                "POST", "/v1/wallets/w1/sign-sessions",
                {"id": "s1", "message": "m", "timeout_seconds": 60},
            )
            # 服务已健康就绪后由"他进程"损坏会话文件
            _write(_sessions_path(self.tmp), raw)
            for method, path, body in [
                ("GET", "/v1/wallets/w1/sign-sessions/s1", None),
                ("POST", "/v1/wallets/w1/sign-sessions",
                 {"id": "y", "message": "m", "timeout_seconds": 1}),
                ("GET", "/v1/wallets/w1", None),
                ("GET", "/v1/wallets/w1/audit-events", None),
            ]:
                status, resp = srv.request(method, path, body)
                self.assertEqual(status, 503, (path, status, resp))
                self.assertEqual(resp, {"error": "service temporarily unavailable"})
        # 现场保留
        with open(_sessions_path(self.tmp), encoding="utf-8") as f:
            self.assertEqual(f.read(), raw)

    def test_startup_corruption_blocks_readiness(self):
        self._seed()
        _write(_sessions_path(self.tmp), "{broken")
        with self.assertRaises(RecoveryError):
            WalletService(WalletStore(self.tmp))
        with open(_sessions_path(self.tmp), encoding="utf-8") as f:
            self.assertEqual(f.read(), "{broken")

    def test_serve_cli_refuses_to_start(self):
        from threshold_wallet import cli

        self._seed()
        _write(_sessions_path(self.tmp), '{"s1": 123}')
        code = cli.main(
            ["serve", "--host", "127.0.0.1", "--port", "0",
             "--data-dir", self.tmp]
        )
        self.assertNotEqual(code, 0)


# ---- 私钥/签名不泄露 -------------------------------------------------------


class SignSessionNoSecretLeakTest(unittest.TestCase):
    def setUp(self):
        self._ctx = http_server(tempfile.mkdtemp())
        self.srv = self._ctx.__enter__()
        self.tmp = self.srv.harness.tmpdir
        self.srv.request(
            "POST", "/v1/wallets", {"wallet_id": "w1", "shares": 2}
        )
        self.srv.request(
            "POST", "/v1/wallets/w1/sign-sessions",
            {"id": "s1", "message": "SECRET-MSG-ZZ9", "timeout_seconds": 60},
        )
        for sid in ("share-1", "share-2"):
            self.srv.request(
                "POST", "/v1/wallets/w1/sign-sessions/s1/shares",
                {"share_id": sid,
                 "signature": self.srv.harness.share_signature(
                     "w1", sid, "s1", "SECRET-MSG-ZZ9")},
            )

    def tearDown(self):
        self._ctx.__exit__(None, None, None)

    def test_session_file_has_no_private_key(self):
        with open(_sessions_path(self.tmp), encoding="utf-8") as f:
            raw = f.read()
        self.assertNotIn("private", raw)
        priv1 = self.srv.harness.share_private_hex("w1", "share-1")
        priv2 = self.srv.harness.share_private_hex("w1", "share-2")
        self.assertNotIn(priv1, raw)
        self.assertNotIn(priv2, raw)

    def test_audit_events_contain_no_share_or_aggregate_signatures(self):
        events = self.srv.request(
            "GET", "/v1/wallets/w1/audit-events"
        )[1]["events"]
        blob = json.dumps(events)
        self.assertNotIn("private", blob)
        # 128 字节聚合签名（hex 256）与 64 字节份额签名（hex 128）都不得入事件
        with open(_sessions_path(self.tmp), encoding="utf-8") as f:
            sess = json.load(f)
        for item in sess["s1"]["shares"]:
            self.assertNotIn(item["signature"], blob)
        self.assertNotIn(sess["s1"]["signature"], blob)

    def test_logs_contain_no_body_or_signature(self):
        log_blob = "\n".join(self.srv.logs)
        self.assertNotIn("SECRET-MSG-ZZ9", log_blob)
        priv1 = self.srv.harness.share_private_hex("w1", "share-1")
        self.assertNotIn(priv1, log_blob)


if __name__ == "__main__":
    unittest.main()
