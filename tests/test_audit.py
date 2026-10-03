"""审计事件测试：seq 重启续接、事件形状、各类触发、重放无事件、
懒过期只记一次、审计 GET 不触发过期、查询参数校验、状态/事件原子回滚。
"""

from __future__ import annotations

import contextlib
import json
import os
import tempfile
import unittest
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone

from tests.helpers import http_server, make_harness
from threshold_wallet.audit import AuditStore
from threshold_wallet.service import ServiceError

EVENT_KEYS = {"seq", "type", "at", "request_id", "actor_id", "reason", "details"}


class AuditStoreTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.store = AuditStore(self.tmp)

    def _event(self, **over):
        e = {
            "type": "policy_updated",
            "at": "2026-09-19T00:00:00Z",
            "request_id": None,
            "actor_id": None,
            "reason": None,
            "details": {},
        }
        e.update(over)
        return e

    def test_seq_starts_at_one_and_monotonic(self):
        e1 = self.store.append_event("w1", self._event())
        e2 = self.store.append_event("w1", self._event(type="request_created"))
        self.assertEqual((e1["seq"], e2["seq"]), (1, 2))
        self.assertEqual([e["seq"] for e in self.store.list_events("w1")], [1, 2])

    def test_seq_continues_after_restart(self):
        self.store.append_event("w1", self._event())
        self.store.append_event("w1", self._event())
        reopened = AuditStore(self.tmp)
        e3 = reopened.append_event("w1", self._event())
        self.assertEqual(e3["seq"], 3)
        self.assertEqual([e["seq"] for e in reopened.list_events("w1")], [1, 2, 3])

    def test_list_filters_and_slices_ascending(self):
        for i in range(5):
            self.store.append_event("w1", self._event())
        self.assertEqual(
            [e["seq"] for e in self.store.list_events("w1", from_seq=3)],
            [3, 4, 5],
        )
        self.assertEqual(
            [e["seq"] for e in self.store.list_events("w1", from_seq=2, limit=2)],
            [2, 3],
        )
        self.assertEqual(self.store.list_events("w1", from_seq=99), [])
        # 钱包无日志文件
        self.assertEqual(self.store.list_events("ghost"), [])

    def test_wallets_are_separate_logs(self):
        self.store.append_event("w1", self._event())
        self.store.append_event("w2", self._event())
        self.assertEqual([e["seq"] for e in self.store.list_events("w1")], [1])
        self.assertEqual([e["seq"] for e in self.store.list_events("w2")], [1])

    def test_path_traversal_rejected(self):
        with self.assertRaises(ValueError):
            self.store.list_events("../escape")


class AuditHttpTest(unittest.TestCase):
    def setUp(self):
        self._ctx = http_server(tempfile.mkdtemp())
        self.srv = self._ctx.__enter__()
        self.request("POST", "/v1/wallets", {"wallet_id": "w1", "shares": 2})

    def tearDown(self):
        self._ctx.__exit__(None, None, None)

    def request(self, method, path, body=None):
        return self.srv.request(method, path, body)

    def events(self, query=""):
        path = "/v1/wallets/w1/audit-events" + (("?" + query) if query else "")
        status, body = self.request("GET", path)
        self.assertEqual(status, 200, body)
        return body

    def put_policy(self, req=2, timeout=3600):
        return self.request(
            "PUT",
            "/v1/wallets/w1/approval-policy",
            {"required_approvals": req, "timeout_seconds": timeout},
        )

    def create_request(self, rid="r1", message="pay-100"):
        return self.request(
            "POST", "/v1/wallets/w1/sign-requests",
            {"id": rid, "message": message},
        )

    def approve(self, rid="r1", approver="alice", reason=None):
        body = {"approver_id": approver}
        if reason is not None:
            body["reason"] = reason
        return self.request(
            "POST", f"/v1/wallets/w1/sign-requests/{rid}/approve", body
        )

    def reject(self, rid="r1", approver="alice", reason=None):
        body = {"approver_id": approver}
        if reason is not None:
            body["reason"] = reason
        return self.request(
            "POST", f"/v1/wallets/w1/sign-requests/{rid}/reject", body
        )

    def expire(self, rid):
        """直接把存储里的 t1 改到过去，模拟 pending 单超时。"""
        store = self.srv.harness.store
        rec = store.get_request("w1", rid)
        rec = dict(rec)
        rec["t1"] = (
            datetime.now(timezone.utc) - timedelta(seconds=1)
        ).isoformat().replace("+00:00", "Z")
        store.update_request("w1", rid, rec)

    def sign_body(self, rid, message):
        return {
            "signing_request_id": rid,
            "message": message,
            "signatures": self.srv.harness.two_signatures("w1", rid, message),
        }

    # ---- 端点契约 -------------------------------------------------------

    def test_endpoint_envelope_and_shape(self):
        self.put_policy()
        body = self.events()
        self.assertEqual(body["wallet_id"], "w1")
        self.assertIsInstance(body["events"], list)
        event = body["events"][0]
        self.assertEqual(set(event), EVENT_KEYS)
        self.assertTrue(event["at"].endswith("Z"))
        self.assertEqual(event["type"], "policy_updated")
        self.assertIsNone(event["request_id"])
        self.assertIsNone(event["actor_id"])
        self.assertIsNone(event["reason"])
        self.assertEqual(
            event["details"],
            {"required_approvals": 2, "timeout_seconds": 3600,
             "operation": "created"},
        )

    def test_events_ascending_contiguous_seq(self):
        self.put_policy(req=1)
        self.create_request()
        self.approve()
        seqs = [e["seq"] for e in self.events()["events"]]
        self.assertEqual(seqs, list(range(1, len(seqs) + 1)))

    # ---- P --------------------------------------------------------------

    def test_policy_same_value_still_recorded_as_updated(self):
        self.put_policy(req=2, timeout=3600)
        self.put_policy(req=2, timeout=3600)
        ops = [
            e["details"]["operation"]
            for e in self.events()["events"]
            if e["type"] == "policy_updated"
        ]
        self.assertEqual(ops, ["created", "updated"])

    # ---- C --------------------------------------------------------------

    def test_request_created_event_and_nulls(self):
        self.put_policy()
        self.create_request()
        c = [e for e in self.events()["events"]
             if e["type"] == "request_created"]
        self.assertEqual(len(c), 1)
        self.assertEqual(c[0]["request_id"], "r1")
        self.assertEqual(c[0]["details"], {"message": "pay-100"})
        for key in ("actor_id", "reason"):
            self.assertIsNone(c[0][key])

    def test_request_create_replay_and_conflict_emit_nothing(self):
        self.put_policy()
        self.create_request()
        n_after_first = len(self.events()["events"])
        # 同文幂等 200、异文 409 均不记事件
        self.assertEqual(self.create_request()[0], 200)
        self.assertEqual(self.create_request(message="other")[0], 409)
        self.assertEqual(len(self.events()["events"]), n_after_first)

    # ---- A / R ----------------------------------------------------------

    def test_approve_events_and_duplicate_silent(self):
        self.put_policy(req=2)
        self.create_request()
        self.approve(approver="alice", reason="ok")
        # 同一 approver 重复批准：不计数、不记事件
        self.approve(approver="alice")
        self.approve(approver="bob")
        approved = [
            e for e in self.events()["events"]
            if e["type"] == "request_approved"
        ]
        self.assertEqual(len(approved), 2)
        self.assertEqual(
            [(e["actor_id"], e["details"]["count"], e["details"]["state"])
             for e in approved],
            [("alice", 1, "pending"), ("bob", 2, "approved")],
        )
        self.assertEqual(approved[0]["reason"], "ok")
        self.assertIsNone(approved[1]["reason"])
        self.assertEqual(
            approved[0]["details"]["req"], 2,
        )
        # 已 approved 再批准：409 且无事件
        n = len(self.events()["events"])
        self.assertEqual(self.approve(approver="carol")[0], 409)
        self.assertEqual(len(self.events()["events"]), n)

    def test_reject_event_and_terminal_silent(self):
        self.put_policy(req=2)
        self.create_request()
        self.reject(reason="nope")
        rejected = [
            e for e in self.events()["events"]
            if e["type"] == "request_rejected"
        ]
        self.assertEqual(len(rejected), 1)
        self.assertEqual(rejected[0]["request_id"], "r1")
        self.assertEqual(rejected[0]["actor_id"], "alice")
        self.assertEqual(rejected[0]["reason"], "nope")
        self.assertEqual(rejected[0]["details"]["state"], "rejected")
        n = len(self.events()["events"])
        # 同人同拒绝重放为 200；不同决定仍为 409，均不记事件
        self.assertEqual(self.reject(approver="alice")[0], 200)
        self.assertEqual(self.approve()[0], 409)
        self.assertEqual(len(self.events()["events"]), n)

    # ---- E --------------------------------------------------------------

    def test_expire_recorded_once_on_each_trigger(self):
        self.put_policy()
        for rid in ("rg", "ra", "rr", "rs"):
            self.create_request(rid=rid)
            self.expire(rid)

        # 审计 GET 不触发过期
        self.events()
        self.assertEqual(
            self.srv.harness.store.get_request("w1", "rg")["state"], "pending"
        )
        # 普通 GET 触发：记一次 E 并持久化
        status, view = self.request("GET", "/v1/wallets/w1/sign-requests/rg")
        self.assertEqual(view["state"], "expired")
        # approve / reject / sign 也触发
        self.assertEqual(self.approve(rid="ra")[0], 409)
        self.assertEqual(self.reject(rid="rr")[0], 409)
        sign_status, _ = self.request(
            "POST", "/v1/wallets/w1/sign", self.sign_body("rs", "pay-100")
        )
        self.assertEqual(sign_status, 409)

        expired_events = [
            e for e in self.events()["events"]
            if e["type"] == "request_expired"
        ]
        self.assertEqual(
            sorted(e["request_id"] for e in expired_events),
            ["ra", "rg", "rr", "rs"],
        )
        for e in expired_events:
            self.assertEqual(e["details"], {"state": "expired"})
            self.assertIsNone(e["actor_id"])
            self.assertIsNone(e["reason"])
        # 反复 GET 已过期单：E 仍只有一条
        for _ in range(3):
            self.request("GET", "/v1/wallets/w1/sign-requests/rg")
        total_e = sum(
            1 for e in self.events()["events"]
            if e["type"] == "request_expired"
        )
        self.assertEqual(total_e, 4)

    # ---- S --------------------------------------------------------------

    def test_signed_event_and_replay_silent(self):
        self.put_policy(req=1)
        self.create_request()
        self.approve()
        status, body = self.request(
            "POST", "/v1/wallets/w1/sign", self.sign_body("r1", "pay-100")
        )
        self.assertEqual(status, 201)
        signed = [
            e for e in self.events()["events"]
            if e["type"] == "request_signed"
        ]
        self.assertEqual(len(signed), 1)
        self.assertEqual(signed[0]["request_id"], "r1")
        self.assertEqual(
            signed[0]["details"], {"message": "pay-100", "state": "signed"}
        )
        # 重放 200，无新事件
        n = len(self.events()["events"])
        status, replay = self.request(
            "POST", "/v1/wallets/w1/sign", self.sign_body("r1", "pay-100")
        )
        self.assertEqual(status, 200)
        self.assertEqual(replay["signature"], body["signature"])
        self.assertEqual(len(self.events()["events"]), n)

    # ---- 查询参数 --------------------------------------------------------

    def test_pagination_from_seq_and_limit(self):
        self.put_policy(req=1)
        self.create_request()
        self.approve()
        all_events = self.events()["events"]
        self.assertGreaterEqual(len(all_events), 3)
        page = self.events("from_seq=2&limit=1")["events"]
        self.assertEqual(len(page), 1)
        self.assertEqual(page[0]["seq"], 2)
        # 默认 from_seq=1：从头开始
        self.assertEqual(self.events("limit=1")["events"][0]["seq"], 1)

    def test_bad_query_params_400(self):
        self.put_policy()
        for query in (
            "from_seq=0",
            "from_seq=-3",
            "from_seq=abc",
            "from_seq=1.5",
            "limit=0",
            "limit=-1",
            "limit=xyz",
            "limit=1001",
            "from_seq=0&limit=10",
        ):
            status, body = self.request(
                "GET", f"/v1/wallets/w1/audit-events?{query}"
            )
            self.assertEqual(status, 400, query)
            self.assertIn("error", body)

    def test_limit_boundary_1000_accepted(self):
        status, _ = self.request(
            "GET", "/v1/wallets/w1/audit-events?limit=1000"
        )
        self.assertEqual(status, 200)

    def test_audit_events_missing_wallet_404(self):
        status, body = self.request(
            "GET", "/v1/wallets/ghost/audit-events"
        )
        self.assertEqual(status, 404)
        self.assertIn("error", body)

    # ---- 线路字节契约 ----------------------------------------------------

    def _raw_get(self, path):
        req = urllib.request.Request(self.srv.base_url + path)
        try:
            with urllib.request.urlopen(req) as resp:
                return resp.status, resp.read()
        except urllib.error.HTTPError as exc:
            return exc.code, exc.read()

    def test_wire_is_compact_utf8_no_trailing_newline(self):
        self.put_policy()
        status, raw = self._raw_get("/v1/wallets/w1/audit-events")
        self.assertEqual(status, 200)
        # 紧凑 JSON：无空白分隔符、无末换行
        self.assertNotIn(b", ", raw)
        self.assertNotIn(b": ", raw)
        self.assertFalse(raw.endswith(b"\n"))
        self.assertEqual(
            json.loads(raw.decode("utf-8"))["wallet_id"], "w1"
        )
        # 成功体键序 wallet_id,events；事件按 seq 升序
        self.assertTrue(raw.startswith(b'{"wallet_id":"w1","events":['))
        seqs = [e["seq"] for e in json.loads(raw)["events"]]
        self.assertEqual(seqs, sorted(seqs))

    def test_wire_non_ascii_not_escaped(self):
        self.put_policy()
        self.create_request()
        self.reject(reason="拒绝")
        status, raw = self._raw_get("/v1/wallets/w1/audit-events")
        self.assertEqual(status, 200)
        # 非 ASCII 原样 UTF-8，不转义为 \uXXXX
        self.assertIn("拒绝".encode("utf-8"), raw)
        self.assertNotIn(b"\\u", raw)

    def test_wire_error_bodies_also_compact(self):
        self.put_policy()
        for path, want in (
            ("/v1/wallets/w1/audit-events?limit=0", 400),
            ("/v1/wallets/ghost/audit-events", 404),
        ):
            status, raw = self._raw_get(path)
            self.assertEqual(status, want)
            self.assertNotIn(b": ", raw)
            self.assertFalse(raw.endswith(b"\n"))
            self.assertIn(b'"error"', raw)

    def test_other_routes_keep_default_wire_format(self):
        self.put_policy()
        # 其余 HTTP 路由的响应字节不变（默认分隔符）
        status, raw = self._raw_get("/v1/wallets/w1")
        self.assertEqual(status, 200)
        self.assertIn(b'": "', raw)


class AuditAtomicityTest(unittest.TestCase):
    """状态/事件原子：事件追加失败时回滚状态，且不留下事件。"""

    def setUp(self):
        self.h = make_harness(tempfile.mkdtemp())
        self.svc = self.h.service
        self.svc.create_wallet("w1", 2)

    @contextlib.contextmanager
    def failing_audit(self):
        original = self.svc._audit.append_event

        def boom(*_a, **_k):
            raise OSError("audit disk full")

        self.svc._audit.append_event = boom
        try:
            yield
        finally:
            self.svc._audit.append_event = original

    def test_policy_rolled_back_when_event_fails(self):
        with self.failing_audit():
            with self.assertRaises(OSError):
                self.svc.put_policy("w1", 1, 60)
        self.assertIsNone(self.h.store.get_policy("w1"))
        # 更新失败：回滚到旧策略
        self.svc.put_policy("w1", 1, 60)
        with self.failing_audit():
            with self.assertRaises(OSError):
                self.svc.put_policy("w1", 2, 120)
        self.assertEqual(self.h.store.get_policy("w1")["required_approvals"], 1)

    def test_request_create_rolled_back_when_event_fails(self):
        self.svc.put_policy("w1", 1, 3600)
        with self.failing_audit():
            with self.assertRaises(OSError):
                self.svc.create_sign_request("w1", "r1", "m")
        self.assertIsNone(self.h.store.get_request("w1", "r1"))

    def test_approve_rolled_back_when_event_fails(self):
        self.svc.put_policy("w1", 2, 3600)
        self.svc.create_sign_request("w1", "r1", "m")
        with self.failing_audit():
            with self.assertRaises(OSError):
                self.svc.approve("w1", "r1", "alice", None)
        rec = self.h.store.get_request("w1", "r1")
        self.assertEqual(rec["state"], "pending")
        self.assertEqual(rec["approvers"], [])

    def test_sign_rolled_back_when_event_fails(self):
        self.svc.put_policy("w1", 1, 3600)
        self.svc.create_sign_request("w1", "r1", "m")
        self.svc.approve("w1", "r1", "alice", None)
        sigs = self.h.two_signatures("w1", "r1", "m")
        with self.failing_audit():
            with self.assertRaises(OSError):
                self.svc.sign("w1", "r1", "m", sigs)
        self.assertIsNone(self.h.store.get_signature("w1", "r1"))
        # 审批单回退到 approved，而非停留在 signed
        self.assertEqual(
            self.h.store.get_request("w1", "r1")["state"], "approved"
        )

    def test_expiry_rolled_back_when_event_fails(self):
        self.svc.put_policy("w1", 1, 3600)
        self.svc.create_sign_request("w1", "r1", "m")
        rec = self.h.store.get_request("w1", "r1")
        rec["t1"] = (
            datetime.now(timezone.utc) - timedelta(seconds=1)
        ).isoformat().replace("+00:00", "Z")
        self.h.store.update_request("w1", "r1", rec)
        with self.failing_audit():
            with self.assertRaises(OSError):
                self.svc.get_sign_request("w1", "r1")
        # 过期状态被回滚：仍是 pending
        self.assertEqual(
            self.h.store.get_request("w1", "r1")["state"], "pending"
        )


class AuditFilterHttpTest(unittest.TestCase):
    """event_type/request_id 筛选：精确匹配、交集、分页语义与参数校验。"""

    def setUp(self):
        self._ctx = http_server(tempfile.mkdtemp())
        self.srv = self._ctx.__enter__()
        self.request("POST", "/v1/wallets", {"wallet_id": "w1", "shares": 2})

    def tearDown(self):
        self._ctx.__exit__(None, None, None)

    def request(self, method, path, body=None):
        return self.srv.request(method, path, body)

    def get(self, query="", wallet="w1"):
        path = f"/v1/wallets/{wallet}/audit-events"
        if query:
            path += "?" + query
        return self.request("GET", path)

    def seqs(self, query=""):
        status, body = self.get(query)
        self.assertEqual(status, 200, body)
        self.assertEqual(set(body), {"wallet_id", "events"})
        return [e["seq"] for e in body["events"]]

    def put_policy(self, req=1):
        return self.request(
            "PUT",
            "/v1/wallets/w1/approval-policy",
            {"required_approvals": req, "timeout_seconds": 3600},
        )

    def create_request(self, rid):
        return self.request(
            "POST", "/v1/wallets/w1/sign-requests",
            {"id": rid, "message": "pay-100"},
        )

    def approve(self, rid, approver="alice"):
        return self.request(
            "POST", f"/v1/wallets/w1/sign-requests/{rid}/approve",
            {"approver_id": approver},
        )

    def reject(self, rid, approver="alice"):
        return self.request(
            "POST", f"/v1/wallets/w1/sign-requests/{rid}/reject",
            {"approver_id": approver},
        )

    def _standard_events(self):
        # seq1 policy_updated(request_id=null) / seq2 request_created(r1) /
        # seq3 request_created(r2) / seq4 request_approved(r1, actor alice)
        self.put_policy()
        self.create_request("r1")
        self.create_request("r2")
        self.approve("r1")

    # ---- 精确匹配与交集 ---------------------------------------------------

    def test_filter_by_event_type(self):
        self._standard_events()
        self.assertEqual(self.seqs("event_type=request_created"), [2, 3])
        self.assertEqual(self.seqs("event_type=policy_updated"), [1])
        self.assertEqual(self.seqs("event_type=request_approved"), [4])

    def test_filter_by_request_id(self):
        self._standard_events()
        self.assertEqual(self.seqs("request_id=r1"), [2, 4])
        self.assertEqual(self.seqs("request_id=r2"), [3])

    def test_filter_intersection(self):
        self._standard_events()
        self.assertEqual(
            self.seqs("event_type=request_created&request_id=r1"), [2]
        )
        # 两条件分别都有记录、但无同时满足的记录：交集为空
        self.assertEqual(
            self.seqs("event_type=request_approved&request_id=r2"), []
        )

    def test_filter_no_match_returns_200_empty(self):
        self._standard_events()
        status, body = self.get("event_type=no_such_type")
        self.assertEqual(status, 200)
        self.assertEqual(body, {"wallet_id": "w1", "events": []})

    def test_filter_does_not_search_actor_or_details(self):
        self._standard_events()
        # actor_id=alice、details.message=pay-100 均不参与匹配
        self.assertEqual(self.seqs("request_id=alice"), [])
        self.assertEqual(self.seqs("event_type=pay-100"), [])
        self.assertEqual(self.seqs("request_id=pay-100"), [])

    def test_null_request_id_not_matched_by_text_null(self):
        self._standard_events()
        # seq1 的 request_id 为 JSON null，不匹配文本 "null"
        self.assertEqual(self.seqs("request_id=null"), [])

    def test_filter_on_wallet_without_events_returns_empty(self):
        # 一条事件都没有的钱包：合法筛选仍 200 空数组
        self.assertEqual(self.seqs("event_type=policy_updated"), [])
        self.assertEqual(self.seqs("request_id=r1"), [])
        self.assertEqual(
            self.seqs("event_type=policy_updated&request_id=r1"), []
        )

    def test_case_and_whitespace_are_significant(self):
        self._standard_events()
        self.assertEqual(self.seqs("event_type=Policy_Updated"), [])
        self.assertEqual(self.seqs("event_type=POLICY_UPDATED"), [])
        # 首尾空白保留：解码后为 " policy_updated" / "policy_updated "
        self.assertEqual(self.seqs("event_type=%20policy_updated"), [])
        self.assertEqual(self.seqs("event_type=policy_updated%20"), [])
        self.assertEqual(self.seqs("request_id=%20r1"), [])

    def test_no_prefix_match(self):
        self._standard_events()
        self.assertEqual(self.seqs("event_type=request"), [])
        self.assertEqual(self.seqs("request_id=r"), [])

    def test_values_are_url_decoded_before_matching(self):
        self._standard_events()
        # %5F == "_"：解码后精确匹配
        self.assertEqual(self.seqs("event_type=request%5Fcreated"), [2, 3])
        self.assertEqual(self.seqs("event_type=policy%5Fupdated"), [1])
        # 斜杠是合法筛选字符（DKG 派生轮 request_id 形如 dkg1/2）：
        # 格式合法但无对应记录时返回空数组
        self.assertEqual(self.seqs("request_id=dkg1%2F2"), [])
        self.assertEqual(self.seqs("request_id=dkg1/2"), [])

    # ---- 分页语义：limit 只数符合全部条件的事件 ---------------------------

    def _interleaved_events(self):
        # policy_updated 落在 seq 2、7、11，中间夹不匹配记录（seq1 用一条
        # dkg_stage 填充：无策略时 create_request 只能 409、不记事件）。
        self.srv.harness.service.post_dkg_stage(
            "w1", "d1", "register", "n1", "aa" * 32, None, None, None
        )                                        # 1 dkg_stage
        self.put_policy()                        # 2 policy_updated ✓
        self.create_request("a")                 # 3 request_created
        self.create_request("b")                 # 4 request_created
        self.approve("a")                        # 5 request_approved
        self.reject("b")                         # 6 request_rejected
        self.put_policy()                        # 7 policy_updated ✓
        self.create_request("c")                 # 8 request_created
        self.approve("c")                        # 9 request_approved
        self.create_request("d")                 # 10 request_created
        self.put_policy()                        # 11 policy_updated ✓

    def test_limit_counts_matching_events_only(self):
        self._interleaved_events()
        self.assertEqual(self.seqs("event_type=policy_updated"), [2, 7, 11])
        # from_seq=3、limit=2 返回 7 和 11：不能因中间记录不匹配而提前结束
        self.assertEqual(
            self.seqs("event_type=policy_updated&from_seq=3&limit=2"),
            [7, 11],
        )
        self.assertEqual(
            self.seqs("event_type=policy_updated&limit=2"), [2, 7]
        )
        self.assertEqual(
            self.seqs("event_type=policy_updated&from_seq=7"), [7, 11]
        )
        # from_seq 是包含端点的原始序号下界：命中记录本身
        self.assertEqual(
            self.seqs("event_type=policy_updated&from_seq=11&limit=1"), [11]
        )
        # 下界超过末尾 / 范围内无匹配：200 空数组
        self.assertEqual(self.seqs("event_type=policy_updated&from_seq=12"), [])
        self.assertEqual(self.seqs("request_id=zz&from_seq=3"), [])

    def test_filter_combines_with_request_id_and_pagination(self):
        self._interleaved_events()
        self.assertEqual(self.seqs("request_id=a"), [3, 5])
        self.assertEqual(
            self.seqs("request_id=a&from_seq=4"), [5]
        )
        self.assertEqual(
            self.seqs("event_type=request_approved&request_id=c"), [9]
        )

    # ---- 参数校验 ----------------------------------------------------------

    def test_duplicate_filter_params_400(self):
        self._standard_events()
        for query in (
            "event_type=request_created&event_type=request_created",
            "event_type=request_created&event_type=policy_updated",
            "request_id=r1&request_id=r1",
            "request_id=r1&request_id=r2",
            "event_type=request_created&event_type=",
        ):
            status, body = self.get(query)
            self.assertEqual(status, 400, query)
            self.assertIn("error", body)

    def test_empty_and_blank_filter_values_400(self):
        self._standard_events()
        for query in (
            "event_type=",
            "event_type",
            "event_type=%20",
            "event_type=+%20",
            "event_type=%09",
            "request_id=",
            "request_id",
            "request_id=%20%20%20",
        ):
            status, body = self.get(query)
            self.assertEqual(status, 400, query)
            self.assertIn("error", body)

    def test_filter_length_boundary(self):
        self._standard_events()
        # 1024 个码点：格式合法（无匹配 → 200 空数组）
        status, body = self.get("event_type=" + "a" * 1024)
        self.assertEqual(status, 200)
        self.assertEqual(body["events"], [])
        status, _ = self.get("request_id=" + "b" * 1024)
        self.assertEqual(status, 200)
        # 1025 个码点：超长 400
        for query in (
            "event_type=" + "a" * 1025,
            "request_id=" + "b" * 1025,
        ):
            status, body = self.get(query)
            self.assertEqual(status, 400, query[:40])
            self.assertIn("error", body)

    def test_non_ascii_filter_value_counts_code_points(self):
        self._standard_events()
        # 1024 个非 ASCII 码点合法；1025 个超长
        status, _ = self.get("event_type=" + "%C3%A9" * 1024)
        self.assertEqual(status, 200)
        status, _ = self.get("event_type=" + "%C3%A9" * 1025)
        self.assertEqual(status, 400)

    def test_missing_wallet_404_precedes_filter_validation(self):
        for query in ("event_type=", "event_type=a&event_type=b",
                      "request_id=%20", "event_type=request_created"):
            status, body = self.get(query, wallet="ghost")
            self.assertEqual(status, 404, query)
            self.assertIn("error", body)

    def test_invalid_wallet_id_400(self):
        status, body = self.get("event_type=x", wallet="bad%20id")
        self.assertEqual(status, 400)
        self.assertIn("error", body)

    def test_bad_pagination_params_keep_current_behavior(self):
        self._standard_events()
        for query in (
            "event_type=request_created&from_seq=0",
            "event_type=request_created&limit=1001",
            "request_id=r1&limit=abc",
        ):
            status, _ = self.get(query)
            self.assertEqual(status, 400, query)
        # from_seq 空值沿用既有行为（视为缺省），不受新参数影响
        self.assertEqual(
            self.seqs("from_seq=&event_type=request_created"), [2, 3]
        )

    # ---- 只读语义与既有行为保持 -------------------------------------------

    def test_no_filter_params_unchanged(self):
        self._standard_events()
        self.assertEqual(self.seqs(), [1, 2, 3, 4])
        self.assertEqual(self.seqs("from_seq=2&limit=2"), [2, 3])

    def test_filtered_events_keep_public_shape(self):
        self._standard_events()
        status, body = self.get("event_type=request_created")
        self.assertEqual(status, 200)
        self.assertEqual(list(body), ["wallet_id", "events"])
        for event in body["events"]:
            self.assertEqual(set(event), EVENT_KEYS)
        self.assertEqual(body["events"][0]["request_id"], "r1")

    def test_filter_does_not_trigger_lazy_expiry_or_writes(self):
        self.put_policy()
        self.create_request("r1")
        store = self.srv.harness.store
        rec = dict(store.get_request("w1", "r1"))
        rec["t1"] = (
            datetime.now(timezone.utc) - timedelta(seconds=1)
        ).isoformat().replace("+00:00", "Z")
        store.update_request("w1", "r1", rec)
        n = len(self.seqs())
        self.seqs("event_type=request_expired")
        self.seqs("request_id=r1")
        # 不触发懒过期、不新增事件、不分配序号
        self.assertEqual(
            store.get_request("w1", "r1")["state"], "pending"
        )
        self.assertEqual(len(self.seqs()), n)

    def test_frozen_wallet_still_queryable_with_filters(self):
        self._standard_events()
        status, _ = self.request(
            "POST", "/v1/wallets/w1/freeze", {"reason": "incident"}
        )
        self.assertEqual(status, 201)
        self.assertEqual(self.seqs("event_type=request_created"), [2, 3])
        self.assertEqual(self.seqs("request_id=r1"), [2, 4])

    def test_corruption_excluded_by_filter_still_503(self):
        self._standard_events()
        # 篡改一条会被筛选条件排除的记录（seq1 policy_updated）：
        # 整份日志严格加载在筛选之前，绝不返回部分结果
        path = os.path.join(
            self.srv.harness.tmpdir, "audit", "w1.json"
        )
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
        data["events"][0]["details"] = "not-an-object"
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(data, fh)
        for query in ("event_type=request_created", "request_id=r1", ""):
            status, body = self.get(query)
            self.assertEqual(status, 503, query)
            self.assertIn("error", body)


class AuditFilterServiceTest(unittest.TestCase):
    """筛选的 service 级回归：DKG 派生轮斜杠 request_id、重启后结果。"""

    KEY_A = "aa" * 32
    KEY_B = "bb" * 32
    KEY_C = "cc" * 32
    HASH_A = "11" * 32
    HASH_B = "22" * 32

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.h = make_harness(self.tmp)
        self.svc = self.h.service
        self.svc.create_wallet("w1", 2)

    def _dkg_failover_event(self):
        """走真实 DKG 故障流程，产生 request_id 为 d1/2 的 dkg_failover。"""
        post = self.svc.post_dkg_stage
        self.assertEqual(post("w1", "d1", "register", "n1",
                              self.KEY_A, None, None)[0], 201)
        self.assertEqual(post("w1", "d1", "register", "n2",
                              self.KEY_B, None, None)[0], 201)
        self.assertEqual(post("w1", "d1", "commit", "n1",
                              None, self.HASH_A, None)[0], 201)
        self.assertEqual(post("w1", "d1", "commit", "n2",
                              None, self.HASH_B, None)[0], 201)
        code, _ = self.svc.post_dkg_failover(
            "w1", "d1", 2, "replace", "n2", "n3", self.KEY_C
        )
        self.assertEqual(code, 201)

    def test_request_id_with_slash_matches_dkg_derived_round(self):
        self._dkg_failover_event()
        matched = self.svc.get_audit_events("w1", request_id="d1/2")["events"]
        self.assertEqual(len(matched), 1)
        self.assertEqual(matched[0]["type"], "dkg_failover")
        self.assertEqual(matched[0]["request_id"], "d1/2")
        # 与 event_type 取交集
        self.assertEqual(
            self.svc.get_audit_events(
                "w1", event_type="dkg_failover", request_id="d1/2"
            )["events"],
            matched,
        )
        self.assertEqual(
            self.svc.get_audit_events(
                "w1", event_type="dkg_stage", request_id="d1/2"
            )["events"],
            [],
        )
        # 会话级 request_id（无斜杠）不受派生轮筛选影响
        stages = self.svc.get_audit_events(
            "w1", event_type="dkg_stage", request_id="d1"
        )["events"]
        self.assertEqual(len(stages), 4)

    def test_filter_results_survive_restart(self):
        self.svc.put_policy("w1", 1, 3600)
        self.svc.create_sign_request("w1", "r1", "m")
        self.svc.create_sign_request("w1", "r2", "m")
        # 重启：同一目录上的新 service，筛选结果由已有记录决定
        svc2 = make_harness(self.tmp).service
        events = svc2.get_audit_events(
            "w1", event_type="request_created"
        )["events"]
        self.assertEqual([e["seq"] for e in events], [2, 3])
        self.assertEqual(
            [e["request_id"] for e in events], ["r1", "r2"]
        )

    def test_service_level_filter_validation(self):
        self.svc.put_policy("w1", 1, 3600)
        for kwargs in (
            {"event_type": ""},
            {"event_type": "   "},
            {"event_type": "a" * 1025},
            {"event_type": ["a", "a"]},
            {"event_type": 7},
            {"request_id": ""},
            {"request_id": "\t"},
            {"request_id": ["r1", "r1"]},
        ):
            with self.assertRaises(ServiceError) as ctx:
                self.svc.get_audit_events("w1", **kwargs)
            self.assertEqual(ctx.exception.status, 400, kwargs)
        # 缺省与边界值不抛
        self.svc.get_audit_events("w1", event_type=None, request_id=None)
        self.svc.get_audit_events("w1", event_type="a" * 1024)


if __name__ == "__main__":
    unittest.main()
