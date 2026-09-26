"""跨链派发最终性查询与资产结算
（GET /v1/wallets/{W}/chain/{D}/finality、
POST /v1/wallets/{W}/chain/{D}/settle）测试。

覆盖：
- finality 返回 F，键序 operation_id,chain_id,confirmation，末值为
  confirm 既有七键 V；未 broadcasted 或无确认 409；纯只读（不写文件/
  事件/seq）；非法 D 400、钱包/派发未知 404；
- settle 空体 POST：非空体（含 {}) 400；归属/tx/事件链一致、V 已
  finalized、操作 pending 才结算；confirming、余额不足或别处已提交
  409 且无副作用；首提 201 返回既有 R，同 D 重放优先 200 同体，并发
  仅一 201；
- 锁内原子结算并相邻追加 chain_dispatch_settled（request_id=D、
  actor_id=adapter_id、reason=null、details 键序 dispatch_id,
  operation_id）与 asset_operation_committed（details=R），两事件俱在
  前滚、俱无回滚；
- 坏 JSON/I/O 分别 CorruptDataError/OSError，语义矛盾 RecoveryError，
  均映射 503 且 serve 拒绝就绪；重放不记事件；响应不泄私钥/份额正文。
"""

from __future__ import annotations

import json
import os
import shutil
import tempfile
import threading
import unittest
import urllib.error
import urllib.request

from threshold_wallet.service import ServiceError, WalletService
from threshold_wallet.store import RecoveryError

from tests.helpers import http_server, make_harness

TX1 = "ab" * 32
BH1 = "01" * 32


def _msg(operation_id="op1", dispatch_id="dp1", adapter_id="ad1",
         chain_id="chain-1"):
    return json.dumps(
        {
            "operation_id": operation_id,
            "dispatch_id": dispatch_id,
            "adapter_id": adapter_id,
            "chain_id": chain_id,
        },
        ensure_ascii=False,
        separators=(",", ":"),
    )


class _SceneMixin:
    """建钱包/策略/审批/派发/播链结果/确认进展的共用装配。"""

    def _build_scene(self, confirmations=3):
        self.svc.create_wallet("w1", 2)
        self.svc.put_policy("w1", 1, 600)
        code, _ = self.svc.create_asset_operation("w1", "op1", "BTC", 100)
        self.assertEqual(code, 201)
        self.svc.put_chain_policy("w1", "BTC", "chain-1", True, 3, 2)
        code, _ = self.svc.create_sign_request("w1", "ap1", _msg())
        self.assertEqual(code, 201)
        self.svc.approve("w1", "ap1", "boss")
        code, _ = self.svc.post_chain_dispatch(
            "w1", "op1", "dp1", "ad1", "ap1"
        )
        self.assertEqual(code, 201)
        code, _ = self.svc.post_chain_dispatch_result(
            "w1", "dp1", "ad1", "broadcasted", TX1
        )
        self.assertEqual(code, 201)
        if confirmations:
            code, _ = self.svc.post_chain_dispatch_confirmation(
                "w1", "dp1", "ad1", TX1, 10, BH1, confirmations
            )
            self.assertEqual(code, 201)

    def _events(self, types=None):
        events = self.svc.get_audit_events("w1")["events"]
        if types is None:
            return events
        return [e for e in events if e["type"] in types]


# ---------------------------------------------------------------------------
# 服务层：finality
# ---------------------------------------------------------------------------

class FinalityServiceTest(_SceneMixin, unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.d, ignore_errors=True)
        self.h = make_harness(self.d)
        self.svc = self.h.service

    def test_no_result_409(self):
        self._build_scene(confirmations=0)
        # 撤掉结果：用一个尚无结果的新派发 dp2
        code, _ = self.svc.create_asset_operation("w1", "op2", "BTC", 5)
        self.assertEqual(code, 201)
        code, _ = self.svc.create_sign_request(
            "w1", "ap2",
            _msg("op2", "dp2", "ad1"),
        )
        self.assertEqual(code, 201)
        self.svc.approve("w1", "ap2", "boss")
        code, _ = self.svc.post_chain_dispatch(
            "w1", "op2", "dp2", "ad1", "ap2"
        )
        self.assertEqual(code, 201)
        with self.assertRaises(ServiceError) as ctx:
            self.svc.get_chain_dispatch_finality("w1", "dp2")
        self.assertEqual(ctx.exception.status, 409)

    def test_broadcasted_without_confirmation_409(self):
        self._build_scene(confirmations=0)
        with self.assertRaises(ServiceError) as ctx:
            self.svc.get_chain_dispatch_finality("w1", "dp1")
        self.assertEqual(ctx.exception.status, 409)

    def test_failed_result_409(self):
        self._build_scene(confirmations=0)
        code, _ = self.svc.create_asset_operation("w1", "op3", "BTC", 5)
        self.assertEqual(code, 201)
        code, _ = self.svc.create_sign_request(
            "w1", "ap3",
            _msg("op3", "dp3", "ad1"),
        )
        self.assertEqual(code, 201)
        self.svc.approve("w1", "ap3", "boss")
        code, _ = self.svc.post_chain_dispatch(
            "w1", "op3", "dp3", "ad1", "ap3"
        )
        self.assertEqual(code, 201)
        code, _ = self.svc.post_chain_dispatch_result(
            "w1", "dp3", "ad1", "failed", None
        )
        self.assertEqual(code, 201)
        with self.assertRaises(ServiceError) as ctx:
            self.svc.get_chain_dispatch_finality("w1", "dp3")
        self.assertEqual(ctx.exception.status, 409)

    def test_confirming_view(self):
        self._build_scene(confirmations=2)
        f = self.svc.get_chain_dispatch_finality("w1", "dp1")
        self.assertEqual(list(f), ["operation_id", "chain_id", "confirmation"])
        self.assertEqual(f["operation_id"], "op1")
        self.assertEqual(f["chain_id"], "chain-1")
        confirmation = f["confirmation"]
        self.assertEqual(
            list(confirmation),
            [
                "dispatch_id",
                "adapter_id",
                "tx_id",
                "block_height",
                "block_hash",
                "confirmations",
                "state",
            ],
        )
        self.assertEqual(confirmation["dispatch_id"], "dp1")
        self.assertEqual(confirmation["adapter_id"], "ad1")
        self.assertEqual(confirmation["tx_id"], TX1)
        self.assertEqual(confirmation["block_height"], 10)
        self.assertEqual(confirmation["block_hash"], BH1)
        self.assertEqual(confirmation["confirmations"], 2)
        self.assertEqual(confirmation["state"], "confirming")

    def test_finalized_view(self):
        self._build_scene(confirmations=3)
        f = self.svc.get_chain_dispatch_finality("w1", "dp1")
        self.assertEqual(f["confirmation"]["state"], "finalized")
        self.assertEqual(f["confirmation"]["confirmations"], 3)

    def test_400_and_404(self):
        self._build_scene()
        for bad in ("bad id", "", 12, None):
            with self.assertRaises(ServiceError) as ctx:
                self.svc.get_chain_dispatch_finality("w1", bad)
            self.assertEqual(ctx.exception.status, 400, bad)
        with self.assertRaises(ServiceError) as ctx:
            self.svc.get_chain_dispatch_finality("w1", "nope")
        self.assertEqual(ctx.exception.status, 404)
        with self.assertRaises(ServiceError) as ctx:
            self.svc.get_chain_dispatch_finality("w9", "dp1")
        self.assertEqual(ctx.exception.status, 404)

    def test_finality_is_read_only(self):
        self._build_scene()
        before = self._events()
        self.assertEqual(
            self.h.store.list_asset_intents("w1"), []
        )
        f1 = self.svc.get_chain_dispatch_finality("w1", "dp1")
        f2 = self.svc.get_chain_dispatch_finality("w1", "dp1")
        self.assertEqual(f1, f2)
        self.assertEqual(self._events(), before)
        self.assertEqual(
            self.h.store.list_asset_intents("w1"), []
        )


# ---------------------------------------------------------------------------
# 服务层：settle
# ---------------------------------------------------------------------------

class SettleServiceTest(_SceneMixin, unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.d, ignore_errors=True)
        self.h = make_harness(self.d)
        self.svc = self.h.service

    def _settle(self, wallet="w1", dispatch_id="dp1"):
        try:
            return self.svc.settle_chain_dispatch(wallet, dispatch_id)
        except ServiceError as exc:
            return exc.status, {"error": exc.message}

    def test_confirming_409_without_side_effects(self):
        self._build_scene(confirmations=2)
        status, body = self._settle()
        self.assertEqual(status, 409)
        self.assertNotIn("state", body)
        self.assertEqual(
            self.h.store.get_asset_operation("w1", "op1")["state"], "pending"
        )
        self.assertEqual(
            self._events({"chain_dispatch_settled"}), []
        )

    def test_settle_201_view_and_events(self):
        self._build_scene()
        status, r = self._settle()
        self.assertEqual(status, 201)
        self.assertEqual(
            r,
            {
                "operation_id": "op1",
                "asset_id": "BTC",
                "delta": 100,
                "state": "committed",
                "balance": 100,
                "version": 1,
            },
        )
        self.assertEqual(
            self.h.store.get_asset_operation("w1", "op1")["state"],
            "committed",
        )
        events = self._events(
            {"chain_dispatch_settled", "asset_operation_committed"}
        )
        self.assertEqual(len(events), 2)
        settled, committed = events
        self.assertEqual(settled["seq"] + 1, committed["seq"])
        self.assertEqual(settled["type"], "chain_dispatch_settled")
        self.assertEqual(settled["request_id"], "dp1")
        self.assertEqual(settled["actor_id"], "ad1")
        self.assertIsNone(settled["reason"])
        self.assertEqual(
            list(settled["details"]), ["dispatch_id", "operation_id"]
        )
        self.assertEqual(
            settled["details"],
            {"dispatch_id": "dp1", "operation_id": "op1"},
        )
        self.assertEqual(committed["type"], "asset_operation_committed")
        self.assertEqual(committed["request_id"], "op1")
        self.assertEqual(committed["details"], r)
        # 落盘 details 键序保序
        with open(os.path.join(self.d, "audit", "w1.json"),
                  encoding="utf-8") as f:
            log = json.load(f)
        stored = [
            e for e in log["events"]
            if e["type"] == "chain_dispatch_settled"
        ][0]
        self.assertEqual(
            list(stored),
            ["actor_id", "at", "details", "reason", "request_id", "seq",
             "type"],
        )
        self.assertEqual(
            list(stored["details"]), ["dispatch_id", "operation_id"]
        )

    def test_replay_200_same_body_no_new_events(self):
        self._build_scene()
        status, r1 = self._settle()
        self.assertEqual(status, 201)
        events_before = self._events()
        status, r2 = self._settle()
        self.assertEqual(status, 200)
        self.assertEqual(r2, r1)
        self.assertEqual(self._events(), events_before)

    def test_insufficient_balance_409_no_side_effects(self):
        self._build_scene()
        # 另一笔支出派发：余额 0、delta=-1000，finalized 后结算必余额不足
        code, _ = self.svc.create_asset_operation("w1", "op2", "BTC", -1000)
        self.assertEqual(code, 201)
        code, _ = self.svc.create_sign_request(
            "w1", "ap2", _msg("op2", "dp2", "ad1")
        )
        self.assertEqual(code, 201)
        self.svc.approve("w1", "ap2", "boss")
        code, _ = self.svc.post_chain_dispatch(
            "w1", "op2", "dp2", "ad1", "ap2"
        )
        self.assertEqual(code, 201)
        code, _ = self.svc.post_chain_dispatch_result(
            "w1", "dp2", "ad1", "broadcasted", TX1
        )
        self.assertEqual(code, 201)
        code, _ = self.svc.post_chain_dispatch_confirmation(
            "w1", "dp2", "ad1", TX1, 10, BH1, 3
        )
        self.assertEqual(code, 201)
        status, _ = self._settle(dispatch_id="dp2")
        self.assertEqual(status, 409)
        self.assertEqual(
            self.h.store.get_asset_operation("w1", "op2")["state"], "pending"
        )
        self.assertEqual(self._events({"chain_dispatch_settled"}), [])
        self.assertEqual(
            self.h.store.get_asset("w1", "BTC"), None
        )

    def test_committed_elsewhere_409(self):
        self._build_scene()
        # 停用策略后人工提交 op1（别处已提交），再结算即 409
        self.svc.put_chain_policy("w1", "BTC", "chain-1", False, 3, 2)
        status, r = self.svc.commit_asset_operation("w1", "op1")
        self.assertEqual(status, 201)
        status, body = self._settle()
        self.assertEqual(status, 409)
        self.assertNotIn("version", body)

    def test_400_and_404(self):
        self._build_scene()
        for bad in ("bad id", "", 7, None):
            status, _ = self._settle(dispatch_id=bad)
            self.assertEqual(status, 400, bad)
        status, _ = self._settle(dispatch_id="nope")
        self.assertEqual(status, 404)
        status, _ = self._settle(wallet="w9")
        self.assertEqual(status, 404)

    def test_concurrent_only_one_201(self):
        self._build_scene()
        results = []
        barrier = threading.Barrier(8)
        lock = threading.Lock()

        def worker():
            barrier.wait()
            status, r = self._settle()
            with lock:
                results.append(status)

        threads = [threading.Thread(target=worker) for _ in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(sorted(results).count(201), 1)
        self.assertEqual(sorted(results).count(200), 7)
        # 只有一对事件
        self.assertEqual(
            len(self._events({"chain_dispatch_settled"})), 1
        )

    def test_restart_preserves_settlement(self):
        self._build_scene()
        status, r = self._settle()
        self.assertEqual(status, 201)
        events_before = self._events()
        h2 = make_harness(self.d)
        status, r2 = h2.service.settle_chain_dispatch("w1", "dp1")
        self.assertEqual(status, 200)
        self.assertEqual(r2, r)
        self.assertEqual(
            [
                (e["type"], e["seq"])
                for e in h2.service.get_audit_events("w1")["events"]
            ],
            [(e["type"], e["seq"]) for e in events_before],
        )

    def test_event_write_failure_rolls_back_and_is_retryable(self):
        self._build_scene()
        original = self.svc._audit.append_events

        def boom(*args, **kwargs):
            raise OSError("simulated write failure")

        self.svc._audit.append_events = boom
        with self.assertRaises(OSError):
            self.svc.settle_chain_dispatch("w1", "dp1")
        self.svc._audit.append_events = original
        # 俱无回滚：操作仍 pending、无事件、无意图残留
        self.assertEqual(
            self.h.store.get_asset_operation("w1", "op1")["state"], "pending"
        )
        self.assertEqual(self._events({"chain_dispatch_settled"}), [])
        self.assertEqual(
            self.h.store.list_asset_intents("w1"), []
        )
        # 可重试：两事件俱在前滚
        status, r = self._settle()
        self.assertEqual(status, 201)
        self.assertEqual(r["state"], "committed")

    def test_isolated_settled_event_is_unreconcilable(self):
        self._build_scene()
        status, _ = self._settle()
        self.assertEqual(status, 201)
        # 删掉紧邻的 committed 事件：孤立结算事件即矛盾现场
        path = os.path.join(self.d, "audit", "w1.json")
        with open(path, encoding="utf-8") as f:
            log = json.load(f)
        log["events"] = [
            e for e in log["events"]
            if not (
                e["type"] == "asset_operation_committed"
                and e["request_id"] == "op1"
            )
        ]
        log["next_seq"] = len(log["events"]) + 1
        with open(path, "w", encoding="utf-8") as f:
            json.dump(log, f)
        with self.assertRaises(RecoveryError):
            make_harness(self.d)
        # 现有进程持锁访问同样 fail-closed
        with self.assertRaises(RecoveryError):
            self.svc.settle_chain_dispatch("w1", "dp1")

    def test_settled_details_out_of_order_is_unreconcilable(self):
        self._build_scene()
        status, _ = self._settle()
        self.assertEqual(status, 201)
        path = os.path.join(self.d, "audit", "w1.json")
        with open(path, encoding="utf-8") as f:
            log = json.load(f)
        for e in log["events"]:
            if e["type"] == "chain_dispatch_settled":
                e["details"] = {
                    "operation_id": "op1",
                    "dispatch_id": "dp1",
                }
        with open(path, "w", encoding="utf-8") as f:
            json.dump(log, f)
        with self.assertRaises(RecoveryError):
            make_harness(self.d)


# ---------------------------------------------------------------------------
# HTTP 层
# ---------------------------------------------------------------------------

class SettleHttpTest(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.d, ignore_errors=True)
        self._cm = http_server(self.d)
        self.srv = self._cm.__enter__()
        self.addCleanup(self._cm.__exit__, None, None, None)
        self.svc = self.srv.harness.service
        self._build_scene()

    def _build_scene(self, confirmations=3):
        svc = self.svc
        svc.create_wallet("w1", 2)
        svc.put_policy("w1", 1, 600)
        code, _ = svc.create_asset_operation("w1", "op1", "BTC", 100)
        self.assertEqual(code, 201)
        svc.put_chain_policy("w1", "BTC", "chain-1", True, 3, 2)
        code, _ = svc.create_sign_request("w1", "ap1", _msg())
        self.assertEqual(code, 201)
        svc.approve("w1", "ap1", "boss")
        code, _ = svc.post_chain_dispatch("w1", "op1", "dp1", "ad1", "ap1")
        self.assertEqual(code, 201)
        code, _ = svc.post_chain_dispatch_result(
            "w1", "dp1", "ad1", "broadcasted", TX1
        )
        self.assertEqual(code, 201)
        code, _ = svc.post_chain_dispatch_confirmation(
            "w1", "dp1", "ad1", TX1, 10, BH1, confirmations
        )
        self.assertEqual(code, 201)

    def _raw(self, method, path, raw):
        headers = {"Accept": "application/json"}
        if raw is not None:
            headers["Content-Type"] = "application/json"
        req = urllib.request.Request(
            self.srv.base_url + path, data=raw, method=method, headers=headers
        )
        try:
            with urllib.request.urlopen(req) as resp:
                return resp.status, resp.read()
        except urllib.error.HTTPError as exc:
            return exc.code, exc.read()

    def test_finality_http(self):
        status, body = self.srv.request(
            "GET", "/v1/wallets/w1/chain/dp1/finality"
        )
        self.assertEqual(status, 200)
        self.assertEqual(list(body), ["operation_id", "chain_id", "confirmation"])
        self.assertEqual(body["confirmation"]["state"], "finalized")

    def test_finality_409_when_no_confirmation(self):
        svc = self.svc
        code, _ = svc.create_asset_operation("w1", "op2", "BTC", 5)
        self.assertEqual(code, 201)
        code, _ = svc.create_sign_request(
            "w1", "ap2", _msg("op2", "dp2", "ad1")
        )
        self.assertEqual(code, 201)
        svc.approve("w1", "ap2", "boss")
        code, _ = svc.post_chain_dispatch(
            "w1", "op2", "dp2", "ad1", "ap2"
        )
        self.assertEqual(code, 201)
        code, _ = svc.post_chain_dispatch_result(
            "w1", "dp2", "ad1", "broadcasted", TX1
        )
        self.assertEqual(code, 201)
        status, body = self.srv.request(
            "GET", "/v1/wallets/w1/chain/dp2/finality"
        )
        self.assertEqual(status, 409)
        # 错误体紧凑且不泄露内部细节
        self.assertEqual(list(body), ["error"])

    def test_settle_empty_body_201_and_replay_200(self):
        status, raw = self._raw(
            "POST", "/v1/wallets/w1/chain/dp1/settle", None
        )
        self.assertEqual(status, 201)
        first = json.loads(raw)
        self.assertEqual(first["state"], "committed")
        self.assertEqual(first["balance"], 100)
        status, raw = self._raw(
            "POST", "/v1/wallets/w1/chain/dp1/settle", b""
        )
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(raw), first)

    def test_settle_non_empty_body_400(self):
        for raw in (b"{}", b'{"x":1}', b"null", b"[]", b"junk"):
            status, body = self._raw(
                "POST", "/v1/wallets/w1/chain/dp1/settle", raw
            )
            self.assertEqual(status, 400, raw)
            self.assertEqual(list(json.loads(body)), ["error"])
        # 400 无副作用：仍可空体首提 201
        status, _ = self._raw(
            "POST", "/v1/wallets/w1/chain/dp1/settle", None
        )
        self.assertEqual(status, 201)

    def test_settle_confirming_409(self):
        d2 = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d2, ignore_errors=True)
        with http_server(d2) as srv2:
            svc = srv2.harness.service
            svc.create_wallet("w1", 2)
            svc.put_policy("w1", 1, 600)
            svc.create_asset_operation("w1", "op1", "BTC", 100)
            svc.put_chain_policy("w1", "BTC", "chain-1", True, 3, 2)
            code, _ = svc.create_sign_request("w1", "ap1", _msg())
            self.assertEqual(code, 201)
            svc.approve("w1", "ap1", "boss")
            svc.post_chain_dispatch("w1", "op1", "dp1", "ad1", "ap1")
            svc.post_chain_dispatch_result(
                "w1", "dp1", "ad1", "broadcasted", TX1
            )
            svc.post_chain_dispatch_confirmation(
                "w1", "dp1", "ad1", TX1, 10, BH1, 2
            )
            status, body = srv2.request(
                "POST", "/v1/wallets/w1/chain/dp1/settle"
            )
            self.assertEqual(status, 409)
            self.assertEqual(list(body), ["error"])

    def test_404_and_400_http(self):
        status, _ = self.srv.request(
            "POST", "/v1/wallets/w1/chain/nope/settle"
        )
        self.assertEqual(status, 404)
        status, _ = self.srv.request(
            "POST", "/v1/wallets/w9/chain/dp1/settle"
        )
        self.assertEqual(status, 404)
        status, raw = self._raw(
            "POST", "/v1/wallets/w1/chain/bad%20id/settle", None
        )
        self.assertEqual(status, 400)

    def test_other_methods_and_finality_post_404(self):
        status, _ = self.srv.request(
            "GET", "/v1/wallets/w1/chain/dp1/settle"
        )
        self.assertEqual(status, 404)
        status, _ = self.srv.request(
            "PUT", "/v1/wallets/w1/chain/dp1/settle", {}
        )
        self.assertEqual(status, 404)
        status, _ = self.srv.request(
            "POST", "/v1/wallets/w1/chain/dp1/finality"
        )
        self.assertEqual(status, 404)

    def test_wire_compact_no_trailing_newline(self):
        status, raw = self._raw(
            "GET", "/v1/wallets/w1/chain/dp1/finality", None
        )
        self.assertEqual(status, 200)
        self.assertNotIn(b": ", raw)
        self.assertFalse(raw.endswith(b"\n"))
        self.assertTrue(raw.startswith(b'{"operation_id":"op1",'))
        status, raw = self._raw(
            "POST", "/v1/wallets/w1/chain/dp1/settle", None
        )
        self.assertEqual(status, 201)
        self.assertNotIn(b": ", raw)
        self.assertNotIn(b", ", raw)
        self.assertFalse(raw.endswith(b"\n"))

    def test_503_on_corrupt_scene(self):
        status, _ = self._raw(
            "POST", "/v1/wallets/w1/chain/dp1/settle", None
        )
        self.assertEqual(status, 201)
        path = os.path.join(self.d, "audit", "w1.json")
        with open(path, encoding="utf-8") as f:
            log = json.load(f)
        # 孤立结算事件：删除紧邻提交事件
        log["events"] = [
            e for e in log["events"]
            if not (
                e["type"] == "asset_operation_committed"
                and e["request_id"] == "op1"
            )
        ]
        log["next_seq"] = len(log["events"]) + 1
        with open(path, "w", encoding="utf-8") as f:
            json.dump(log, f)
        status, raw = self._raw(
            "GET", "/v1/wallets/w1/chain/dp1/finality", None
        )
        self.assertEqual(status, 503)
        body = json.loads(raw)
        self.assertEqual(list(body), ["error"])
        self.assertNotIn("dp1", json.dumps(body))


if __name__ == "__main__":
    unittest.main()
