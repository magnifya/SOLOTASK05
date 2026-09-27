"""跨链派发接管（POST /v1/wallets/{W}/chain/{D}/takeover）测试。

覆盖：
- 请求体恰含 adapter_id/approval_request_id 两安全标识键，键集/值错
  400；钱包/派发/审批未知 404；
- 首提前置：操作 pending、结果为 failed 且未接管、adapter_id 须变化、
  审批单同钱包 approved 且 message 逐字为按 dispatch_id,adapter_id 序
  的紧凑 JSON，任一不满足 409 且零副作用；
- 成功 201 返回 {dispatch_id,adapter_id,state:requested}（键序固定）；
  同参重放 200 同体不记事件，异参或再次接管 409；
- chain_dispatch_taken_over 为唯一提交点（request_id=D、
  actor_id=approval_request_id、reason=null、details=V），锁内并发
  只有一个 201；
- 接管后 result 只接受新适配器一次结果、confirm 只承接 broadcasted
  交易；finality/settle 沿用接管后的新归属；
- 重启/恢复按 seq 复核派发、failed、审批、接管与事件；矛盾现场
  RecoveryError（HTTP 503），重放不记事件。
"""

from __future__ import annotations

import json
import os
import shutil
import tempfile
import threading
import unittest

from threshold_wallet.service import ServiceError, WalletService
from threshold_wallet.store import RecoveryError

from tests.helpers import http_server, make_harness

TX1 = "ab" * 32
TX2 = "cd" * 32
BH1 = "01" * 32
BH2 = "02" * 32


def _dispatch_msg(operation_id="op1", dispatch_id="dp1", adapter_id="ad1",
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


def _takeover_msg(dispatch_id="dp1", adapter_id="ad2"):
    return json.dumps(
        {"dispatch_id": dispatch_id, "adapter_id": adapter_id},
        ensure_ascii=False,
        separators=(",", ":"),
    )


class _SceneMixin:
    """建钱包/策略/审批/派发/failed 结果的共用装配。"""

    def _build_failed(self):
        self.svc.create_wallet("w1", 2)
        self.svc.put_policy("w1", 1, 600)
        code, _ = self.svc.create_asset_operation("w1", "op1", "BTC", 100)
        self.assertEqual(code, 201)
        self.svc.put_chain_policy("w1", "BTC", "chain-1", True, 3, 2)
        code, _ = self.svc.create_sign_request(
            "w1", "ap1", _dispatch_msg()
        )
        self.assertEqual(code, 201)
        self.svc.approve("w1", "ap1", "boss")
        code, _ = self.svc.post_chain_dispatch(
            "w1", "op1", "dp1", "ad1", "ap1"
        )
        self.assertEqual(code, 201)
        code, _ = self.svc.post_chain_dispatch_result(
            "w1", "dp1", "ad1", "failed", None
        )
        self.assertEqual(code, 201)
        code, _ = self.svc.create_sign_request(
            "w1", "ap2", _takeover_msg("dp1", "ad2")
        )
        self.assertEqual(code, 201)
        self.svc.approve("w1", "ap2", "boss")

    def _takeover(self, wallet="w1", dispatch_id="dp1", adapter_id="ad2",
                  approval="ap2"):
        try:
            return self.svc.post_chain_dispatch_takeover(
                wallet, dispatch_id, adapter_id, approval
            )
        except ServiceError as exc:
            return exc.status, {"error": exc.message}

    def _events(self, types=None):
        events = self.svc.get_audit_events("w1")["events"]
        if types is None:
            return events
        return [e for e in events if e["type"] in types]


class TakeoverServiceTest(_SceneMixin, unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.d, ignore_errors=True)
        self.h = make_harness(self.d)
        self.svc = self.h.service

    def test_takeover_201_view_and_event(self):
        self._build_failed()
        status, v = self._takeover()
        self.assertEqual(status, 201)
        self.assertEqual(list(v), ["dispatch_id", "adapter_id", "state"])
        self.assertEqual(
            v,
            {"dispatch_id": "dp1", "adapter_id": "ad2",
             "state": "requested"},
        )
        events = self._events({"chain_dispatch_taken_over"})
        self.assertEqual(len(events), 1)
        event = events[0]
        self.assertEqual(event["request_id"], "dp1")
        self.assertEqual(event["actor_id"], "ap2")
        self.assertIsNone(event["reason"])
        self.assertEqual(event["details"], v)
        # 落盘外层七字段规范序、details 恰为 dispatch_id,adapter_id,state
        with open(os.path.join(self.d, "audit", "w1.json"),
                  encoding="utf-8") as f:
            log = json.load(f)
        stored = [
            e for e in log["events"]
            if e["type"] == "chain_dispatch_taken_over"
        ][0]
        self.assertEqual(
            list(stored),
            ["actor_id", "at", "details", "reason", "request_id", "seq",
             "type"],
        )
        self.assertEqual(
            list(stored["details"]),
            ["dispatch_id", "adapter_id", "state"],
        )

    def test_replay_200_same_body_no_new_events(self):
        self._build_failed()
        status, v1 = self._takeover()
        self.assertEqual(status, 201)
        events_before = self._events()
        status, v2 = self._takeover()
        self.assertEqual(status, 200)
        self.assertEqual(v2, v1)
        self.assertEqual(self._events(), events_before)

    def test_different_params_and_second_takeover_409(self):
        self._build_failed()
        status, _ = self._takeover()
        self.assertEqual(status, 201)
        events_before = self._events()
        # 换适配器
        self.assertEqual(self._takeover(adapter_id="ad3")[0], 409)
        # 换审批单
        self.assertEqual(self._takeover(approval="ap1")[0], 409)
        # 再次接管一律 409，零副作用
        self.assertEqual(self._events(), events_before)
        self.assertEqual(
            len(self._events({"chain_dispatch_taken_over"})), 1
        )

    def test_400_on_invalid_ids(self):
        self._build_failed()
        for kwargs in (
            {"dispatch_id": "bad id"},
            {"adapter_id": ""},
            {"adapter_id": "x" * 129},
            {"approval": "bad id"},
            {"adapter_id": 1},
        ):
            status, _ = self._takeover(**kwargs)
            self.assertEqual(status, 400, kwargs)
        self.assertEqual(self._events({"chain_dispatch_taken_over"}), [])

    def test_404_unknown_wallet_dispatch_approval(self):
        self._build_failed()
        self.assertEqual(self._takeover(wallet="nope")[0], 404)
        self.assertEqual(self._takeover(dispatch_id="nope")[0], 404)
        self.assertEqual(self._takeover(approval="nope")[0], 404)
        self.assertEqual(self._events({"chain_dispatch_taken_over"}), [])

    def test_409_when_result_not_failed(self):
        self.svc.create_wallet("w1", 2)
        self.svc.put_policy("w1", 1, 600)
        self.svc.create_asset_operation("w1", "op1", "BTC", 100)
        self.svc.put_chain_policy("w1", "BTC", "chain-1", True, 3, 2)
        self.svc.create_sign_request("w1", "ap1", _dispatch_msg())
        self.svc.approve("w1", "ap1", "boss")
        self.svc.post_chain_dispatch("w1", "op1", "dp1", "ad1", "ap1")
        self.svc.create_sign_request("w1", "ap2", _takeover_msg("dp1", "ad2"))
        self.svc.approve("w1", "ap2", "boss")
        # 尚无结果：409
        self.assertEqual(self._takeover()[0], 409)
        # broadcasted 结果：409
        self.svc.post_chain_dispatch_result(
            "w1", "dp1", "ad1", "broadcasted", TX1
        )
        self.assertEqual(self._takeover()[0], 409)
        self.assertEqual(self._events({"chain_dispatch_taken_over"}), [])

    def test_409_when_operation_not_pending(self):
        self._build_failed()
        # 链上确认达门槛自动提交源操作
        status, _ = self.svc.post_chain_report(
            "w1", "op1", "chain-1", TX1, 10, BH1, 3
        )
        self.assertEqual(status, 201)
        self.assertEqual(
            self.h.store.get_asset_operation("w1", "op1")["state"],
            "committed",
        )
        self.assertEqual(self._takeover()[0], 409)
        self.assertEqual(self._events({"chain_dispatch_taken_over"}), [])

    def test_409_when_adapter_unchanged(self):
        self._build_failed()
        self.svc.create_sign_request(
            "w1", "ap3", _takeover_msg("dp1", "ad1")
        )
        self.svc.approve("w1", "ap3", "boss")
        self.assertEqual(
            self._takeover(adapter_id="ad1", approval="ap3")[0], 409
        )
        self.assertEqual(self._events({"chain_dispatch_taken_over"}), [])

    def test_409_on_approval_state_and_message(self):
        self._build_failed()
        # 审批单 pending
        self.svc.create_sign_request(
            "w1", "ap4", _takeover_msg("dp1", "ad3")
        )
        self.assertEqual(
            self._takeover(adapter_id="ad3", approval="ap4")[0], 409
        )
        # message 不符（键序不同/内容不同）
        self.svc.create_sign_request("w1", "ap5", "other-message")
        self.svc.approve("w1", "ap5", "boss")
        self.assertEqual(self._takeover(approval="ap5")[0], 409)
        self.svc.create_sign_request(
            "w1", "ap6",
            json.dumps({"adapter_id": "ad2", "dispatch_id": "dp1"},
                       separators=(",", ":")),
        )
        self.svc.approve("w1", "ap6", "boss")
        self.assertEqual(self._takeover(approval="ap6")[0], 409)
        self.assertEqual(self._events({"chain_dispatch_taken_over"}), [])

    def test_result_after_takeover_only_new_adapter_once(self):
        self._build_failed()
        self.assertEqual(self._takeover()[0], 201)
        # 旧适配器新结果 409；旧 failed 同参重放仍 200
        with self.assertRaises(ServiceError) as ctx:
            self.svc.post_chain_dispatch_result(
                "w1", "dp1", "ad1", "broadcasted", TX1
            )
        self.assertEqual(ctx.exception.status, 409)
        code, v = self.svc.post_chain_dispatch_result(
            "w1", "dp1", "ad1", "failed", None
        )
        self.assertEqual(code, 200)
        self.assertEqual(v["state"], "failed")
        # 新适配器一次结果 201（六键 V 归属新适配器）
        code, v = self.svc.post_chain_dispatch_result(
            "w1", "dp1", "ad2", "broadcasted", TX1
        )
        self.assertEqual(code, 201)
        self.assertEqual(
            list(v),
            ["dispatch_id", "operation_id", "adapter_id", "chain_id",
             "state", "tx_id"],
        )
        self.assertEqual(v["adapter_id"], "ad2")
        self.assertEqual(v["operation_id"], "op1")
        # 同参重放 200；第二条新结果（异参）409
        code, v2 = self.svc.post_chain_dispatch_result(
            "w1", "dp1", "ad2", "broadcasted", TX1
        )
        self.assertEqual(code, 200)
        self.assertEqual(v2, v)
        with self.assertRaises(ServiceError) as ctx:
            self.svc.post_chain_dispatch_result(
                "w1", "dp1", "ad2", "failed", None
            )
        self.assertEqual(ctx.exception.status, 409)

    def test_confirm_finality_settle_after_takeover(self):
        self._build_failed()
        self.assertEqual(self._takeover()[0], 201)
        # 接管后无 broadcasted 结果：confirm 409
        with self.assertRaises(ServiceError) as ctx:
            self.svc.post_chain_dispatch_confirmation(
                "w1", "dp1", "ad2", TX1, 10, BH1, 3
            )
        self.assertEqual(ctx.exception.status, 409)
        self.svc.post_chain_dispatch_result(
            "w1", "dp1", "ad2", "broadcasted", TX1
        )
        # 旧适配器 confirm 409；新适配器 201
        with self.assertRaises(ServiceError) as ctx:
            self.svc.post_chain_dispatch_confirmation(
                "w1", "dp1", "ad1", TX1, 10, BH1, 3
            )
        self.assertEqual(ctx.exception.status, 409)
        code, v = self.svc.post_chain_dispatch_confirmation(
            "w1", "dp1", "ad2", TX1, 10, BH1, 3
        )
        self.assertEqual(code, 201)
        self.assertEqual(v["state"], "finalized")
        f = self.svc.get_chain_dispatch_finality("w1", "dp1")
        self.assertEqual(f["confirmation"]["adapter_id"], "ad2")
        code, r = self.svc.settle_chain_dispatch("w1", "dp1")
        self.assertEqual(code, 201)
        self.assertEqual(r["state"], "committed")
        self.assertEqual(r["balance"], 100)

    def test_settle_and_reorg_after_takeover_survive_restart(self):
        self._build_failed()
        self.assertEqual(self._takeover()[0], 201)
        self.svc.post_chain_dispatch_result(
            "w1", "dp1", "ad2", "broadcasted", TX1
        )
        self.svc.post_chain_dispatch_confirmation(
            "w1", "dp1", "ad2", TX1, 10, BH1, 3
        )
        code, _ = self.svc.settle_chain_dispatch("w1", "dp1")
        self.assertEqual(code, 201)
        # 结算/重组事件的归属适配器为接管后的新适配器
        for event in self._events(
            {"chain_dispatch_settled"}
        ):
            self.assertEqual(event["actor_id"], "ad2")
        # 已结算派发的重组补偿：新适配器上报
        code, v = self.svc.post_chain_dispatch_confirmation(
            "w1", "dp1", "ad2", TX1, 9, BH2, 1
        )
        self.assertEqual(code, 201)
        self.assertEqual(v["state"], "reorged")
        for event in self._events({"chain_dispatch_reorged"}):
            self.assertEqual(event["actor_id"], "ad2")
        # 重启恢复可对账；重组同体重放 200
        h2 = make_harness(self.d)
        code, v2 = h2.service.post_chain_dispatch_confirmation(
            "w1", "dp1", "ad2", TX1, 9, BH2, 1
        )
        self.assertEqual(code, 200)
        self.assertEqual(v2, v)

    def test_concurrent_only_one_201(self):
        self._build_failed()
        results = []
        barrier = threading.Barrier(8)
        lock = threading.Lock()

        def worker():
            barrier.wait()
            status, _ = self._takeover()
            with lock:
                results.append(status)

        threads = [threading.Thread(target=worker) for _ in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(sorted(results).count(201), 1)
        self.assertEqual(sorted(results).count(200), 7)
        self.assertEqual(
            len(self._events({"chain_dispatch_taken_over"})), 1
        )

    def test_restart_preserves_takeover(self):
        self._build_failed()
        status, v1 = self._takeover()
        self.assertEqual(status, 201)
        self.svc.post_chain_dispatch_result(
            "w1", "dp1", "ad2", "broadcasted", TX1
        )
        events_before = self._events()
        h2 = make_harness(self.d)
        # 重放 200 同体、不记事件；结果重放 200
        status, v2 = h2.service.post_chain_dispatch_takeover(
            "w1", "dp1", "ad2", "ap2"
        )
        self.assertEqual(status, 200)
        self.assertEqual(v2, v1)
        code, _ = h2.service.post_chain_dispatch_result(
            "w1", "dp1", "ad2", "broadcasted", TX1
        )
        self.assertEqual(code, 200)
        self.assertEqual(
            [
                (e["type"], e["seq"])
                for e in h2.service.get_audit_events("w1")["events"]
            ],
            [(e["type"], e["seq"]) for e in events_before],
        )

    def _rewrite_events(self, transform):
        path = os.path.join(self.d, "audit", "w1.json")
        with open(path, encoding="utf-8") as f:
            log = json.load(f)
        log["events"] = [
            transform(e) for e in log["events"]
        ]
        log["events"] = [e for e in log["events"] if e is not None]
        log["next_seq"] = len(log["events"]) + 1
        with open(path, "w", encoding="utf-8") as f:
            json.dump(log, f)

    def test_takeover_details_out_of_order_is_unreconcilable(self):
        self._build_failed()
        self.assertEqual(self._takeover()[0], 201)

        def reorder(e):
            if e["type"] == "chain_dispatch_taken_over":
                e["details"] = {
                    "adapter_id": "ad2",
                    "dispatch_id": "dp1",
                    "state": "requested",
                }
            return e

        self._rewrite_events(reorder)
        with self.assertRaises(RecoveryError):
            make_harness(self.d)

    def test_orphan_takeover_event_is_unreconcilable(self):
        self._build_failed()
        self.assertEqual(self._takeover()[0], 201)
        # 删掉派发请求事件：接管缺失前置派发即矛盾现场
        self._rewrite_events(
            lambda e: None
            if e["type"] == "chain_dispatch_requested"
            else e
        )
        with self.assertRaises(RecoveryError):
            make_harness(self.d)

    def test_takeover_without_failed_result_is_unreconcilable(self):
        self._build_failed()
        self.assertEqual(self._takeover()[0], 201)
        # 删掉 failed 结果事件：接管缺失 failed 前置即矛盾现场
        self._rewrite_events(
            lambda e: None
            if e["type"] == "chain_dispatch_result"
            else e
        )
        with self.assertRaises(RecoveryError):
            make_harness(self.d)

    def test_second_result_without_takeover_is_unreconcilable(self):
        self._build_failed()
        self.assertEqual(self._takeover()[0], 201)
        self.svc.post_chain_dispatch_result(
            "w1", "dp1", "ad2", "broadcasted", TX1
        )
        # 删掉接管事件：第二条结果缺失接管前置即矛盾现场
        self._rewrite_events(
            lambda e: None
            if e["type"] == "chain_dispatch_taken_over"
            else e
        )
        with self.assertRaises(RecoveryError):
            make_harness(self.d)

    def test_duplicate_takeover_event_is_unreconcilable(self):
        self._build_failed()
        self.assertEqual(self._takeover()[0], 201)
        path = os.path.join(self.d, "audit", "w1.json")
        with open(path, encoding="utf-8") as f:
            log = json.load(f)
        dup = None
        for e in log["events"]:
            if e["type"] == "chain_dispatch_taken_over":
                dup = dict(e)
                dup["details"] = dict(e["details"])
        dup["seq"] = len(log["events"]) + 1
        log["events"].append(dup)
        log["next_seq"] = len(log["events"]) + 1
        with open(path, "w", encoding="utf-8") as f:
            json.dump(log, f)
        with self.assertRaises(RecoveryError):
            make_harness(self.d)


class TakeoverHttpTest(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.d, ignore_errors=True)
        self._cm = http_server(self.d)
        self.srv = self._cm.__enter__()
        self.addCleanup(self._cm.__exit__, None, None, None)
        self.svc = self.srv.harness.service
        svc = self.svc
        svc.create_wallet("w1", 2)
        svc.put_policy("w1", 1, 600)
        svc.create_asset_operation("w1", "op1", "BTC", 100)
        svc.put_chain_policy("w1", "BTC", "chain-1", True, 3, 2)
        svc.create_sign_request("w1", "ap1", _dispatch_msg())
        svc.approve("w1", "ap1", "boss")
        svc.post_chain_dispatch("w1", "op1", "dp1", "ad1", "ap1")
        svc.post_chain_dispatch_result("w1", "dp1", "ad1", "failed", None)
        svc.create_sign_request("w1", "ap2", _takeover_msg("dp1", "ad2"))
        svc.approve("w1", "ap2", "boss")

    def _takeover(self, body, wallet="w1", dispatch_id="dp1"):
        return self.srv.request(
            "POST", f"/v1/wallets/{wallet}/chain/{dispatch_id}/takeover",
            body,
        )

    def test_http_201_replay_200_and_conflicts(self):
        # 未知派发/审批（首提）404
        body = {"adapter_id": "ad2", "approval_request_id": "ap2"}
        status, _ = self._takeover(body, dispatch_id="nope")
        self.assertEqual(status, 404)
        status, _ = self._takeover(
            {"adapter_id": "ad2", "approval_request_id": "nope"}
        )
        self.assertEqual(status, 404)
        status, v = self._takeover(body)
        self.assertEqual(status, 201)
        self.assertEqual(
            list(v), ["dispatch_id", "adapter_id", "state"]
        )
        self.assertEqual(
            v,
            {"dispatch_id": "dp1", "adapter_id": "ad2",
             "state": "requested"},
        )
        status, v2 = self._takeover(body)
        self.assertEqual(status, 200)
        self.assertEqual(v2, v)
        # 异参（含更换审批单）或再次接管一律 409
        status, err = self._takeover(
            {"adapter_id": "ad3", "approval_request_id": "ap2"}
        )
        self.assertEqual(status, 409)
        self.assertEqual(list(err), ["error"])
        status, _ = self._takeover(
            {"adapter_id": "ad2", "approval_request_id": "ap1"}
        )
        self.assertEqual(status, 409)

    def test_http_400_on_bad_body(self):
        # 缺键/多键一律 400
        for body in (
            {"adapter_id": "ad2"},
            {"approval_request_id": "ap2"},
            {"adapter_id": "ad2", "approval_request_id": "ap2",
             "extra": "x"},
            {"adapter_id": "bad id", "approval_request_id": "ap2"},
        ):
            status, err = self._takeover(body)
            self.assertEqual(status, 400, body)
            self.assertEqual(list(err), ["error"])

    def test_http_result_and_confirm_after_takeover(self):
        status, _ = self._takeover(
            {"adapter_id": "ad2", "approval_request_id": "ap2"}
        )
        self.assertEqual(status, 201)
        status, v = self.srv.request(
            "POST", "/v1/wallets/w1/chain/dp1/result",
            {"adapter_id": "ad2", "state": "broadcasted", "tx_id": TX1},
        )
        self.assertEqual(status, 201)
        self.assertEqual(v["adapter_id"], "ad2")
        status, v = self.srv.request(
            "POST", "/v1/wallets/w1/chain/dp1/confirm",
            {"adapter_id": "ad2", "tx_id": TX1, "block_height": 10,
             "block_hash": BH1, "confirmations": 3},
        )
        self.assertEqual(status, 201)
        self.assertEqual(v["state"], "finalized")
        status, r = self.srv.request(
            "POST", "/v1/wallets/w1/chain/dp1/settle"
        )
        self.assertEqual(status, 201)
        self.assertEqual(r["state"], "committed")

    def test_503_on_corrupt_scene(self):
        status, _ = self._takeover(
            {"adapter_id": "ad2", "approval_request_id": "ap2"}
        )
        self.assertEqual(status, 201)
        # 删掉 failed 结果事件：接管缺失前置即矛盾现场
        path = os.path.join(self.d, "audit", "w1.json")
        with open(path, encoding="utf-8") as f:
            log = json.load(f)
        log["events"] = [
            e for e in log["events"]
            if e["type"] != "chain_dispatch_result"
        ]
        log["next_seq"] = len(log["events"]) + 1
        with open(path, "w", encoding="utf-8") as f:
            json.dump(log, f)
        status, err = self._takeover(
            {"adapter_id": "ad2", "approval_request_id": "ap2"}
        )
        self.assertEqual(status, 503)
        self.assertEqual(list(err), ["error"])
        self.assertNotIn("dp1", json.dumps(err))


if __name__ == "__main__":
    unittest.main()
