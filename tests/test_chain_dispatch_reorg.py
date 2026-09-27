"""已结算跨链派发的链上重组与反向补偿
（POST /v1/wallets/{W}/chain/{D}/confirm 在 settled 之后的新语义）测试。

覆盖：
- settle 的 201/200 之 R 键序统一为
  operation_id,asset_id,delta,state,balance,version；
- 已结算（settled）后 confirm 仅接受 adapter 匹配且"tx_id 改变，或换块、
  confirmations 低于阈值且高度回退 <= reorg_window"的新 B；历史同体仍
  200（含 finalized 历史 B 与 reorged B），异体 409；
- 接受新 B 时以 D 为 operation_id 创建同资产、反向 delta、state=reorged
  的补偿操作，201 返回 confirm 既有 V（state=reorged）；ID 占用或余额将
  负为 409 且零副作用；锁内并发仅一个 201；
- 锁内原子追加连续的 chain_dispatch_confirmation、
  chain_dispatch_reorged、asset_operation_committed（request_id=D、
  actor_id=adapter_id、reason=null），三者俱在前滚、俱无回滚；残缺/矛盾
  抛 RecoveryError、坏 JSON 抛 CorruptDataError，留现场；
- 恢复/灾备/重放不增事件。
"""

from __future__ import annotations

import json
import os
import shutil
import tempfile
import threading
import unittest

from threshold_wallet.service import ServiceError, WalletService
from threshold_wallet.store import CorruptDataError, RecoveryError

from tests.helpers import http_server, make_harness

TX1 = "ab" * 32
BH1 = "01" * 32
TX2 = "cd" * 32
BH2 = "02" * 32

R_KEYS = ["operation_id", "asset_id", "delta", "state", "balance", "version"]
V_KEYS = [
    "dispatch_id",
    "adapter_id",
    "tx_id",
    "block_height",
    "block_hash",
    "confirmations",
    "state",
]


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


class ReorgSceneMixin:
    """装配：钱包/策略/审批/派发/播链/达门槛确认/结算。"""

    def _build_scene(self, svc=None, delta=100, confirmations=3):
        s = svc or self.svc
        s.create_wallet("w1", 2)
        s.put_policy("w1", 1, 600)
        code, _ = s.create_asset_operation("w1", "op1", "BTC", delta)
        self.assertEqual(code, 201)
        s.put_chain_policy("w1", "BTC", "chain-1", True, 3, 2)
        code, _ = s.create_sign_request("w1", "ap1", _msg())
        self.assertEqual(code, 201)
        s.approve("w1", "ap1", "boss")
        code, _ = s.post_chain_dispatch("w1", "op1", "dp1", "ad1", "ap1")
        self.assertEqual(code, 201)
        code, _ = s.post_chain_dispatch_result(
            "w1", "dp1", "ad1", "broadcasted", TX1
        )
        self.assertEqual(code, 201)
        code, _ = s.post_chain_dispatch_confirmation(
            "w1", "dp1", "ad1", TX1, 10, BH1, confirmations
        )
        self.assertEqual(code, 201)
        code, r = s.settle_chain_dispatch("w1", "dp1")
        self.assertEqual(code, 201)
        return r

    def _reorg(self, svc=None, tx_id=TX2, height=9, block_hash=BH2,
               confirmations=1, adapter="ad1"):
        s = svc or self.svc
        return s.post_chain_dispatch_confirmation(
            "w1", "dp1", adapter, tx_id, height, block_hash, confirmations
        )

    def _events(self, svc=None, types=None):
        s = svc or self.svc
        events = s.get_audit_events("w1")["events"]
        if types is None:
            return events
        return [e for e in events if e["type"] in types]


class SettleKeyOrderTest(ReorgSceneMixin, unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.d, ignore_errors=True)
        self.h = make_harness(self.d)
        self.svc = self.h.service

    def test_settle_r_key_order_201_and_200(self):
        r = self._build_scene()
        self.assertEqual(list(r), R_KEYS)
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
        code, r2 = self.svc.settle_chain_dispatch("w1", "dp1")
        self.assertEqual(code, 200)
        self.assertEqual(list(r2), R_KEYS)
        self.assertEqual(r2, r)


class ReorgConfirmServiceTest(ReorgSceneMixin, unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.d, ignore_errors=True)
        self.h = make_harness(self.d)
        self.svc = self.h.service

    def test_tx_change_201_view_events_and_compensation(self):
        self._build_scene()
        code, v = self._reorg()
        self.assertEqual(code, 201)
        self.assertEqual(list(v), V_KEYS)
        self.assertEqual(v["dispatch_id"], "dp1")
        self.assertEqual(v["adapter_id"], "ad1")
        self.assertEqual(v["tx_id"], TX2)
        self.assertEqual(v["block_height"], 9)
        self.assertEqual(v["block_hash"], BH2)
        self.assertEqual(v["confirmations"], 1)
        self.assertEqual(v["state"], "reorged")

        # 补偿操作：以 D 为 operation_id、同资产、反向 delta、state=reorged
        comp = self.h.store.get_asset_operation("w1", "dp1")
        self.assertIsNotNone(comp)
        self.assertEqual(comp["asset_id"], "BTC")
        self.assertEqual(comp["delta"], -100)
        self.assertEqual(comp["state"], "reorged")
        self.assertEqual(comp["balance"], 0)
        self.assertEqual(comp["version"], 2)
        # 源操作仍 committed；资产余额回到 0
        self.assertEqual(
            self.h.store.get_asset_operation("w1", "op1")["state"],
            "committed",
        )
        self.assertEqual(self.svc.get_asset("w1", "BTC")["balance"], 0)

        triple = self._events(
            types={
                "chain_dispatch_confirmation",
                "chain_dispatch_reorged",
                "asset_operation_committed",
            }
        )[-3:]
        confirmation, reorged, committed = triple
        self.assertEqual(confirmation["seq"] + 1, reorged["seq"])
        self.assertEqual(reorged["seq"] + 1, committed["seq"])
        self.assertEqual(confirmation["type"], "chain_dispatch_confirmation")
        self.assertEqual(confirmation["request_id"], "dp1")
        self.assertEqual(confirmation["actor_id"], "ad1")
        self.assertIsNone(confirmation["reason"])
        self.assertEqual(confirmation["details"], v)
        self.assertEqual(reorged["type"], "chain_dispatch_reorged")
        self.assertEqual(reorged["request_id"], "dp1")
        self.assertEqual(reorged["actor_id"], "ad1")
        self.assertIsNone(reorged["reason"])
        self.assertEqual(
            list(reorged["details"]), ["dispatch_id", "operation_id"]
        )
        self.assertEqual(
            reorged["details"],
            {"dispatch_id": "dp1", "operation_id": "dp1"},
        )
        self.assertEqual(committed["type"], "asset_operation_committed")
        self.assertEqual(committed["request_id"], "dp1")
        self.assertEqual(committed["actor_id"], "ad1")
        self.assertIsNone(committed["reason"])
        self.assertEqual(
            committed["details"],
            {
                "operation_id": "dp1",
                "asset_id": "BTC",
                "delta": -100,
                "state": "reorged",
                "balance": 0,
                "version": 2,
            },
        )
        # 落盘 details 键序保序
        with open(os.path.join(self.d, "audit", "w1.json"),
                  encoding="utf-8") as f:
            log = json.load(f)
        stored = [
            e for e in log["events"]
            if e["type"] == "chain_dispatch_reorged"
        ][0]
        self.assertEqual(
            list(stored),
            ["actor_id", "at", "details", "reason", "request_id", "seq",
             "type"],
        )
        self.assertEqual(
            list(stored["details"]), ["dispatch_id", "operation_id"]
        )

    def test_same_tx_block_change_in_window_accepted(self):
        self._build_scene()
        code, v = self._reorg(tx_id=TX1, height=9, block_hash=BH2,
                              confirmations=2)
        self.assertEqual(code, 201)
        self.assertEqual(v["state"], "reorged")
        self.assertEqual(v["tx_id"], TX1)

    def test_replay_reorged_body_200_no_new_events(self):
        self._build_scene()
        code, v1 = self._reorg()
        self.assertEqual(code, 201)
        before = self._events()
        code, v2 = self._reorg()
        self.assertEqual(code, 200)
        self.assertEqual(v2, v1)
        self.assertEqual(self._events(), before)

    def test_historical_finalized_body_still_200(self):
        self._build_scene()
        self._reorg()
        # finalized 历史同体仍 200，返回原 finalized V
        code, v = self.svc.post_chain_dispatch_confirmation(
            "w1", "dp1", "ad1", TX1, 10, BH1, 3
        )
        self.assertEqual(code, 200)
        self.assertEqual(v["state"], "finalized")

    def test_different_body_after_reorg_409(self):
        self._build_scene()
        code, _ = self._reorg()
        self.assertEqual(code, 201)
        with self.assertRaises(ServiceError) as ctx:
            self._reorg(height=8)
        self.assertEqual(ctx.exception.status, 409)

    def test_adapter_mismatch_409(self):
        self._build_scene()
        with self.assertRaises(ServiceError) as ctx:
            self._reorg(adapter="adX")
        self.assertEqual(ctx.exception.status, 409)

    def test_out_of_window_409(self):
        self._build_scene()
        # 旧高度 10，回退到 7（回退 3 > reorg_window 2）；tx 不变 -> 409
        with self.assertRaises(ServiceError) as ctx:
            self._reorg(tx_id=TX1, height=7, block_hash=BH2)
        self.assertEqual(ctx.exception.status, 409)

    def test_block_change_at_threshold_409(self):
        self._build_scene()
        # 同 tx、换块但确认数仍达阈值（3）：不满足"低于阈值"，409
        with self.assertRaises(ServiceError) as ctx:
            self._reorg(tx_id=TX1, height=9, block_hash=BH2,
                        confirmations=3)
        self.assertEqual(ctx.exception.status, 409)

    def test_no_settle_new_tx_409(self):
        # 仅 finalized、未结算：换 tx 仍是原契约的 tx 归属冲突 409
        self.svc.create_wallet("w1", 2)
        self.svc.put_policy("w1", 1, 600)
        self.svc.create_asset_operation("w1", "op1", "BTC", 100)
        self.svc.put_chain_policy("w1", "BTC", "chain-1", True, 3, 2)
        self.svc.create_sign_request("w1", "ap1", _msg())
        self.svc.approve("w1", "ap1", "boss")
        self.svc.post_chain_dispatch("w1", "op1", "dp1", "ad1", "ap1")
        self.svc.post_chain_dispatch_result(
            "w1", "dp1", "ad1", "broadcasted", TX1
        )
        self.svc.post_chain_dispatch_confirmation(
            "w1", "dp1", "ad1", TX1, 10, BH1, 3
        )
        with self.assertRaises(ServiceError) as ctx:
            self._reorg()
        self.assertEqual(ctx.exception.status, 409)
        self.assertIsNone(self.h.store.get_asset_operation("w1", "dp1"))

    def test_id_occupied_409_zero_side_effects(self):
        self._build_scene()
        # 停用策略后人工建一笔占用 id=dp1 的操作（不提交）
        self.svc.put_chain_policy("w1", "BTC", "chain-1", False, 3, 2)
        code, _ = self.svc.create_asset_operation("w1", "dp1", "BTC", 1)
        self.assertEqual(code, 201)
        seq_before = self._events()[-1]["seq"]
        with self.assertRaises(ServiceError) as ctx:
            self._reorg()
        self.assertEqual(ctx.exception.status, 409)
        # 零副作用：占用者仍 pending、无新事件、无意图、余额未变
        self.assertEqual(
            self.h.store.get_asset_operation("w1", "dp1")["state"], "pending"
        )
        self.assertEqual(self._events()[-1]["seq"], seq_before)
        self.assertEqual(self.h.store.list_asset_intents("w1"), [])
        self.assertEqual(self.svc.get_asset("w1", "BTC")["balance"], 100)

    def test_insufficient_balance_409_zero_side_effects(self):
        self._build_scene()  # 结算后余额 100
        # 再人工提交一笔 -60，使余额 40；反向补偿需 -100 -> 将负
        self.svc.put_chain_policy("w1", "BTC", "chain-1", False, 3, 2)
        self.svc.create_asset_operation("w1", "spend", "BTC", -60)
        code, _ = self.svc.commit_asset_operation("w1", "spend")
        self.assertEqual(code, 201)
        with self.assertRaises(ServiceError) as ctx:
            self._reorg()
        self.assertEqual(ctx.exception.status, 409)
        self.assertIsNone(self.h.store.get_asset_operation("w1", "dp1"))
        self.assertEqual(self.h.store.list_asset_intents("w1"), [])
        self.assertEqual(self.svc.get_asset("w1", "BTC")["balance"], 40)

    def test_concurrent_only_one_201(self):
        self._build_scene()
        results = []
        barrier = threading.Barrier(8)
        lock = threading.Lock()

        def worker():
            barrier.wait()
            try:
                code, _ = self._reorg()
            except ServiceError as exc:
                code = exc.status
            with lock:
                results.append(code)

        threads = [threading.Thread(target=worker) for _ in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(sorted(results).count(201), 1)
        self.assertEqual(sorted(results).count(200), 7)
        self.assertEqual(
            len(self._events(types={"chain_dispatch_reorged"})), 1
        )
        self.assertEqual(
            len(
                [
                    e
                    for e in self._events(
                        types={"asset_operation_committed"}
                    )
                    if e["request_id"] == "dp1"
                ]
            ),
            1,
        )

    def test_restart_preserves_compensation_and_replay_no_events(self):
        self._build_scene()
        code, v = self._reorg()
        self.assertEqual(code, 201)
        events_before = [(e["type"], e["seq"]) for e in self._events()]
        h2 = make_harness(self.d)
        # 同体重放 200 且不增事件
        code, v2 = h2.service.post_chain_dispatch_confirmation(
            "w1", "dp1", "ad1", TX2, 9, BH2, 1
        )
        self.assertEqual(code, 200)
        self.assertEqual(v2, v)
        self.assertEqual(
            [(e["type"], e["seq"])
             for e in h2.service.get_audit_events("w1")["events"]],
            events_before,
        )
        self.assertEqual(
            h2.store.get_asset_operation("w1", "dp1")["state"], "reorged"
        )

    def test_event_write_failure_rolls_back_and_is_retryable(self):
        self._build_scene()
        original = self.svc._audit.append_events

        def boom(*args, **kwargs):
            raise OSError("simulated write failure")

        self.svc._audit.append_events = boom
        with self.assertRaises(OSError):
            self._reorg()
        self.svc._audit.append_events = original
        # 俱无回滚：补偿操作不存在、无三事件、无意图残留
        self.assertIsNone(self.h.store.get_asset_operation("w1", "dp1"))
        self.assertEqual(
            self._events(
                types={"chain_dispatch_reorged",
                       "chain_dispatch_confirmation"}
            )[-1]["details"]["state"],
            "finalized",
        )
        self.assertEqual(self.h.store.list_asset_intents("w1"), [])
        # 可重试：三事件俱在前滚
        code, v = self._reorg()
        self.assertEqual(code, 201)
        self.assertEqual(v["state"], "reorged")
        self.assertEqual(
            self.h.store.get_asset_operation("w1", "dp1")["state"], "reorged"
        )

    def _tamper(self, drop_type=None, request_id=None):
        path = os.path.join(self.d, "audit", "w1.json")
        with open(path, encoding="utf-8") as f:
            log = json.load(f)
        log["events"] = [
            e
            for e in log["events"]
            if not (
                e.get("type") == drop_type
                and (request_id is None or e.get("request_id") == request_id)
            )
        ]
        log["next_seq"] = len(log["events"]) + 1
        with open(path, "w", encoding="utf-8") as f:
            json.dump(log, f)

    def test_partial_batch_missing_committed_unreconcilable(self):
        self._build_scene()
        self._reorg()
        self._tamper(drop_type="asset_operation_committed", request_id="dp1")
        with self.assertRaises(RecoveryError):
            make_harness(self.d)
        with self.assertRaises(RecoveryError):
            self.svc.get_asset("w1", "BTC")

    def test_partial_batch_missing_reorged_unreconcilable(self):
        self._build_scene()
        self._reorg()
        self._tamper(drop_type="chain_dispatch_reorged")
        with self.assertRaises(RecoveryError):
            make_harness(self.d)

    def test_partial_batch_missing_confirmation_unreconcilable(self):
        self._build_scene()
        self._reorg()
        # 仅删除最后一条（reorged）确认进展
        path = os.path.join(self.d, "audit", "w1.json")
        with open(path, encoding="utf-8") as f:
            log = json.load(f)
        reorged_conf_seqs = [
            e["seq"]
            for e in log["events"]
            if e["type"] == "chain_dispatch_confirmation"
            and e["details"]["state"] == "reorged"
        ]
        log["events"] = [
            e for e in log["events"] if e["seq"] not in reorged_conf_seqs
        ]
        log["next_seq"] = len(log["events"]) + 1
        with open(path, "w", encoding="utf-8") as f:
            json.dump(log, f)
        with self.assertRaises(RecoveryError):
            make_harness(self.d)

    def test_reorged_details_out_of_order_unreconcilable(self):
        self._build_scene()
        self._reorg()
        path = os.path.join(self.d, "audit", "w1.json")
        with open(path, encoding="utf-8") as f:
            log = json.load(f)
        for e in log["events"]:
            if e["type"] == "chain_dispatch_reorged":
                e["details"] = {
                    "operation_id": "dp1",
                    "dispatch_id": "dp1",
                }
        with open(path, "w", encoding="utf-8") as f:
            json.dump(log, f)
        with self.assertRaises(RecoveryError):
            make_harness(self.d)

    def test_bad_json_is_corrupt_and_serves_503(self):
        self._build_scene()
        self._reorg()
        path = os.path.join(self.d, "audit", "w1.json")
        with open(path, "w", encoding="utf-8") as f:
            f.write("{not json")
        with self.assertRaises((CorruptDataError, RecoveryError)):
            make_harness(self.d)


class ReorgHttpTest(ReorgSceneMixin, unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.d, ignore_errors=True)
        self._cm = http_server(self.d)
        self.srv = self._cm.__enter__()
        self.addCleanup(self._cm.__exit__, None, None, None)
        self.svc = self.srv.harness.service

    def _confirm_raw(self, body):
        import urllib.error
        import urllib.request

        raw = json.dumps(body).encode("utf-8")
        req = urllib.request.Request(
            self.srv.base_url + "/v1/wallets/w1/chain/dp1/confirm",
            data=raw,
            method="POST",
            headers={"Content-Type": "application/json"},
        )
        try:
            with urllib.request.urlopen(req) as resp:
                return resp.status, resp.read()
        except urllib.error.HTTPError as exc:
            return exc.code, exc.read()

    def test_settle_key_order_and_reorg_over_http(self):
        # 完整前置（不结算），随后空体 settle 首提 201，校验原始字节键序
        import urllib.error
        import urllib.request

        s = self.svc
        s.create_wallet("w1", 2)
        s.put_policy("w1", 1, 600)
        code, _ = s.create_asset_operation("w1", "op1", "BTC", 100)
        self.assertEqual(code, 201)
        s.put_chain_policy("w1", "BTC", "chain-1", True, 3, 2)
        code, _ = s.create_sign_request("w1", "ap1", _msg())
        self.assertEqual(code, 201)
        s.approve("w1", "ap1", "boss")
        s.post_chain_dispatch("w1", "op1", "dp1", "ad1", "ap1")
        s.post_chain_dispatch_result("w1", "dp1", "ad1", "broadcasted", TX1)
        s.post_chain_dispatch_confirmation(
            "w1", "dp1", "ad1", TX1, 10, BH1, 3
        )

        req = urllib.request.Request(
            self.srv.base_url + "/v1/wallets/w1/chain/dp1/settle",
            data=b"",
            method="POST",
        )
        with urllib.request.urlopen(req) as resp:
            self.assertEqual(resp.status, 201)
            raw = resp.read()
        # settle 201 原始字节以统一 R 键序起头
        self.assertTrue(
            raw.startswith(
                b'{"operation_id":"op1","asset_id":"BTC","delta":100,'
                b'"state":"committed","balance":100,"version":1}'
            ),
            raw,
        )
        self.assertFalse(raw.endswith(b"\n"))
        # 重放 200 同体字节
        req = urllib.request.Request(
            self.srv.base_url + "/v1/wallets/w1/chain/dp1/settle",
            data=b"",
            method="POST",
        )
        with urllib.request.urlopen(req) as resp:
            self.assertEqual(resp.status, 200)
            self.assertEqual(resp.read(), raw)

        status, raw = self._confirm_raw(
            {
                "adapter_id": "ad1",
                "tx_id": TX2,
                "block_height": 9,
                "block_hash": BH2,
                "confirmations": 1,
            }
        )
        self.assertEqual(status, 201)
        body = json.loads(raw)
        self.assertEqual(list(body), V_KEYS)
        self.assertEqual(body["state"], "reorged")
        # 紧凑 JSON：无空白、无末换行
        self.assertNotIn(b": ", raw)
        self.assertNotIn(b", ", raw)
        self.assertFalse(raw.endswith(b"\n"))
        self.assertTrue(raw.startswith(b'{"dispatch_id":"dp1",'))
        # 异体 409，错误体紧凑
        status, raw = self._confirm_raw(
            {
                "adapter_id": "ad1",
                "tx_id": TX2,
                "block_height": 8,
                "block_hash": BH2,
                "confirmations": 0,
            }
        )
        self.assertEqual(status, 409)
        self.assertEqual(list(json.loads(raw)), ["error"])

    def test_corrupt_scene_503(self):
        self._build_scene()
        self._reorg()
        path = os.path.join(self.d, "audit", "w1.json")
        with open(path, "w", encoding="utf-8") as f:
            f.write("{not json")
        status, raw = self._confirm_raw(
            {
                "adapter_id": "ad1",
                "tx_id": TX2,
                "block_height": 9,
                "block_hash": BH2,
                "confirmations": 1,
            }
        )
        self.assertEqual(status, 503)
        self.assertEqual(list(json.loads(raw)), ["error"])
        self.assertNotIn(b"dp1", raw)


if __name__ == "__main__":
    unittest.main()
