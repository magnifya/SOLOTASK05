"""跨链派发失败接管（POST /v1/wallets/{W}/chain/{D}/takeover）测试。

覆盖：
- 体恰含 adapter_id,approval_request_id 两键（两值为安全 ID），键集/值错
  400；钱包/派发/审批未知 404；
- 仅操作 pending、派发结果为 failed 且未接管时可首提，adapter_id 须变化；
  审批须同钱包 approved，message 逐字等于按 dispatch_id,adapter_id 序的
  紧凑 JSON，否则 409 且零副作用；
- 首提 201 返回 {dispatch_id,adapter_id,state:requested}；同参 200 同体、
  异参或再次接管 409；锁内并发仅一 201；
- chain_dispatch_taken_over 七字段为唯一提交事件：request_id=D、
  actor_id=approval_request_id、reason=null、details=响应，重放不记事件；
- 接管后 result 只接受新适配器恰好一条结果，confirm 只承接 broadcasted
  新交易，finality/settle 随之由新适配器完成；
- 恢复按 seq 复核派发、failed 结果、pending 操作、审批与接管；矛盾、坏
  JSON 与 I/O 沿用 README 异常类型（RecoveryError/CorruptDataError），
  HTTP 503 并拒绝 serve；重启/灾备保状态与 seq。
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
from threshold_wallet.store import (
    CorruptDataError,
    RecoveryError,
    WalletStore,
)

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
        {
            "dispatch_id": dispatch_id,
            "adapter_id": adapter_id,
        },
        ensure_ascii=False,
        separators=(",", ":"),
    )


def _call(fn, *args):
    try:
        return fn(*args)
    except ServiceError as exc:
        return exc.status, {"error": exc.message}


class _SceneMixin:
    """建钱包/策略/审批/派发/失败结果/接管审批的共用装配。"""

    def _build_failed_dispatch(self, new_approval="ap2", new_adapter="ad2"):
        self.svc.create_wallet("w1", 2)
        self.svc.put_policy("w1", 1, 600)
        code, _ = self.svc.create_asset_operation("w1", "op1", "BTC", 100)
        self.assertEqual(code, 201)
        self.svc.put_chain_policy(
            "w1", "BTC", "chain-1", True, 3, 2
        )
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
        if new_approval is not None:
            code, _ = self.svc.create_sign_request(
                "w1", new_approval,
                _takeover_msg(adapter_id=new_adapter),
            )
            self.assertEqual(code, 201)
            self.svc.approve("w1", new_approval, "boss")

    def _takeover(self, wallet="w1", dispatch_id="dp1", adapter_id="ad2",
                  approval_request_id="ap2"):
        return _call(
            self.svc.post_chain_dispatch_takeover,
            wallet,
            dispatch_id,
            adapter_id,
            approval_request_id,
        )

    def _takeover_events(self, svc=None, dispatch_id="dp1"):
        svc = svc or self.svc
        return [
            e
            for e in svc.get_audit_events("w1")["events"]
            if e["type"] == "chain_dispatch_taken_over"
            and e["request_id"] == dispatch_id
        ]


class TakeoverServiceTest(_SceneMixin, unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.d, ignore_errors=True)
        self.h = make_harness(self.d)
        self.svc = self.h.service

    def _audit_path(self):
        return os.path.join(self.d, "audit", "w1.json")

    def _rewrite(self, mutate):
        path = self._audit_path()
        with open(path, encoding="utf-8") as f:
            log = json.load(f)
        mutate(log)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(log, f)

    # ---- 201 / 视图 / 事件形状 --------------------------------------------

    def test_first_takeover_201_view_and_event(self):
        self._build_failed_dispatch()
        code, v = self._takeover()
        self.assertEqual(code, 201)
        self.assertEqual(
            list(v), ["dispatch_id", "adapter_id", "state"]
        )
        self.assertEqual(
            v,
            {"dispatch_id": "dp1", "adapter_id": "ad2",
             "state": "requested"},
        )
        events = self._takeover_events()
        self.assertEqual(len(events), 1)
        event = events[0]
        self.assertEqual(event["request_id"], "dp1")
        self.assertEqual(event["actor_id"], "ap2")
        self.assertIsNone(event["reason"])
        self.assertEqual(event["details"], v)
        self.assertEqual(
            list(event["details"]),
            ["dispatch_id", "adapter_id", "state"],
        )

    def test_event_is_the_only_commit_point(self):
        self._build_failed_dispatch()
        before = self.svc.get_audit_events("w1")["events"]
        self.assertEqual(self._takeover_events(), [])
        self.assertEqual(self._takeover()[0], 201)
        after = self.svc.get_audit_events("w1")["events"]
        self.assertEqual(len(after), len(before) + 1)
        self.assertEqual(after[-1]["type"], "chain_dispatch_taken_over")

    # ---- 400 / 404 ---------------------------------------------------------

    def test_bad_ids_400(self):
        self._build_failed_dispatch()
        for bad in ("", "has space", "a/b", "x" * 129):
            self.assertEqual(
                self._takeover(dispatch_id=bad)[0], 400, bad
            )
            self.assertEqual(
                self._takeover(adapter_id=bad)[0], 400, bad
            )
            self.assertEqual(
                self._takeover(approval_request_id=bad)[0], 400, bad
            )

    def test_unknown_wallet_dispatch_approval_404(self):
        self._build_failed_dispatch()
        self.assertEqual(
            self._takeover(wallet="w9")[0], 404
        )
        self.assertEqual(
            self._takeover(dispatch_id="nope")[0], 404
        )
        self.assertEqual(
            self._takeover(approval_request_id="apX")[0], 404
        )

    # ---- 409 前置 ----------------------------------------------------------

    def test_takeover_without_result_409(self):
        # 不产生 failed 结果
        self.svc.create_wallet("w1", 2)
        self.svc.put_policy("w1", 1, 600)
        self.svc.create_asset_operation("w1", "op1", "BTC", 100)
        self.svc.put_chain_policy("w1", "BTC", "chain-1", True, 3, 2)
        self.svc.create_sign_request("w1", "ap1", _dispatch_msg())
        self.svc.approve("w1", "ap1", "boss")
        self.svc.post_chain_dispatch("w1", "op1", "dp1", "ad1", "ap1")
        self.svc.create_sign_request("w1", "ap2", _takeover_msg())
        self.svc.approve("w1", "ap2", "boss")
        self.assertEqual(self._takeover()[0], 409)
        self.assertEqual(self._takeover_events(), [])

    def test_takeover_after_broadcasted_409(self):
        self.svc.create_wallet("w1", 2)
        self.svc.put_policy("w1", 1, 600)
        self.svc.create_asset_operation("w1", "op1", "BTC", 100)
        self.svc.put_chain_policy("w1", "BTC", "chain-1", True, 3, 2)
        self.svc.create_sign_request("w1", "ap1", _dispatch_msg())
        self.svc.approve("w1", "ap1", "boss")
        self.svc.post_chain_dispatch("w1", "op1", "dp1", "ad1", "ap1")
        self.assertEqual(
            self.svc.post_chain_dispatch_result(
                "w1", "dp1", "ad1", "broadcasted", TX1
            )[0],
            201,
        )
        self.svc.create_sign_request("w1", "ap2", _takeover_msg())
        self.svc.approve("w1", "ap2", "boss")
        self.assertEqual(self._takeover()[0], 409)
        self.assertEqual(self._takeover_events(), [])

    def test_same_adapter_409(self):
        self._build_failed_dispatch()
        self.assertEqual(
            self._takeover(adapter_id="ad1")[0], 409
        )
        self.assertEqual(self._takeover_events(), [])

    def test_approval_message_mismatch_409(self):
        self._build_failed_dispatch(new_approval=None)
        # message 键序/内容不符（按派发请求的四键 message）
        self.svc.create_sign_request("w1", "ap2", _dispatch_msg())
        self.svc.approve("w1", "ap2", "boss")
        self.assertEqual(self._takeover()[0], 409)
        self.assertEqual(self._takeover_events(), [])

    def test_approval_not_approved_409(self):
        self._build_failed_dispatch(new_approval=None)
        self.svc.create_sign_request("w1", "ap2", _takeover_msg())
        # 不 approve
        self.assertEqual(self._takeover()[0], 409)
        self.assertEqual(self._takeover_events(), [])

    def test_409_has_zero_side_effects(self):
        self._build_failed_dispatch()
        events_before = self.svc.get_audit_events("w1")["events"]
        self.assertEqual(
            self._takeover(adapter_id="ad1")[0], 409
        )
        self.assertEqual(
            self.svc.get_audit_events("w1")["events"], events_before
        )

    # ---- 幂等 / 再次接管 ---------------------------------------------------

    def test_replay_same_params_200_same_view_no_event(self):
        self._build_failed_dispatch()
        code, v1 = self._takeover()
        self.assertEqual(code, 201)
        events_before = self.svc.get_audit_events("w1")["events"]
        code, v2 = self._takeover()
        self.assertEqual(code, 200)
        self.assertEqual(v2, v1)
        self.assertEqual(
            self.svc.get_audit_events("w1")["events"], events_before
        )

    def test_different_params_after_takeover_409(self):
        self._build_failed_dispatch()
        self.assertEqual(self._takeover()[0], 201)
        # 换适配器
        self.assertEqual(
            self._takeover(adapter_id="ad9")[0], 409
        )
        # 换审批单
        self.svc.create_sign_request("w1", "ap3", _takeover_msg())
        self.svc.approve("w1", "ap3", "boss")
        self.assertEqual(
            self._takeover(approval_request_id="ap3")[0], 409
        )
        # 仍只有一条接管事件
        self.assertEqual(len(self._takeover_events()), 1)

    def test_concurrent_single_201_rest_200(self):
        self._build_failed_dispatch()
        statuses = []
        guard = threading.Lock()

        def go():
            code, _ = self._takeover()
            with guard:
                statuses.append(code)

        threads = [threading.Thread(target=go) for _ in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(statuses.count(201), 1)
        self.assertEqual(statuses.count(200), 7)
        self.assertEqual(len(self._takeover_events()), 1)

    # ---- 接管后的结果与确认 ------------------------------------------------

    def test_result_after_takeover_new_adapter_once(self):
        self._build_failed_dispatch()
        self.assertEqual(self._takeover()[0], 201)
        # 原适配器的结果被拒
        self.assertEqual(
            _call(
                self.svc.post_chain_dispatch_result,
                "w1", "dp1", "ad1", "broadcasted", TX1,
            )[0],
            409,
        )
        # 新适配器首条 broadcasted 结果 201，V 取新适配器
        code, v = _call(
            self.svc.post_chain_dispatch_result,
            "w1", "dp1", "ad2", "broadcasted", TX2,
        )
        self.assertEqual(code, 201)
        self.assertEqual(v["adapter_id"], "ad2")
        self.assertEqual(v["tx_id"], TX2)
        # 同参重放 200
        self.assertEqual(
            _call(
                self.svc.post_chain_dispatch_result,
                "w1", "dp1", "ad2", "broadcasted", TX2,
            )[0],
            200,
        )
        # 新适配器异参（另一笔交易）第二条 409
        self.assertEqual(
            _call(
                self.svc.post_chain_dispatch_result,
                "w1", "dp1", "ad2", "broadcasted", TX1,
            )[0],
            409,
        )

    def test_confirm_after_takeover_only_new_broadcasted_tx(self):
        self._build_failed_dispatch()
        self.assertEqual(self._takeover()[0], 201)
        # 尚无新适配器 broadcasted 结果：confirm 409
        self.assertEqual(
            _call(
                self.svc.post_chain_dispatch_confirmation,
                "w1", "dp1", "ad2", TX2, 10, BH1, 1,
            )[0],
            409,
        )
        self.assertEqual(
            self.svc.post_chain_dispatch_result(
                "w1", "dp1", "ad2", "broadcasted", TX2
            )[0],
            201,
        )
        # 原适配器身份上报 409
        self.assertEqual(
            _call(
                self.svc.post_chain_dispatch_confirmation,
                "w1", "dp1", "ad1", TX2, 10, BH1, 1,
            )[0],
            409,
        )
        # 旧交易 tx 409
        self.assertEqual(
            _call(
                self.svc.post_chain_dispatch_confirmation,
                "w1", "dp1", "ad2", TX1, 10, BH1, 1,
            )[0],
            409,
        )
        # 新交易确认到达门槛 -> finalized
        code, v = _call(
            self.svc.post_chain_dispatch_confirmation,
            "w1", "dp1", "ad2", TX2, 10, BH1, 3,
        )
        self.assertEqual(code, 201)
        self.assertEqual(v["state"], "finalized")

    def test_finality_and_settle_after_takeover(self):
        self._build_failed_dispatch()
        self.assertEqual(self._takeover()[0], 201)
        self.svc.post_chain_dispatch_result(
            "w1", "dp1", "ad2", "broadcasted", TX2
        )
        self.svc.post_chain_dispatch_confirmation(
            "w1", "dp1", "ad2", TX2, 10, BH1, 3
        )
        finality = self.svc.get_chain_dispatch_finality("w1", "dp1")
        self.assertEqual(
            finality["confirmation"]["state"], "finalized"
        )
        code, r = self.svc.settle_chain_dispatch("w1", "dp1")
        self.assertEqual(code, 201)
        self.assertEqual(r["state"], "committed")
        self.assertEqual(r["operation_id"], "op1")
        # 结算事件 actor 为新适配器
        settled = [
            e
            for e in self.svc.get_audit_events("w1")["events"]
            if e["type"] == "chain_dispatch_settled"
        ]
        self.assertEqual(len(settled), 1)
        self.assertEqual(settled[0]["actor_id"], "ad2")

    def test_reorg_after_takeover(self):
        self._build_failed_dispatch()
        self.assertEqual(self._takeover()[0], 201)
        self.svc.post_chain_dispatch_result(
            "w1", "dp1", "ad2", "broadcasted", TX2
        )
        self.svc.post_chain_dispatch_confirmation(
            "w1", "dp1", "ad2", TX2, 10, BH1, 3
        )
        self.assertEqual(
            self.svc.settle_chain_dispatch("w1", "dp1")[0], 201
        )
        # 新适配器上报重组形态
        code, v = _call(
            self.svc.post_chain_dispatch_confirmation,
            "w1", "dp1", "ad2", TX2, 9, BH2, 1,
        )
        self.assertEqual(code, 201)
        self.assertEqual(v["state"], "reorged")
        comp = self.h.store.get_asset_operation("w1", "dp1")
        self.assertEqual(comp["state"], "committed")
        self.assertEqual(comp["delta"], -100)

    # ---- 持久化与恢复 ------------------------------------------------------

    def test_restart_preserves_takeover_and_replay(self):
        self._build_failed_dispatch()
        self.assertEqual(self._takeover()[0], 201)
        self.svc.post_chain_dispatch_result(
            "w1", "dp1", "ad2", "broadcasted", TX2
        )
        h2 = make_harness(self.d)
        svc2 = h2.service
        code, v = svc2.post_chain_dispatch_takeover(
            "w1", "dp1", "ad2", "ap2"
        )
        self.assertEqual(code, 200)
        self.assertEqual(
            v,
            {"dispatch_id": "dp1", "adapter_id": "ad2",
             "state": "requested"},
        )
        # 重启后接管事件仍仅一条，seq 连续
        events = svc2.get_audit_events("w1")["events"]
        self.assertEqual(
            [e["seq"] for e in events], list(range(1, len(events) + 1))
        )
        self.assertEqual(
            len(
                [
                    e
                    for e in events
                    if e["type"] == "chain_dispatch_taken_over"
                ]
            ),
            1,
        )

    def _expect_recovery_fail(self, error=RecoveryError):
        with self.assertRaises(error):
            make_harness(self.d)

    def test_takeover_details_out_of_order_fail_closed(self):
        self._build_failed_dispatch()
        self.assertEqual(self._takeover()[0], 201)

        def mutate(log):
            for e in log["events"]:
                if e["type"] == "chain_dispatch_taken_over":
                    e["details"] = {
                        "adapter_id": "ad2",
                        "dispatch_id": "dp1",
                        "state": "requested",
                    }

        self._rewrite(mutate)
        self._expect_recovery_fail()

    def test_duplicate_takeover_fail_closed(self):
        self._build_failed_dispatch()
        self.assertEqual(self._takeover()[0], 201)

        def mutate(log):
            dup = next(
                e
                for e in log["events"]
                if e["type"] == "chain_dispatch_taken_over"
            )
            dup = json.loads(json.dumps(dup))
            dup["seq"] = log["next_seq"]
            log["events"].append(dup)
            log["next_seq"] += 1

        self._rewrite(mutate)
        self._expect_recovery_fail()

    def test_takeover_without_failed_result_fail_closed(self):
        self._build_failed_dispatch()
        self.assertEqual(self._takeover()[0], 201)

        def mutate(log):
            log["events"] = [
                e
                for e in log["events"]
                if not (
                    e["type"] == "chain_dispatch_result"
                    and e["details"]["state"] == "failed"
                )
            ]
            for i, e in enumerate(log["events"], 1):
                e["seq"] = i
            log["next_seq"] = len(log["events"]) + 1

        self._rewrite(mutate)
        self._expect_recovery_fail()

    def test_takeover_after_committed_operation_fail_closed(self):
        # 在接管事件之前插入 op1 的 committed 事件并把账本落为 committed：
        # 接管时操作必须仍为 pending（提交点不得早于接管），矛盾现场
        # fail-closed。
        self._build_failed_dispatch()
        self.assertEqual(self._takeover()[0], 201)

        def mutate(log):
            committed = {
                "actor_id": None,
                "at": "2026-09-20T00:00:00Z",
                "details": {
                    "operation_id": "op1",
                    "asset_id": "BTC",
                    "delta": 100,
                    "state": "committed",
                    "balance": 100,
                    "version": 1,
                },
                "reason": None,
                "request_id": "op1",
                "type": "asset_operation_committed",
            }
            for i, event in enumerate(log["events"]):
                if event["type"] == "chain_dispatch_taken_over":
                    log["events"].insert(i, committed)
                    break
            for i, event in enumerate(log["events"], 1):
                event["seq"] = i
            log["next_seq"] = len(log["events"]) + 1

        self._rewrite(mutate)
        ledger_path = os.path.join(self.d, "assets", "w1.json")
        with open(ledger_path, encoding="utf-8") as f:
            ledger = json.load(f)
        ledger["operations"]["op1"]["state"] = "committed"
        ledger["operations"]["op1"]["balance"] = 100
        ledger["operations"]["op1"]["version"] = 1
        ledger["assets"]["BTC"] = {"balance": 100, "version": 1}
        with open(ledger_path, "w", encoding="utf-8") as f:
            json.dump(ledger, f)
        self._expect_recovery_fail()

    def test_takeover_approval_message_mismatch_fail_closed(self):
        self._build_failed_dispatch()
        self.assertEqual(self._takeover()[0], 201)
        requests_path = os.path.join(self.d, "requests", "w1.json")
        with open(requests_path, encoding="utf-8") as f:
            records = json.load(f)
        records["ap2"]["message"] = "tampered"
        with open(requests_path, "w", encoding="utf-8") as f:
            json.dump(records, f)
        self._expect_recovery_fail()

    def test_takeover_same_adapter_fail_closed(self):
        self._build_failed_dispatch()
        self.assertEqual(self._takeover()[0], 201)

        def mutate(log):
            for e in log["events"]:
                if e["type"] == "chain_dispatch_taken_over":
                    e["details"]["adapter_id"] = "ad1"

        self._rewrite(mutate)
        self._expect_recovery_fail()

    def test_bad_audit_json_fail_closed(self):
        self._build_failed_dispatch()
        self.assertEqual(self._takeover()[0], 201)
        with open(self._audit_path(), "w", encoding="utf-8") as f:
            f.write("{broken")
        # 启动恢复保持 CorruptDataError 原类型（同样阻止就绪、现场保留）。
        with self.assertRaises(CorruptDataError):
            make_harness(self.d)

    # ---- HTTP 层 -----------------------------------------------------------

    def test_http_wire_compact_and_statuses(self):
        self._build_failed_dispatch()
        with http_server(self.d) as srv:
            def raw(method, path, body):
                data = None
                headers = {}
                if body is not None:
                    data = json.dumps(body).encode("utf-8")
                    headers["Content-Type"] = "application/json"
                req = urllib.request.Request(
                    srv.base_url + path,
                    data=data,
                    method=method,
                    headers=headers,
                )
                try:
                    with urllib.request.urlopen(req) as resp:
                        return resp.status, resp.read()
                except urllib.error.HTTPError as exc:
                    return exc.code, exc.read()

            status, body = raw(
                "POST",
                "/v1/wallets/w1/chain/dp1/takeover",
                {"adapter_id": "ad2", "approval_request_id": "ap2"},
            )
            self.assertEqual(status, 201)
            self.assertEqual(
                body,
                b'{"dispatch_id":"dp1","adapter_id":"ad2",'
                b'"state":"requested"}',
            )
            self.assertFalse(body.endswith(b"\n"))
            status, body = raw(
                "POST",
                "/v1/wallets/w1/chain/dp1/takeover",
                {"adapter_id": "ad2", "approval_request_id": "ap2"},
            )
            self.assertEqual(status, 200)
            # 缺键 / 多键 400
            self.assertEqual(
                raw(
                    "POST",
                    "/v1/wallets/w1/chain/dp1/takeover",
                    {"adapter_id": "ad2"},
                )[0],
                400,
            )
            self.assertEqual(
                raw(
                    "POST",
                    "/v1/wallets/w1/chain/dp1/takeover",
                    {"adapter_id": "ad2", "approval_request_id": "ap2",
                     "extra": 1},
                )[0],
                400,
            )
            # 未知派发 404
            self.assertEqual(
                raw(
                    "POST",
                    "/v1/wallets/w1/chain/nope/takeover",
                    {"adapter_id": "ad2", "approval_request_id": "ap2"},
                )[0],
                404,
            )

    def test_http_503_on_corrupt_scene(self):
        self._build_failed_dispatch()
        with http_server(self.d) as srv:
            status, _ = srv.request(
                "POST",
                "/v1/wallets/w1/chain/dp1/takeover",
                {"adapter_id": "ad2", "approval_request_id": "ap2"},
            )
            self.assertEqual(status, 201)
            # 运行中损坏审计：后续请求 503，现场不动、不泄露标识
            with open(self._audit_path(), "w", encoding="utf-8") as f:
                f.write("{broken")
            status, body = srv.request(
                "POST",
                "/v1/wallets/w1/chain/dp1/takeover",
                {"adapter_id": "ad2", "approval_request_id": "ap2"},
            )
            self.assertEqual(status, 503)
            self.assertNotIn("dp1", json.dumps(body))


if __name__ == "__main__":
    unittest.main()
