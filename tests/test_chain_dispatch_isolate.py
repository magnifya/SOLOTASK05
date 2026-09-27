"""跨链派发隔离（POST /v1/wallets/{W}/chain/{D}/isolate）测试。

覆盖：
- 体须恰为 {}（缺体/夹带键一律 400）；W/D 非法 400；钱包/派发未知 404；
- 首提须操作 pending、D 无 result/takeover/isolate、原 adapter_id 在当前
  健康表显式 down（表未配置/缺席视为 up）；否则 409 且零副作用；
- 首提 201 返回 {dispatch_id,adapter_id,state:"isolated"}；同 D 重放优先
  200 同 V；锁内并发仅一 201；
- chain_dispatch_isolated 七字段为唯一提交事件：request_id=D、
  actor_id/reason=null、details=V，重放不记事件；
- 隔离后旧适配器 result 一律 409；既有 takeover 可从 failed 或 isolated
  接管；接管新适配器显式 down 时 409；
- 恢复按 seq 复核派发在先、当时健康 down、操作 pending、隔离前无
  result/takeover、每 D 至多一次；矛盾 RecoveryError、坏 JSON
  CorruptDataError、I/O OSError，HTTP 503、serve 拒绝就绪；重启/灾备/
  重放不增事件。
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


def _call(fn, *args):
    try:
        return fn(*args)
    except ServiceError as exc:
        return exc.status, {"error": exc.message}


class _SceneMixin:
    """建钱包/策略/审批/派发的共用装配（操作 pending、已派发、无结果）。"""

    def _build_pending_dispatch(self, adapter="ad1", approval="ap1"):
        self.svc.create_wallet("w1", 2)
        self.svc.put_policy("w1", 1, 600)
        code, _ = self.svc.create_asset_operation("w1", "op1", "BTC", 100)
        self.assertEqual(code, 201)
        self.svc.put_chain_policy("w1", "BTC", "chain-1", True, 3, 2)
        code, _ = self.svc.create_sign_request(
            "w1", approval,
            _dispatch_msg(adapter_id=adapter),
        )
        self.assertEqual(code, 201)
        self.svc.approve("w1", approval, "boss")
        code, _ = self.svc.post_chain_dispatch(
            "w1", "op1", "dp1", adapter, approval
        )
        self.assertEqual(code, 201)

    def _set_adapters(self, table):
        self.svc.put_chain_adapters("w1", table)

    def _isolate(self, wallet="w1", dispatch_id="dp1"):
        return _call(
            self.svc.post_chain_dispatch_isolate, wallet, dispatch_id
        )

    def _isolate_events(self, svc=None, dispatch_id="dp1"):
        svc = svc or self.svc
        return [
            e
            for e in svc.get_audit_events("w1")["events"]
            if e["type"] == "chain_dispatch_isolated"
            and e["request_id"] == dispatch_id
        ]


class IsolateServiceTest(_SceneMixin, unittest.TestCase):
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

    def test_first_isolate_201_view_and_event(self):
        self._build_pending_dispatch()
        self._set_adapters({"ad1": "down"})
        code, v = self._isolate()
        self.assertEqual(code, 201)
        self.assertEqual(list(v), ["dispatch_id", "adapter_id", "state"])
        self.assertEqual(
            v,
            {"dispatch_id": "dp1", "adapter_id": "ad1",
             "state": "isolated"},
        )
        events = self._isolate_events()
        self.assertEqual(len(events), 1)
        event = events[0]
        self.assertEqual(event["request_id"], "dp1")
        self.assertIsNone(event["actor_id"])
        self.assertIsNone(event["reason"])
        self.assertEqual(event["details"], v)
        self.assertEqual(
            list(event["details"]),
            ["dispatch_id", "adapter_id", "state"],
        )

    def test_event_is_the_only_commit_point(self):
        self._build_pending_dispatch()
        self._set_adapters({"ad1": "down"})
        before = self.svc.get_audit_events("w1")["events"]
        self.assertEqual(self._isolate_events(), [])
        self.assertEqual(self._isolate()[0], 201)
        after = self.svc.get_audit_events("w1")["events"]
        self.assertEqual(len(after), len(before) + 1)
        self.assertEqual(after[-1]["type"], "chain_dispatch_isolated")

    # ---- 400 / 404 ---------------------------------------------------------

    def test_bad_dispatch_id_400(self):
        self._build_pending_dispatch()
        self._set_adapters({"ad1": "down"})
        for bad in ("", "has space", "a/b", "x" * 129):
            self.assertEqual(self._isolate(dispatch_id=bad)[0], 400, bad)

    def test_unknown_wallet_dispatch_404(self):
        self._build_pending_dispatch()
        self._set_adapters({"ad1": "down"})
        self.assertEqual(self._isolate(wallet="w9")[0], 404)
        self.assertEqual(self._isolate(dispatch_id="nope")[0], 404)

    # ---- 409 前置 ----------------------------------------------------------

    def test_no_health_table_is_up_409(self):
        self._build_pending_dispatch()
        # 健康表未配置：视为 up，不隔离
        self.assertEqual(self._isolate()[0], 409)
        self.assertEqual(self._isolate_events(), [])

    def test_adapter_absent_from_table_is_up_409(self):
        self._build_pending_dispatch()
        # 表里没有 ad1：缺席视为 up
        self._set_adapters({"ad9": "down"})
        self.assertEqual(self._isolate()[0], 409)
        self.assertEqual(self._isolate_events(), [])

    def test_adapter_explicitly_up_409(self):
        self._build_pending_dispatch()
        self._set_adapters({"ad1": "up"})
        self.assertEqual(self._isolate()[0], 409)
        self.assertEqual(self._isolate_events(), [])

    def test_cannot_isolate_after_failed_result(self):
        self._build_pending_dispatch()
        self.assertEqual(
            self.svc.post_chain_dispatch_result(
                "w1", "dp1", "ad1", "failed", None
            )[0],
            201,
        )
        self._set_adapters({"ad1": "down"})
        self.assertEqual(self._isolate()[0], 409)
        self.assertEqual(self._isolate_events(), [])

    def test_cannot_isolate_after_broadcasted_result(self):
        self._build_pending_dispatch()
        self.assertEqual(
            self.svc.post_chain_dispatch_result(
                "w1", "dp1", "ad1", "broadcasted", TX1
            )[0],
            201,
        )
        self._set_adapters({"ad1": "down"})
        self.assertEqual(self._isolate()[0], 409)
        self.assertEqual(self._isolate_events(), [])

    def test_cannot_isolate_committed_operation(self):
        # 走完 失败->接管->广播->确认->结算：操作已 committed。此后隔离须
        # 409（pending 判定先于结果判定）。
        self._build_pending_dispatch()
        self.assertEqual(
            self.svc.post_chain_dispatch_result(
                "w1", "dp1", "ad1", "failed", None
            )[0],
            201,
        )
        self._set_adapters({"ad1": "down", "ad2": "up"})
        self._approve_takeover()
        self.assertEqual(
            _call(
                self.svc.post_chain_dispatch_takeover,
                "w1", "dp1", "ad2", "ap2",
            )[0],
            201,
        )
        self.assertEqual(
            self.svc.post_chain_dispatch_result(
                "w1", "dp1", "ad2", "broadcasted", TX2
            )[0],
            201,
        )
        self.assertEqual(
            self.svc.post_chain_dispatch_confirmation(
                "w1", "dp1", "ad2", TX2, 10, BH1, 3
            )[0],
            201,
        )
        self.assertEqual(
            self.svc.settle_chain_dispatch("w1", "dp1")[0], 201
        )
        code, body = self._isolate()
        self.assertEqual(code, 409)
        self.assertIn("not pending", body["error"])
        self.assertEqual(self._isolate_events(), [])

    def test_409_has_zero_side_effects(self):
        self._build_pending_dispatch()
        # 表显式 up -> 409
        self._set_adapters({"ad1": "up"})
        events_before = self.svc.get_audit_events("w1")["events"]
        self.assertEqual(self._isolate()[0], 409)
        self.assertEqual(
            self.svc.get_audit_events("w1")["events"], events_before
        )

    # ---- 幂等 / 并发 --------------------------------------------------------

    def test_replay_200_same_view_no_event_and_ignores_health_flip(self):
        self._build_pending_dispatch()
        self._set_adapters({"ad1": "down"})
        code, v1 = self._isolate()
        self.assertEqual(code, 201)
        # 事后把适配器翻回 up：同 D 重放仍优先 200 同 V
        self._set_adapters({"ad1": "up"})
        events_before = self.svc.get_audit_events("w1")["events"]
        code, v2 = self._isolate()
        self.assertEqual(code, 200)
        self.assertEqual(v2, v1)
        self.assertEqual(
            self.svc.get_audit_events("w1")["events"], events_before
        )

    def test_concurrent_single_201_rest_200(self):
        self._build_pending_dispatch()
        self._set_adapters({"ad1": "down"})
        statuses = []
        guard = threading.Lock()

        def go():
            code, _ = self._isolate()
            with guard:
                statuses.append(code)

        threads = [threading.Thread(target=go) for _ in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(statuses.count(201), 1)
        self.assertEqual(statuses.count(200), 7)
        self.assertEqual(len(self._isolate_events()), 1)

    # ---- 隔离后 result 409、takeover 可接管 ---------------------------------

    def test_result_after_isolate_old_adapter_409(self):
        self._build_pending_dispatch()
        self._set_adapters({"ad1": "down"})
        self.assertEqual(self._isolate()[0], 201)
        # 旧适配器 failed / broadcasted 结果一律 409（同参也无回放）
        self.assertEqual(
            _call(
                self.svc.post_chain_dispatch_result,
                "w1", "dp1", "ad1", "failed", None,
            )[0],
            409,
        )
        self.assertEqual(
            _call(
                self.svc.post_chain_dispatch_result,
                "w1", "dp1", "ad1", "broadcasted", TX1,
            )[0],
            409,
        )
        # 没有产生任何结果事件
        self.assertEqual(
            [
                e
                for e in self.svc.get_audit_events("w1")["events"]
                if e["type"] == "chain_dispatch_result"
            ],
            [],
        )

    def _approve_takeover(self, adapter="ad2", rid="ap2"):
        code, _ = self.svc.create_sign_request(
            "w1", rid, _takeover_msg(adapter_id=adapter)
        )
        self.assertEqual(code, 201)
        self.svc.approve("w1", rid, "boss")

    def test_takeover_from_isolated_then_result_confirm_settle(self):
        self._build_pending_dispatch()
        self._set_adapters({"ad1": "down", "ad2": "up"})
        self.assertEqual(self._isolate()[0], 201)
        # 隔离态可直接接管（无需 failed 结果）
        self._approve_takeover()
        code, v = _call(
            self.svc.post_chain_dispatch_takeover,
            "w1", "dp1", "ad2", "ap2",
        )
        self.assertEqual(code, 201)
        self.assertEqual(
            v,
            {"dispatch_id": "dp1", "adapter_id": "ad2",
             "state": "requested"},
        )
        # 旧适配器结果仍 409
        self.assertEqual(
            _call(
                self.svc.post_chain_dispatch_result,
                "w1", "dp1", "ad1", "broadcasted", TX1,
            )[0],
            409,
        )
        # 新适配器广播 -> 确认 -> 结算
        self.assertEqual(
            self.svc.post_chain_dispatch_result(
                "w1", "dp1", "ad2", "broadcasted", TX2
            )[0],
            201,
        )
        self.assertEqual(
            self.svc.post_chain_dispatch_confirmation(
                "w1", "dp1", "ad2", TX2, 10, BH1, 3
            )[0],
            201,
        )
        code, r = self.svc.settle_chain_dispatch("w1", "dp1")
        self.assertEqual(code, 201)
        self.assertEqual(r["state"], "committed")

    def test_takeover_from_isolated_rejects_down_new_adapter(self):
        self._build_pending_dispatch()
        # 原适配器 down，候选新适配器 ad2 也显式 down
        self._set_adapters({"ad1": "down", "ad2": "down"})
        self.assertEqual(self._isolate()[0], 201)
        self._approve_takeover(adapter="ad2")
        code, _ = _call(
            self.svc.post_chain_dispatch_takeover,
            "w1", "dp1", "ad2", "ap2",
        )
        self.assertEqual(code, 409)
        # 没有产生接管事件
        self.assertEqual(
            [
                e
                for e in self.svc.get_audit_events("w1")["events"]
                if e["type"] == "chain_dispatch_taken_over"
            ],
            [],
        )

    def test_takeover_still_works_from_failed(self):
        # 既有 failed -> takeover 路径不变
        self._build_pending_dispatch()
        self.assertEqual(
            self.svc.post_chain_dispatch_result(
                "w1", "dp1", "ad1", "failed", None
            )[0],
            201,
        )
        self._set_adapters({"ad1": "down", "ad2": "up"})
        self._approve_takeover()
        code, _ = _call(
            self.svc.post_chain_dispatch_takeover,
            "w1", "dp1", "ad2", "ap2",
        )
        self.assertEqual(code, 201)

    # ---- 持久化与恢复 ------------------------------------------------------

    def test_restart_preserves_isolation_and_replay(self):
        self._build_pending_dispatch()
        self._set_adapters({"ad1": "down"})
        self.assertEqual(self._isolate()[0], 201)
        svc2 = make_harness(self.d).service
        code, v = svc2.post_chain_dispatch_isolate("w1", "dp1")
        self.assertEqual(code, 200)
        self.assertEqual(
            v,
            {"dispatch_id": "dp1", "adapter_id": "ad1",
             "state": "isolated"},
        )
        events = svc2.get_audit_events("w1")["events"]
        self.assertEqual(
            [e["seq"] for e in events], list(range(1, len(events) + 1))
        )
        self.assertEqual(len(self._isolate_events(svc2)), 1)

    def _expect_recovery_fail(self, error=RecoveryError):
        with self.assertRaises(error):
            make_harness(self.d)

    def test_isolate_without_prior_dispatch_fail_closed(self):
        self._build_pending_dispatch()
        self._set_adapters({"ad1": "down"})
        self.assertEqual(self._isolate()[0], 201)

        def mutate(log):
            log["events"] = [
                e
                for e in log["events"]
                if e["type"] != "chain_dispatch_requested"
            ]
            for i, e in enumerate(log["events"], 1):
                e["seq"] = i
            log["next_seq"] = len(log["events"]) + 1

        self._rewrite(mutate)
        self._expect_recovery_fail()

    def test_isolate_without_prior_down_snapshot_fail_closed(self):
        self._build_pending_dispatch()
        self._set_adapters({"ad1": "down"})
        self.assertEqual(self._isolate()[0], 201)
        # 删除隔离之前的健康快照（全部 health 事件）：隔离事前无快照，矛盾
        def mutate(log):
            log["events"] = [
                e
                for e in log["events"]
                if e["type"] != "chain_adapter_health"
            ]
            for i, e in enumerate(log["events"], 1):
                e["seq"] = i
            log["next_seq"] = len(log["events"]) + 1

        self._rewrite(mutate)
        self._expect_recovery_fail()

    def test_isolate_when_adapter_was_up_fail_closed(self):
        self._build_pending_dispatch()
        self._set_adapters({"ad1": "down"})
        self.assertEqual(self._isolate()[0], 201)
        # 把隔离前的健康快照篡改为 up：事前原适配器非显式 down，矛盾
        def mutate(log):
            for e in log["events"]:
                if e["type"] == "chain_adapter_health":
                    e["details"]["adapters"]["ad1"] = "up"

        self._rewrite(mutate)
        self._expect_recovery_fail()

    def test_duplicate_isolate_fail_closed(self):
        self._build_pending_dispatch()
        self._set_adapters({"ad1": "down"})
        self.assertEqual(self._isolate()[0], 201)

        def mutate(log):
            dup = next(
                e
                for e in log["events"]
                if e["type"] == "chain_dispatch_isolated"
            )
            dup = json.loads(json.dumps(dup))
            dup["seq"] = log["next_seq"]
            log["events"].append(dup)
            log["next_seq"] += 1

        self._rewrite(mutate)
        self._expect_recovery_fail()

    def test_isolate_after_takeover_fail_closed(self):
        # 篡改出 takeover 先于 isolate 的序列：隔离之前不得有接管，矛盾。
        self._build_pending_dispatch()
        self._set_adapters({"ad1": "down", "ad2": "up"})
        self.assertEqual(self._isolate()[0], 201)
        self._approve_takeover()
        self.assertEqual(
            _call(
                self.svc.post_chain_dispatch_takeover,
                "w1", "dp1", "ad2", "ap2",
            )[0],
            201,
        )

        def mutate(log):
            iso = next(
                i
                for i, e in enumerate(log["events"])
                if e["type"] == "chain_dispatch_isolated"
            )
            to = next(
                i
                for i, e in enumerate(log["events"])
                if e["type"] == "chain_dispatch_taken_over"
            )
            evs = log["events"]
            evs[iso], evs[to] = evs[to], evs[iso]
            for i, e in enumerate(evs, 1):
                e["seq"] = i
            log["next_seq"] = len(evs) + 1

        self._rewrite(mutate)
        self._expect_recovery_fail()

    def test_result_after_isolate_without_takeover_fail_closed(self):
        # 篡改出 isolate 之后、无接管的结果事件：在线隔离态 result 一律
        # 409，故该序列矛盾。
        self._build_pending_dispatch()
        self._set_adapters({"ad1": "down"})
        self.assertEqual(self._isolate()[0], 201)

        def mutate(log):
            result = {
                "actor_id": "ad1",
                "at": "2026-09-20T00:00:00Z",
                "details": {
                    "dispatch_id": "dp1",
                    "operation_id": "op1",
                    "adapter_id": "ad1",
                    "chain_id": "chain-1",
                    "state": "failed",
                    "tx_id": None,
                },
                "reason": None,
                "request_id": "dp1",
                "seq": 0,
                "type": "chain_dispatch_result",
            }
            log["events"].append(result)
            for i, e in enumerate(log["events"], 1):
                e["seq"] = i
            log["next_seq"] = len(log["events"]) + 1

        self._rewrite(mutate)
        self._expect_recovery_fail()

    def test_isolate_details_out_of_order_fail_closed(self):
        self._build_pending_dispatch()
        self._set_adapters({"ad1": "down"})
        self.assertEqual(self._isolate()[0], 201)

        def mutate(log):
            for e in log["events"]:
                if e["type"] == "chain_dispatch_isolated":
                    e["details"] = {
                        "adapter_id": "ad1",
                        "dispatch_id": "dp1",
                        "state": "isolated",
                    }

        self._rewrite(mutate)
        self._expect_recovery_fail()

    def test_bad_audit_json_is_corrupt_data(self):
        self._build_pending_dispatch()
        self._set_adapters({"ad1": "down"})
        self.assertEqual(self._isolate()[0], 201)
        with open(self._audit_path(), "wb") as f:
            f.write(b"{broken")
        with self.assertRaises(CorruptDataError):
            self.svc._audit.chain_dispatch_isolated_events("w1")
        with self.assertRaises(CorruptDataError):
            make_harness(self.d)

    def test_backup_restore_keeps_isolation_and_seq(self):
        from threshold_wallet import drbackup

        out_dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, out_dir, ignore_errors=True)
        self._build_pending_dispatch()
        self._set_adapters({"ad1": "down"})
        self.assertEqual(self._isolate()[0], 201)
        out = os.path.join(out_dir, "snap.tar")
        result = drbackup.backup(self.d, "w1", "snap-1", out)
        self.assertEqual(result["status"], 201)
        d2 = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d2, ignore_errors=True)
        status, body = drbackup.restore(d2, "w1", out)
        self.assertEqual(status, 201)
        svc2 = make_harness(d2).service
        # 灾备恢复后隔离仍在、重放 200、seq 不增
        events_before = svc2.get_audit_events("w1")["events"]
        code, v = svc2.post_chain_dispatch_isolate("w1", "dp1")
        self.assertEqual(code, 200)
        self.assertEqual(v["state"], "isolated")
        self.assertEqual(
            svc2.get_audit_events("w1")["events"], events_before
        )

    # ---- HTTP 层 -----------------------------------------------------------

    def test_http_wire_compact_and_statuses(self):
        self._build_pending_dispatch()
        self._set_adapters({"ad1": "down"})
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
                "POST", "/v1/wallets/w1/chain/dp1/isolate", {}
            )
            self.assertEqual(status, 201)
            self.assertEqual(
                body,
                b'{"dispatch_id":"dp1","adapter_id":"ad1",'
                b'"state":"isolated"}',
            )
            self.assertFalse(body.endswith(b"\n"))
            status, body = raw(
                "POST", "/v1/wallets/w1/chain/dp1/isolate", {}
            )
            self.assertEqual(status, 200)
            # 夹带键 400
            self.assertEqual(
                raw(
                    "POST", "/v1/wallets/w1/chain/dp1/isolate",
                    {"extra": 1},
                )[0],
                400,
            )
            # 未知派发 404
            self.assertEqual(
                raw(
                    "POST", "/v1/wallets/w1/chain/nope/isolate", {}
                )[0],
                404,
            )

    def test_http_empty_body_is_400(self):
        self._build_pending_dispatch()
        self._set_adapters({"ad1": "down"})
        with http_server(self.d) as srv:
            req = urllib.request.Request(
                srv.base_url + "/v1/wallets/w1/chain/dp1/isolate",
                data=b"",
                method="POST",
                headers={"Content-Type": "application/json"},
            )
            try:
                with urllib.request.urlopen(req) as resp:
                    status = resp.status
            except urllib.error.HTTPError as exc:
                status = exc.code
            self.assertEqual(status, 400)


if __name__ == "__main__":
    unittest.main()
