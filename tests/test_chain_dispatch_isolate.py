"""跨链派发隔离（POST /v1/wallets/{W}/chain/{D}/isolate）测试。

覆盖：
- 体须恰为 ``{}``（夹带键/非对象/非 JSON/空体均 400）；路径 W/D 非法 400；
  钱包/派发未知 404；
- 首提前置：资产操作仍 pending、该派发尚无 result/takeover/isolate、派发
  原适配器在**当前**健康表中显式 down（未配置/缺席/up 一律 409）；任一不
  满足 409 且零副作用（均为 ServiceError）；
- 首提 201 返回 V={dispatch_id,adapter_id,state:"isolated"}（键序固定）；
  同 D 重放优先 200 同 V（事后翻转健康表不影响幂等）；锁内并发仅一 201；
- chain_dispatch_isolated 七字段是唯一提交事件：request_id=D、
  actor_id/reason=null、details=V（三键既定序），重放不记事件；
- 隔离后旧适配器 result（failed/broadcasted）一律 409；既有 failed 与
  isolated 两种前置都可由新适配器接管，新适配器显式 down 时 409；接管后
  新适配器 result/confirm/finality/settle 契约不变；
- 恢复按 seq 复核：派发在先、事前健康表显式 down、操作 pending、与
  result/takeover 互斥、每 D 至多一次；矛盾 RecoveryError、坏 JSON
  CorruptDataError（HTTP 503、serve 拒绝就绪）；重启/灾备/重放不增事件；
- HTTP 成功/错误体均为紧凑 UTF-8 JSON（无末换行）。
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
    """建钱包/策略/审批/派发的共用装配。"""

    def _dispatch_only(self, dispatch_id="dp1", adapter_id="ad1"):
        self.svc.create_wallet("w1", 2)
        self.svc.put_policy("w1", 1, 600)
        code, _ = self.svc.create_asset_operation("w1", "op1", "BTC", 100)
        self.assertEqual(code, 201)
        self.svc.put_chain_policy("w1", "BTC", "chain-1", True, 3, 2)
        code, _ = self.svc.create_sign_request(
            "w1", "ap1",
            _dispatch_msg(dispatch_id=dispatch_id, adapter_id=adapter_id),
        )
        self.assertEqual(code, 201)
        self.svc.approve("w1", "ap1", "boss")
        code, _ = self.svc.post_chain_dispatch(
            "w1", "op1", dispatch_id, adapter_id, "ap1"
        )
        self.assertEqual(code, 201)

    def _isolated_dispatch(self, dispatch_id="dp1"):
        self._dispatch_only(dispatch_id=dispatch_id)
        self.svc.put_chain_adapters("w1", {"ad1": "down"})
        code, v = self.svc.post_chain_dispatch_isolate("w1", dispatch_id)
        self.assertEqual(code, 201)
        return v

    def _approve_takeover(self, approval="ap2", adapter_id="ad2"):
        code, _ = self.svc.create_sign_request(
            "w1", approval, _takeover_msg(adapter_id=adapter_id)
        )
        self.assertEqual(code, 201)
        self.svc.approve("w1", approval, "boss")

    def _isolate(self, wallet="w1", dispatch_id="dp1"):
        return _call(self.svc.post_chain_dispatch_isolate, wallet, dispatch_id)

    def _isolate_events(self, svc=None, dispatch_id="dp1"):
        svc = svc or self.svc
        return [
            e
            for e in svc.get_audit_events("w1")["events"]
            if e["type"] == "chain_dispatch_isolated"
            and e["request_id"] == dispatch_id
        ]

    def _audit_path(self):
        return os.path.join(self.d, "audit", "w1.json")

    def _rewrite(self, mutate):
        with open(self._audit_path(), encoding="utf-8") as f:
            log = json.load(f)
        mutate(log)
        with open(self._audit_path(), "w", encoding="utf-8") as f:
            json.dump(log, f)


class IsolateServiceTest(_SceneMixin, unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.d, ignore_errors=True)
        self.h = make_harness(self.d)
        self.svc = self.h.service

    # ---- 201 / 视图 / 事件形状 --------------------------------------------

    def test_first_isolate_201_view_and_event(self):
        self._dispatch_only()
        self.svc.put_chain_adapters("w1", {"ad1": "down"})
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
        # 落盘外层七字段规范序
        with open(self._audit_path(), encoding="utf-8") as f:
            raw = f.read()
        isolate_record = next(
            line for line in raw.splitlines()
            if '"chain_dispatch_isolated"' in line
        )
        self.assertIn('"type": "chain_dispatch_isolated"', isolate_record)

    def test_event_is_the_only_commit_point(self):
        self._isolated_dispatch()
        events_before = self.svc.get_audit_events("w1")["events"]
        # 重放不记事件
        self.assertEqual(self._isolate()[0], 200)
        self.assertEqual(
            self.svc.get_audit_events("w1")["events"], events_before
        )

    def test_replay_200_same_view_even_if_adapter_back_up(self):
        v1 = self._isolated_dispatch()
        # 事后把适配器翻回 up：同 D 重放仍优先 200 同 V，不复查健康表
        self.svc.put_chain_adapters("w1", {"ad1": "up"})
        code, v2 = self._isolate()
        self.assertEqual(code, 200)
        self.assertEqual(v2, v1)
        # 翻表记了一条健康事件，但没有新的隔离事件
        self.assertEqual(len(self._isolate_events()), 1)

    # ---- 400 / 404 ---------------------------------------------------------

    def test_bad_dispatch_id_400(self):
        self._dispatch_only()
        self.svc.put_chain_adapters("w1", {"ad1": "down"})
        for bad in ("", "has space", "a/b", "x" * 129):
            self.assertEqual(self._isolate(dispatch_id=bad)[0], 400, bad)

    def test_unknown_wallet_or_dispatch_404(self):
        self._dispatch_only()
        self.svc.put_chain_adapters("w1", {"ad1": "down"})
        self.assertEqual(self._isolate(wallet="w9")[0], 404)
        self.assertEqual(self._isolate(dispatch_id="nope")[0], 404)

    # ---- 409 前置与零副作用 ------------------------------------------------

    def test_no_health_table_409(self):
        self._dispatch_only()
        events_before = self.svc.get_audit_events("w1")["events"]
        self.assertEqual(self._isolate()[0], 409)
        self.assertEqual(
            self.svc.get_audit_events("w1")["events"], events_before
        )
        self.assertEqual(self._isolate_events(), [])

    def test_adapter_absent_or_up_409(self):
        self._dispatch_only()
        # 适配器缺席：视为 up，不隔离
        self.svc.put_chain_adapters("w1", {"ad9": "down"})
        self.assertEqual(self._isolate()[0], 409)
        # 显式 up
        self.svc.put_chain_adapters("w1", {"ad1": "up"})
        self.assertEqual(self._isolate()[0], 409)
        self.assertEqual(self._isolate_events(), [])

    def test_with_result_409(self):
        self._dispatch_only()
        # failed 结果后不能隔离（接管是 failed 的恢复路径）
        self.svc.post_chain_dispatch_result("w1", "dp1", "ad1", "failed", None)
        self.svc.put_chain_adapters("w1", {"ad1": "down"})
        self.assertEqual(self._isolate()[0], 409)
        self.assertEqual(self._isolate_events(), [])

    def test_after_takeover_409(self):
        self._dispatch_only()
        self.svc.post_chain_dispatch_result("w1", "dp1", "ad1", "failed", None)
        self._approve_takeover()
        self.svc.post_chain_dispatch_takeover("w1", "dp1", "ad2", "ap2")
        # 已接管的派发不能隔离
        self.assertEqual(self._isolate()[0], 409)
        self.assertEqual(self._isolate_events(), [])

    def test_committed_operation_409(self):
        self._dispatch_only()
        # 该资产启用了链确认策略：达门槛报告按既有 commit 契约自动提交，
        # 派发在提交之前创建（合法现场）。
        tx = "ab" * 32
        block_hash = "01" * 32
        code, _ = _call(
            self.svc.post_chain_report,
            "w1", "op1", "chain-1", tx, 10, block_hash, 3,
        )
        self.assertEqual(code, 201)
        self.assertEqual(
            self.h.store.get_asset_operation("w1", "op1")["state"],
            "committed",
        )
        self.svc.put_chain_adapters("w1", {"ad1": "down"})
        self.assertEqual(self._isolate()[0], 409)
        self.assertEqual(self._isolate_events(), [])

    def test_409_has_zero_side_effects(self):
        self._dispatch_only()
        events_before = self.svc.get_audit_events("w1")["events"]
        # 无健康表 409
        self.assertEqual(self._isolate()[0], 409)
        self.assertEqual(
            self.svc.get_audit_events("w1")["events"], events_before
        )

    # ---- 并发 --------------------------------------------------------------

    def test_concurrent_single_201_rest_200(self):
        self._dispatch_only()
        self.svc.put_chain_adapters("w1", {"ad1": "down"})
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

    # ---- 隔离后旧适配器 result 409 -----------------------------------------

    def test_old_adapter_result_after_isolation_409(self):
        self._isolated_dispatch()
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
                "w1", "dp1", "ad1", "broadcasted", TX2,
            )[0],
            409,
        )

    # ---- 从 isolated 接管 --------------------------------------------------

    def test_takeover_from_isolated_201(self):
        v = self._isolated_dispatch()
        self._approve_takeover()
        # 新适配器显式 down：409
        self.svc.put_chain_adapters("w1", {"ad1": "down", "ad2": "down"})
        self.assertEqual(
            _call(
                self.svc.post_chain_dispatch_takeover,
                "w1", "dp1", "ad2", "ap2",
            )[0],
            409,
        )
        # 新适配器恢复 up：可从 isolated 接管
        self.svc.put_chain_adapters("w1", {"ad1": "down", "ad2": "up"})
        code, tv = self.svc.post_chain_dispatch_takeover(
            "w1", "dp1", "ad2", "ap2"
        )
        self.assertEqual(code, 201)
        self.assertEqual(
            tv,
            {"dispatch_id": "dp1", "adapter_id": "ad2",
             "state": "requested"},
        )
        # 接管后隔离事件仍在、重放 200
        self.assertEqual(len(self._isolate_events()), 1)
        self.assertEqual(self._isolate()[0], 200)
        self.assertEqual(self._isolate()[1], v)

    def test_takeover_from_isolated_same_adapter_409(self):
        self._isolated_dispatch()
        self._approve_takeover(adapter_id="ad1")
        self.svc.put_chain_adapters("w1", {"ad1": "down"})
        self.assertEqual(
            _call(
                self.svc.post_chain_dispatch_takeover,
                "w1", "dp1", "ad1", "ap2",
            )[0],
            409,
        )

    def test_takeover_from_failed_also_rejects_down_new_adapter(self):
        # 既有 failed 接管规则不变，但新增：新适配器显式 down 时 409
        self._dispatch_only()
        self.svc.post_chain_dispatch_result("w1", "dp1", "ad1", "failed", None)
        self._approve_takeover()
        self.svc.put_chain_adapters("w1", {"ad1": "down", "ad2": "down"})
        self.assertEqual(
            _call(
                self.svc.post_chain_dispatch_takeover,
                "w1", "dp1", "ad2", "ap2",
            )[0],
            409,
        )
        self.svc.put_chain_adapters("w1", {"ad1": "down", "ad2": "up"})
        self.assertEqual(
            self.svc.post_chain_dispatch_takeover(
                "w1", "dp1", "ad2", "ap2"
            )[0],
            201,
        )

    def test_full_chain_after_isolated_takeover(self):
        self._isolated_dispatch()
        self._approve_takeover()
        self.svc.put_chain_adapters("w1", {"ad1": "down", "ad2": "up"})
        self.assertEqual(
            self.svc.post_chain_dispatch_takeover(
                "w1", "dp1", "ad2", "ap2"
            )[0],
            201,
        )
        self.assertEqual(
            self.svc.post_chain_dispatch_result(
                "w1", "dp1", "ad2", "broadcasted", TX2
            )[0],
            201,
        )
        code, v = _call(
            self.svc.post_chain_dispatch_confirmation,
            "w1", "dp1", "ad2", TX2, 10, BH1, 3,
        )
        self.assertEqual(code, 201)
        self.assertEqual(v["state"], "finalized")
        self.assertEqual(
            self.svc.get_chain_dispatch_finality("w1", "dp1")[
                "confirmation"
            ]["state"],
            "finalized",
        )
        code, r = self.svc.settle_chain_dispatch("w1", "dp1")
        self.assertEqual(code, 201)
        self.assertEqual(r["state"], "committed")

    # ---- 重启与恢复 --------------------------------------------------------

    def test_restart_preserves_isolation_and_replays(self):
        v = self._isolated_dispatch()
        before = self.svc.get_audit_events("w1")["events"]
        svc2 = make_harness(self.d).service
        self.assertEqual(svc2.get_audit_events("w1")["events"], before)
        code, v2 = svc2.post_chain_dispatch_isolate("w1", "dp1")
        self.assertEqual(code, 200)
        self.assertEqual(v2, v)

    def _expect_recovery_fail(self, error=RecoveryError):
        with self.assertRaises(error):
            make_harness(self.d)

    def test_isolated_details_out_of_order_fail_closed(self):
        self._isolated_dispatch()

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

    def test_isolated_non_null_actor_fail_closed(self):
        self._isolated_dispatch()

        def mutate(log):
            for e in log["events"]:
                if e["type"] == "chain_dispatch_isolated":
                    e["actor_id"] = "ap1"

        self._rewrite(mutate)
        self._expect_recovery_fail()

    def test_isolated_bad_state_fail_closed(self):
        self._isolated_dispatch()

        def mutate(log):
            for e in log["events"]:
                if e["type"] == "chain_dispatch_isolated":
                    e["details"]["state"] = "requested"

        self._rewrite(mutate)
        self._expect_recovery_fail()

    def test_duplicate_isolate_fail_closed(self):
        self._isolated_dispatch()

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

    def test_isolate_without_dispatch_fail_closed(self):
        self._isolated_dispatch()

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

    def test_isolate_without_down_snapshot_fail_closed(self):
        # 删除隔离之前的健康快照（留下之后无快照）：事前无显式 down
        self._isolated_dispatch()

        def mutate(log):
            log["events"] = [
                e for e in log["events"]
                if e["type"] != "chain_adapter_health"
            ]
            for i, e in enumerate(log["events"], 1):
                e["seq"] = i
            log["next_seq"] = len(log["events"]) + 1

        self._rewrite(mutate)
        self._expect_recovery_fail()

    def test_isolate_snapshot_not_down_fail_closed(self):
        self._isolated_dispatch()

        def mutate(log):
            for e in log["events"]:
                if e["type"] == "chain_adapter_health":
                    e["details"]["adapters"]["ad1"] = "up"

        self._rewrite(mutate)
        self._expect_recovery_fail()

    def test_isolate_after_committed_operation_fail_closed(self):
        self._isolated_dispatch()

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
                if event["type"] == "chain_dispatch_isolated":
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

    def test_result_before_isolate_fail_closed(self):
        # 派发请求与隔离之间插入一条旧适配器 failed 结果：result 与隔离
        # 互斥在前，矛盾现场 fail-closed。
        self._isolated_dispatch()

        def mutate(log):
            failed = {
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
                "type": "chain_dispatch_result",
            }
            for i, event in enumerate(log["events"]):
                if event["type"] == "chain_dispatch_isolated":
                    log["events"].insert(i, failed)
                    break
            for i, event in enumerate(log["events"], 1):
                event["seq"] = i
            log["next_seq"] = len(log["events"]) + 1

        self._rewrite(mutate)
        self._expect_recovery_fail()

    def test_bad_audit_json_is_corrupt_data(self):
        self._isolated_dispatch()
        with open(self._audit_path(), "w", encoding="utf-8") as f:
            f.write("{broken")
        self._expect_recovery_fail(error=CorruptDataError)

    # ---- 灾备 --------------------------------------------------------------

    def test_backup_restore_preserves_isolation(self):
        from threshold_wallet import drbackup

        self._isolated_dispatch()
        snap = os.path.join(self.d + "-out", "snap.tar")
        os.makedirs(self.d + "-out", exist_ok=True)
        self.addCleanup(shutil.rmtree, self.d + "-out", ignore_errors=True)
        drbackup.backup(self.d, "w1", "snap-1", snap)
        restore_dir = self.d + "-restore"
        os.makedirs(restore_dir, exist_ok=True)
        self.addCleanup(shutil.rmtree, restore_dir, ignore_errors=True)
        status, body = drbackup.restore(restore_dir, "w1", snap)
        self.assertEqual(status, 201)
        svc2 = make_harness(restore_dir).service
        code, v = svc2.post_chain_dispatch_isolate("w1", "dp1")
        self.assertEqual(code, 200)
        self.assertEqual(v["state"], "isolated")
        # 恢复本身不新增事件
        self.assertEqual(
            len(svc2.get_audit_events("w1")["events"]),
            len(self.svc.get_audit_events("w1")["events"]),
        )


class IsolateHttpTest(_SceneMixin, unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.d, ignore_errors=True)

    def _raw(self, srv, method, path, raw_body):
        headers = {}
        data = None
        if raw_body is not None:
            data = raw_body
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

    def test_http_body_wire_and_statuses(self):
        with http_server(self.d) as srv:
            self.h = srv.harness
            self.svc = srv.harness.service
            self._dispatch_only()
            self.svc.put_chain_adapters("w1", {"ad1": "down"})

            status, body = self._raw(
                srv, "POST", "/v1/wallets/w1/chain/dp1/isolate", b"{}"
            )
            self.assertEqual(status, 201)
            self.assertEqual(
                body,
                b'{"dispatch_id":"dp1","adapter_id":"ad1",'
                b'"state":"isolated"}',
            )
            self.assertFalse(body.endswith(b"\n"))
            # 重放 200 同字节
            status, body = self._raw(
                srv, "POST", "/v1/wallets/w1/chain/dp1/isolate", b"{}"
            )
            self.assertEqual(status, 200)
            self.assertEqual(
                body,
                b'{"dispatch_id":"dp1","adapter_id":"ad1",'
                b'"state":"isolated"}',
            )
            # 夹带键 400
            self.assertEqual(
                self._raw(
                    srv, "POST",
                    "/v1/wallets/w1/chain/dp1/isolate", b'{"x":1}',
                )[0],
                400,
            )
            # 空体 400
            self.assertEqual(
                self._raw(
                    srv, "POST",
                    "/v1/wallets/w1/chain/dp1/isolate", b"",
                )[0],
                400,
            )
            # 非法 JSON 400
            self.assertEqual(
                self._raw(
                    srv, "POST",
                    "/v1/wallets/w1/chain/dp1/isolate", b"{broken",
                )[0],
                400,
            )
            # 非对象 400
            self.assertEqual(
                self._raw(
                    srv, "POST",
                    "/v1/wallets/w1/chain/dp1/isolate", b"[]",
                )[0],
                400,
            )
            # 未知派发 404
            self.assertEqual(
                self._raw(
                    srv, "POST",
                    "/v1/wallets/w1/chain/nope/isolate", b"{}",
                )[0],
                404,
            )
            # 非法路径 D 400
            self.assertEqual(
                self._raw(
                    srv, "POST",
                    "/v1/wallets/w1/chain/bad%2Fid/isolate", b"{}",
                )[0],
                400,
            )
            # 未知钱包 404
            self.assertEqual(
                self._raw(
                    srv, "POST",
                    "/v1/wallets/w9/chain/dp1/isolate", b"{}",
                )[0],
                404,
            )

    def test_http_503_on_corrupt_scene(self):
        with http_server(self.d) as srv:
            self.h = srv.harness
            self.svc = srv.harness.service
            self._isolated_dispatch()
            audit_path = os.path.join(self.d, "audit", "w1.json")
            with open(audit_path, "w", encoding="utf-8") as f:
                f.write("{broken")
            status, body = self._raw(
                srv, "POST", "/v1/wallets/w1/chain/dp1/isolate", b"{}"
            )
            self.assertEqual(status, 503)
            self.assertNotIn("dp1", body.decode("utf-8"))


if __name__ == "__main__":
    unittest.main()
