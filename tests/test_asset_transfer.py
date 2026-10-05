"""原子资产转账（POST /v1/wallets/{id}/asset-transfers）测试。

覆盖：
- 成功 201：九键转账视图，来源减、目标加、两个 version 各加一，
  目标资产可新建；只追加一条 asset_transfer_committed 事件
  （details 即转账视图）作为提交点；
- 幂等：transfer_id 同参重放 200 原视图（不重新校验现场，expected_*
  任意合法值均不重新比较），异参 409 transfer conflict；
- 400：缺键/夹带/非对象体、两个资产相同、amount 非正的非布尔整数、
  expected_*_version 非非负整数、标识非法；404：钱包不存在（先于 400）；
- 409：asset version conflict / insufficient balance /
  wallet or asset frozen / transaction policy violation，全部零副作用；
- at_seq 历史、资产清单、审计筛选与 backup/restore 按事件序号同时
  反映两个资产的变化；
- 崩溃恢复：事件在则前滚、事件不在则整体回滚（绝不只恢复一边）；
  事件与账本无法对账时 503 保留现场。
"""

from __future__ import annotations

import json
import shutil
import tempfile
import threading
import unittest
import urllib.error
import urllib.request

from threshold_wallet import audit as audit_mod
from threshold_wallet import drbackup
from threshold_wallet.service import WalletService
from threshold_wallet.store import RecoveryError, WalletStore
from tests.helpers import http_server, make_harness


class AssetTransferHttpTest(unittest.TestCase):
    """HTTP 层语义：状态码、响应体、幂等与各 409 零副作用。"""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmpdir, ignore_errors=True)
        self._ctx = http_server(self.tmpdir)
        self.srv = self._ctx.__enter__()
        self.addCleanup(self._ctx.__exit__, None, None, None)
        status, _ = self.srv.request(
            "POST", "/v1/wallets", {"wallet_id": "w1", "shares": 2}
        )
        self.assertEqual(status, 201)
        self._fund("btc", 100)

    # ---- 辅助 -----------------------------------------------------------

    def _fund(self, asset_id, amount):
        op = f"fund-{asset_id}"
        status, _ = self.srv.request(
            "POST",
            "/v1/wallets/w1/asset-operations",
            {"operation_id": op, "asset_id": asset_id, "delta": amount},
        )
        self.assertEqual(status, 201)
        status, _ = self.srv.request(
            "POST", f"/v1/wallets/w1/asset-operations/{op}/commit"
        )
        self.assertEqual(status, 201)

    def _transfer(self, transfer_id, from_asset="btc", to_asset="eth",
                  amount=30, ev_from=1, ev_to=0, wallet_id="w1"):
        return self.srv.request(
            "POST",
            f"/v1/wallets/{wallet_id}/asset-transfers",
            {
                "transfer_id": transfer_id,
                "from_asset_id": from_asset,
                "to_asset_id": to_asset,
                "amount": amount,
                "expected_from_version": ev_from,
                "expected_to_version": ev_to,
            },
        )

    def _transfer_raw(self, raw, wallet_id="w1"):
        req = urllib.request.Request(
            self.srv.base_url + f"/v1/wallets/{wallet_id}/asset-transfers",
            data=raw,
            method="POST",
            headers={"Content-Type": "application/json"},
        )
        try:
            with urllib.request.urlopen(req) as resp:
                return resp.status, json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            return exc.code, json.loads(exc.read().decode("utf-8"))

    def _asset(self, asset_id):
        return self.srv.request("GET", f"/v1/wallets/w1/assets/{asset_id}")

    def _events(self, event_type=None):
        path = "/v1/wallets/w1/audit-events"
        if event_type is not None:
            path += f"?event_type={event_type}"
        status, events = self.srv.request("GET", path)
        self.assertEqual(status, 200)
        return events["events"]

    def _transfer_events(self):
        return self._events("asset_transfer_committed")

    # ---- 成功路径 ---------------------------------------------------------

    def test_commit_201_view_and_both_assets_updated(self):
        status, body = self._transfer("t1")
        self.assertEqual(status, 201)
        self.assertEqual(
            body,
            {
                "transfer_id": "t1",
                "from_asset_id": "btc",
                "to_asset_id": "eth",
                "amount": 30,
                "state": "committed",
                "from_balance": 70,
                "from_version": 2,
                "to_balance": 30,
                "to_version": 1,
            },
        )
        _, btc = self._asset("btc")
        self.assertEqual((btc["balance"], btc["version"]), (70, 2))
        _, eth = self._asset("eth")
        self.assertEqual((eth["balance"], eth["version"]), (30, 1))
        # 恰一条提交事件，details 即转账视图
        events = self._transfer_events()
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["request_id"], "t1")
        self.assertEqual(events[0]["details"], body)

    def test_transfer_between_existing_assets(self):
        self._fund("eth", 40)
        status, body = self._transfer("t1", amount=25, ev_from=1, ev_to=1)
        self.assertEqual(status, 201)
        self.assertEqual(
            (body["from_balance"], body["from_version"]), (75, 2)
        )
        self.assertEqual((body["to_balance"], body["to_version"]), (65, 2))

    def test_sequential_transfers_chain_versions(self):
        self.assertEqual(self._transfer("t1")[0], 201)
        status, body = self._transfer("t2", amount=10, ev_from=2, ev_to=1)
        self.assertEqual(status, 201)
        self.assertEqual(
            (body["from_balance"], body["from_version"]), (60, 3)
        )
        self.assertEqual((body["to_balance"], body["to_version"]), (40, 2))
        self.assertEqual(len(self._transfer_events()), 2)

    # ---- 幂等 -------------------------------------------------------------

    def test_same_params_replay_200_without_revalidation(self):
        status, committed = self._transfer("t1")
        self.assertEqual(status, 201)
        # 同参重放：expected_* 任意合法值也不重新校验现场
        for ev_from, ev_to in ((1, 0), (2, 1), (99, 99)):
            status, body = self._transfer(
                "t1", ev_from=ev_from, ev_to=ev_to
            )
            self.assertEqual(status, 200)
            self.assertEqual(body, committed)
        # 不重复改账、不重复记事件
        _, btc = self._asset("btc")
        self.assertEqual((btc["balance"], btc["version"]), (70, 2))
        self.assertEqual(len(self._transfer_events()), 1)

    def test_different_params_conflict_409(self):
        self.assertEqual(self._transfer("t1")[0], 201)
        for kwargs in (
            {"amount": 31},
            {"from_asset": "eth", "to_asset": "btc", "ev_from": 0,
             "ev_to": 1},
            {"to_asset": "usdt"},
        ):
            merged = {"amount": 30, "ev_from": 1, "ev_to": 0}
            merged.update(kwargs)
            status, body = self._transfer("t1", **merged)
            self.assertEqual(status, 409, kwargs)
            self.assertEqual(body, {"error": "transfer conflict"})
        self.assertEqual(len(self._transfer_events()), 1)

    # ---- 400 --------------------------------------------------------------

    def test_body_must_contain_exactly_six_keys(self):
        base = {
            "transfer_id": "t1",
            "from_asset_id": "btc",
            "to_asset_id": "eth",
            "amount": 30,
            "expected_from_version": 1,
            "expected_to_version": 0,
        }
        for key in base:
            body = {k: v for k, v in base.items() if k != key}
            status, _ = self.srv.request(
                "POST", "/v1/wallets/w1/asset-transfers", body
            )
            self.assertEqual(status, 400, f"missing {key}")
        status, _ = self.srv.request(
            "POST",
            "/v1/wallets/w1/asset-transfers",
            {**base, "extra": 1},
        )
        self.assertEqual(status, 400)
        self.assertEqual(self._transfer_events(), [])

    def test_non_object_and_malformed_body_400(self):
        for raw in (b"[1]", b'"x"', b"1", b"null", b"{not-json", b""):
            status, _ = self._transfer_raw(raw)
            self.assertEqual(status, 400, raw)

    def test_same_from_and_to_asset_400(self):
        status, _ = self._transfer("t1", to_asset="btc")
        self.assertEqual(status, 400)
        self.assertEqual(self._transfer_events(), [])

    def test_invalid_amount_400(self):
        for amount in (0, -1, True, False, 1.5, "30", None, [30]):
            status, _ = self._transfer("t1", amount=amount)
            self.assertEqual(status, 400, amount)
        self.assertEqual(self._transfer_events(), [])

    def test_invalid_expected_versions_400(self):
        for value in (True, False, None, -1, 1.5, "1", [0], {"v": 0}):
            status, _ = self._transfer("t1", ev_from=value)
            self.assertEqual(status, 400, value)
            status, _ = self._transfer("t1", ev_to=value)
            self.assertEqual(status, 400, value)
        self.assertEqual(self._transfer_events(), [])

    def test_invalid_ids_400(self):
        for bad in ("", "a b", "a/b", ".." , "x" * 129, 1, None):
            status, _ = self._transfer(bad)
            self.assertEqual(status, 400, bad)
            status, _ = self._transfer("t1", from_asset=bad)
            self.assertEqual(status, 400, bad)
            status, _ = self._transfer("t1", to_asset=bad)
            self.assertEqual(status, 400, bad)

    # ---- 404 --------------------------------------------------------------

    def test_missing_wallet_404_precedes_400(self):
        status, _ = self._transfer("t1", wallet_id="nope")
        self.assertEqual(status, 404)
        # 非法参数同样先 404
        status, _ = self._transfer("t1", amount=-5, wallet_id="nope")
        self.assertEqual(status, 404)

    # ---- 409：版本冲突 -----------------------------------------------------

    def test_version_conflict_409_zero_side_effects(self):
        self.assertEqual(self._transfer("t1")[0], 201)
        # from 版本滞留
        status, body = self._transfer("t2", ev_from=1, ev_to=1)
        self.assertEqual(status, 409)
        self.assertEqual(body, {"error": "asset version conflict"})
        # to 版本滞留
        status, body = self._transfer("t2", ev_from=2, ev_to=0)
        self.assertEqual(status, 409)
        self.assertEqual(body, {"error": "asset version conflict"})
        # 零副作用：余额/version 不变、无新事件、可用新版本重试
        _, btc = self._asset("btc")
        self.assertEqual((btc["balance"], btc["version"]), (70, 2))
        _, eth = self._asset("eth")
        self.assertEqual((eth["balance"], eth["version"]), (30, 1))
        self.assertEqual(len(self._transfer_events()), 1)
        status, committed = self._transfer("t2", ev_from=2, ev_to=1)
        self.assertEqual(status, 201)

    def test_missing_source_with_nonzero_expected_version_conflicts(self):
        status, body = self._transfer(
            "t1", from_asset="nope", ev_from=3, ev_to=0
        )
        self.assertEqual(status, 409)
        self.assertEqual(body, {"error": "asset version conflict"})

    def test_missing_target_with_nonzero_expected_version_conflicts(self):
        status, body = self._transfer("t1", ev_from=1, ev_to=2)
        self.assertEqual(status, 409)
        self.assertEqual(body, {"error": "asset version conflict"})

    # ---- 409：余额不足 -----------------------------------------------------

    def test_insufficient_balance_409_zero_side_effects(self):
        status, body = self._transfer("t1", amount=101)
        self.assertEqual(status, 409)
        self.assertEqual(body, {"error": "insufficient balance"})
        _, btc = self._asset("btc")
        self.assertEqual((btc["balance"], btc["version"]), (100, 1))
        self.assertEqual(self._transfer_events(), [])
        # 可重试
        self.assertEqual(self._transfer("t1")[0], 201)

    def test_missing_source_is_insufficient_balance(self):
        status, body = self._transfer(
            "t1", from_asset="nope", ev_from=0, ev_to=0
        )
        self.assertEqual(status, 409)
        self.assertEqual(body, {"error": "insufficient balance"})

    def test_full_balance_transfer_leaves_zero(self):
        status, body = self._transfer("t1", amount=100)
        self.assertEqual(status, 201)
        self.assertEqual(body["from_balance"], 0)
        _, btc = self._asset("btc")
        self.assertEqual((btc["balance"], btc["version"]), (0, 2))

    # ---- 409：冻结 ---------------------------------------------------------

    def test_frozen_wallet_409(self):
        status, _ = self.srv.request(
            "POST", "/v1/wallets/w1/freeze", {"reason": "halt"}
        )
        self.assertEqual(status, 201)
        status, body = self._transfer("t1")
        self.assertEqual(status, 409)
        self.assertEqual(body, {"error": "wallet or asset frozen"})
        self.assertEqual(self._transfer_events(), [])

    def test_frozen_from_or_to_asset_409(self):
        self._fund("eth", 40)
        status, _ = self.srv.request(
            "POST", "/v1/wallets/w1/assets/btc/freeze", {"reason": "inc"}
        )
        self.assertEqual(status, 201)
        status, body = self._transfer("t1", ev_from=1, ev_to=1)
        self.assertEqual(status, 409)
        self.assertEqual(body, {"error": "wallet or asset frozen"})
        # 作为目标侧同样被闸门拦截
        status, body = self._transfer(
            "t1", from_asset="eth", to_asset="btc", ev_from=1, ev_to=1
        )
        self.assertEqual(status, 409)
        self.assertEqual(body, {"error": "wallet or asset frozen"})
        self.assertEqual(self._transfer_events(), [])

    # ---- 409：交易策略 -----------------------------------------------------

    def _set_policy(self, max_delta=50, allowed=("btc", "eth")):
        status, _ = self.srv.request(
            "PUT",
            "/v1/wallets/w1/transaction-policy",
            {
                "mode": "hot",
                "max_delta": max_delta,
                "allowed_assets": list(allowed),
            },
        )
        self.assertEqual(status, 200)

    def test_policy_whitelist_and_max_delta_409(self):
        # 先构造 usdt 余额（策略生效前），随后白名单只含 btc/eth
        self._fund("usdt", 20)
        self._set_policy()
        # amount 超过 max_delta
        status, body = self._transfer("t1", amount=51)
        self.assertEqual(status, 409)
        self.assertEqual(body, {"error": "transaction policy violation"})
        # 目标不在白名单
        status, body = self._transfer("t2", to_asset="usdt", amount=10,
                                      ev_to=1)
        self.assertEqual(status, 409)
        self.assertEqual(body, {"error": "transaction policy violation"})
        # 来源不在白名单
        status, body = self._transfer(
            "t3", from_asset="usdt", to_asset="btc", amount=10,
            ev_from=1, ev_to=1,
        )
        self.assertEqual(status, 409)
        self.assertEqual(body, {"error": "transaction policy violation"})
        # 全部零副作用
        _, btc = self._asset("btc")
        self.assertEqual((btc["balance"], btc["version"]), (100, 1))
        self.assertEqual(self._transfer_events(), [])
        # 白名单内且不超额可成功
        status, _ = self._transfer("t4", amount=50)
        self.assertEqual(status, 201)

    # ---- 并发 --------------------------------------------------------------

    def test_concurrent_same_version_exactly_one_201(self):
        barrier = threading.Barrier(2)
        results = []

        def worker(tid):
            barrier.wait()
            results.append(self._transfer(tid))

        threads = [
            threading.Thread(target=worker, args=(tid,))
            for tid in ("t1", "t2")
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        statuses = sorted(status for status, _ in results)
        self.assertEqual(statuses, [201, 409])
        conflict = [b for s, b in results if s == 409][0]
        self.assertEqual(conflict, {"error": "asset version conflict"})
        self.assertEqual(len(self._transfer_events()), 1)
        _, btc = self._asset("btc")
        self.assertEqual(btc["version"], 2)

    # ---- at_seq 历史 / 资产清单 / 审计筛选 --------------------------------

    def test_at_seq_history_reflects_both_sides_at_transfer_seq(self):
        self.assertEqual(self._transfer("t1")[0], 201)
        (event,) = self._transfer_events()
        seq = event["seq"]
        # 边界落在转账事件上：两个资产同时反映新状态
        status, btc = self.srv.request(
            "GET", f"/v1/wallets/w1/assets/btc?at_seq={seq}"
        )
        self.assertEqual(status, 200)
        self.assertEqual((btc["balance"], btc["version"]), (70, 2))
        status, eth = self.srv.request(
            "GET", f"/v1/wallets/w1/assets/eth?at_seq={seq}"
        )
        self.assertEqual(status, 200)
        self.assertEqual((eth["balance"], eth["version"]), (30, 1))
        self.assertEqual(btc["head"], eth["head"])
        # 边界在转账前：来源旧状态，目标尚不存在
        status, btc = self.srv.request(
            "GET", f"/v1/wallets/w1/assets/btc?at_seq={seq - 1}"
        )
        self.assertEqual(status, 200)
        self.assertEqual((btc["balance"], btc["version"]), (100, 1))
        status, _ = self.srv.request(
            "GET", f"/v1/wallets/w1/assets/eth?at_seq={seq - 1}"
        )
        self.assertEqual(status, 404)

    def test_asset_list_reflects_both_sides(self):
        self.assertEqual(self._transfer("t1")[0], 201)
        (event,) = self._transfer_events()
        seq = event["seq"]
        status, listing = self.srv.request("GET", "/v1/wallets/w1/assets")
        self.assertEqual(status, 200)
        self.assertEqual(
            {a["asset_id"]: (a["balance"], a["version"])
             for a in listing["assets"]},
            {"btc": (70, 2), "eth": (30, 1)},
        )
        status, listing = self.srv.request(
            "GET", f"/v1/wallets/w1/assets?at_seq={seq - 1}"
        )
        self.assertEqual(status, 200)
        self.assertEqual(
            [a["asset_id"] for a in listing["assets"]], ["btc"]
        )

    def test_audit_events_filter_by_transfer_type(self):
        self.assertEqual(self._transfer("t1")[0], 201)
        events = self._events("asset_transfer_committed")
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["type"], "asset_transfer_committed")
        # 其他类型筛选不含转账事件
        committed = self._events("asset_operation_committed")
        self.assertEqual(
            [e["type"] for e in committed], ["asset_operation_committed"]
        )


class AssetTransferRecoveryTest(unittest.TestCase):
    """崩溃一致性与对账：事件为唯一提交点，绝不只恢复一边。"""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.h = make_harness(self.tmp)
        self.svc = self.h.service
        self.store = self.h.store
        self.svc.create_wallet("w1", 2)
        self.svc.create_asset_operation("w1", "op1", "btc", 100)
        self.svc.commit_asset_operation("w1", "op1")

    def _intent(self, transfer_id="t1", amount=30):
        return {
            "kind": "transfer",
            "transfer_id": transfer_id,
            "from_asset_id": "btc",
            "to_asset_id": "eth",
            "amount": amount,
            "old_from_asset": {"balance": 100, "version": 1},
            "old_to_asset": None,
            "committed": {
                "transfer_id": transfer_id,
                "from_asset_id": "btc",
                "to_asset_id": "eth",
                "amount": amount,
                "state": "committed",
                "from_balance": 100 - amount,
                "from_version": 2,
                "to_balance": amount,
                "to_version": 1,
            },
        }

    def test_crash_before_event_rolls_back_both_sides(self):
        intent = self._intent()
        self.store.write_asset_commit_intent("w1", "t1", intent)
        self.store.commit_asset_transfer(
            "w1", "t1", intent["committed"],
            "btc", {"balance": 70, "version": 2},
            "eth", {"balance": 30, "version": 1},
        )
        # 重启（新 service）后首次访问触发自愈：整体回滚
        svc = WalletService(WalletStore(self.tmp))
        btc = svc.get_asset("w1", "btc")
        self.assertEqual((btc["balance"], btc["version"]), (100, 1))
        with self.assertRaises(Exception) as cm:
            svc.get_asset("w1", "eth")
        self.assertEqual(getattr(cm.exception, "status", None), 404)
        self.assertIsNone(self.store.get_asset_transfer("w1", "t1"))
        self.assertEqual(self.store.list_asset_intents("w1"), [])
        # 无转账事件、可重新转账
        events = svc.get_audit_events("w1")["events"]
        self.assertEqual(
            [e["type"] for e in events], ["asset_operation_committed"]
        )
        self.assertEqual(
            svc.create_asset_transfer("w1", "t1", "btc", "eth", 30, 1, 0)[0],
            201,
        )

    def test_crash_after_event_rolls_forward_both_sides(self):
        intent = self._intent()
        self.store.write_asset_commit_intent("w1", "t1", intent)
        self.svc._emit(
            "w1",
            self.svc._audit_event(
                audit_mod.TYPE_ASSET_TRANSFER_COMMITTED,
                request_id="t1",
                details=intent["committed"],
            ),
        )
        # 账本未落、意图未删：自愈按事件 R 前滚补齐两个资产
        svc = WalletService(WalletStore(self.tmp))
        btc = svc.get_asset("w1", "btc")
        self.assertEqual((btc["balance"], btc["version"]), (70, 2))
        eth = svc.get_asset("w1", "eth")
        self.assertEqual((eth["balance"], eth["version"]), (30, 1))
        self.assertEqual(self.store.list_asset_intents("w1"), [])
        # 不重复记事件；同参重放 200
        events = svc.get_audit_events("w1")["events"]
        self.assertEqual(
            [e["type"] for e in events].count("asset_transfer_committed"), 1
        )
        self.assertEqual(
            svc.create_asset_transfer("w1", "t1", "btc", "eth", 30, 0, 0)[0],
            200,
        )

    def test_event_append_failure_rolls_back_without_seq_gap(self):
        real_append = self.svc._audit.append_event

        def boom(wallet_id, event):
            if event.get("type") == "asset_transfer_committed":
                raise OSError("audit disk full")
            return real_append(wallet_id, event)

        self.svc._audit.append_event = boom
        try:
            with self.assertRaises(OSError):
                self.svc.create_asset_transfer(
                    "w1", "t1", "btc", "eth", 30, 1, 0
                )
        finally:
            self.svc._audit.append_event = real_append
        # 两个资产一起回滚，绝不只恢复一边；无意图、无事件、无 seq 缺口
        self.assertEqual(
            self.store.get_asset("w1", "btc"),
            {"balance": 100, "version": 1},
        )
        self.assertIsNone(self.store.get_asset("w1", "eth"))
        self.assertIsNone(self.store.get_asset_transfer("w1", "t1"))
        self.assertEqual(self.store.list_asset_intents("w1"), [])
        events = self.svc.get_audit_events("w1")["events"]
        self.assertEqual([e["seq"] for e in events], [1])
        # 重试首提 201
        code, body = self.svc.create_asset_transfer(
            "w1", "t1", "btc", "eth", 30, 1, 0
        )
        self.assertEqual(code, 201)
        self.assertEqual((body["from_balance"], body["to_balance"]), (70, 30))
        events = self.svc.get_audit_events("w1")["events"]
        self.assertEqual([e["seq"] for e in events], [1, 2])

    def test_orphan_transfer_event_refuses_startup_and_503s(self):
        # 有事件无账本转账：不可对账，保留现场并拒绝就绪/503
        self.svc._emit(
            "w1",
            self.svc._audit_event(
                audit_mod.TYPE_ASSET_TRANSFER_COMMITTED,
                request_id="t9",
                details=self._intent("t9")["committed"],
            ),
        )
        with self.assertRaises(RecoveryError):
            WalletService(WalletStore(self.tmp))
        with self.assertRaises(RecoveryError):
            self.svc.get_asset("w1", "btc")

    def test_ledger_transfer_without_event_refuses_startup_and_503s(self):
        intent = self._intent()
        self.store.commit_asset_transfer(
            "w1", "t1", intent["committed"],
            "btc", {"balance": 70, "version": 2},
            "eth", {"balance": 30, "version": 1},
        )
        with self.assertRaises(RecoveryError):
            WalletService(WalletStore(self.tmp))
        with self.assertRaises(RecoveryError):
            self.svc.get_asset("w1", "btc")

    def test_malformed_intent_refuses_startup_and_keeps_scene(self):
        self.store.write_asset_commit_intent(
            "w1", "t1", {"kind": "transfer", "transfer_id": "t1"}
        )
        with self.assertRaises(RecoveryError):
            WalletService(WalletStore(self.tmp))
        with self.assertRaises(RecoveryError):
            self.svc.get_asset("w1", "btc")
        # 现场保留：意图未被清理
        self.assertIsNotNone(self.store.get_asset_commit_intent("w1", "t1"))


class AssetTransferBackupRestoreTest(unittest.TestCase):
    """backup/restore 必须按同一序号同时反映两个资产的变化。"""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.h = make_harness(self.tmp)
        self.svc = self.h.service
        self.svc.create_wallet("w1", 2)
        self.svc.create_asset_operation("w1", "op1", "btc", 100)
        self.svc.commit_asset_operation("w1", "op1")
        self.assertEqual(
            self.svc.create_asset_transfer(
                "w1", "t1", "btc", "eth", 30, 1, 0
            )[0],
            201,
        )

    def test_backup_restore_round_trip(self):
        import os

        out = os.path.join(tempfile.mkdtemp(), "snap.tar")
        drbackup.backup(self.tmp, "w1", "S1", out)
        tmp2 = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmp2, ignore_errors=True)
        svc2 = WalletService(WalletStore(tmp2))
        svc2.create_wallet("w1", 2)
        drbackup.restore(tmp2, "w1", out)
        # 两个资产与序号一致恢复
        btc = svc2.get_asset("w1", "btc")
        self.assertEqual((btc["balance"], btc["version"]), (70, 2))
        eth = svc2.get_asset("w1", "eth")
        self.assertEqual((eth["balance"], eth["version"]), (30, 1))
        # 幂等重放仍命中原视图
        self.assertEqual(
            svc2.create_asset_transfer("w1", "t1", "btc", "eth", 30, 0, 0)[0],
            200,
        )
        # 恢复后可继续转账，version/seq 接续
        code, body = svc2.create_asset_transfer(
            "w1", "t2", "eth", "btc", 5, 1, 2
        )
        self.assertEqual(code, 201)
        self.assertEqual((body["from_balance"], body["to_balance"]), (25, 75))
        integrity = svc2.get_audit_integrity("w1")
        self.assertEqual(integrity["state"], "valid")


if __name__ == "__main__":
    unittest.main()
