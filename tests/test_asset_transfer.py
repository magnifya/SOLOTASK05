"""原子资产转账：POST /v1/wallets/{id}/asset-transfers。

覆盖任务契约：
- 请求体恰含 transfer_id/from_asset_id/to_asset_id/amount/
  expected_from_version/expected_to_version 六键；两资产不得相同，
  amount 为非布尔正整数，两个版本为非布尔非负整数；非法 400、未知
  钱包 404；
- 成功 201 返回转账视图九键，来源减、目标加、两个 version 各加一，
  状态 committed，目标可新建；只追加一条 asset_transfer_committed
  审计事件（details 即转账视图）作为提交点；
- 版本冲突 409 "asset version conflict"、来源不存在或余额不足 409
  "insufficient balance"、钱包或任一资产冻结 409 "wallet or asset
  frozen"、交易策略白名单/上限 409 "transaction policy violation"，
  均零副作用；
- transfer_id 同参重放 200 原视图（不重新校验现场），异参 409
  "transfer conflict"；
- at_seq 历史、资产清单、审计筛选、重启与 backup/restore 按事件序号
  同时反映两侧变化；崩溃恢复绝不只恢复一边；输出不含私钥材料。
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

from threshold_wallet import drbackup
from threshold_wallet.audit import AuditStore
from threshold_wallet.service import WalletService
from threshold_wallet.store import WalletStore
from tests.helpers import http_server, make_harness


class AssetTransferHttpTest(unittest.TestCase):
    """HTTP 边界：状态码、响应体、审计与历史读。"""

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
        # btc=100 (v1, seq1)、eth=50 (v1, seq2)
        self._seed("op1", "btc", 100)
        self._seed("op2", "eth", 50)

    # ---- 辅助 -------------------------------------------------------------

    def _seed(self, operation_id, asset_id, delta):
        status, _ = self.srv.request(
            "POST",
            "/v1/wallets/w1/asset-operations",
            {"operation_id": operation_id, "asset_id": asset_id,
             "delta": delta},
        )
        assert status == 201
        status, _ = self.srv.request(
            "POST",
            f"/v1/wallets/w1/asset-operations/{operation_id}/commit",
        )
        assert status == 201

    def _transfer(self, transfer_id="t1", frm="btc", to="eth", amount=30,
                  efv=1, etv=1, wallet="w1", **overrides):
        body = {
            "transfer_id": transfer_id,
            "from_asset_id": frm,
            "to_asset_id": to,
            "amount": amount,
            "expected_from_version": efv,
            "expected_to_version": etv,
        }
        body.update(overrides)
        return self.srv.request(
            "POST", f"/v1/wallets/{wallet}/asset-transfers", body
        )

    def _transfer_raw(self, raw, wallet="w1"):
        req = urllib.request.Request(
            self.srv.base_url + f"/v1/wallets/{wallet}/asset-transfers",
            data=raw,
            method="POST",
            headers={"Content-Type": "application/json"},
        )
        try:
            with urllib.request.urlopen(req) as resp:
                return resp.status, json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            return exc.code, json.loads(exc.read().decode("utf-8"))

    def _asset(self, asset_id, query=""):
        suffix = f"?{query}" if query else ""
        return self.srv.request(
            "GET", f"/v1/wallets/w1/assets/{asset_id}{suffix}"
        )

    def _assets(self, query=""):
        suffix = f"?{query}" if query else ""
        return self.srv.request("GET", f"/v1/wallets/w1/assets{suffix}")

    def _events(self):
        status, body = self.srv.request("GET", "/v1/wallets/w1/audit-events")
        assert status == 200
        return body["events"]

    def _transfer_events(self):
        return [
            e for e in self._events()
            if e["type"] == "asset_transfer_committed"
        ]

    # ---- 成功路径 -----------------------------------------------------------

    def test_commit_201_view_and_both_assets_updated(self):
        status, body = self._transfer()
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
                "to_balance": 80,
                "to_version": 2,
            },
        )
        _, btc = self._asset("btc")
        self.assertEqual((btc["balance"], btc["version"]), (70, 2))
        _, eth = self._asset("eth")
        self.assertEqual((eth["balance"], eth["version"]), (80, 2))

    def test_target_asset_created_by_transfer(self):
        status, body = self._transfer(to="usd", amount=10, etv=0)
        self.assertEqual(status, 201)
        self.assertEqual((body["to_balance"], body["to_version"]), (10, 1))
        _, usd = self._asset("usd")
        self.assertEqual((usd["balance"], usd["version"]), (10, 1))

    def test_transfer_all_of_source_balance(self):
        status, body = self._transfer(amount=100)
        self.assertEqual(status, 201)
        self.assertEqual(body["from_balance"], 0)

    # ---- 幂等重放 -----------------------------------------------------------

    def test_replay_same_params_200_same_view_no_new_event(self):
        status, committed = self._transfer()
        self.assertEqual(status, 201)
        status, replay = self._transfer()
        self.assertEqual(status, 200)
        self.assertEqual(replay, committed)
        self.assertEqual(len(self._transfer_events()), 1)
        _, btc = self._asset("btc")
        self.assertEqual((btc["balance"], btc["version"]), (70, 2))

    def test_replay_ignores_expected_versions(self):
        status, committed = self._transfer()
        self.assertEqual(status, 201)
        # 乐观版本是现场校验而非转账身份：重放不重新比较
        for efv, etv in ((0, 0), (1, 1), (99, 7)):
            status, body = self._transfer(efv=efv, etv=etv)
            self.assertEqual(status, 200, (efv, etv))
            self.assertEqual(body, committed)
        self.assertEqual(len(self._transfer_events()), 1)

    def test_replay_different_params_409_transfer_conflict(self):
        self.assertEqual(self._transfer()[0], 201)
        for overrides in (
            {"amount": 31},
            {"to_asset_id": "usd", "etv": 0},
            {"from_asset_id": "eth", "to_asset_id": "btc"},
        ):
            kwargs = {"transfer_id": "t1"}
            kwargs.update(overrides)
            status, body = self._transfer(**kwargs)
            self.assertEqual(status, 409, overrides)
            self.assertEqual(body, {"error": "transfer conflict"})
        self.assertEqual(len(self._transfer_events()), 1)

    def test_transfer_id_namespace_independent_of_operations(self):
        # transfer_id 与既有 operation_id 同名不冲突（不同命名空间）
        status, body = self._transfer(transfer_id="op1")
        self.assertEqual(status, 201)
        self.assertEqual(body["transfer_id"], "op1")

    # ---- 请求校验 400 --------------------------------------------------------

    def test_same_from_and_to_asset_400(self):
        status, _ = self._transfer(frm="btc", to="btc", etv=1)
        self.assertEqual(status, 400)
        self.assertEqual(self._transfer_events(), [])

    def test_invalid_amount_400(self):
        for amount in (0, -1, True, False, 1.5, "30", None, [30], {"x": 1}):
            status, _ = self._transfer(amount=amount)
            self.assertEqual(status, 400, amount)
        self.assertEqual(self._transfer_events(), [])

    def test_invalid_expected_versions_400(self):
        for value in (-1, True, False, 1.5, "1", None, [1]):
            status, _ = self._transfer(efv=value)
            self.assertEqual(status, 400, value)
            status, _ = self._transfer(etv=value)
            self.assertEqual(status, 400, value)
        self.assertEqual(self._transfer_events(), [])

    def test_invalid_ids_400(self):
        for bad in ("", "has space", "bad$id", "x" * 129, 1, True, None):
            status, _ = self._transfer(transfer_id=bad)
            self.assertEqual(status, 400, bad)
            status, _ = self._transfer(frm=bad)
            self.assertEqual(status, 400, bad)
            status, _ = self._transfer(to=bad)
            self.assertEqual(status, 400, bad)
        self.assertEqual(self._transfer_events(), [])

    def test_missing_and_extra_body_keys_400(self):
        full = {
            "transfer_id": "t1",
            "from_asset_id": "btc",
            "to_asset_id": "eth",
            "amount": 30,
            "expected_from_version": 1,
            "expected_to_version": 1,
        }
        for missing in full:
            body = {k: v for k, v in full.items() if k != missing}
            status, _ = self.srv.request(
                "POST", "/v1/wallets/w1/asset-transfers", body
            )
            self.assertEqual(status, 400, missing)
        status, _ = self.srv.request(
            "POST", "/v1/wallets/w1/asset-transfers",
            dict(full, extra=1),
        )
        self.assertEqual(status, 400)
        self.assertEqual(self._transfer_events(), [])

    def test_non_object_and_malformed_body_400(self):
        for raw in (b"[1]", b'"x"', b"1", b"null", b"{not-json"):
            status, _ = self._transfer_raw(raw)
            self.assertEqual(status, 400, raw)

    def test_unknown_wallet_404(self):
        status, _ = self._transfer(wallet="ghost")
        self.assertEqual(status, 404)

    # ---- 版本冲突 ------------------------------------------------------------

    def test_version_conflict_409_zero_side_effects(self):
        # 来源版本不符
        status, body = self._transfer(efv=0)
        self.assertEqual(status, 409)
        self.assertEqual(body, {"error": "asset version conflict"})
        # 目标版本不符
        status, body = self._transfer(etv=0)
        self.assertEqual(status, 409)
        self.assertEqual(body, {"error": "asset version conflict"})
        # 零副作用：余额/version 不变、无事件、无意图
        _, btc = self._asset("btc")
        self.assertEqual((btc["balance"], btc["version"]), (100, 1))
        _, eth = self._asset("eth")
        self.assertEqual((eth["balance"], eth["version"]), (50, 1))
        self.assertEqual(self._transfer_events(), [])
        # 用正确版本重试成功
        status, committed = self._transfer()
        self.assertEqual(status, 201)
        self.assertEqual((committed["from_version"],
                          committed["to_version"]), (2, 2))

    def test_version_conflict_when_source_missing(self):
        # 来源不存在按 version 0：声明非 0 即版本冲突
        status, body = self._transfer(frm="usd", to="eth", efv=1)
        self.assertEqual(status, 409)
        self.assertEqual(body, {"error": "asset version conflict"})

    # ---- 余额不足 ------------------------------------------------------------

    def test_insufficient_balance_409(self):
        status, body = self._transfer(amount=101)
        self.assertEqual(status, 409)
        self.assertEqual(body, {"error": "insufficient balance"})
        _, btc = self._asset("btc")
        self.assertEqual((btc["balance"], btc["version"]), (100, 1))
        self.assertEqual(self._transfer_events(), [])

    def test_missing_source_is_insufficient_balance_409(self):
        status, body = self._transfer(frm="usd", to="eth", efv=0)
        self.assertEqual(status, 409)
        self.assertEqual(body, {"error": "insufficient balance"})

    # ---- 冻结闸门 ------------------------------------------------------------

    def test_frozen_wallet_409(self):
        status, _ = self.srv.request(
            "POST", "/v1/wallets/w1/freeze", {"reason": "incident"}
        )
        self.assertEqual(status, 201)
        status, body = self._transfer()
        self.assertEqual(status, 409)
        self.assertEqual(body, {"error": "wallet or asset frozen"})
        self.assertEqual(self._transfer_events(), [])

    def test_frozen_source_or_target_asset_409(self):
        status, _ = self.srv.request(
            "POST", "/v1/wallets/w1/assets/eth/freeze",
            {"reason": "incident"},
        )
        self.assertEqual(status, 201)
        # eth 作为目标
        status, body = self._transfer()
        self.assertEqual(status, 409)
        self.assertEqual(body, {"error": "wallet or asset frozen"})
        # eth 作为来源
        status, body = self._transfer(frm="eth", to="btc", efv=1, etv=1)
        self.assertEqual(status, 409)
        self.assertEqual(body, {"error": "wallet or asset frozen"})
        self.assertEqual(self._transfer_events(), [])

    # ---- 交易策略 ------------------------------------------------------------

    def test_transaction_policy_violation_409(self):
        status, _ = self.srv.request(
            "PUT", "/v1/wallets/w1/transaction-policy",
            {"mode": "hot", "max_delta": 40,
             "allowed_assets": ["btc", "eth"]},
        )
        self.assertEqual(status, 200)
        # 目标不在白名单
        status, body = self._transfer(to="usd", amount=10, etv=0)
        self.assertEqual(status, 409)
        self.assertEqual(body, {"error": "transaction policy violation"})
        # 超过 max_delta
        status, body = self._transfer(amount=41)
        self.assertEqual(status, 409)
        self.assertEqual(body, {"error": "transaction policy violation"})
        self.assertEqual(self._transfer_events(), [])
        # 白名单内且不超上限：成功
        status, _ = self._transfer(amount=40)
        self.assertEqual(status, 201)

    # ---- 审计事件与筛选 ------------------------------------------------------

    def test_single_commit_event_details_are_the_view(self):
        status, committed = self._transfer()
        self.assertEqual(status, 201)
        events = self._transfer_events()
        self.assertEqual(len(events), 1)
        event = events[0]
        self.assertEqual(event["request_id"], "t1")
        self.assertEqual(event["details"], committed)
        self.assertEqual(event["seq"], 3)
        # 审计筛选按类型与 request_id 命中
        status, body = self.srv.request(
            "GET",
            "/v1/wallets/w1/audit-events"
            "?event_type=asset_transfer_committed",
        )
        self.assertEqual(status, 200)
        self.assertEqual([e["seq"] for e in body["events"]], [3])
        status, body = self.srv.request(
            "GET", "/v1/wallets/w1/audit-events?request_id=t1"
        )
        self.assertEqual(status, 200)
        self.assertEqual([e["type"] for e in body["events"]],
                         ["asset_transfer_committed"])

    # ---- at_seq 历史与资产清单 ------------------------------------------------

    def test_at_seq_history_reflects_both_sides(self):
        self.assertEqual(self._transfer()[0], 201)          # seq 3
        self.assertEqual(
            self._transfer("t2", to="usd", amount=10, efv=2, etv=0)[0], 201
        )                                                    # seq 4
        # 边界在转账事件之前：落账前状态
        _, btc = self._asset("btc", "at_seq=2")
        self.assertEqual((btc["balance"], btc["version"]), (100, 1))
        _, eth = self._asset("eth", "at_seq=2")
        self.assertEqual((eth["balance"], eth["version"]), (50, 1))
        # 边界落在转账事件上：两侧同时生效
        _, btc = self._asset("btc", "at_seq=3")
        self.assertEqual((btc["balance"], btc["version"]), (70, 2))
        _, eth = self._asset("eth", "at_seq=3")
        self.assertEqual((eth["balance"], eth["version"]), (80, 2))
        # 转账新建的资产：边界前 404，边界上可见
        status, _ = self._asset("usd", "at_seq=3")
        self.assertEqual(status, 404)
        _, usd = self._asset("usd", "at_seq=4")
        self.assertEqual((usd["balance"], usd["version"]), (10, 1))
        _, btc = self._asset("btc", "at_seq=4")
        self.assertEqual((btc["balance"], btc["version"]), (60, 3))

    def test_list_assets_reflects_transfer_at_seq(self):
        self.assertEqual(self._transfer()[0], 201)          # seq 3
        status, body = self._assets("at_seq=2")
        self.assertEqual(status, 200)
        self.assertEqual(
            {a["asset_id"]: (a["balance"], a["version"])
             for a in body["assets"]},
            {"btc": (100, 1), "eth": (50, 1)},
        )
        _, body = self._assets("at_seq=3")
        self.assertEqual(
            {a["asset_id"]: (a["balance"], a["version"])
             for a in body["assets"]},
            {"btc": (70, 2), "eth": (80, 2)},
        )
        # 缺省（当前尾）同样反映
        _, body = self._assets()
        self.assertEqual(
            {a["asset_id"]: (a["balance"], a["version"])
             for a in body["assets"]},
            {"btc": (70, 2), "eth": (80, 2)},
        )

    # ---- 并发 ----------------------------------------------------------------

    def test_concurrent_same_version_exactly_one_201(self):
        barrier = threading.Barrier(2)
        results = []

        def worker(tid):
            barrier.wait()
            results.append(self._transfer(transfer_id=tid))

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
        # 恰一条转账事件，两侧 version 只跳一次
        self.assertEqual(len(self._transfer_events()), 1)
        _, btc = self._asset("btc")
        self.assertEqual(btc["version"], 2)
        _, eth = self._asset("eth")
        self.assertEqual(eth["version"], 2)

    # ---- 重启与灾备 ------------------------------------------------------------

    def test_restart_keeps_results_and_replay(self):
        status, committed = self._transfer()
        self.assertEqual(status, 201)
        self.srv.stop()
        self._ctx.__exit__(None, None, None)
        self._ctx = http_server(self.tmpdir)
        self.srv = self._ctx.__enter__()
        _, btc = self._asset("btc")
        self.assertEqual((btc["balance"], btc["version"]), (70, 2))
        _, eth = self._asset("eth")
        self.assertEqual((eth["balance"], eth["version"]), (80, 2))
        status, replay = self._transfer()
        self.assertEqual(status, 200)
        self.assertEqual(replay, committed)
        self.assertEqual(len(self._transfer_events()), 1)

    def test_backup_restore_reflects_both_sides(self):
        status, committed = self._transfer()
        self.assertEqual(status, 201)
        out_dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, out_dir, ignore_errors=True)
        snapshot = os.path.join(out_dir, "snap.tar")
        body = drbackup.backup(self.tmpdir, "w1", "S1", snapshot)
        self.assertEqual(body["status"], 201)
        dst = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, dst, ignore_errors=True)
        status, _ = drbackup.restore(dst, "w1", snapshot)
        self.assertEqual(status, 201)
        svc = WalletService(WalletStore(dst))
        self.assertEqual(
            svc.get_asset("w1", "btc"),
            {"asset_id": "btc", "balance": 70, "version": 2},
        )
        self.assertEqual(
            svc.get_asset("w1", "eth"),
            {"asset_id": "eth", "balance": 80, "version": 2},
        )
        events = [
            e for e in svc.get_audit_events("w1")["events"]
            if e["type"] == "asset_transfer_committed"
        ]
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["details"], committed)
        # 恢复后的现场上重放仍是 200 同体
        code, replay = svc.create_asset_transfer(
            "w1", "t1", "btc", "eth", 30, 1, 1
        )
        self.assertEqual(code, 200)
        self.assertEqual(replay, committed)

    # ---- 输出不含私钥材料 ------------------------------------------------------

    def test_outputs_contain_no_private_key_material(self):
        self.assertEqual(self._transfer()[0], 201)
        privates = [
            self.srv.harness.store.get_share("w1", sid)["private_key"]
            for sid in ("share-1", "share-2")
        ]
        _, transfer_events = self.srv.request(
            "GET",
            "/v1/wallets/w1/audit-events"
            "?event_type=asset_transfer_committed",
        )
        _, asset = self._asset("btc")
        blobs = [
            json.dumps(transfer_events),
            json.dumps(asset),
            json.dumps(self._transfer()[1]),
        ]
        for path in (
            os.path.join(self.tmpdir, "assets", "w1.json"),
            os.path.join(self.tmpdir, "audit", "w1.json"),
        ):
            with open(path, encoding="utf-8") as f:
                blobs.append(f.read())
        for blob in blobs:
            for private in privates:
                self.assertNotIn(private, blob)
            self.assertNotIn("private_key", blob)


class TransferRecoveryTest(unittest.TestCase):
    """转账事务的崩溃一致性与恢复（服务层）。"""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.h = make_harness(self.tmp)
        self.svc = self.h.service
        self.store = self.h.store
        self.svc.create_wallet("w1", 2)
        self.svc.create_asset_operation("w1", "op1", "btc", 100)
        self.svc.commit_asset_operation("w1", "op1")      # v1 / seq1
        self.svc.create_asset_operation("w1", "op2", "eth", 50)
        self.svc.commit_asset_operation("w1", "op2")      # v1 / seq2

    def _transfer(self, tid="t1", amount=30):
        return self.svc.create_asset_transfer(
            "w1", tid, "btc", "eth", amount, 1, 1
        )

    def _plant_crash_scene(self, transfer_id, phase):
        """摆放转账事务在 phase 阶段被强杀的现场。

        phase 1：仅意图；2：意图 + 账本已落账；3：意图 + 账本 + 事件已落盘。
        """
        from_asset = self.store.get_asset("w1", "btc")
        to_asset = self.store.get_asset("w1", "eth")
        record = {
            "transfer_id": transfer_id,
            "from_asset_id": "btc",
            "to_asset_id": "eth",
            "amount": 30,
            "state": "committed",
            "from_balance": from_asset["balance"] - 30,
            "from_version": from_asset["version"] + 1,
            "to_balance": to_asset["balance"] + 30,
            "to_version": to_asset["version"] + 1,
        }
        intent = {
            "kind": "transfer",
            "transfer_id": transfer_id,
            "from_asset_id": "btc",
            "to_asset_id": "eth",
            "amount": 30,
            "old_from_asset": from_asset,
            "old_to_asset": to_asset,
            "record": record,
        }
        self.store.write_asset_commit_intent("w1", transfer_id, intent)
        if phase >= 2:
            self.store.commit_asset_transfer(
                "w1", transfer_id, record,
                "btc", {"balance": record["from_balance"],
                        "version": record["from_version"]},
                "eth", {"balance": record["to_balance"],
                        "version": record["to_version"]},
            )
        if phase >= 3:
            AuditStore(self.tmp).append_event("w1", {
                "type": "asset_transfer_committed",
                "at": "2026-10-05T00:00:00Z",
                "request_id": transfer_id,
                "actor_id": None,
                "reason": None,
                "details": record,
            })
        return record

    def test_event_append_failure_rolls_back_both_sides(self):
        real_append = self.svc._audit.append_event

        def boom(wallet_id, event):
            if event.get("type") == "asset_transfer_committed":
                raise OSError("audit disk full")
            return real_append(wallet_id, event)

        self.svc._audit.append_event = boom
        try:
            with self.assertRaises(OSError):
                self._transfer()
        finally:
            self.svc._audit.append_event = real_append
        # 两侧都回滚：无转账记录、余额/version 不变、无意图、无事件
        self.assertIsNone(self.store.get_asset_transfer("w1", "t1"))
        self.assertEqual(self.store.get_asset("w1", "btc"),
                         {"balance": 100, "version": 1})
        self.assertEqual(self.store.get_asset("w1", "eth"),
                         {"balance": 50, "version": 1})
        self.assertEqual(self.store.list_asset_intents("w1"), [])
        events = self.svc.get_audit_events("w1")["events"]
        self.assertEqual([e["seq"] for e in events], [1, 2])
        # 重试仍为首次 201：version 与 seq 接续，无缺口
        code, body = self._transfer()
        self.assertEqual(code, 201)
        self.assertEqual((body["from_version"], body["to_version"]), (2, 2))
        events = self.svc.get_audit_events("w1")["events"]
        self.assertEqual([e["seq"] for e in events], [1, 2, 3])

    def test_ledger_write_failure_rolls_back(self):
        original = self.store.commit_asset_transfer

        def boom(*a, **k):
            raise OSError("assets disk full")

        self.store.commit_asset_transfer = boom
        try:
            with self.assertRaises(OSError):
                self._transfer()
        finally:
            self.store.commit_asset_transfer = original
        self.assertIsNone(self.store.get_asset_transfer("w1", "t1"))
        self.assertEqual(self.store.get_asset("w1", "btc"),
                         {"balance": 100, "version": 1})
        self.assertEqual(self.store.list_asset_intents("w1"), [])
        code, _ = self._transfer()
        self.assertEqual(code, 201)

    def test_phase1_only_intent_rolls_back(self):
        self._plant_crash_scene("t1", 1)
        store, svc = WalletStore(self.tmp), WalletService(
            WalletStore(self.tmp)
        )
        self.assertEqual(store.list_asset_intents("w1"), [])
        self.assertIsNone(store.get_asset_transfer("w1", "t1"))
        self.assertEqual(store.get_asset("w1", "btc"),
                         {"balance": 100, "version": 1})
        self.assertEqual(store.get_asset("w1", "eth"),
                         {"balance": 50, "version": 1})
        events = svc.get_audit_events("w1")["events"]
        self.assertEqual([e["seq"] for e in events], [1, 2])
        # 恢复后可重新转账（首提 201）
        code, _ = svc.create_asset_transfer(
            "w1", "t1", "btc", "eth", 30, 1, 1
        )
        self.assertEqual(code, 201)

    def test_phase2_ledger_without_event_rolls_back(self):
        self._plant_crash_scene("t1", 2)
        store, svc = WalletStore(self.tmp), WalletService(
            WalletStore(self.tmp)
        )
        self.assertEqual(store.list_asset_intents("w1"), [])
        self.assertIsNone(store.get_asset_transfer("w1", "t1"))
        self.assertEqual(store.get_asset("w1", "btc"),
                         {"balance": 100, "version": 1})
        self.assertEqual(store.get_asset("w1", "eth"),
                         {"balance": 50, "version": 1})
        events = svc.get_audit_events("w1")["events"]
        self.assertEqual([e["seq"] for e in events], [1, 2])

    def test_phase3_event_persisted_rolls_forward_both_sides(self):
        record = self._plant_crash_scene("t1", 3)
        store, svc = WalletStore(self.tmp), WalletService(
            WalletStore(self.tmp)
        )
        self.assertEqual(store.list_asset_intents("w1"), [])
        # 两侧一并前滚，绝不只恢复一边
        self.assertEqual(store.get_asset("w1", "btc"),
                         {"balance": 70, "version": 2})
        self.assertEqual(store.get_asset("w1", "eth"),
                         {"balance": 80, "version": 2})
        self.assertEqual(store.get_asset_transfer("w1", "t1"), record)
        events = svc.get_audit_events("w1")["events"]
        self.assertEqual([e["seq"] for e in events], [1, 2, 3])
        # 重放 200 同体，不重复记事件
        code, body = svc.create_asset_transfer(
            "w1", "t1", "btc", "eth", 30, 1, 1
        )
        self.assertEqual(code, 200)
        self.assertEqual(body, record)
        self.assertEqual(len(svc.get_audit_events("w1")["events"]), 3)

    def test_malformed_intent_fails_closed(self):
        self.store.write_asset_commit_intent(
            "w1", "t1", {"kind": "transfer", "transfer_id": "t1"}
        )
        with self.assertRaises(Exception) as ctx:
            WalletService(WalletStore(self.tmp))
        self.assertEqual(type(ctx.exception).__name__, "RecoveryError")
        # 意图现场保留，未被静默清理
        self.assertTrue(
            os.path.exists(
                os.path.join(self.tmp, "asset-intents", "w1", "t1.json")
            )
        )

    def test_ledger_event_mismatch_fails_closed(self):
        code, _ = self._transfer()
        self.assertEqual(code, 201)
        # 篡改账本中的转账记录（事件不变）：账本与事件无法对账
        path = os.path.join(self.tmp, "assets", "w1.json")
        with open(path, encoding="utf-8") as f:
            ledger = json.load(f)
        ledger["transfers"]["t1"]["from_balance"] = 71
        with open(path, "w", encoding="utf-8") as f:
            json.dump(ledger, f)
        with self.assertRaises(Exception):
            WalletService(WalletStore(self.tmp))

    def test_transfer_event_without_ledger_record_fails_closed(self):
        code, record = self._transfer()
        self.assertEqual(code, 201)
        # 删除账本中的转账记录（事件仍在）：有事件无记录，fail-closed
        path = os.path.join(self.tmp, "assets", "w1.json")
        with open(path, encoding="utf-8") as f:
            ledger = json.load(f)
        del ledger["transfers"]["t1"]
        # 保持账本自身语义一致（两侧资产回滚到转账前），只制造事件矛盾
        ledger["assets"]["btc"] = {"balance": 100, "version": 1}
        ledger["assets"]["eth"] = {"balance": 50, "version": 1}
        with open(path, "w", encoding="utf-8") as f:
            json.dump(ledger, f)
        with self.assertRaises(Exception):
            WalletService(WalletStore(self.tmp))


if __name__ == "__main__":
    unittest.main()
