"""资产账本测试：asset-operations 的创建、提交、查询、审计与重启持久化。

覆盖：
- POST /v1/wallets/{id}/asset-operations 的参数校验（400）、钱包 404、
  首建 201（pending）、同参重放 200 同体、异参 409、ID 钱包内唯一；
- POST .../{operation_id}/commit 的 404、pending 首提交 201、committed
  重放 200、余额不足 409 不变可重试、version 单调递增；
- 并发提交恰一个 201、其余 200，余额只应用一次；
- 审计事件 asset_operation_committed 只在首提交记录，seq 连续；
- 重启后 pending/committed 状态、幂等与版本不回退；
- 账本文件与响应不含私钥材料。
"""

from __future__ import annotations

import json
import os
import shutil
import tempfile
import threading
import unittest

from threshold_wallet.service import WalletService
from threshold_wallet.store import WalletStore
from tests.helpers import http_server, make_harness


class AssetOperationCreateTest(unittest.TestCase):
    """POST /v1/wallets/{id}/asset-operations 的校验与幂等。"""

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

    def _create(self, body, wallet_id="w1"):
        return self.srv.request(
            "POST", f"/v1/wallets/{wallet_id}/asset-operations", body
        )

    def test_first_create_returns_201_pending(self):
        status, body = self._create(
            {"operation_id": "op1", "asset_id": "btc", "delta": 100}
        )
        self.assertEqual(status, 201)
        self.assertEqual(
            body,
            {
                "operation_id": "op1",
                "asset_id": "btc",
                "state": "pending",
                "delta": 100,
                "balance": 0,
                "version": 0,
            },
        )

    def test_replay_same_params_returns_200_same_body(self):
        _, first = self._create(
            {"operation_id": "op1", "asset_id": "btc", "delta": 100}
        )
        status, second = self._create(
            {"operation_id": "op1", "asset_id": "btc", "delta": 100}
        )
        self.assertEqual(status, 200)
        self.assertEqual(first, second)

    def test_same_id_different_asset_returns_409(self):
        self._create({"operation_id": "op1", "asset_id": "btc", "delta": 100})
        status, _ = self._create(
            {"operation_id": "op1", "asset_id": "eth", "delta": 100}
        )
        self.assertEqual(status, 409)

    def test_same_id_different_delta_returns_409(self):
        self._create({"operation_id": "op1", "asset_id": "btc", "delta": 100})
        status, _ = self._create(
            {"operation_id": "op1", "asset_id": "btc", "delta": 200}
        )
        self.assertEqual(status, 409)

    def test_operation_id_unique_per_wallet_only(self):
        self.srv.request(
            "POST", "/v1/wallets", {"wallet_id": "w2", "shares": 2}
        )
        status, _ = self._create(
            {"operation_id": "op1", "asset_id": "btc", "delta": 100}
        )
        self.assertEqual(status, 201)
        # 同一 operation_id 可在另一钱包独立使用
        status, _ = self._create(
            {"operation_id": "op1", "asset_id": "btc", "delta": 100},
            wallet_id="w2",
        )
        self.assertEqual(status, 201)

    def test_missing_wallet_returns_404(self):
        status, _ = self._create(
            {"operation_id": "op1", "asset_id": "btc", "delta": 100},
            wallet_id="nope",
        )
        self.assertEqual(status, 404)

    def test_invalid_ids_return_400(self):
        bad_ids = [
            "",
            "has space",
            "slash/inside",
            "dot.name",
            "x" * 129,
            "中文",
        ]
        for bad in bad_ids:
            with self.subTest(operation_id=bad):
                status, _ = self._create(
                    {"operation_id": bad, "asset_id": "btc", "delta": 1}
                )
                self.assertEqual(status, 400)
            with self.subTest(asset_id=bad):
                status, _ = self._create(
                    {"operation_id": "op1", "asset_id": bad, "delta": 1}
                )
                self.assertEqual(status, 400)
        for non_string in (None, 1, True, 1.5, [], {}):
            with self.subTest(operation_id=non_string):
                status, _ = self._create(
                    {
                        "operation_id": non_string,
                        "asset_id": "btc",
                        "delta": 1,
                    }
                )
                self.assertEqual(status, 400)

    def test_boundary_length_ids_accepted(self):
        status, _ = self._create(
            {"operation_id": "x" * 128, "asset_id": "y" * 128, "delta": 1}
        )
        self.assertEqual(status, 201)

    def test_invalid_delta_returns_400(self):
        for bad in (0, True, False, 1.5, "10", None, [1], {"v": 1}):
            with self.subTest(delta=bad):
                status, _ = self._create(
                    {"operation_id": "op1", "asset_id": "btc", "delta": bad}
                )
                self.assertEqual(status, 400)

    def test_negative_delta_accepted(self):
        status, body = self._create(
            {"operation_id": "op1", "asset_id": "btc", "delta": -50}
        )
        self.assertEqual(status, 201)
        self.assertEqual(body["delta"], -50)


class AssetOperationCommitTest(unittest.TestCase):
    """POST .../asset-operations/{id}/commit 与 GET assets/{asset_id}。"""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmpdir, ignore_errors=True)
        self._ctx = http_server(self.tmpdir)
        self.srv = self._ctx.__enter__()
        self.addCleanup(self._ctx.__exit__, None, None, None)
        self.srv.request(
            "POST", "/v1/wallets", {"wallet_id": "w1", "shares": 2}
        )

    def _create(self, operation_id, asset_id, delta):
        status, body = self.srv.request(
            "POST",
            "/v1/wallets/w1/asset-operations",
            {
                "operation_id": operation_id,
                "asset_id": asset_id,
                "delta": delta,
            },
        )
        self.assertEqual(status, 201)
        return body

    def _commit(self, operation_id, wallet_id="w1"):
        return self.srv.request(
            "POST",
            f"/v1/wallets/{wallet_id}/asset-operations/{operation_id}/commit",
        )

    def _asset(self, asset_id, wallet_id="w1"):
        return self.srv.request(
            "GET", f"/v1/wallets/{wallet_id}/assets/{asset_id}"
        )

    def test_commit_unknown_operation_returns_404(self):
        status, _ = self._commit("nope")
        self.assertEqual(status, 404)

    def test_commit_missing_wallet_returns_404(self):
        status, _ = self._commit("op1", wallet_id="nope")
        self.assertEqual(status, 404)

    def test_first_commit_returns_201_and_updates_ledger(self):
        self._create("op1", "btc", 100)
        status, body = self._commit("op1")
        self.assertEqual(status, 201)
        self.assertEqual(
            body,
            {
                "operation_id": "op1",
                "asset_id": "btc",
                "state": "committed",
                "delta": 100,
                "balance": 100,
                "version": 1,
            },
        )
        status, asset = self._asset("btc")
        self.assertEqual(status, 200)
        self.assertEqual(asset["balance"], 100)
        self.assertEqual(asset["version"], 1)

    def test_commit_replay_returns_200_same_body(self):
        self._create("op1", "btc", 100)
        _, first = self._commit("op1")
        status, second = self._commit("op1")
        self.assertEqual(status, 200)
        self.assertEqual(first, second)
        # 余额只应用一次
        _, asset = self._asset("btc")
        self.assertEqual(asset["balance"], 100)
        self.assertEqual(asset["version"], 1)

    def test_insufficient_balance_returns_409_and_is_retryable(self):
        self._create("op1", "btc", 100)
        self._commit("op1")
        self._create("op2", "btc", -150)
        status, _ = self._commit("op2")
        self.assertEqual(status, 409)
        # 状态不变：余额与版本未动，操作仍可重试
        _, asset = self._asset("btc")
        self.assertEqual((asset["balance"], asset["version"]), (100, 1))
        # 充值后重试成功
        self._create("op3", "btc", 60)
        self._commit("op3")
        status, body = self._commit("op2")
        self.assertEqual(status, 201)
        self.assertEqual(body["state"], "committed")
        self.assertEqual(body["balance"], 10)
        self.assertEqual(body["version"], 3)

    def test_version_increments_once_per_committed_operation(self):
        self._create("op1", "btc", 10)
        self._create("op2", "btc", 20)
        self._create("op3", "btc", -5)
        self._commit("op1")
        self._commit("op2")
        _, body = self._commit("op3")
        self.assertEqual((body["balance"], body["version"]), (25, 3))
        _, asset = self._asset("btc")
        self.assertEqual((asset["balance"], asset["version"]), (25, 3))

    def test_assets_are_independent(self):
        self._create("op1", "btc", 10)
        self._create("op2", "eth", 7)
        self._commit("op1")
        _, btc = self._asset("btc")
        self.assertEqual((btc["balance"], btc["version"]), (10, 1))
        status, _ = self._asset("eth")
        self.assertEqual(status, 404)
        self._commit("op2")
        _, eth = self._asset("eth")
        self.assertEqual((eth["balance"], eth["version"]), (7, 1))

    def test_get_asset_unknown_returns_404(self):
        status, _ = self._asset("nope")
        self.assertEqual(status, 404)

    def test_get_asset_missing_wallet_returns_404(self):
        status, _ = self._asset("btc", wallet_id="nope")
        self.assertEqual(status, 404)

    def test_get_asset_invalid_id_returns_400(self):
        status, _ = self._asset("bad$id")
        self.assertEqual(status, 400)

    def test_pending_operation_does_not_create_asset_entry(self):
        self._create("op1", "btc", 100)
        status, _ = self._asset("btc")
        self.assertEqual(status, 404)


class AssetOperationConcurrencyTest(unittest.TestCase):
    """并发提交：恰一个首次提交，其余幂等重放。"""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmpdir, ignore_errors=True)
        self._ctx = http_server(self.tmpdir)
        self.srv = self._ctx.__enter__()
        self.addCleanup(self._ctx.__exit__, None, None, None)
        self.srv.request(
            "POST", "/v1/wallets", {"wallet_id": "w1", "shares": 2}
        )
        self.srv.request(
            "POST",
            "/v1/wallets/w1/asset-operations",
            {"operation_id": "op1", "asset_id": "btc", "delta": 100},
        )

    def _run_concurrent(self, fn, count=8):
        barrier = threading.Barrier(count)
        results = []

        def worker():
            barrier.wait()
            results.append(fn())

        threads = [threading.Thread(target=worker) for _ in range(count)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        return results

    def test_concurrent_commits_only_one_first_commit(self):
        results = self._run_concurrent(
            lambda: self.srv.request(
                "POST", "/v1/wallets/w1/asset-operations/op1/commit"
            )
        )
        statuses = sorted(status for status, _ in results)
        self.assertEqual(statuses, [200] * 7 + [201])
        bodies = {json.dumps(body, sort_keys=True) for _, body in results}
        # 所有响应体一致：同一个 committed R
        self.assertEqual(len(bodies), 1)
        _, asset = self.srv.request("GET", "/v1/wallets/w1/assets/btc")
        self.assertEqual((asset["balance"], asset["version"]), (100, 1))
        # 审计只记一次 asset_operation_committed
        _, events = self.srv.request("GET", "/v1/wallets/w1/audit-events")
        committed = [
            e
            for e in events["events"]
            if e["type"] == "asset_operation_committed"
        ]
        self.assertEqual(len(committed), 1)

    def test_concurrent_creates_only_one_first_create(self):
        results = self._run_concurrent(
            lambda: self.srv.request(
                "POST",
                "/v1/wallets/w1/asset-operations",
                {"operation_id": "op2", "asset_id": "eth", "delta": 5},
            )
        )
        statuses = sorted(status for status, _ in results)
        self.assertEqual(statuses, [200] * 7 + [201])


class AssetOperationAuditTest(unittest.TestCase):
    """asset_operation_committed 事件：只记首提交，seq 连续。"""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmpdir, ignore_errors=True)
        self.harness = make_harness(self.tmpdir)
        self.service = self.harness.service
        self.service.create_wallet("w1", 2)

    def _events(self):
        return self.service.get_audit_events("w1")["events"]

    def test_first_commit_records_event_with_r_details(self):
        self.service.create_asset_operation("w1", "op1", "btc", 100)
        _, record = self.service.commit_asset_operation("w1", "op1")
        events = self._events()
        self.assertEqual(len(events), 1)
        event = events[0]
        self.assertEqual(event["seq"], 1)
        self.assertEqual(event["type"], "asset_operation_committed")
        self.assertEqual(event["request_id"], "op1")
        self.assertIsNone(event["actor_id"])
        self.assertIsNone(event["reason"])
        self.assertEqual(event["details"], record)

    def test_create_and_replay_and_failure_record_no_event(self):
        self.service.create_asset_operation("w1", "op1", "btc", 100)
        self.service.create_asset_operation("w1", "op1", "btc", 100)
        self.service.create_asset_operation("w1", "op2", "btc", -500)
        with self.assertRaises(Exception):
            self.service.commit_asset_operation("w1", "op2")
        self.assertEqual(self._events(), [])
        self.service.commit_asset_operation("w1", "op1")
        self.service.commit_asset_operation("w1", "op1")
        self.assertEqual(len(self._events()), 1)

    def test_seq_stays_continuous_with_other_events(self):
        self.service.put_policy("w1", 1, 60)
        self.service.create_asset_operation("w1", "op1", "btc", 5)
        self.service.commit_asset_operation("w1", "op1")
        self.service.create_asset_operation("w1", "op2", "btc", 5)
        self.service.commit_asset_operation("w1", "op2")
        events = self._events()
        self.assertEqual([e["seq"] for e in events], [1, 2, 3])
        self.assertEqual(
            [e["type"] for e in events],
            [
                "policy_updated",
                "asset_operation_committed",
                "asset_operation_committed",
            ],
        )


class AssetOperationPersistenceTest(unittest.TestCase):
    """重启后：pending/committed 状态、幂等重放与版本不回退。"""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmpdir, ignore_errors=True)

    def _restart(self):
        self.harness = make_harness(self.tmpdir)
        self.service = self.harness.service
        return self.service

    def test_restart_preserves_states_and_idempotency(self):
        service = self._restart()
        service.create_wallet("w1", 2)
        service.create_asset_operation("w1", "op1", "btc", 100)
        service.create_asset_operation("w1", "op2", "btc", -30)
        service.commit_asset_operation("w1", "op1")

        service = self._restart()
        # committed 重放仍 200，余额不重复应用
        status, body = service.commit_asset_operation("w1", "op1")
        self.assertEqual(status, 200)
        self.assertEqual(body["state"], "committed")
        self.assertEqual((body["balance"], body["version"]), (100, 1))
        # pending 仍可提交，version 接续递增（不回退、不重复）
        status, body = service.commit_asset_operation("w1", "op2")
        self.assertEqual(status, 201)
        self.assertEqual((body["balance"], body["version"]), (70, 2))
        asset = service.get_asset("w1", "btc")
        self.assertEqual((asset["balance"], asset["version"]), (70, 2))
        # 创建重放仍幂等
        status, replay = service.create_asset_operation(
            "w1", "op1", "btc", 100
        )
        self.assertEqual(status, 200)
        self.assertEqual(replay["state"], "committed")
        # 审计事件跨重启接续、不重号
        events = service.get_audit_events("w1")["events"]
        self.assertEqual([e["seq"] for e in events], [1, 2])
        self.assertEqual(
            [e["type"] for e in events],
            ["asset_operation_committed", "asset_operation_committed"],
        )

    def test_ledger_files_contain_no_private_material(self):
        service = self._restart()
        service.create_wallet("w1", 2)
        service.create_asset_operation("w1", "op1", "btc", 100)
        service.commit_asset_operation("w1", "op1")
        store = WalletStore(self.tmpdir)
        priv_hexes = [
            store.get_share("w1", sid)["private_key"]
            for sid in ("share-1", "share-2")
        ]
        path = os.path.join(self.tmpdir, "assets", "w1.json")
        with open(path, encoding="utf-8") as f:
            raw = f.read()
        self.assertNotIn("private", raw)
        for priv_hex in priv_hexes:
            self.assertNotIn(priv_hex, raw)
        # 账本文件是合法 JSON 且不含私钥字段
        ledger = json.loads(raw)
        self.assertIn("operations", ledger)
        self.assertIn("assets", ledger)


if __name__ == "__main__":
    unittest.main()
