"""资产账本测试：操作单创建/提交、幂等与冲突、余额版本、审计事件、
跨进程并发、重启持久化，以及响应/磁盘无私钥。"""

from __future__ import annotations

import multiprocessing
import os
import shutil
import tempfile
import unittest

from threshold_wallet.service import ServiceError, WalletService
from threshold_wallet.store import WalletStore

from tests.helpers import http_server


def _make_service(data_dir: str) -> WalletService:
    return WalletService(WalletStore(data_dir))


# ---- 子进程 worker（模块级，可 pickle） ------------------------------------


def _child_commit(data_dir, operation_id, result_queue):
    service = _make_service(data_dir)
    try:
        status, body = service.commit_asset_operation("w1", operation_id)
        result_queue.put(
            (status, body["balance"], body["version"], body["state"])
        )
    except ServiceError as exc:
        result_queue.put((exc.status, None, None, None))


class AssetLedgerHttpTest(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmpdir, ignore_errors=True)
        self._ctx = http_server(self.tmpdir)
        self.srv = self._ctx.__enter__()
        self.addCleanup(self._ctx.__exit__, None, None, None)

    def request(self, method, path, body=None):
        return self.srv.request(method, path, body)

    def create_wallet(self, wallet_id="w1"):
        status, _ = self.request(
            "POST", "/v1/wallets", {"wallet_id": wallet_id, "shares": 2}
        )
        self.assertEqual(status, 201)

    def create_op(self, operation_id, asset_id, delta, wallet_id="w1"):
        return self.request(
            "POST",
            f"/v1/wallets/{wallet_id}/asset-operations",
            {
                "operation_id": operation_id,
                "asset_id": asset_id,
                "delta": delta,
            },
        )

    def commit(self, operation_id, wallet_id="w1"):
        return self.request(
            "POST",
            f"/v1/wallets/{wallet_id}/asset-operations/"
            f"{operation_id}/commit",
        )

    def get_asset(self, asset_id, wallet_id="w1"):
        return self.request(
            "GET", f"/v1/wallets/{wallet_id}/assets/{asset_id}"
        )

    # ---- 创建操作单 -----------------------------------------------------

    def test_create_201_pending_contract(self):
        self.create_wallet()
        status, body = self.create_op("op-1", "USD", 100)
        self.assertEqual(status, 201)
        self.assertEqual(
            set(body),
            {"operation_id", "asset_id", "delta", "state", "balance",
             "version"},
        )
        self.assertEqual(body["operation_id"], "op-1")
        self.assertEqual(body["asset_id"], "USD")
        self.assertEqual(body["delta"], 100)
        self.assertEqual(body["state"], "pending")
        # pending 尚无入账结果
        self.assertIsNone(body["balance"])
        self.assertIsNone(body["version"])

    def test_create_accepts_negative_and_large_delta(self):
        self.create_wallet()
        status, body = self.create_op("op-neg", "USD", -250)
        self.assertEqual(status, 201)
        self.assertEqual(body["delta"], -250)
        big = 10 ** 30
        status, body = self.create_op("op-big", "USD", big)
        self.assertEqual(status, 201)
        self.assertEqual(body["delta"], big)

    def test_create_validation_errors_400(self):
        self.create_wallet()
        bad_ids = ["", " ", "a b", "usd/coin", "x" * 129, None, 7, ["a"]]
        for bad in bad_ids:
            status, _ = self.create_op(bad, "USD", 1)
            self.assertEqual(status, 400, f"operation_id={bad!r}")
            status, _ = self.create_op("op-x", bad, 1)
            self.assertEqual(status, 400, f"asset_id={bad!r}")
        # delta：非布尔、非零真整数
        for bad_delta in (0, True, False, 1.0, 1.5, "5", None, [5], {}):
            status, _ = self.create_op(f"op-{type(bad_delta).__name__}",
                                       "USD", bad_delta)
            self.assertEqual(status, 400, f"delta={bad_delta!r}")

    def test_create_missing_body_fields_400(self):
        self.create_wallet()
        for body in (
            {"asset_id": "USD", "delta": 1},
            {"operation_id": "op-1", "delta": 1},
            {"operation_id": "op-1", "asset_id": "USD"},
            {},
        ):
            status, _ = self.request(
                "POST", "/v1/wallets/w1/asset-operations", body
            )
            self.assertEqual(status, 400, body)

    def test_create_wallet_404(self):
        status, _ = self.create_op("op-1", "USD", 1, wallet_id="nope")
        self.assertEqual(status, 404)

    def test_create_same_params_replay_200_same_body(self):
        self.create_wallet()
        status, first = self.create_op("op-1", "USD", 100)
        self.assertEqual(status, 201)
        status, second = self.create_op("op-1", "USD", 100)
        self.assertEqual(status, 200)
        self.assertEqual(second, first)

    def test_create_different_params_409(self):
        self.create_wallet()
        self.create_op("op-1", "USD", 100)
        # 不同 delta
        status, _ = self.create_op("op-1", "USD", 50)
        self.assertEqual(status, 409)
        # 不同 asset_id
        status, _ = self.create_op("op-1", "EUR", 100)
        self.assertEqual(status, 409)
        # 冲突不覆盖原单：重放仍是原参数
        status, body = self.create_op("op-1", "USD", 100)
        self.assertEqual(status, 200)
        self.assertEqual(body["asset_id"], "USD")
        self.assertEqual(body["delta"], 100)

    def test_operation_id_unique_per_wallet_but_not_across_wallets(self):
        self.create_wallet("w1")
        self.create_wallet("w2")
        status, _ = self.create_op("op-1", "USD", 1, wallet_id="w1")
        self.assertEqual(status, 201)
        # 不同钱包可复用同名 operation_id
        status, _ = self.create_op("op-1", "USD", 1, wallet_id="w2")
        self.assertEqual(status, 201)

    # ---- 提交操作单 -----------------------------------------------------

    def test_commit_201_applies_balance_and_version(self):
        self.create_wallet()
        self.create_op("op-1", "USD", 100)
        status, body = self.commit("op-1")
        self.assertEqual(status, 201)
        self.assertEqual(body["state"], "committed")
        self.assertEqual(body["balance"], 100)
        self.assertEqual(body["version"], 1)

    def test_commit_unknown_operation_404(self):
        self.create_wallet()
        status, _ = self.commit("nope")
        self.assertEqual(status, 404)

    def test_commit_wallet_404(self):
        status, _ = self.request(
            "POST", "/v1/wallets/nope/asset-operations/op-1/commit"
        )
        self.assertEqual(status, 404)

    def test_commit_insufficient_funds_409_unchanged_and_retryable(self):
        self.create_wallet()
        self.create_op("op-over", "USD", -50)
        status, _ = self.commit("op-over")
        self.assertEqual(status, 409)
        # 状态不变：仍是 pending，资产仍不存在
        status, _ = self.get_asset("USD")
        self.assertEqual(status, 404)
        # 入账后可重试成功
        self.create_op("op-fund", "USD", 100)
        status, funded = self.commit("op-fund")
        self.assertEqual(status, 201)
        self.assertEqual((funded["balance"], funded["version"]), (100, 1))
        status, debited = self.commit("op-over")
        self.assertEqual(status, 201)
        self.assertEqual((debited["balance"], debited["version"]), (50, 2))

    def test_commit_exactly_zero_balance_ok(self):
        self.create_wallet()
        self.create_op("op-in", "USD", 30)
        self.commit("op-in")
        self.create_op("op-out", "USD", -30)
        status, body = self.commit("op-out")
        self.assertEqual(status, 201)
        self.assertEqual(body["balance"], 0)
        self.assertEqual(body["version"], 2)

    def test_commit_replay_200_same_body_no_double_apply(self):
        self.create_wallet()
        self.create_op("op-1", "USD", 10)
        status, first = self.commit("op-1")
        self.assertEqual(status, 201)
        status, second = self.commit("op-1")
        self.assertEqual(status, 200)
        self.assertEqual(second, first)
        # 余额/版本只入账一次
        status, asset = self.get_asset("USD")
        self.assertEqual(asset, {"balance": 10, "version": 1})

    def test_versions_monotonic_no_regression_or_repeat(self):
        self.create_wallet()
        expected_balance = 0
        expected_version = 0
        for i, delta in enumerate((5, -2, 7), start=1):
            self.create_op(f"op-{i}", "USD", delta)
            status, body = self.commit(f"op-{i}")
            self.assertEqual(status, 201)
            expected_balance += delta
            expected_version += 1
            self.assertEqual(body["balance"], expected_balance)
            self.assertEqual(body["version"], expected_version)
        _, asset = self.get_asset("USD")
        self.assertEqual(asset, {"balance": 10, "version": 3})

    def test_distinct_assets_have_independent_balances(self):
        self.create_wallet()
        self.create_op("a1", "USD", 100)
        self.commit("a1")
        self.create_op("b1", "EUR", 7)
        self.commit("b1")
        _, usd = self.get_asset("USD")
        _, eur = self.get_asset("EUR")
        self.assertEqual(usd, {"balance": 100, "version": 1})
        self.assertEqual(eur, {"balance": 7, "version": 1})

    # ---- GET 资产 -------------------------------------------------------

    def test_get_asset_404_before_first_commit(self):
        self.create_wallet()
        # 仅有 pending 单不产生资产记录
        self.create_op("op-1", "USD", 100)
        status, _ = self.get_asset("USD")
        self.assertEqual(status, 404)

    def test_get_asset_wallet_404_and_bad_id_400(self):
        status, _ = self.request("GET", "/v1/wallets/nope/assets/USD")
        self.assertEqual(status, 404)
        self.create_wallet()
        status, _ = self.request("GET", "/v1/wallets/w1/assets/bad%20id")
        self.assertEqual(status, 400)

    # ---- 审计事件 -------------------------------------------------------

    def _events(self):
        status, body = self.request(
            "GET", "/v1/wallets/w1/audit-events"
        )
        self.assertEqual(status, 200)
        return body["events"]

    def test_commit_records_one_event_with_contract_fields(self):
        self.create_wallet()
        self.create_op("op-1", "USD", 100)
        self.commit("op-1")
        events = self._events()
        self.assertEqual(len(events), 1)
        event = events[0]
        self.assertEqual(event["seq"], 1)
        self.assertEqual(event["type"], "asset_operation_committed")
        self.assertEqual(event["request_id"], "op-1")
        self.assertIsNone(event["actor_id"])
        self.assertIsNone(event["reason"])
        # details 即本次提交返回的 R
        self.assertEqual(
            event["details"],
            {
                "operation_id": "op-1",
                "asset_id": "USD",
                "delta": 100,
                "state": "committed",
                "balance": 100,
                "version": 1,
            },
        )

    def test_replays_and_failures_emit_no_events(self):
        self.create_wallet()
        self.create_op("op-1", "USD", 100)
        self.create_op("op-1", "USD", 100)   # 创建重放
        self.commit("op-1")                  # 首次提交
        self.commit("op-1")                  # 提交重放
        self.create_op("op-over", "USD", -200)
        self.commit("op-over")               # 余额不足 409
        events = self._events()
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["request_id"], "op-1")

    def test_event_seq_contiguous_with_other_events(self):
        self.create_wallet()
        self.request(
            "PUT",
            "/v1/wallets/w1/approval-policy",
            {"required_approvals": 1, "timeout_seconds": 3600},
        )
        self.create_op("op-1", "USD", 10)
        self.commit("op-1")
        self.create_op("op-2", "USD", 5)
        self.commit("op-2")
        events = self._events()
        self.assertEqual([e["seq"] for e in events], [1, 2, 3])
        self.assertEqual(
            [e["type"] for e in events],
            ["policy_updated", "asset_operation_committed",
             "asset_operation_committed"],
        )

    # ---- 私钥边界 -------------------------------------------------------

    def test_asset_responses_and_files_contain_no_private_key(self):
        self.create_wallet()
        self.create_op("op-1", "USD", 100)
        _, pending = self.create_op("op-1", "USD", 100)
        _, committed = self.commit("op-1")
        _, asset = self.get_asset("USD")
        for body in (pending, committed, asset):
            text = str(body)
            self.assertNotIn("private", text)
            self.assertNotIn("share", text)
        # 资产相关磁盘文件不含 private 字样
        for sub in ("asset-operations", "assets"):
            base = os.path.join(self.tmpdir, sub)
            for root, _, files in os.walk(base):
                for name in files:
                    with open(os.path.join(root, name), encoding="utf-8") as f:
                        self.assertNotIn("private", f.read())


class AssetLedgerConcurrencyTest(unittest.TestCase):
    """同一 data-dir 上多进程并发提交。"""

    def setUp(self):
        self.data_dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.data_dir, ignore_errors=True)
        self.ctx = multiprocessing.get_context("fork")
        service = _make_service(self.data_dir)
        service.create_wallet("w1", 2)

    def _run(self, operation_ids):
        queue = self.ctx.Queue()
        procs = [
            self.ctx.Process(
                target=_child_commit, args=(self.data_dir, opid, queue)
            )
            for opid in operation_ids
        ]
        for proc in procs:
            proc.start()
        for proc in procs:
            proc.join(20)
            self.assertFalse(proc.is_alive(), "child timed out")
        return sorted(queue.get() for _ in range(len(procs)))

    def test_concurrent_commit_same_operation_one_201_rest_200(self):
        service = _make_service(self.data_dir)
        service.create_asset_operation("w1", "op-1", "COIN", 42)
        rows = self._run(["op-1"] * 8)
        statuses = [r[0] for r in rows]
        self.assertEqual(statuses.count(201), 1)
        self.assertEqual(statuses.count(200), 7)
        # 所有响应同体，余额/版本只入账一次
        self.assertTrue(all(r[1] == 42 and r[2] == 1 for r in rows))
        service = _make_service(self.data_dir)
        self.assertEqual(
            service.get_asset("w1", "COIN"),
            {"balance": 42, "version": 1},
        )
        events = service.get_audit_events("w1")["events"]
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["type"], "asset_operation_committed")

    def test_concurrent_commit_distinct_ops_contiguous_versions(self):
        service = _make_service(self.data_dir)
        for i in range(6):
            service.create_asset_operation("w1", f"op-{i}", "COIN", 1)
        rows = self._run([f"op-{i}" for i in range(6)])
        self.assertTrue(all(r[0] == 201 for r in rows))
        self.assertEqual(sorted(r[2] for r in rows), [1, 2, 3, 4, 5, 6])
        # 最终余额与版本确定，无重复版本/倒退
        service = _make_service(self.data_dir)
        self.assertEqual(
            service.get_asset("w1", "COIN"),
            {"balance": 6, "version": 6},
        )
        events = service.get_audit_events("w1")["events"]
        self.assertEqual([e["seq"] for e in events], [1, 2, 3, 4, 5, 6])


class AssetLedgerRestartTest(unittest.TestCase):
    """重启后 pending/committed 保持、幂等、版本不倒退。"""

    def setUp(self):
        self.data_dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.data_dir, ignore_errors=True)

    def test_pending_and_committed_survive_restart(self):
        service = _make_service(self.data_dir)
        service.create_wallet("w1", 2)
        service.create_asset_operation("w1", "p1", "COIN", 10)  # pending
        service.create_asset_operation("w1", "c1", "COIN", 5)
        service.commit_asset_operation("w1", "c1")              # committed

        service = _make_service(self.data_dir)
        # committed 重放不重复入账
        status, body = service.commit_asset_operation("w1", "c1")
        self.assertEqual(status, 200)
        self.assertEqual(body["balance"], 5)
        self.assertEqual(body["version"], 1)
        # pending 仍可提交，版本严格 +1、不倒退
        status, body = service.commit_asset_operation("w1", "p1")
        self.assertEqual(status, 201)
        self.assertEqual(body["balance"], 15)
        self.assertEqual(body["version"], 2)
        self.assertEqual(
            service.get_asset("w1", "COIN"),
            {"balance": 15, "version": 2},
        )
        # 重启恢复不产生事件；seq 仍连续
        events = service.get_audit_events("w1")["events"]
        self.assertEqual([e["seq"] for e in events], [1, 2])


if __name__ == "__main__":
    unittest.main()
