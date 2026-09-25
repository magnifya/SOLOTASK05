"""跨链资产确认测试：链确认策略、确认数报告、达门槛提交与故障恢复。

覆盖：
- PUT/GET /v1/wallets/{id}/chain/{asset_id} 的键集/值校验（400）、
  钱包 404、未配置 404、同值更新也记 chain_policy 事件、策略仅由
  审计事件持久化（重启/灾备后不变）；
- POST /v1/wallets/{id}/chain/{oid}/report 的键集/值校验（400）、
  钱包/操作 404、策略未启用/链/tx/越界/终态冲突（409）、首报 201、
  同体 200、同块确认数不降、换块回退窗、达门槛按既有 commit 契约
  提交一次（报告事件紧邻唯一提交事件）；
- 策略启用时人工 commit 对 pending 409（committed 重放仍 200）；
- 并发同体报告恰一个 201、达门槛提交恰一次；重启后视图与 seq 连续；
- 事件损坏/矛盾 fail-closed（常驻 503、启动恢复阻止就绪）；
- 灾备 backup/restore 后策略、报告与提交现场不变、不新增审计事件。
"""

from __future__ import annotations

import json
import os
import shutil
import tempfile
import threading
import unittest

from threshold_wallet import drbackup
from threshold_wallet.audit import AuditStore
from threshold_wallet.service import WalletService
from threshold_wallet.store import RecoveryError, WalletStore
from tests.helpers import http_server, make_harness

TX = "ab" * 32
TX2 = "cd" * 32
HASH1 = "11" * 32
HASH2 = "22" * 32
HASH3 = "33" * 32

POLICY = {
    "chain_id": "bitcoin",
    "enabled": True,
    "required_confirmations": 3,
    "reorg_window": 2,
}


def _report(chain_id="bitcoin", tx_id=TX, height=100, block_hash=HASH1,
            confirmations=1):
    return {
        "chain_id": chain_id,
        "tx_id": tx_id,
        "block_height": height,
        "block_hash": block_hash,
        "confirmations": confirmations,
    }


class _HttpBase(unittest.TestCase):
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

    def _put_policy(self, body, wallet="w1", asset="btc"):
        return self.srv.request(
            "PUT", f"/v1/wallets/{wallet}/chain/{asset}", body
        )

    def _get_policy(self, wallet="w1", asset="btc"):
        return self.srv.request("GET", f"/v1/wallets/{wallet}/chain/{asset}")

    def _create_op(self, operation_id="op1", asset_id="btc", delta=100):
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

    def _report(self, body, wallet="w1", operation="op1"):
        return self.srv.request(
            "POST", f"/v1/wallets/{wallet}/chain/{operation}/report", body
        )

    def _events(self, wallet="w1"):
        status, body = self.srv.request(
            "GET", f"/v1/wallets/{wallet}/audit-events"
        )
        self.assertEqual(status, 200)
        return body["events"]


class ChainPolicyHttpTest(_HttpBase):
    """PUT/GET /v1/wallets/{id}/chain/{asset_id} 的校验与幂等。"""

    def test_put_then_get_returns_same_body(self):
        status, body = self._put_policy(POLICY)
        self.assertEqual(status, 200)
        self.assertEqual(body, POLICY)
        status, body = self._get_policy()
        self.assertEqual(status, 200)
        self.assertEqual(body, POLICY)

    def test_get_without_policy_returns_404(self):
        status, _ = self._get_policy()
        self.assertEqual(status, 404)

    def test_get_other_asset_returns_404(self):
        self._put_policy(POLICY)
        status, _ = self._get_policy(asset="eth")
        self.assertEqual(status, 404)

    def test_unknown_wallet_returns_404(self):
        status, _ = self._put_policy(POLICY, wallet="nope")
        self.assertEqual(status, 404)
        status, _ = self._get_policy(wallet="nope")
        self.assertEqual(status, 404)

    def test_invalid_asset_id_returns_400(self):
        status, _ = self._put_policy(POLICY, asset="bad$id")
        self.assertEqual(status, 400)
        status, _ = self._get_policy(asset="bad$id")
        self.assertEqual(status, 400)

    def test_key_set_errors_return_400(self):
        for body in (
            {},
            {"chain_id": "bitcoin"},
            {**POLICY, "extra": 1},
            {k: v for k, v in POLICY.items() if k != "enabled"},
        ):
            with self.subTest(body=body):
                status, _ = self._put_policy(body)
                self.assertEqual(status, 400)

    def test_value_errors_return_400(self):
        bad_bodies = []
        for bad_chain in ("", "has space", "slash/x", "x" * 129, 1, None,
                          True, ["bitcoin"]):
            bad_bodies.append({**POLICY, "chain_id": bad_chain})
        for bad_enabled in (0, 1, "true", None, []):
            bad_bodies.append({**POLICY, "enabled": bad_enabled})
        for bad_required in (0, -1, 1.5, "3", True, False, None, [3]):
            bad_bodies.append(
                {**POLICY, "required_confirmations": bad_required}
            )
        for bad_window in (-1, 1.5, "2", True, False, None, [2]):
            bad_bodies.append({**POLICY, "reorg_window": bad_window})
        for body in bad_bodies:
            with self.subTest(body=body):
                status, _ = self._put_policy(body)
                self.assertEqual(status, 400)
        # 边界合法值
        status, _ = self._put_policy(
            {**POLICY, "required_confirmations": 1, "reorg_window": 0}
        )
        self.assertEqual(status, 200)

    def test_same_value_put_records_event_each_time(self):
        self._put_policy(POLICY)
        self._put_policy(POLICY)
        events = [
            e for e in self._events() if e["type"] == "chain_policy"
        ]
        self.assertEqual(len(events), 2)
        self.assertEqual([e["seq"] for e in events], [1, 2])
        for event in events:
            self.assertEqual(event["request_id"], "btc")
            self.assertIsNone(event["actor_id"])
            self.assertIsNone(event["reason"])
            self.assertEqual(event["details"], POLICY)

    def test_policies_are_per_asset(self):
        self._put_policy(POLICY, asset="btc")
        other = {**POLICY, "chain_id": "ethereum", "enabled": False}
        self._put_policy(other, asset="eth")
        _, btc = self._get_policy(asset="btc")
        _, eth = self._get_policy(asset="eth")
        self.assertEqual(btc, POLICY)
        self.assertEqual(eth, other)


class ChainReportValidationTest(_HttpBase):
    """POST .../chain/{oid}/report 的 400/404/409 判定。"""

    def setUp(self):
        super().setUp()
        self._put_policy(POLICY)
        self._create_op()

    def test_key_set_errors_return_400(self):
        good = _report()
        for body in (
            {},
            {"chain_id": "bitcoin"},
            {**good, "extra": 1},
            {k: v for k, v in good.items() if k != "tx_id"},
        ):
            with self.subTest(body=body):
                status, _ = self._report(body)
                self.assertEqual(status, 400)

    def test_value_errors_return_400(self):
        bad_bodies = []
        for bad_chain in ("", "has space", 1, None, True):
            bad_bodies.append(_report(chain_id=bad_chain))
        for key in ("tx_id", "block_hash"):
            for bad in ("AB" * 32, "ab" * 31, "ab" * 33, "zz" * 32, 1,
                        None, True):
                bad_bodies.append(_report(**{key: bad}))
        for key in ("block_height", "confirmations"):
            for bad in (-1, 1.5, "1", True, False, None, [1]):
                body = _report()
                body[key] = bad
                bad_bodies.append(body)
        for body in bad_bodies:
            with self.subTest(body=body):
                status, _ = self._report(body)
                self.assertEqual(status, 400)

    def test_unknown_wallet_returns_404(self):
        status, _ = self._report(_report(), wallet="nope")
        self.assertEqual(status, 404)

    def test_unknown_operation_returns_404(self):
        status, _ = self._report(_report(), operation="nope")
        self.assertEqual(status, 404)

    def test_invalid_operation_id_returns_400(self):
        status, _ = self._report(_report(), operation="bad$id")
        self.assertEqual(status, 400)

    def test_missing_or_disabled_policy_returns_409(self):
        # 操作资产无策略
        self._create_op("op2", "eth", 10)
        status, _ = self._report(_report(), operation="op2")
        self.assertEqual(status, 409)
        # 策略未启用
        self._put_policy({**POLICY, "enabled": False})
        status, _ = self._report(_report())
        self.assertEqual(status, 409)

    def test_chain_mismatch_returns_409(self):
        status, _ = self._report(_report(chain_id="ethereum"))
        self.assertEqual(status, 409)


class ChainReportStateMachineTest(_HttpBase):
    """报告状态机：首报/重放/同块单调/换块回退窗/tx 与链绑定。"""

    def setUp(self):
        super().setUp()
        self._put_policy(POLICY)
        self._create_op()

    def test_first_report_201_and_replay_200(self):
        status, body = self._report(_report())
        self.assertEqual(status, 201)
        self.assertEqual(body, _report())
        status, body2 = self._report(_report())
        self.assertEqual(status, 200)
        self.assertEqual(body2, body)
        # 重放不记事件
        reports = [
            e for e in self._events() if e["type"] == "chain_report"
        ]
        self.assertEqual(len(reports), 1)
        self.assertEqual(reports[0]["request_id"], "op1")
        self.assertEqual(reports[0]["details"], _report())
        self.assertIsNone(reports[0]["actor_id"])
        self.assertIsNone(reports[0]["reason"])

    def test_same_block_confirmations_must_not_decrease(self):
        self.assertEqual(self._report(_report(confirmations=1))[0], 201)
        self.assertEqual(self._report(_report(confirmations=2))[0], 201)
        status, _ = self._report(_report(confirmations=1))
        self.assertEqual(status, 409)
        # 确认数不变但内容相同 -> 同体重放 200
        self.assertEqual(self._report(_report(confirmations=2))[0], 200)

    def test_block_change_allows_confirmation_drop(self):
        self.assertEqual(self._report(_report(confirmations=2))[0], 201)
        # 高度前进、换哈希，确认数可降
        status, _ = self._report(
            _report(height=101, block_hash=HASH2, confirmations=0)
        )
        self.assertEqual(status, 201)
        # 同高度换哈希（reorg 同级）也算换块
        status, _ = self._report(
            _report(height=101, block_hash=HASH3, confirmations=0)
        )
        self.assertEqual(status, 201)

    def test_height_regression_bounded_by_reorg_window(self):
        self.assertEqual(self._report(_report(confirmations=1))[0], 201)
        # 回退 2（100 -> 98），恰在窗内
        status, _ = self._report(
            _report(height=98, block_hash=HASH2, confirmations=0)
        )
        self.assertEqual(status, 201)
        # 回退 3（98 -> 95），越界
        status, _ = self._report(
            _report(height=95, block_hash=HASH3, confirmations=0)
        )
        self.assertEqual(status, 409)

    def test_tx_and_chain_are_bound_by_first_report(self):
        self.assertEqual(self._report(_report())[0], 201)
        status, _ = self._report(_report(tx_id=TX2, confirmations=2))
        self.assertEqual(status, 409)
        # chain_id 与策略链一致但与首报不同（策略链先被改来改去）
        self._put_policy({**POLICY, "chain_id": "ethereum"})
        self._put_policy(POLICY)
        status, _ = self._report(_report(confirmations=2))
        self.assertEqual(status, 201)


class ChainThresholdCommitTest(_HttpBase):
    """达门槛提交：报告事件紧邻唯一提交事件；启用时人工 commit 409。"""

    def setUp(self):
        super().setUp()
        self._put_policy(POLICY)  # required_confirmations = 3
        self._create_op()  # op1: btc +100

    def _commit_event_count(self):
        return len(
            [
                e
                for e in self._events()
                if e["type"] == "asset_operation_committed"
            ]
        )

    def test_threshold_report_commits_once_with_adjacent_events(self):
        self.assertEqual(self._report(_report(confirmations=1))[0], 201)
        self.assertEqual(self._report(_report(confirmations=2))[0], 201)
        status, body = self._report(_report(confirmations=3))
        self.assertEqual(status, 201)
        self.assertEqual(body, _report(confirmations=3))
        # 账本已提交
        status, asset = self.srv.request("GET", "/v1/wallets/w1/assets/btc")
        self.assertEqual(status, 200)
        self.assertEqual((asset["balance"], asset["version"]), (100, 1))
        # 报告事件后紧邻唯一提交事件
        events = self._events()
        types = [e["type"] for e in events]
        self.assertEqual(self._commit_event_count(), 1)
        commit_at = types.index("asset_operation_committed")
        self.assertEqual(types[commit_at - 1], "chain_report")
        self.assertEqual(
            events[commit_at - 1]["details"], _report(confirmations=3)
        )
        self.assertEqual(events[commit_at]["request_id"], "op1")
        self.assertEqual(
            events[commit_at]["details"],
            {
                "operation_id": "op1",
                "asset_id": "btc",
                "state": "committed",
                "delta": 100,
                "balance": 100,
                "version": 1,
            },
        )
        # 提交后同体 200、异体 409（终态）
        self.assertEqual(self._report(_report(confirmations=3))[0], 200)
        self.assertEqual(self._report(_report(confirmations=4))[0], 409)
        status, _ = self._report(_report(tx_id=TX2, confirmations=3))
        self.assertEqual(status, 409)
        # 事件数量不变
        self.assertEqual(self._commit_event_count(), 1)

    def test_first_report_over_threshold_commits_immediately(self):
        status, _ = self._report(_report(confirmations=5))
        self.assertEqual(status, 201)
        _, asset = self.srv.request("GET", "/v1/wallets/w1/assets/btc")
        self.assertEqual((asset["balance"], asset["version"]), (100, 1))
        self.assertEqual(self._commit_event_count(), 1)

    def test_manual_commit_gated_while_enabled(self):
        # 启用时人工提交 pending 一律 409
        status, _ = self.srv.request(
            "POST", "/v1/wallets/w1/asset-operations/op1/commit"
        )
        self.assertEqual(status, 409)
        # 禁用后恢复原契约
        self._put_policy({**POLICY, "enabled": False})
        status, body = self.srv.request(
            "POST", "/v1/wallets/w1/asset-operations/op1/commit"
        )
        self.assertEqual(status, 201)
        self.assertEqual(body["state"], "committed")
        # committed 重放仍 200（即使重新启用）
        self._put_policy(POLICY)
        status, _ = self.srv.request(
            "POST", "/v1/wallets/w1/asset-operations/op1/commit"
        )
        self.assertEqual(status, 200)

    def test_insufficient_balance_fails_without_recording_report(self):
        # 先有大额支出操作：提交时余额不足
        self._create_op("op2", "btc", -100)
        status, _ = self._report(_report(confirmations=3), operation="op2")
        self.assertEqual(status, 409)
        # 报告未落盘：无 chain_report 事件、操作仍 pending、账本不变
        reports = [
            e for e in self._events() if e["type"] == "chain_report"
        ]
        self.assertEqual(reports, [])
        _, op = self.srv.request(
            "POST",
            "/v1/wallets/w1/asset-operations",
            {"operation_id": "op2", "asset_id": "btc", "delta": -100},
        )
        self.assertEqual(op["state"], "pending")
        # 先经报告提交充值，再重试支出报告成功
        self.assertEqual(self._report(_report(confirmations=3))[0], 201)
        status, _ = self._report(_report(confirmations=3), operation="op2")
        self.assertEqual(status, 201)
        _, asset = self.srv.request("GET", "/v1/wallets/w1/assets/btc")
        self.assertEqual((asset["balance"], asset["version"]), (0, 2))


class ChainConcurrencyTest(_HttpBase):
    """并发同体报告恰一个 201；达门槛提交恰一次。"""

    def setUp(self):
        super().setUp()
        self._put_policy(POLICY)
        self._create_op()

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

    def test_concurrent_identical_reports_only_one_201(self):
        results = self._run_concurrent(
            lambda: self._report(_report(confirmations=1))
        )
        statuses = sorted(status for status, _ in results)
        self.assertEqual(statuses, [200] * 7 + [201])
        reports = [
            e for e in self._events() if e["type"] == "chain_report"
        ]
        self.assertEqual(len(reports), 1)

    def test_concurrent_threshold_reports_commit_exactly_once(self):
        results = self._run_concurrent(
            lambda: self._report(_report(confirmations=3))
        )
        statuses = sorted(status for status, _ in results)
        self.assertEqual(statuses, [200] * 7 + [201])
        events = self._events()
        commits = [
            e for e in events if e["type"] == "asset_operation_committed"
        ]
        self.assertEqual(len(commits), 1)
        _, asset = self.srv.request("GET", "/v1/wallets/w1/assets/btc")
        self.assertEqual((asset["balance"], asset["version"]), (100, 1))
        # seq 连续不重号
        self.assertEqual(
            [e["seq"] for e in events], list(range(1, len(events) + 1))
        )


class ChainRestartTest(unittest.TestCase):
    """重启后：策略/报告/提交现场与幂等保持，seq 连续不重号。"""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmpdir, ignore_errors=True)

    def _restart(self):
        self.harness = make_harness(self.tmpdir)
        return self.harness.service

    def test_restart_preserves_policy_reports_and_commit(self):
        service = self._restart()
        service.create_wallet("w1", 2)
        service.put_chain_policy("w1", "btc", "bitcoin", True, 2, 1)
        service.create_asset_operation("w1", "op1", "btc", 100)
        service.create_asset_operation("w1", "op2", "btc", 50)
        report1 = _report(confirmations=1)
        service.post_chain_report(
            "w1", "op1", "bitcoin", TX, 100, HASH1, 1
        )
        service.post_chain_report(
            "w1", "op1", "bitcoin", TX, 100, HASH1, 2
        )

        service = self._restart()
        # 策略与提交现场保持
        self.assertEqual(
            service.get_chain_policy("w1", "btc"),
            {
                "chain_id": "bitcoin",
                "enabled": True,
                "required_confirmations": 2,
                "reorg_window": 1,
            },
        )
        asset = service.get_asset("w1", "btc")
        self.assertEqual((asset["balance"], asset["version"]), (100, 1))
        # 已提交操作同体重放 200、异体 409
        status, _ = service.post_chain_report(
            "w1", "op1", "bitcoin", TX, 100, HASH1, 2
        )
        self.assertEqual(status, 200)
        with self.assertRaises(Exception):
            service.post_chain_report(
                "w1", "op1", "bitcoin", TX, 100, HASH1, 3
            )
        # 另一操作继续走状态机，事件 seq 接续
        status, _ = service.post_chain_report(
            "w1", "op2", "bitcoin", TX, 100, HASH1, 1
        )
        self.assertEqual(status, 201)
        status, _ = service.post_chain_report(
            "w1", "op2", "bitcoin", TX, 100, HASH1, 2
        )
        self.assertEqual(status, 201)
        events = service.get_audit_events("w1")["events"]
        self.assertEqual(
            [e["seq"] for e in events], list(range(1, len(events) + 1))
        )
        commits = [
            e for e in events if e["type"] == "asset_operation_committed"
        ]
        self.assertEqual(len(commits), 2)
        asset = service.get_asset("w1", "btc")
        self.assertEqual((asset["balance"], asset["version"]), (150, 2))


class ChainCorruptionTest(unittest.TestCase):
    """事件损坏/矛盾 fail-closed：常驻 503、启动恢复阻止就绪。"""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmpdir, ignore_errors=True)
        self._ctx = http_server(self.tmpdir)
        self.srv = self._ctx.__enter__()
        self.addCleanup(self._ctx.__exit__, None, None, None)
        self.srv.request(
            "POST", "/v1/wallets", {"wallet_id": "w1", "shares": 2}
        )
        self._put_policy()
        self.srv.request(
            "POST",
            "/v1/wallets/w1/asset-operations",
            {"operation_id": "op1", "asset_id": "btc", "delta": 100},
        )

    def _put_policy(self):
        self.srv.request("PUT", "/v1/wallets/w1/chain/btc", POLICY)

    def _audit_path(self):
        return os.path.join(self.tmpdir, "audit", "w1.json")

    def _read_log(self):
        with open(self._audit_path(), encoding="utf-8") as f:
            return json.load(f)

    def _write_log(self, log):
        with open(self._audit_path(), "w", encoding="utf-8") as f:
            json.dump(log, f)

    def _tamper_event(self, index, **updates):
        log = self._read_log()
        log["events"][index].update(updates)
        self._write_log(log)

    def _expect_503_and_not_ready(self):
        status, _ = self.srv.request("GET", "/v1/wallets/w1/chain/btc")
        self.assertEqual(status, 503)
        status, _ = self.srv.request(
            "POST", "/v1/wallets/w1/chain/op1/report", _report()
        )
        self.assertEqual(status, 503)
        # 启动恢复同样 fail-closed（阻止就绪）
        with self.assertRaises(RecoveryError):
            WalletService(WalletStore(self.tmpdir))

    def test_malformed_chain_policy_event(self):
        self._tamper_event(0, details={"enabled": True})
        self._expect_503_and_not_ready()

    def test_chain_policy_event_with_actor(self):
        self._tamper_event(0, actor_id="mallory")
        self._expect_503_and_not_ready()

    def test_malformed_chain_report_event(self):
        self.srv.request(
            "POST", "/v1/wallets/w1/chain/op1/report", _report()
        )
        self._tamper_event(1, details={"tx_id": "not-hex"})
        self._expect_503_and_not_ready()

    def test_report_for_unknown_operation(self):
        audit = AuditStore(self.tmpdir)
        audit.append_event(
            "w1",
            {
                "type": "chain_report",
                "at": "2026-09-25T00:00:00Z",
                "request_id": "ghost",
                "actor_id": None,
                "reason": None,
                "details": _report(),
            },
        )
        self._expect_503_and_not_ready()

    def test_duplicate_below_threshold_report_is_contradiction(self):
        self.srv.request(
            "POST", "/v1/wallets/w1/chain/op1/report", _report()
        )
        audit = AuditStore(self.tmpdir)
        audit.append_event(
            "w1",
            {
                "type": "chain_report",
                "at": "2026-09-25T00:00:01Z",
                "request_id": "op1",
                "actor_id": None,
                "reason": None,
                "details": _report(),
            },
        )
        self._expect_503_and_not_ready()

    def test_commit_without_preceding_threshold_report(self):
        # 达门槛提交后抹掉全部 chain_report 事件：启用策略下的提交
        # 必须紧邻达门槛报告，否则矛盾
        self.srv.request(
            "POST", "/v1/wallets/w1/chain/op1/report", _report(confirmations=3)
        )
        log = self._read_log()
        kept = [
            e for e in log["events"] if e["type"] != "chain_report"
        ]
        for seq, event in enumerate(kept, start=1):
            event["seq"] = seq
        log["events"] = kept
        log["next_seq"] = len(kept) + 1
        self._write_log(log)
        self._expect_503_and_not_ready()

    def test_report_after_commit_is_contradiction(self):
        self.srv.request(
            "POST", "/v1/wallets/w1/chain/op1/report", _report(confirmations=3)
        )
        audit = AuditStore(self.tmpdir)
        audit.append_event(
            "w1",
            {
                "type": "chain_report",
                "at": "2026-09-25T00:00:01Z",
                "request_id": "op1",
                "actor_id": None,
                "reason": None,
                "details": _report(confirmations=4),
            },
        )
        self._expect_503_and_not_ready()


class ChainCrashConvergenceTest(unittest.TestCase):
    """崩溃窗口收敛：孤立报告事件由同体重试补齐唯一提交。"""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmpdir, ignore_errors=True)

    def test_orphan_report_is_completed_by_retry(self):
        service = make_harness(self.tmpdir).service
        service.create_wallet("w1", 2)
        service.put_chain_policy("w1", "btc", "bitcoin", True, 2, 1)
        service.create_asset_operation("w1", "op1", "btc", 100)
        # 模拟崩溃：意图已写、账本已提交、报告事件已落盘、提交事件缺失
        record = service._store.get_asset_operation("w1", "op1")
        intent = {
            "operation_id": "op1",
            "asset_id": "btc",
            "delta": 100,
            "old_asset": None,
            "pending": record,
            "new_balance": 100,
            "new_version": 1,
        }
        service._store.write_asset_commit_intent("w1", "op1", intent)
        committed = {
            "operation_id": "op1",
            "asset_id": "btc",
            "state": "committed",
            "delta": 100,
            "balance": 100,
            "version": 1,
        }
        service._store.commit_asset_operation(
            "w1", "op1", committed, "btc", {"balance": 100, "version": 1}
        )
        report = _report(confirmations=2)
        service._emit(
            "w1",
            service._audit_event(
                "chain_report", request_id="op1", details=report
            ),
        )
        # 重启：提交事件缺失 -> 回滚账本，孤立报告保留
        service = make_harness(self.tmpdir).service
        op = service._store.get_asset_operation("w1", "op1")
        self.assertEqual(op["state"], "pending")
        self.assertIsNone(service._store.get_asset("w1", "btc"))
        # 同体重试：补齐提交（新报告事件与提交事件紧邻），恰一次
        status, body = service.post_chain_report(
            "w1", "op1", "bitcoin", TX, 100, HASH1, 2
        )
        self.assertEqual(status, 201)
        self.assertEqual(body, report)
        asset = service.get_asset("w1", "btc")
        self.assertEqual((asset["balance"], asset["version"]), (100, 1))
        events = service.get_audit_events("w1")["events"]
        types = [e["type"] for e in events]
        commit_at = types.index("asset_operation_committed")
        self.assertEqual(types[commit_at - 1], "chain_report")
        self.assertEqual(
            len([e for e in events if e["type"] == "asset_operation_committed"]),
            1,
        )
        # 再次重启：对账通过，现场不变
        service = make_harness(self.tmpdir).service
        asset = service.get_asset("w1", "btc")
        self.assertEqual((asset["balance"], asset["version"]), (100, 1))
        status, _ = service.post_chain_report(
            "w1", "op1", "bitcoin", TX, 100, HASH1, 2
        )
        self.assertEqual(status, 200)


class ChainDrBackupTest(unittest.TestCase):
    """灾备 backup/restore：策略、报告与提交现场收敛，不新增审计事件。"""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmpdir, ignore_errors=True)
        self.src = os.path.join(self.tmpdir, "src")
        self.dst = os.path.join(self.tmpdir, "dst")
        self.out = os.path.join(self.tmpdir, "snap.tar")
        os.makedirs(self.src)
        os.makedirs(self.dst)

    def test_backup_restore_roundtrip(self):
        service = make_harness(self.src).service
        service.create_wallet("w1", 2)
        service.put_chain_policy("w1", "btc", "bitcoin", True, 2, 1)
        service.create_asset_operation("w1", "op1", "btc", 100)
        service.create_asset_operation("w1", "op2", "btc", 50)
        service.post_chain_report("w1", "op1", "bitcoin", TX, 100, HASH1, 1)
        service.post_chain_report("w1", "op1", "bitcoin", TX, 100, HASH1, 2)
        service.post_chain_report("w1", "op2", "bitcoin", TX, 100, HASH1, 1)
        before = service.get_audit_events("w1")["events"]

        body = drbackup.backup(self.src, "w1", "S1", self.out)
        self.assertEqual(body["status"], 201)
        status, _ = drbackup.restore(self.dst, "w1", self.out)
        self.assertEqual(status, 201)

        restored = make_harness(self.dst).service
        self.assertEqual(
            restored.get_chain_policy("w1", "btc"),
            {
                "chain_id": "bitcoin",
                "enabled": True,
                "required_confirmations": 2,
                "reorg_window": 1,
            },
        )
        asset = restored.get_asset("w1", "btc")
        self.assertEqual((asset["balance"], asset["version"]), (100, 1))
        # 恢复不新增审计事件，seq 不变
        after = restored.get_audit_events("w1")["events"]
        self.assertEqual(
            [e["seq"] for e in after], [e["seq"] for e in before]
        )
        self.assertEqual(len(after), len(before))
        # 已提交操作同体重放 200；pending 操作继续达门槛提交
        status, _ = restored.post_chain_report(
            "w1", "op1", "bitcoin", TX, 100, HASH1, 2
        )
        self.assertEqual(status, 200)
        status, _ = restored.post_chain_report(
            "w1", "op2", "bitcoin", TX, 100, HASH1, 2
        )
        self.assertEqual(status, 201)
        asset = restored.get_asset("w1", "btc")
        self.assertEqual((asset["balance"], asset["version"]), (150, 2))


if __name__ == "__main__":
    unittest.main()
