"""多源仲裁测试：仲裁策略、观察票、达 quorum 原子提交与故障恢复。

覆盖：
- PUT/GET /v1/wallets/{id}/chain/{asset_id}/arbitration 的键集/值校验
  （400）、钱包 404、未配置 404、同值更新也记 chain_vote 策略事件、
  sources 按 ID 升序、策略仅由审计事件持久化（重启/灾备后不变）；
  该资产存在 pending 操作时 PUT 409 不改；
- POST /v1/wallets/{id}/chain/{oid}/observe 的键集/值校验（400）、
  钱包/操作 404、未配置策略/未知/停用源/改报/终态新增（409）、
  各源首收 201、同源同体 200、异体票并存 conflict、真票达 quorum
  adopted 且票事件紧邻唯一提交事件、提交失败票不落盘；
- 仲裁配置后人工 commit 与链上 report 对 pending 一律 409；
- 并发达门槛恰一个 201/一次提交；重启后视图与 seq 连续；
- chain_vote 事件损坏/矛盾 fail-closed（常驻 503、启动阻止就绪）；
- 灾备 backup/restore 后策略、票与提交现场不变、不新增审计事件。
"""

from __future__ import annotations

import json
import os
import shutil
import tempfile
import threading
import unittest

from threshold_wallet import drbackup
from threshold_wallet.service import WalletService
from threshold_wallet.store import RecoveryError, WalletStore
from tests.helpers import http_server, make_harness

Q = {"sources": {"s1": True, "s2": True, "s3": False}, "quorum": 2}
Q_SORTED = {
    "sources": {"b": True, "a": True, "c": False},
    "quorum": 2,
}
Q_SORTED_EXPECTED = {
    "sources": {"a": True, "b": True, "c": False},
    "quorum": 2,
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

    def _put_arb(self, body, wallet="w1", asset="btc"):
        return self.srv.request(
            "PUT", f"/v1/wallets/{wallet}/chain/{asset}/arbitration", body
        )

    def _get_arb(self, wallet="w1", asset="btc"):
        return self.srv.request(
            "GET", f"/v1/wallets/{wallet}/chain/{asset}/arbitration"
        )

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

    def _observe(self, source, report, wallet="w1", operation="op1"):
        return self.srv.request(
            "POST",
            f"/v1/wallets/{wallet}/chain/{operation}/observe",
            {"source": source, "report": report},
        )

    def _events(self, wallet="w1"):
        status, body = self.srv.request(
            "GET", f"/v1/wallets/{wallet}/audit-events"
        )
        self.assertEqual(status, 200)
        return body["events"]


class ArbitrationPolicyHttpTest(_HttpBase):
    """PUT/GET .../chain/{asset}/arbitration 的校验与幂等。"""

    def test_put_then_get_returns_same_body(self):
        status, body = self._put_arb(Q)
        self.assertEqual(status, 200)
        self.assertEqual(body, Q)
        status, body = self._get_arb()
        self.assertEqual(status, 200)
        self.assertEqual(body, Q)

    def test_sources_are_returned_sorted_by_id(self):
        status, body = self._put_arb(Q_SORTED)
        self.assertEqual(status, 200)
        self.assertEqual(body, Q_SORTED_EXPECTED)
        self.assertEqual(list(body["sources"]), ["a", "b", "c"])

    def test_get_without_policy_returns_404(self):
        self.assertEqual(self._get_arb()[0], 404)

    def test_unknown_wallet_returns_404(self):
        self.assertEqual(self._put_arb(Q, wallet="ghost")[0], 404)
        self.assertEqual(self._get_arb(wallet="ghost")[0], 404)

    def test_invalid_asset_id_returns_400(self):
        self.assertEqual(self._put_arb(Q, asset="bad$")[0], 400)
        self.assertEqual(self._get_arb(asset="bad$")[0], 400)

    def test_key_set_errors_return_400(self):
        for body in (
            {},
            {"sources": Q["sources"]},
            {"quorum": 2},
            {**Q, "extra": 1},
        ):
            with self.subTest(body=body):
                self.assertEqual(self._put_arb(body)[0], 400)

    def test_value_errors_return_400(self):
        bad_sources = (
            {},
            [],
            {"bad$id": True},
            {"s1": "true"},
            {"s1": 1},
            {"s1": None},
            {"": True},
            {"s" * 129: True},
        )
        for sources in bad_sources:
            with self.subTest(sources=sources):
                self.assertEqual(
                    self._put_arb({"sources": sources, "quorum": 2})[0],
                    400,
                )
        bad_quorums = (1, 0, -1, 3, 2.0, "2", True, False, None, [2])
        # Q 只有 2 个启用源，故 quorum=3 越界
        for quorum in bad_quorums:
            with self.subTest(quorum=quorum):
                self.assertEqual(
                    self._put_arb(
                        {"sources": Q["sources"], "quorum": quorum}
                    )[0],
                    400,
                )

    def test_single_enabled_source_has_no_valid_quorum(self):
        status, _ = self._put_arb(
            {"sources": {"s1": True, "s2": False}, "quorum": 2}
        )
        self.assertEqual(status, 400)

    def test_same_value_put_records_event_each_time(self):
        self._put_arb(Q)
        self._put_arb(Q)
        events = [e for e in self._events() if e["type"] == "chain_vote"]
        self.assertEqual(len(events), 2)
        self.assertEqual([e["seq"] for e in events], [1, 2])
        for event in events:
            self.assertEqual(event["request_id"], "btc")
            self.assertIsNone(event["actor_id"])
            self.assertIsNone(event["reason"])
            self.assertEqual(event["details"], Q)
            self.assertEqual(list(event["details"]), ["sources", "quorum"])

    def test_put_conflicts_while_asset_has_pending_operation(self):
        self._put_arb(Q)
        self._create_op()
        status, _ = self._put_arb(
            {"sources": {"s1": True, "s2": True, "s3": True}, "quorum": 3}
        )
        self.assertEqual(status, 409)
        # 策略与审计现场不变
        self.assertEqual(self._get_arb()[1], Q)
        votes = [e for e in self._events() if e["type"] == "chain_vote"]
        self.assertEqual(len(votes), 1)

    def test_put_allowed_after_operation_committed(self):
        self._put_arb(Q)
        self._create_op()
        self._observe("s1", True)
        self.assertEqual(self._observe("s2", True)[1], {"state": "adopted"})
        new_q = {"sources": {"a": True, "b": True}, "quorum": 2}
        self.assertEqual(self._put_arb(new_q)[0], 200)
        self.assertEqual(self._get_arb()[1], new_q)

    def test_pending_operation_of_other_asset_does_not_block(self):
        self._put_arb(Q, asset="btc")
        self._create_op(asset_id="eth")
        status, _ = self._put_arb(
            {"sources": {"a": True, "b": True}, "quorum": 2}, asset="eth"
        )
        # 未决操作属于 eth：配置 eth 的仲裁策略应 409
        self.assertEqual(status, 409)
        # 但可以给另一个无 pending 操作的资产配策略
        status, _ = self._put_arb(Q, asset="doge")
        self.assertEqual(status, 200)


class ObserveHttpTest(_HttpBase):
    """POST .../chain/{oid}/observe 的状态机。"""

    def setUp(self):
        super().setUp()
        self._put_arb(Q)
        self._create_op()

    def test_first_ballot_201_collecting_and_replay_200(self):
        status, body = self._observe("s1", True)
        self.assertEqual((status, body), (201, {"state": "collecting"}))
        status, body = self._observe("s1", True)
        self.assertEqual((status, body), (200, {"state": "collecting"}))

    def test_dissenting_ballot_yields_conflict(self):
        self.assertEqual(self._observe("s1", True)[1], {"state": "collecting"})
        self.assertEqual(self._observe("s2", False)[1], {"state": "conflict"})
        # 同源同体在 conflict 下仍 200 回当前状态
        self.assertEqual(self._observe("s1", True)[1], {"state": "conflict"})

    def test_true_ballots_reach_quorum_and_adopt(self):
        self.assertEqual(self._observe("s1", True)[0], 201)
        status, body = self._observe("s2", True)
        self.assertEqual((status, body), (201, {"state": "adopted"}))
        # 账本已提交
        status, asset = self.srv.request("GET", "/v1/wallets/w1/assets/btc")
        self.assertEqual(status, 200)
        self.assertEqual(asset["balance"], 100)
        self.assertEqual(asset["version"], 1)

    def test_quorum_can_form_after_conflict(self):
        self._observe("s1", True)
        self._observe("s2", False)
        # s3 在策略中停用：仍只有两个启用源，conflict 无法翻盘
        self.assertEqual(self._observe("s3", True)[0], 409)
        # 改配三启用源需要先提交/清空 pending，这里直接用新资产验证
        self._put_arb(
            {"sources": {"s1": True, "s2": True, "s3": True}, "quorum": 2},
            asset="eth",
        )
        self._create_op(operation_id="op2", asset_id="eth")
        self.assertEqual(
            self._observe("s1", True, operation="op2")[1],
            {"state": "collecting"},
        )
        self.assertEqual(
            self._observe("s2", False, operation="op2")[1],
            {"state": "conflict"},
        )
        self.assertEqual(
            self._observe("s3", True, operation="op2")[1],
            {"state": "adopted"},
        )

    def test_change_report_409_and_state_unchanged(self):
        self._observe("s1", True)
        self.assertEqual(self._observe("s1", False)[0], 409)
        events = [
            e
            for e in self._events()
            if e["type"] == "chain_vote" and e["request_id"] == "op1"
        ]
        self.assertEqual(len(events), 1)

    def test_unknown_or_disabled_source_409(self):
        self.assertEqual(self._observe("s3", True)[0], 409)
        self.assertEqual(self._observe("s9", True)[0], 409)

    def test_no_arbitration_policy_is_unknown_source_409(self):
        self._create_op(operation_id="opx", asset_id="doge")
        self.assertEqual(
            self._observe("s1", True, operation="opx")[0], 409
        )

    def test_unknown_wallet_and_operation_404(self):
        status, _ = self.srv.request(
            "POST",
            "/v1/wallets/ghost/chain/op1/observe",
            {"source": "s1", "report": True},
        )
        self.assertEqual(status, 404)
        self.assertEqual(self._observe("s1", True, operation="nope")[0], 404)

    def test_key_set_and_value_errors_400(self):
        for body in (
            {},
            {"source": "s1"},
            {"report": True},
            {"source": "s1", "report": True, "extra": 1},
        ):
            status, _ = self.srv.request(
                "POST", "/v1/wallets/w1/chain/op1/observe", body
            )
            self.assertEqual(status, 400, body)
        for body in (
            {"source": 1, "report": True},
            {"source": "bad$", "report": True},
            {"source": "s1", "report": "true"},
            {"source": "s1", "report": 1},
        ):
            status, _ = self.srv.request(
                "POST", "/v1/wallets/w1/chain/op1/observe", body
            )
            self.assertEqual(status, 400, body)

    def test_terminal_operation_rejects_new_and_changed_ballots(self):
        self._observe("s1", True)
        self._observe("s2", True)
        # 已投票源同体重放 200 adopted
        self.assertEqual(
            self._observe("s1", True), (200, {"state": "adopted"})
        )
        # 新源投票 409、同源改报 409
        self.assertEqual(self._observe("s3", True)[0], 409)
        self.assertEqual(self._observe("s1", False)[0], 409)
        events = [
            e
            for e in self._events()
            if e["type"] == "chain_vote" and e["request_id"] == "op1"
        ]
        # adopted 后重放/新增都不记事件：仍只有两张票
        self.assertEqual(len(events), 2)

    def test_manual_commit_and_chain_report_blocked_while_arbitrated(self):
        status, _ = self.srv.request(
            "POST", "/v1/wallets/w1/asset-operations/op1/commit"
        )
        self.assertEqual(status, 409)
        # 同时配置链确认策略后，report 对 pending 仍 409
        chain_policy = {
            "chain_id": "bitcoin",
            "enabled": True,
            "required_confirmations": 3,
            "reorg_window": 2,
        }
        self.assertEqual(
            self.srv.request(
                "PUT", "/v1/wallets/w1/chain/btc", chain_policy
            )[0],
            200,
        )
        report = {
            "chain_id": "bitcoin",
            "tx_id": "ab" * 32,
            "block_height": 10,
            "block_hash": "cd" * 32,
            "confirmations": 1,
        }
        status, _ = self.srv.request(
            "POST", "/v1/wallets/w1/chain/op1/report", report
        )
        self.assertEqual(status, 409)

    def test_insufficient_balance_vote_not_persisted_and_retryable(self):
        # 无资金的负 delta：达 quorum 提交失败 409，票不落盘
        self._create_op(operation_id="poor", delta=-50)
        self.assertEqual(
            self._observe("s1", True, operation="poor")[0], 201
        )
        status, _ = self._observe("s2", True, operation="poor")
        self.assertEqual(status, 409)
        events = [
            e
            for e in self._events()
            if e["type"] == "chain_vote" and e["request_id"] == "poor"
        ]
        self.assertEqual(len(events), 1)
        # 充钱后另一操作达 quorum 提交，poor 可重试成功
        self._create_op(operation_id="fund", delta=100)
        self._observe("s1", True, operation="fund")
        self._observe("s2", True, operation="fund")
        status, body = self._observe("s2", True, operation="poor")
        self.assertEqual((status, body), (201, {"state": "adopted"}))

    def test_adopted_ballot_event_is_adjacent_to_commit(self):
        self._observe("s1", True)
        self._observe("s2", True)
        events = self._events()
        votes = [
            (i, e)
            for i, e in enumerate(events)
            if e["type"] == "chain_vote" and e["request_id"] == "op1"
        ]
        adopted_index, adopted = votes[-1]
        self.assertEqual(adopted["details"]["state"], "adopted")
        follower = events[adopted_index + 1]
        self.assertEqual(follower["type"], "asset_operation_committed")
        self.assertEqual(follower["request_id"], "op1")
        self.assertEqual(
            [e["seq"] for e in (adopted, follower)],
            [adopted["seq"], adopted["seq"] + 1],
        )


class ObserveConcurrencyTest(_HttpBase):
    """并发达门槛：恰一个 201 触发一次原子提交。"""

    def test_concurrent_quorum_single_adoption(self):
        self._put_arb(
            {"sources": {"s1": True, "s2": True, "s3": True}, "quorum": 2}
        )
        self._create_op()
        results = []
        lock = threading.Lock()

        def vote(source):
            status, body = self._observe(source, True)
            with lock:
                results.append((source, status, body))

        threads = [
            threading.Thread(target=vote, args=(source,))
            for source in ("s1", "s2", "s3")
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        adopted = [r for r in results if r[2] == {"state": "adopted"}]
        self.assertEqual(len(adopted), 1)
        self.assertEqual({r[1] for r in results}, {201, 409})
        commits = [
            e
            for e in self._events()
            if e["type"] == "asset_operation_committed"
        ]
        self.assertEqual(len(commits), 1)


class ArbitrationPersistenceTest(unittest.TestCase):
    """策略/票仅由审计事件持久化：重启与灾备后现场不变。"""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmpdir, ignore_errors=True)

    def _populated(self, data_dir):
        harness = make_harness(data_dir)
        service = harness.service
        service.create_wallet("w1", 2)
        service.put_chain_arbitration(
            "w1", "btc", {"s1": True, "s2": True, "s3": True}, 2
        )
        service.create_asset_operation("w1", "op1", "btc", 100)
        service.observe("w1", "op1", "s1", True)
        service.observe("w1", "op1", "s2", True)
        return harness

    def test_restart_preserves_policy_votes_and_seq(self):
        self._populated(self.tmpdir)
        before = WalletService(WalletStore(self.tmpdir))
        seq_before = len(before._audit.all_events("w1"))
        reopened = WalletService(WalletStore(self.tmpdir))
        self.assertEqual(
            reopened.get_chain_arbitration("w1", "btc"),
            {"sources": {"s1": True, "s2": True, "s3": True}, "quorum": 2},
        )
        self.assertEqual(
            reopened.observe("w1", "op1", "s1", True),
            (200, {"state": "adopted"}),
        )
        from threshold_wallet.service import ServiceError

        with self.assertRaises(ServiceError) as ctx:
            reopened.observe("w1", "op1", "s2", False)
        self.assertEqual(ctx.exception.status, 409)
        self.assertEqual(
            len(reopened._audit.all_events("w1")), seq_before
        )

    def test_backup_restore_roundtrip(self):
        self._populated(self.tmpdir)
        target = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, target, ignore_errors=True)
        snapshot = tempfile.mktemp(suffix=".tar")
        self.addCleanup(
            lambda: __import__("os").path.exists(snapshot)
            and __import__("os").unlink(snapshot)
        )
        result = drbackup.backup(self.tmpdir, "w1", "snap-1", snapshot)
        self.assertEqual(result["status"], 201)
        status, _ = drbackup.restore(target, "w1", snapshot)
        self.assertEqual(status, 201)
        reopened = WalletService(WalletStore(target))
        self.assertEqual(
            reopened.get_chain_arbitration("w1", "btc"),
            {"sources": {"s1": True, "s2": True, "s3": True}, "quorum": 2},
        )
        self.assertEqual(
            reopened.observe("w1", "op1", "s1", True),
            (200, {"state": "adopted"}),
        )
        self.assertEqual(reopened.get_asset("w1", "btc")["version"], 1)


class ArbitrationCorruptionTest(unittest.TestCase):
    """chain_vote 事件损坏/矛盾 fail-closed：常驻 503、启动阻止就绪。"""

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
            "PUT",
            "/v1/wallets/w1/chain/btc/arbitration",
            {"sources": {"s1": True, "s2": True}, "quorum": 2},
        )
        self.srv.request(
            "POST",
            "/v1/wallets/w1/asset-operations",
            {"operation_id": "op1", "asset_id": "btc", "delta": 100},
        )
        self.srv.request(
            "POST",
            "/v1/wallets/w1/chain/op1/observe",
            {"source": "s1", "report": True},
        )

    def _audit_path(self):
        return f"{self.tmpdir}/audit/w1.json"

    def _rewrite_audit(self, mutate):
        with open(self._audit_path(), encoding="utf-8") as f:
            log = json.load(f)
        mutate(log)
        with open(self._audit_path(), "w", encoding="utf-8") as f:
            json.dump(log, f)

    def _append_event(self, details):
        from threshold_wallet.audit import AuditStore

        AuditStore(self.tmpdir).append_event("w1", details)

    def _expect_503_and_not_ready(self):
        # 常驻进程下一次持锁访问自愈失败：一律 503
        status, _ = self.srv.request(
            "GET", "/v1/wallets/w1/chain/btc/arbitration"
        )
        self.assertEqual(status, 503)
        status, _ = self.srv.request(
            "POST",
            "/v1/wallets/w1/chain/op1/observe",
            {"source": "s2", "report": True},
        )
        self.assertEqual(status, 503)
        # 启动恢复同样 fail-closed（阻止就绪），现场保留
        with self.assertRaises(RecoveryError):
            WalletService(WalletStore(self.tmpdir))

    def test_forged_ballot_state_blocks_startup(self):
        def mutate(log):
            for event in log["events"]:
                if event.get("request_id") == "op1":
                    event["details"]["state"] = "adopted"

        self._rewrite_audit(mutate)
        self._expect_503_and_not_ready()

    def test_adopted_ballot_without_commit_blocks_startup(self):
        self._append_event(
            {
                "type": "chain_vote",
                "at": "2026-09-25T00:00:00Z",
                "request_id": "op1",
                "actor_id": None,
                "reason": None,
                "details": {
                    "source": "s2",
                    "report": True,
                    "state": "adopted",
                },
            }
        )
        self._expect_503_and_not_ready()

    def test_bad_quorum_policy_blocks_startup(self):
        self._append_event(
            {
                "type": "chain_vote",
                "at": "2026-09-25T00:00:01Z",
                "request_id": "doge",
                "actor_id": None,
                "reason": None,
                "details": {"sources": {"s1": True}, "quorum": 1},
            }
        )
        self._expect_503_and_not_ready()

    def test_repeated_ballot_from_same_source_blocks_startup(self):
        self._append_event(
            {
                "type": "chain_vote",
                "at": "2026-09-25T00:00:02Z",
                "request_id": "op1",
                "actor_id": None,
                "reason": None,
                "details": {
                    "source": "s1",
                    "report": False,
                    "state": "collecting",
                },
            }
        )
        self._expect_503_and_not_ready()


class VoteCommitCrashRecoveryTest(unittest.TestCase):
    """达 quorum 票触发提交的崩溃前滚/回滚（意图为唯一判据）。"""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmpdir, ignore_errors=True)
        self.harness = make_harness(self.tmpdir)
        self.service = self.harness.service
        self.service.create_wallet("w1", 2)
        self.service.put_chain_arbitration(
            "w1", "btc", {"s1": True, "s2": True}, 2
        )
        self.service.create_asset_operation("w1", "op1", "btc", 100)
        self.service.observe("w1", "op1", "s1", True)
        self._record = self.harness.store.get_asset_operation("w1", "op1")
        self._intent = {
            "operation_id": "op1",
            "asset_id": "btc",
            "delta": 100,
            "old_asset": None,
            "pending": self._record,
            "new_balance": 100,
            "new_version": 1,
            "vote": True,
        }

    def _write_intent(self):
        path = f"{self.tmpdir}/asset-intents/w1/op1.json"
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(self._intent, f)

    def _intent_exists(self):
        return os.path.exists(f"{self.tmpdir}/asset-intents/w1/op1.json")

    def test_rollback_when_vote_and_commit_events_absent(self):
        self._write_intent()
        reopened = WalletService(WalletStore(self.tmpdir))
        self.assertEqual(
            self.harness.store.get_asset_operation("w1", "op1")["state"],
            "pending",
        )
        self.assertFalse(self._intent_exists())
        # 票从未落盘：s2 首票可正常达 quorum 提交
        self.assertEqual(
            reopened.observe("w1", "op1", "s2", True),
            (201, {"state": "adopted"}),
        )
        self.assertEqual(
            self.harness.store.get_asset("w1", "btc"),
            {"balance": 100, "version": 1},
        )

    def test_rollforward_when_vote_and_commit_events_landed(self):
        committed = {
            **self._record,
            "state": "committed",
            "balance": 100,
            "version": 1,
        }
        self._write_intent()
        self.harness.store.commit_asset_operation(
            "w1", "op1", committed, "btc", {"balance": 100, "version": 1}
        )
        self.service._audit.append_events(
            "w1",
            [
                self.service._audit_event(
                    "chain_vote",
                    request_id="op1",
                    details={
                        "source": "s2",
                        "report": True,
                        "state": "adopted",
                    },
                ),
                self.service._audit_event(
                    "asset_operation_committed",
                    request_id="op1",
                    details=committed,
                ),
            ],
        )
        reopened = WalletService(WalletStore(self.tmpdir))
        self.assertEqual(
            self.harness.store.get_asset_operation("w1", "op1")["state"],
            "committed",
        )
        self.assertFalse(self._intent_exists())
        self.assertEqual(
            reopened.observe("w1", "op1", "s1", True),
            (200, {"state": "adopted"}),
        )

