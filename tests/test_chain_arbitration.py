"""多源仲裁测试：仲裁策略、观察票状态机、quorum 原子提交与故障恢复。

覆盖：
- PUT/GET /v1/wallets/{id}/chain/{asset_id}/arbitration 的键集/值校验
  （400）、钱包 404、未配置 404、sources ID 升序、quorum ∈ [2,启用数]、
  同值更新也记 chain_vote 策略事件、策略仅由审计事件持久化；
  该资产存在任一 pending 资产操作（即使尚无票）时 PUT 409，策略/审计/
  seq 均不变；
- POST /v1/wallets/{id}/chain/{oid}/observe 的键集/值校验（400）、
  钱包/操作/策略 404、未知/停用源、未达门槛报告、改报、终态新增票
  （409）、各源首收 201、同源同体 200、异体票 conflict、达 quorum
  adopted 且票/报告/提交三事件紧邻原子落盘；
- 启用仲裁后 chain report 对 pending 操作 409（committed 重放 200）；
- 并发首票/决定性票恰一个 201、提交恰一次；重启后视图与 seq 连续；
- 事件损坏/矛盾 fail-closed（常驻 503、启动恢复阻止就绪）；
- 合法旧 chain_arbitration 事件仅只读兼容；
- 灾备 backup/restore 后策略、票与提交现场不变、不新增审计事件。
"""

from __future__ import annotations

import json
import os
import shutil
import tempfile
import threading
import unittest
from unittest import mock

from threshold_wallet import drbackup
from threshold_wallet.audit import AuditStore
from threshold_wallet.service import WalletService
from threshold_wallet.store import CorruptDataError, RecoveryError, WalletStore
from tests.helpers import http_server, make_harness

TX = "ab" * 32
HASH1 = "11" * 32
HASH2 = "22" * 32

CHAIN_POLICY = {
    "chain_id": "bitcoin",
    "enabled": True,
    "required_confirmations": 3,
    "reorg_window": 2,
}

ARBITRATION = {"sources": {"s1": True, "s2": True, "s3": False}, "quorum": 2}


def _report(chain_id="bitcoin", tx_id=TX, height=100, block_hash=HASH1,
            confirmations=3):
    return {
        "chain_id": chain_id,
        "tx_id": tx_id,
        "block_height": height,
        "block_hash": block_hash,
        "confirmations": confirmations,
    }


def _is_policy_event(event: dict) -> bool:
    """新形仲裁策略事件：chain_vote 且 details 恰为 {sources,quorum}。"""
    return (
        event.get("type") == "chain_vote"
        and isinstance(event.get("details"), dict)
        and set(event["details"]) == {"sources", "quorum"}
    )


def _is_vote_event(event: dict) -> bool:
    """观察票事件：chain_vote 且 details 恰为 {source,report,state}。"""
    return (
        event.get("type") == "chain_vote"
        and isinstance(event.get("details"), dict)
        and set(event["details"]) == {"source", "report", "state"}
    )


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

    def _chain_policy(self, body=CHAIN_POLICY, wallet="w1", asset="btc"):
        return self.srv.request(
            "PUT", f"/v1/wallets/{wallet}/chain/{asset}", body
        )

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
        status, body = self._put_arb(ARBITRATION)
        self.assertEqual(status, 200)
        self.assertEqual(body, ARBITRATION)
        status, body = self._get_arb()
        self.assertEqual(status, 200)
        self.assertEqual(body, ARBITRATION)

    def test_get_without_policy_returns_404(self):
        status, _ = self._get_arb()
        self.assertEqual(status, 404)

    def test_unknown_wallet_returns_404(self):
        status, _ = self._put_arb(ARBITRATION, wallet="nope")
        self.assertEqual(status, 404)
        status, _ = self._get_arb(wallet="nope")
        self.assertEqual(status, 404)

    def test_invalid_asset_id_returns_400(self):
        status, _ = self._put_arb(ARBITRATION, asset="bad$id")
        self.assertEqual(status, 400)
        status, _ = self._get_arb(asset="bad$id")
        self.assertEqual(status, 400)

    def test_key_set_errors_return_400(self):
        for body in (
            {},
            {"sources": ARBITRATION["sources"]},
            {"quorum": 2},
            {**ARBITRATION, "extra": 1},
        ):
            with self.subTest(body=body):
                status, _ = self._put_arb(body)
                self.assertEqual(status, 400)

    def test_value_errors_return_400(self):
        bad_bodies = []
        # sources 必须是非空 {安全ID: bool}
        for bad_sources in (
            {},
            [],
            {"bad$id": True},
            {"a": 1},
            {"a": "true"},
            {"a": None},
            {1: True},
        ):
            bad_bodies.append({"sources": bad_sources, "quorum": 2})
        # quorum 必须为 [2, 启用数] 内非布尔整数
        for bad_quorum in (1, 3, 0, -1, True, False, 2.0, "2", None, [2]):
            bad_bodies.append(
                {"sources": {"a": True, "b": True}, "quorum": bad_quorum}
            )
        # 只有一个启用源时 quorum 永远非法
        bad_bodies.append({"sources": {"a": True, "b": False}, "quorum": 2})
        for body in bad_bodies:
            with self.subTest(body=body):
                status, _ = self._put_arb(body)
                self.assertEqual(status, 400)
        # 边界合法：两启用源 quorum=2；响应 sources 按 ID 升序
        status, body = self._put_arb(
            {"sources": {"b": True, "a": True}, "quorum": 2}
        )
        self.assertEqual(status, 200)
        self.assertEqual(
            list(body["sources"]), ["a", "b"]
        )

    def test_sources_normalized_to_id_ascending_order(self):
        status, body = self._put_arb(
            {"sources": {"z": False, "a": True, "m": True}, "quorum": 2}
        )
        self.assertEqual(status, 200)
        self.assertEqual(
            list(body["sources"].keys()), ["a", "m", "z"]
        )
        events = [e for e in self._events() if _is_policy_event(e)]
        self.assertEqual(
            list(events[0]["details"]["sources"].keys()), ["a", "m", "z"]
        )
        # 新策略只写 chain_vote 事件（七字段，request_id=A，
        # actor_id/reason=null）
        self.assertEqual(events[0]["type"], "chain_vote")
        self.assertEqual(events[0]["request_id"], "btc")
        self.assertIsNone(events[0]["actor_id"])
        self.assertIsNone(events[0]["reason"])
        self.assertEqual(
            list(events[0]["details"]), ["sources", "quorum"]
        )

    def test_same_value_put_records_event_each_time(self):
        self._put_arb(ARBITRATION)
        self._put_arb(ARBITRATION)
        events = [e for e in self._events() if _is_policy_event(e)]
        self.assertEqual(len(events), 2)
        for event in events:
            self.assertEqual(event["request_id"], "btc")
            self.assertIsNone(event["actor_id"])
            self.assertIsNone(event["reason"])
            self.assertEqual(event["details"], ARBITRATION)

    def test_put_with_pending_operation_but_no_votes_is_409(self):
        # 只要该资产存在任一 pending 资产操作，即使尚无任何观察票，
        # PUT 也一律 409；策略、审计与 seq 均不变。
        self._chain_policy()
        self.assertEqual(self._put_arb(ARBITRATION)[0], 200)
        before = self._events()
        self._create_op()
        status, _ = self._put_arb(
            {"sources": {"s1": True, "s2": True, "s3": True}, "quorum": 3}
        )
        self.assertEqual(status, 409)
        # 策略仍是旧值，审计事件集与 seq 不变
        status, body = self._get_arb()
        self.assertEqual(status, 200)
        self.assertEqual(body, ARBITRATION)
        after = self._events()
        self.assertEqual(
            [e["seq"] for e in after], [e["seq"] for e in before]
        )
        self.assertEqual(len(after), len(before))

    def test_put_after_pending_operation_committed_is_allowed(self):
        # pending 操作经仲裁提交（终态）后，策略可再次更新
        self._chain_policy()
        self._put_arb({"sources": {"s1": True, "s2": True}, "quorum": 2})
        self._create_op()
        self.assertEqual(self._observe("s1", _report())[0], 201)
        self.assertEqual(self._observe("s2", _report())[0], 201)
        status, _ = self._put_arb(
            {"sources": {"s1": True, "s2": True, "s3": True}, "quorum": 2}
        )
        self.assertEqual(status, 200)

    def test_put_while_unresolved_arbitration_returns_409(self):
        self._chain_policy()
        self._put_arb(ARBITRATION)
        self._create_op()
        self.assertEqual(self._observe("s1", _report())[0], 201)
        # collecting 期间（该资产有 pending 操作）改策略 409
        status, _ = self._put_arb(
            {"sources": {"s1": True, "s2": True}, "quorum": 2}
        )
        self.assertEqual(status, 409)
        # 另一资产（无 pending 操作）不受影响
        status, _ = self._put_arb(
            {"sources": {"s1": True, "s2": True}, "quorum": 2}, asset="eth"
        )
        self.assertEqual(status, 200)


class ObserveValidationTest(_HttpBase):
    """observe 的 400/404/409 判定。"""

    def setUp(self):
        super().setUp()
        self._chain_policy()
        self._put_arb(ARBITRATION)
        self._create_op()

    def test_key_set_errors_return_400(self):
        for body in (
            {},
            {"source": "s1"},
            {"report": _report()},
            {"source": "s1", "report": _report(), "extra": 1},
        ):
            with self.subTest(body=body):
                status, _ = self.srv.request(
                    "POST", "/v1/wallets/w1/chain/op1/observe", body
                )
                self.assertEqual(status, 400)

    def test_bad_source_returns_400(self):
        for bad in ("", "has space", "bad$id", 1, True, None, ["s1"]):
            with self.subTest(bad=bad):
                status, _ = self._observe(bad, _report())
                self.assertEqual(status, 400)

    def test_bad_report_returns_400(self):
        bad_reports = []
        bad_reports.append("not-an-object")
        bad_reports.append({k: v for k, v in _report().items() if k != "tx_id"})
        bad_reports.append({**_report(), "extra": 1})
        bad_reports.append({**_report(), "chain_id": "bad$chain"})
        bad_reports.append({**_report(), "tx_id": "ZZ" * 32})
        bad_reports.append({**_report(), "confirmations": True})
        for report in bad_reports:
            with self.subTest(report=report):
                status, _ = self._observe("s1", report)
                self.assertEqual(status, 400)

    def test_unknown_wallet_returns_404(self):
        status, _ = self._observe("s1", _report(), wallet="nope")
        self.assertEqual(status, 404)

    def test_unknown_operation_returns_404(self):
        status, _ = self._observe("s1", _report(), operation="ghost")
        self.assertEqual(status, 404)

    def test_unknown_or_disabled_source_returns_409(self):
        status, _ = self._observe("nope", _report())
        self.assertEqual(status, 409)
        # s3 在策略中但停用
        status, _ = self._observe("s3", _report())
        self.assertEqual(status, 409)

    def test_report_below_threshold_returns_409(self):
        status, _ = self._observe("s1", _report(confirmations=2))
        self.assertEqual(status, 409)

    def test_report_on_other_chain_returns_409(self):
        status, _ = self._observe("s1", _report(chain_id="ethereum"))
        self.assertEqual(status, 409)

    def test_observe_without_chain_policy_returns_409(self):
        # 仲裁策略可在无跨链策略时配置；该资产有 pending 操作后观察因
        # 跨链策略未启用而 409（策略先于 pending 操作配置）。
        self._put_arb(
            {"sources": {"s1": True, "s2": True}, "quorum": 2}, asset="eth"
        )
        self._create_op("op2", "eth", 10)
        status, _ = self._observe("s1", _report(chain_id="bitcoin"),
                                  operation="op2")
        self.assertEqual(status, 409)


class ObserveStateMachineTest(_HttpBase):
    """票状态机：collecting/conflict/adopted、幂等与改报。"""

    def setUp(self):
        super().setUp()
        self._chain_policy()
        self._put_arb(ARBITRATION)
        self._create_op()

    def test_first_vote_collecting_then_replay_200(self):
        status, body = self._observe("s1", _report())
        self.assertEqual(status, 201)
        self.assertEqual(body, {"state": "collecting"})
        status, body = self._observe("s1", _report())
        self.assertEqual(status, 200)
        self.assertEqual(body, {"state": "collecting"})
        # 重放不记事件
        votes = [e for e in self._events() if _is_vote_event(e)]
        self.assertEqual(len(votes), 1)
        self.assertEqual(votes[0]["request_id"], "op1")
        self.assertEqual(
            votes[0]["details"],
            {"source": "s1", "report": _report(), "state": "collecting"},
        )
        self.assertIsNone(votes[0]["actor_id"])
        self.assertIsNone(votes[0]["reason"])

    def test_divergent_votes_become_conflict(self):
        self.assertEqual(self._observe("s1", _report())[0], 201)
        status, body = self._observe("s2", _report(height=101, block_hash=HASH2))
        self.assertEqual(status, 201)
        self.assertEqual(body, {"state": "conflict"})
        # 两票并存；再投同 s2 体仍 conflict（幂等 200）
        status, body = self._observe("s2", _report(height=101, block_hash=HASH2))
        self.assertEqual(status, 200)
        self.assertEqual(body, {"state": "conflict"})

    def test_same_source_changed_report_returns_409(self):
        self._observe("s1", _report())
        status, _ = self._observe("s1", _report(height=101, block_hash=HASH2))
        self.assertEqual(status, 409)
        # 现场不改：仍只一张 s1 票
        votes = [e for e in self._events() if _is_vote_event(e)]
        self.assertEqual(len(votes), 1)

    def test_conflict_then_third_agreeing_source_adopts(self):
        # 三源 quorum=2：s1 投 X、s2 投 Y -> conflict；s3 投 X 与 s1
        # 凑齐 quorum -> adopted X。第二资产的策略须先于其 pending
        # 操作配置（有 pending 操作后 PUT 仲裁策略一律 409）。
        self._chain_policy({**CHAIN_POLICY, "chain_id": "ethereum"}, asset="eth")
        self._put_arb(
            {"sources": {"s1": True, "s2": True, "s3": True}, "quorum": 2},
            asset="eth",
        )
        self._create_op("op2", "eth", 10)
        body_x = _report(chain_id="ethereum")
        body_y = _report(
            chain_id="ethereum", height=101, block_hash=HASH2
        )
        self.assertEqual(
            self._observe("s1", body_x, operation="op2")[1],
            {"state": "collecting"},
        )
        self.assertEqual(
            self._observe("s2", body_y, operation="op2")[1],
            {"state": "conflict"},
        )
        status, body = self._observe("s3", body_x, operation="op2")
        self.assertEqual(status, 201)
        self.assertEqual(body, {"state": "adopted"})
        # 账本按 X 提交
        status, asset = self.srv.request("GET", "/v1/wallets/w1/assets/eth")
        self.assertEqual(status, 200)
        self.assertEqual((asset["balance"], asset["version"]), (10, 1))

    def test_quorum_of_three_requires_three_agreeing_votes(self):
        self._chain_policy(
            {**CHAIN_POLICY, "chain_id": "ethereum"}, asset="eth"
        )
        policy = {"sources": {"s1": True, "s2": True, "s3": True}, "quorum": 3}
        self._put_arb(policy, asset="eth")
        self._create_op("op2", "eth", 10)
        other = _report(chain_id="ethereum")
        self.assertEqual(
            self._observe("s1", other, operation="op2")[1],
            {"state": "collecting"},
        )
        self.assertEqual(
            self._observe("s2", other, operation="op2")[1],
            {"state": "collecting"},
        )
        status, body = self._observe("s3", other, operation="op2")
        self.assertEqual(status, 201)
        self.assertEqual(body, {"state": "adopted"})


class QuorumCommitTest(_HttpBase):
    """达 quorum：票/报告/提交三事件紧邻原子落盘。"""

    def setUp(self):
        super().setUp()
        self._chain_policy()
        self._put_arb(ARBITRATION)
        self._create_op()

    def test_adoption_commits_with_three_adjacent_events(self):
        self.assertEqual(self._observe("s1", _report())[0], 201)
        status, body = self._observe("s2", _report())
        self.assertEqual(status, 201)
        self.assertEqual(body, {"state": "adopted"})
        status, asset = self.srv.request("GET", "/v1/wallets/w1/assets/btc")
        self.assertEqual(status, 200)
        self.assertEqual((asset["balance"], asset["version"]), (100, 1))
        events = self._events()
        types = [e["type"] for e in events]
        commits = [t for t in types if t == "asset_operation_committed"]
        self.assertEqual(len(commits), 1)
        commit_at = types.index("asset_operation_committed")
        self.assertEqual(types[commit_at - 1], "chain_report")
        self.assertEqual(types[commit_at - 2], "chain_vote")
        self.assertEqual(
            events[commit_at - 2]["details"],
            {"source": "s2", "report": _report(), "state": "adopted"},
        )
        self.assertEqual(events[commit_at - 1]["details"], _report())
        self.assertEqual(events[commit_at]["request_id"], "op1")

    def test_report_endpoint_gated_while_arbitration_enabled(self):
        # pending 操作的链上报告一律 409
        status, _ = self.srv.request(
            "POST", "/v1/wallets/w1/chain/op1/report", _report()
        )
        self.assertEqual(status, 409)
        # 经仲裁提交后同体报告重放仍 200（committed 终态）
        self._observe("s1", _report())
        self._observe("s2", _report())
        status, _ = self.srv.request(
            "POST", "/v1/wallets/w1/chain/op1/report", _report()
        )
        self.assertEqual(status, 200)

    def test_new_vote_after_adoption_returns_409(self):
        self._observe("s1", _report())
        self._observe("s2", _report())  # adopted
        # 启用 s3 后再投也不接受（终态）
        status, _ = self._observe("s3", _report())
        self.assertEqual(status, 409)

    def test_insufficient_balance_does_not_record_deciding_vote(self):
        self._create_op("op2", "btc", -50)
        self.assertEqual(self._observe("s1", _report(), operation="op2")[0], 201)
        status, _ = self._observe("s2", _report(), operation="op2")
        self.assertEqual(status, 409)
        votes = [
            e
            for e in self._events()
            if _is_vote_event(e) and e["request_id"] == "op2"
        ]
        self.assertEqual([v["details"]["source"] for v in votes], ["s1"])
        # 先经仲裁提交充值 op1（+100），再重试 op2 s2 即可 adopted
        self._observe("s1", _report())
        self._observe("s2", _report())  # op1 adopted, balance 100
        status, body = self._observe("s2", _report(), operation="op2")
        self.assertEqual(status, 201)
        self.assertEqual(body, {"state": "adopted"})
        status, asset = self.srv.request("GET", "/v1/wallets/w1/assets/btc")
        self.assertEqual((asset["balance"], asset["version"]), (50, 2))


class ObserveConcurrencyTest(_HttpBase):
    """并发首票/决定性票恰一个 201；提交恰一次。"""

    def setUp(self):
        super().setUp()
        self._chain_policy()
        self._put_arb(ARBITRATION)
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

    def test_concurrent_first_votes_only_one_201(self):
        results = self._run_concurrent(lambda: self._observe("s1", _report()))
        statuses = sorted(status for status, _ in results)
        self.assertEqual(statuses, [200] * 7 + [201])
        votes = [e for e in self._events() if _is_vote_event(e)]
        self.assertEqual(len(votes), 1)

    def test_concurrent_deciding_votes_commit_exactly_once(self):
        self._observe("s1", _report())
        results = self._run_concurrent(lambda: self._observe("s2", _report()))
        statuses = sorted(status for status, _ in results)
        self.assertEqual(statuses, [200] * 7 + [201])
        events = self._events()
        commits = [
            e for e in events if e["type"] == "asset_operation_committed"
        ]
        self.assertEqual(len(commits), 1)
        self.assertEqual(
            [e["seq"] for e in events], list(range(1, len(events) + 1))
        )


class ArbitrationRestartTest(unittest.TestCase):
    """重启后策略/票/提交现场与幂等保持，seq 连续。"""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmpdir, ignore_errors=True)

    def _service(self):
        return make_harness(self.tmpdir).service

    def test_restart_preserves_policy_votes_and_commit(self):
        service = self._service()
        service.create_wallet("w1", 2)
        service.put_chain_policy("w1", "btc", "bitcoin", True, 2, 1)
        service.put_chain_arbitration(
            "w1", "btc", {"s1": True, "s2": True}, 2
        )
        service.create_asset_operation("w1", "op1", "btc", 100)
        service.create_asset_operation("w1", "op2", "btc", 50)
        service.observe("w1", "op1", {"source": "s1", "report": _report(confirmations=2)})
        service.observe("w1", "op1", {"source": "s2", "report": _report(confirmations=2)})

        service = self._service()
        self.assertEqual(
            service.get_chain_arbitration("w1", "btc"),
            {"sources": {"s1": True, "s2": True}, "quorum": 2},
        )
        # 已 adopted 操作同源同体重放 200
        status, _ = service.observe(
            "w1", "op1", {"source": "s1", "report": _report(confirmations=2)}
        )
        self.assertEqual(status, 200)
        # 另一操作继续 adopted，seq 接续
        service.observe("w1", "op2", {"source": "s1", "report": _report(confirmations=2)})
        status, _ = service.observe(
            "w1", "op2", {"source": "s2", "report": _report(confirmations=2)}
        )
        self.assertEqual(status, 201)
        events = service.get_audit_events("w1")["events"]
        self.assertEqual(
            [e["seq"] for e in events], list(range(1, len(events) + 1))
        )
        self.assertEqual(
            service.get_asset("w1", "btc"),
            {"asset_id": "btc", "balance": 150, "version": 2},
        )


class ArbitrationCorruptionTest(unittest.TestCase):
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
        self.srv.request("PUT", "/v1/wallets/w1/chain/btc", CHAIN_POLICY)
        self.srv.request(
            "PUT",
            "/v1/wallets/w1/chain/btc/arbitration",
            ARBITRATION,
        )
        self.srv.request(
            "POST",
            "/v1/wallets/w1/asset-operations",
            {"operation_id": "op1", "asset_id": "btc", "delta": 100},
        )

    def _audit_path(self):
        return os.path.join(self.tmpdir, "audit", "w1.json")

    def _read_log(self):
        with open(self._audit_path(), encoding="utf-8") as f:
            return json.load(f)

    def _write_log(self, log):
        with open(self._audit_path(), "w", encoding="utf-8") as f:
            json.dump(log, f)

    def _expect_503_and_not_ready(self):
        status, _ = self.srv.request(
            "GET", "/v1/wallets/w1/chain/btc/arbitration"
        )
        self.assertEqual(status, 503)
        status, _ = self.srv.request(
            "POST",
            "/v1/wallets/w1/chain/op1/observe",
            {"source": "s1", "report": _report()},
        )
        self.assertEqual(status, 503)
        with self.assertRaises(RecoveryError):
            WalletService(WalletStore(self.tmpdir))

    def test_malformed_arbitration_event(self):
        log = self._read_log()
        log["events"][1]["details"] = {"quorum": 2}
        self._write_log(log)
        self._expect_503_and_not_ready()

    def test_malformed_vote_event(self):
        self.srv.request(
            "POST",
            "/v1/wallets/w1/chain/op1/observe",
            {"source": "s1", "report": _report()},
        )
        log = self._read_log()
        log["events"][2]["details"] = {"source": "s1"}
        self._write_log(log)
        self._expect_503_and_not_ready()

    def test_vote_for_unknown_operation(self):
        audit = AuditStore(self.tmpdir)
        audit.append_event(
            "w1",
            {
                "type": "chain_vote",
                "at": "2026-09-25T00:00:00Z",
                "request_id": "ghost",
                "actor_id": None,
                "reason": None,
                "details": {
                    "source": "s1",
                    "report": _report(),
                    "state": "collecting",
                },
            },
        )
        self._expect_503_and_not_ready()

    def test_vote_from_disabled_source(self):
        audit = AuditStore(self.tmpdir)
        audit.append_event(
            "w1",
            {
                "type": "chain_vote",
                "at": "2026-09-25T00:00:00Z",
                "request_id": "op1",
                "actor_id": None,
                "reason": None,
                "details": {
                    "source": "s3",
                    "report": _report(),
                    "state": "collecting",
                },
            },
        )
        self._expect_503_and_not_ready()

    def test_orphan_adopted_vote_is_contradiction(self):
        audit = AuditStore(self.tmpdir)
        for source in ("s1", "s2"):
            state = "collecting" if source == "s1" else "adopted"
            audit.append_event(
                "w1",
                {
                    "type": "chain_vote",
                    "at": "2026-09-25T00:00:00Z",
                    "request_id": "op1",
                    "actor_id": None,
                    "reason": None,
                    "details": {
                        "source": source,
                        "report": _report(),
                        "state": state,
                    },
                },
            )
        self._expect_503_and_not_ready()

    def test_malformed_new_policy_event_is_contradiction(self):
        # 新形策略事件也是 chain_vote（details {sources,quorum}）：
        # details 残缺（缺 sources）即畸形事件，fail-closed。
        audit = AuditStore(self.tmpdir)
        audit.append_event(
            "w1",
            {
                "type": "chain_vote",
                "at": "2026-09-25T00:00:00Z",
                "request_id": "btc",
                "actor_id": None,
                "reason": None,
                "details": {"quorum": 2},
            },
        )
        self._expect_503_and_not_ready()

    def test_new_policy_event_with_bad_value_is_contradiction(self):
        audit = AuditStore(self.tmpdir)
        audit.append_event(
            "w1",
            {
                "type": "chain_vote",
                "at": "2026-09-25T00:00:00Z",
                "request_id": "btc",
                "actor_id": None,
                "reason": None,
                "details": {"sources": {"s1": True}, "quorum": 2},
            },
        )
        self._expect_503_and_not_ready()

    def test_chain_vote_event_with_unrecognized_keys_is_contradiction(self):
        # 键集既非策略也非票的 chain_vote 不得被静默忽略
        audit = AuditStore(self.tmpdir)
        audit.append_event(
            "w1",
            {
                "type": "chain_vote",
                "at": "2026-09-25T00:00:00Z",
                "request_id": "op1",
                "actor_id": None,
                "reason": None,
                "details": {"source": "s1", "report": _report()},
            },
        )
        self._expect_503_and_not_ready()

    def test_duplicate_source_votes_are_contradiction(self):
        audit = AuditStore(self.tmpdir)
        for _ in range(2):
            audit.append_event(
                "w1",
                {
                    "type": "chain_vote",
                    "at": "2026-09-25T00:00:00Z",
                    "request_id": "op1",
                    "actor_id": None,
                    "reason": None,
                    "details": {
                        "source": "s1",
                        "report": _report(),
                        "state": "collecting",
                    },
                },
            )
        self._expect_503_and_not_ready()

    def test_wrong_vote_state_is_contradiction(self):
        # s1、s2 同体两票本应达 quorum=2 -> adopted；票上却写
        # collecting，状态机矛盾，fail-closed。
        audit = AuditStore(self.tmpdir)
        for source in ("s1", "s2"):
            audit.append_event(
                "w1",
                {
                    "type": "chain_vote",
                    "at": "2026-09-25T00:00:00Z",
                    "request_id": "op1",
                    "actor_id": None,
                    "reason": None,
                    "details": {
                        "source": source,
                        "report": _report(),
                        "state": "collecting",
                    },
                },
            )
        self._expect_503_and_not_ready()

    def test_vote_after_adopted_is_contradiction(self):
        # 先在线合法达成 adopted（账本与三事件提交点一致），再篡改追加
        # 一张终态后的新源票（先追加启用 s3 的新策略，使其不因"停用源"
        # 而提前失败）：终态后新增票即矛盾，fail-closed。
        self.assertEqual(
            self.srv.request(
                "POST",
                "/v1/wallets/w1/chain/op1/observe",
                {"source": "s1", "report": _report()},
            )[0],
            201,
        )
        self.assertEqual(
            self.srv.request(
                "POST",
                "/v1/wallets/w1/chain/op1/observe",
                {"source": "s2", "report": _report()},
            )[0],
            201,
        )
        audit = AuditStore(self.tmpdir)
        audit.append_event(
            "w1",
            {
                "type": "chain_vote",
                "at": "2026-09-25T00:00:00Z",
                "request_id": "btc",
                "actor_id": None,
                "reason": None,
                "details": {
                    "sources": {"s1": True, "s2": True, "s3": True},
                    "quorum": 2,
                },
            },
        )
        audit.append_event(
            "w1",
            {
                "type": "chain_vote",
                "at": "2026-09-25T00:00:00Z",
                "request_id": "op1",
                "actor_id": None,
                "reason": None,
                "details": {
                    "source": "s3",
                    "report": _report(),
                    "state": "collecting",
                },
            },
        )
        self._expect_503_and_not_ready()

    def test_corrupt_audit_json_is_corrupt_data_error(self):
        # 审计 JSON 损坏（不可解析）：存储层异常类型为 CorruptDataError，
        # HTTP 统一为 JSON 503，serve 拒绝就绪（由 _expect 复用），现场
        # 原样保留。
        with open(self._audit_path(), "w", encoding="utf-8") as f:
            f.write("{broken")
        with self.assertRaises(CorruptDataError):
            AuditStore(self.tmpdir).check_log("w1")
        self._expect_503_and_not_ready()
        # 现场保留：损坏字节不被归一/覆盖
        with open(self._audit_path(), encoding="utf-8") as f:
            self.assertEqual(f.read(), "{broken")

    def test_missing_ledger_with_residual_vote_is_503(self):
        # 审计残留票事件但账本文件被删：持锁访问（GET 策略/observe/
        # report）都须重放"票->操作"并对未知操作票 fail-closed 为 503，
        # 绝不把操作当未知（404）后继续。
        self.srv.request(
            "POST",
            "/v1/wallets/w1/chain/op1/observe",
            {"source": "s1", "report": _report()},
        )
        os.remove(os.path.join(self.tmpdir, "assets", "w1.json"))
        status, body = self.srv.request(
            "GET", "/v1/wallets/w1/chain/btc/arbitration"
        )
        self.assertEqual(status, 503)
        self.assertEqual(body, {"error": "service temporarily unavailable"})
        status, _ = self.srv.request(
            "POST",
            "/v1/wallets/w1/chain/op1/observe",
            {"source": "s2", "report": _report()},
        )
        self.assertEqual(status, 503)
        status, _ = self.srv.request(
            "POST", "/v1/wallets/w1/chain/op1/report", _report()
        )
        self.assertEqual(status, 503)
        with self.assertRaises(RecoveryError):
            WalletService(WalletStore(self.tmpdir))


class ArbitrationCrashConvergenceTest(unittest.TestCase):
    """崩溃原子性：决定性票/报告/提交三事件同批落盘。"""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmpdir, ignore_errors=True)

    def _service(self):
        return make_harness(self.tmpdir).service

    def _setup(self):
        service = self._service()
        service.create_wallet("w1", 2)
        service.put_chain_policy("w1", "btc", "bitcoin", True, 2, 1)
        service.put_chain_arbitration(
            "w1", "btc", {"s1": True, "s2": True}, 2
        )
        service.create_asset_operation("w1", "op1", "btc", 100)
        return service

    def _intent(self, vote):
        return {
            "operation_id": "op1",
            "asset_id": "btc",
            "delta": 100,
            "old_asset": None,
            "pending": {
                "operation_id": "op1",
                "asset_id": "btc",
                "state": "pending",
                "delta": 100,
                "balance": 0,
                "version": 0,
            },
            "new_balance": 100,
            "new_version": 1,
            "report": _report(confirmations=2),
            "vote": vote,
        }

    def test_crash_before_triple_append_rolls_back(self):
        service = self._setup()
        service.observe(
            "w1", "op1", {"source": "s1", "report": _report(confirmations=2)}
        )
        vote = {"source": "s2", "report": _report(confirmations=2), "state": "adopted"}
        service._store.write_asset_commit_intent(
            "w1", "op1", self._intent(vote)
        )
        service._store.commit_asset_operation(
            "w1",
            "op1",
            {
                "operation_id": "op1",
                "asset_id": "btc",
                "state": "committed",
                "delta": 100,
                "balance": 100,
                "version": 1,
            },
            "btc",
            {"balance": 100, "version": 1},
        )
        service = self._service()  # 三事件未落盘 -> 回滚
        self.assertEqual(
            service._store.get_asset_operation("w1", "op1")["state"],
            "pending",
        )
        self.assertEqual(service._store.list_asset_intents("w1"), [])
        events = service.get_audit_events("w1")["events"]
        # 策略事件与 s1 观察票同为 chain_vote，按 details 键集区分
        self.assertEqual(
            [e["type"] for e in events],
            ["chain_policy", "chain_vote", "chain_vote"],
        )
        self.assertTrue(_is_policy_event(events[1]))
        self.assertTrue(_is_vote_event(events[2]))
        # 重试：三事件紧邻一次提交
        status, body = service.observe(
            "w1", "op1", {"source": "s2", "report": _report(confirmations=2)}
        )
        self.assertEqual(status, 201)
        self.assertEqual(body, {"state": "adopted"})
        events = service.get_audit_events("w1")["events"]
        self.assertEqual(
            [e["type"] for e in events],
            [
                "chain_policy",
                "chain_vote",
                "chain_vote",
                "chain_vote",
                "chain_report",
                "asset_operation_committed",
            ],
        )
        # 语义依次为：策略、s1 收集票、s2 决定性 adopted 票
        self.assertTrue(_is_policy_event(events[1]))
        self.assertTrue(_is_vote_event(events[2]))
        self.assertTrue(_is_vote_event(events[3]))
        self.assertEqual(events[3]["details"]["state"], "adopted")

    def test_triple_append_failure_rolls_back_without_events(self):
        service = self._setup()
        service.observe(
            "w1", "op1", {"source": "s1", "report": _report(confirmations=2)}
        )
        with mock.patch(
            "threshold_wallet.audit._atomic_write_log",
            side_effect=OSError("disk full"),
        ):
            with self.assertRaises(OSError):
                service.observe(
                    "w1", "op1",
                    {"source": "s2", "report": _report(confirmations=2)},
                )
        events = service.get_audit_events("w1")["events"]
        # 策略事件与 s1 观察票同为 chain_vote，按 details 键集区分
        self.assertEqual(
            [e["type"] for e in events],
            ["chain_policy", "chain_vote", "chain_vote"],
        )
        self.assertTrue(_is_policy_event(events[1]))
        self.assertTrue(_is_vote_event(events[2]))
        # 重试成功
        status, _ = service.observe(
            "w1", "op1", {"source": "s2", "report": _report(confirmations=2)}
        )
        self.assertEqual(status, 201)


class LegacyChainArbitrationCompatTest(unittest.TestCase):
    """合法旧 chain_arbitration 策略事件仅只读兼容。"""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmpdir, ignore_errors=True)

    def _service(self):
        return make_harness(self.tmpdir).service

    def _append_legacy_policy(self, service, asset="btc",
                              sources=None, quorum=2):
        AuditStore(self.tmpdir).append_event(
            "w1",
            {
                "type": "chain_arbitration",
                "at": "2026-09-25T00:00:00Z",
                "request_id": asset,
                "actor_id": None,
                "reason": None,
                "details": {
                    "sources": sources
                    or {"s1": True, "s2": True},
                    "quorum": quorum,
                },
            },
        )

    def test_legacy_policy_is_read_by_get(self):
        service = self._service()
        service.create_wallet("w1", 2)
        service.put_chain_policy("w1", "btc", "bitcoin", True, 2, 1)
        self._append_legacy_policy(service)
        self.assertEqual(
            service.get_chain_arbitration("w1", "btc"),
            {"sources": {"s1": True, "s2": True}, "quorum": 2},
        )

    def test_legacy_policy_drives_observe_and_restart(self):
        service = self._service()
        service.create_wallet("w1", 2)
        service.put_chain_policy("w1", "btc", "bitcoin", True, 2, 1)
        self._append_legacy_policy(service)
        service.create_asset_operation("w1", "op1", "btc", 100)
        status, _ = service.observe(
            "w1", "op1",
            {"source": "s1", "report": _report(confirmations=2)},
        )
        self.assertEqual(status, 201)
        service = self._service()  # 重放不报错
        status, body = service.observe(
            "w1", "op1",
            {"source": "s2", "report": _report(confirmations=2)},
        )
        self.assertEqual((status, body), (201, {"state": "adopted"}))
        # 旧事件原样保留，不被改写成新类型，不新增策略事件
        events = service.get_audit_events("w1")["events"]
        self.assertEqual(
            [e["type"] for e in events[:2]],
            ["chain_policy", "chain_arbitration"],
        )

    def test_new_policy_event_overrides_legacy_by_seq(self):
        service = self._service()
        service.create_wallet("w1", 2)
        service.put_chain_policy("w1", "btc", "bitcoin", True, 2, 1)
        self._append_legacy_policy(
            service, sources={"s1": True, "s2": True, "s3": False}
        )
        # 新形 chain_vote 策略事件在其后，按 seq 取最后一条
        service.put_chain_arbitration(
            "w1", "btc", {"s1": True, "s2": True, "s3": True}, 3
        )
        self.assertEqual(
            service.get_chain_arbitration("w1", "btc"),
            {"sources": {"s1": True, "s2": True, "s3": True}, "quorum": 3},
        )
        events = service.get_audit_events("w1")["events"]
        self.assertEqual(events[1]["type"], "chain_arbitration")
        self.assertTrue(_is_policy_event(events[2]))

    def test_malformed_legacy_event_fails_closed(self):
        service = self._service()
        service.create_wallet("w1", 2)
        AuditStore(self.tmpdir).append_event(
            "w1",
            {
                "type": "chain_arbitration",
                "at": "2026-09-25T00:00:00Z",
                "request_id": "btc",
                "actor_id": None,
                "reason": None,
                "details": {"sources": {"s1": True}, "quorum": 2},
            },
        )
        with self.assertRaises(RecoveryError):
            WalletService(WalletStore(self.tmpdir))


class ArbitrationHttpOsErrorBoundaryTest(_HttpBase):
    """文件系统失败：PUT/GET/observe 统一 JSON 503，不新增事件/改状态。"""

    def setUp(self):
        super().setUp()
        self._chain_policy()
        self._put_arb(ARBITRATION)
        self._create_op()

    def test_get_arbitration_oserror_is_json_503(self):
        with mock.patch.object(
            AuditStore, "all_events", side_effect=OSError("disk dead")
        ):
            status, body = self._get_arb()
        self.assertEqual(status, 503)
        self.assertEqual(body, {"error": "service temporarily unavailable"})

    def test_observe_oserror_is_json_503_without_events(self):
        before = self._events()
        with mock.patch(
            "threshold_wallet.audit._atomic_write_log",
            side_effect=OSError("disk full"),
        ):
            status, body = self._observe("s1", _report())
        self.assertEqual(status, 503)
        self.assertEqual(body, {"error": "service temporarily unavailable"})
        # 不新增事件、不改 seq
        after = self._events()
        self.assertEqual(
            [e["seq"] for e in after], [e["seq"] for e in before]
        )
        self.assertEqual(len(after), len(before))

    def test_put_arbitration_oserror_is_json_503(self):
        # 对尚无 pending 操作的资产配策略时写盘失败 -> 503，无事件
        before = self._events()
        with mock.patch(
            "threshold_wallet.audit._atomic_write_log",
            side_effect=OSError("disk full"),
        ):
            status, body = self._put_arb(
                {"sources": {"s1": True, "s2": True}, "quorum": 2},
                asset="eth",
            )
        self.assertEqual(status, 503)
        self.assertEqual(body, {"error": "service temporarily unavailable"})
        after = self._events()
        self.assertEqual(len(after), len(before))


class ArbitrationDrBackupTest(unittest.TestCase):
    """灾备 backup/restore：策略、票与提交现场不变，不新增审计事件。"""

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
        service.put_chain_arbitration(
            "w1", "btc", {"s1": True, "s2": True}, 2
        )
        service.create_asset_operation("w1", "op1", "btc", 100)
        service.create_asset_operation("w1", "op2", "btc", 50)
        service.observe(
            "w1", "op1", {"source": "s1", "report": _report(confirmations=2)}
        )
        service.observe(
            "w1", "op1", {"source": "s2", "report": _report(confirmations=2)}
        )
        before = service.get_audit_events("w1")["events"]

        body = drbackup.backup(self.src, "w1", "S1", self.out)
        self.assertEqual(body["status"], 201)
        status, _ = drbackup.restore(self.dst, "w1", self.out)
        self.assertEqual(status, 201)

        restored = make_harness(self.dst).service
        self.assertEqual(
            restored.get_chain_arbitration("w1", "btc"),
            {"sources": {"s1": True, "s2": True}, "quorum": 2},
        )
        after = restored.get_audit_events("w1")["events"]
        self.assertEqual(
            [e["seq"] for e in after], [e["seq"] for e in before]
        )
        self.assertEqual(len(after), len(before))
        status, _ = restored.observe(
            "w1", "op2", {"source": "s1", "report": _report(confirmations=2)}
        )
        self.assertEqual(status, 201)
        status, _ = restored.observe(
            "w1", "op2", {"source": "s2", "report": _report(confirmations=2)}
        )
        self.assertEqual(status, 201)
        self.assertEqual(
            restored.get_asset("w1", "btc"),
            {"asset_id": "btc", "balance": 150, "version": 2},
        )


if __name__ == "__main__":
    unittest.main()
