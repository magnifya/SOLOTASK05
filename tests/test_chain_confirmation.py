"""跨链资产确认测试。

覆盖：
- PUT/GET /v1/wallets/{W}/chain/{A}：键集/值校验（chain_id 安全标识、
  enabled 布尔、required_confirmations 非布尔正整数、reorg_window 非布尔
  非负，四整数拒 bool）、路径/体 chain_id 一致、GET 无策 404、同值 PUT 也
  记 chain_policy 事件（request_id=A、details=Q、seq 连续、重启保持）；
- POST /v1/wallets/{W}/chain/{O}/report：首提 201、同体重放 200，同块
  确认数不降，换块仅 pending 且高度回退 ≤ reorg_window（可降确认数），
  链/tx/越界/终态冲突 409，未知钱包/操作 404，策略缺失或停用 409；
- 达门槛按既有 commit 契约提交一次：chain_report 事件后紧邻唯一
  asset_operation_committed 事件，余额不足不落报告，启用时原 commit 对
  pending 为 409，停用后原 commit 恢复；
- 并发/重启/灾备收敛、seq 连续；链事件形状/语义损坏 fail-closed（503、
  serve 拒绝就绪）；backup/restore 兼容新事件类型。
"""

from __future__ import annotations

import json
import os
import shutil
import tempfile
import unittest

from tests.helpers import http_server, make_harness
from threshold_wallet import drbackup
from threshold_wallet.service import ServiceError, WalletService
from threshold_wallet.store import RecoveryError, WalletStore

HEX32_TX = "a" * 64
HEX32_B1 = "b" * 64
HEX32_B2 = "c" * 64
Q = {
    "chain_id": "eth",
    "enabled": True,
    "required_confirmations": 3,
    "reorg_window": 5,
}


def _report_body(confirmations=1, *, height=100, block_hash=HEX32_B1,
                 chain_id="eth", tx_id=HEX32_TX):
    return {
        "chain_id": chain_id,
        "tx_id": tx_id,
        "block_height": height,
        "block_hash": block_hash,
        "confirmations": confirmations,
    }


class ChainPolicyHttpTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self._ctx = http_server(self.tmp)
        self.srv = self._ctx.__enter__()
        self.addCleanup(self._ctx.__exit__, None, None, None)
        self.assertEqual(
            self.srv.request(
                "POST", "/v1/wallets", {"wallet_id": "w1", "shares": 2}
            )[0],
            201,
        )

    def _put(self, chain, body, wallet="w1"):
        return self.srv.request(
            "PUT", f"/v1/wallets/{wallet}/chain/{chain}", body
        )

    def _get(self, chain, wallet="w1"):
        return self.srv.request(
            "GET", f"/v1/wallets/{wallet}/chain/{chain}"
        )

    def test_put_get_200_same_body(self):
        self.assertEqual(self._put("eth", Q)[0:], (200, Q))
        self.assertEqual(self._get("eth"), (200, Q))

    def test_get_unknown_policy_404_wallet_404(self):
        self.assertEqual(self._get("eth")[0], 404)
        self.assertEqual(self._get("eth", wallet="ghost")[0], 404)
        self.assertEqual(self._put("eth", Q, wallet="ghost")[0], 404)

    def test_path_chain_id_invalid_400(self):
        self.assertEqual(self._put("bad-chain$", Q)[0], 400)
        self.assertEqual(self._get("bad$")[0], 400)

    def test_body_chain_id_must_match_path(self):
        body = dict(Q, chain_id="btc")
        self.assertEqual(self._put("eth", body)[0], 400)
        self.assertEqual(self._get("eth")[0], 404)

    def test_key_set_must_be_exact(self):
        for body in (
            {k: v for k, v in Q.items() if k != "reorg_window"},
            dict(Q, extra=1),
            {},
        ):
            self.assertEqual(self._put("eth", body)[0], 400, body)

    def test_value_validation(self):
        bad = [
            dict(Q, enabled="yes"),
            dict(Q, enabled=1),
            dict(Q, required_confirmations=0),
            dict(Q, required_confirmations=-1),
            dict(Q, required_confirmations=True),
            dict(Q, required_confirmations=1.5),
            dict(Q, required_confirmations="3"),
            dict(Q, reorg_window=-1),
            dict(Q, reorg_window=True),
            dict(Q, reorg_window=1.0),
            dict(Q, chain_id="bad id"),
            dict(Q, chain_id=7),
        ]
        for body in bad:
            self.assertEqual(self._put("eth", body)[0], 400, body)

    def test_zero_reorg_window_allowed_boundary(self):
        body = dict(Q, reorg_window=0)
        self.assertEqual(self._put("eth", body), (200, body))
        self.assertEqual(self._get("eth"), (200, body))


class ChainPolicyEventTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)

    def _events(self, srv):
        return srv.request("GET", "/v1/wallets/w1/audit-events")[1]["events"]

    def test_same_value_put_records_event_and_persists(self):
        with http_server(self.tmp) as srv:
            srv.request("POST", "/v1/wallets", {"wallet_id": "w1", "shares": 2})
            for _ in range(2):
                self.assertEqual(
                    srv.request("PUT", "/v1/wallets/w1/chain/eth", Q)[0], 200
                )
            events = self._events(srv)
            self.assertEqual([e["type"] for e in events],
                             ["chain_policy", "chain_policy"])
            self.assertEqual([e["seq"] for e in events], [1, 2])
            for e in events:
                self.assertEqual(e["request_id"], "eth")
                self.assertIsNone(e["actor_id"])
                self.assertIsNone(e["reason"])
                self.assertEqual(e["details"], Q)
        # 重启后 GET 取最后一条，seq 接续不重号
        with http_server(self.tmp) as srv:
            self.assertEqual(
                srv.request("GET", "/v1/wallets/w1/chain/eth"), (200, Q)
            )
            srv.request("PUT", "/v1/wallets/w1/chain/eth", Q)
            seq = [e["seq"] for e in self._events(srv)]
            self.assertEqual(seq, [1, 2, 3])

    def test_latest_policy_wins_on_restart(self):
        with http_server(self.tmp) as srv:
            srv.request("POST", "/v1/wallets", {"wallet_id": "w1", "shares": 2})
            srv.request("PUT", "/v1/wallets/w1/chain/eth", Q)
            disabled = dict(Q, enabled=False, reorg_window=9)
            srv.request("PUT", "/v1/wallets/w1/chain/eth", disabled)
        with http_server(self.tmp) as srv:
            self.assertEqual(
                srv.request("GET", "/v1/wallets/w1/chain/eth"),
                (200, dict(Q, enabled=False, reorg_window=9)),
            )


class ChainReportHttpTest(unittest.TestCase):
    """HTTP 路由、请求体键集与端到端状态码。"""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self._ctx = http_server(self.tmp)
        self.srv = self._ctx.__enter__()
        self.addCleanup(self._ctx.__exit__, None, None, None)
        self.srv.request("POST", "/v1/wallets", {"wallet_id": "w1", "shares": 2})
        self.assertEqual(
            self.srv.request("PUT", "/v1/wallets/w1/chain/eth", Q)[0], 200
        )
        self.srv.request(
            "POST", "/v1/wallets/w1/asset-operations",
            {"operation_id": "op1", "asset_id": "btc", "delta": 10},
        )

    def _report(self, body):
        return self.srv.request(
            "POST", "/v1/wallets/w1/chain/op1/report", body
        )

    def test_report_key_set_exact(self):
        body = _report_body()
        for bad in (
            {k: v for k, v in body.items() if k != "tx_id"},
            dict(body, extra=1),
            {},
        ):
            self.assertEqual(self._report(bad)[0], 400, bad)

    def test_report_lifecycle_over_http(self):
        body = _report_body(confirmations=1)
        self.assertEqual(self._report(body), (201, body))
        # 同体重放 200
        self.assertEqual(self._report(body), (200, body))
        # 越界换块 409
        bad = _report_body(confirmations=1, height=90, block_hash="d" * 64)
        self.assertEqual(self._report(bad)[0], 409)
        # 达门槛提交
        settled = _report_body(confirmations=3)
        self.assertEqual(self._report(settled), (201, settled))
        # 紧邻事件
        events = self.srv.request(
            "GET", "/v1/wallets/w1/audit-events"
        )[1]["events"]
        seq = [(e["type"], e["request_id"]) for e in events[-2:]]
        self.assertEqual(
            seq,
            [("chain_report", "op1"),
             ("asset_operation_committed", "op1")],
        )
        self.assertEqual(
            self.srv.request("GET", "/v1/wallets/w1/assets/btc")[1]["balance"],
            10,
        )
        # 未知操作 404
        self.assertEqual(
            self.srv.request(
                "POST", "/v1/wallets/w1/chain/ghost/report", _report_body()
            )[0],
            404,
        )


class ChainReportFlowTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.h = make_harness(self.tmp)
        self.svc = self.h.service
        self.svc.create_wallet("w1", 2)
        self.svc.put_chain_policy(
            "w1", "eth", Q["chain_id"], Q["enabled"],
            Q["required_confirmations"], Q["reorg_window"],
        )
        self.svc.create_asset_operation("w1", "op1", "btc", 10)

    def _post(self, body, operation_id="op1"):
        return self.svc.post_chain_report(
            "w1", operation_id, body["chain_id"], body["tx_id"],
            body["block_height"], body["block_hash"], body["confirmations"],
        )

    def _report(self, operation_id="op1", **overrides):
        return self._post(_report_body(**overrides), operation_id)

    def test_first_201_replay_200(self):
        self.assertEqual(self._report()[0], 201)
        self.assertEqual(self._report(), (200, _report_body(1)))

    def test_unknown_wallet_and_operation_404(self):
        body = _report_body()
        with self.assertRaises(ServiceError) as cm:
            self.svc.post_chain_report(
                "ghost", "op1", body["chain_id"], body["tx_id"],
                body["block_height"], body["block_hash"],
                body["confirmations"],
            )
        self.assertEqual(cm.exception.status, 404)
        with self.assertRaises(ServiceError) as cm:
            self._report(operation_id="nope")
        self.assertEqual(cm.exception.status, 404)

    def test_bad_values_400(self):
        bad = [
            dict(chain_id="bad id"),
            dict(tx_id="zz" * 32),
            dict(tx_id="aa" * 31),
            dict(block_hash="AA" * 32),
            dict(height=-1),
            dict(height=True),
            dict(confirmations=-1),
            dict(confirmations=False),
        ]
        for kw in bad:
            with self.assertRaises(ServiceError) as cm:
                self._report(**kw)
            self.assertEqual(cm.exception.status, 400, kw)

    def test_missing_or_disabled_policy_409(self):
        body = _report_body(chain_id="btc")
        with self.assertRaises(ServiceError) as cm:
            self.svc.post_chain_report(
                "w1", "op1", body["chain_id"], body["tx_id"],
                body["block_height"], body["block_hash"],
                body["confirmations"],
            )
        self.assertEqual(cm.exception.status, 409)
        # 停用后首报也 409
        self.svc.put_chain_policy("w1", "eth", "eth", False, 3, 5)
        with self.assertRaises(ServiceError) as cm:
            self._report()
        self.assertEqual(cm.exception.status, 409)

    def test_same_block_confirmations_must_not_decrease(self):
        self._report(confirmations=2)
        with self.assertRaises(ServiceError) as cm:
            self._report(confirmations=1)
        self.assertEqual(cm.exception.status, 409)
        # 同块不同高度也冲突
        with self.assertRaises(ServiceError) as cm:
            self._report(confirmations=2, height=101)
        self.assertEqual(cm.exception.status, 409)
        # 同块确认数持平/上升允许
        self.assertEqual(self._report(confirmations=2)[0], 200)
        self.assertEqual(self._report(confirmations=3)[0], 201)

    def test_block_change_requires_pending_and_respects_window(self):
        self._report(confirmations=2, height=100)
        # 回退恰在窗口边界（100-5=95）允许，且可降确认数
        status, _ = self._report(
            confirmations=1, height=95, block_hash=HEX32_B2
        )
        self.assertEqual(status, 201)
        # 再回退超出窗口 409
        with self.assertRaises(ServiceError) as cm:
            self._report(confirmations=1, height=89, block_hash="d" * 64)
        self.assertEqual(cm.exception.status, 409)
        # 高度上升（回退为负）也允许
        status, _ = self._report(
            confirmations=2, height=96, block_hash="e" * 64
        )
        self.assertEqual(status, 201)

    def test_chain_and_tx_conflict_409(self):
        self._report()
        with self.assertRaises(ServiceError) as cm:
            self._report(chain_id="btc")
        self.assertEqual(cm.exception.status, 409)
        with self.assertRaises(ServiceError) as cm:
            self._report(tx_id="f" * 64)
        self.assertEqual(cm.exception.status, 409)

    def test_settle_triggers_single_adjacent_commit(self):
        self._report(confirmations=1)
        self._report(confirmations=2)
        status, body = self._report(confirmations=3)
        self.assertEqual(status, 201)
        self.assertEqual(body["confirmations"], 3)
        # 账本已提交
        self.assertEqual(
            self.svc.get_asset("w1", "btc"),
            {"asset_id": "btc", "balance": 10, "version": 1},
        )
        op = self.svc._store.get_asset_operation("w1", "op1")
        self.assertEqual(op["state"], "committed")
        events = self.svc.get_audit_events("w1")["events"]
        chain = [e for e in events if e["type"] == "chain_report"]
        commits = [e for e in events if e["type"]
                   == "asset_operation_committed"]
        self.assertEqual(len(chain), 3)
        self.assertEqual(len(commits), 1)
        # 报告事件后紧邻唯一提交事件，seq 连续
        self.assertEqual(commits[0]["seq"], chain[-1]["seq"] + 1)
        self.assertEqual(commits[0]["request_id"], "op1")

    def test_settled_operation_rejects_further_reports(self):
        self._report(confirmations=3)
        # 同体（最后一条）仍 200 幂等
        self.assertEqual(self._report(confirmations=3)[0], 200)
        # 异体（同块确认数变化）终态冲突 409
        with self.assertRaises(ServiceError) as cm:
            self._report(confirmations=4)
        self.assertEqual(cm.exception.status, 409)
        # 换块同样 409
        with self.assertRaises(ServiceError) as cm:
            self._report(confirmations=1, height=101, block_hash=HEX32_B2)
        self.assertEqual(cm.exception.status, 409)

    def test_insufficient_balance_does_not_persist_report(self):
        self.svc.create_asset_operation("w1", "op2", "btc", -5)
        # 先给 btc 入账 10 以建立余额，再构造一笔会透支的 pending
        # op1 已占用 +10（未提交不计余额）；直接用 op3 透支
        self.svc.create_asset_operation("w1", "op3", "btc", -100)
        with self.assertRaises(ServiceError) as cm:
            self._report(operation_id="op3", confirmations=3)
        self.assertEqual(cm.exception.status, 409)
        # 报告未落、操作仍 pending、余额未变、无提交意图
        events = [
            e for e in self.svc.get_audit_events("w1")["events"]
            if e.get("request_id") == "op3"
        ]
        self.assertEqual(events, [])
        self.assertEqual(
            self.svc._store.get_asset_operation("w1", "op3")["state"],
            "pending",
        )
        self.assertIsNone(
            self.svc._store.get_asset_commit_intent("w1", "op3")
        )

    def test_direct_commit_409_while_enabled_then_allowed_when_disabled(self):
        self._report(confirmations=1)
        with self.assertRaises(ServiceError) as cm:
            self.svc.commit_asset_operation("w1", "op1")
        self.assertEqual(cm.exception.status, 409)
        # 停用策略后：原 commit 恢复（该操作已有 pending 报告但策略已关）
        self.svc.put_chain_policy("w1", "eth", "eth", False, 3, 5)
        status, record = self.svc.commit_asset_operation("w1", "op1")
        self.assertEqual(status, 201)
        self.assertEqual(record["state"], "committed")

    def test_unbound_operation_still_commits_directly(self):
        # 配了链策略但从未上报的操作不受影响
        self.svc.create_asset_operation("w1", "op9", "btc", 3)
        status, _ = self.svc.commit_asset_operation("w1", "op9")
        self.assertEqual(status, 201)


class ChainReportRestartTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)

    def test_pending_reports_and_policy_survive_restart(self):
        h = make_harness(self.tmp)
        h.service.create_wallet("w1", 2)
        h.service.put_chain_policy("w1", "eth", "eth", True, 3, 5)
        h.service.create_asset_operation("w1", "op1", "btc", 10)
        for c in (1, 2):
            body = _report_body(confirmations=c)
            h.service.post_chain_report(
                "w1", "op1", body["chain_id"], body["tx_id"],
                body["block_height"], body["block_hash"],
                body["confirmations"],
            )
        h2 = make_harness(self.tmp)
        # 重启后继续上报至达门槛，正常提交
        body = _report_body(confirmations=3)
        status, _ = h2.service.post_chain_report(
            "w1", "op1", body["chain_id"], body["tx_id"],
            body["block_height"], body["block_hash"], body["confirmations"],
        )
        self.assertEqual(status, 201)
        seq = [
            e["seq"] for e in h2.service.get_audit_events("w1")["events"]
        ]
        self.assertEqual(seq, list(range(1, len(seq) + 1)))
        self.assertEqual(
            h2.service.get_asset("w1", "btc")["balance"], 10
        )

    def test_concurrent_services_converge_single_commit(self):
        h1 = make_harness(self.tmp)
        h1.service.create_wallet("w1", 2)
        h1.service.put_chain_policy("w1", "eth", "eth", True, 2, 5)
        h1.service.create_asset_operation("w1", "op1", "btc", 10)
        h2 = WalletService(WalletStore(self.tmp), recover=False)
        body = _report_body(confirmations=2)
        r1 = h1.service.post_chain_report(
            "w1", "op1", body["chain_id"], body["tx_id"],
            body["block_height"], body["block_hash"], body["confirmations"],
        )
        # 第二进程同体重放 -> 200，不再提交
        r2 = h2.post_chain_report(
            "w1", "op1", body["chain_id"], body["tx_id"],
            body["block_height"], body["block_hash"], body["confirmations"],
        )
        self.assertEqual(r1[0], 201)
        self.assertEqual(r2[0], 200)
        commits = [
            e for e in h1.service.get_audit_events("w1")["events"]
            if e["type"] == "asset_operation_committed"
        ]
        self.assertEqual(len(commits), 1)


class ChainCorruptionTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        h = make_harness(self.tmp)
        h.service.create_wallet("w1", 2)
        h.service.put_chain_policy("w1", "eth", "eth", True, 3, 5)
        h.service.create_asset_operation("w1", "op1", "btc", 10)
        body = _report_body(confirmations=1)
        h.service.post_chain_report(
            "w1", "op1", body["chain_id"], body["tx_id"],
            body["block_height"], body["block_hash"], body["confirmations"],
        )
        self.audit_path = os.path.join(self.tmp, "audit", "w1.json")

    def _load(self):
        with open(self.audit_path, encoding="utf-8") as f:
            return json.load(f)

    def _dump(self, data):
        with open(self.audit_path, "w", encoding="utf-8") as f:
            json.dump(data, f)

    def test_malformed_policy_event_fail_closed(self):
        data = self._load()
        data["events"][0]["details"]["required_confirmations"] = 0
        # 改坏后 next_seq 仍一致，但语义矛盾
        self._dump(data)
        svc = WalletService(WalletStore(self.tmp), recover=False)
        with self.assertRaises(RecoveryError):
            svc.get_chain_policy("w1", "eth")

    def test_malformed_policy_event_http_503(self):
        # 健康服务启动后再损坏审计：链路由的对账须把矛盾映射为 503
        with http_server(self.tmp) as srv:
            self.assertEqual(
                srv.request("GET", "/v1/wallets/w1/chain/eth")[0], 200
            )
            data = self._load()
            data["events"][0]["details"]["reorg_window"] = -1
            self._dump(data)
            status, body = srv.request("GET", "/v1/wallets/w1/chain/eth")
            self.assertEqual(status, 503)
            self.assertEqual(body, {"error": "service temporarily unavailable"})

    def test_commit_not_adjacent_to_threshold_report_fail_closed(self):
        h = make_harness(self.tmp)
        body = _report_body(confirmations=3)
        h.service.post_chain_report(
            "w1", "op1", body["chain_id"], body["tx_id"],
            body["block_height"], body["block_hash"], body["confirmations"],
        )
        data = self._load()
        report_idx = max(
            i for i, e in enumerate(data["events"])
            if e["type"] == "chain_report"
        )
        commit_idx = next(
            i for i, e in enumerate(data["events"])
            if e["type"] == "asset_operation_committed"
        )
        self.assertEqual(commit_idx, report_idx + 1)
        # 在达门槛报告与提交事件之间插入一条（复制的）chain_policy 事件并
        # 整体重排 seq：1..N 仍连续，但报告不再紧邻提交——矛盾现场。
        extra = json.loads(json.dumps(data["events"][0]))
        data["events"].insert(report_idx + 1, extra)
        for i, e in enumerate(data["events"], start=1):
            e["seq"] = i
        data["next_seq"] = len(data["events"]) + 1
        self._dump(data)
        with self.assertRaises(RecoveryError):
            WalletService(WalletStore(self.tmp))
        svc = WalletService(WalletStore(self.tmp), recover=False)
        with self.assertRaises(RecoveryError):
            svc.post_chain_report(
                "w1", "op1", body["chain_id"], body["tx_id"],
                body["block_height"], body["block_hash"],
                body["confirmations"],
            )

    def test_serve_refuses_ready_on_corruption(self):
        data = self._load()
        data["events"][1]["details"]["tx_id"] = "ZZ" * 32  # 非小写 hex
        self._dump(data)
        with self.assertRaises(RecoveryError):
            WalletService(WalletStore(self.tmp))

    def test_direct_commit_while_enabled_with_report_is_contradiction(self):
        # 手工制造：报告未达门槛，但操作已被直提且策略当时启用——重启对账
        # 必须 fail-closed。
        h = make_harness(self.tmp)
        # 停用策略后直提
        h.service.put_chain_policy("w1", "eth", "eth", False, 3, 5)
        h.service.commit_asset_operation("w1", "op1")  # 201
        data = self._load()
        # 把停用事件的 enabled 改回 true（其 seq 早于提交），制造矛盾
        for e in data["events"]:
            if e["type"] == "chain_policy" and e["details"]["enabled"] is False:
                e["details"]["enabled"] = True
        self._dump(data)
        with self.assertRaises(RecoveryError):
            WalletService(WalletStore(self.tmp))


class ChainBackupRestoreTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.data = os.path.join(self.tmp, "data")
        self.data2 = os.path.join(self.tmp, "data2")
        self.out = os.path.join(self.tmp, "b.tar")
        h = make_harness(self.data)
        h.service.create_wallet("w1", 2)
        h.service.put_chain_policy("w1", "eth", "eth", True, 2, 5)
        h.service.create_asset_operation("w1", "op1", "btc", 10)
        body = _report_body(confirmations=1)
        h.service.post_chain_report(
            "w1", "op1", body["chain_id"], body["tx_id"],
            body["block_height"], body["block_hash"], body["confirmations"],
        )

    def test_backup_restore_preserves_chain_scene(self):
        body = drbackup.backup(self.data, "w1", "S1", self.out)
        self.assertEqual(body["status"], 201)
        # 快照里携带含 chain 事件的审计日志
        paths = [f["path"] for f in body["manifest"]["files"]]
        self.assertIn("audit/w1.json", paths)
        status, restored = drbackup.restore(self.data2, "w1", self.out)
        self.assertEqual(status, 201)
        h2 = make_harness(self.data2)
        self.assertEqual(
            h2.service.get_chain_policy("w1", "eth"),
            {
                "chain_id": "eth",
                "enabled": True,
                "required_confirmations": 2,
                "reorg_window": 5,
            },
        )
        # 恢复后可继续上报并达门槛提交
        report = _report_body(confirmations=2)
        st, _ = h2.service.post_chain_report(
            "w1", "op1", report["chain_id"], report["tx_id"],
            report["block_height"], report["block_hash"],
            report["confirmations"],
        )
        self.assertEqual(st, 201)
        self.assertEqual(h2.service.get_asset("w1", "btc")["balance"], 10)

    def test_backup_includes_settled_scene(self):
        # 达门槛提交后的现场也能正常出包/恢复（紧邻事件）
        h = make_harness(self.data)
        report = _report_body(confirmations=2)
        h.service.post_chain_report(
            "w1", "op1", report["chain_id"], report["tx_id"],
            report["block_height"], report["block_hash"],
            report["confirmations"],
        )
        out2 = os.path.join(self.tmp, "b2.tar")
        self.assertEqual(drbackup.backup(self.data, "w1", "S2", out2)["status"], 201)
        self.assertEqual(
            drbackup.restore(os.path.join(self.tmp, "data3"), "w1", out2)[0],
            201,
        )


if __name__ == "__main__":
    unittest.main()
