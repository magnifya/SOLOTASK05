"""历史资产状态查询：GET /assets/{asset_id}?at_seq=N[&expected_head=H]。

覆盖：
- at_seq 缺省时响应与错误语义完全保持现状（{asset_id,balance,version}）；
- 历史响应恰含 asset_id/balance/version/at_seq/head，head 与
  audit-evidence 同 to_seq 的 end_head 相同；
- 余额/版本仅从边界内该资产最后一条 asset_operation_committed 事件 R
  得出；pending、cancelled、幂等重放不改变结果；不同资产分别计算；
- 边界可落在任意事件（含别的资产、策略、冻结事件）上；边界落在同批
  报告/投票/结算事件但未包含提交事件时按落账前状态回答（404 或旧值）；
- 人工提交、链上确认、多源仲裁、派发结算与重组补偿五类提交点；
- 边界前无已提交操作 404（不以当前/零余额代替）；边界超审计尾 404；
- at_seq/expected_head 的空值/非法/重复/缺 at_seq 400；expected_head
  不符 409；钱包 404 先于参数 400；非法标识 400；
- 冻结钱包/资产可查询；查询纯只读（无事件、无意图、链与账本不变）；
- 重启（新进程视图）与灾备恢复后同一边界结果一致；
- 审计链损坏时 503 通用文案、不返回部分结果；响应与日志不含密钥材料。
"""

from __future__ import annotations

import json
import shutil
import tempfile
import unittest

from tests.helpers import http_server, make_harness

TX1 = "ab" * 32
BH1 = "01" * 32
BH2 = "02" * 32


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

    def _create(self, operation_id, asset_id, delta, wallet="w1"):
        status, body = self.srv.request(
            "POST",
            f"/v1/wallets/{wallet}/asset-operations",
            {
                "operation_id": operation_id,
                "asset_id": asset_id,
                "delta": delta,
            },
        )
        assert status == 201, body
        return body

    def _commit(self, operation_id, wallet="w1"):
        return self.srv.request(
            "POST",
            f"/v1/wallets/{wallet}/asset-operations/"
            f"{operation_id}/commit",
        )

    def _asset(self, asset_id, query="", wallet="w1"):
        suffix = f"?{query}" if query else ""
        return self.srv.request(
            "GET", f"/v1/wallets/{wallet}/assets/{asset_id}{suffix}"
        )

    def _events(self, wallet="w1"):
        status, body = self.srv.request(
            "GET", f"/v1/wallets/{wallet}/audit-events"
        )
        assert status == 200, body
        return body["events"]

    def _committed_seqs(self, asset_id=None, wallet="w1"):
        return [
            event["seq"]
            for event in self._events(wallet)
            if event["type"] == "asset_operation_committed"
            and (asset_id is None
                 or event["details"]["asset_id"] == asset_id)
        ]

    def _head_at(self, seq, wallet="w1"):
        status, body = self.srv.request(
            "GET",
            f"/v1/wallets/{wallet}/audit-evidence"
            f"?from_seq=1&to_seq={seq}",
        )
        assert status == 200, body
        return body["end_head"]


class CurrentStateUnchangedTest(_HttpBase):
    """无 at_seq：响应与错误语义保持现状。"""

    def test_no_params_returns_three_keys(self):
        self._create("op1", "btc", 100)
        self._commit("op1")
        status, body = self._asset("btc")
        self.assertEqual(status, 200)
        self.assertEqual(set(body), {"asset_id", "balance", "version"})
        self.assertEqual(
            body,
            {"asset_id": "btc", "balance": 100, "version": 1},
        )

    def test_no_committed_operation_is_404(self):
        self._create("op1", "btc", 100)
        status, body = self._asset("btc")
        self.assertEqual(status, 404)
        self.assertEqual(body, {"error": "asset 'btc' not found"})

    def test_missing_wallet_is_404(self):
        status, _ = self.srv.request(
            "GET", "/v1/wallets/nope/assets/btc"
        )
        self.assertEqual(status, 404)

    def test_invalid_asset_id_is_400(self):
        status, _ = self._asset("bad$id")
        self.assertEqual(status, 400)

    def test_unknown_query_params_remain_ignored(self):
        self._create("op1", "btc", 100)
        self._commit("op1")
        status, body = self._asset("btc", "foo=bar")
        self.assertEqual(status, 200)
        self.assertEqual(set(body), {"asset_id", "balance", "version"})


class ManualCommitHistoryTest(_HttpBase):
    """人工提交序列上的历史余额/版本/链头。"""

    def _setup_two_assets(self):
        self._create("a1", "btc", 100)
        self._create("a2", "btc", 25)
        self._create("e1", "eth", 7)
        self._commit("a1")
        self._commit("a2")
        self._commit("e1")

    def test_history_shape_is_strict(self):
        self._create("a1", "btc", 100)
        status, r = self._commit("a1")
        seq = self._committed_seqs("btc")[0]
        status, body = self._asset("btc", f"at_seq={seq}")
        self.assertEqual(status, 200)
        self.assertEqual(
            list(body),
            ["asset_id", "balance", "version", "at_seq", "head"],
        )
        self.assertEqual(body["at_seq"], seq)
        self.assertEqual(body["balance"], r["balance"])
        self.assertEqual(body["version"], r["version"])
        self.assertRegex(body["head"], r"^[0-9a-f]{64}$")

    def test_balance_version_track_last_committed_in_prefix(self):
        self._setup_two_assets()
        btc_seqs = self._committed_seqs("btc")
        eth_seqs = self._committed_seqs("eth")
        status, first = self._asset("btc", f"at_seq={btc_seqs[0]}")
        self.assertEqual(status, 200)
        self.assertEqual((first["balance"], first["version"]), (100, 1))
        status, second = self._asset("btc", f"at_seq={btc_seqs[1]}")
        self.assertEqual((second["balance"], second["version"]), (125, 2))
        # 边界在别的资产事件上：btc 仍取自己最后一条提交
        status, third = self._asset("btc", f"at_seq={eth_seqs[0]}")
        self.assertEqual(status, 200)
        self.assertEqual((third["balance"], third["version"]), (125, 2))

    def test_head_equals_evidence_end_head(self):
        self._setup_two_assets()
        for seq in self._committed_seqs():
            status, body = self._asset("btc", f"at_seq={seq}")
            self.assertEqual(status, 200)
            self.assertEqual(body["head"], self._head_at(seq))

    def test_assets_are_computed_independently(self):
        self._setup_two_assets()
        btc_seqs = self._committed_seqs("btc")
        eth_seqs = self._committed_seqs("eth")
        # eth 提交前，任意边界上 eth 均 404（含 btc 的提交事件边界）
        status, _ = self._asset("eth", f"at_seq={btc_seqs[0]}")
        self.assertEqual(status, 404)
        status, _ = self._asset("eth", f"at_seq={btc_seqs[1]}")
        self.assertEqual(status, 404)
        status, body = self._asset("eth", f"at_seq={eth_seqs[0]}")
        self.assertEqual(status, 200)
        self.assertEqual((body["balance"], body["version"]), (7, 1))

    def test_pending_cancelled_and_replay_do_not_change_history(self):
        self._create("a1", "btc", 100)
        self._commit("a1")
        # 再来一笔 pending：历史与当前都不计数
        self._create("p1", "btc", 5)
        seq_tail = self._events()[-1]["seq"]
        status, body = self._asset("btc", f"at_seq={seq_tail}")
        self.assertEqual((body["balance"], body["version"]), (100, 1))
        # committed 重放不记事件、不改历史
        status, _ = self._commit("a1")
        self.assertEqual(status, 200)
        status, body = self._asset("btc", f"at_seq={seq_tail}")
        self.assertEqual((body["balance"], body["version"]), (100, 1))
        self.assertEqual(body["head"], self._head_at(seq_tail))

    def test_negative_delta_is_reflected(self):
        self._create("in", "btc", 100)
        self._commit("in")
        self._create("out", "btc", -30)
        self._commit("out")
        seqs = self._committed_seqs("btc")
        status, body = self._asset("btc", f"at_seq={seqs[-1]}")
        self.assertEqual(status, 200)
        self.assertEqual((body["balance"], body["version"]), (70, 2))

    def test_boundary_before_any_commit_is_404(self):
        # 仅一条与资产无关的事件（链策略事件）：边界落在其上仍 404
        self.srv.request(
            "PUT",
            "/v1/wallets/w1/chain/btc",
            {
                "chain_id": "bitcoin",
                "enabled": True,
                "required_confirmations": 3,
                "reorg_window": 2,
            },
        )
        tail = self._events()[-1]["seq"]
        status, _ = self._asset("btc", f"at_seq={tail}")
        self.assertEqual(status, 404)
        # 零余额绝不代替
        status, body = self._asset("btc", f"at_seq={tail}")
        self.assertNotIn("balance", body)


class ParameterValidationTest(_HttpBase):
    """at_seq / expected_head 参数校验与错误次序。"""

    def test_404_wallet_precedes_param_validation(self):
        for query in (
            "at_seq=0",
            "at_seq=",
            "at_seq=abc",
            "expected_head=" + "a" * 64,
            "at_seq=1&at_seq=2",
        ):
            status, _ = self.srv.request(
                "GET", f"/v1/wallets/nope/assets/btc?{query}"
            )
            self.assertEqual(status, 404, query)

    def test_invalid_at_seq_values_are_400(self):
        bad_values = [
            "0",
            "-1",
            "1.0",
            "1e1",
            "%201",
            "1%20",
            "",
            "abc",
            "0x1",
            "%2B1",
        ]
        for value in bad_values:
            with self.subTest(value=value):
                status, body = self._asset("btc", f"at_seq={value}")
                self.assertEqual(status, 400, value)
                self.assertEqual(body["error"], "invalid at_seq", value)
        # 全角数字（Unicode digit，非 ASCII）：百分号编码后仍是非 ASCII
        # 数字码点，正则只放行 ASCII 数字 -> 400
        status, body = self._asset(
            "btc", "at_seq=" + "%EF%BC%91"
        )
        self.assertEqual(status, 400)
        self.assertEqual(body["error"], "invalid at_seq")

    def test_huge_numeric_value_is_404_not_400(self):
        # 超过 Python int 字符串转换上限的纯数字串：形状仍是合法正
        # 整数，越尾 -> 404，而不是被转换异常误判为 400/503
        self._create("a1", "btc", 100)
        self._commit("a1")
        status, body = self._asset("btc", f"at_seq={'9' * 5000}")
        self.assertEqual(status, 404)
        self.assertEqual(body["error"], "at_seq beyond the audit tail")

    def test_all_zeros_are_400_even_with_leading_zeros(self):
        for value in ("0", "00", "0000"):
            status, body = self._asset("btc", f"at_seq={value}")
            self.assertEqual(status, 400, value)
            self.assertEqual(body["error"], "invalid at_seq", value)

    def test_leading_zeros_accepted_as_positive_integer(self):
        self._create("a1", "btc", 100)
        self._commit("a1")
        status, body = self._asset("btc", "at_seq=01")
        self.assertEqual(status, 200)
        self.assertEqual(body["at_seq"], 1)

    def test_duplicate_params_are_400(self):
        status, body = self._asset("btc", "at_seq=1&at_seq=2")
        self.assertEqual(status, 400)
        self.assertEqual(body["error"], "duplicate at_seq parameters")
        status, body = self._asset(
            "btc", f"at_seq=1&expected_head={'a'*64}"
            f"&expected_head={'b'*64}"
        )
        self.assertEqual(status, 400)
        self.assertEqual(
            body["error"], "duplicate expected_head parameters"
        )

    def test_expected_head_without_at_seq_is_400(self):
        # 格式合法但缺 at_seq
        status, body = self._asset("btc", f"expected_head={'a'*64}")
        self.assertEqual(status, 400)
        self.assertEqual(body["error"], "invalid at_seq")

    def test_expected_head_bad_format_is_400(self):
        for value in ("", "zz", "a" * 63, "A" * 64, "g" * 64, "12"):
            with self.subTest(value=value):
                status, body = self._asset(
                    "btc", f"at_seq=1&expected_head={value}"
                )
                self.assertEqual(status, 400, value)
                self.assertEqual(
                    body["error"], "invalid expected_head", value
                )

    def test_boundary_beyond_tail_is_404_not_400(self):
        # 空钱包：at_seq=1 超尾（尾为 0）
        status, body = self._asset("btc", "at_seq=1")
        self.assertEqual(status, 404)
        self.assertEqual(body["error"], "at_seq beyond the audit tail")
        self._create("a1", "btc", 100)
        self._commit("a1")
        tail = self._events()[-1]["seq"]
        status, body = self._asset("btc", f"at_seq={tail + 1}")
        self.assertEqual(status, 404)
        self.assertEqual(body["error"], "at_seq beyond the audit tail")

    def test_beyond_tail_404_precedes_head_mismatch_409(self):
        self._create("a1", "btc", 100)
        self._commit("a1")
        tail = self._events()[-1]["seq"]
        status, _ = self._asset(
            "btc", f"at_seq={tail + 1}&expected_head={'a'*64}"
        )
        self.assertEqual(status, 404)

    def test_expected_head_match_returns_200(self):
        self._create("a1", "btc", 100)
        self._commit("a1")
        seq = self._committed_seqs("btc")[0]
        head = self._head_at(seq)
        status, body = self._asset(
            "btc", f"at_seq={seq}&expected_head={head}"
        )
        self.assertEqual(status, 200)
        self.assertEqual(body["head"], head)

    def test_expected_head_mismatch_is_409(self):
        self._create("a1", "btc", 100)
        self._commit("a1")
        seq = self._committed_seqs("btc")[0]
        status, body = self._asset(
            "btc", f"at_seq={seq}&expected_head={'a'*64}"
        )
        self.assertEqual(status, 409)
        self.assertEqual(
            body["error"], "expected_head does not match chain head"
        )

    def test_404_asset_precedes_409(self):
        self._create("a1", "btc", 100)
        self._commit("a1")
        seq = self._committed_seqs("btc")[0]
        status, _ = self._asset(
            "eth", f"at_seq={seq}&expected_head={'a'*64}"
        )
        self.assertEqual(status, 404)

    def test_invalid_asset_id_with_at_seq_is_400(self):
        status, _ = self._asset("bad$id", "at_seq=1")
        self.assertEqual(status, 400)


class FreezeAndReadOnlyTest(_HttpBase):
    """冻结钱包/资产仍可查；历史查询纯只读。"""

    def test_frozen_wallet_history_still_readable(self):
        self._create("a1", "btc", 100)
        self._commit("a1")
        seq = self._committed_seqs("btc")[0]
        status, _ = self.srv.request(
            "POST",
            "/v1/wallets/w1/freeze",
            {"reason": "incident"},
        )
        self.assertEqual(status, 201)
        status, body = self._asset("btc", f"at_seq={seq}")
        self.assertEqual(status, 200)
        self.assertEqual((body["balance"], body["version"]), (100, 1))
        # 当前余额查询在冻结下也保持可用
        status, _ = self._asset("btc")
        self.assertEqual(status, 200)

    def test_frozen_asset_history_still_readable(self):
        self._create("a1", "btc", 100)
        self._commit("a1")
        seq = self._committed_seqs("btc")[0]
        status, _ = self.srv.request(
            "POST",
            "/v1/wallets/w1/assets/btc/freeze",
            {"reason": "asset incident"},
        )
        self.assertEqual(status, 201)
        status, body = self._asset("btc", f"at_seq={seq}")
        self.assertEqual(status, 200)
        self.assertEqual((body["balance"], body["version"]), (100, 1))

    def test_history_query_appends_no_events_or_intents(self):
        self._create("a1", "btc", 100)
        self._commit("a1")
        seq = self._committed_seqs("btc")[0]
        before = self._events()
        for query in (
            f"at_seq={seq}",
            f"at_seq={seq}&expected_head={self._head_at(seq)}",
            f"at_seq={seq + 1}",
        ):
            self._asset("btc", query)
        after = self._events()
        self.assertEqual(before, after)
        # 当前余额、版本与链头不变
        status, integ = self.srv.request(
            "GET", "/v1/wallets/w1/audit-integrity"
        )
        self.assertEqual(status, 200)
        self.assertEqual(integ["count"], len(after))

    def test_boundary_on_unrelated_freeze_event(self):
        self._create("a1", "btc", 100)
        self._commit("a1")
        status, _ = self.srv.request(
            "POST",
            "/v1/wallets/w1/freeze",
            {"reason": "incident"},
        )
        self.assertEqual(status, 201)
        freeze_seq = self._events()[-1]["seq"]
        # 边界落在冻结事件上：链头推进，但余额仍是提交后状态
        status, body = self._asset("btc", f"at_seq={freeze_seq}")
        self.assertEqual(status, 200)
        self.assertEqual((body["balance"], body["version"]), (100, 1))
        self.assertEqual(body["head"], self._head_at(freeze_seq))

    def test_no_private_material_in_response_or_logs(self):
        self._create("a1", "btc", 100)
        self._commit("a1")
        seq = self._committed_seqs("btc")[0]
        status, raw = self.srv.request(
            "GET", f"/v1/wallets/w1/assets/btc?at_seq={seq}"
        )
        self.assertEqual(status, 200)
        text = json.dumps(raw)
        self.assertNotIn("private_key", text)
        self.assertNotIn("share", text)


class ChainConfirmationHistoryTest(_HttpBase):
    """链上确认达门槛：报告事件与提交事件同批，边界取到报告未取提交。"""

    POLICY = {
        "chain_id": "bitcoin",
        "enabled": True,
        "required_confirmations": 3,
        "reorg_window": 2,
    }

    def _report(self, operation_id, confirmations, tx_id=TX1,
                height=100, block_hash=BH1):
        return self.srv.request(
            "POST",
            f"/v1/wallets/w1/chain/{operation_id}/report",
            {
                "chain_id": "bitcoin",
                "tx_id": tx_id,
                "block_height": height,
                "block_hash": block_hash,
                "confirmations": confirmations,
            },
        )

    def test_batch_boundary_before_commit_is_pre_landing(self):
        self.srv.request(
            "PUT", "/v1/wallets/w1/chain/btc", self.POLICY
        )
        self._create("op1", "btc", 100)
        # 每个新确认数都首报 201（各记一条 chain_report）
        status, _ = self._report("op1", 1)
        self.assertEqual(status, 201)
        status, _ = self._report("op1", 2)
        self.assertEqual(status, 201)
        status, _ = self._report("op1", 3)
        self.assertEqual(status, 201)
        events = self._events()
        report_seqs = [
            e["seq"] for e in events if e["type"] == "chain_report"
        ]
        commit_seqs = [
            e["seq"] for e in events
            if e["type"] == "asset_operation_committed"
        ]
        self.assertEqual(len(commit_seqs), 1)
        self.assertEqual(commit_seqs[0], report_seqs[-1] + 1)
        # 边界落在达门槛报告事件（提交事件紧邻其后但不在边界内）：
        # 按落账前状态回答 -> 404，绝不把同批提交计入
        status, _ = self._asset("btc", f"at_seq={report_seqs[-1]}")
        self.assertEqual(status, 404)
        # 边界含提交事件：落账后状态
        status, body = self._asset("btc", f"at_seq={commit_seqs[0]}")
        self.assertEqual(status, 200)
        self.assertEqual((body["balance"], body["version"]), (100, 1))
        self.assertEqual(body["head"], self._head_at(commit_seqs[0]))


class ArbitrationHistoryTest(_HttpBase):
    """多源仲裁达 quorum：vote + report + committed 三事件同批。"""

    CHAIN_POLICY = {
        "chain_id": "bitcoin",
        "enabled": True,
        "required_confirmations": 3,
        "reorg_window": 2,
    }
    ARBITRATION = {
        "sources": {"s1": True, "s2": True, "s3": False},
        "quorum": 2,
    }

    @staticmethod
    def _report(confirmations=3):
        return {
            "chain_id": "bitcoin",
            "tx_id": TX1,
            "block_height": 100,
            "block_hash": BH1,
            "confirmations": confirmations,
        }

    def _observe(self, source, operation="op1"):
        return self.srv.request(
            "POST",
            f"/v1/wallets/w1/chain/{operation}/observe",
            {"source": source, "report": self._report()},
        )

    def test_quorum_batch_boundary_semantics(self):
        self.srv.request(
            "PUT", "/v1/wallets/w1/chain/btc", self.CHAIN_POLICY
        )
        self.srv.request(
            "PUT",
            "/v1/wallets/w1/chain/btc/arbitration",
            self.ARBITRATION,
        )
        self._create("op1", "btc", 100)
        status, _ = self._observe("s1")
        self.assertEqual(status, 201)
        # 一票不足 quorum：未落账
        tail = self._events()[-1]["seq"]
        status, _ = self._asset("btc", f"at_seq={tail}")
        self.assertEqual(status, 404)
        status, _ = self._observe("s2")
        self.assertEqual(status, 201)
        events = self._events()
        commit_seq = [
            e["seq"] for e in events
            if e["type"] == "asset_operation_committed"
        ][-1]
        votes = [
            e["seq"] for e in events
            if e["type"] == "chain_vote"
            and set(e["details"]) == {"source", "report", "state"}
        ]
        reports = [
            e["seq"] for e in events if e["type"] == "chain_report"
        ]
        # 决定性票、报告、提交三事件同批连续，提交收尾
        self.assertEqual(votes[-1], commit_seq - 2)
        self.assertEqual(reports[-1], commit_seq - 1)
        # 边界落在报告事件（未含提交）：落账前 404
        status, _ = self._asset("btc", f"at_seq={commit_seq - 1}")
        self.assertEqual(status, 404)
        # 边界含提交：落账
        status, body = self._asset("btc", f"at_seq={commit_seq}")
        self.assertEqual(status, 200)
        self.assertEqual((body["balance"], body["version"]), (100, 1))
        # 同源重放不改变历史
        status, _ = self._observe("s1")
        self.assertEqual(status, 200)
        status, body = self._asset("btc", f"at_seq={commit_seq}")
        self.assertEqual((body["balance"], body["version"]), (100, 1))


class SettleAndReorgHistoryTest(unittest.TestCase):
    """派发最终性结算与重组补偿：服务层装配场景。"""

    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.d, ignore_errors=True)
        self.h = make_harness(self.d)
        self.svc = self.h.service

    def _build_settled(self, delta=100):
        self.svc.create_wallet("w1", 2)
        self.svc.put_policy("w1", 1, 600)
        code, _ = self.svc.create_asset_operation("w1", "op1", "BTC", delta)
        self.assertEqual(code, 201)
        self.svc.put_chain_policy("w1", "BTC", "chain-1", True, 3, 2)
        code, _ = self.svc.create_sign_request("w1", "ap1", _dispatch_msg())
        self.assertEqual(code, 201)
        self.svc.approve("w1", "ap1", "boss")
        code, _ = self.svc.post_chain_dispatch("w1", "op1", "dp1", "ad1",
                                               "ap1")
        self.assertEqual(code, 201)
        code, _ = self.svc.post_chain_dispatch_result(
            "w1", "dp1", "ad1", "broadcasted", TX1
        )
        self.assertEqual(code, 201)
        code, _ = self.svc.post_chain_dispatch_confirmation(
            "w1", "dp1", "ad1", TX1, 10, BH1, 3
        )
        self.assertEqual(code, 201)
        code, r = self.svc.settle_chain_dispatch("w1", "dp1")
        self.assertEqual(code, 201)
        return r

    def _events(self):
        return self.svc.get_audit_events("w1")["events"]

    def test_settle_boundary_before_commit_is_pre_landing(self):
        self._build_settled()
        events = self._events()
        settled = [
            e for e in events
            if e["type"] == "chain_dispatch_settled"
        ][-1]
        committed = [
            e for e in events
            if e["type"] == "asset_operation_committed"
        ][-1]
        self.assertEqual(committed["seq"], settled["seq"] + 1)
        # 边界在结算事件、未含提交：404
        from threshold_wallet.service import ServiceError
        with self.assertRaises(ServiceError) as ctx:
            self.svc.get_asset("w1", "BTC", at_seq=str(settled["seq"]))
        self.assertEqual(ctx.exception.status, 404)
        result = self.svc.get_asset(
            "w1", "BTC", at_seq=str(committed["seq"])
        )
        self.assertEqual((result["balance"], result["version"]), (100, 1))
        self.assertEqual(result["at_seq"], committed["seq"])
        # head 与 evidence 一致
        evidence = self.svc.get_audit_evidence(
            "w1", ["1"], [str(committed["seq"])]
        )
        self.assertEqual(result["head"], evidence["end_head"])

    def test_reorg_compensation_counted_once(self):
        from threshold_wallet.service import ServiceError
        self._build_settled(delta=100)
        # 重组：回退区块报告 -> 补偿操作（反向 delta）三事件同批
        status, _ = self.svc.post_chain_dispatch_confirmation(
            "w1", "dp1", "ad1", TX1, 9, BH2, 1
        )
        self.assertEqual(status, 201)
        events = self._events()
        by_type = {}
        for event in events:
            by_type.setdefault(event["type"], []).append(event)
        reorged = by_type["chain_dispatch_reorged"][-1]
        compensation = by_type["asset_operation_committed"][-1]
        self.assertEqual(compensation["details"]["delta"], -100)
        self.assertEqual(compensation["details"]["balance"], 0)
        self.assertEqual(compensation["details"]["version"], 2)
        self.assertEqual(reorged["seq"] + 1, compensation["seq"])
        # 边界在重组事件、未含补偿提交：仍为结算后 100/v1
        result = self.svc.get_asset(
            "w1", "BTC", at_seq=str(reorged["seq"])
        )
        self.assertEqual((result["balance"], result["version"]), (100, 1))
        # 边界含补偿提交：0/v2
        result = self.svc.get_asset(
            "w1", "BTC", at_seq=str(compensation["seq"])
        )
        self.assertEqual((result["balance"], result["version"]), (0, 2))
        evidence = self.svc.get_audit_evidence(
            "w1", ["1"], [str(compensation["seq"])]
        )
        self.assertEqual(result["head"], evidence["end_head"])
        # 边界超尾 404
        with self.assertRaises(ServiceError) as ctx:
            self.svc.get_asset(
                "w1", "BTC", at_seq=str(compensation["seq"] + 1)
            )
        self.assertEqual(ctx.exception.status, 404)


class RestartAndRecoveryConsistencyTest(unittest.TestCase):
    """重启（新进程视图）与灾备恢复后历史结果一致。"""

    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.d, ignore_errors=True)
        self.h = make_harness(self.d)
        self.svc = self.h.service

    def _build(self):
        self.svc.create_wallet("w1", 2)
        code, _ = self.svc.create_asset_operation("w1", "a1", "btc", 100)
        self.assertEqual(code, 201)
        code, _ = self.svc.commit_asset_operation("w1", "a1")
        self.assertEqual(code, 201)
        code, _ = self.svc.create_asset_operation("w1", "a2", "btc", 25)
        self.assertEqual(code, 201)
        code, _ = self.svc.commit_asset_operation("w1", "a2")
        self.assertEqual(code, 201)
        code, _ = self.svc.create_asset_operation("w1", "e1", "eth", 7)
        self.assertEqual(code, 201)
        code, _ = self.svc.commit_asset_operation("w1", "e1")
        self.assertEqual(code, 201)

    def test_history_stable_across_restart(self):
        self._build()
        committed = [
            event["seq"]
            for event in self.svc.get_audit_events("w1")["events"]
            if event["type"] == "asset_operation_committed"
        ]
        expected = {
            seq: self.svc.get_asset("w1", "btc", at_seq=str(seq))
            for seq in committed
        }
        h2 = make_harness(self.d)
        for seq, want in expected.items():
            got = h2.service.get_asset("w1", "btc", at_seq=str(seq))
            self.assertEqual(got, want)
            evidence = h2.service.get_audit_evidence(
                "w1", ["1"], [str(seq)]
            )
            self.assertEqual(got["head"], evidence["end_head"])

    def test_history_stable_after_dr_restore(self):
        from threshold_wallet import drbackup
        self._build()
        committed = [
            event["seq"]
            for event in self.svc.get_audit_events("w1")["events"]
            if event["type"] == "asset_operation_committed"
        ]
        expected = {
            seq: self.svc.get_asset("w1", "btc", at_seq=str(seq))
            for seq in committed
        }
        snap = tempfile.NamedTemporaryFile(
            prefix="snap-", suffix=".tar", delete=False
        )
        snap.close()
        self.addCleanup(shutil.rmtree, snap.name, ignore_errors=True)
        drbackup.backup(self.d, "w1", "snap1", snap.name)
        d2 = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d2, ignore_errors=True)
        status, _ = drbackup.restore(d2, "w1", snap.name)
        self.assertEqual(status, 201)
        h2 = make_harness(d2)
        for seq, want in expected.items():
            got = h2.service.get_asset("w1", "btc", at_seq=str(seq))
            self.assertEqual(got, want)

    def test_later_operations_do_not_change_old_boundary(self):
        self._build()
        first = 1
        before = self.svc.get_asset("w1", "btc", at_seq=str(first))
        # 后续多笔提交与策略/冻结事件
        code, _ = self.svc.create_asset_operation("w1", "a3", "btc", -5)
        self.assertEqual(code, 201)
        code, _ = self.svc.commit_asset_operation("w1", "a3")
        self.assertEqual(code, 201)
        self.svc.freeze_asset("w1", "btc", "asset freeze")
        after = self.svc.get_asset("w1", "btc", at_seq=str(first))
        self.assertEqual(after, before)


class CorruptAuditHistoryTest(_HttpBase):
    """历史查询在审计链不可对账时 fail-closed 503。"""

    def test_tampered_chain_head_returns_503(self):
        import os
        self._create("a1", "btc", 100)
        self._commit("a1")
        seq = self._committed_seqs("btc")[0]
        path = os.path.join(self.tmpdir, "audit", "w1.json")
        with open(path, encoding="utf-8") as handle:
            data = json.load(handle)
        data["chain"]["head"] = "a" * 64
        with open(path, "w", encoding="utf-8") as handle:
            json.dump(data, handle)
        status, body = self._asset("btc", f"at_seq={seq}")
        self.assertEqual(status, 503)
        self.assertEqual(body["error"], "service temporarily unavailable")
        # 当前余额查询同样 fail-closed
        status, body = self._asset("btc")
        self.assertEqual(status, 503)
        self.assertEqual(body["error"], "service temporarily unavailable")

    def test_missing_chain_metadata_returns_503(self):
        import os
        self._create("a1", "btc", 100)
        self._commit("a1")
        seq = self._committed_seqs("btc")[0]
        path = os.path.join(self.tmpdir, "audit", "w1.json")
        with open(path, encoding="utf-8") as handle:
            data = json.load(handle)
        del data["chain"]
        with open(path, "w", encoding="utf-8") as handle:
            json.dump(data, handle)
        status, body = self._asset("btc", f"at_seq={seq}")
        self.assertEqual(status, 503)
        self.assertEqual(body["error"], "service temporarily unavailable")
