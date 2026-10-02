"""历史资产状态 GET /v1/wallets/{id}/assets/{asset_id}?at_seq= 回归测试。

覆盖：
- 缺省契约不变：仍返回 {asset_id,balance,version}；at_seq 历史响应仅含
  asset_id、balance、version、at_seq、head 五键；
- 边界重放：人工提交、链上确认（同批 chain_report + 提交）、多源仲裁
  （同批 vote + report + 提交）、派发结算（settled + 提交）、重组补偿
  （confirmation + reorged + 提交）；资产变化从提交事件序号起生效，
  边界落在同批触发事件但未含提交时按落账前状态 404；
- 每笔已提交操作只计一次：committed 重放、pending、cancelled、幂等
  观察/结算重放均不改变边界结果；不同资产分别计算余额与 version，
  head 绑定整个钱包审计前缀，与 audit-evidence 同结束序号 end_head
  相同；
- 400：at_seq 空值/0/负数/小数/布尔/非 ASCII 数字/重复、expected_head
  格式错/重复/缺 at_seq、非法 asset_id；
- 404：钱包不存在（先于参数校验）、边界超过审计尾、边界前无该资产
  已提交操作（含当前已提交但边界前无、零钱包）；
- 409：expected_head 合法但与 head 不符；
- 纯只读：不新增事件/seq/历史状态文件，不改余额/version/摘要链；钱包
  与资产冻结仍可查；后续操作/策略修改不改变同一边界结果；
- 503：审计链或现场损坏，泛化文案、保留现场、无部分结果；
- 重启（新 service 打开同一现场）后同一边界结果一致。
"""

from __future__ import annotations

import json
import os
import shutil
import tempfile
import unittest

from tests.helpers import http_server, make_harness

TX1 = "ab" * 32
TX2 = "cd" * 32
BH1 = "01" * 32
BH2 = "02" * 32


def _audit_path(data_dir: str, wallet_id: str = "w1") -> str:
    return os.path.join(data_dir, "audit", wallet_id + ".json")


def _load_audit(data_dir: str, wallet_id: str = "w1") -> dict:
    with open(_audit_path(data_dir, wallet_id), encoding="utf-8") as f:
        return json.load(f)


def _dump_audit(data_dir: str, data: dict, wallet_id: str = "w1") -> None:
    with open(_audit_path(data_dir, wallet_id), "w", encoding="utf-8") as f:
        json.dump(data, f)


def _msg(operation_id="op1", dispatch_id="dp1", adapter_id="ad1",
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
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self._ctx = http_server(self.tmp)
        self.srv = self._ctx.__enter__()
        self.addCleanup(self._ctx.__exit__, None, None, None)
        status, _ = self.srv.request(
            "POST", "/v1/wallets", {"wallet_id": "w1", "shares": 2}
        )
        self.assertEqual(status, 201)

    def request(self, method, path, body=None):
        return self.srv.request(method, path, body)

    def get_asset(self, asset, tail=""):
        suffix = f"?{tail}" if tail else ""
        return self.request("GET", f"/v1/wallets/w1/assets/{asset}{suffix}")

    def create(self, oid, asset, delta):
        return self.request(
            "POST",
            "/v1/wallets/w1/asset-operations",
            {"operation_id": oid, "asset_id": asset, "delta": delta},
        )

    def commit(self, oid):
        return self.request(
            "POST", f"/v1/wallets/w1/asset-operations/{oid}/commit", None
        )

    def cancel(self, oid, cancel_id="c1", approval_request_id="ap1"):
        return self.request(
            "POST",
            f"/v1/wallets/w1/asset-operations/{oid}/cancel",
            {
                "cancel_id": cancel_id,
                "approval_request_id": approval_request_id,
            },
        )

    def events(self, wallet_id="w1"):
        status, body = self.request(
            "GET", f"/v1/wallets/{wallet_id}/audit-events"
        )
        self.assertEqual(status, 200)
        return body["events"]

    def seq_of(self, event_type, request_id=None, index=-1):
        matched = [
            e
            for e in self.events()
            if e["type"] == event_type
            and (request_id is None or e["request_id"] == request_id)
        ]
        self.assertTrue(matched, (event_type, request_id))
        return matched[index]["seq"]

    def evidence_head(self, to_seq):
        status, body = self.request(
            "GET",
            f"/v1/wallets/w1/audit-evidence?from_seq=1&to_seq={to_seq}",
        )
        self.assertEqual(status, 200, body)
        return body["end_head"]


class HistoryShapeAndReplayTest(_HttpBase):
    """成功形状、人工提交边界与跨资产独立。"""

    def test_default_contract_unchanged(self):
        self.create("op1", "btc", 100)
        self.commit("op1")
        status, body = self.get_asset("btc")
        self.assertEqual(status, 200)
        self.assertEqual(
            body, {"asset_id": "btc", "balance": 100, "version": 1}
        )

    def test_history_envelope_only_five_keys(self):
        self.create("op1", "btc", 100)
        self.commit("op1")
        seq = self.seq_of("asset_operation_committed", "op1")
        status, body = self.get_asset("btc", f"at_seq={seq}")
        self.assertEqual(status, 200, body)
        self.assertEqual(
            set(body),
            {"asset_id", "balance", "version", "at_seq", "head"},
        )
        self.assertEqual(body["asset_id"], "btc")
        self.assertEqual(body["balance"], 100)
        self.assertEqual(body["version"], 1)
        self.assertEqual(body["at_seq"], seq)
        self.assertRegex(body["head"], r"^[0-9a-f]{64}$")

    def test_boundary_before_first_commit_is_404(self):
        # 先放一条不相关事件（审批策略），边界合法但资产尚未落账
        status, _ = self.request(
            "PUT",
            "/v1/wallets/w1/approval-policy",
            {"required_approvals": 1, "timeout_seconds": 600},
        )
        self.assertEqual(status, 200)
        self.create("op1", "btc", 100)
        self.commit("op1")
        seq = self.seq_of("policy_updated")
        status, body = self.get_asset("btc", f"at_seq={seq}")
        self.assertEqual(status, 404)
        self.assertEqual(body["error"], "asset 'btc' not found")

    def test_prefix_balance_versions_accumulate(self):
        self.create("op1", "btc", 100)
        self.commit("op1")
        s1 = self.seq_of("asset_operation_committed", "op1")
        self.create("op2", "btc", -30)
        self.commit("op2")
        s2 = self.seq_of("asset_operation_committed", "op2")
        _, at1 = self.get_asset("btc", f"at_seq={s1}")
        _, at2 = self.get_asset("btc", f"at_seq={s2}")
        self.assertEqual((at1["balance"], at1["version"]), (100, 1))
        self.assertEqual((at2["balance"], at2["version"]), (70, 2))

    def test_assets_computed_independently_share_wallet_head(self):
        self.create("op1", "btc", 100)
        self.commit("op1")
        sb = self.seq_of("asset_operation_committed", "op1")
        self.create("op2", "eth", 5)
        self.commit("op2")
        se = self.seq_of("asset_operation_committed", "op2")
        _, btc = self.get_asset("btc", f"at_seq={se}")
        _, eth = self.get_asset("eth", f"at_seq={se}")
        self.assertEqual((btc["balance"], btc["version"]), (100, 1))
        self.assertEqual((eth["balance"], eth["version"]), (5, 1))
        # head 绑定整个钱包审计前缀：两资产同边界 head 相同
        self.assertEqual(btc["head"], eth["head"])
        self.assertEqual(btc["head"], self.evidence_head(se))

    def test_boundary_on_unrelated_event(self):
        self.create("op1", "btc", 100)
        self.commit("op1")
        # 策略修改事件不属任何资产：边界落在其上时 btc 结果不变
        status, _ = self.request(
            "PUT",
            "/v1/wallets/w1/approval-policy",
            {"required_approvals": 2, "timeout_seconds": 900},
        )
        self.assertEqual(status, 200)
        pseq = self.seq_of("policy_updated", index=-1)
        status, body = self.get_asset("btc", f"at_seq={pseq}")
        self.assertEqual(status, 200)
        self.assertEqual((body["balance"], body["version"]), (100, 1))

    def test_head_equals_audit_evidence_end_head(self):
        self.create("op1", "btc", 100)
        self.commit("op1")
        seq = self.seq_of("asset_operation_committed", "op1")
        _, body = self.get_asset("btc", f"at_seq={seq}")
        self.assertEqual(body["head"], self.evidence_head(seq))


class PendingCancelledReplayTest(_HttpBase):
    """pending/cancelled/幂等重放不改变边界结果。"""

    def test_pending_operation_not_counted(self):
        self.create("op1", "btc", 100)
        self.commit("op1")
        s1 = self.seq_of("asset_operation_committed", "op1")
        self.create("op2", "btc", 50)  # 仅 pending，不记事件
        status, body = self.get_asset("btc", f"at_seq={s1}")
        self.assertEqual(status, 200)
        self.assertEqual((body["balance"], body["version"]), (100, 1))

    def test_committed_replay_not_double_counted(self):
        self.create("op1", "btc", 100)
        status1, first = self.commit("op1")
        status2, second = self.commit("op1")
        self.assertEqual(status1, 201)
        self.assertEqual(status2, 200)
        self.assertEqual(first, second)
        tail = self.events()[-1]["seq"]
        status, body = self.get_asset("btc", f"at_seq={tail}")
        self.assertEqual(status, 200)
        self.assertEqual((body["balance"], body["version"]), (100, 1))
        # 只有一条提交事件
        commits = [
            e for e in self.events() if e["type"] ==
            "asset_operation_committed"
        ]
        self.assertEqual(len(commits), 1)

    def test_cancelled_operation_not_counted(self):
        # 用 service 层构造 approved 审批单后撤销 pending 操作
        svc = self.srv.harness.service
        svc.put_policy("w1", 1, 600)
        svc.create_asset_operation("w1", "op1", "btc", 100)
        svc.commit_asset_operation("w1", "op1")
        svc.create_asset_operation("w1", "op2", "btc", 50)
        message = json.dumps(
            {"operation_id": "op2", "cancel_id": "c1"},
            separators=(",", ":"),
        )
        svc.create_sign_request("w1", "ap1", message)
        svc.approve("w1", "ap1", "boss")
        code, _ = svc.cancel_asset_operation("w1", "op2", "c1", "ap1")
        self.assertEqual(code, 201)
        tail = self.events()[-1]["seq"]
        status, body = self.get_asset("btc", f"at_seq={tail}")
        self.assertEqual(status, 200)
        self.assertEqual((body["balance"], body["version"]), (100, 1))
        # 边界落在取消事件上仍无 op2
        cseq = self.seq_of("asset_operation_cancelled", "c1")
        status, body = self.get_asset("btc", f"at_seq={cseq}")
        self.assertEqual((body["balance"], body["version"]), (100, 1))

    def test_asset_with_only_cancelled_history_404(self):
        svc = self.srv.harness.service
        svc.put_policy("w1", 1, 600)
        svc.create_asset_operation("w1", "opx", "xrp", 9)
        message = json.dumps(
            {"operation_id": "opx", "cancel_id": "cx"},
            separators=(",", ":"),
        )
        svc.create_sign_request("w1", "apx", message)
        svc.approve("w1", "apx", "boss")
        code, _ = svc.cancel_asset_operation("w1", "opx", "cx", "apx")
        self.assertEqual(code, 201)
        tail = self.events()[-1]["seq"]
        status, body = self.get_asset("xrp", f"at_seq={tail}")
        self.assertEqual(status, 404)
        self.assertEqual(body["error"], "asset 'xrp' not found")
        # 当前余额查询同样 404
        status, _ = self.get_asset("xrp")
        self.assertEqual(status, 404)

    def test_later_operations_do_not_change_earlier_boundary(self):
        self.create("op1", "btc", 100)
        self.commit("op1")
        s1 = self.seq_of("asset_operation_committed", "op1")
        _, before = self.get_asset("btc", f"at_seq={s1}")
        self.create("op2", "btc", 200)
        self.commit("op2")
        self.create("op3", "btc", -50)
        self.commit("op3")
        _, after = self.get_asset("btc", f"at_seq={s1}")
        self.assertEqual(before, after)


class ChainCommitHistoryTest(_HttpBase):
    """链上确认 / 多源仲裁 / 派发结算 / 重组补偿的边界语义。"""

    def _report(self, oid, chain_id, tx_id, height, block_hash, confs):
        return self.request(
            "POST",
            f"/v1/wallets/w1/chain/{oid}/report",
            {
                "chain_id": chain_id,
                "tx_id": tx_id,
                "block_height": height,
                "block_hash": block_hash,
                "confirmations": confs,
            },
        )

    def test_chain_confirmation_batch_boundary(self):
        self.create("e1", "eth", 200)
        status, _ = self.request(
            "PUT",
            "/v1/wallets/w1/chain/eth",
            {
                "chain_id": "chain-1",
                "enabled": True,
                "required_confirmations": 2,
                "reorg_window": 2,
            },
        )
        self.assertEqual(status, 200)
        self.assertEqual(self._report(
            "e1", "chain-1", TX1, 10, BH1, 1)[0], 201)
        self.assertEqual(self._report(
            "e1", "chain-1", TX1, 10, BH1, 2)[0], 201)
        report_seq = self.seq_of("chain_report", "e1")
        commit_seq = self.seq_of(
            "asset_operation_committed", "e1")
        self.assertEqual(report_seq + 1, commit_seq)
        # 边界落在报告事件：提交尚未生效 -> 404
        status, body = self.get_asset("eth", f"at_seq={report_seq}")
        self.assertEqual(status, 404, body)
        # 边界落在提交事件：生效
        status, body = self.get_asset("eth", f"at_seq={commit_seq}")
        self.assertEqual(status, 200)
        self.assertEqual((body["balance"], body["version"]), (200, 1))
        # 同体报告重放不改变结果
        self.assertEqual(self._report(
            "e1", "chain-1", TX1, 10, BH1, 2)[0], 200)
        tail = self.events()[-1]["seq"]
        _, body = self.get_asset("eth", f"at_seq={tail}")
        self.assertEqual((body["balance"], body["version"]), (200, 1))

    def test_arbitration_batch_boundary(self):
        svc = self.srv.harness.service
        svc.put_chain_policy("w1", "ltc", "chain-9", True, 1, 2)
        svc.put_chain_arbitration(
            "w1", "ltc", {"s1": True, "s2": True}, 2)
        svc.create_asset_operation("w1", "l1", "ltc", 7)
        report = {
            "chain_id": "chain-9",
            "tx_id": TX1,
            "block_height": 3,
            "block_hash": BH1,
            "confirmations": 1,
        }
        code, first = svc.observe(
            "w1", "l1", {"source": "s1", "report": report})
        self.assertEqual(code, 201)
        self.assertEqual(first["state"], "collecting")
        code, second = svc.observe(
            "w1", "l1", {"source": "s2", "report": report})
        self.assertEqual(code, 201)
        self.assertEqual(second["state"], "adopted")
        events = self.events()
        vote_seq = next(
            e["seq"] for e in events
            if e["type"] == "chain_vote"
            and e.get("details", {}).get("state") == "adopted"
        )
        commit_seq = self.seq_of(
            "asset_operation_committed", "l1")
        self.assertEqual(vote_seq + 2, commit_seq)
        # 边界落在决定性票事件：提交尚未生效 -> 404
        status, _ = self.get_asset("ltc", f"at_seq={vote_seq}")
        self.assertEqual(status, 404)
        # 边界落在中间的报告事件同样未生效
        status, _ = self.get_asset("ltc", f"at_seq={vote_seq + 1}")
        self.assertEqual(status, 404)
        status, body = self.get_asset("ltc", f"at_seq={commit_seq}")
        self.assertEqual(status, 200)
        self.assertEqual((body["balance"], body["version"]), (7, 1))
        # 同源同体重放不记事件、不改结果
        code, replay = svc.observe(
            "w1", "l1", {"source": "s1", "report": report})
        self.assertEqual(code, 200)
        self.assertEqual(replay["state"], "adopted")
        tail = self.events()[-1]["seq"]
        self.assertEqual(tail, commit_seq)

    def _build_settled(self, oid="op1", dp="dp1", asset="BTC",
                       delta=100):
        svc = self.srv.harness.service
        svc.put_policy("w1", 1, 600)
        svc.create_asset_operation("w1", oid, asset, delta)
        svc.put_chain_policy("w1", asset, "chain-1", True, 3, 2)
        svc.create_sign_request(
            "w1", "ap1", _msg(oid, dp, "ad1", "chain-1"))
        svc.approve("w1", "ap1", "boss")
        self.assertEqual(svc.post_chain_dispatch(
            "w1", oid, dp, "ad1", "ap1")[0], 201)
        self.assertEqual(svc.post_chain_dispatch_result(
            "w1", dp, "ad1", "broadcasted", TX1)[0], 201)
        self.assertEqual(svc.post_chain_dispatch_confirmation(
            "w1", dp, "ad1", TX1, 10, BH1, 3)[0], 201)
        self.assertEqual(svc.settle_chain_dispatch("w1", dp)[0], 201)

    def test_settle_batch_boundary_and_replay(self):
        self._build_settled()
        settled_seq = self.seq_of("chain_dispatch_settled", "dp1")
        commit_seq = self.seq_of(
            "asset_operation_committed", "op1")
        self.assertEqual(settled_seq + 1, commit_seq)
        status, _ = self.get_asset("BTC", f"at_seq={settled_seq}")
        self.assertEqual(status, 404)
        status, body = self.get_asset("BTC", f"at_seq={commit_seq}")
        self.assertEqual(status, 200)
        self.assertEqual((body["balance"], body["version"]), (100, 1))
        # settle 重放 200 同体不记事件
        svc = self.srv.harness.service
        self.assertEqual(svc.settle_chain_dispatch("w1", "dp1")[0], 200)
        self.assertEqual(self.events()[-1]["seq"], commit_seq)

    def test_reorg_compensation_boundary(self):
        self._build_settled()
        svc = self.srv.harness.service
        code, v = svc.post_chain_dispatch_confirmation(
            "w1", "dp1", "ad1", TX2, 9, BH2, 1)
        self.assertEqual(code, 201)
        self.assertEqual(v["state"], "reorged")
        events = self.events()
        conf_seq = self.seq_of(
            "chain_dispatch_confirmation", "dp1", index=-1)
        reorged_seq = self.seq_of("chain_dispatch_reorged", "dp1")
        comp_seq = self.seq_of(
            "asset_operation_committed", "dp1")
        self.assertEqual(conf_seq + 1, reorged_seq)
        self.assertEqual(reorged_seq + 1, comp_seq)
        # 补偿提交前：仍是 +100/version 1
        for seq in (conf_seq, reorged_seq):
            status, body = self.get_asset("BTC", f"at_seq={seq}")
            self.assertEqual(status, 200, seq)
            self.assertEqual(
                (body["balance"], body["version"]), (100, 1), seq)
        # 补偿提交后：反向 delta（-100）落账，余额 0、version 2
        status, body = self.get_asset("BTC", f"at_seq={comp_seq}")
        self.assertEqual(status, 200)
        self.assertEqual((body["balance"], body["version"]), (0, 2))


class ParameterValidationTest(_HttpBase):
    """400 参数矩阵。"""

    def setUp(self):
        super().setUp()
        self.create("op1", "btc", 100)
        self.commit("op1")
        self.tail = self.events()[-1]["seq"]

    def _bad(self, tail, expected="at_seq must be a positive integer"):
        status, body = self.get_asset("btc", tail)
        self.assertEqual(status, 400, tail)
        self.assertEqual(body["error"], expected, tail)

    def test_at_seq_invalid_values(self):
        import urllib.parse

        for value in ("", "0", "00", "-1", "1.0", " 1", "1 ", "0x1",
                      "abc", "１", "1e3", "+1", "true"):
            with self.subTest(value=value):
                encoded = urllib.parse.quote(value, safe="")
                self._bad(f"at_seq={encoded}")

    def test_at_seq_duplicate(self):
        self._bad(
            f"at_seq={self.tail}&at_seq={self.tail}",
            "duplicate at_seq parameter",
        )

    def test_expected_head_duplicate(self):
        head = "a" * 64
        self._bad(
            f"at_seq={self.tail}&expected_head={head}&expected_head={head}",
            "duplicate expected_head parameter",
        )

    def test_expected_head_without_at_seq(self):
        self._bad(
            "expected_head=" + "a" * 64,
            "expected_head requires at_seq",
        )

    def test_expected_head_empty_or_malformed(self):
        for value in ("", "zzz", "A" * 64, "a" * 63, "a" * 65, "0x" + "a"*62):
            with self.subTest(value=value):
                self._bad(
                    f"at_seq={self.tail}&expected_head={value}",
                    "expected_head must be 64-char lowercase hex",
                )

    def test_invalid_asset_id_400(self):
        import urllib.parse

        for bad in ("has space", "slash/x", "中文", "x" * 129,
                    "dot.name"):
            with self.subTest(asset=bad):
                encoded = urllib.parse.quote(bad, safe="")
                status, body = self.request(
                    "GET",
                    f"/v1/wallets/w1/assets/{encoded}?at_seq=1",
                )
                self.assertEqual(status, 400, bad)

    def test_ascii_digits_leading_zeros_accepted(self):
        # 仅 ASCII 数字组成的正整数：前导零不改变数值，合法
        status, body = self.get_asset("btc", f"at_seq=000{self.tail}")
        self.assertEqual(status, 200, body)
        self.assertEqual(body["at_seq"], self.tail)


class NotFoundAndConflictTest(_HttpBase):
    """404 / 409 语义。"""

    def test_wallet_not_found_precedes_param_validation(self):
        # 钱包不存在 404，即使 at_seq 非法
        status, body = self.request(
            "GET", "/v1/wallets/ghost/assets/btc?at_seq=notanum"
        )
        self.assertEqual(status, 404)
        self.assertEqual(body["error"], "wallet 'ghost' not found")
        # expected_head 缺 at_seq 也被钱包 404 抢先
        status, _ = self.request(
            "GET",
            "/v1/wallets/ghost/assets/btc?expected_head=" + "a" * 64,
        )
        self.assertEqual(status, 404)

    def test_boundary_beyond_tail_404(self):
        self.create("op1", "btc", 100)
        self.commit("op1")
        tail = self.events()[-1]["seq"]
        for seq in (tail + 1, tail + 100):
            status, body = self.get_asset("btc", f"at_seq={seq}")
            self.assertEqual(status, 404, seq)
            self.assertEqual(body["error"], "at_seq beyond audit tail")

    def test_empty_wallet_boundary_404(self):
        status, _ = self.request(
            "POST", "/v1/wallets", {"wallet_id": "w2", "shares": 2}
        )
        self.assertEqual(status, 201)
        status, body = self.request(
            "GET", "/v1/wallets/w2/assets/btc?at_seq=1"
        )
        self.assertEqual(status, 404)
        self.assertEqual(body["error"], "at_seq beyond audit tail")

    def test_no_zero_balance_substitute_before_first_commit(self):
        # 资产当前有已提交余额，但边界之前没有 -> 404 而非 0 余额
        self.request(
            "PUT",
            "/v1/wallets/w1/approval-policy",
            {"required_approvals": 1, "timeout_seconds": 600},
        )
        self.create("op1", "btc", 100)
        self.commit("op1")
        pseq = self.seq_of("policy_updated")
        status, body = self.get_asset("btc", f"at_seq={pseq}")
        self.assertEqual(status, 404)
        self.assertEqual(body["error"], "asset 'btc' not found")

    def test_expected_head_match_and_mismatch(self):
        self.create("op1", "btc", 100)
        self.commit("op1")
        tail = self.events()[-1]["seq"]
        _, ok = self.get_asset("btc", f"at_seq={tail}")
        status, body = self.get_asset(
            "btc", f"at_seq={tail}&expected_head={ok['head']}")
        self.assertEqual(status, 200, body)
        wrong = "a" * 64
        self.assertNotEqual(wrong, ok["head"])
        status, body = self.get_asset(
            "btc", f"at_seq={tail}&expected_head={wrong}")
        self.assertEqual(status, 409)
        self.assertEqual(
            body["error"], "expected_head does not match chain head")

    def test_expected_head_from_other_boundary_409(self):
        self.create("op1", "btc", 100)
        self.commit("op1")
        s1 = self.seq_of("asset_operation_committed", "op1")
        self.create("op2", "btc", 1)
        self.commit("op2")
        s2 = self.seq_of("asset_operation_committed", "op2")
        _, old = self.get_asset("btc", f"at_seq={s1}")
        status, _ = self.get_asset(
            "btc", f"at_seq={s2}&expected_head={old['head']}")
        self.assertEqual(status, 409)


class ReadOnlyAndFreezeTest(_HttpBase):
    """纯只读、冻结可用、重启一致。"""

    def test_query_is_read_only(self):
        self.create("op1", "btc", 100)
        self.commit("op1")
        s1 = self.seq_of("asset_operation_committed", "op1")
        before = self.events()

        def snapshot():
            out = {}
            for root, _, files in os.walk(self.tmp):
                for f in files:
                    path = os.path.join(root, f)
                    with open(path, "rb") as fh:
                        out[os.path.relpath(path, self.tmp)] = fh.read()
            return out

        files_before = snapshot()
        # 含 409/404/200 三类结果各查一次
        self.get_asset("btc", f"at_seq={s1}")
        self.get_asset("btc", f"at_seq={s1}&expected_head={'a'*64}")
        self.get_asset("ghost-asset", f"at_seq={s1}")
        self.assertEqual(self.events(), before)
        self.assertEqual(snapshot(), files_before)

    def test_frozen_wallet_and_asset_still_queryable(self):
        self.create("op1", "btc", 100)
        self.commit("op1")
        tail = self.events()[-1]["seq"]
        status, _ = self.request(
            "POST", "/v1/wallets/w1/freeze", {"reason": "incident"}
        )
        self.assertEqual(status, 201)
        status, body = self.get_asset("btc", f"at_seq={tail}")
        self.assertEqual(status, 200)
        self.assertEqual((body["balance"], body["version"]), (100, 1))
        # 解冻后冻结单个资产，历史仍可查
        self.request("POST", "/v1/wallets/w1/unfreeze", {"reason": "ok"})
        status, _ = self.request(
            "POST", "/v1/wallets/w1/assets/btc/freeze", {"reason": "risk"}
        )
        self.assertEqual(status, 201)
        status, body = self.get_asset("btc", f"at_seq={tail}")
        self.assertEqual(status, 200)
        self.assertEqual((body["balance"], body["version"]), (100, 1))
        status, body = self.get_asset("btc")
        self.assertEqual(status, 200)
        self.assertEqual(body["balance"], 100)

    def test_policy_change_does_not_change_boundary(self):
        self.create("op1", "btc", 100)
        self.commit("op1")
        s1 = self.seq_of("asset_operation_committed", "op1")
        _, before = self.get_asset("btc", f"at_seq={s1}")
        # 策略修改追加事件，但旧边界结果（含 head 与余额）完全不变
        self.request(
            "PUT",
            "/v1/wallets/w1/approval-policy",
            {"required_approvals": 2, "timeout_seconds": 30},
        )
        _, after = self.get_asset("btc", f"at_seq={s1}")
        self.assertEqual(before, after)

    def test_result_consistent_after_restart(self):
        self.create("op1", "btc", 100)
        self.commit("op1")
        s1 = self.seq_of("asset_operation_committed", "op1")
        self.create("op2", "btc", -40)
        self.commit("op2")
        s2 = self.seq_of("asset_operation_committed", "op2")
        _, expected_1 = self.get_asset("btc", f"at_seq={s1}")
        _, expected_2 = self.get_asset("btc", f"at_seq={s2}")
        # 用新 service 重新打开同一数据目录（模拟重启）
        restarted = make_harness(self.tmp).service
        got_1 = restarted.get_asset("w1", "btc", at_seq=str(s1))
        got_2 = restarted.get_asset("w1", "btc", at_seq=str(s2))
        self.assertEqual(got_1, expected_1)
        self.assertEqual(got_2, expected_2)


class Corruption503Test(_HttpBase):
    """审计链/现场损坏 -> 503 泛化文案、保留现场。"""

    def test_tampered_audit_log_503(self):
        self.create("op1", "btc", 100)
        self.commit("op1")
        tail = self.events()[-1]["seq"]
        log = _load_audit(self.tmp)
        log["events"][0]["details"]["tampered"] = True
        _dump_audit(self.tmp, log)
        status, body = self.get_asset("btc", f"at_seq={tail}")
        self.assertEqual(status, 503, body)
        self.assertEqual(
            body["error"], "service temporarily unavailable")
        # 现场保留：不修复/覆盖
        self.assertIn(
            "tampered", _load_audit(self.tmp)["events"][0]["details"])

    def test_broken_chain_metadata_503(self):
        self.create("op1", "btc", 100)
        self.commit("op1")
        tail = self.events()[-1]["seq"]
        log = _load_audit(self.tmp)
        log["chain"]["head"] = "a" * 64
        _dump_audit(self.tmp, log)
        status, body = self.get_asset("btc", f"at_seq={tail}")
        self.assertEqual(status, 503, body)
        self.assertEqual(
            body["error"], "service temporarily unavailable")

    def test_no_secret_material_in_responses(self):
        self.create("op1", "btc", 100)
        self.commit("op1")
        tail = self.events()[-1]["seq"]
        status, body = self.get_asset("btc", f"at_seq={tail}")
        self.assertEqual(status, 200)
        raw = json.dumps(body)
        self.assertNotIn("private", raw)
        self.assertNotIn("share", raw)


class PrefixEvidenceStoreTest(unittest.TestCase):
    """AuditStore.prefix_evidence 单元。"""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.store = __import__(
            "threshold_wallet.audit", fromlist=["AuditStore"]
        ).AuditStore(self.tmp)
        for i in range(1, 4):
            self.store.append_event(
                "w1",
                {
                    "type": "policy_updated",
                    "at": f"2026-09-21T00:00:{i:02d}Z",
                    "request_id": None,
                    "actor_id": None,
                    "reason": None,
                    "details": {"i": i},
                },
            )

    def test_missing_log_is_none(self):
        self.assertIsNone(self.store.prefix_evidence("ghost", 1))

    def test_prefix_head_matches_range_evidence(self):
        audit_mod = __import__("threshold_wallet.audit")
        for seq in (1, 2, 3):
            prefix = self.store.prefix_evidence("w1", seq)
            rng = self.store.range_evidence("w1", 1, seq)
            self.assertEqual(
                [e["seq"] for e in prefix["events"]],
                list(range(1, seq + 1)),
            )
            self.assertEqual(prefix["count"], 3)
            self.assertEqual(prefix["head"], rng["end_head"])


if __name__ == "__main__":
    unittest.main()


class ForeignMalformedCommitTest(_HttpBase):
    """边界内其他资产的畸形提交点同样 fail-closed 503。"""

    def test_malformed_other_asset_commit_in_prefix_503(self):
        svc = self.srv.harness.service
        svc.create_asset_operation("w1", "op1", "btc", 100)
        svc.commit_asset_operation("w1", "op1")
        svc.create_asset_operation("w1", "op2", "eth", 5)
        svc.commit_asset_operation("w1", "op2")
        tail = self.events()[-1]["seq"]
        # 篡改 eth 提交事件的 delta 形状（链摘要随之失配）
        log = _load_audit(self.tmp)
        target = next(
            e for e in log["events"]
            if e["type"] == "asset_operation_committed"
            and e["request_id"] == "op2"
        )
        target["details"]["delta"] = "5"
        _dump_audit(self.tmp, log)
        # 即使只查 btc，边界内的畸形提交点也不得静默放过
        status, body = self.get_asset("btc", f"at_seq={tail}")
        self.assertEqual(status, 503, body)
        self.assertEqual(
            body["error"], "service temporarily unavailable")


class DisasterRecoveryConsistencyTest(unittest.TestCase):
    """合法灾备快照备份/恢复后同一边界结果一致。"""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.snap = self.tmp + ".snap.tar"
        self.addCleanup(
            lambda: os.path.exists(self.snap) and os.remove(self.snap))

    def test_history_identical_after_backup_restore(self):
        from threshold_wallet import drbackup

        h = make_harness(self.tmp)
        svc = h.service
        svc.create_wallet("w1", 2)
        svc.create_asset_operation("w1", "op1", "btc", 100)
        svc.commit_asset_operation("w1", "op1")
        svc.create_asset_operation("w1", "op2", "btc", -30)
        svc.commit_asset_operation("w1", "op2")
        # 备份后再追加一笔：恢复回到快照时刻，旧边界结果须与备份前一致
        s2 = svc.get_audit_events("w1")["events"][-1]["seq"]
        expected = svc.get_asset("w1", "btc", at_seq=str(s2))
        drbackup.backup(self.tmp, "w1", "snap-1", self.snap)
        svc.create_asset_operation("w1", "op3", "btc", 1)
        svc.commit_asset_operation("w1", "op3")

        restore_dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, restore_dir, ignore_errors=True)
        code, _ = drbackup.restore(restore_dir, "w1", self.snap)
        self.assertEqual(code, 201)
        svc2 = make_harness(restore_dir).service
        got = svc2.get_asset("w1", "btc", at_seq=str(s2))
        self.assertEqual(got, expected)
        # 恢复现场的尾序号就是快照尾序号，再之后的边界越界 404
        from threshold_wallet.service import ServiceError

        with self.assertRaises(ServiceError) as ctx:
            svc2.get_asset("w1", "btc", at_seq=str(s2 + 1))
        self.assertEqual(ctx.exception.status, 404)
