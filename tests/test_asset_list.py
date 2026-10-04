"""钱包级资产清单分页查询：GET /v1/wallets/{id}/assets。

覆盖：
- 响应恰含 wallet_id/at_seq/head/assets/next_after；assets 每项仅含
  asset_id/balance/version，按 asset_id 的 ASCII 序升序；
- 只列出边界内已有已提交操作的资产：余额归零仍保留，只有 pending 或
  cancelled 操作的资产不出现；同一资产不重复；余额/版本与同一边界的
  单资产历史查询一致；
- at_seq 缺省取本次查询的一致审计尾序号；显式 0 表示空前缀（空数组、
  head 为 64 个零）；正边界 head 与 audit-evidence 同 to_seq 的
  end_head 一致；
- expected_head 只能随显式 at_seq 使用：缺 at_seq/格式非法 400，
  不符 409；后续页带回相同 at_seq 与 head 时分页集合与数值不变；
- limit 缺省 100、1..1000；after 为排他游标且不要求标识实际存在；
  仍有后续资产时 next_after 为本页最后一个标识，否则为 null；
- 空钱包、零边界或游标之后无资产均返回 200 空数组（仍校验摘要）；
- 钱包 404 先于参数 400；非法标识 400；参数重复/空值/格式非法/limit
  越界 400；边界越尾 404；
- 冻结钱包/资产可查询；查询纯只读（无事件、账本与链不变）。
"""

from __future__ import annotations

import json
import shutil
import tempfile
import unittest

from tests.helpers import http_server

ZERO_HEAD = "0" * 64


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

    def _list(self, query="", wallet="w1"):
        suffix = f"?{query}" if query else ""
        return self.srv.request(
            "GET", f"/v1/wallets/{wallet}/assets{suffix}"
        )

    def _events(self, wallet="w1"):
        status, body = self.srv.request(
            "GET", f"/v1/wallets/{wallet}/audit-events"
        )
        assert status == 200, body
        return body["events"]

    def _head_at(self, seq, wallet="w1"):
        status, body = self.srv.request(
            "GET",
            f"/v1/wallets/{wallet}/audit-evidence"
            f"?from_seq=1&to_seq={seq}",
        )
        assert status == 200, body
        return body["end_head"]

    def _asset_history(self, asset_id, at_seq, wallet="w1"):
        status, body = self.srv.request(
            "GET",
            f"/v1/wallets/{wallet}/assets/{asset_id}?at_seq={at_seq}",
        )
        assert status == 200, body
        return body


class EmptyAndShapeTest(_HttpBase):
    def test_empty_wallet_returns_empty_page(self):
        status, body = self._list()
        self.assertEqual(status, 200)
        self.assertEqual(
            body,
            {
                "wallet_id": "w1",
                "at_seq": 0,
                "head": ZERO_HEAD,
                "assets": [],
                "next_after": None,
            },
        )

    def test_explicit_zero_boundary_is_empty_prefix(self):
        self._create("op1", "btc", 100)
        self._commit("op1")
        status, body = self._list("at_seq=0")
        self.assertEqual(status, 200)
        self.assertEqual(body["at_seq"], 0)
        self.assertEqual(body["head"], ZERO_HEAD)
        self.assertEqual(body["assets"], [])
        self.assertEqual(body["next_after"], None)

    def test_response_and_item_key_order(self):
        self._create("op1", "btc", 100)
        self._commit("op1")
        status, body = self._list()
        self.assertEqual(status, 200)
        self.assertEqual(
            list(body), ["wallet_id", "at_seq", "head", "assets", "next_after"]
        )
        self.assertEqual(
            list(body["assets"][0]), ["asset_id", "balance", "version"]
        )


class ListingContentTest(_HttpBase):
    def test_lists_only_committed_assets_sorted_ascii(self):
        self._create("op1", "eth", 7)
        self._commit("op1")
        self._create("op2", "btc", 100)
        self._commit("op2")
        self._create("op3", "btc", -40)
        self._commit("op3")
        # 只有 pending 操作的资产不出现
        self._create("op4", "doge", 5)
        status, body = self._list()
        self.assertEqual(status, 200)
        self.assertEqual(
            body["assets"],
            [
                {"asset_id": "btc", "balance": 60, "version": 2},
                {"asset_id": "eth", "balance": 7, "version": 1},
            ],
        )
        self.assertIsNone(body["next_after"])
        # at_seq 缺省 = 当前审计尾序号；head 与证据链一致
        tail = self._events()[-1]["seq"]
        self.assertEqual(body["at_seq"], tail)
        self.assertEqual(body["head"], self._head_at(tail))

    def test_zero_balance_asset_is_retained(self):
        self._create("op1", "btc", 100)
        self._commit("op1")
        self._create("op2", "btc", -100)
        self._commit("op2")
        status, body = self._list()
        self.assertEqual(status, 200)
        self.assertEqual(
            body["assets"],
            [{"asset_id": "btc", "balance": 0, "version": 2}],
        )

    def test_cancelled_only_asset_is_absent(self):
        # 审批工作流：取消 pending 操作需要 approved 审批单
        self.srv.request(
            "PUT",
            "/v1/wallets/w1/approval-policy",
            {"required_approvals": 1, "timeout_seconds": 3600},
        )
        self._create("op1", "btc", 100)
        message = json.dumps(
            {"operation_id": "op1", "cancel_id": "c1"},
            separators=(",", ":"),
        )
        status, _ = self.srv.request(
            "POST",
            "/v1/wallets/w1/sign-requests",
            {"id": "ap1", "message": message},
        )
        self.assertEqual(status, 201)
        self.srv.request(
            "POST",
            "/v1/wallets/w1/sign-requests/ap1/approve",
            {"approver_id": "alice"},
        )
        status, _ = self.srv.request(
            "POST",
            "/v1/wallets/w1/asset-operations/op1/cancel",
            {"cancel_id": "c1", "approval_request_id": "ap1"},
        )
        self.assertEqual(status, 201)
        status, body = self._list()
        self.assertEqual(status, 200)
        self.assertEqual(body["assets"], [])

    def test_boundary_matches_single_asset_history(self):
        self._create("op1", "btc", 100)
        self._commit("op1")
        self._create("op2", "eth", 9)
        self._commit("op2")
        self._create("op3", "btc", -30)
        self._commit("op3")
        boundary = self._events()[-2]["seq"]  # 第三笔提交之前
        status, body = self._list(f"at_seq={boundary}")
        self.assertEqual(status, 200)
        self.assertEqual(body["at_seq"], boundary)
        self.assertEqual(body["head"], self._head_at(boundary))
        for item in body["assets"]:
            history = self._asset_history(item["asset_id"], boundary)
            self.assertEqual(item["balance"], history["balance"])
            self.assertEqual(item["version"], history["version"])
        self.assertEqual(
            body["assets"],
            [
                {"asset_id": "btc", "balance": 100, "version": 1},
                {"asset_id": "eth", "balance": 9, "version": 1},
            ],
        )

    def test_new_events_do_not_change_pinned_boundary(self):
        self._create("op1", "btc", 100)
        self._commit("op1")
        status, first = self._list()
        self.assertEqual(status, 200)
        # 新增事件后，带回相同 at_seq 与 head 作为 expected_head
        self._create("op2", "eth", 5)
        self._commit("op2")
        status, second = self._list(
            f"at_seq={first['at_seq']}&expected_head={first['head']}"
        )
        self.assertEqual(status, 200)
        self.assertEqual(second, first)


class PaginationTest(_HttpBase):
    def _seed(self, count=5):
        for i in range(count):
            self._create(f"op{i}", f"asset-{i:02d}", i + 1)
            self._commit(f"op{i}")

    def test_default_limit_and_next_after(self):
        self._seed(3)
        status, body = self._list("limit=2")
        self.assertEqual(status, 200)
        self.assertEqual(
            [a["asset_id"] for a in body["assets"]],
            ["asset-00", "asset-01"],
        )
        self.assertEqual(body["next_after"], "asset-01")
        # 第二页：带回相同 at_seq/head 与 after 游标
        status, page2 = self._list(
            f"at_seq={body['at_seq']}&expected_head={body['head']}"
            f"&limit=2&after={body['next_after']}"
        )
        self.assertEqual(status, 200)
        self.assertEqual(
            [a["asset_id"] for a in page2["assets"]], ["asset-02"]
        )
        self.assertIsNone(page2["next_after"])
        self.assertEqual(page2["at_seq"], body["at_seq"])
        self.assertEqual(page2["head"], body["head"])

    def test_after_excludes_value_and_before(self):
        self._seed(4)
        status, body = self._list("after=asset-01")
        self.assertEqual(status, 200)
        self.assertEqual(
            [a["asset_id"] for a in body["assets"]],
            ["asset-02", "asset-03"],
        )

    def test_after_need_not_exist(self):
        self._seed(3)
        status, body = self._list("after=asset-0")
        self.assertEqual(status, 200)
        # "asset-0" 是 "asset-00" 的前缀，ASCII 序在其之前
        self.assertEqual(len(body["assets"]), 3)
        status, body = self._list("after=asset-01x")
        self.assertEqual(status, 200)
        self.assertEqual(
            [a["asset_id"] for a in body["assets"]], ["asset-02"]
        )

    def test_after_beyond_all_returns_empty_page(self):
        self._seed(2)
        status, body = self._list("after=zzz")
        self.assertEqual(status, 200)
        self.assertEqual(body["assets"], [])
        self.assertIsNone(body["next_after"])

    def test_exact_page_boundary_has_null_next_after(self):
        self._seed(2)
        status, body = self._list("limit=2")
        self.assertEqual(status, 200)
        self.assertEqual(len(body["assets"]), 2)
        self.assertIsNone(body["next_after"])


class ParameterValidationTest(_HttpBase):
    def setUp(self):
        super().setUp()
        self._create("op1", "btc", 100)
        self._commit("op1")

    def test_invalid_at_seq_values(self):
        for query in (
            "at_seq=",
            "at_seq=%20",
            "at_seq=+1",
            "at_seq=-1",
            "at_seq=1.0",
            "at_seq=1e2",
            "at_seq=abc",
        ):
            with self.subTest(query=query):
                status, body = self._list(query)
                self.assertEqual(status, 400)
                self.assertEqual(body["error"], "invalid at_seq")

    def test_at_seq_zero_and_leading_zeros_accepted(self):
        status, body = self._list("at_seq=0")
        self.assertEqual(status, 200)
        self.assertEqual(body["at_seq"], 0)
        status, body = self._list("at_seq=001")
        self.assertEqual(status, 200)
        self.assertEqual(body["at_seq"], 1)

    def test_at_seq_beyond_tail_404(self):
        tail = self._events()[-1]["seq"]
        status, body = self._list(f"at_seq={tail + 1}")
        self.assertEqual(status, 404)
        self.assertEqual(body["error"], "at_seq beyond the audit tail")

    def test_duplicate_parameters(self):
        for query, message in (
            ("at_seq=1&at_seq=1", "duplicate at_seq parameters"),
            (
                "at_seq=1&expected_head={}&expected_head={}".format(
                    ZERO_HEAD, ZERO_HEAD
                ),
                "duplicate expected_head parameters",
            ),
            ("limit=1&limit=2", "duplicate limit parameters"),
            ("after=a&after=b", "duplicate after parameters"),
        ):
            with self.subTest(query=query):
                status, body = self._list(query)
                self.assertEqual(status, 400)
                self.assertEqual(body["error"], message)

    def test_expected_head_requires_at_seq(self):
        status, body = self._list(f"expected_head={ZERO_HEAD}")
        self.assertEqual(status, 400)

    def test_expected_head_format(self):
        for head in ("", "AB" * 32, "ab" * 16, "g" * 64):
            with self.subTest(head=head):
                status, body = self._list(
                    f"at_seq=1&expected_head={head}"
                )
                self.assertEqual(status, 400)
                self.assertEqual(body["error"], "invalid expected_head")

    def test_expected_head_mismatch_409(self):
        status, body = self._list(f"at_seq=1&expected_head={ZERO_HEAD}")
        self.assertEqual(status, 409)
        self.assertEqual(
            body["error"], "expected_head does not match chain head"
        )

    def test_expected_head_match_200(self):
        head = self._head_at(1)
        status, body = self._list(f"at_seq=1&expected_head={head}")
        self.assertEqual(status, 200)
        self.assertEqual(body["head"], head)

    def test_expected_head_validated_on_empty_page(self):
        # 零边界空数组仍校验摘要
        status, body = self._list(
            f"at_seq=0&expected_head={'1' * 64}"
        )
        self.assertEqual(status, 409)
        status, body = self._list(f"at_seq=0&expected_head={ZERO_HEAD}")
        self.assertEqual(status, 200)
        self.assertEqual(body["assets"], [])

    def test_limit_validation(self):
        for query in (
            "limit=",
            "limit=0",
            "limit=1001",
            "limit=-1",
            "limit=1.5",
            "limit=abc",
            "limit=99999999999999999999999999",
        ):
            with self.subTest(query=query):
                status, body = self._list(query)
                self.assertEqual(status, 400)
                self.assertEqual(body["error"], "invalid limit")
        for query, expected in (("limit=1", 1), ("limit=1000", 1000)):
            with self.subTest(query=query):
                status, body = self._list(query)
                self.assertEqual(status, 200)

    def test_after_validation(self):
        for query in ("after=", "after=a%20b", "after=a*b"):
            with self.subTest(query=query):
                status, body = self._list(query)
                self.assertEqual(status, 400)
                self.assertEqual(body["error"], "invalid after")

    def test_wallet_not_found_precedes_param_validation(self):
        status, body = self._list("at_seq=abc&limit=xyz", wallet="nope")
        self.assertEqual(status, 404)
        status, body = self._list(wallet="nope")
        self.assertEqual(status, 404)

    def test_invalid_wallet_id_400(self):
        status, body = self._list(wallet="bad.id!")
        self.assertEqual(status, 400)


class ReadOnlyAndFreezeTest(_HttpBase):
    def test_query_is_read_only(self):
        self._create("op1", "btc", 100)
        self._commit("op1")
        before_events = self._events()
        before_asset = self.srv.request("GET", "/v1/wallets/w1/assets/btc")
        status, body = self._list("limit=1")
        self.assertEqual(status, 200)
        self.assertEqual(self._events(), before_events)
        self.assertEqual(
            self.srv.request("GET", "/v1/wallets/w1/assets/btc"),
            before_asset,
        )

    def test_frozen_wallet_and_asset_still_queryable(self):
        self._create("op1", "btc", 100)
        self._commit("op1")
        status, _ = self.srv.request(
            "POST",
            "/v1/wallets/w1/assets/btc/freeze",
            {"reason": "risk"},
        )
        self.assertEqual(status, 201)
        status, body = self._list()
        self.assertEqual(status, 200)
        self.assertEqual(len(body["assets"]), 1)
        status, _ = self.srv.request(
            "POST", "/v1/wallets/w1/freeze", {"reason": "risk"}
        )
        self.assertEqual(status, 201)
        status, body = self._list()
        self.assertEqual(status, 200)
        self.assertEqual(len(body["assets"]), 1)


if __name__ == "__main__":
    unittest.main()
