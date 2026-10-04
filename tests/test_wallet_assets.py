"""钱包级资产清单分页查询：GET /v1/wallets/{id}/assets。

覆盖：
- 响应形状恰为 {wallet_id,at_seq,head,assets,next_after}，每项恰含
  {asset_id,balance,version}；按 asset_id ASCII 升序；余额归零保留、
  只有 pending/cancelled 操作的资产不出现；
- at_seq 缺省取审计尾序号，显式 0 为零边界（head 为 64 个零）；head
  与 audit-evidence 同 to_seq 的 end_head 一致；余额/版本与同一边界
  单资产历史查询一致；
- expected_head 只能随显式 at_seq 使用，匹配 200、不符 409；后续页
  带回相同 at_seq/head 时新增事件不改变分页集合与数值；
- limit 1..1000 缺省 100；after 排除该值及之前、不要求存在；
  next_after 仅在仍有后续资产时返回本页末位标识，否则 null；
- 空钱包/零边界/游标之后无资产均 200 空数组但仍校验摘要；
- 参数重复/空值/非法/limit 越界/expected_head 缺 at_seq 400；钱包
  标识非法 400、钱包不存在 404 优先；边界越尾 404；
- 人工提交、链上确认、派发结算与重组补偿统一纳入且同一资产不重复；
- 冻结钱包/资产可查；查询纯只读；重启与灾备恢复后同边界结果一致；
- 审计链损坏 503 通用文案、不返回部分结果；响应与日志不含密钥材料。
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
ZERO_HEAD = "0" * 64


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

    def _assets(self, query="", wallet="w1"):
        suffix = f"?{query}" if query else ""
        return self.srv.request(
            "GET", f"/v1/wallets/{wallet}/assets{suffix}"
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

    def _tail(self, wallet="w1"):
        events = self._events(wallet)
        return events[-1]["seq"] if events else 0

    def _head_at(self, seq, wallet="w1"):
        status, body = self.srv.request(
            "GET",
            f"/v1/wallets/{wallet}/audit-evidence"
            f"?from_seq=1&to_seq={seq}",
        )
        assert status == 200, body
        return body["end_head"]


class EmptyAndZeroBoundaryTest(_HttpBase):
    """空钱包与零边界：200 空数组，head 为 64 个零，仍校验摘要。"""

    def test_empty_wallet_default_boundary(self):
        status, body = self._assets()
        self.assertEqual(status, 200)
        self.assertEqual(
            list(body), ["wallet_id", "at_seq", "head", "assets",
                         "next_after"]
        )
        self.assertEqual(body["wallet_id"], "w1")
        self.assertEqual(body["at_seq"], 0)
        self.assertEqual(body["head"], ZERO_HEAD)
        self.assertEqual(body["assets"], [])
        self.assertIsNone(body["next_after"])

    def test_explicit_zero_boundary(self):
        self._create("a1", "btc", 100)
        self._commit("a1")
        status, body = self._assets("at_seq=0")
        self.assertEqual(status, 200)
        self.assertEqual(body["at_seq"], 0)
        self.assertEqual(body["head"], ZERO_HEAD)
        self.assertEqual(body["assets"], [])
        self.assertIsNone(body["next_after"])

    def test_zero_boundary_head_still_verified(self):
        status, body = self._assets(
            f"at_seq=0&expected_head={ZERO_HEAD}"
        )
        self.assertEqual(status, 200)
        status, body = self._assets(
            f"at_seq=0&expected_head={'a' * 64}"
        )
        self.assertEqual(status, 409)
        self.assertEqual(
            body["error"], "expected_head does not match chain head"
        )

    def test_empty_wallet_beyond_tail_is_404(self):
        status, body = self._assets("at_seq=1")
        self.assertEqual(status, 404)
        self.assertEqual(body["error"], "at_seq beyond the audit tail")

    def test_cursor_beyond_all_assets_is_empty_page(self):
        self._create("a1", "btc", 100)
        self._commit("a1")
        status, body = self._assets("after=zzz")
        self.assertEqual(status, 200)
        self.assertEqual(body["assets"], [])
        self.assertIsNone(body["next_after"])
        # 空页同样校验摘要
        status, body = self._assets(
            f"at_seq={body['at_seq']}&expected_head={'a' * 64}&after=zzz"
        )
        self.assertEqual(status, 409)


class ListingContentTest(_HttpBase):
    """清单内容：排序、形状、与单资产历史查询一致、零余额保留。"""

    def _setup_three(self):
        self._create("a1", "eth", 7)
        self._create("a2", "btc", 100)
        self._create("a3", "usd", 50)
        self._commit("a2")
        self._commit("a1")
        self._commit("a3")

    def test_assets_sorted_by_asset_id_with_strict_item_shape(self):
        self._setup_three()
        status, body = self._assets()
        self.assertEqual(status, 200)
        self.assertEqual(
            [item["asset_id"] for item in body["assets"]],
            ["btc", "eth", "usd"],
        )
        for item in body["assets"]:
            self.assertEqual(
                list(item), ["asset_id", "balance", "version"]
            )
        self.assertEqual(
            body["assets"],
            [
                {"asset_id": "btc", "balance": 100, "version": 1},
                {"asset_id": "eth", "balance": 7, "version": 1},
                {"asset_id": "usd", "balance": 50, "version": 1},
            ],
        )
        self.assertIsNone(body["next_after"])

    def test_default_boundary_is_audit_tail_and_head_matches(self):
        self._setup_three()
        tail = self._tail()
        status, body = self._assets()
        self.assertEqual(status, 200)
        self.assertEqual(body["at_seq"], tail)
        self.assertEqual(body["head"], self._head_at(tail))

    def test_values_match_single_asset_history_at_same_boundary(self):
        self._setup_three()
        self._create("a4", "btc", 25)
        self._commit("a4")
        tail = self._tail()
        status, body = self._assets(f"at_seq={tail}")
        self.assertEqual(status, 200)
        by_id = {item["asset_id"]: item for item in body["assets"]}
        self.assertEqual(
            by_id["btc"],
            {"asset_id": "btc", "balance": 125, "version": 2},
        )
        for asset_id, item in by_id.items():
            status, single = self._asset(asset_id, f"at_seq={tail}")
            self.assertEqual(status, 200)
            self.assertEqual(item["balance"], single["balance"])
            self.assertEqual(item["version"], single["version"])
            self.assertEqual(body["head"], single["head"])

    def test_zero_balance_asset_is_retained(self):
        self._create("in", "btc", 100)
        self._commit("in")
        self._create("out", "btc", -100)
        self._commit("out")
        status, body = self._assets()
        self.assertEqual(status, 200)
        self.assertEqual(
            body["assets"],
            [{"asset_id": "btc", "balance": 0, "version": 2}],
        )

    def test_pending_and_cancelled_only_assets_are_absent(self):
        self._create("a1", "btc", 100)
        self._commit("a1")
        # 仅 pending 的资产不出现
        self._create("p1", "eth", 5)
        # 仅 cancelled 的资产不出现（审批策略降为单批，便于构造）
        status, _ = self.srv.request(
            "PUT", "/v1/wallets/w1/approval-policy",
            {"required_approvals": 1, "timeout_seconds": 600},
        )
        self.assertEqual(status, 200)
        message = json.dumps(
            {"operation_id": "p2", "cancel_id": "c1"},
            separators=(",", ":"),
        )
        status, _ = self.srv.request(
            "POST", "/v1/wallets/w1/sign-requests",
            {"id": "ap1", "message": message},
        )
        self.assertEqual(status, 201)
        status, _ = self.srv.request(
            "POST", "/v1/wallets/w1/sign-requests/ap1/approve",
            {"approver_id": "alice"},
        )
        self.assertEqual(status, 200)
        self._create("p2", "doge", 9)
        status, _ = self.srv.request(
            "POST", "/v1/wallets/w1/asset-operations/p2/cancel",
            {"cancel_id": "c1", "approval_request_id": "ap1"},
        )
        self.assertEqual(status, 201)
        status, body = self._assets()
        self.assertEqual(status, 200)
        self.assertEqual(
            [item["asset_id"] for item in body["assets"]], ["btc"]
        )

    def test_boundary_prefix_limits_the_set(self):
        self._create("a1", "btc", 100)
        self._commit("a1")
        first_tail = self._tail()
        self._create("a2", "eth", 7)
        self._commit("a2")
        status, body = self._assets(f"at_seq={first_tail}")
        self.assertEqual(status, 200)
        self.assertEqual(
            [item["asset_id"] for item in body["assets"]], ["btc"]
        )
        self.assertEqual(body["head"], self._head_at(first_tail))
        # 边界落在与资产无关的事件上：集合不变、head 推进
        status, _ = self.srv.request(
            "POST", "/v1/wallets/w1/freeze", {"reason": "incident"}
        )
        self.assertEqual(status, 201)
        status, _ = self.srv.request(
            "POST", "/v1/wallets/w1/unfreeze", {"reason": "done"}
        )
        self.assertEqual(status, 201)
        tail = self._tail()
        status, body = self._assets(f"at_seq={tail}")
        self.assertEqual(status, 200)
        self.assertEqual(
            [item["asset_id"] for item in body["assets"]],
            ["btc", "eth"],
        )
        self.assertEqual(body["head"], self._head_at(tail))


class PaginationTest(_HttpBase):
    """limit/after/next_after 分页语义。"""

    def _setup(self, count=5):
        for index in range(count):
            asset_id = f"a{index:02d}"
            self._create(f"op{index}", asset_id, index + 1)
            self._commit(f"op{index}")

    def test_limit_and_next_after_walk_all_pages(self):
        self._setup(5)
        seen = []
        after = ""
        for expected_page in (2, 2, 1):
            query = f"limit=2&after={after}" if after else "limit=2"
            status, body = self._assets(query)
            self.assertEqual(status, 200)
            self.assertEqual(len(body["assets"]), expected_page)
            seen.extend(item["asset_id"] for item in body["assets"])
            if expected_page == 2:
                self.assertEqual(
                    body["next_after"], body["assets"][-1]["asset_id"]
                )
                after = body["next_after"]
            else:
                self.assertIsNone(body["next_after"])
        self.assertEqual(seen, ["a00", "a01", "a02", "a03", "a04"])

    def test_after_excludes_cursor_and_earlier(self):
        self._setup(3)
        status, body = self._assets("after=a00")
        self.assertEqual(status, 200)
        self.assertEqual(
            [item["asset_id"] for item in body["assets"]],
            ["a01", "a02"],
        )

    def test_after_need_not_exist(self):
        self._setup(3)
        # 游标落在两个实际标识之间
        status, body = self._assets("after=a00x")
        self.assertEqual(status, 200)
        self.assertEqual(
            [item["asset_id"] for item in body["assets"]],
            ["a01", "a02"],
        )

    def test_exact_page_boundary_has_null_next_after(self):
        self._setup(2)
        status, body = self._assets("limit=2")
        self.assertEqual(status, 200)
        self.assertEqual(len(body["assets"]), 2)
        self.assertIsNone(body["next_after"])

    def test_limit_one_paginates_every_asset(self):
        self._setup(3)
        seen = []
        after = None
        for _ in range(3):
            query = "limit=1" + (f"&after={after}" if after else "")
            status, body = self._assets(query)
            self.assertEqual(status, 200)
            self.assertEqual(len(body["assets"]), 1)
            seen.append(body["assets"][0]["asset_id"])
            after = body["next_after"]
        self.assertEqual(seen, ["a00", "a01", "a02"])
        # 末页 next_after 已为 null；显式以末位标识为游标则为空页
        self.assertIsNone(after)
        status, body = self._assets("limit=1&after=a02")
        self.assertEqual(body["assets"], [])
        self.assertIsNone(body["next_after"])

    def test_limit_with_at_seq_applies_to_boundary_set(self):
        self._setup(3)
        tail = self._tail()
        self._create("op3", "a03", 9)
        self._commit("op3")
        status, body = self._assets(f"at_seq={tail}&limit=2")
        self.assertEqual(status, 200)
        self.assertEqual(
            [item["asset_id"] for item in body["assets"]],
            ["a00", "a01"],
        )
        self.assertEqual(body["next_after"], "a01")
        status, body = self._assets(
            f"at_seq={tail}&limit=2&after=a01"
        )
        self.assertEqual(
            [item["asset_id"] for item in body["assets"]], ["a02"]
        )
        self.assertIsNone(body["next_after"])


class DefaultAndMaxLimitTest(unittest.TestCase):
    """缺省 limit=100、上限 1000（服务层，避免百余次 HTTP 往返）。"""

    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.d, ignore_errors=True)
        self.h = make_harness(self.d)
        self.svc = self.h.service
        self.svc.create_wallet("w1", 2)
        for index in range(105):
            asset_id = f"a{index:03d}"
            code, _ = self.svc.create_asset_operation(
                "w1", f"op{index}", asset_id, index + 1
            )
            self.assertEqual(code, 201)
            code, _ = self.svc.commit_asset_operation("w1", f"op{index}")
            self.assertEqual(code, 201)

    def test_default_limit_is_100(self):
        body = self.svc.list_assets("w1")
        self.assertEqual(len(body["assets"]), 100)
        self.assertEqual(body["next_after"], "a099")
        rest = self.svc.list_assets("w1", after=["a099"])
        self.assertEqual(len(rest["assets"]), 5)
        self.assertIsNone(rest["next_after"])

    def test_limit_1000_returns_all(self):
        body = self.svc.list_assets("w1", limit=["1000"])
        self.assertEqual(len(body["assets"]), 105)
        self.assertIsNone(body["next_after"])

    def test_limit_out_of_range_is_400(self):
        from threshold_wallet.service import ServiceError
        for value in ("0", "1001", "9999", "9" * 5000, "", "abc",
                      "-1", "1.0", "%20"):
            with self.subTest(value=value):
                with self.assertRaises(ServiceError) as ctx:
                    self.svc.list_assets("w1", limit=[value])
                self.assertEqual(ctx.exception.status, 400)
                self.assertEqual(ctx.exception.message, "invalid limit")

    def test_limit_leading_zeros_accepted(self):
        body = self.svc.list_assets("w1", limit=["0100"])
        self.assertEqual(len(body["assets"]), 100)


class ExpectedHeadAndStabilityTest(_HttpBase):
    """expected_head 校验与跨页一致性。"""

    def _setup(self):
        self._create("a1", "btc", 100)
        self._commit("a1")
        self._create("a2", "eth", 7)
        self._commit("a2")

    def test_expected_head_match_returns_200(self):
        self._setup()
        tail = self._tail()
        head = self._head_at(tail)
        status, body = self._assets(
            f"at_seq={tail}&expected_head={head}"
        )
        self.assertEqual(status, 200)
        self.assertEqual(body["head"], head)

    def test_expected_head_mismatch_is_409(self):
        self._setup()
        tail = self._tail()
        status, body = self._assets(
            f"at_seq={tail}&expected_head={'a' * 64}"
        )
        self.assertEqual(status, 409)
        self.assertEqual(
            body["error"], "expected_head does not match chain head"
        )

    def test_expected_head_without_at_seq_is_400(self):
        status, body = self._assets(f"expected_head={'a' * 64}")
        self.assertEqual(status, 400)
        self.assertEqual(body["error"], "expected_head requires at_seq")

    def test_expected_head_bad_format_is_400(self):
        for value in ("", "zz", "a" * 63, "A" * 64, "g" * 64):
            with self.subTest(value=value):
                status, body = self._assets(
                    f"at_seq=1&expected_head={value}"
                )
                self.assertEqual(status, 400, value)
                self.assertEqual(body["error"], "invalid expected_head")

    def test_new_events_do_not_change_pinned_pages(self):
        self._setup()
        status, page1 = self._assets("limit=1")
        self.assertEqual(status, 200)
        self.assertEqual(
            [item["asset_id"] for item in page1["assets"]], ["btc"]
        )
        pinned_seq = page1["at_seq"]
        pinned_head = page1["head"]
        # 新增提交与无关事件
        self._create("a3", "aaa", 1)
        self._commit("a3")
        self._create("a4", "zzz", 2)
        self._commit("a4")
        # 重取第一页：集合与数值不变
        status, again = self._assets(
            f"at_seq={pinned_seq}&expected_head={pinned_head}&limit=1"
        )
        self.assertEqual(status, 200)
        self.assertEqual(again, page1)
        # 第二页带回相同 at_seq/head：仍取到 eth，新增的 aaa 不插入
        status, page2 = self._assets(
            f"at_seq={pinned_seq}&expected_head={pinned_head}"
            f"&limit=1&after={page1['next_after']}"
        )
        self.assertEqual(status, 200)
        self.assertEqual(
            [item["asset_id"] for item in page2["assets"]], ["eth"]
        )
        self.assertIsNone(page2["next_after"])
        # 缺省边界（新尾）则包含新资产
        status, current = self._assets()
        self.assertEqual(
            [item["asset_id"] for item in current["assets"]],
            ["aaa", "btc", "eth", "zzz"],
        )


class ParameterValidationTest(_HttpBase):
    """参数校验与错误次序。"""

    def test_invalid_wallet_id_is_400(self):
        status, _ = self._assets(wallet="bad$id")
        self.assertEqual(status, 400)

    def test_missing_wallet_404_precedes_param_validation(self):
        for query in (
            "",
            "at_seq=0",
            "at_seq=",
            "at_seq=abc",
            "limit=0",
            "limit=abc",
            "after=bad$id",
            "expected_head=" + "a" * 64,
            "at_seq=1&at_seq=2",
        ):
            status, _ = self._assets(query, wallet="nope")
            self.assertEqual(status, 404, query)

    def test_invalid_at_seq_values_are_400(self):
        for value in ("", "-1", "1.0", "1e1", "abc", "0x1", "%2B1",
                      "%201", "1%20"):
            with self.subTest(value=value):
                status, body = self._assets(f"at_seq={value}")
                self.assertEqual(status, 400, value)
                self.assertEqual(body["error"], "invalid at_seq")
        # 全角数字（Unicode digit，非 ASCII）-> 400
        status, body = self._assets("at_seq=" + "%EF%BC%91")
        self.assertEqual(status, 400)
        self.assertEqual(body["error"], "invalid at_seq")

    def test_at_seq_zero_and_all_zeros_are_accepted(self):
        for value in ("0", "00", "0000"):
            status, body = self._assets(f"at_seq={value}")
            self.assertEqual(status, 200, value)
            self.assertEqual(body["at_seq"], 0)
            self.assertEqual(body["head"], ZERO_HEAD)

    def test_at_seq_leading_zeros_normalized(self):
        self._create("a1", "btc", 100)
        self._commit("a1")
        tail = self._tail()
        status, body = self._assets(f"at_seq=0{tail}")
        self.assertEqual(status, 200)
        self.assertEqual(body["at_seq"], tail)

    def test_huge_numeric_at_seq_is_404_not_400(self):
        self._create("a1", "btc", 100)
        self._commit("a1")
        status, body = self._assets(f"at_seq={'9' * 5000}")
        self.assertEqual(status, 404)
        self.assertEqual(body["error"], "at_seq beyond the audit tail")

    def test_beyond_tail_is_404(self):
        self._create("a1", "btc", 100)
        self._commit("a1")
        tail = self._tail()
        status, body = self._assets(f"at_seq={tail + 1}")
        self.assertEqual(status, 404)
        self.assertEqual(body["error"], "at_seq beyond the audit tail")

    def test_beyond_tail_404_precedes_head_mismatch_409(self):
        self._create("a1", "btc", 100)
        self._commit("a1")
        tail = self._tail()
        status, _ = self._assets(
            f"at_seq={tail + 1}&expected_head={'a' * 64}"
        )
        self.assertEqual(status, 404)

    def test_duplicate_params_are_400(self):
        cases = (
            ("at_seq=1&at_seq=2", "duplicate at_seq parameters"),
            (
                f"at_seq=1&expected_head={'a' * 64}"
                f"&expected_head={'b' * 64}",
                "duplicate expected_head parameters",
            ),
            ("limit=1&limit=2", "duplicate limit parameters"),
            ("after=a&after=b", "duplicate after parameters"),
        )
        for query, message in cases:
            with self.subTest(query=query):
                status, body = self._assets(query)
                self.assertEqual(status, 400, query)
                self.assertEqual(body["error"], message)

    def test_invalid_after_is_400(self):
        for value in ("", "bad$id", "a" * 129, "has%20space"):
            with self.subTest(value=value):
                status, body = self._assets(f"after={value}")
                self.assertEqual(status, 400, value)
                self.assertEqual(body["error"], "invalid after")

    def test_invalid_limit_is_400_over_http(self):
        for value in ("", "0", "1001", "abc", "-1", "1.0"):
            with self.subTest(value=value):
                status, body = self._assets(f"limit={value}")
                self.assertEqual(status, 400, value)
                self.assertEqual(body["error"], "invalid limit")

    def test_unknown_query_params_are_ignored(self):
        self._create("a1", "btc", 100)
        self._commit("a1")
        status, body = self._assets("foo=bar")
        self.assertEqual(status, 200)
        self.assertEqual(len(body["assets"]), 1)


class FreezeAndReadOnlyTest(_HttpBase):
    """冻结期间仍可查询；查询纯只读。"""

    def test_frozen_wallet_and_asset_still_listed(self):
        self._create("a1", "btc", 100)
        self._commit("a1")
        status, _ = self.srv.request(
            "POST", "/v1/wallets/w1/freeze", {"reason": "incident"}
        )
        self.assertEqual(status, 201)
        status, body = self._assets()
        self.assertEqual(status, 200)
        self.assertEqual(
            body["assets"],
            [{"asset_id": "btc", "balance": 100, "version": 1}],
        )
        status, _ = self.srv.request(
            "POST", "/v1/wallets/w1/unfreeze", {"reason": "done"}
        )
        self.assertEqual(status, 201)
        status, _ = self.srv.request(
            "POST", "/v1/wallets/w1/assets/btc/freeze",
            {"reason": "asset incident"},
        )
        self.assertEqual(status, 201)
        status, body = self._assets()
        self.assertEqual(status, 200)
        self.assertEqual(len(body["assets"]), 1)

    def test_query_appends_no_events_and_changes_nothing(self):
        self._create("a1", "btc", 100)
        self._commit("a1")
        tail = self._tail()
        head = self._head_at(tail)
        before = self._events()
        for query in (
            "",
            f"at_seq={tail}",
            f"at_seq={tail}&expected_head={head}",
            "at_seq=0",
            "limit=1",
            "after=btc",
            f"at_seq={tail + 1}",
            "limit=0",
        ):
            self._assets(query)
        self.assertEqual(before, self._events())
        status, integ = self.srv.request(
            "GET", "/v1/wallets/w1/audit-integrity"
        )
        self.assertEqual(status, 200)
        self.assertEqual(integ["count"], len(before))
        self.assertEqual(integ["head"], head)
        # 当前余额/版本不变
        status, asset = self._asset("btc")
        self.assertEqual(
            (asset["balance"], asset["version"]), (100, 1)
        )

    def test_no_private_material_in_response_or_logs(self):
        self._create("a1", "btc", 100)
        self._commit("a1")
        status, raw = self.srv.request("GET", "/v1/wallets/w1/assets")
        self.assertEqual(status, 200)
        text = json.dumps(raw)
        self.assertNotIn("private_key", text)
        self.assertNotIn("share", text)
        self.assertNotIn("signature", text)
        for line in self.srv.logs:
            self.assertNotIn("private_key", line)
            self.assertNotIn("share", line)


class AllCommitPathsTest(unittest.TestCase):
    """人工提交、派发结算与重组补偿统一纳入，同一资产不重复。"""

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

    def test_settle_and_reorg_compensation_counted_once(self):
        self._build_settled(delta=100)
        # 人工提交另一资产
        code, _ = self.svc.create_asset_operation("w1", "op2", "eth", 5)
        self.assertEqual(code, 201)
        code, _ = self.svc.commit_asset_operation("w1", "op2")
        self.assertEqual(code, 201)
        # 重组补偿：BTC 反向 -100，余额归零仍保留
        status, _ = self.svc.post_chain_dispatch_confirmation(
            "w1", "dp1", "ad1", TX1, 9, BH2, 1
        )
        self.assertEqual(status, 201)
        body = self.svc.list_assets("w1")
        self.assertEqual(
            body["assets"],
            [
                {"asset_id": "BTC", "balance": 0, "version": 2},
                {"asset_id": "eth", "balance": 5, "version": 1},
            ],
        )
        # 与同一边界单资产历史查询一致
        tail = body["at_seq"]
        single = self.svc.get_asset("w1", "BTC", at_seq=str(tail))
        self.assertEqual(
            (body["assets"][0]["balance"], body["assets"][0]["version"]),
            (single["balance"], single["version"]),
        )
        self.assertEqual(body["head"], single["head"])
        # 边界落在结算事件（未含提交）：BTC 尚未落账
        events = self.svc.get_audit_events("w1")["events"]
        settled = [
            e for e in events if e["type"] == "chain_dispatch_settled"
        ][-1]
        body = self.svc.list_assets("w1", at_seq=[str(settled["seq"])])
        self.assertEqual(
            [item["asset_id"] for item in body["assets"]], []
        )


class RestartAndRecoveryConsistencyTest(unittest.TestCase):
    """重启（新进程视图）与灾备恢复后同一边界结果一致。"""

    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.d, ignore_errors=True)
        self.h = make_harness(self.d)
        self.svc = self.h.service

    def _build(self):
        self.svc.create_wallet("w1", 2)
        for op, asset, delta in (
            ("a1", "btc", 100),
            ("a2", "btc", -30),
            ("a3", "eth", 7),
        ):
            code, _ = self.svc.create_asset_operation(
                "w1", op, asset, delta
            )
            self.assertEqual(code, 201)
            code, _ = self.svc.commit_asset_operation("w1", op)
            self.assertEqual(code, 201)

    def test_listing_stable_across_restart(self):
        self._build()
        tail = self.svc.get_audit_events("w1")["events"][-1]["seq"]
        expected = [
            self.svc.list_assets("w1", at_seq=[str(seq)])
            for seq in range(tail + 1)
        ]
        h2 = make_harness(self.d)
        for seq, want in enumerate(expected):
            self.assertEqual(
                h2.service.list_assets("w1", at_seq=[str(seq)]), want
            )

    def test_listing_stable_after_dr_restore(self):
        from threshold_wallet import drbackup
        self._build()
        tail = self.svc.get_audit_events("w1")["events"][-1]["seq"]
        expected = [
            self.svc.list_assets("w1", at_seq=[str(seq)])
            for seq in range(tail + 1)
        ]
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
        for seq, want in enumerate(expected):
            self.assertEqual(
                h2.service.list_assets("w1", at_seq=[str(seq)]), want
            )


class CorruptAuditTest(_HttpBase):
    """审计链不可对账时 fail-closed 503，不返回部分结果。"""

    def _tamper(self, mutate):
        import os
        path = os.path.join(self.tmpdir, "audit", "w1.json")
        with open(path, encoding="utf-8") as handle:
            data = json.load(handle)
        mutate(data)
        with open(path, "w", encoding="utf-8") as handle:
            json.dump(data, handle)

    def test_tampered_chain_head_returns_503(self):
        self._create("a1", "btc", 100)
        self._commit("a1")
        self._tamper(lambda data: data["chain"].update(head="a" * 64))
        status, body = self._assets()
        self.assertEqual(status, 503)
        self.assertEqual(body["error"], "service temporarily unavailable")
        self.assertNotIn("assets", body)

    def test_missing_chain_metadata_returns_503(self):
        self._create("a1", "btc", 100)
        self._commit("a1")
        self._tamper(lambda data: data.pop("chain"))
        status, body = self._assets()
        self.assertEqual(status, 503)
        self.assertEqual(body["error"], "service temporarily unavailable")

    def test_corrupt_audit_json_returns_503(self):
        import os
        self._create("a1", "btc", 100)
        self._commit("a1")
        path = os.path.join(self.tmpdir, "audit", "w1.json")
        with open(path, "w", encoding="utf-8") as handle:
            handle.write("{not json")
        status, body = self._assets()
        self.assertEqual(status, 503)
        self.assertEqual(body["error"], "service temporarily unavailable")


if __name__ == "__main__":
    unittest.main()
