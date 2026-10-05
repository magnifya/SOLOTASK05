"""资产一致性校验（POST /v1/wallets/{id}/asset-consistency）测试。

覆盖：
- 成功 200：八键报告视图（wallet_id/at_seq/head/state_root/matched/
  missing/mismatched/unexpected）；快照与实际一致时 matched=true、
  三数组为空；state_root 为按 asset_id ASCII 升序的
  {asset_id,balance,version} 记录数组经紧凑 UTF-8 JSON 的 SHA-256；
- 差异分类：missing 只含标识、unexpected 回显提交的三字段记录、
  mismatched 同时给出期望与实际 balance/version，三者均按标识升序；
- at_seq/expected_head 沿用资产清单语义：缺省取尾序号、0 为空前缀、
  expected_head 只能随 at_seq 且须 64 位小写十六进制；
- 400：重复查询参数、at_seq/expected_head 非法、请求体形状/键集/
  标识/balance/version 非法、asset_id 重复；404：钱包不存在（优先于
  请求校验）、边界越尾；409：expected_head 不符；
- 方法 405；冻结期间仍可校验；纯只读不新增事件；重启后同一边界结果
  一致。
"""

from __future__ import annotations

import hashlib
import json
import shutil
import tempfile
import unittest
import urllib.error
import urllib.request

from tests.helpers import http_server

ZERO_HEAD = "0" * 64


def state_root_of(records):
    """按契约独立计算状态根：记录按 asset_id 升序、固定三字段、紧凑
    UTF-8 JSON 的 SHA-256 小写十六进制。"""
    ordered = sorted(records, key=lambda r: r["asset_id"])
    payload = json.dumps(
        [
            {
                "asset_id": r["asset_id"],
                "balance": r["balance"],
                "version": r["version"],
            }
            for r in ordered
        ],
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


class AssetConsistencyHttpTest(unittest.TestCase):
    """HTTP 层语义：状态码、响应体、校验次序与只读性。"""

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
        self._fund("btc", 100)
        self._fund("eth", 50)

    # ---- 辅助 -----------------------------------------------------------

    def _fund(self, asset_id, amount):
        op = f"fund-{asset_id}"
        status, _ = self.srv.request(
            "POST",
            "/v1/wallets/w1/asset-operations",
            {"operation_id": op, "asset_id": asset_id, "delta": amount},
        )
        self.assertEqual(status, 201)
        status, _ = self.srv.request(
            "POST", f"/v1/wallets/w1/asset-operations/{op}/commit"
        )
        self.assertEqual(status, 201)

    def _check(self, assets, query="", wallet_id="w1"):
        return self.srv.request(
            "POST",
            f"/v1/wallets/{wallet_id}/asset-consistency{query}",
            {"assets": assets},
        )

    def _check_raw(self, raw, query="", wallet_id="w1", method="POST"):
        req = urllib.request.Request(
            self.srv.base_url
            + f"/v1/wallets/{wallet_id}/asset-consistency{query}",
            data=raw,
            method=method,
            headers={"Content-Type": "application/json"},
        )
        try:
            with urllib.request.urlopen(req) as resp:
                return resp.status, json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            return exc.code, json.loads(exc.read().decode("utf-8"))

    def _tail(self):
        status, events = self.srv.request(
            "GET", "/v1/wallets/w1/audit-events"
        )
        self.assertEqual(status, 200)
        return len(events["events"])

    def _head_at(self, seq):
        status, ev = self.srv.request(
            "GET", f"/v1/wallets/w1/audit-evidence?from_seq=1&to_seq={seq}"
        )
        self.assertEqual(status, 200)
        return ev["end_head"]

    # ---- 成功路径 ---------------------------------------------------------

    def test_matched_snapshot_returns_200_and_state_root(self):
        tail = self._tail()
        snapshot = [
            {"asset_id": "btc", "balance": 100, "version": 1},
            {"asset_id": "eth", "balance": 50, "version": 1},
        ]
        status, body = self._check(snapshot)
        self.assertEqual(status, 200)
        self.assertEqual(
            body,
            {
                "wallet_id": "w1",
                "at_seq": tail,
                "head": self._head_at(tail),
                "state_root": state_root_of(snapshot),
                "matched": True,
                "missing": [],
                "mismatched": [],
                "unexpected": [],
            },
        )

    def test_empty_snapshot_reports_all_missing(self):
        status, body = self._check([])
        self.assertEqual(status, 200)
        self.assertFalse(body["matched"])
        self.assertEqual(body["missing"], ["btc", "eth"])
        self.assertEqual(body["mismatched"], [])
        self.assertEqual(body["unexpected"], [])
        self.assertEqual(
            body["state_root"],
            state_root_of(
                [
                    {"asset_id": "btc", "balance": 100, "version": 1},
                    {"asset_id": "eth", "balance": 50, "version": 1},
                ]
            ),
        )

    def test_differences_are_classified_and_sorted(self):
        snapshot = [
            {"asset_id": "eth", "balance": 51, "version": 1},  # 余额不符
            {"asset_id": "btc", "balance": 100, "version": 2},  # 版本不符
            {"asset_id": "doge", "balance": 7, "version": 0},  # 实际没有
            {"asset_id": "aaa", "balance": 1, "version": 1},  # 实际没有
        ]
        status, body = self._check(snapshot)
        self.assertEqual(status, 200)
        self.assertFalse(body["matched"])
        self.assertEqual(body["missing"], [])
        self.assertEqual(
            body["mismatched"],
            [
                {
                    "asset_id": "btc",
                    "expected_balance": 100,
                    "expected_version": 2,
                    "actual_balance": 100,
                    "actual_version": 1,
                },
                {
                    "asset_id": "eth",
                    "expected_balance": 51,
                    "expected_version": 1,
                    "actual_balance": 50,
                    "actual_version": 1,
                },
            ],
        )
        self.assertEqual(
            body["unexpected"],
            [
                {"asset_id": "aaa", "balance": 1, "version": 1},
                {"asset_id": "doge", "balance": 7, "version": 0},
            ],
        )

    def test_transfer_is_reflected_at_tail(self):
        status, _ = self.srv.request(
            "POST",
            "/v1/wallets/w1/asset-transfers",
            {
                "transfer_id": "t1",
                "from_asset_id": "btc",
                "to_asset_id": "eth",
                "amount": 30,
                "expected_from_version": 1,
                "expected_to_version": 1,
            },
        )
        self.assertEqual(status, 201)
        snapshot = [
            {"asset_id": "btc", "balance": 70, "version": 2},
            {"asset_id": "eth", "balance": 80, "version": 2},
        ]
        status, body = self._check(snapshot)
        self.assertEqual(status, 200)
        self.assertTrue(body["matched"])
        self.assertEqual(body["state_root"], state_root_of(snapshot))

    # ---- at_seq / expected_head -----------------------------------------

    def test_zero_boundary_is_empty_prefix(self):
        status, body = self._check([], query="?at_seq=0")
        self.assertEqual(status, 200)
        self.assertEqual(body["at_seq"], 0)
        self.assertEqual(body["head"], ZERO_HEAD)
        self.assertEqual(body["state_root"], state_root_of([]))
        self.assertEqual(body["missing"], [])
        self.assertTrue(body["matched"])

    def test_zero_boundary_makes_snapshot_unexpected(self):
        snapshot = [{"asset_id": "btc", "balance": 100, "version": 1}]
        status, body = self._check(snapshot, query="?at_seq=0")
        self.assertEqual(status, 200)
        self.assertFalse(body["matched"])
        self.assertEqual(body["unexpected"], snapshot)
        self.assertEqual(body["missing"], [])

    def test_historical_boundary_uses_events_up_to_at_seq(self):
        # btc 的注资提交是 seq 1（eth 在 seq 2）：边界 1 只含 btc
        status, body = self._check(
            [{"asset_id": "btc", "balance": 100, "version": 1}],
            query="?at_seq=1",
        )
        self.assertEqual(status, 200)
        self.assertTrue(body["matched"])
        self.assertEqual(body["at_seq"], 1)
        self.assertEqual(body["head"], self._head_at(1))
        self.assertEqual(
            body["state_root"],
            state_root_of(
                [{"asset_id": "btc", "balance": 100, "version": 1}]
            ),
        )

    def test_expected_head_round_trip(self):
        tail = self._tail()
        head = self._head_at(tail)
        status, body = self._check(
            [], query=f"?at_seq={tail}&expected_head={head}"
        )
        self.assertEqual(status, 200)
        self.assertEqual(body["head"], head)

    def test_expected_head_mismatch_409(self):
        tail = self._tail()
        status, body = self._check(
            [], query=f"?at_seq={tail}&expected_head={'a' * 64}"
        )
        self.assertEqual(status, 409)
        self.assertEqual(
            body, {"error": "expected_head does not match chain head"}
        )

    def test_expected_head_without_at_seq_400(self):
        status, body = self._check([], query=f"?expected_head={'a' * 64}")
        self.assertEqual(status, 400)
        self.assertEqual(body, {"error": "invalid expected_head"})

    def test_expected_head_bad_format_400(self):
        for bad in ("zz" * 32, "A" * 64, "a" * 63, ""):
            status, body = self._check(
                [], query=f"?at_seq=1&expected_head={bad}"
            )
            self.assertEqual(status, 400, bad)
            self.assertEqual(body, {"error": "invalid expected_head"})

    def test_invalid_at_seq_400(self):
        for bad in ("", "-1", "1.5", "+1", "abc", "%201"):
            status, body = self._check([], query=f"?at_seq={bad}")
            self.assertEqual(status, 400, bad)
            self.assertEqual(body, {"error": "invalid at_seq"})

    def test_at_seq_beyond_tail_404(self):
        status, body = self._check([], query="?at_seq=999999")
        self.assertEqual(status, 404)
        self.assertEqual(
            body, {"error": "at_seq beyond the audit tail"}
        )

    def test_duplicate_query_parameters_400(self):
        dup_head = "?expected_head=%s&expected_head=%s" % ("a" * 64, "b" * 64)
        for query in ("?at_seq=1&at_seq=2", dup_head):
            status, body = self._check([], query=query)
            self.assertEqual(status, 400, query)
            self.assertEqual(
                body, {"error": "duplicate query parameters"}
            )

    # ---- 请求体校验 --------------------------------------------------------

    def test_body_key_set_errors_400(self):
        for body in (
            {},
            {"assets": [], "extra": 1},
            {"snapshot": []},
        ):
            status, _ = self.srv.request(
                "POST", "/v1/wallets/w1/asset-consistency", body
            )
            self.assertEqual(status, 400, body)

    def test_assets_must_be_array(self):
        status, _ = self.srv.request(
            "POST",
            "/v1/wallets/w1/asset-consistency",
            {"assets": {"btc": 1}},
        )
        self.assertEqual(status, 400)

    def test_item_key_set_errors_400(self):
        for item in (
            {"asset_id": "btc", "balance": 100},
            {"asset_id": "btc", "balance": 100, "version": 1, "x": 0},
            {"asset_id": "btc"},
            "btc",
        ):
            status, _ = self.srv.request(
                "POST",
                "/v1/wallets/w1/asset-consistency",
                {"assets": [item]},
            )
            self.assertEqual(status, 400, item)

    def test_invalid_asset_id_400(self):
        for bad in ("", "not safe!", "a" * 129, 7, None):
            status, _ = self.srv.request(
                "POST",
                "/v1/wallets/w1/asset-consistency",
                {"assets": [{"asset_id": bad, "balance": 1, "version": 1}]},
            )
            self.assertEqual(status, 400, bad)

    def test_balance_and_version_must_be_non_negative_ints(self):
        for key in ("balance", "version"):
            for bad in (-1, True, 1.5, "1", None):
                item = {"asset_id": "btc", "balance": 1, "version": 1}
                item[key] = bad
                status, _ = self.srv.request(
                    "POST",
                    "/v1/wallets/w1/asset-consistency",
                    {"assets": [item]},
                )
                self.assertEqual(status, 400, (key, bad))

    def test_duplicate_asset_id_400(self):
        status, _ = self.srv.request(
            "POST",
            "/v1/wallets/w1/asset-consistency",
            {
                "assets": [
                    {"asset_id": "btc", "balance": 1, "version": 1},
                    {"asset_id": "btc", "balance": 2, "version": 2},
                ]
            },
        )
        self.assertEqual(status, 400)

    def test_non_object_and_malformed_body_400(self):
        for raw in (b"[1,2]", b'"x"', b"null", b"{", b""):
            status, _ = self._check_raw(raw)
            self.assertEqual(status, 400, raw)

    # ---- 404/405/次序 -------------------------------------------------------

    def test_missing_wallet_404_precedes_request_validation(self):
        # 缺键体 + 非法 at_seq + 不存在钱包：一律先 404
        status, _ = self.srv.request(
            "POST",
            "/v1/wallets/nope/asset-consistency?at_seq=abc",
            {"wrong": 1},
        )
        self.assertEqual(status, 404)
        status, body = self._check_raw(b"{", wallet_id="nope")
        self.assertEqual(status, 404)
        self.assertEqual(body, {"error": "wallet 'nope' not found"})

    def test_other_methods_405(self):
        for method in ("GET", "PUT", "DELETE", "PATCH"):
            status, body = self._check_raw(None, method=method)
            self.assertEqual(status, 405, method)
            self.assertEqual(body, {"error": "method not allowed"})

    # ---- 只读/冻结/重启 ------------------------------------------------------

    def test_check_is_read_only(self):
        before = self._tail()
        self._check([])
        self._check([{"asset_id": "btc", "balance": 1, "version": 1}])
        self.assertEqual(self._tail(), before)
        # 账本余额不变
        status, asset = self.srv.request("GET", "/v1/wallets/w1/assets/btc")
        self.assertEqual(status, 200)
        self.assertEqual(
            asset, {"asset_id": "btc", "balance": 100, "version": 1}
        )

    def test_frozen_wallet_still_checkable(self):
        status, _ = self.srv.request(
            "POST", "/v1/wallets/w1/freeze", {"reason": "incident"}
        )
        self.assertEqual(status, 201)
        status, body = self._check(
            [
                {"asset_id": "btc", "balance": 100, "version": 1},
                {"asset_id": "eth", "balance": 50, "version": 1},
            ]
        )
        self.assertEqual(status, 200)
        self.assertTrue(body["matched"])

    def test_restart_preserves_boundary_result(self):
        tail = self._tail()
        status, first = self._check([], query=f"?at_seq={tail}")
        self.assertEqual(status, 200)
        # 用同一 data-dir 重启：全新 service + HTTP 服务器
        self._ctx.__exit__(None, None, None)
        self._ctx = http_server(self.tmpdir)
        self.srv = self._ctx.__enter__()
        status, second = self._check([], query=f"?at_seq={tail}")
        self.assertEqual(status, 200)
        self.assertEqual(first, second)

    def test_response_contains_no_private_material(self):
        status, body = self._check([])
        self.assertEqual(status, 200)
        text = json.dumps(body)
        for word in ("private", "share", "signature"):
            self.assertNotIn(word, text)


if __name__ == "__main__":
    unittest.main()
