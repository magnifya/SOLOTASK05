"""资产一致性校验：POST /v1/wallets/{id}/asset-consistency。

覆盖：
- 请求体恰含 {"assets":[{asset_id,balance,version},...]}；assets 可空；
  键集错误、形状错误、标识非法/重复、balance/version 非布尔非负整数
  之外取值一律 400；
- 200 恰含 wallet_id/at_seq/head/state_root/matched/missing/
  mismatched/unexpected；state_root 为按 asset_id 升序的固定字段
  记录数组经紧凑 UTF-8 JSON 的 SHA-256；missing 仅标识、unexpected
  为实际三字段记录、mismatched 同时给期望与实际值，均按标识升序；
  三者全空时 matched 为 true；
- at_seq/expected_head 沿用资产清单语义：缺省取尾序号、0 为空前缀、
  expected_head 只能随 at_seq；重复参数/非法 at_seq/非法
  expected_head 400，越尾 404，摘要不符 409；
- 钱包 404 优先于一切请求校验；冻结期间仍可校验；GET/PUT/DELETE 等
  方法 405；校验纯只读（无新事件、账本不变）；重启后同一 at_seq
  结果一致。
"""

from __future__ import annotations

import hashlib
import json
import shutil
import tempfile
import unittest

from tests.helpers import http_server, make_harness

ZERO_HEAD = "0" * 64


def _state_root(records):
    payload = json.dumps(
        records, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


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
        status, body = self.srv.request(
            "POST",
            f"/v1/wallets/{wallet}/asset-operations/"
            f"{operation_id}/commit",
        )
        assert status == 201, body
        return body

    def _transfer(self, transfer_id, from_id, to_id, amount,
                  from_version, to_version, wallet="w1"):
        status, body = self.srv.request(
            "POST",
            f"/v1/wallets/{wallet}/asset-transfers",
            {
                "transfer_id": transfer_id,
                "from_asset_id": from_id,
                "to_asset_id": to_id,
                "amount": amount,
                "expected_from_version": from_version,
                "expected_to_version": to_version,
            },
        )
        assert status == 201, body
        return body

    def _check(self, assets, query="", wallet="w1"):
        suffix = f"?{query}" if query else ""
        return self.srv.request(
            "POST",
            f"/v1/wallets/{wallet}/asset-consistency{suffix}",
            {"assets": assets},
        )

    def _events(self, wallet="w1"):
        status, body = self.srv.request(
            "GET", f"/v1/wallets/{wallet}/audit-events"
        )
        assert status == 200, body
        return body["events"]

    def _tail_seq(self, wallet="w1"):
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


class MatchedReportTest(_HttpBase):
    def test_empty_wallet_empty_assets_matched(self):
        status, body = self._check([])
        self.assertEqual(status, 200)
        self.assertEqual(
            body,
            {
                "wallet_id": "w1",
                "at_seq": 0,
                "head": ZERO_HEAD,
                "state_root": _state_root([]),
                "matched": True,
                "missing": [],
                "mismatched": [],
                "unexpected": [],
            },
        )

    def test_full_snapshot_matched(self):
        self._create("op1", "btc", 100)
        self._commit("op1")
        self._create("op2", "eth", 50)
        self._commit("op2")
        self._transfer("t1", "btc", "eth", 30, 1, 1)
        tail = self._tail_seq()
        status, body = self._check(
            [
                {"asset_id": "btc", "balance": 70, "version": 2},
                {"asset_id": "eth", "balance": 80, "version": 2},
            ]
        )
        self.assertEqual(status, 200)
        self.assertEqual(
            body,
            {
                "wallet_id": "w1",
                "at_seq": tail,
                "head": self._head_at(tail),
                "state_root": _state_root(
                    [
                        {"asset_id": "btc", "balance": 70, "version": 2},
                        {"asset_id": "eth", "balance": 80, "version": 2},
                    ]
                ),
                "matched": True,
                "missing": [],
                "mismatched": [],
                "unexpected": [],
            },
        )

    def test_zero_balance_asset_still_listed(self):
        self._create("op1", "btc", 100)
        self._commit("op1")
        self._create("op2", "btc", -100)
        self._commit("op2")
        status, body = self._check(
            [{"asset_id": "btc", "balance": 0, "version": 2}]
        )
        self.assertEqual(status, 200)
        self.assertTrue(body["matched"])
        self.assertEqual(
            body["state_root"],
            _state_root(
                [{"asset_id": "btc", "balance": 0, "version": 2}]
            ),
        )


class MismatchReportTest(_HttpBase):
    def setUp(self):
        super().setUp()
        self._create("op1", "btc", 100)
        self._commit("op1")
        self._create("op2", "eth", 50)
        self._commit("op2")

    def test_missing_only_identifier_sorted(self):
        status, body = self._check(
            [
                {"asset_id": "btc", "balance": 100, "version": 1},
                {"asset_id": "eth", "balance": 50, "version": 1},
                {"asset_id": "usdt", "balance": 5, "version": 1},
                {"asset_id": "doge", "balance": 5, "version": 1},
            ]
        )
        self.assertEqual(status, 200)
        self.assertFalse(body["matched"])
        self.assertEqual(body["missing"], ["doge", "usdt"])
        self.assertEqual(body["mismatched"], [])
        self.assertEqual(body["unexpected"], [])

    def test_unexpected_is_actual_record_sorted(self):
        status, body = self._check([])
        self.assertEqual(status, 200)
        self.assertFalse(body["matched"])
        self.assertEqual(body["missing"], [])
        self.assertEqual(body["mismatched"], [])
        self.assertEqual(
            body["unexpected"],
            [
                {"asset_id": "btc", "balance": 100, "version": 1},
                {"asset_id": "eth", "balance": 50, "version": 1},
            ],
        )

    def test_mismatched_gives_expected_and_actual(self):
        status, body = self._check(
            [
                {"asset_id": "btc", "balance": 99, "version": 1},
                {"asset_id": "eth", "balance": 50, "version": 7},
            ]
        )
        self.assertEqual(status, 200)
        self.assertFalse(body["matched"])
        self.assertEqual(body["missing"], [])
        self.assertEqual(body["unexpected"], [])
        self.assertEqual(
            body["mismatched"],
            [
                {
                    "asset_id": "btc",
                    "expected_balance": 99,
                    "expected_version": 1,
                    "actual_balance": 100,
                    "actual_version": 1,
                },
                {
                    "asset_id": "eth",
                    "expected_balance": 50,
                    "expected_version": 7,
                    "actual_balance": 50,
                    "actual_version": 1,
                },
            ],
        )

    def test_all_three_categories_together(self):
        status, body = self._check(
            [
                {"asset_id": "btc", "balance": 1, "version": 1},
                {"asset_id": "usdt", "balance": 5, "version": 1},
            ]
        )
        self.assertEqual(status, 200)
        self.assertFalse(body["matched"])
        self.assertEqual(body["missing"], ["usdt"])
        self.assertEqual(
            body["mismatched"],
            [
                {
                    "asset_id": "btc",
                    "expected_balance": 1,
                    "expected_version": 1,
                    "actual_balance": 100,
                    "actual_version": 1,
                }
            ],
        )
        self.assertEqual(
            body["unexpected"],
            [{"asset_id": "eth", "balance": 50, "version": 1}],
        )


class BoundaryTest(_HttpBase):
    def setUp(self):
        super().setUp()
        self._create("op1", "btc", 100)
        self._commit("op1")
        self._create("op2", "eth", 50)
        self._commit("op2")

    def _committed_seqs(self):
        return [
            e["seq"]
            for e in self._events()
            if e["type"] == "asset_operation_committed"
        ]

    def test_explicit_zero_boundary_is_empty_prefix(self):
        status, body = self._check([], "at_seq=0")
        self.assertEqual(status, 200)
        self.assertEqual(body["at_seq"], 0)
        self.assertEqual(body["head"], ZERO_HEAD)
        self.assertEqual(body["state_root"], _state_root([]))
        self.assertTrue(body["matched"])

    def test_zero_boundary_actual_assets_unexpected(self):
        status, body = self._check([], "at_seq=0")
        self.assertEqual(status, 200)
        # 零边界实际状态为空：快照为空即 matched
        self.assertEqual(body["unexpected"], [])
        status, body = self._check(
            [{"asset_id": "btc", "balance": 100, "version": 1}],
            "at_seq=0",
        )
        self.assertEqual(status, 200)
        self.assertEqual(body["missing"], ["btc"])

    def test_historical_boundary_uses_last_committed_record(self):
        first_seq = self._committed_seqs()[0]
        status, body = self._check(
            [{"asset_id": "btc", "balance": 100, "version": 1}],
            f"at_seq={first_seq}",
        )
        self.assertEqual(status, 200)
        self.assertEqual(body["at_seq"], first_seq)
        self.assertEqual(body["head"], self._head_at(first_seq))
        self.assertTrue(body["matched"])
        self.assertEqual(
            body["state_root"],
            _state_root(
                [{"asset_id": "btc", "balance": 100, "version": 1}]
            ),
        )

    def test_default_boundary_is_audit_tail(self):
        tail = self._tail_seq()
        status, body = self._check([])
        self.assertEqual(status, 200)
        self.assertEqual(body["at_seq"], tail)
        self.assertEqual(body["head"], self._head_at(tail))

    def test_expected_head_accepted_with_at_seq(self):
        tail = self._tail_seq()
        head = self._head_at(tail)
        status, body = self._check(
            [], f"at_seq={tail}&expected_head={head}"
        )
        self.assertEqual(status, 200)
        self.assertEqual(body["head"], head)

    def test_expected_head_mismatch_409(self):
        tail = self._tail_seq()
        bad = "a" * 64
        status, body = self._check(
            [], f"at_seq={tail}&expected_head={bad}"
        )
        self.assertEqual(status, 409)
        self.assertEqual(
            body, {"error": "expected_head does not match chain head"}
        )

    def test_expected_head_without_at_seq_400(self):
        status, body = self._check([], f"expected_head={'a' * 64}")
        self.assertEqual(status, 400)
        self.assertEqual(body, {"error": "invalid expected_head"})

    def test_expected_head_bad_format_400(self):
        for bad in ("xyz", "A" * 64, "a" * 63, ""):
            status, body = self._check(
                [], f"at_seq=1&expected_head={bad}"
            )
            self.assertEqual(status, 400, bad)
            self.assertEqual(body, {"error": "invalid expected_head"})

    def test_at_seq_invalid_400(self):
        for bad in ("", "abc", "-1", "1.5", "+1", "%201"):
            status, body = self._check([], f"at_seq={bad}")
            self.assertEqual(status, 400, bad)
            self.assertEqual(body, {"error": "invalid at_seq"})

    def test_at_seq_beyond_tail_404(self):
        tail = self._tail_seq()
        status, body = self._check([], f"at_seq={tail + 1}")
        self.assertEqual(status, 404)
        self.assertEqual(
            body, {"error": "at_seq beyond the audit tail"}
        )

    def test_duplicate_query_parameters_400(self):
        status, body = self._check([], "at_seq=1&at_seq=2")
        self.assertEqual(status, 400)
        self.assertEqual(body, {"error": "duplicate query parameters"})
        status, body = self._check(
            [], f"at_seq=1&expected_head={'a' * 64}&expected_head={'b' * 64}"
        )
        self.assertEqual(status, 400)
        self.assertEqual(body, {"error": "duplicate query parameters"})


class BodyValidationTest(_HttpBase):
    def _raw(self, body, wallet="w1"):
        return self.srv.request(
            "POST", f"/v1/wallets/{wallet}/asset-consistency", body
        )

    def test_body_key_set_must_be_exactly_assets(self):
        for body in (
            {},
            {"assets": [], "extra": 1},
            {"snapshot": []},
        ):
            status, _ = self._raw(body)
            self.assertEqual(status, 400, body)

    def test_assets_must_be_array(self):
        for body in (
            {"assets": {}},
            {"assets": "btc"},
            {"assets": None},
            {"assets": 1},
        ):
            status, _ = self._raw(body)
            self.assertEqual(status, 400, body)

    def test_item_key_set_must_be_exact(self):
        for item in (
            {},
            {"asset_id": "btc", "balance": 1},
            {"asset_id": "btc", "balance": 1, "version": 1, "x": 0},
            {"asset_id": "btc", "balance": 1, "state": "committed"},
        ):
            status, _ = self._raw({"assets": [item]})
            self.assertEqual(status, 400, item)

    def test_asset_id_must_follow_identifier_rules(self):
        for bad in ("", "a b", "btc!", "btc/eth", 1, None, "x" * 129):
            status, _ = self._raw(
                {"assets": [
                    {"asset_id": bad, "balance": 1, "version": 1}
                ]}
            )
            self.assertEqual(status, 400, bad)

    def test_balance_and_version_non_bool_non_negative_int(self):
        for key in ("balance", "version"):
            for bad in (True, False, -1, 1.5, "1", None):
                item = {"asset_id": "btc", "balance": 1, "version": 1}
                item[key] = bad
                status, _ = self._raw({"assets": [item]})
                self.assertEqual(status, 400, (key, bad))

    def test_duplicate_asset_id_400(self):
        status, _ = self._raw(
            {
                "assets": [
                    {"asset_id": "btc", "balance": 1, "version": 1},
                    {"asset_id": "btc", "balance": 2, "version": 1},
                ]
            }
        )
        self.assertEqual(status, 400)

    def test_non_object_body_400(self):
        import urllib.error
        import urllib.request

        for raw in (b"[1,2]", b"null", b"{bad json", b""):
            req = urllib.request.Request(
                self.srv.base_url + "/v1/wallets/w1/asset-consistency",
                data=raw,
                method="POST",
                headers={"Content-Type": "application/json"},
            )
            try:
                with urllib.request.urlopen(req) as resp:
                    status = resp.status
            except urllib.error.HTTPError as exc:
                status = exc.code
            self.assertEqual(status, 400, raw)


class PriorityAndMethodTest(_HttpBase):
    def test_wallet_404_precedes_request_validation(self):
        # 不存在的钱包 + 各类非法请求：一律 404
        bad_bodies = (
            {},
            {"assets": [{"asset_id": "a b", "balance": -1}]},
            {
                "assets": [
                    {"asset_id": "btc", "balance": 1, "version": 1},
                    {"asset_id": "btc", "balance": 1, "version": 1},
                ]
            },
        )
        for body in bad_bodies:
            status, _ = self.srv.request(
                "POST", "/v1/wallets/ghost/asset-consistency", body
            )
            self.assertEqual(status, 404, body)
        status, _ = self.srv.request(
            "POST", "/v1/wallets/ghost/asset-consistency?at_seq=abc",
            {"assets": []},
        )
        self.assertEqual(status, 404)
        status, _ = self.srv.request(
            "POST",
            "/v1/wallets/ghost/asset-consistency?at_seq=1&at_seq=2",
            {"assets": []},
        )
        self.assertEqual(status, 404)

    def test_wallet_404_precedes_malformed_json(self):
        import urllib.error
        import urllib.request

        req = urllib.request.Request(
            self.srv.base_url + "/v1/wallets/ghost/asset-consistency",
            data=b"{bad json",
            method="POST",
            headers={"Content-Type": "application/json"},
        )
        try:
            with urllib.request.urlopen(req) as resp:
                status = resp.status
        except urllib.error.HTTPError as exc:
            status = exc.code
        self.assertEqual(status, 404)

    def test_other_methods_405(self):
        for method in ("GET", "PUT", "DELETE", "PATCH"):
            status, _ = self.srv.request(
                method, "/v1/wallets/w1/asset-consistency"
            )
            self.assertEqual(status, 405, method)
            status, _ = self.srv.request(
                method, "/v1/wallets/ghost/asset-consistency"
            )
            self.assertEqual(status, 405, (method, "ghost"))

    def test_frozen_wallet_still_checkable(self):
        self._create("op1", "btc", 100)
        self._commit("op1")
        status, _ = self.srv.request(
            "POST", "/v1/wallets/w1/freeze", {"reason": "incident"}
        )
        self.assertEqual(status, 201)
        status, body = self._check(
            [{"asset_id": "btc", "balance": 100, "version": 1}]
        )
        self.assertEqual(status, 200)
        self.assertTrue(body["matched"])


class ReadOnlyAndRestartTest(_HttpBase):
    def test_check_is_read_only(self):
        self._create("op1", "btc", 100)
        self._commit("op1")
        before_events = self._events()
        status, asset_before = self.srv.request(
            "GET", "/v1/wallets/w1/assets/btc"
        )
        self.assertEqual(status, 200)
        status, body = self._check(
            [{"asset_id": "btc", "balance": 100, "version": 1}]
        )
        self.assertEqual(status, 200)
        self.assertEqual(self._events(), before_events)
        status, asset_after = self.srv.request(
            "GET", "/v1/wallets/w1/assets/btc"
        )
        self.assertEqual(status, 200)
        self.assertEqual(asset_before, asset_after)

    def test_same_at_seq_consistent_after_restart(self):
        self._create("op1", "btc", 100)
        self._commit("op1")
        self._create("op2", "eth", 50)
        self._commit("op2")
        tail = self._tail_seq()
        snapshot = [
            {"asset_id": "btc", "balance": 100, "version": 1},
            {"asset_id": "eth", "balance": 50, "version": 1},
        ]
        status, first = self._check(snapshot, f"at_seq={tail}")
        self.assertEqual(status, 200)
        # 同一数据目录上重建 service（模拟重启），同一 at_seq 结果一致
        restarted = make_harness(self.tmpdir)
        again = restarted.service.check_asset_consistency(
            "w1", {"assets": snapshot}, [str(tail)], None
        )
        self.assertEqual(again, first)


if __name__ == "__main__":
    unittest.main()
