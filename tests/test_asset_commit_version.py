"""人工提交的可选乐观版本校验（expected_version）测试。

覆盖：
- 零字节请求体沿用旧的无条件提交语义（201/200 不变）；
- 非空体只接受恰含 expected_version 的 JSON 对象，值为非布尔非负整数，
  非对象/缺键/夹带/类型非法一律 400；
- pending 且版本一致才提交（201），不一致 409 且错误体固定为
  {"error":"asset version conflict"}，操作保持 pending，余额/version/
  审计事件/摘要链不变，可用新版本重试；
- committed 重放不重新比较 expected_version，仍按原幂等规则 200；
- 多个 pending 操作声明同一版本时至多一个 201，其余 409 保持 pending；
- 0 表示资产尚无提交版本；钱包/操作不存在仍按既有 404 顺序。
"""

from __future__ import annotations

import json
import shutil
import tempfile
import threading
import unittest
import urllib.error
import urllib.request

from tests.helpers import http_server


class CommitExpectedVersionTest(unittest.TestCase):
    """POST .../asset-operations/{oid}/commit 的 expected_version 语义。"""

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

    def _create(self, operation_id, asset_id="btc", delta=100):
        status, body = self.srv.request(
            "POST",
            "/v1/wallets/w1/asset-operations",
            {"operation_id": operation_id, "asset_id": asset_id,
             "delta": delta},
        )
        self.assertEqual(status, 201)
        return body

    def _commit(self, operation_id, body=None, wallet_id="w1"):
        if body is None:
            return self.srv.request(
                "POST",
                f"/v1/wallets/{wallet_id}/asset-operations/"
                f"{operation_id}/commit",
            )
        return self.srv.request(
            "POST",
            f"/v1/wallets/{wallet_id}/asset-operations/"
            f"{operation_id}/commit",
            body,
        )

    def _commit_raw(self, operation_id, raw):
        req = urllib.request.Request(
            self.srv.base_url
            + f"/v1/wallets/w1/asset-operations/{operation_id}/commit",
            data=raw,
            method="POST",
            headers={"Content-Type": "application/json"},
        )
        try:
            with urllib.request.urlopen(req) as resp:
                return resp.status, json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            return exc.code, json.loads(exc.read().decode("utf-8"))

    def _asset(self, asset_id="btc"):
        return self.srv.request("GET", f"/v1/wallets/w1/assets/{asset_id}")

    def _committed_events(self):
        _, events = self.srv.request("GET", "/v1/wallets/w1/audit-events")
        return [
            e
            for e in events["events"]
            if e["type"] == "asset_operation_committed"
        ]

    # ---- 兼容：零字节体无条件提交 --------------------------------------

    def test_zero_byte_body_keeps_unconditional_commit(self):
        self._create("op1")
        status, body = self._commit("op1")
        self.assertEqual(status, 201)
        self.assertEqual(body["state"], "committed")
        self.assertEqual((body["balance"], body["version"]), (100, 1))
        status, replay = self._commit("op1")
        self.assertEqual(status, 200)
        self.assertEqual(replay, body)

    # ---- 版本一致：正常提交 ---------------------------------------------

    def test_expected_version_zero_on_fresh_asset_commits(self):
        self._create("op1")
        status, body = self._commit("op1", {"expected_version": 0})
        self.assertEqual(status, 201)
        self.assertEqual((body["balance"], body["version"]), (100, 1))

    def test_expected_version_match_after_prior_commit(self):
        self._create("op1")
        self._create("op2", delta=50)
        status, _ = self._commit("op1", {"expected_version": 0})
        self.assertEqual(status, 201)
        status, body = self._commit("op2", {"expected_version": 1})
        self.assertEqual(status, 201)
        self.assertEqual((body["balance"], body["version"]), (150, 2))

    # ---- 版本冲突：409 固定错误体且零副作用 ----------------------------

    def test_version_conflict_409_fixed_body_and_no_side_effects(self):
        self._create("op1")
        self._create("op2", delta=50)
        self.assertEqual(self._commit("op1")[0], 201)
        status, body = self._commit("op2", {"expected_version": 0})
        self.assertEqual(status, 409)
        self.assertEqual(body, {"error": "asset version conflict"})
        # 操作仍为 pending，余额/version 不变，无新增提交事件
        _, op = self.srv.request(
            "GET", "/v1/wallets/w1/asset-operations/op2"
        )
        self.assertEqual(op["state"], "pending")
        _, asset = self._asset()
        self.assertEqual((asset["balance"], asset["version"]), (100, 1))
        self.assertEqual(len(self._committed_events()), 1)
        # 用新版本重试成功
        status, committed = self._commit("op2", {"expected_version": 1})
        self.assertEqual(status, 201)
        self.assertEqual(
            (committed["balance"], committed["version"]), (150, 2)
        )

    def test_expected_version_zero_conflicts_when_asset_versioned(self):
        self._create("op1")
        self.assertEqual(self._commit("op1")[0], 201)
        self._create("op2", delta=10)
        status, body = self._commit("op2", {"expected_version": 0})
        self.assertEqual(status, 409)
        self.assertEqual(body, {"error": "asset version conflict"})

    def test_stale_expected_version_after_other_asset_unaffected(self):
        # 不同资产的 version 互不影响
        self._create("op1", asset_id="btc")
        self._create("op2", asset_id="eth", delta=7)
        self.assertEqual(self._commit("op1")[0], 201)
        status, body = self._commit("op2", {"expected_version": 0})
        self.assertEqual(status, 201)
        self.assertEqual((body["balance"], body["version"]), (7, 1))

    # ---- committed 重放不重新比较 ---------------------------------------

    def test_committed_replay_ignores_expected_version(self):
        self._create("op1")
        status, committed = self._commit("op1", {"expected_version": 0})
        self.assertEqual(status, 201)
        # 重放携带任何合法 expected_version 都按原幂等规则 200 同体
        for version in (0, 1, 99):
            status, body = self._commit(
                "op1", {"expected_version": version}
            )
            self.assertEqual(status, 200)
            self.assertEqual(body, committed)
        self.assertEqual(len(self._committed_events()), 1)

    # ---- 同一版本多操作竞争：至多一个 201 -------------------------------

    def test_two_pending_ops_same_version_only_one_commits(self):
        self._create("op1", delta=10)
        self._create("op2", delta=5)
        status, _ = self._commit("op1", {"expected_version": 0})
        self.assertEqual(status, 201)
        status, body = self._commit("op2", {"expected_version": 0})
        self.assertEqual(status, 409)
        self.assertEqual(body, {"error": "asset version conflict"})
        _, op = self.srv.request(
            "GET", "/v1/wallets/w1/asset-operations/op2"
        )
        self.assertEqual(op["state"], "pending")
        # 用新版本重试成功
        status, committed = self._commit("op2", {"expected_version": 1})
        self.assertEqual(status, 201)
        self.assertEqual(
            (committed["balance"], committed["version"]), (15, 2)
        )

    def test_concurrent_same_version_exactly_one_201(self):
        self._create("op1", delta=10)
        self._create("op2", delta=5)
        barrier = threading.Barrier(2)
        results = []

        def worker(op):
            barrier.wait()
            results.append(
                self._commit(op, {"expected_version": 0})
            )

        threads = [
            threading.Thread(target=worker, args=(op,))
            for op in ("op1", "op2")
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        statuses = sorted(status for status, _ in results)
        self.assertEqual(statuses, [201, 409])
        conflict = [b for s, b in results if s == 409][0]
        self.assertEqual(conflict, {"error": "asset version conflict"})
        # 恰一次提交事件、version 只跳一次
        self.assertEqual(len(self._committed_events()), 1)
        _, asset = self._asset()
        self.assertEqual(asset["version"], 1)

    # ---- 既有 409 语义保持不变 ------------------------------------------

    def test_insufficient_balance_409_unchanged_with_matching_version(self):
        self._create("op1", delta=-50)
        status, body = self._commit("op1", {"expected_version": 0})
        self.assertEqual(status, 409)
        self.assertNotEqual(body, {"error": "asset version conflict"})
        _, op = self.srv.request(
            "GET", "/v1/wallets/w1/asset-operations/op1"
        )
        self.assertEqual(op["state"], "pending")

    # ---- 请求体校验：400 -------------------------------------------------

    def test_empty_object_body_is_400(self):
        self._create("op1")
        status, _ = self._commit("op1", {})
        self.assertEqual(status, 400)

    def test_extra_field_is_400(self):
        self._create("op1")
        status, _ = self._commit(
            "op1", {"expected_version": 0, "other": 1}
        )
        self.assertEqual(status, 400)

    def test_non_object_body_is_400(self):
        self._create("op1")
        for raw in (b"[1]", b'"x"', b"1", b"null"):
            status, _ = self._commit_raw("op1", raw)
            self.assertEqual(status, 400, raw)

    def test_malformed_json_body_is_400(self):
        self._create("op1")
        status, _ = self._commit_raw("op1", b"{not-json")
        self.assertEqual(status, 400)

    def test_invalid_expected_version_types_are_400(self):
        self._create("op1")
        for value in (True, False, None, -1, 1.5, "1", [0], {"v": 0}):
            status, _ = self._commit("op1", {"expected_version": value})
            self.assertEqual(status, 400, value)
        # 全部失败后操作仍 pending、无提交事件
        _, op = self.srv.request(
            "GET", "/v1/wallets/w1/asset-operations/op1"
        )
        self.assertEqual(op["state"], "pending")
        self.assertEqual(self._committed_events(), [])

    # ---- 404 顺序保持不变 ------------------------------------------------

    def test_missing_wallet_still_404(self):
        status, _ = self._commit(
            "op1", {"expected_version": 0}, wallet_id="nope"
        )
        self.assertEqual(status, 404)

    def test_missing_operation_still_404(self):
        status, _ = self._commit("nope", {"expected_version": 0})
        self.assertEqual(status, 404)
        status, _ = self._commit("nope")
        self.assertEqual(status, 404)


if __name__ == "__main__":
    unittest.main()
