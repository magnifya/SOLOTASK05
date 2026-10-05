"""人工提交的可选乐观版本校验（expected_version）测试。

覆盖：
- 零字节请求体沿用旧的无条件提交语义（201）；
- 非空请求体只接受恰含 expected_version 的 JSON 对象（非布尔的非负
  整数，0 表示资产尚无提交版本）；非对象、缺失或夹带字段、类型非法
  均 400；
- pending 操作版本一致才提交（201），不一致 409 且错误体固定为
  {"error":"asset version conflict"}，操作保持 pending、余额/version/
  审计事件不变，可用新版本重试；
- committed 重放不重新比较 expected_version，仍按原幂等规则 200；
- 钱包/操作不存在仍按既有 404 顺序；
- 并发声明同一版本时至多一个 201，其余 409 保持 pending。
"""

from __future__ import annotations

import json
import shutil
import tempfile
import threading
import urllib.error
import urllib.request
import unittest

from tests.helpers import http_server


class CommitExpectedVersionTest(unittest.TestCase):
    """POST .../asset-operations/{id}/commit 的 expected_version 校验。"""

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

    def _create(self, operation_id, asset_id, delta):
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

    def _commit(self, operation_id, body=None, wallet_id="w1"):
        return self.srv.request(
            "POST",
            f"/v1/wallets/{wallet_id}/asset-operations/{operation_id}/commit",
            body,
        )

    def _commit_raw(self, operation_id, raw, wallet_id="w1"):
        req = urllib.request.Request(
            self.srv.base_url
            + f"/v1/wallets/{wallet_id}/asset-operations/{operation_id}/commit",
            data=raw,
            method="POST",
            headers={"Content-Type": "application/json"},
        )
        try:
            with urllib.request.urlopen(req) as resp:
                return resp.status, json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            return exc.code, json.loads(exc.read().decode("utf-8"))

    def _asset(self, asset_id, wallet_id="w1"):
        return self.srv.request(
            "GET", f"/v1/wallets/{wallet_id}/assets/{asset_id}"
        )

    def _committed_events(self):
        status, body = self.srv.request(
            "GET", "/v1/wallets/w1/audit-events"
        )
        self.assertEqual(status, 200)
        events = body["events"] if isinstance(body, dict) else body
        return [
            e for e in events if e["type"] == "asset_operation_committed"
        ]

    # ---- 请求体形状与类型校验（400） ------------------------------------

    def test_empty_object_body_returns_400(self):
        self._create("op1", "btc", 100)
        status, _ = self._commit("op1", {})
        self.assertEqual(status, 400)

    def test_extra_field_returns_400(self):
        self._create("op1", "btc", 100)
        status, _ = self._commit(
            "op1", {"expected_version": 0, "other": 1}
        )
        self.assertEqual(status, 400)

    def test_non_object_body_returns_400(self):
        self._create("op1", "btc", 100)
        for body in ([1], "x", 1, True):
            status, _ = self._commit("op1", body)
            self.assertEqual(status, 400, body)

    def test_invalid_json_body_returns_400(self):
        self._create("op1", "btc", 100)
        status, _ = self._commit_raw("op1", b"{not json")
        self.assertEqual(status, 400)

    def test_illegal_expected_version_types_return_400(self):
        self._create("op1", "btc", 100)
        for value in (True, False, -1, 1.5, "0", None):
            status, _ = self._commit("op1", {"expected_version": value})
            self.assertEqual(status, 400, value)
        # 非法请求零副作用：操作仍 pending，可无体提交成功
        status, body = self._commit("op1")
        self.assertEqual(status, 201)
        self.assertEqual(body["state"], "committed")

    # ---- 版本校验语义 ----------------------------------------------------

    def test_zero_byte_body_keeps_unconditional_commit(self):
        self._create("op1", "btc", 100)
        status, body = self._commit("op1")
        self.assertEqual(status, 201)
        self.assertEqual(body["version"], 1)

    def test_expected_version_zero_commits_fresh_asset(self):
        self._create("op1", "btc", 100)
        status, body = self._commit("op1", {"expected_version": 0})
        self.assertEqual(status, 201)
        self.assertEqual(body["state"], "committed")
        self.assertEqual(body["balance"], 100)
        self.assertEqual(body["version"], 1)

    def test_matching_expected_version_commits(self):
        self._create("op1", "btc", 100)
        self._create("op2", "btc", 50)
        status, _ = self._commit("op1", {"expected_version": 0})
        self.assertEqual(status, 201)
        status, body = self._commit("op2", {"expected_version": 1})
        self.assertEqual(status, 201)
        self.assertEqual(body["balance"], 150)
        self.assertEqual(body["version"], 2)

    def test_version_conflict_returns_409_fixed_body_and_no_side_effects(
        self,
    ):
        self._create("op1", "btc", 100)
        self._create("op2", "btc", 50)
        status, _ = self._commit("op1", {"expected_version": 0})
        self.assertEqual(status, 201)
        events_before = self._committed_events()

        status, body = self._commit("op2", {"expected_version": 0})
        self.assertEqual(status, 409)
        self.assertEqual(body, {"error": "asset version conflict"})

        # 操作保持 pending，余额/version 不变，无新增提交事件
        status, op = self.srv.request(
            "GET", "/v1/wallets/w1/asset-operations/op2"
        )
        self.assertEqual(status, 200)
        self.assertEqual(op["state"], "pending")
        status, asset = self._asset("btc")
        self.assertEqual(status, 200)
        self.assertEqual(asset["balance"], 100)
        self.assertEqual(asset["version"], 1)
        self.assertEqual(self._committed_events(), events_before)

        # 可用新版本重试
        status, body = self._commit("op2", {"expected_version": 1})
        self.assertEqual(status, 201)
        self.assertEqual(body["version"], 2)

    def test_conflict_then_unconditional_commit_still_works(self):
        self._create("op1", "btc", 100)
        self._create("op2", "btc", 50)
        self._commit("op1")
        status, _ = self._commit("op2", {"expected_version": 0})
        self.assertEqual(status, 409)
        # 未提供 expected_version 时完全沿用旧的无条件提交语义
        status, body = self._commit("op2")
        self.assertEqual(status, 201)
        self.assertEqual(body["version"], 2)

    def test_committed_replay_ignores_expected_version(self):
        self._create("op1", "btc", 100)
        status, first = self._commit("op1", {"expected_version": 0})
        self.assertEqual(status, 201)
        # 已 committed：即便声明的版本已过期也按原幂等规则 200 同体
        status, replay = self._commit("op1", {"expected_version": 0})
        self.assertEqual(status, 200)
        self.assertEqual(replay, first)
        status, replay = self._commit("op1", {"expected_version": 99})
        self.assertEqual(status, 200)
        self.assertEqual(replay, first)
        # 重放不重复改账、不记事件
        _, asset = self._asset("btc")
        self.assertEqual(asset["version"], 1)
        self.assertEqual(len(self._committed_events()), 1)

    def test_missing_wallet_and_operation_keep_404(self):
        status, _ = self._commit(
            "op1", {"expected_version": 0}, wallet_id="nope"
        )
        self.assertEqual(status, 404)
        status, _ = self._commit("nope", {"expected_version": 0})
        self.assertEqual(status, 404)

    def test_expected_version_independent_per_asset(self):
        self._create("op1", "btc", 100)
        self._create("op2", "eth", 7)
        status, _ = self._commit("op1", {"expected_version": 0})
        self.assertEqual(status, 201)
        # eth 尚无提交版本：按 0 处理
        status, body = self._commit("op2", {"expected_version": 0})
        self.assertEqual(status, 201)
        self.assertEqual(body["version"], 1)

    def test_concurrent_same_version_commits_exactly_one(self):
        self._create("op1", "btc", 100)
        self._create("op2", "btc", 50)
        results = []
        barrier = threading.Barrier(2)

        def commit(operation_id):
            barrier.wait()
            results.append(
                (operation_id, self._commit(operation_id,
                                            {"expected_version": 0}))
            )

        threads = [
            threading.Thread(target=commit, args=(op,))
            for op in ("op1", "op2")
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        statuses = sorted(status for _, (status, _) in results)
        self.assertEqual(statuses, [201, 409])
        loser = next(op for op, (status, _) in results if status == 409)
        _, op = self.srv.request(
            "GET", f"/v1/wallets/w1/asset-operations/{loser}"
        )
        self.assertEqual(op["state"], "pending")
        _, asset = self._asset("btc")
        self.assertEqual(asset["version"], 1)
        self.assertEqual(len(self._committed_events()), 1)
        # 落败方可用新版本重试成功
        status, body = self._commit(loser, {"expected_version": 1})
        self.assertEqual(status, 201)
        self.assertEqual(body["version"], 2)


if __name__ == "__main__":
    unittest.main()
