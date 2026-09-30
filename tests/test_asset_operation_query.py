"""GET /v1/wallets/{id}/asset-operations/{oid} 只读查询与取消重放边界。

覆盖：
- pending/committed 视图 cancellation 为 null；cancelled 视图带
  cancel_id/approval_request_id/事件 seq；
- 非法 operation_id 400、钱包/操作不存在 404、冻结钱包仍可查询；
- 查询只读：余额/version/状态/审计 seq/摘要链不变，响应确定性；
- 取消重放三键（cancel_id/operation_id/approval_request_id）全同即 200，
  审批单事后推进为 signed 也不复查；任一不同 409；
- 首次撤销审批门控：message 逐字匹配，pending/rejected/expired 409，
  缺审批/缺操作 404，请求体或 ID 非法 400；
- 账本与取消事件矛盾 503（RecoveryError），JSON 损坏 503（CorruptData）。
"""

from __future__ import annotations

import json
import os
import shutil
import tempfile
import threading
import time
import unittest

from tests.helpers import http_server


def _cancel_message(operation_id, cancel_id):
    return json.dumps(
        {"operation_id": operation_id, "cancel_id": cancel_id},
        ensure_ascii=False,
        separators=(",", ":"),
    )


class _Server(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmpdir, ignore_errors=True)
        self._ctx = http_server(self.tmpdir)
        self.srv = self._ctx.__enter__()
        self.addCleanup(self._ctx.__exit__, None, None, None)
        self.srv.request(
            "POST", "/v1/wallets", {"wallet_id": "w1", "shares": 2}
        )

    def _put_policy(self, timeout=60, wallet="w1"):
        status, _ = self.srv.request(
            "PUT",
            f"/v1/wallets/{wallet}/approval-policy",
            {"required_approvals": 1, "timeout_seconds": timeout},
        )
        self.assertEqual(status, 200)

    def _create(self, operation_id="op1", asset_id="btc", delta=100,
                wallet="w1"):
        return self.srv.request(
            "POST",
            f"/v1/wallets/{wallet}/asset-operations",
            {
                "operation_id": operation_id,
                "asset_id": asset_id,
                "delta": delta,
            },
        )

    def _get_op(self, operation_id, wallet="w1"):
        return self.srv.request(
            "GET",
            f"/v1/wallets/{wallet}/asset-operations/{operation_id}",
        )

    def _make_approved(self, operation_id, cancel_id, request_id):
        message = _cancel_message(operation_id, cancel_id)
        status, _ = self.srv.request(
            "POST",
            "/v1/wallets/w1/sign-requests",
            {"id": request_id, "message": message},
        )
        self.assertEqual(status, 201)
        status, _ = self.srv.request(
            "POST",
            f"/v1/wallets/w1/sign-requests/{request_id}/approve",
            {"approver_id": "alice"},
        )
        self.assertEqual(status, 200)
        return message

    def _cancel(self, operation_id, cancel_id, approval_request_id,
                wallet="w1"):
        return self.srv.request(
            "POST",
            f"/v1/wallets/{wallet}/asset-operations/"
            f"{operation_id}/cancel",
            {
                "cancel_id": cancel_id,
                "approval_request_id": approval_request_id,
            },
        )

    def _cancelled_events(self):
        _, events = self.srv.request(
            "GET", "/v1/wallets/w1/audit-events"
        )
        return [
            event
            for event in events["events"]
            if event["type"] == "asset_operation_cancelled"
        ]


class AssetOperationQueryTest(_Server):
    def test_pending_view_has_null_cancellation(self):
        self._create("op1")
        status, body = self._get_op("op1")
        self.assertEqual(status, 200)
        self.assertEqual(
            body,
            {
                "operation_id": "op1",
                "asset_id": "btc",
                "state": "pending",
                "delta": 100,
                "balance": 0,
                "version": 0,
                "cancellation": None,
            },
        )
        self.assertEqual(
            list(body.keys()),
            [
                "operation_id",
                "asset_id",
                "state",
                "delta",
                "balance",
                "version",
                "cancellation",
            ],
        )

    def test_committed_view_has_null_cancellation(self):
        self._create("op1")
        status, _ = self.srv.request(
            "POST", "/v1/wallets/w1/asset-operations/op1/commit"
        )
        self.assertEqual(status, 201)
        status, body = self._get_op("op1")
        self.assertEqual(status, 200)
        self.assertEqual(body["state"], "committed")
        self.assertEqual((body["balance"], body["version"]), (100, 1))
        self.assertIsNone(body["cancellation"])

    def test_cancelled_view_carries_cancel_info_and_seq(self):
        self._put_policy()
        self._create("op1")
        self._make_approved("op1", "c1", "ar1")
        status, cancelled = self._cancel("op1", "c1", "ar1")
        self.assertEqual(status, 201)
        status, body = self._get_op("op1")
        self.assertEqual(status, 200)
        self.assertEqual(body["state"], "cancelled")
        self.assertEqual(
            body["cancellation"],
            {
                "cancel_id": "c1",
                "approval_request_id": "ar1",
                "seq": self._cancelled_events()[0]["seq"],
            },
        )
        self.assertEqual(
            list(body["cancellation"].keys()),
            ["cancel_id", "approval_request_id", "seq"],
        )
        for key in ("operation_id", "asset_id", "state", "delta",
                    "balance", "version"):
            self.assertEqual(body[key], cancelled[key])

    def test_invalid_operation_id_returns_400(self):
        # 注：含 "/" 的标识无法在路径段中表达，会落到路由 404；
        # 这里只覆盖到达处理器后被判非法的安全标识
        for bad in ("dot.x", "$", "%", "x" * 129):
            with self.subTest(operation_id=bad):
                status, _ = self._get_op(bad)
                self.assertEqual(status, 400)

    def test_missing_wallet_and_operation_return_404(self):
        status, _ = self._get_op("op1", wallet="nope")
        self.assertEqual(status, 404)
        status, _ = self._get_op("nope")
        self.assertEqual(status, 404)

    def test_query_works_on_frozen_wallet(self):
        self._create("op1")
        status, _ = self.srv.request(
            "POST",
            "/v1/wallets/w1/freeze",
            {"reason": "incident"},
        )
        self.assertIn(status, (200, 201))
        status, body = self._get_op("op1")
        self.assertEqual(status, 200)
        self.assertEqual(body["state"], "pending")

    def test_query_is_read_only_and_deterministic(self):
        self._put_policy()
        self._create("op1")
        self._make_approved("op1", "c1", "ar1")
        self._cancel("op1", "c1", "ar1")
        _, before = self.srv.request("GET", "/v1/wallets/w1/audit-events")
        views = []
        for _ in range(3):
            status, body = self._get_op("op1")
            self.assertEqual(status, 200)
            views.append(json.dumps(body, ensure_ascii=False))
        self.assertEqual(len(set(views)), 1)
        _, after = self.srv.request("GET", "/v1/wallets/w1/audit-events")
        # 不追加事件、不分配 seq
        self.assertEqual(before, after)
        # 撤销不落账：资产条目仍不存在，balance/version 从未被创建
        status, _ = self.srv.request("GET", "/v1/wallets/w1/assets/btc")
        self.assertEqual(status, 404)
        # 查询不触发审批单懒过期
        _, approval = self.srv.request(
            "GET", "/v1/wallets/w1/sign-requests/ar1"
        )
        self.assertEqual(approval["state"], "approved")

    def test_query_survives_restart(self):
        self._put_policy()
        self._create("op1")
        self._make_approved("op1", "c1", "ar1")
        self._cancel("op1", "c1", "ar1")
        status, before = self._get_op("op1")
        self.assertEqual(status, 200)
        self.srv.stop()
        self._ctx.__exit__(None, None, None)
        new_ctx = http_server(self.tmpdir)
        self.srv = new_ctx.__enter__()
        self.addCleanup(new_ctx.__exit__, None, None, None)
        status, after = self._get_op("op1")
        self.assertEqual(status, 200)
        self.assertEqual(before, after)


class AssetCancelReplayTest(_Server):
    def test_replay_returns_200_even_after_approval_becomes_signed(self):
        self._put_policy()
        self._create("op1")
        message = self._make_approved("op1", "c1", "ar1")
        status, first = self._cancel("op1", "c1", "ar1")
        self.assertEqual(status, 201)
        sigs = self.srv.harness.two_signatures("w1", "ar1", message)
        status, signed = self.srv.request(
            "POST",
            "/v1/wallets/w1/sign",
            {
                "signing_request_id": "ar1",
                "message": message,
                "signatures": sigs,
            },
        )
        self.assertIn(status, (200, 201))
        self.assertIn("signature", signed)
        _, approval_now = self.srv.request(
            "GET", "/v1/wallets/w1/sign-requests/ar1"
        )
        self.assertEqual(approval_now["state"], "signed")
        # 重放不复查审批单当前状态：200 且视图不变
        status, replay = self._cancel("op1", "c1", "ar1")
        self.assertEqual(status, 200)
        self.assertEqual(replay, first)
        self.assertEqual(len(self._cancelled_events()), 1)

    def test_same_cancel_id_different_approval_returns_409(self):
        self._put_policy()
        self._create("op1")
        self._make_approved("op1", "c1", "ar1")
        status, _ = self._cancel("op1", "c1", "ar1")
        self.assertEqual(status, 201)
        self._make_approved("op1", "c1", "ar2")
        status, _ = self._cancel("op1", "c1", "ar2")
        self.assertEqual(status, 409)
        self.assertEqual(len(self._cancelled_events()), 1)

    def test_same_cancel_id_different_operation_returns_409(self):
        self._put_policy()
        self._create("op1")
        self._create("op2")
        self._make_approved("op1", "c1", "ar1")
        status, _ = self._cancel("op1", "c1", "ar1")
        self.assertEqual(status, 201)
        message2 = _cancel_message("op2", "c1")
        status, _ = self.srv.request(
            "POST",
            "/v1/wallets/w1/sign-requests",
            {"id": "ar2", "message": message2},
        )
        self.assertEqual(status, 201)
        status, _ = self.srv.request(
            "POST",
            "/v1/wallets/w1/sign-requests/ar2/approve",
            {"approver_id": "alice"},
        )
        self.assertEqual(status, 200)
        status, _ = self._cancel("op2", "c1", "ar2")
        self.assertEqual(status, 409)
        # op2 未被误撤销
        _, body = self._get_op("op2")
        self.assertEqual(body["state"], "pending")

    def test_operation_cancelled_by_other_cancel_id_returns_409(self):
        self._put_policy()
        self._create("op1")
        self._make_approved("op1", "c1", "ar1")
        status, _ = self._cancel("op1", "c1", "ar1")
        self.assertEqual(status, 201)
        self._make_approved("op1", "c2", "ar2")
        status, _ = self._cancel("op1", "c2", "ar2")
        self.assertEqual(status, 409)

    def test_concurrent_replays_all_see_200_and_single_event(self):
        self._put_policy()
        self._create("op1")
        self._make_approved("op1", "c1", "ar1")
        status, _ = self._cancel("op1", "c1", "ar1")
        self.assertEqual(status, 201)
        barrier = threading.Barrier(8)
        results = []

        def worker():
            barrier.wait()
            results.append(self._cancel("op1", "c1", "ar1"))

        threads = [threading.Thread(target=worker) for _ in range(8)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual({status for status, _ in results}, {200})
        self.assertEqual(len(self._cancelled_events()), 1)


class AssetCancelFirstTimeGateTest(_Server):
    def _create_request(self, request_id, message):
        status, _ = self.srv.request(
            "POST",
            "/v1/wallets/w1/sign-requests",
            {"id": request_id, "message": message},
        )
        self.assertEqual(status, 201)

    def _decide(self, request_id, decision):
        status, _ = self.srv.request(
            "POST",
            f"/v1/wallets/w1/sign-requests/{request_id}/{decision}",
            {"approver_id": "alice"},
        )
        self.assertEqual(status, 200)

    def test_missing_approval_and_operation_return_404(self):
        self._put_policy()
        self._create("op1")
        status, _ = self._cancel("op1", "c1", "missing")
        self.assertEqual(status, 404)
        status, _ = self._cancel("nope", "c1", "ar1")
        self.assertEqual(status, 404)

    def test_message_mismatch_returns_409(self):
        self._put_policy()
        self._create("op1")
        self._create_request("ar1", "something else")
        self._decide("ar1", "approve")
        status, _ = self._cancel("op1", "c1", "ar1")
        self.assertEqual(status, 409)
        _, body = self._get_op("op1")
        self.assertEqual(body["state"], "pending")

    def test_pending_and_rejected_approval_return_409(self):
        self._put_policy()
        self._create("op1")
        message = _cancel_message("op1", "c1")
        self._create_request("arp", message)
        self._create_request("arr", message)
        self._decide("arr", "reject")
        status, _ = self._cancel("op1", "c1", "arp")
        self.assertEqual(status, 409)
        status, _ = self._cancel("op1", "c1", "arr")
        self.assertEqual(status, 409)

    def test_expired_approval_returns_409_without_lazy_write(self):
        self._put_policy(timeout=1)
        self._create("op1")
        message = _cancel_message("op1", "c1")
        self._create_request("arx", message)
        self._decide("arx", "approve")
        # 已 approved 的单不会过期；改用一张超时未决的 pending 单
        self._create_request("arp", message)
        time.sleep(1.1)
        _, events_before = self.srv.request(
            "GET", "/v1/wallets/w1/audit-events"
        )
        status, _ = self._cancel("op1", "c1", "arp")
        self.assertEqual(status, 409)
        # 失败不触发懒过期：不追加 request_expired 事件
        _, events_after = self.srv.request(
            "GET", "/v1/wallets/w1/audit-events"
        )
        self.assertEqual(events_before, events_after)
        # GET 视图可虚拟呈现 expired，但磁盘仍 pending、无懒写事件
        # （events_before == events_after 已验证零副作用）

    def test_invalid_body_and_ids_return_400(self):
        self._put_policy()
        self._create("op1")
        message = _cancel_message("op1", "c1")
        self._create_request("ar1", message)
        self._decide("ar1", "approve")
        base = "/v1/wallets/w1/asset-operations/op1/cancel"
        # 夹带多余键 / 缺键
        status, _ = self.srv.request(
            "POST",
            base,
            {
                "cancel_id": "c1",
                "approval_request_id": "ar1",
                "extra": 1,
            },
        )
        self.assertEqual(status, 400)
        status, _ = self.srv.request(
            "POST", base, {"cancel_id": "c1"}
        )
        self.assertEqual(status, 400)
        # 非法 cancel_id / approval_request_id / operation_id
        status, _ = self._cancel("op1", "bad id", "ar1")
        self.assertEqual(status, 400)
        status, _ = self._cancel("op1", "c1", "bad/id")
        self.assertEqual(status, 400)
        status, _ = self.srv.request(
            "POST",
            "/v1/wallets/w1/asset-operations/bad.id/cancel",
            {"cancel_id": "c1", "approval_request_id": "ar1"},
        )
        self.assertEqual(status, 400)


class AssetOperationQueryCorruptionTest(_Server):
    def _ledger_path(self):
        return os.path.join(self.tmpdir, "assets", "w1.json")
    def _cancel_one(self):
        self._put_policy()
        self._create("op1")
        self._make_approved("op1", "c1", "ar1")
        status, _ = self._cancel("op1", "c1", "ar1")
        self.assertEqual(status, 201)

    def test_event_ledger_contradiction_returns_503(self):
        self._cancel_one()
        # 外部把账本记录改回 pending，与已落盘撤销事件矛盾
        with open(self._ledger_path(), encoding="utf-8") as handle:
            ledger = json.load(handle)
        ledger["operations"]["op1"]["state"] = "pending"
        with open(self._ledger_path(), "w", encoding="utf-8") as handle:
            json.dump(ledger, handle)
        status, body = self._get_op("op1")
        self.assertEqual(status, 503)
        self.assertEqual(body, {"error": "service temporarily unavailable"})

    def test_corrupt_json_returns_503(self):
        self._cancel_one()
        with open(self._ledger_path(), "w", encoding="utf-8") as handle:
            handle.write("{not json")
        status, body = self._get_op("op1")
        self.assertEqual(status, 503)
        self.assertEqual(body, {"error": "service temporarily unavailable"})


if __name__ == "__main__":
    unittest.main()
