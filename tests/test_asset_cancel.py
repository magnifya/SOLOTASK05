"""资产操作撤销（cancel）端到端测试。

覆盖任务契约：
- POST /v1/wallets/{id}/asset-operations/{oid}/cancel 首撤 201，pending
  转 cancelled，余额/version/资产条目不变，返回既有操作视图 R；
- 同 cancel_id+同操作+同审批单重放 200，不新增事件；同 cancel_id 异参、
  撤销 committed/cancelled（他 cancel_id）409；
- 请求体恰为 {"cancel_id","approval_request_id"}，ID/取值非法 400；
  钱包/操作/审批单不存在 404；审批单非 approved/过期/message 异文 409；
  冻结钱包 409；
- asset_operation_cancelled 是唯一提交点（request_id=cancel_id、
  actor_id=approval_request_id、details=R），崩溃按事件前滚/回滚，失败
  不写意图残留、账本与审计不变；
- 与 commit 在同一钱包事务锁内竞争，恰一个成功；
- 重启、backup/restore 后状态、幂等、seq 与摘要链一致，恢复不新增审计。
"""

from __future__ import annotations

import json
import os
import shutil
import tempfile
import threading
import time
import unittest

from threshold_wallet import drbackup
from threshold_wallet.audit import AuditStore
from threshold_wallet.store import RecoveryError, WalletStore
from threshold_wallet.service import ServiceError, WalletService
from tests.helpers import http_server, make_harness


def cancel_message(operation_id: str, cancel_id: str) -> str:
    """审批单 message：按 operation_id,cancel_id 排列的紧凑 JSON。"""
    return json.dumps(
        {"operation_id": operation_id, "cancel_id": cancel_id},
        ensure_ascii=False,
        separators=(",", ":"),
    )


class CancelHttpTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self._ctx = http_server(self.tmp)
        self.srv = self._ctx.__enter__()
        self.addCleanup(self._ctx.__exit__, None, None, None)
        self.request("POST", "/v1/wallets", {"wallet_id": "w1", "shares": 2})
        self.request(
            "PUT",
            "/v1/wallets/w1/approval-policy",
            {"required_approvals": 1, "timeout_seconds": 3600},
        )

    def request(self, method, path, body=None):
        return self.srv.request(method, path, body)

    def _approval(self, aid, oid, cid, *, state="approved"):
        self.request(
            "POST",
            "/v1/wallets/w1/sign-requests",
            {"id": aid, "message": cancel_message(oid, cid)},
        )
        if state == "approved":
            self.request(
                "POST",
                f"/v1/wallets/w1/sign-requests/{aid}/approve",
                {"approver_id": "bob"},
            )
        elif state == "rejected":
            self.request(
                "POST",
                f"/v1/wallets/w1/sign-requests/{aid}/reject",
                {"approver_id": "bob"},
            )

    def _pending(self, oid="op1", asset="btc", delta=100):
        status, body = self.request(
            "POST",
            "/v1/wallets/w1/asset-operations",
            {"operation_id": oid, "asset_id": asset, "delta": delta},
        )
        self.assertEqual(status, 201, body)
        return body

    def _cancel(self, oid, cid, aid, wallet="w1"):
        return self.request(
            "POST",
            f"/v1/wallets/{wallet}/asset-operations/{oid}/cancel",
            {"cancel_id": cid, "approval_request_id": aid},
        )

    def test_first_cancel_201_cancelled_view_unchanged_snapshot(self):
        self._approval("a1", "op1", "c1")
        self._pending()
        status, body = self._cancel("op1", "c1", "a1")
        self.assertEqual(status, 201, body)
        self.assertEqual(
            body,
            {
                "operation_id": "op1",
                "asset_id": "btc",
                "delta": 100,
                "state": "cancelled",
                "balance": 0,
                "version": 0,
            },
        )
        status, _ = self.request("GET", "/v1/wallets/w1/assets/btc", None)
        self.assertEqual(status, 404)

    def test_cancel_does_not_touch_balance_or_version(self):
        self._pending("op0", delta=100)
        self.assertEqual(
            self.request(
                "POST",
                "/v1/wallets/w1/asset-operations/op0/commit",
                None,
            )[0],
            201,
        )
        self._pending("op1", delta=-30)
        self._approval("a1", "op1", "c1")
        status, body = self._cancel("op1", "c1", "a1")
        self.assertEqual(status, 201)
        self.assertEqual((body["balance"], body["version"]), (100, 1))
        status, asset = self.request(
            "GET", "/v1/wallets/w1/assets/btc", None
        )
        self.assertEqual(status, 200)
        self.assertEqual(
            asset,
            {"asset_id": "btc", "balance": 100, "version": 1},
        )

    def test_cancel_event_is_the_unique_commit_point(self):
        self._approval("a1", "op1", "c1")
        self._pending()
        self.assertEqual(self._cancel("op1", "c1", "a1")[0], 201)
        status, body = self.request(
            "GET", "/v1/wallets/w1/audit-events", None
        )
        self.assertEqual(status, 200)
        cancels = [
            e
            for e in body["events"]
            if e["type"] == "asset_operation_cancelled"
        ]
        self.assertEqual(len(cancels), 1)
        event = cancels[0]
        self.assertEqual(event["request_id"], "c1")
        self.assertEqual(event["actor_id"], "a1")
        self.assertIsNone(event["reason"])
        self.assertEqual(
            event["details"],
            {
                "operation_id": "op1",
                "asset_id": "btc",
                "delta": 100,
                "state": "cancelled",
                "balance": 0,
                "version": 0,
            },
        )

    def test_replay_same_params_returns_200_without_new_event(self):
        self._approval("a1", "op1", "c1")
        self._pending()
        self.assertEqual(self._cancel("op1", "c1", "a1")[0], 201)
        status, body = self._cancel("op1", "c1", "a1")
        self.assertEqual((status, body["state"]), (200, "cancelled"))
        status, events = self.request(
            "GET", "/v1/wallets/w1/audit-events", None
        )
        self.assertEqual(
            len(
                [
                    e
                    for e in events["events"]
                    if e["type"] == "asset_operation_cancelled"
                ]
            ),
            1,
        )

    def test_same_cancel_id_different_approval_returns_409(self):
        self._approval("a1", "op1", "c1")
        self._approval("a2", "op1", "c1")
        self._pending()
        self.assertEqual(self._cancel("op1", "c1", "a1")[0], 201)
        self.assertEqual(self._cancel("op1", "c1", "a2")[0], 409)

    def test_replay_does_not_recheck_approval_presence(self):
        self._approval("a1", "op1", "c1")
        self._pending()
        self.assertEqual(self._cancel("op1", "c1", "a1")[0], 201)
        # 审批单事后被删除：同参数重放仍 200（幂等优先于审批 404）
        requests_path = os.path.join(
            self.tmp, "requests", "w1.json"
        )
        os.unlink(requests_path)
        status, body = self._cancel("op1", "c1", "a1")
        self.assertEqual(status, 200, body)
        self.assertEqual(body["state"], "cancelled")

    def test_same_cancel_id_different_operation_returns_409(self):
        self._approval("a1", "op1", "c1")
        self._pending("op1")
        self._pending("op2", delta=5)
        self.assertEqual(self._cancel("op1", "c1", "a1")[0], 201)
        self._approval("a2", "op2", "c1")
        self.assertEqual(self._cancel("op2", "c1", "a2")[0], 409)
        self.assertEqual(
            self.srv.harness.store.get_asset_operation("w1", "op2")[
                "state"
            ],
            "pending",
        )

    def test_cancel_committed_returns_409(self):
        self._approval("a1", "op1", "c1")
        self._pending()
        self.assertEqual(
            self.request(
                "POST",
                "/v1/wallets/w1/asset-operations/op1/commit",
                None,
            )[0],
            201,
        )
        self.assertEqual(self._cancel("op1", "c1", "a1")[0], 409)

    def test_cancel_with_other_cancel_id_returns_409(self):
        self._approval("a1", "op1", "c1")
        self._approval("a2", "op1", "c2")
        self._pending()
        self.assertEqual(self._cancel("op1", "c1", "a1")[0], 201)
        self.assertEqual(self._cancel("op1", "c2", "a2")[0], 409)

    def test_body_must_contain_exactly_two_keys(self):
        self._approval("a1", "op1", "c1")
        self._pending()
        path = "/v1/wallets/w1/asset-operations/op1/cancel"
        for body in (
            {"cancel_id": "c1"},
            {"approval_request_id": "a1"},
            {"cancel_id": "c1", "approval_request_id": "a1", "x": 1},
            {},
        ):
            self.assertEqual(self.request("POST", path, body)[0], 400, body)

    def test_invalid_identifiers_return_400(self):
        self._approval("a1", "op1", "c1")
        self._pending()
        for bad in ("", "has space", "slash/x", "x" * 129):
            status, _ = self.request(
                "POST",
                "/v1/wallets/w1/asset-operations/op1/cancel",
                {"cancel_id": bad, "approval_request_id": "a1"},
            )
            self.assertEqual(status, 400, bad)
            status, _ = self.request(
                "POST",
                "/v1/wallets/w1/asset-operations/op1/cancel",
                {"cancel_id": "c1", "approval_request_id": bad},
            )
            self.assertEqual(status, 400, bad)

    def test_missing_wallet_operation_approval_return_404(self):
        self._approval("a1", "op1", "c1")
        self._pending()
        self.assertEqual(
            self.request(
                "POST",
                "/v1/wallets/ghost/asset-operations/op1/cancel",
                {"cancel_id": "c1", "approval_request_id": "a1"},
            )[0],
            404,
        )
        self.assertEqual(self._cancel("nope", "c1", "a1")[0], 404)
        self.assertEqual(
            self._cancel("op1", "c1", "missing-a")[0], 404
        )

    def test_approval_gate_message_and_state(self):
        self._pending()
        reversed_message = json.dumps(
            {"cancel_id": "c1", "operation_id": "op1"},
            separators=(",", ":"),
        )
        self.request(
            "POST",
            "/v1/wallets/w1/sign-requests",
            {"id": "a-rev", "message": reversed_message},
        )
        self.request(
            "POST",
            "/v1/wallets/w1/sign-requests/a-rev/approve",
            {"approver_id": "bob"},
        )
        self.assertEqual(
            self._cancel("op1", "c1", "a-rev")[0], 409
        )
        self._approval("a-pending", "op1", "c1", state="pending")
        self.assertEqual(
            self._cancel("op1", "c1", "a-pending")[0], 409
        )
        self._approval("a-reject", "op1", "c1", state="rejected")
        self.assertEqual(
            self._cancel("op1", "c1", "a-reject")[0], 409
        )
        self.assertEqual(
            self.srv.harness.store.get_asset_operation("w1", "op1")[
                "state"
            ],
            "pending",
        )

    def test_expired_approval_returns_409(self):
        self._approval("a1", "op1", "c1")
        self._pending()
        record = self.srv.harness.store.get_request("w1", "a1")
        record["state"] = "pending"
        record["t1"] = "2000-01-01T00:00:00Z"
        self.srv.harness.store.update_request("w1", "a1", record)
        self.assertEqual(self._cancel("op1", "c1", "a1")[0], 409)

    def test_frozen_wallet_returns_409(self):
        self._approval("a1", "op1", "c1")
        self._pending()
        self.assertEqual(
            self.request(
                "POST",
                "/v1/wallets/w1/freeze",
                {"reason": "incident"},
            )[0],
            201,
        )
        self.assertEqual(self._cancel("op1", "c1", "a1")[0], 409)
        self.assertEqual(
            self.srv.harness.store.get_asset_operation("w1", "op1")[
                "state"
            ],
            "pending",
        )


class CancelConcurrentCommitTest(unittest.TestCase):
    """cancel 与 commit 在每钱包跨进程事务锁内竞争。"""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.h = make_harness(self.tmp)
        self.svc = self.h.service

    def _setup_wallet(self, wallet_id: str) -> None:
        self.svc.create_wallet(wallet_id, 2)
        self.svc.put_policy(wallet_id, 1, 3600)
        self.svc.create_sign_request(
            wallet_id, "a1", cancel_message("op1", "c1")
        )
        self.svc.approve(wallet_id, "a1", "bob", None)
        self.svc.create_asset_operation(wallet_id, "op1", "btc", 100)

    def _race(self, wallet_id: str, cancel_delay: float, commit_delay: float):
        outcomes: list[tuple[str, object]] = []
        barrier = threading.Barrier(2)

        def do_cancel() -> None:
            barrier.wait()
            time.sleep(cancel_delay)
            try:
                code, body = self.svc.cancel_asset_operation(
                    wallet_id, "op1", "c1", "a1"
                )
                outcomes.append(("cancel", code, body["state"]))
            except ServiceError as exc:
                outcomes.append(("cancel", exc.status, exc.message))

        def do_commit() -> None:
            barrier.wait()
            time.sleep(commit_delay)
            try:
                code, body = self.svc.commit_asset_operation(
                    wallet_id, "op1"
                )
                outcomes.append(("commit", code, body["state"]))
            except ServiceError as exc:
                outcomes.append(("commit", exc.status, exc.message))

        t1 = threading.Thread(target=do_cancel)
        t2 = threading.Thread(target=do_commit)
        t1.start()
        t2.start()
        t1.join()
        t2.join()
        return outcomes

    def test_exactly_one_side_wins_repeated_races(self):
        # 每轮独立钱包：恰一个 201、另一个 409；多轮后两个方向都赢过。
        winners = {"cancel": 0, "commit": 0}
        rounds = 20
        for index in range(rounds):
            wallet_id = f"w{index}"
            self._setup_wallet(wallet_id)
            winner = None
            # 交替让双方先抢到钱包事务锁，覆盖两个竞争方向
            if index % 2 == 0:
                delays = (0.0, 0.01)
            else:
                delays = (0.01, 0.0)
            for name, code, state in self._race(wallet_id, *delays):
                if code == 201:
                    self.assertIsNone(winner)
                    winner = name
                    self.assertEqual(
                        state,
                        "cancelled" if name == "cancel" else "committed",
                    )
                else:
                    self.assertEqual(code, 409)
            self.assertIsNotNone(winner)
            winners[winner] += 1
            ledger = self.h.store
            if winner == "cancel":
                self.assertEqual(
                    ledger.get_asset_operation(wallet_id, "op1")["state"],
                    "cancelled",
                )
                self.assertIsNone(ledger.get_asset(wallet_id, "btc"))
            else:
                self.assertEqual(
                    ledger.get_asset_operation(wallet_id, "op1")["state"],
                    "committed",
                )
                self.assertEqual(
                    ledger.get_asset(wallet_id, "btc"),
                    {"balance": 100, "version": 1},
                )
        self.assertEqual(winners["cancel"] + winners["commit"], rounds)
        self.assertGreater(winners["cancel"], 0)
        self.assertGreater(winners["commit"], 0)


class CancelRecoveryTest(unittest.TestCase):
    """撤销是「意图 → 账本 → 事件 → 删意图」的可恢复事务。"""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.h = make_harness(self.tmp)
        self.svc = self.h.service
        self.store = self.h.store
        self.svc.create_wallet("w1", 2)
        self.svc.put_policy("w1", 1, 3600)
        self.svc.create_sign_request(
            "w1", "a1", cancel_message("op1", "c1")
        )
        self.svc.approve("w1", "a1", "bob", None)
        self.svc.create_asset_operation("w1", "op1", "btc", 100)

    def _intent(self):
        record = self.store.get_asset_operation("w1", "op1")
        record = dict(record)
        record["state"] = "pending"
        return {
            "operation_id": "op1",
            "asset_id": "btc",
            "delta": 100,
            "pending": record,
            "cancel": {
                "cancel_id": "c1",
                "approval_request_id": "a1",
            },
        }

    def _cancelled_view(self):
        view = self.svc._asset_operation_view(
            self.store.get_asset_operation("w1", "op1")
        )
        view["state"] = "cancelled"
        return view

    def test_event_missing_rolls_back_to_pending(self):
        # 账本已转 cancelled、意图在、事件未写：回滚为 pending
        self.store.write_asset_commit_intent("w1", "op1", self._intent())
        self.store.cancel_asset_operation(
            "w1", "op1", self._cancelled_view()
        )
        WalletService(WalletStore(self.tmp))
        self.assertEqual(
            self.store.get_asset_operation("w1", "op1")["state"],
            "pending",
        )
        self.assertIsNone(self.store.get_asset("w1", "btc"))
        intent_dir = os.path.join(self.tmp, "asset-intents", "w1")
        self.assertEqual(os.listdir(intent_dir), [])
        self.assertEqual(
            [
                e
                for e in self.svc.get_audit_events("w1")["events"]
                if e["type"] == "asset_operation_cancelled"
            ],
            [],
        )
        # 回滚后首次撤销仍 201
        code, body = self.svc.cancel_asset_operation(
            "w1", "op1", "c1", "a1"
        )
        self.assertEqual(code, 201)
        self.assertEqual(body["state"], "cancelled")

    def test_event_landed_rolls_forward_to_cancelled(self):
        code, view = self.svc.cancel_asset_operation(
            "w1", "op1", "c1", "a1"
        )
        self.assertEqual(code, 201)
        # 模拟崩溃：重新落意图并把账本改回 pending（事件已持久化）
        self.store.write_asset_commit_intent("w1", "op1", self._intent())
        pending = dict(view)
        pending["state"] = "pending"
        self.store.cancel_asset_operation("w1", "op1", pending)
        WalletService(WalletStore(self.tmp))
        self.assertEqual(
            self.store.get_asset_operation("w1", "op1"), view
        )
        # 前滚后同参数重放 200，且不新增事件
        code, body = self.svc.cancel_asset_operation(
            "w1", "op1", "c1", "a1"
        )
        self.assertEqual((code, body), (200, view))
        events = self.svc.get_audit_events("w1")["events"]
        self.assertEqual(
            len(
                [
                    e
                    for e in events
                    if e["type"] == "asset_operation_cancelled"
                ]
            ),
            1,
        )

    def test_failed_writes_leave_no_trace(self):
        original = self.store.cancel_asset_operation
        calls = {"n": 0}

        def boom(*args, **kwargs):
            calls["n"] += 1
            if calls["n"] > 1:
                return original(*args, **kwargs)
            raise OSError("assets disk full")

        self.store.cancel_asset_operation = boom
        try:
            with self.assertRaises(OSError):
                self.svc.cancel_asset_operation(
                    "w1", "op1", "c1", "a1"
                )
        finally:
            self.store.cancel_asset_operation = original
        self.assertEqual(
            self.store.get_asset_operation("w1", "op1")["state"],
            "pending",
        )
        self.assertIsNone(
            self.store.get_asset_commit_intent("w1", "op1")
        )
        self.assertEqual(
            [
                e
                for e in self.svc.get_audit_events("w1")["events"]
                if e["type"] == "asset_operation_cancelled"
            ],
            [],
        )

    def test_event_append_failure_rolls_back(self):
        real_append = self.svc._audit.append_event

        def boom(wallet_id, event):
            if event.get("type") == "asset_operation_cancelled":
                raise OSError("audit disk full")
            return real_append(wallet_id, event)

        self.svc._audit.append_event = boom
        try:
            with self.assertRaises(OSError):
                self.svc.cancel_asset_operation(
                    "w1", "op1", "c1", "a1"
                )
        finally:
            self.svc._audit.append_event = real_append
        self.assertEqual(
            self.store.get_asset_operation("w1", "op1")["state"],
            "pending",
        )
        code, body = self.svc.cancel_asset_operation(
            "w1", "op1", "c1", "a1"
        )
        self.assertEqual(code, 201)
        self.assertEqual(body["state"], "cancelled")

    def test_malformed_cancel_intent_refuses_readiness(self):
        self.store.write_asset_commit_intent(
            "w1", "op1", {"operation_id": "op1", "cancel": {}}
        )
        with self.assertRaises(RecoveryError):
            WalletService(WalletStore(self.tmp))

    def test_cancelled_operation_without_event_refuses_readiness(self):
        self.store.cancel_asset_operation(
            "w1", "op1", self._cancelled_view()
        )
        with self.assertRaises(RecoveryError):
            WalletService(WalletStore(self.tmp))

    def test_phantom_cancel_event_refuses_readiness(self):
        # 先合法撤销，再把账本记录改回 pending：有事件无操作
        self.assertEqual(
            self.svc.cancel_asset_operation(
                "w1", "op1", "c1", "a1"
            )[0],
            201,
        )
        pending = dict(
            self.store.get_asset_operation("w1", "op1")
        )
        pending["state"] = "pending"
        self.store.cancel_asset_operation("w1", "op1", pending)
        with self.assertRaises(RecoveryError):
            WalletService(WalletStore(self.tmp))


class CancelRestartAndBackupTest(unittest.TestCase):
    """重启与 backup/restore 后状态、幂等、seq 与摘要链一致。"""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.out = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.out, ignore_errors=True)

    def _populate(self, data_dir: str) -> WalletService:
        h = make_harness(data_dir)
        svc = h.service
        svc.create_wallet("w1", 2)
        svc.put_policy("w1", 1, 3600)
        svc.create_sign_request(
            "w1", "a1", cancel_message("op1", "c1")
        )
        svc.approve("w1", "a1", "bob", None)
        svc.create_asset_operation("w1", "op1", "btc", 100)
        self.assertEqual(
            svc.cancel_asset_operation("w1", "op1", "c1", "a1")[0], 201
        )
        return svc

    def test_restart_preserves_state_idempotency_and_chain(self):
        self._populate(self.tmp)
        before = AuditStore(self.tmp).integrity("w1")
        svc = WalletService(WalletStore(self.tmp))
        record = svc._store.get_asset_operation("w1", "op1")
        self.assertEqual(record["state"], "cancelled")
        code, body = svc.cancel_asset_operation(
            "w1", "op1", "c1", "a1"
        )
        self.assertEqual(code, 200)
        self.assertEqual(body["state"], "cancelled")
        after = AuditStore(self.tmp).integrity("w1")
        self.assertEqual(before, after)
        events = svc.get_audit_events("w1")["events"]
        self.assertEqual(
            [e["seq"] for e in events],
            list(range(1, len(events) + 1)),
        )

    def test_backup_restore_roundtrip(self):
        self._populate(self.tmp)
        snapshot = os.path.join(self.out, "snap.tar")
        result = drbackup.backup(self.tmp, "w1", "snap1", snapshot)
        self.assertEqual(result["status"], 201)
        target = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, target, ignore_errors=True)
        status, _ = drbackup.restore(target, "w1", snapshot)
        self.assertIn(status, (200, 201))
        restored = WalletService(WalletStore(target))
        record = restored._store.get_asset_operation("w1", "op1")
        self.assertEqual(record["state"], "cancelled")
        code, body = restored.cancel_asset_operation(
            "w1", "op1", "c1", "a1"
        )
        self.assertEqual(code, 200)
        self.assertEqual(body["state"], "cancelled")
        integrity = restored.get_audit_integrity("w1")
        self.assertEqual(integrity["state"], "valid")
        self.assertEqual(integrity["count"], 4)

    def test_cancel_intent_carries_no_private_material(self):
        svc = self._populate(self.tmp)
        del svc
        # 正常完成后意图目录为空
        intent_dir = os.path.join(self.tmp, "asset-intents", "w1")
        self.assertTrue(
            not os.path.exists(intent_dir)
            or os.listdir(intent_dir) == []
        )
