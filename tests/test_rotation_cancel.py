"""未激活份额轮换的主动撤销：契约、幂等、冻结、恢复与灾备。"""

from __future__ import annotations

import json
import os
import tempfile
import unittest

from threshold_wallet import drbackup
from threshold_wallet.service import ServiceError, WalletService
from threshold_wallet.store import RecoveryError, WalletStore

from tests.helpers import http_server, make_harness


class RotationCancelHttpTest(unittest.TestCase):
    def setUp(self):
        self._ctx = http_server(tempfile.mkdtemp())
        self.srv = self._ctx.__enter__()

    def tearDown(self):
        self._ctx.__exit__(None, None, None)

    def request(self, method, path, body=None):
        return self.srv.request(method, path, body)

    def create_wallet(self, wallet_id="w1"):
        status, body = self.request(
            "POST", "/v1/wallets", {"wallet_id": wallet_id, "shares": 2}
        )
        self.assertEqual(status, 201)
        return body

    def prepare(self, wallet_id="w1", rotation_id="rot-1"):
        return self.request(
            "POST",
            f"/v1/wallets/{wallet_id}/share-rotations",
            {"rotation_id": rotation_id},
        )

    def cancel(
        self, wallet_id="w1", rotation_id="rot-1",
        cancel_id="c-1", reason="不再轮换",
    ):
        return self.request(
            "POST",
            f"/v1/wallets/{wallet_id}/share-rotations/{rotation_id}/cancel",
            {"cancel_id": cancel_id, "reason": reason},
        )

    def _staging_dir(self, rotation_id="rot-1"):
        return os.path.join(
            self.srv.harness.tmpdir, "rotation-staging", "w1", rotation_id
        )

    def _audit_events(self, wallet_id="w1"):
        status, body = self.request(
            "GET", f"/v1/wallets/{wallet_id}/audit-events"
        )
        self.assertEqual(status, 200)
        return body["events"]

    # ---- 首次撤销 -------------------------------------------------------

    def test_cancel_201_contract_and_staging_cleaned(self):
        wallet = self.create_wallet()
        _, prepared = self.prepare()
        status, body = self.cancel()
        self.assertEqual(status, 201)
        self.assertEqual(
            set(body),
            {"rotation_id", "state", "share_ids", "public_key",
             "cancellation"},
        )
        self.assertEqual(body["rotation_id"], "rot-1")
        self.assertEqual(body["state"], "cancelled")
        self.assertEqual(body["share_ids"], prepared["share_ids"])
        self.assertEqual(body["public_key"], prepared["public_key"])
        self.assertEqual(
            body["cancellation"],
            {"cancel_id": "c-1", "reason": "不再轮换"},
        )
        # 暂存份额已清理
        self.assertFalse(os.path.exists(self._staging_dir()))
        # 在用份额、钱包公钥不变
        _, current = self.request("GET", "/v1/wallets/w1")
        self.assertEqual(current["public_key"], wallet["public_key"])
        shares_dir = os.path.join(self.srv.harness.tmpdir, "shares", "w1")
        self.assertEqual(
            sorted(os.listdir(shares_dir)), ["share-1.json", "share-2.json"]
        )
        # 查询返回同一撤销视图
        status, view = self.request(
            "GET", "/v1/wallets/w1/share-rotations/rot-1"
        )
        self.assertEqual(status, 200)
        self.assertEqual(view, body)

    def test_cancel_reason_kept_verbatim(self):
        self.create_wallet()
        self.prepare()
        reason = "  含 前后空白\n与换行  "
        status, body = self.cancel(reason=reason)
        self.assertEqual(status, 201)
        self.assertEqual(body["cancellation"]["reason"], reason)
        # rot-1 已撤销释放占用：可准备 rot-2 并以 1024 字符原因撤销
        self.assertEqual(self.prepare(rotation_id="rot-2")[0], 201)
        status, body = self.cancel(
            rotation_id="rot-2", cancel_id="c-2", reason="x" * 1024
        )
        self.assertEqual(status, 201)
        self.assertEqual(body["cancellation"]["reason"], "x" * 1024)

    # ---- 请求体验证 -----------------------------------------------------

    def test_cancel_bad_body_400(self):
        self.create_wallet()
        self.prepare()
        path = "/v1/wallets/w1/share-rotations/rot-1/cancel"
        for body in (
            {},
            {"cancel_id": "c-1"},
            {"reason": "r"},
            {"cancel_id": "c-1", "reason": "r", "extra": 1},
            {"cancel_id": "c-1", "reason": "r", "rotation_id": "rot-1"},
        ):
            status, _ = self.request("POST", path, body)
            self.assertEqual(status, 400, body)

    def test_cancel_invalid_ids_and_reason_400(self):
        self.create_wallet()
        self.prepare()
        for bad_id in ("", "has space", "a/b", "x" * 129, "中文", 7, None):
            status, _ = self.cancel(cancel_id=bad_id)
            self.assertEqual(status, 400, bad_id)
        for bad_reason in ("", "   ", "x" * 1025, 7, None, ["r"]):
            status, _ = self.cancel(reason=bad_reason)
            self.assertEqual(status, 400, bad_reason)
        # 全部失败后轮换仍 prepared，可正常撤销
        status, _ = self.cancel()
        self.assertEqual(status, 201)

    def test_cancel_unknown_wallet_or_rotation_404(self):
        self.create_wallet()
        self.prepare()
        status, _ = self.cancel(wallet_id="ghost")
        self.assertEqual(status, 404)
        status, _ = self.cancel(rotation_id="nope")
        self.assertEqual(status, 404)

    def test_cancel_other_methods_405(self):
        self.create_wallet()
        self.prepare()
        path = "/v1/wallets/w1/share-rotations/rot-1/cancel"
        for method in ("GET", "PUT", "DELETE", "PATCH"):
            status, _ = self.request(method, path)
            self.assertEqual(status, 405, method)

    # ---- 幂等与判重 -----------------------------------------------------

    def test_cancel_replay_200_same_body_no_new_event(self):
        self.create_wallet()
        self.prepare()
        _, first = self.cancel()
        status, second = self.cancel()
        self.assertEqual(status, 200)
        self.assertEqual(second, first)
        events = self._audit_events()
        self.assertEqual(
            [e["type"] for e in events],
            ["share_rotation_prepared", "share_rotation_cancelled"],
        )

    def test_cancel_same_id_different_reason_409(self):
        self.create_wallet()
        self.prepare()
        self.cancel()
        status, _ = self.cancel(reason="另一个原因")
        self.assertEqual(status, 409)

    def test_cancel_again_with_new_cancel_id_409(self):
        self.create_wallet()
        self.prepare()
        self.cancel()
        status, _ = self.cancel(cancel_id="c-2")
        self.assertEqual(status, 409)

    def test_cancel_id_reused_on_another_rotation_409(self):
        self.create_wallet()
        self.prepare(rotation_id="rot-1")
        self.assertEqual(self.cancel(rotation_id="rot-1")[0], 201)
        # 撤销释放占用：可用新 rotation_id 准备下一笔
        self.assertEqual(self.prepare(rotation_id="rot-2")[0], 201)
        # 但同一 cancel_id 不得复用到另一轮换
        status, _ = self.cancel(rotation_id="rot-2", cancel_id="c-1")
        self.assertEqual(status, 409)
        # 新标识可撤销
        status, _ = self.cancel(rotation_id="rot-2", cancel_id="c-2")
        self.assertEqual(status, 201)

    def test_cancel_id_namespace_independent_from_session_cancel(self):
        # cancel_id 只在轮换撤销之间判重：签名会话撤销用过同值不影响
        self.create_wallet()
        self.prepare()
        service = self.srv.harness.service
        self.assertEqual(
            service.create_sign_session("w1", "s1", "m", 600)[0], 201
        )
        self.assertEqual(
            service.cancel_sign_session("w1", "s1", "c-1", "会话原因")[0],
            201,
        )
        status, _ = self.cancel(cancel_id="c-1")
        self.assertEqual(status, 201)

    # ---- 状态机 ---------------------------------------------------------

    def test_cancel_activated_rotation_409(self):
        self.create_wallet()
        self.prepare()
        status, _ = self.request(
            "POST", "/v1/wallets/w1/share-rotations/rot-1/activate"
        )
        self.assertEqual(status, 201)
        status, _ = self.cancel()
        self.assertEqual(status, 409)

    def test_activate_after_cancel_409(self):
        self.create_wallet()
        self.prepare()
        self.assertEqual(self.cancel()[0], 201)
        status, _ = self.request(
            "POST", "/v1/wallets/w1/share-rotations/rot-1/activate"
        )
        self.assertEqual(status, 409)

    def test_prepare_after_cancel_returns_cancelled_view_200(self):
        self.create_wallet()
        self.prepare()
        _, cancelled = self.cancel()
        # 用原 rotation_id 再准备：200 撤销视图，不生成新份额
        status, body = self.prepare()
        self.assertEqual(status, 200)
        self.assertEqual(body, cancelled)
        self.assertFalse(os.path.exists(self._staging_dir()))
        # 用新标识可准备下一笔
        status, body = self.prepare(rotation_id="rot-2")
        self.assertEqual(status, 201)
        self.assertEqual(body["state"], "prepared")

    def test_sign_unaffected_by_cancel(self):
        self.create_wallet()
        body = {
            "signing_request_id": "r1",
            "message": "hello",
            "signatures": self.srv.harness.two_signatures("w1", "r1", "hello"),
        }
        self.prepare()
        self.assertEqual(self.cancel()[0], 201)
        # 撤销不改变在用份额：签名仍可用
        status, signed = self.request("POST", "/v1/wallets/w1/sign", body)
        self.assertEqual(status, 201)
        self.assertIn("signature", signed)

    # ---- 冻结 -----------------------------------------------------------

    def test_frozen_wallet_cancel_and_replay_409(self):
        self.create_wallet()
        self.prepare(rotation_id="rot-1")
        # 先撤销 rot-1，再冻结；rot-2 仍 prepared
        self.assertEqual(self.cancel(rotation_id="rot-1")[0], 201)
        self.assertEqual(self.prepare(rotation_id="rot-2")[0], 201)
        status, _ = self.request(
            "POST", "/v1/wallets/w1/freeze", {"reason": "incident"}
        )
        self.assertEqual(status, 201)
        # 新撤销 409
        status, _ = self.cancel(rotation_id="rot-2", cancel_id="c-2")
        self.assertEqual(status, 409)
        # 已提交撤销的重放同样 409
        status, _ = self.cancel(rotation_id="rot-1")
        self.assertEqual(status, 409)
        # 无副作用：rot-2 仍 prepared，无新事件
        _, view = self.request("GET", "/v1/wallets/w1/share-rotations/rot-2")
        self.assertEqual(view["state"], "prepared")
        self.assertEqual(
            [e["type"] for e in self._audit_events()],
            [
                "share_rotation_prepared",
                "share_rotation_cancelled",
                "share_rotation_prepared",
                "wallet_frozen",
            ],
        )
        # 查询仍可用
        _, view = self.request("GET", "/v1/wallets/w1/share-rotations/rot-1")
        self.assertEqual(view["state"], "cancelled")
        # 解冻后重放恢复 200
        status, _ = self.request(
            "POST", "/v1/wallets/w1/unfreeze", {"reason": "resolved"}
        )
        self.assertEqual(status, 201)
        status, _ = self.cancel(rotation_id="rot-1")
        self.assertEqual(status, 200)

    # ---- 审计 -----------------------------------------------------------

    def test_cancel_audit_event_contract(self):
        self.create_wallet()
        _, prepared = self.prepare()
        self.cancel(cancel_id="c-9", reason="撤回原因")
        events = self._audit_events()
        self.assertEqual(len(events), 2)
        event = events[1]
        self.assertEqual(
            set(event),
            {"seq", "type", "at", "request_id", "actor_id", "reason",
             "details"},
        )
        self.assertEqual(event["type"], "share_rotation_cancelled")
        self.assertEqual(event["seq"], 2)
        self.assertIsNone(event["request_id"])
        self.assertIsNone(event["actor_id"])
        self.assertIsNone(event["reason"])
        self.assertEqual(
            event["details"],
            {
                "rotation_id": "rot-1",
                "cancel_id": "c-9",
                "reason": "撤回原因",
            },
        )
        self.assertEqual(prepared["rotation_id"], "rot-1")
        # 审计与响应均不含私钥
        path = os.path.join(self.srv.harness.tmpdir, "audit", "w1.json")
        with open(path, encoding="utf-8") as f:
            self.assertNotIn("private_key", f.read())


class RotationCancelServiceTest(unittest.TestCase):
    """直接驱动 service/store：重启持久化、崩溃窗口恢复与灾备。"""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.harness = make_harness(self.tmpdir)
        self.service = self.harness.service
        self.store = self.harness.store
        self.service.create_wallet("w1", 2)

    def _restart(self):
        self.service = WalletService(WalletStore(self.tmpdir))
        return self.service

    def _prepare(self, rotation_id="rot-1"):
        status, view = self.service.create_share_rotation("w1", rotation_id)
        self.assertEqual(status, 201)
        return view

    def test_cancel_persists_across_restart(self):
        self._prepare()
        status, cancelled = self.service.cancel_share_rotation(
            "w1", "rot-1", "c-1", "原因"
        )
        self.assertEqual(status, 201)
        service = self._restart()
        view = service.get_share_rotation("w1", "rot-1")
        self.assertEqual(view, cancelled)
        # 重启后重放仍 200 同体，不补记事件
        status, replay = service.cancel_share_rotation(
            "w1", "rot-1", "c-1", "原因"
        )
        self.assertEqual(status, 200)
        self.assertEqual(replay, cancelled)
        events = service.get_audit_events("w1")["events"]
        self.assertEqual(
            [e["type"] for e in events],
            ["share_rotation_prepared", "share_rotation_cancelled"],
        )

    def test_cancel_event_failure_rolls_back(self):
        self._prepare()

        def boom(wallet_id, event):
            raise OSError("disk full")

        self.service._emit = boom
        with self.assertRaises(OSError):
            self.service.cancel_share_rotation("w1", "rot-1", "c-1", "r")
        # 记录回滚为 prepared，暂存份额保留
        view = self.service.get_share_rotation("w1", "rot-1")
        self.assertEqual(view["state"], "prepared")
        self.assertNotIn("cancellation", view)
        staging = os.path.join(
            self.tmpdir, "rotation-staging", "w1", "rot-1"
        )
        self.assertEqual(
            sorted(os.listdir(staging)),
            ["rot-1-share-1.json", "rot-1-share-2.json"],
        )
        # 无撤销事件、无 seq 缺口；修复后可重试
        events = self.service.get_audit_events("w1")["events"]
        self.assertEqual(
            [e["type"] for e in events], ["share_rotation_prepared"]
        )
        self.service._emit = self.service._audit.append_event
        status, view = self.service.cancel_share_rotation(
            "w1", "rot-1", "c-1", "r"
        )
        self.assertEqual(status, 201)
        self.assertEqual(view["state"], "cancelled")
        events = self.service.get_audit_events("w1")["events"]
        self.assertEqual([e["seq"] for e in events], [1, 2])

    def test_startup_rolls_back_uncommitted_cancel(self):
        self._prepare()
        # 模拟崩溃现场：记录已写 cancelled 但撤销事件未落盘
        record = self.store.get_rotation("w1", "rot-1")
        record["state"] = "cancelled"
        record["cancellation"] = {"cancel_id": "c-1", "reason": "r"}
        self.store.update_rotation("w1", "rot-1", record)
        service = self._restart()
        # 撤销未提交：置回 prepared，暂存份额保留
        view = service.get_share_rotation("w1", "rot-1")
        self.assertEqual(view["state"], "prepared")
        self.assertNotIn("cancellation", view)
        staging = os.path.join(
            self.tmpdir, "rotation-staging", "w1", "rot-1"
        )
        self.assertEqual(
            sorted(os.listdir(staging)),
            ["rot-1-share-1.json", "rot-1-share-2.json"],
        )
        # 可重新撤销
        status, view = service.cancel_share_rotation(
            "w1", "rot-1", "c-1", "r"
        )
        self.assertEqual(status, 201)
        self.assertEqual(view["state"], "cancelled")

    def test_startup_forwards_committed_cancel_and_cleans_staging(self):
        self._prepare()
        status, cancelled = self.service.cancel_share_rotation(
            "w1", "rot-1", "c-1", "r"
        )
        self.assertEqual(status, 201)
        # 模拟崩溃：撤销已提交但暂存目录残留
        staging = os.path.join(
            self.tmpdir, "rotation-staging", "w1", "rot-1"
        )
        os.makedirs(staging)
        with open(os.path.join(staging, "rot-1-share-1.json"), "w") as f:
            json.dump({"share_id": "rot-1-share-1"}, f)
        service = self._restart()
        self.assertFalse(os.path.exists(staging))
        view = service.get_share_rotation("w1", "rot-1")
        self.assertEqual(view, cancelled)

    def test_startup_forward_completes_record_from_event(self):
        self._prepare()
        # 模拟崩溃窗口：撤销事件已落盘但记录仍 prepared、暂存残留
        record = self.store.get_rotation("w1", "rot-1")
        cancelled_record = dict(record)
        cancelled_record["state"] = "cancelled"
        cancelled_record["cancellation"] = {
            "cancel_id": "c-1",
            "reason": "r",
        }
        # 先按正常路径撤销以产生事件，再把记录改回 prepared 并重建暂存
        status, cancelled = self.service.cancel_share_rotation(
            "w1", "rot-1", "c-1", "r"
        )
        self.assertEqual(status, 201)
        self.store.update_rotation("w1", "rot-1", record)
        staging = os.path.join(
            self.tmpdir, "rotation-staging", "w1", "rot-1"
        )
        os.makedirs(staging, exist_ok=True)
        service = self._restart()
        # 事件已提交：保持撤销结果（不复活轮换），记录前滚为 cancelled
        view = service.get_share_rotation("w1", "rot-1")
        self.assertEqual(view, cancelled)
        self.assertFalse(os.path.exists(staging))

    def test_cancel_record_event_mismatch_fails_closed(self):
        self._prepare()
        self.service.cancel_share_rotation("w1", "rot-1", "c-1", "r")
        # 篡改记录使 cancellation 与审计事件矛盾：对账 fail-closed
        record = self.store.get_rotation("w1", "rot-1")
        record["cancellation"] = {"cancel_id": "c-1", "reason": "篡改"}
        self.store.update_rotation("w1", "rot-1", record)
        # 启动恢复无法对账：拒绝就绪（构造即抛），保留现场
        with self.assertRaises(RecoveryError):
            self._restart()

    def test_cancel_activate_interleave_single_terminal(self):
        self._prepare()
        # 撤销与激活交错：只有先提交的一方生效
        self.assertEqual(
            self.service.cancel_share_rotation("w1", "rot-1", "c-1", "r")[0],
            201,
        )
        with self.assertRaises(ServiceError) as ctx:
            self.service.activate_share_rotation("w1", "rot-1")
        self.assertEqual(ctx.exception.status, 409)

    def test_activate_then_cancel_409(self):
        self._prepare()
        self.assertEqual(
            self.service.activate_share_rotation("w1", "rot-1")[0], 201
        )
        with self.assertRaises(ServiceError) as ctx:
            self.service.cancel_share_rotation("w1", "rot-1", "c-1", "r")
        self.assertEqual(ctx.exception.status, 409)

    def test_cancel_survives_backup_restore(self):
        self._prepare()
        status, cancelled = self.service.cancel_share_rotation(
            "w1", "rot-1", "c-1", "撤回"
        )
        self.assertEqual(status, 201)
        out = os.path.join(tempfile.mkdtemp(), "b.tar")
        self.assertEqual(
            drbackup.backup(self.tmpdir, "w1", "S1", out)["status"], 201
        )
        dst = tempfile.mkdtemp()
        self.assertEqual(drbackup.restore(dst, "w1", out)[0], 201)
        restored = make_harness(dst)
        view = restored.service.get_share_rotation("w1", "rot-1")
        self.assertEqual(view, cancelled)
        # 恢复不新增事件；重放仍 200
        events = restored.service.get_audit_events("w1")["events"]
        self.assertEqual(
            [e["type"] for e in events],
            ["share_rotation_prepared", "share_rotation_cancelled"],
        )
        status, replay = restored.service.cancel_share_rotation(
            "w1", "rot-1", "c-1", "撤回"
        )
        self.assertEqual(status, 200)
        self.assertEqual(replay, cancelled)

    def test_private_key_boundary(self):
        """撤销后响应、轮换记录与审计均不含私钥，暂存私钥已清除。"""
        self._prepare()
        _, cancelled = self.service.cancel_share_rotation(
            "w1", "rot-1", "c-1", "r"
        )
        self.assertNotIn("private_key", json.dumps(cancelled))
        for path in (
            os.path.join(self.tmpdir, "rotations", "w1.json"),
            os.path.join(self.tmpdir, "audit", "w1.json"),
        ):
            with open(path, encoding="utf-8") as f:
                self.assertNotIn("private_key", f.read(), path)
        self.assertFalse(
            os.path.exists(
                os.path.join(self.tmpdir, "rotation-staging", "w1", "rot-1")
            )
        )


if __name__ == "__main__":
    unittest.main()
