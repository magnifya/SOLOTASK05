"""份额轮换主动撤销（POST .../share-rotations/{rid}/cancel）测试。

覆盖：首次撤销 201 与 cancellation 视图、同参重放 200、异参/复用/再撤销
409、已激活撤销 409、冻结 409 且零副作用、键集/标识/原因 400、未知
404、其他方法 405、撤销后再准备/激活/槽位绑定语义、审计事件唯一、
崩溃窗口前滚/回滚、重启与 backup/restore 持久化、CLI 对应命令。
"""

from __future__ import annotations

import contextlib
import io
import json
import os
import shutil
import tempfile
import threading
import unittest

from threshold_wallet import drbackup
from threshold_wallet.cli import main as cli_main
from threshold_wallet.service import WalletService
from threshold_wallet.store import WalletStore

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
        status, _ = self.request(
            "POST", "/v1/wallets", {"wallet_id": wallet_id, "shares": 2}
        )
        self.assertEqual(status, 201)

    def prepare(self, wallet_id="w1", rotation_id="rot-1"):
        return self.request(
            "POST",
            f"/v1/wallets/{wallet_id}/share-rotations",
            {"rotation_id": rotation_id},
        )

    def cancel(self, rotation_id="rot-1", wallet_id="w1",
               cancel_id="c1", reason="不再需要进行这次轮换"):
        return self.request(
            "POST",
            f"/v1/wallets/{wallet_id}/share-rotations/{rotation_id}/cancel",
            {"cancel_id": cancel_id, "reason": reason},
        )

    def _audit_events(self, wallet_id="w1"):
        status, body = self.request(
            "GET", f"/v1/wallets/{wallet_id}/audit-events"
        )
        self.assertEqual(status, 200)
        return body["events"]

    def _cancel_events(self, wallet_id="w1"):
        return [
            e for e in self._audit_events(wallet_id)
            if e["type"] == "share_rotation_cancelled"
        ]

    # ---- 首次撤销契约 ------------------------------------------------------

    def test_cancel_201_contract_and_staging_cleaned(self):
        self.create_wallet()
        _, prepared = self.prepare()
        staging = os.path.join(
            self.srv.harness.tmpdir, "rotation-staging", "w1", "rot-1"
        )
        self.assertTrue(os.path.isdir(staging))
        status, body = self.cancel(reason=" 计划变更\t保留原文 ")
        self.assertEqual(status, 201)
        # 既有轮换视图 + 恰含 cancel_id/reason 的 cancellation（原文保留）
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
            {"cancel_id": "c1", "reason": " 计划变更\t保留原文 "},
        )
        # 暂存份额已清理；钱包公钥与在用份额不变
        self.assertFalse(os.path.exists(staging))
        _, wallet = self.request("GET", "/v1/wallets/w1")
        shares_dir = os.path.join(self.srv.harness.tmpdir, "shares", "w1")
        self.assertEqual(
            sorted(os.listdir(shares_dir)), ["share-1.json", "share-2.json"]
        )
        self.assertNotEqual(wallet["public_key"], prepared["public_key"])
        # 查询返回同一撤销视图
        status, view = self.request(
            "GET", "/v1/wallets/w1/share-rotations/rot-1"
        )
        self.assertEqual(status, 200)
        self.assertEqual(view, body)

    def test_cancel_audit_event_exactly_once(self):
        self.create_wallet()
        _, prepared = self.prepare()
        self.cancel(cancel_id="c9", reason="原文 reason")
        events = self._cancel_events()
        self.assertEqual(len(events), 1)
        event = events[0]
        self.assertEqual(
            set(event),
            {"seq", "type", "at", "request_id", "actor_id", "reason",
             "details"},
        )
        self.assertIsNone(event["request_id"])
        self.assertIsNone(event["actor_id"])
        self.assertIsNone(event["reason"])
        self.assertEqual(
            event["details"],
            {
                "rotation_id": "rot-1",
                "cancel_id": "c9",
                "reason": "原文 reason",
            },
        )
        # 审计与轮换记录绝不含私钥
        for rel in ("audit/w1.json", "rotations/w1.json"):
            with open(
                os.path.join(self.srv.harness.tmpdir, rel), encoding="utf-8"
            ) as f:
                self.assertNotIn("private_key", f.read(), rel)
        self.assertEqual(prepared["state"], "prepared")

    # ---- 幂等与判重 --------------------------------------------------------

    def test_replay_200_same_body_no_new_event(self):
        self.create_wallet()
        self.prepare()
        _, first = self.cancel()
        status, second = self.cancel()
        self.assertEqual(status, 200)
        self.assertEqual(second, first)
        self.assertEqual(len(self._cancel_events()), 1)

    def test_same_cancel_id_different_reason_409(self):
        self.create_wallet()
        self.prepare()
        self.assertEqual(self.cancel(reason="r1")[0], 201)
        status, body = self.cancel(reason="r2")
        self.assertEqual(status, 409)
        self.assertIn("error", body)
        self.assertEqual(len(self._cancel_events()), 1)

    def test_new_cancel_id_on_cancelled_rotation_409(self):
        self.create_wallet()
        self.prepare()
        self.assertEqual(self.cancel(cancel_id="c1")[0], 201)
        status, _ = self.cancel(cancel_id="c2", reason="c1")
        self.assertEqual(status, 409)

    def test_cancel_id_reused_on_another_rotation_409(self):
        self.create_wallet()
        self.assertEqual(self.prepare(rotation_id="rot-1")[0], 201)
        self.assertEqual(
            self.cancel(rotation_id="rot-1", cancel_id="c1")[0], 201
        )
        # 撤销释放占用：可用新标识准备下一笔
        self.assertEqual(self.prepare(rotation_id="rot-2")[0], 201)
        status, _ = self.cancel(rotation_id="rot-2", cancel_id="c1")
        self.assertEqual(status, 409)
        # 新标识可撤销 rot-2
        self.assertEqual(
            self.cancel(rotation_id="rot-2", cancel_id="c2")[0], 201
        )

    def test_cancel_active_rotation_409(self):
        self.create_wallet()
        self.prepare()
        status, _ = self.request(
            "POST", "/v1/wallets/w1/share-rotations/rot-1/activate"
        )
        self.assertEqual(status, 201)
        status, _ = self.cancel()
        self.assertEqual(status, 409)
        self.assertEqual(self._cancel_events(), [])

    def test_activate_after_cancel_409(self):
        self.create_wallet()
        self.prepare()
        self.assertEqual(self.cancel()[0], 201)
        status, _ = self.request(
            "POST", "/v1/wallets/w1/share-rotations/rot-1/activate"
        )
        self.assertEqual(status, 409)

    # ---- 撤销后的准备语义 ---------------------------------------------------

    def test_reprepare_same_id_returns_cancelled_view_without_regenerate(self):
        self.create_wallet()
        _, prepared = self.prepare()
        _, cancelled = self.cancel()
        status, body = self.prepare()
        self.assertEqual(status, 200)
        self.assertEqual(body, cancelled)
        # 不生成新份额：share_ids/public_key 与撤销前一致
        self.assertEqual(body["share_ids"], prepared["share_ids"])
        self.assertEqual(body["public_key"], prepared["public_key"])
        # 无新事件
        self.assertEqual(
            [e["type"] for e in self._audit_events()],
            ["share_rotation_prepared", "share_rotation_cancelled"],
        )

    def test_prepare_new_rotation_after_cancel_201(self):
        self.create_wallet()
        self.prepare(rotation_id="rot-1")
        self.cancel(rotation_id="rot-1")
        status, body = self.prepare(rotation_id="rot-2")
        self.assertEqual(status, 201)
        self.assertEqual(body["state"], "prepared")
        self.assertNotIn("cancellation", body)

    # ---- 400 / 404 / 405 ---------------------------------------------------

    def test_bad_body_400(self):
        self.create_wallet()
        self.prepare()
        path = "/v1/wallets/w1/share-rotations/rot-1/cancel"
        # 缺键 / 夹带键 / 非对象
        for body in (
            {"cancel_id": "c1"},
            {"reason": "r"},
            {"cancel_id": "c1", "reason": "r", "extra": 1},
            {},
            [1, 2],
        ):
            status, _ = self.request("POST", path, body)
            self.assertEqual(status, 400, body)
        # cancel_id 非法
        for bad in ("", "has space", "a/b", "..", "x" * 129, "中文", 7, None):
            status, _ = self.request(
                "POST", path, {"cancel_id": bad, "reason": "r"}
            )
            self.assertEqual(status, 400, bad)
        # reason 非法：非字符串/空/全空白/超长/布尔
        for bad in ("", "   ", "x" * 1025, 7, True, None, ["r"]):
            status, _ = self.request(
                "POST", path, {"cancel_id": "c1", "reason": bad}
            )
            self.assertEqual(status, 400, repr(bad))
        # 边界：1024 字符可撤销
        status, _ = self.request(
            "POST", path, {"cancel_id": "c1", "reason": "x" * 1024}
        )
        self.assertEqual(status, 201)

    def test_unknown_404(self):
        self.create_wallet()
        self.prepare()
        status, _ = self.cancel(wallet_id="ghost")
        self.assertEqual(status, 404)
        status, _ = self.cancel(rotation_id="nope")
        self.assertEqual(status, 404)

    def test_other_methods_405(self):
        self.create_wallet()
        self.prepare()
        path = "/v1/wallets/w1/share-rotations/rot-1/cancel"
        for method in ("GET", "PUT", "DELETE", "PATCH"):
            status, _ = self.request(method, path)
            self.assertEqual(status, 405, method)

    # ---- 冻结 --------------------------------------------------------------

    def test_frozen_wallet_cancel_and_replay_409_no_side_effects(self):
        self.create_wallet()
        self.prepare()
        status, _ = self.request(
            "POST", "/v1/wallets/w1/freeze", {"reason": "应急"}
        )
        self.assertEqual(status, 201)
        status, _ = self.cancel()
        self.assertEqual(status, 409)
        # 查询仍可用，轮换仍是 prepared，暂存保留，无撤销事件
        status, view = self.request(
            "GET", "/v1/wallets/w1/share-rotations/rot-1"
        )
        self.assertEqual(status, 200)
        self.assertEqual(view["state"], "prepared")
        self.assertNotIn("cancellation", view)
        self.assertEqual(self._cancel_events(), [])
        staging = os.path.join(
            self.srv.harness.tmpdir, "rotation-staging", "w1", "rot-1"
        )
        self.assertTrue(os.path.isdir(staging))
        # 解冻后撤销可用；撤销后再冻结，重放也 409
        status, _ = self.request(
            "POST", "/v1/wallets/w1/unfreeze", {"reason": "解除"}
        )
        self.assertEqual(status, 201)
        self.assertEqual(self.cancel()[0], 201)
        self.request("POST", "/v1/wallets/w1/freeze", {"reason": "再冻"})
        status, _ = self.cancel()
        self.assertEqual(status, 409)


class RotationCancelServiceTest(unittest.TestCase):
    """直接驱动 service/store：重启持久化、崩溃窗口恢复、并发终态。"""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmpdir, ignore_errors=True)
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

    def _cancel(self, rotation_id="rot-1", cancel_id="c1", reason="r"):
        return self.service.cancel_share_rotation(
            "w1", rotation_id, {"cancel_id": cancel_id, "reason": reason}
        )

    def _cancel_events(self, service=None):
        service = service or self.service
        return [
            e
            for e in service.get_audit_events("w1")["events"]
            if e["type"] == "share_rotation_cancelled"
        ]

    def test_state_survives_restart_and_replay(self):
        self._prepare()
        status, cancelled = self._cancel(reason="重启前撤销")
        self.assertEqual(status, 201)
        service = self._restart()
        view = service.get_share_rotation("w1", "rot-1")
        self.assertEqual(view, cancelled)
        self.assertEqual(view["state"], "cancelled")
        # 重启后同参重放 200 同体、不新增事件
        status, replay = service.cancel_share_rotation(
            "w1", "rot-1", {"cancel_id": "c1", "reason": "重启前撤销"}
        )
        self.assertEqual(status, 200)
        self.assertEqual(replay, cancelled)
        self.assertEqual(len(self._cancel_events(service)), 1)
        # 撤销后用新标识准备下一笔
        status, _ = service.create_share_rotation("w1", "rot-2")
        self.assertEqual(status, 201)

    def test_emit_failure_rolls_back_to_prepared(self):
        self._prepare()

        def boom(wallet_id, event):
            raise OSError("disk full")

        self.service._emit = boom
        with self.assertRaises(OSError):
            self._cancel()
        # 记录回滚为 prepared，暂存份额保留，无事件
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
        self.assertEqual(self._cancel_events(), [])
        # 修复后可重试，seq 连续
        self.service._emit = self.service._audit.append_event
        status, _ = self._cancel()
        self.assertEqual(status, 201)
        events = self.service.get_audit_events("w1")["events"]
        self.assertEqual([e["seq"] for e in events], [1, 2])
        self.assertEqual(events[1]["type"], "share_rotation_cancelled")

    def test_event_landed_then_error_still_commits(self):
        self._prepare()
        original = self.service._audit.append_event

        def boom(wallet_id, event):
            result = original(wallet_id, event)
            raise OSError("crash after commit")

        self.service._emit = boom
        # 事件已落盘：提交不可撤回，前滚为 cancelled 并清理暂存
        status, view = self._cancel()
        self.assertEqual(status, 201)
        self.assertEqual(view["state"], "cancelled")
        self.assertEqual(len(self._cancel_events()), 1)
        staging = os.path.join(
            self.tmpdir, "rotation-staging", "w1", "rot-1"
        )
        self.assertFalse(os.path.exists(staging))
        # 重启后仍是 cancelled，不复活
        service = self._restart()
        self.assertEqual(
            service.get_share_rotation("w1", "rot-1")["state"], "cancelled"
        )

    def test_startup_rolls_back_uncommitted_cancel(self):
        self._prepare()
        # 模拟崩溃现场：记录已写 cancelled 但撤销事件未落盘
        record = self.store.get_rotation("w1", "rot-1")
        crashed = dict(record)
        crashed["state"] = "cancelled"
        crashed["cancellation"] = {"cancel_id": "c1", "reason": "r"}
        self.store.update_rotation("w1", "rot-1", crashed)
        service = self._restart()
        # 回滚为 prepared，暂存份额保留，可重新撤销或激活
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
        status, _ = service.activate_share_rotation("w1", "rot-1")
        self.assertEqual(status, 201)

    def test_lazy_heal_rolls_back_uncommitted_cancel_then_retries(self):
        self._prepare()
        # 不重启：他进程崩溃遗留的 cancelled 记录（无事件）在持锁访问时
        # 自愈回滚为 prepared，随后同参撤销作为首次撤销成功
        record = self.store.get_rotation("w1", "rot-1")
        crashed = dict(record)
        crashed["state"] = "cancelled"
        crashed["cancellation"] = {"cancel_id": "c1", "reason": "r"}
        self.store.update_rotation("w1", "rot-1", crashed)
        status, view = self._cancel()
        self.assertEqual(status, 201)
        self.assertEqual(view["state"], "cancelled")
        self.assertEqual(len(self._cancel_events()), 1)

    def test_startup_forward_completes_committed_cancel(self):
        self._prepare()
        status, cancelled = self._cancel(reason="已提交")
        self.assertEqual(status, 201)
        # 模拟崩溃窗口：事件已落盘但记录停在 prepared、暂存残留
        record = self.store.get_rotation("w1", "rot-1")
        reverted = {
            k: v for k, v in record.items() if k != "cancellation"
        }
        reverted["state"] = "prepared"
        self.store.update_rotation("w1", "rot-1", reverted)
        staging = os.path.join(
            self.tmpdir, "rotation-staging", "w1", "rot-1"
        )
        os.makedirs(staging)
        with open(os.path.join(staging, "leftover.json"), "w") as f:
            json.dump({"share_id": "leftover"}, f)
        service = self._restart()
        view = service.get_share_rotation("w1", "rot-1")
        self.assertEqual(view, cancelled)
        self.assertFalse(os.path.exists(staging))
        # 恢复不新增事件
        self.assertEqual(len(self._cancel_events(service)), 1)

    def test_startup_cleans_staging_leftover_of_cancelled(self):
        self._prepare()
        self._cancel()
        staging = os.path.join(
            self.tmpdir, "rotation-staging", "w1", "rot-1"
        )
        os.makedirs(staging)
        with open(os.path.join(staging, "leftover.json"), "w") as f:
            json.dump({"share_id": "leftover"}, f)
        self._restart()
        self.assertFalse(os.path.exists(staging))
        view = self.service.get_share_rotation("w1", "rot-1")
        self.assertEqual(view["state"], "cancelled")

    def test_contradictory_cancel_scene_fails_closed(self):
        self._prepare()
        self._cancel(cancel_id="c1", reason="r1")
        # 篡改：记录的撤销快照与已提交事件不一致
        record = self.store.get_rotation("w1", "rot-1")
        tampered = dict(record)
        tampered["cancellation"] = {"cancel_id": "c1", "reason": "other"}
        self.store.update_rotation("w1", "rot-1", tampered)
        with self.assertRaises(Exception):
            self._restart()

    def test_cancel_vs_activate_exactly_one_terminal_state(self):
        self._prepare()
        results = {}
        barrier = threading.Barrier(2)

        def run(name, fn):
            barrier.wait()
            try:
                results[name] = fn()
            except Exception as exc:  # ServiceError 409 等
                results[name] = (getattr(exc, "status", None), str(exc))

        threads = [
            threading.Thread(
                target=run,
                args=("cancel", lambda: self._cancel()),
            ),
            threading.Thread(
                target=run,
                args=(
                    "activate",
                    lambda: self.service.activate_share_rotation(
                        "w1", "rot-1"
                    ),
                ),
            ),
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        statuses = {
            name: outcome[0] for name, outcome in results.items()
        }
        # 只能一个终态生效：一方 201，另一方 409
        self.assertEqual(sorted(statuses.values()), [201, 409])
        service = self._restart()
        final = service.get_share_rotation("w1", "rot-1")["state"]
        winner = min(statuses, key=lambda k: statuses[k] != 201)
        self.assertEqual(
            final, "cancelled" if winner == "cancel" else "active"
        )

    def test_cancel_survives_backup_restore(self):
        self._prepare()
        _, cancelled = self._cancel(reason="灾备原文")
        out = os.path.join(tempfile.mkdtemp(), "snap.tar")
        self.assertEqual(
            drbackup.backup(self.tmpdir, "w1", "S1", out)["status"], 201
        )
        dst = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, dst, ignore_errors=True)
        self.assertEqual(drbackup.restore(dst, "w1", out)[0], 201)
        service = make_harness(dst).service
        view = service.get_share_rotation("w1", "rot-1")
        self.assertEqual(view, cancelled)
        # 恢复不新增事件；重放 200 同体
        self.assertEqual(len(self._cancel_events(service)), 1)
        status, replay = service.cancel_share_rotation(
            "w1", "rot-1", {"cancel_id": "c1", "reason": "灾备原文"}
        )
        self.assertEqual(status, 200)
        self.assertEqual(replay, cancelled)

    def test_old_snapshot_without_cancel_still_restores(self):
        self._prepare()
        out = os.path.join(tempfile.mkdtemp(), "snap.tar")
        self.assertEqual(
            drbackup.backup(self.tmpdir, "w1", "S1", out)["status"], 201
        )
        # 快照之后撤销；旧快照（prepared 现场）仍可恢复
        self._cancel()
        dst = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, dst, ignore_errors=True)
        self.assertEqual(drbackup.restore(dst, "w1", out)[0], 201)
        service = make_harness(dst).service
        view = service.get_share_rotation("w1", "rot-1")
        self.assertEqual(view["state"], "prepared")
        self.assertNotIn("cancellation", view)
        status, _ = service.activate_share_rotation("w1", "rot-1")
        self.assertEqual(status, 201)

    def test_signatures_and_wallet_untouched_by_cancel(self):
        # 撤销前完成一次签名；撤销后重放仍 200，钱包公钥与份额不变
        wallet_before = self.store.get_wallet("w1")
        body = {
            "signing_request_id": "r1",
            "message": "hello",
            "signatures": self.harness.two_signatures("w1", "r1", "hello"),
        }
        status, first = self.service.sign(
            "w1", "r1", "hello", body["signatures"]
        )
        self.assertEqual(status, 201)
        self._prepare()
        status, _ = self._cancel()
        self.assertEqual(status, 201)
        self.assertEqual(self.store.get_wallet("w1"), wallet_before)
        for sid in ("share-1", "share-2"):
            self.assertIsNotNone(self.store.get_share("w1", sid))
        status, replay = self.service.sign(
            "w1", "r1", "hello", body["signatures"]
        )
        self.assertEqual(status, 200)
        self.assertEqual(replay["signature"], first["signature"])


class RotationCancelShareBindTest(unittest.TestCase):
    """撤销后首次槽位绑定 409；既有绑定审计与同参重放不受影响。"""

    KEY_A = "aa" * 32
    KEY_B = "bb" * 32
    KEY_C = "cc" * 32
    HASH_A = "11" * 32
    HASH_B = "22" * 32
    HASH_C = "33" * 32
    HEALTH = {
        "n1": {"key": KEY_A, "state": "up"},
        "n2": {"key": KEY_B, "state": "up"},
        "n3": {"key": KEY_C, "state": "down"},
    }

    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.d, ignore_errors=True)
        self.svc = make_harness(self.d).service
        self.svc.create_wallet("w1", 2)
        self.svc.put_policy("w1", 1, 600)
        self.svc.put_dkg_nodes("w1", self.HEALTH)
        for op, node, key, hsh in (
            ("register", "n1", self.KEY_A, None),
            ("register", "n2", self.KEY_B, None),
            ("commit", "n1", None, self.HASH_A),
            ("commit", "n2", None, self.HASH_B),
        ):
            code, _ = self.svc.post_dkg_stage(
                "w1", "d1", op, node, key, hsh, None
            )
            self.assertEqual(code, 201)
        rj_msg = json.dumps(
            {
                "rejoin_id": "rj1",
                "dkg_id": "d1",
                "round": 1,
                "node": "n3",
                "key": self.KEY_C,
            },
            separators=(",", ":"),
        )
        self.svc.create_sign_request("w1", "apR", rj_msg)
        self.svc.approve("w1", "apR", "boss")
        code, _ = self.svc.post_node_rejoin(
            "w1", "n3", "rj1", "d1", 1, self.KEY_C, "apR"
        )
        self.assertEqual(code, 201)
        ri_msg = json.dumps(
            {
                "dkg_id": "d1",
                "round": 2,
                "action": "reinstate",
                "node": "n2",
                "replacement": "n3",
                "key": self.KEY_C,
            },
            separators=(",", ":"),
        )
        self.svc.create_sign_request("w1", "ap2", ri_msg)
        self.svc.approve("w1", "ap2", "boss")
        code, _ = self.svc.post_dkg_failover(
            "w1", "d1", 2, "reinstate", "n2", "n3", self.KEY_C, "ap2"
        )
        self.assertEqual(code, 201)
        for node, hsh in (("n1", self.HASH_A), ("n3", self.HASH_C)):
            code, _ = self.svc.post_dkg_stage(
                "w1", "d1", "commit", node, None, hsh, None, "2"
            )
            self.assertEqual(code, 201)
        for node, peer in (("n1", "n3"), ("n3", "n1")):
            code, _ = self.svc.post_dkg_stage(
                "w1",
                "d1",
                "share",
                node,
                None,
                {"n1": self.HASH_A, "n3": self.HASH_C}[peer],
                peer,
                "2",
            )
            self.assertEqual(code, 201)
        code, _ = self.svc.create_share_rotation("w1", "rot1")
        self.assertEqual(code, 201)

    @staticmethod
    def _bind_message():
        return json.dumps(
            {
                "id": "b1",
                "rotation": "rot1",
                "dkg": "d1",
                "round": 2,
                "node": "n3",
                "slot": 2,
            },
            separators=(",", ":"),
        )

    def _approve_bind(self):
        self.svc.create_sign_request("w1", "apB", self._bind_message())
        self.svc.approve("w1", "apB", "boss")

    def _bind(self):
        try:
            return self.svc.post_share_bind(
                "w1", "b1", "rot1", "d1", 2, "n3", 2, "apB"
            )
        except Exception as exc:
            return getattr(exc, "status", None), {"error": str(exc)}

    def test_first_bind_on_cancelled_rotation_409(self):
        self._approve_bind()
        status, _ = self.svc.cancel_share_rotation(
            "w1", "rot1", {"cancel_id": "c1", "reason": "r"}
        )
        self.assertEqual(status, 201)
        code, _ = self._bind()
        self.assertEqual(code, 409)

    def test_completed_bind_replay_survives_cancel(self):
        self._approve_bind()
        code, view = self._bind()
        self.assertEqual(code, 201)
        # 绑定完成后撤销轮换：绑定审计保留，同参重放仍 200
        status, _ = self.svc.cancel_share_rotation(
            "w1", "rot1", {"cancel_id": "c1", "reason": "r"}
        )
        self.assertEqual(status, 201)
        code, replay = self._bind()
        self.assertEqual(code, 200)
        self.assertEqual(replay, view)


class RotationCancelCliTest(unittest.TestCase):
    def setUp(self):
        self._ctx = http_server(tempfile.mkdtemp())
        self.srv = self._ctx.__enter__()
        self.url = self.srv.base_url

    def tearDown(self):
        self._ctx.__exit__(None, None, None)

    def run_cli(self, *argv):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = cli_main(list(argv))
        return code, out.getvalue().strip(), err.getvalue().strip()

    def test_rotation_cancel_via_cli(self):
        self.srv.request(
            "POST", "/v1/wallets", {"wallet_id": "w1", "shares": 2}
        )
        self.srv.request(
            "POST", "/v1/wallets/w1/share-rotations", {"rotation_id": "rot-1"}
        )
        code, out, err = self.run_cli(
            "rotation-cancel",
            "--url", self.url,
            "--wallet-id", "w1",
            "--rotation-id", "rot-1",
            "--cancel-id", "c1",
            "--reason", "计划取消",
        )
        self.assertEqual(code, 0, err)
        body = json.loads(out)
        self.assertEqual(body["state"], "cancelled")
        self.assertEqual(
            body["cancellation"], {"cancel_id": "c1", "reason": "计划取消"}
        )
        self.assertNotIn("private_key", out)
        # 重放退出码仍为 0（200）
        code, out2, _ = self.run_cli(
            "rotation-cancel",
            "--url", self.url,
            "--wallet-id", "w1",
            "--rotation-id", "rot-1",
            "--cancel-id", "c1",
            "--reason", "计划取消",
        )
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(out2), body)


if __name__ == "__main__":
    unittest.main()
