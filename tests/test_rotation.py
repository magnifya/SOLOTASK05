"""份额轮换灾备测试：准备/查询/激活、幂等重放、签名切换、审计与启动恢复。"""

from __future__ import annotations

import json
import os
import tempfile
import unittest

from threshold_wallet import crypto
from threshold_wallet.service import WalletService
from threshold_wallet.store import WalletStore

from tests.helpers import http_server, make_harness


class RotationHttpTest(unittest.TestCase):
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

    def activate(self, wallet_id="w1", rotation_id="rot-1"):
        return self.request(
            "POST",
            f"/v1/wallets/{wallet_id}/share-rotations/{rotation_id}/activate",
        )

    # ---- 准备 -----------------------------------------------------------

    def test_prepare_201_contract(self):
        wallet = self.create_wallet()
        status, body = self.prepare()
        self.assertEqual(status, 201)
        self.assertEqual(
            set(body), {"rotation_id", "state", "share_ids", "public_key"}
        )
        self.assertEqual(body["rotation_id"], "rot-1")
        self.assertEqual(body["state"], "prepared")
        self.assertEqual(
            body["share_ids"], ["rot-1-share-1", "rot-1-share-2"]
        )
        self.assertEqual(len(bytes.fromhex(body["public_key"])), 64)
        # 新公钥必须不同于在用车钱包公钥
        self.assertNotEqual(body["public_key"], wallet["public_key"])
        # 准备阶段钱包元数据不变
        _, current = self.request("GET", "/v1/wallets/w1")
        self.assertEqual(current["public_key"], wallet["public_key"])

    def test_prepare_writes_two_staging_files_with_private_keys(self):
        self.create_wallet()
        _, body = self.prepare()
        staging = os.path.join(
            self.srv.harness.tmpdir,
            "rotation-staging",
            "w1",
            "rot-1",
        )
        for share_id in body["share_ids"]:
            path = os.path.join(staging, share_id + ".json")
            self.assertTrue(os.path.exists(path), path)
            with open(path, encoding="utf-8") as f:
                record = json.load(f)
            self.assertEqual(record["share_id"], share_id)
            self.assertEqual(len(bytes.fromhex(record["private_key"])), 32)
        # 暂存目录里恰好两份新份额，无其他文件
        self.assertEqual(sorted(os.listdir(staging)), [
            "rot-1-share-1.json",
            "rot-1-share-2.json",
        ])

    def test_prepare_replay_200_does_not_regenerate(self):
        self.create_wallet()
        _, first = self.prepare()
        status, second = self.prepare()
        self.assertEqual(status, 200)
        self.assertEqual(second, first)

    def test_prepare_invalid_rotation_id_400(self):
        self.create_wallet()
        for bad in ("", "has space", "a/b", ".." , "x" * 129, "中文"):
            status, body = self.prepare(rotation_id=bad)
            self.assertEqual(status, 400, bad)
            self.assertIn("error", body)
        status, body = self.request(
            "POST", "/v1/wallets/w1/share-rotations", {"rotation_id": 7}
        )
        self.assertEqual(status, 400)

    def test_prepare_missing_wallet_404(self):
        status, body = self.prepare(wallet_id="ghost")
        self.assertEqual(status, 404)
        self.assertIn("error", body)

    def test_prepare_second_prepared_conflict_409(self):
        self.create_wallet()
        self.assertEqual(self.prepare(rotation_id="rot-1")[0], 201)
        status, body = self.prepare(rotation_id="rot-2")
        self.assertEqual(status, 409)
        self.assertIn("error", body)
        # 原 prepared 轮换不受影响
        status, view = self.request(
            "GET", "/v1/wallets/w1/share-rotations/rot-1"
        )
        self.assertEqual(status, 200)
        self.assertEqual(view["state"], "prepared")

    def test_prepare_after_activation_allowed(self):
        self.create_wallet()
        self.prepare(rotation_id="rot-1")
        self.assertEqual(self.activate(rotation_id="rot-1")[0], 201)
        status, body = self.prepare(rotation_id="rot-2")
        self.assertEqual(status, 201)
        self.assertEqual(body["state"], "prepared")

    # ---- 查询 -----------------------------------------------------------

    def test_get_rotation_200_and_404(self):
        self.create_wallet()
        _, prepared = self.prepare()
        status, body = self.request(
            "GET", "/v1/wallets/w1/share-rotations/rot-1"
        )
        self.assertEqual(status, 200)
        self.assertEqual(body, prepared)
        status, body = self.request(
            "GET", "/v1/wallets/w1/share-rotations/nope"
        )
        self.assertEqual(status, 404)
        status, body = self.request(
            "GET", "/v1/wallets/ghost/share-rotations/rot-1"
        )
        self.assertEqual(status, 404)

    # ---- 激活 -----------------------------------------------------------

    def test_activate_201_swaps_shares_and_cleans_staging(self):
        wallet = self.create_wallet()
        _, prepared = self.prepare()
        status, body = self.activate()
        self.assertEqual(status, 201)
        self.assertEqual(body["state"], "active")
        self.assertEqual(body["share_ids"], prepared["share_ids"])
        self.assertEqual(body["public_key"], prepared["public_key"])
        # 钱包元数据已切换
        _, current = self.request("GET", "/v1/wallets/w1")
        self.assertEqual(current["public_key"], prepared["public_key"])
        # 新份额文件就位、旧份额文件删除、暂存目录清空
        shares_dir = os.path.join(
            self.srv.harness.tmpdir, "shares", "w1"
        )
        self.assertEqual(
            sorted(os.listdir(shares_dir)),
            ["rot-1-share-1.json", "rot-1-share-2.json"],
        )
        staging = os.path.join(
            self.srv.harness.tmpdir, "rotation-staging", "w1", "rot-1"
        )
        self.assertFalse(os.path.exists(staging))
        # 轮换状态持久化
        status, view = self.request(
            "GET", "/v1/wallets/w1/share-rotations/rot-1"
        )
        self.assertEqual(status, 200)
        self.assertEqual(view["state"], "active")

    def test_activate_replay_200(self):
        self.create_wallet()
        self.prepare()
        _, first = self.activate()
        status, second = self.activate()
        self.assertEqual(status, 200)
        self.assertEqual(second, first)

    def test_activate_unknown_rotation_404(self):
        self.create_wallet()
        status, body = self.activate(rotation_id="nope")
        self.assertEqual(status, 404)
        status, body = self.activate(wallet_id="ghost")
        self.assertEqual(status, 404)

    # ---- 激活后签名 -----------------------------------------------------

    def _sign_body(self, wallet_id, srid, message, share_ids):
        return {
            "signing_request_id": srid,
            "message": message,
            "signatures": [
                {
                    "share_id": sid,
                    "signature": self.srv.harness.share_signature(
                        wallet_id, sid, srid, message
                    ),
                }
                for sid in share_ids
            ],
        }

    def test_sign_after_activation_requires_new_shares(self):
        self.create_wallet()
        # 激活前先构造好旧份额签名（激活后旧份额私钥文件已删除）
        old_body = self._sign_body("w1", "r1", "hello", ["share-1", "share-2"])
        self.prepare()
        self.activate()
        # 旧份额 400
        status, body = self.request(
            "POST", "/v1/wallets/w1/sign", old_body
        )
        self.assertEqual(status, 400)
        # 新份额 201，聚合签名可用新公钥拆半独立验证
        new_ids = ["rot-1-share-1", "rot-1-share-2"]
        status, body = self.request(
            "POST",
            "/v1/wallets/w1/sign",
            self._sign_body("w1", "r1", "hello", new_ids),
        )
        self.assertEqual(status, 201)
        _, rotation = self.request(
            "GET", "/v1/wallets/w1/share-rotations/rot-1"
        )
        public_key = bytes.fromhex(rotation["public_key"])
        signature = bytes.fromhex(body["signature"])
        payload = crypto.build_payload("r1", "hello")
        for index, share_public in enumerate(crypto.split_public_key(public_key)):
            share_sig = crypto.split_signature(signature)[index]
            self.assertTrue(
                crypto.verify_share(share_public, payload, share_sig)
            )
        # 重放 200
        status, replay = self.request(
            "POST",
            "/v1/wallets/w1/sign",
            self._sign_body("w1", "r1", "hello", new_ids),
        )
        self.assertEqual(status, 200)
        self.assertEqual(replay["signature"], body["signature"])

    def test_signature_before_activation_still_replays_after(self):
        self.create_wallet()
        body = self._sign_body("w1", "r0", "early", ["share-1", "share-2"])
        status, first = self.request("POST", "/v1/wallets/w1/sign", body)
        self.assertEqual(status, 201)
        self.prepare()
        self.activate()
        # 已首签的请求激活后重放仍 200，不受份额切换影响
        status, replay = self.request("POST", "/v1/wallets/w1/sign", body)
        self.assertEqual(status, 200)
        self.assertEqual(replay["signature"], first["signature"])

    # ---- 审计 -----------------------------------------------------------

    def _audit_events(self, wallet_id="w1"):
        status, body = self.request(
            "GET", f"/v1/wallets/{wallet_id}/audit-events"
        )
        self.assertEqual(status, 200)
        return body["events"]

    def test_audit_prepared_and_activated(self):
        wallet = self.create_wallet()
        _, prepared = self.prepare()
        self.activate()
        events = self._audit_events()
        self.assertEqual(
            [e["type"] for e in events],
            ["share_rotation_prepared", "share_rotation_activated"],
        )
        # 七字段齐备、seq 从 1 连续
        for index, event in enumerate(events, start=1):
            self.assertEqual(
                set(event),
                {"seq", "type", "at", "request_id", "actor_id",
                 "reason", "details"},
            )
            self.assertEqual(event["seq"], index)
            self.assertIsNone(event["request_id"])
            self.assertIsNone(event["actor_id"])
            self.assertIsNone(event["reason"])
        self.assertEqual(
            events[0]["details"],
            {
                "rotation_id": "rot-1",
                "share_ids": prepared["share_ids"],
                "public_key": prepared["public_key"],
            },
        )
        self.assertEqual(
            events[1]["details"],
            {
                "rotation_id": "rot-1",
                "share_ids": prepared["share_ids"],
                "public_key": prepared["public_key"],
                "previous_public_key": wallet["public_key"],
            },
        )

    def test_audit_replays_do_not_add_events(self):
        self.create_wallet()
        self.prepare()
        self.prepare()
        self.activate()
        self.activate()
        events = self._audit_events()
        self.assertEqual(len(events), 2)
        self.assertEqual([e["seq"] for e in events], [1, 2])

    def test_audit_details_contain_no_private_key(self):
        self.create_wallet()
        self.prepare()
        self.activate()
        path = os.path.join(
            self.srv.harness.tmpdir, "audit", "w1.json"
        )
        with open(path, encoding="utf-8") as f:
            raw = f.read()
        self.assertNotIn("private_key", raw)


class RotationServiceTest(unittest.TestCase):
    """直接驱动 service/store：重启持久化、失败回滚与启动恢复。"""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.harness = make_harness(self.tmpdir)
        self.service = self.harness.service
        self.store = self.harness.store
        self.service.create_wallet("w1", 2)

    def _restart(self):
        self.service = WalletService(WalletStore(self.tmpdir))
        return self.service

    def test_state_survives_restart(self):
        status, prepared = self.service.create_share_rotation("w1", "rot-1")
        self.assertEqual(status, 201)
        service = self._restart()
        view = service.get_share_rotation("w1", "rot-1")
        self.assertEqual(view, prepared)
        # 重启后同 ID 重放仍 200 不重生
        status, replay = service.create_share_rotation("w1", "rot-1")
        self.assertEqual(status, 200)
        self.assertEqual(replay, prepared)
        # 重启后激活仍可用，且激活状态同样跨重启
        status, active = service.activate_share_rotation("w1", "rot-1")
        self.assertEqual(status, 201)
        service = self._restart()
        view = service.get_share_rotation("w1", "rot-1")
        self.assertEqual(view["state"], "active")
        self.assertEqual(view["public_key"], active["public_key"])

    def test_startup_rolls_back_incomplete_activation(self):
        _, prepared = self.service.create_share_rotation("w1", "rot-1")
        wallet_before = self.store.get_wallet("w1")
        old_shares = {
            sid: self.store.get_share("w1", sid)
            for sid in ("share-1", "share-2")
        }
        # 模拟崩溃现场：activating 标记 + 备份已落盘，新份额已换入一半
        activating = dict(prepared)
        activating["state"] = "activating"
        activating["previous_public_key"] = wallet_before["public_key"]
        record = self.store.get_rotation("w1", "rot-1")
        record.update(activating)
        self.store.update_rotation("w1", "rot-1", record)
        self.store.save_activation_backups(
            "w1",
            "rot-1",
            list(old_shares.values()),
            wallet_before,
        )
        staged = self.store.get_staging_share("w1", "rot-1", "rot-1-share-1")
        self.store.save_share("w1", staged)
        self.store.delete_share("w1", "share-1")
        tampered = dict(wallet_before)
        tampered["public_key"] = prepared["public_key"]
        self.store.save_wallet_meta("w1", tampered)

        # 重启：未完成的激活先回滚
        service = self._restart()
        view = service.get_share_rotation("w1", "rot-1")
        self.assertEqual(view["state"], "prepared")
        # 钱包元数据与旧份额文件恢复，新份额文件清除
        self.assertEqual(self.store.get_wallet("w1"), wallet_before)
        for sid, share_record in old_shares.items():
            self.assertEqual(self.store.get_share("w1", sid), share_record)
        self.assertIsNone(self.store.get_share("w1", "rot-1-share-1"))
        # 备份已清理，暂存的新份额保留（可重试激活）
        staging = os.path.join(
            self.tmpdir, "rotation-staging", "w1", "rot-1"
        )
        self.assertEqual(
            sorted(os.listdir(staging)),
            ["rot-1-share-1.json", "rot-1-share-2.json"],
        )
        # 回滚后可正常重新激活
        status, active = service.activate_share_rotation("w1", "rot-1")
        self.assertEqual(status, 201)
        self.assertEqual(active["state"], "active")

    def test_startup_cleans_staging_of_completed_activation(self):
        self.service.create_share_rotation("w1", "rot-1")
        self.service.activate_share_rotation("w1", "rot-1")
        # 模拟崩溃：激活已提交但暂存目录残留
        staging = os.path.join(
            self.tmpdir, "rotation-staging", "w1", "rot-1"
        )
        os.makedirs(staging)
        with open(os.path.join(staging, "leftover.json"), "w") as f:
            json.dump({"share_id": "leftover"}, f)
        self._restart()
        self.assertFalse(os.path.exists(staging))

    def test_activation_event_failure_rolls_back(self):
        _, prepared = self.service.create_share_rotation("w1", "rot-1")
        wallet_before = self.store.get_wallet("w1")

        def boom(wallet_id, event):
            raise OSError("disk full")

        self.service._emit = boom
        with self.assertRaises(OSError):
            self.service.activate_share_rotation("w1", "rot-1")
        # 文件、公钥、状态全部回滚，暂存备份已清理
        self.assertEqual(self.store.get_wallet("w1"), wallet_before)
        for sid in ("share-1", "share-2"):
            self.assertIsNotNone(self.store.get_share("w1", sid))
        for sid in prepared["share_ids"]:
            self.assertIsNone(self.store.get_share("w1", sid))
        view = self.service.get_share_rotation("w1", "rot-1")
        self.assertEqual(view["state"], "prepared")
        staging = os.path.join(
            self.tmpdir, "rotation-staging", "w1", "rot-1"
        )
        self.assertEqual(
            sorted(os.listdir(staging)),
            ["rot-1-share-1.json", "rot-1-share-2.json"],
        )
        # 无事件、无 seq 缺口
        events = self.service.get_audit_events("w1")["events"]
        self.assertEqual([e["type"] for e in events],
                         ["share_rotation_prepared"])
        # 修复后可重试激活，seq 连续
        self.service._emit = self.service._audit.append_event
        status, _ = self.service.activate_share_rotation("w1", "rot-1")
        self.assertEqual(status, 201)
        events = self.service.get_audit_events("w1")["events"]
        self.assertEqual([e["seq"] for e in events], [1, 2])
        self.assertEqual(events[1]["type"], "share_rotation_activated")

    def test_prepare_event_failure_rolls_back(self):
        def boom(wallet_id, event):
            raise OSError("disk full")

        self.service._emit = boom
        with self.assertRaises(OSError):
            self.service.create_share_rotation("w1", "rot-1")
        # 轮换记录与暂存文件全部清理
        self.assertIsNone(self.store.get_rotation("w1", "rot-1"))
        staging = os.path.join(
            self.tmpdir, "rotation-staging", "w1", "rot-1"
        )
        self.assertFalse(os.path.exists(staging))
        # 无事件；修复后可重新准备，seq 从 1 连续
        self.service._emit = self.service._audit.append_event
        status, _ = self.service.create_share_rotation("w1", "rot-1")
        self.assertEqual(status, 201)
        events = self.service.get_audit_events("w1")["events"]
        self.assertEqual([e["seq"] for e in events], [1])

    def test_private_key_boundary(self):
        """元数据、轮换记录、审计与响应均不含私钥；私钥只在份额/暂存文件。"""
        _, prepared = self.service.create_share_rotation("w1", "rot-1")
        self.service.activate_share_rotation("w1", "rot-1")
        # 响应不含私钥
        self.assertNotIn("private_key", json.dumps(prepared))
        # 钱包元数据与轮换记录不含私钥
        for path in (
            os.path.join(self.tmpdir, "wallets", "w1.json"),
            os.path.join(self.tmpdir, "rotations", "w1.json"),
            os.path.join(self.tmpdir, "audit", "w1.json"),
        ):
            with open(path, encoding="utf-8") as f:
                self.assertNotIn("private_key", f.read(), path)
        # 激活后暂存目录已删除，私钥只存在于新份额文件（一份一个文件）
        shares_dir = os.path.join(self.tmpdir, "shares", "w1")
        for name in os.listdir(shares_dir):
            with open(os.path.join(shares_dir, name), encoding="utf-8") as f:
                record = json.load(f)
            self.assertIn("private_key", record)
            self.assertEqual(len(record["private_key"]), 64)


if __name__ == "__main__":
    unittest.main()
