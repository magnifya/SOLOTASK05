"""恢复 fail-closed 与运行时（常驻进程）自愈测试。

覆盖任务契约：
- 启动恢复无法把崩溃现场对账到一致状态时，WalletService 构造直接抛
  RecoveryError，阻止服务就绪，绝不静默跳过；
- 对外接口在常驻进程内遇到他进程崩溃遗留的现场时，在每钱包事务锁内
  先自愈：事件未落盘的激活回滚 prepared（恢复旧公钥/旧份额），
  事件已落盘的激活前滚为唯一 active；恢复失败的请求返回 503，
  绝不暴露半完成状态；
- 恢复/自愈不新增业务审计事件、不泄露私钥。
"""

from __future__ import annotations

import json
import os
import shutil
import tempfile
import unittest

from tests.helpers import http_server
from threshold_wallet import audit as audit_mod
from threshold_wallet.audit import AuditStore
from threshold_wallet.service import WalletService
from threshold_wallet.store import RecoveryError, WalletStore


def _make_service(data_dir: str) -> WalletService:
    return WalletService(WalletStore(data_dir))


def _prepare_rotation(data_dir: str, wallet_id="w1", rotation_id="rot-1"):
    service = _make_service(data_dir)
    service.create_wallet(wallet_id, 2)
    _, view = service.create_share_rotation(wallet_id, rotation_id)
    return service, view


def _plant_unrecoverable_activation(
    data_dir: str, wallet_id="w1", rotation_id="rot-1"
):
    """摆出无法安全回滚的激活现场：新份额/新公钥已换入、旧份额已删、
    激活事件未落盘，且激活前备份（wallet.bak.json/*.bak.json）被抹掉。"""
    store = WalletStore(data_dir)
    record = store.get_rotation(wallet_id, rotation_id)
    wallet = store.get_wallet(wallet_id)
    old_share_records = [
        store.get_share(wallet_id, s["share_id"]) for s in wallet["shares"]
    ]
    activating = dict(record)
    activating["state"] = "activating"
    activating["previous_public_key"] = wallet["public_key"]
    store.update_rotation(wallet_id, rotation_id, activating)
    new_records = [
        store.get_staging_share(wallet_id, rotation_id, sid)
        for sid in record["share_ids"]
    ]
    for share_record in new_records:
        store.save_share(wallet_id, share_record)
    new_meta = dict(wallet)
    new_meta["shares"] = [
        {"share_id": r["share_id"], "public_key": r["public_key"]}
        for r in new_records
    ]
    new_meta["public_key"] = record["public_key"]
    store.save_wallet_meta(wallet_id, new_meta)
    for share_record in old_share_records:
        store.delete_share(wallet_id, share_record["share_id"])
    staging = os.path.join(
        data_dir, "rotation-staging", wallet_id, rotation_id
    )
    for name in os.listdir(staging):
        if name.endswith(".bak.json"):
            os.unlink(os.path.join(staging, name))
    return staging


class StartupFailClosedTest(unittest.TestCase):
    """启动恢复失败必须阻止服务就绪。"""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        _prepare_rotation(self.tmp)
        self.store = WalletStore(self.tmp)

    def _plant_activating_without_backup(self):
        # 换入已发生、事件未落盘、回滚备份被抹掉：无法安全恢复旧密钥
        staging = _plant_unrecoverable_activation(self.tmp)
        self.assertFalse(
            os.path.exists(os.path.join(staging, "wallet.bak.json"))
        )

    def test_constructor_raises_recovery_error(self):
        self._plant_activating_without_backup()
        with self.assertRaises(RecoveryError):
            WalletService(WalletStore(self.tmp))

    def test_serve_cli_refuses_to_start(self):
        from threshold_wallet import cli

        self._plant_activating_without_backup()
        # serve 子命令必须以非零码退出，并输出单行 JSON 错误，不绑定端口
        code = cli.main(
            ["serve", "--host", "127.0.0.1", "--port", "0",
             "--data-dir", self.tmp]
        )
        self.assertNotEqual(code, 0)


class HttpRecoveryFailClosedTest(unittest.TestCase):
    """常驻服务遇到无法对账的现场：请求返回 503，不暴露半完成状态。"""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        _prepare_rotation(self.tmp)

    def test_get_wallet_returns_503_on_unrecoverable_scene(self):
        with http_server(self.tmp) as srv:
            # 健康服务就绪后，他进程摆出无法回滚的激活现场
            _plant_unrecoverable_activation(self.tmp)

            status, body = srv.request("GET", "/v1/wallets/w1")
            self.assertEqual(status, 503, body)
            self.assertIn("error", body)
            # 503 不泄露任何私钥材料
            self.assertNotIn("private", json.dumps(body))

    def test_asset_query_returns_503_on_corrupt_committed_intent(self):
        # 先在健康服务上建出 pending 操作
        with http_server(self.tmp) as srv:
            status, _ = srv.request(
                "POST",
                "/v1/wallets/w1/asset-operations",
                {"operation_id": "op1", "asset_id": "btc", "delta": 100},
            )
            self.assertEqual(status, 201)
            # 他进程摆出「账本 committed、有意图、无事件」且意图不可解析
            store = WalletStore(self.tmp)
            intent_path = os.path.join(
                self.tmp, "asset-intents", "w1", "op1.json"
            )
            os.makedirs(os.path.dirname(intent_path), exist_ok=True)
            with open(intent_path, "w", encoding="utf-8") as f:
                f.write("{broken")
            store.commit_asset_operation(
                "w1",
                "op1",
                {
                    "operation_id": "op1",
                    "asset_id": "btc",
                    "state": "committed",
                    "delta": 100,
                    "balance": 100,
                    "version": 1,
                },
                "btc",
                {"balance": 100, "version": 1},
            )
            status, body = srv.request(
                "GET", "/v1/wallets/w1/assets/btc"
            )
            self.assertEqual(status, 503, body)


class RuntimeHttpHealTest(unittest.TestCase):
    """常驻服务在请求路径上锁内自愈可恢复的崩溃现场（不返回 503）。"""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        _prepare_rotation(self.tmp)

    def _plant_crashed_activation_with_backup(self):
        # 他进程激活到一半（换入已发生）但事件未落盘；备份仍在，
        # 因此可安全回滚为 prepared。
        store = WalletStore(self.tmp)
        record = store.get_rotation("w1", "rot-1")
        wallet = store.get_wallet("w1")
        old_shares = [
            store.get_share("w1", s["share_id"]) for s in wallet["shares"]
        ]
        activating = dict(record)
        activating["state"] = "activating"
        activating["previous_public_key"] = wallet["public_key"]
        store.update_rotation("w1", "rot-1", activating)
        store.save_activation_backups(
            "w1", "rot-1", old_shares, wallet
        )
        new_records = [
            store.get_staging_share("w1", "rot-1", sid)
            for sid in record["share_ids"]
        ]
        for share_record in new_records:
            store.save_share("w1", share_record)
        new_meta = dict(wallet)
        new_meta["shares"] = [
            {"share_id": r["share_id"], "public_key": r["public_key"]}
            for r in new_records
        ]
        new_meta["public_key"] = record["public_key"]
        store.save_wallet_meta("w1", new_meta)
        for share_record in old_shares:
            store.delete_share("w1", share_record["share_id"])
        return wallet, record

    def test_get_wallet_self_heals_to_old_key(self):
        with http_server(self.tmp) as srv:
            # 健康服务就绪后，他进程激活到一半（换入已发生）但事件未落盘；
            # 备份仍在，可安全回滚。GET 在锁内自愈回滚，不返回 503。
            wallet_before, _ = self._plant_crashed_activation_with_backup()
            status, body = srv.request("GET", "/v1/wallets/w1")
            self.assertEqual(status, 200, body)
            self.assertEqual(body["public_key"], wallet_before["public_key"])
            status, body = srv.request(
                "GET", "/v1/wallets/w1/share-rotations/rot-1"
            )
            self.assertEqual(status, 200, body)
            self.assertEqual(body["state"], "prepared")
            # 自愈不新增审计事件
            status, body = srv.request(
                "GET", "/v1/wallets/w1/audit-events"
            )
            self.assertEqual(
                [e["type"] for e in body["events"]],
                ["share_rotation_prepared"],
            )


class RuntimeSelfHealTest(unittest.TestCase):
    """常驻进程在锁内自愈他进程崩溃遗留的轮换/资产现场。"""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)

    def _wallet_before(self, store):
        return store.get_wallet("w1")

    def test_heals_uncommitted_activation_back_to_prepared(self):
        _, prepared = _prepare_rotation(self.tmp)
        store = WalletStore(self.tmp)
        wallet_before = self._wallet_before(store)
        # 他进程：activating + 备份 + 新份额换入一半，事件未落盘
        record = store.get_rotation("w1", "rot-1")
        old_shares = [
            store.get_share("w1", s["share_id"]) for s in wallet_before["shares"]
        ]
        activating = dict(record)
        activating["state"] = "activating"
        activating["previous_public_key"] = wallet_before["public_key"]
        store.update_rotation("w1", "rot-1", activating)
        store.save_activation_backups(
            "w1", "rot-1", old_shares, wallet_before
        )
        staged = store.get_staging_share("w1", "rot-1", "rot-1-share-1")
        store.save_share("w1", staged)
        store.delete_share("w1", "share-1")
        tampered = dict(wallet_before)
        tampered["public_key"] = prepared["public_key"]
        store.save_wallet_meta("w1", tampered)

        svc = _make_service(self.tmp)  # 启动恢复即把现场回滚
        # 任意持锁读操作后的状态一致：钱包回到旧公钥，轮换回 prepared
        wallet = svc.get_wallet("w1")
        self.assertEqual(wallet["public_key"], wallet_before["public_key"])
        self.assertEqual(
            svc.get_share_rotation("w1", "rot-1")["state"], "prepared"
        )
        self.assertEqual(store.get_share("w1", "share-1")["share_id"], "share-1")
        self.assertIsNone(store.get_share("w1", "rot-1-share-1"))
        # 自愈不新增事件
        events = svc.get_audit_events("w1")["events"]
        self.assertEqual(
            [e["type"] for e in events], ["share_rotation_prepared"]
        )

    def test_heals_committed_activation_forward_to_active(self):
        _, prepared = _prepare_rotation(self.tmp)
        store = WalletStore(self.tmp)
        wallet_before = self._wallet_before(store)
        # 他进程：active 状态 + 激活事件落盘，但暂存/备份残留
        record = store.get_rotation("w1", "rot-1")
        active = dict(record)
        active["state"] = "active"
        active["previous_public_key"] = wallet_before["public_key"]
        store.update_rotation("w1", "rot-1", active)
        AuditStore(self.tmp).append_event(
            "w1",
            {
                "type": audit_mod.TYPE_SHARE_ROTATION_ACTIVATED,
                "at": "2026-09-20T00:00:00Z",
                "request_id": None,
                "actor_id": None,
                "reason": None,
                "details": {
                    "rotation_id": "rot-1",
                    "share_ids": list(prepared["share_ids"]),
                    "public_key": prepared["public_key"],
                    "previous_public_key": wallet_before["public_key"],
                },
            },
        )
        # 暂存目录仍残留（内含新份额与备份）
        staging = os.path.join(self.tmp, "rotation-staging", "w1", "rot-1")
        self.assertTrue(os.path.isdir(staging))

        svc = _make_service(self.tmp)
        view = svc.get_share_rotation("w1", "rot-1")
        self.assertEqual(view["state"], "active")
        self.assertFalse(os.path.exists(staging))
        wallet = store.get_wallet("w1")
        self.assertEqual(wallet["public_key"], prepared["public_key"])
        # 自愈不重复记激活事件
        events = svc.get_audit_events("w1")["events"]
        self.assertEqual(
            [e["type"] for e in events],
            ["share_rotation_prepared", "share_rotation_activated"],
        )
        # 重放仍 200
        self.assertEqual(svc.activate_share_rotation("w1", "rot-1")[0], 200)
        self.assertEqual(
            len(svc.get_audit_events("w1")["events"]), 2
        )


if __name__ == "__main__":
    unittest.main()
