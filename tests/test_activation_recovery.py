"""份额轮换激活的事件门控恢复测试（任务恢复一致性契约）。

以 share_rotation_activated 事件是否落盘作为激活事务的唯一提交判据：
- 状态已写 active、但激活事件未落盘：恢复旧公钥/旧份额、状态回 prepared、
  保留经校验有效的暂存份额、不记激活事件，之后可重新激活；
- 激活事件已落盘：即使轮换状态停在 activating、暂存/备份未清理或在用
  新份额缺失，也确定性前滚为唯一 active 结果、清理全部残留、不重复记事件；
- 无法找回旧份额（已切换却无备份且无事件）：RecoveryError 阻止服务就绪，
  HTTP 访问得到 500，绝不暴露半完成状态；
- 常驻进程在每钱包事务锁内自愈他进程崩溃遗留的轮换现场；
- 激活事件成功落盘后的异常不回滚、不重复记事件。
"""

from __future__ import annotations

import json
import os
import shutil
import tempfile
import unittest

from threshold_wallet import audit as audit_mod
from threshold_wallet.audit import AuditStore
from threshold_wallet.service import ServiceError, WalletService
from threshold_wallet.store import RecoveryError, WalletStore
from tests.helpers import make_harness


def _make_service(data_dir: str) -> WalletService:
    return WalletService(WalletStore(data_dir))


class _SceneBuilder:
    """直接在存储层摆放激活事务各阶段的崩溃现场。"""

    def __init__(self, tmpdir: str, wallet_id: str = "w1",
                 rotation_id: str = "rot-1"):
        self.tmp = tmpdir
        self.wallet_id = wallet_id
        self.rotation_id = rotation_id
        self.store = WalletStore(tmpdir)
        self.svc = _make_service(tmpdir)
        self.svc.create_wallet(wallet_id, 2)
        _, self.prepared = self.svc.create_share_rotation(
            wallet_id, rotation_id
        )
        self.wallet_before = self.store.get_wallet(wallet_id)
        self.old_share_records = [
            self.store.get_share(wallet_id, s["share_id"])
            for s in self.wallet_before["shares"]
        ]
        self.new_share_records = [
            self.store.get_staging_share(wallet_id, rotation_id, sid)
            for sid in self.prepared["share_ids"]
        ]

    def _write_activating_and_backups(self):
        record = self.store.get_rotation(
            self.wallet_id, self.rotation_id
        )
        activating = dict(record)
        activating["state"] = "activating"
        activating["previous_public_key"] = self.wallet_before["public_key"]
        self.store.update_rotation(
            self.wallet_id, self.rotation_id, activating
        )
        self.store.save_activation_backups(
            self.wallet_id,
            self.rotation_id,
            self.old_share_records,
            self.wallet_before,
        )

    def _swap(self):
        for share_record in self.new_share_records:
            self.store.save_share(self.wallet_id, share_record)
        new_meta = dict(self.wallet_before)
        new_meta["shares"] = [
            {"share_id": r["share_id"], "public_key": r["public_key"]}
            for r in self.new_share_records
        ]
        new_meta["public_key"] = self.prepared["public_key"]
        self.store.save_wallet_meta(self.wallet_id, new_meta)
        for share_record in self.old_share_records:
            self.store.delete_share(
                self.wallet_id, share_record["share_id"]
            )

    def _write_active_state(self):
        record = self.store.get_rotation(
            self.wallet_id, self.rotation_id
        )
        active = dict(record)
        active["state"] = "active"
        active["previous_public_key"] = self.wallet_before["public_key"]
        self.store.update_rotation(self.wallet_id, self.rotation_id, active)

    def _write_activation_event(self):
        AuditStore(self.tmp).append_event(self.wallet_id, {
            "type": audit_mod.TYPE_SHARE_ROTATION_ACTIVATED,
            "at": "2026-09-20T00:00:00Z",
            "request_id": None,
            "actor_id": None,
            "reason": None,
            "details": {
                "rotation_id": self.rotation_id,
                "share_ids": list(self.prepared["share_ids"]),
                "public_key": self.prepared["public_key"],
                "previous_public_key": self.wallet_before["public_key"],
            },
        })

    def scene_active_without_event(self):
        """新份额已换入、active 已落盘，但激活事件未写。"""
        self._write_activating_and_backups()
        self._swap()
        self._write_active_state()

    def scene_event_persisted_with_residue(self, state="active",
                                           drop_inuse_share=False):
        """激活事件已落盘，但轮换状态/在用份额/暂存仍有残留。"""
        self._write_activating_and_backups()
        self._swap()
        record = self.store.get_rotation(
            self.wallet_id, self.rotation_id
        )
        record["state"] = state
        self.store.update_rotation(
            self.wallet_id, self.rotation_id, record
        )
        if drop_inuse_share:
            # 在用新份额缺失，但暂存里仍有（暂存尚未清理）
            self.store.delete_share(
                self.wallet_id, self.prepared["share_ids"][0]
            )
        self._write_activation_event()

    def scene_switched_without_backup_or_event(self):
        """已切换到新份额，但备份被删、激活事件未落盘（无法回滚）。"""
        self._write_activating_and_backups()
        self._swap()
        self._write_active_state()
        # 抹掉回滚所需的全部备份（wallet.bak.json 与各份额 *.bak.json）
        self.store.delete_activation_backups(
            self.wallet_id, self.rotation_id
        )


class ActiveWithoutEventRollsBackTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.b = _SceneBuilder(self.tmp)
        self.b.scene_active_without_event()

    def test_restart_restores_old_key_and_prepared(self):
        svc = _make_service(self.tmp)
        store = WalletStore(self.tmp)
        # 状态回 prepared，钱包公钥/份额恢复旧值
        view = svc.get_share_rotation("w1", "rot-1")
        self.assertEqual(view["state"], "prepared")
        self.assertEqual(store.get_wallet("w1"), self.b.wallet_before)
        for rec in self.b.old_share_records:
            self.assertEqual(
                store.get_share("w1", rec["share_id"]), rec
            )
        for sid in self.b.prepared["share_ids"]:
            self.assertIsNone(store.get_share("w1", sid))
        # 有效暂存份额保留（恰两份，无备份）
        staging = os.path.join(
            self.tmp, "rotation-staging", "w1", "rot-1"
        )
        self.assertEqual(
            sorted(os.listdir(staging)),
            ["rot-1-share-1.json", "rot-1-share-2.json"],
        )
        # 无激活事件（仅准备期一条），无 seq 缺口
        events = svc.get_audit_events("w1")["events"]
        self.assertEqual(
            [e["type"] for e in events],
            ["share_rotation_prepared"],
        )

    def test_wallet_query_does_not_expose_half_switched_key(self):
        # 直接读盘是半切换的新公钥
        self.assertEqual(
            WalletStore(self.tmp).get_wallet("w1")["public_key"],
            self.b.prepared["public_key"],
        )
        svc = _make_service(self.tmp)
        # 经服务读取：锁内自愈后呈现旧公钥，绝不暴露半完成状态
        wallet = svc.get_wallet("w1")
        self.assertEqual(
            wallet["public_key"], self.b.wallet_before["public_key"]
        )

    def test_reactivate_after_rollback_is_single_first_commit(self):
        svc = _make_service(self.tmp)
        status, active = svc.activate_share_rotation("w1", "rot-1")
        self.assertEqual(status, 201)
        self.assertEqual(active["state"], "active")
        # 重放不重复记事件
        status, again = svc.activate_share_rotation("w1", "rot-1")
        self.assertEqual(status, 200)
        self.assertEqual(again["state"], "active")
        events = svc.get_audit_events("w1")["events"]
        self.assertEqual(
            [e["type"] for e in events],
            ["share_rotation_prepared", "share_rotation_activated"],
        )
        self.assertEqual([e["seq"] for e in events], [1, 2])


class EventPersistedRollsForwardTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)

    def test_activating_state_with_event_rolls_forward(self):
        b = _SceneBuilder(self.tmp)
        b.scene_event_persisted_with_residue(state="activating")
        svc = _make_service(self.tmp)
        view = svc.get_share_rotation("w1", "rot-1")
        self.assertEqual(view["state"], "active")
        self.assertEqual(view["public_key"], b.prepared["public_key"])
        store = WalletStore(self.tmp)
        wallet = store.get_wallet("w1")
        self.assertEqual(wallet["public_key"], b.prepared["public_key"])
        self.assertEqual(
            sorted(
                n[:-5] for n in os.listdir(
                    os.path.join(self.tmp, "shares", "w1")
                )
            ),
            ["rot-1-share-1", "rot-1-share-2"],
        )
        # 暂存/备份全部清除
        self.assertFalse(
            os.path.exists(
                os.path.join(self.tmp, "rotation-staging", "w1", "rot-1")
            )
        )
        # 只有一条激活事件，重放不新增
        svc.activate_share_rotation("w1", "rot-1")
        events = svc.get_audit_events("w1")["events"]
        self.assertEqual(
            [e["type"] for e in events],
            ["share_rotation_prepared", "share_rotation_activated"],
        )

    def test_missing_inuse_share_rebuilt_from_staging(self):
        b = _SceneBuilder(self.tmp)
        b.scene_event_persisted_with_residue(
            state="active", drop_inuse_share=True
        )
        svc = _make_service(self.tmp)
        view = svc.get_share_rotation("w1", "rot-1")
        self.assertEqual(view["state"], "active")
        store = WalletStore(self.tmp)
        # 缺失的在用新份额被从暂存补齐
        share = store.get_share("w1", b.prepared["share_ids"][0])
        self.assertIsNotNone(share)
        self.assertEqual(share["public_key"], b.new_share_records[0]["public_key"])
        # 暂存最终清空
        self.assertFalse(
            os.path.exists(
                os.path.join(self.tmp, "rotation-staging", "w1", "rot-1")
            )
        )

    def test_recovery_adds_no_event_and_seq_stays_continuous(self):
        _SceneBuilder(self.tmp).scene_event_persisted_with_residue()
        svc = _make_service(self.tmp)
        _make_service(self.tmp)  # 再重启一次，幂等
        events = svc.get_audit_events("w1")["events"]
        self.assertEqual([e["seq"] for e in events], [1, 2])
        self.assertEqual(
            [e["type"] for e in events],
            ["share_rotation_prepared", "share_rotation_activated"],
        )


class RecoveryFailureBlocksReadinessTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.b = _SceneBuilder(self.tmp)
        self.b.scene_switched_without_backup_or_event()

    def test_constructor_raises_recovery_error(self):
        with self.assertRaises(RecoveryError):
            WalletService(WalletStore(self.tmp))

    def test_http_access_fails_500_not_half_state(self):
        # 不经过构造恢复：用一个早已启动的常驻服务，随后现场被破坏，
        # 锁内自愈无法对账时返回 500，而不是半切换公钥。
        fresh = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, fresh, ignore_errors=True)
        b2 = _SceneBuilder(fresh)
        svc = b2.svc  # 启动恢复早已成功完成
        # 现在人为制造无法回滚的现场
        b2.scene_switched_without_backup_or_event()
        with self.assertRaises(ServiceError) as ctx:
            svc.get_wallet("w1")
        self.assertEqual(ctx.exception.status, 500)
        with self.assertRaises(ServiceError) as ctx:
            svc.get_share_rotation("w1", "rot-1")
        self.assertEqual(ctx.exception.status, 500)


class RunningProcessLazyRotationHealTest(unittest.TestCase):
    """常驻进程（启动恢复已结束）遇到他进程崩溃的轮换现场时锁内自愈。"""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.b = _SceneBuilder(self.tmp)
        # svc 在干净目录上完成启动恢复后长期运行
        self.svc = self.b.svc

    def test_lazy_heal_on_rotation_query(self):
        # 他进程随后摆下 active 无事件现场
        self.b.scene_active_without_event()
        view = self.svc.get_share_rotation("w1", "rot-1")
        self.assertEqual(view["state"], "prepared")
        self.assertEqual(
            self.svc.get_wallet("w1")["public_key"],
            self.b.wallet_before["public_key"],
        )

    def test_lazy_heal_then_sign_uses_old_shares(self):
        from threshold_wallet import crypto
        # 旧份额私钥在崩溃现场摆下前就由 builder 留存
        payload = crypto.build_payload("r-new", "m")
        sigs = [
            {
                "share_id": rec["share_id"],
                "signature": crypto.sign_share(
                    bytes.fromhex(rec["private_key"]), payload
                ).hex(),
            }
            for rec in self.b.old_share_records
        ]
        # 他进程随后摆下 active 无事件现场（旧份额已换走）
        self.b.scene_active_without_event()
        # 自愈回滚后旧份额恢复，旧份额首签成功
        status, _ = self.svc.sign("w1", "r-new", "m", sigs)
        self.assertEqual(status, 201)


class ActivationEventLandedThenRaisesTest(unittest.TestCase):
    """激活事件成功落盘后、函数返回前再抛异常：不回滚、前滚、不重复事件。"""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.h = make_harness(self.tmp)
        self.svc = self.h.service
        self.store = self.h.store
        self.svc.create_wallet("w1", 2)
        self.svc.create_share_rotation("w1", "rot-1")

    def test_event_landed_despite_late_error_commits_201(self):
        real_append = self.svc._audit.append_event

        def append_then_raise(wallet_id, event):
            result = real_append(wallet_id, event)  # 事件确实落盘
            if event.get("type") == "share_rotation_activated":
                raise RuntimeError("failure after fsync, before response")
            return result

        self.svc._audit.append_event = append_then_raise
        # service 内部以事件是否落盘对账：事件在 → 前滚，返回首提 201
        status, body = self.svc.activate_share_rotation("w1", "rot-1")
        self.assertEqual(status, 201)
        self.assertEqual(body["state"], "active")
        # 暂存被前滚清理
        self.assertFalse(
            os.path.exists(
                os.path.join(self.tmp, "rotation-staging", "w1", "rot-1")
            )
        )
        # 恰一条激活事件；再次激活是 200 重放，不重复记
        status, _ = self.svc.activate_share_rotation("w1", "rot-1")
        self.assertEqual(status, 200)
        events = self.svc.get_audit_events("w1")["events"]
        self.assertEqual(
            [e["type"] for e in events],
            ["share_rotation_prepared", "share_rotation_activated"],
        )
        self.assertEqual([e["seq"] for e in events], [1, 2])


if __name__ == "__main__":
    unittest.main()
