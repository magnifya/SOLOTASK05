"""节点故障与灾难恢复的服务级测试。

覆盖：
- 激活各故障点崩溃后的启动恢复（activating 回滚 / active 清理）；
- 轮换暂存残留的有效性判定与安全清理（孤儿目录、损坏文件、无效记录）；
- 清理后的私钥边界（不留私钥副本、不改在用钱包）；
- 审计 seq 跨重启连续升序、不重复，恢复与清理不产生业务事件。

可独立运行：python -m unittest tests.test_recovery -v
"""

from __future__ import annotations

import json
import os
import tempfile
import unittest

from threshold_wallet import crypto
from threshold_wallet.audit import AuditStore
from threshold_wallet.service import WalletService
from threshold_wallet.store import WalletStore

from tests.helpers import make_harness


def _new_service(data_dir: str) -> WalletService:
    """模拟一次服务重启：全新 store + service（构造时执行启动恢复）。"""
    return WalletService(WalletStore(data_dir))


def _staging_dir(data_dir: str, wallet_id: str, rotation_id: str) -> str:
    return os.path.join(
        data_dir, "rotation-staging", wallet_id, rotation_id
    )


def _read_json(path: str):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def _write_json(path: str, data) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f)


class _Base(unittest.TestCase):
    def setUp(self):
        self.data_dir = tempfile.mkdtemp()
        self.service = _new_service(self.data_dir)
        self.store = self.service._store
        self.wallet = self.service.create_wallet("w1", 2)

    def prepare(self, rotation_id="rot-1"):
        status, body = self.service.create_share_rotation("w1", rotation_id)
        self.assertEqual(status, 201)
        return body

    def rotation_record(self, rotation_id="rot-1"):
        return self.store.get_rotation("w1", rotation_id)

    def wallet_meta(self):
        return self.store.get_wallet("w1")

    def audit_events(self):
        return AuditStore(self.data_dir).list_events("w1")

    def _staging_path(self, rotation_id="rot-1"):
        return _staging_dir(self.data_dir, "w1", rotation_id)


class ActivatingCrashRecoveryTest(_Base):
    """activating 状态崩溃：恢复原钱包、旧份额与 prepared。"""

    def _simulate_crash_during_activation(self, swap: bool) -> dict:
        """把 prepared 轮换推进到 activating 崩溃现场。

        swap=False：崩溃在备份之后、换份额之前；
        swap=True：崩溃在新份额与钱包元数据已换入、提交 active 之前。
        返回 (原钱包元数据, 原份额记录, 轮换记录)。
        """
        prep = self.prepare()
        record = self.rotation_record()
        wallet = self.wallet_meta()
        old_shares = [
            self.store.get_share("w1", s["share_id"]) for s in wallet["shares"]
        ]
        activating = dict(record)
        activating["state"] = "activating"
        activating["previous_public_key"] = wallet["public_key"]
        self.store.update_rotation("w1", "rot-1", activating)
        self.store.save_activation_backups("w1", "rot-1", old_shares, wallet)
        if swap:
            new_records = [
                self.store.get_staging_share("w1", "rot-1", sid)
                for sid in record["share_ids"]
            ]
            new_meta = dict(wallet)
            new_meta["shares"] = [
                {"share_id": r["share_id"], "public_key": r["public_key"]}
                for r in new_records
            ]
            new_meta["public_key"] = record["public_key"]
            for r in new_records:
                self.store.save_share("w1", r)
            self.store.save_wallet_meta("w1", new_meta)
            for s in old_shares:
                self.store.delete_share("w1", s["share_id"])
        return wallet, old_shares, prep

    def _assert_restored(self, wallet, old_shares, prep):
        meta = self.wallet_meta()
        # 原钱包元数据恢复（公钥、份额列表回到轮换前）
        self.assertEqual(meta["public_key"], wallet["public_key"])
        self.assertEqual(meta["shares"], wallet["shares"])
        # 旧份额文件原样恢复（含各自私钥），新份额文件已清除
        for old in old_shares:
            self.assertEqual(self.store.get_share("w1", old["share_id"]), old)
        for sid in prep["share_ids"]:
            self.assertIsNone(self.store.get_share("w1", sid))
        # 轮换记录回滚为 prepared，暂存目录保留恰两份新份额，备份已清理
        record = self.rotation_record()
        self.assertEqual(record["state"], "prepared")
        self.assertNotIn("previous_public_key", record)
        staging = _staging_dir(self.data_dir, "w1", "rot-1")
        self.assertEqual(
            sorted(os.listdir(staging)),
            [sid + ".json" for sid in sorted(prep["share_ids"])],
        )

    def test_crash_before_swap_restores_prepared(self):
        wallet, old_shares, prep = self._simulate_crash_during_activation(
            swap=False
        )
        self.assertEqual(self.rotation_record()["state"], "activating")
        service2 = _new_service(self.data_dir)
        self._assert_restored(wallet, old_shares, prep)
        # 恢复后可用原份额正常签名
        status, _ = service2.sign(
            "w1",
            "req-after",
            "m",
            [
                {"share_id": sid, "signature": sig}
                for sid, sig in (
                    ("share-1", self._sign_with("share-1", "req-after", "m")),
                    ("share-2", self._sign_with("share-2", "req-after", "m")),
                )
            ],
        )
        self.assertEqual(status, 201)

    def test_crash_after_swap_restores_prepared(self):
        wallet, old_shares, prep = self._simulate_crash_during_activation(
            swap=True
        )
        # 崩溃现场：钱包已指向新公钥
        self.assertEqual(self.wallet_meta()["public_key"], prep["public_key"])
        service2 = _new_service(self.data_dir)
        self._assert_restored(wallet, old_shares, prep)
        # 恢复后可重新激活并成功
        status, body = service2.activate_share_rotation("w1", "rot-1")
        self.assertEqual(status, 201)
        self.assertEqual(body["state"], "active")
        self.assertEqual(self.wallet_meta()["public_key"], prep["public_key"])

    def _sign_with(self, share_id, request_id, message):
        share = self.store.get_share("w1", share_id)
        payload = crypto.build_payload(request_id, message)
        return crypto.sign_share(
            bytes.fromhex(share["private_key"]), payload
        ).hex()

    def test_recovery_is_idempotent(self):
        wallet, old_shares, prep = self._simulate_crash_during_activation(
            swap=True
        )
        _new_service(self.data_dir)
        self._assert_restored(wallet, old_shares, prep)
        # 再次重启：已恢复的现场不应被二次改动
        _new_service(self.data_dir)
        self._assert_restored(wallet, old_shares, prep)


class ActiveCrashCleanupTest(_Base):
    """active 已提交但暂存未清理的崩溃现场：清理暂存与备份。"""

    def test_active_with_leftover_staging_is_cleaned(self):
        prep = self.prepare()
        status, _ = self.service.activate_share_rotation("w1", "rot-1")
        self.assertEqual(status, 201)
        # 正常激活已清理暂存；手工重建"激活后崩溃"的残留现场
        record = self.rotation_record()
        self.assertEqual(record["state"], "active")
        staging = _staging_dir(self.data_dir, "w1", "rot-1")
        os.makedirs(staging)
        for sid in prep["share_ids"]:
            _write_json(
                os.path.join(staging, sid + ".json"),
                {
                    "share_id": sid,
                    "public_key": "00" * 32,
                    "private_key": "11" * 32,
                },
            )
        _write_json(
            os.path.join(staging, "share-1.bak.json"),
            {"share_id": "share-1", "private_key": "22" * 32},
        )
        service2 = _new_service(self.data_dir)
        # 暂存目录整体清除，不留私钥副本
        self.assertFalse(os.path.exists(staging))
        # 钱包与轮换状态不受影响
        self.assertEqual(self.wallet_meta()["public_key"], prep["public_key"])
        self.assertEqual(self.rotation_record()["state"], "active")
        # 激活重放仍 200
        status, _ = service2.activate_share_rotation("w1", "rot-1")
        self.assertEqual(status, 200)


class StagingResidueValidityTest(_Base):
    """prepared 残留的严格有效性判定：仅完全匹配才保留。"""

    def _recover(self):
        _new_service(self.data_dir)

    def _assert_purged(self, rotation_id="rot-1"):
        """记录与暂存均被删除，在用钱包与份额不受影响。"""
        self.assertIsNone(self.rotation_record(rotation_id))
        self.assertFalse(os.path.exists(self._staging_path(rotation_id)))
        meta = self.wallet_meta()
        self.assertEqual(meta["public_key"], self.wallet["public_key"])
        for sid in ("share-1", "share-2"):
            share = self.store.get_share("w1", sid)
            self.assertIsNotNone(share)
            self.assertEqual(len(bytes.fromhex(share["private_key"])), 32)

    def test_valid_prepared_residue_is_kept(self):
        prep = self.prepare()
        self._recover()
        record = self.rotation_record()
        self.assertIsNotNone(record)
        self.assertEqual(record["state"], "prepared")
        self.assertEqual(
            sorted(os.listdir(self._staging_path())),
            [sid + ".json" for sid in sorted(prep["share_ids"])],
        )

    def test_extra_file_in_staging_purged(self):
        self.prepare()
        _write_json(
            os.path.join(self._staging_path(), "extra.json"), {"x": 1}
        )
        self._recover()
        self._assert_purged()

    def test_missing_share_file_purged(self):
        prep = self.prepare()
        os.unlink(
            os.path.join(self._staging_path(), prep["share_ids"][0] + ".json")
        )
        self._recover()
        self._assert_purged()

    def test_corrupted_json_purged(self):
        prep = self.prepare()
        path = os.path.join(self._staging_path(), prep["share_ids"][0] + ".json")
        with open(path, "w", encoding="utf-8") as f:
            f.write("{not json")
        self._recover()
        self._assert_purged()

    def test_share_id_mismatch_purged(self):
        prep = self.prepare()
        path = os.path.join(self._staging_path(), prep["share_ids"][0] + ".json")
        record = _read_json(path)
        record["share_id"] = "rot-1-share-2"
        _write_json(path, record)
        self._recover()
        self._assert_purged()

    def test_wrong_private_key_length_purged(self):
        prep = self.prepare()
        path = os.path.join(self._staging_path(), prep["share_ids"][0] + ".json")
        record = _read_json(path)
        record["private_key"] = "ab" * 16  # 16 字节，不是 32
        _write_json(path, record)
        self._recover()
        self._assert_purged()

    def test_public_key_not_matching_private_purged(self):
        prep = self.prepare()
        path = os.path.join(self._staging_path(), prep["share_ids"][0] + ".json")
        record = _read_json(path)
        other = crypto.generate_share_key("x")
        record["public_key"] = other.public_bytes.hex()
        _write_json(path, record)
        self._recover()
        self._assert_purged()

    def test_tampered_record_public_key_purged(self):
        prep = self.prepare()
        record = self.rotation_record()
        record["public_key"] = "ff" * 64
        self.store.update_rotation("w1", "rot-1", record)
        self._recover()
        self._assert_purged()

    def test_orphan_staging_dir_without_record_purged(self):
        # 没有轮换记录的孤儿暂存目录（含私钥材料）必须安全删除
        staging = self._staging_path("ghost-rot")
        os.makedirs(staging)
        key = crypto.generate_share_key("ghost-rot-share-1")
        _write_json(
            os.path.join(staging, "ghost-rot-share-1.json"),
            {
                "share_id": "ghost-rot-share-1",
                "public_key": key.public_bytes.hex(),
                "private_key": key.private_bytes.hex(),
            },
        )
        self._recover()
        self.assertFalse(os.path.exists(staging))
        # 孤儿清理不影响在用钱包
        self.assertEqual(
            self.wallet_meta()["public_key"], self.wallet["public_key"]
        )

    def test_orphan_wallet_staging_root_purged(self):
        # 钱包连轮换记录文件都没有：整个暂存根目录为孤儿
        root = os.path.join(self.data_dir, "rotation-staging", "ghost-wallet")
        os.makedirs(os.path.join(root, "rot-x"))
        _write_json(
            os.path.join(root, "rot-x", "rot-x-share-1.json"),
            {"share_id": "rot-x-share-1", "private_key": "33" * 32},
        )
        self._recover()
        self.assertFalse(os.path.exists(root))

    def test_unknown_state_record_purged(self):
        self.prepare()
        record = self.rotation_record()
        record["state"] = "half-committed"
        self.store.update_rotation("w1", "rot-1", record)
        self._recover()
        self._assert_purged()

    def test_prepared_record_without_staging_purged(self):
        self.prepare()
        self.store.delete_staging("w1", "rot-1")
        self._recover()
        self._assert_purged()


class RecoveryPrivateKeyBoundaryTest(_Base):
    """清理后的私钥边界：不留私钥副本、不改在用钱包。"""

    def test_no_private_key_copies_left_after_cleanup(self):
        prep = self.prepare()
        staged_privs = []
        for sid in prep["share_ids"]:
            record = _read_json(
                os.path.join(self._staging_path("rot-1"), sid + ".json")
            )
            staged_privs.append(record["private_key"])
        # 制造各种无效残留并触发恢复清理
        _write_json(
            os.path.join(self._staging_path("rot-1"), "junk.json"), {}
        )
        orphan = _staging_dir(self.data_dir, "w1", "orphan-rot")
        os.makedirs(orphan)
        orphan_key = crypto.generate_share_key("orphan-rot-share-1")
        _write_json(
            os.path.join(orphan, "orphan-rot-share-1.json"),
            {
                "share_id": "orphan-rot-share-1",
                "public_key": orphan_key.public_bytes.hex(),
                "private_key": orphan_key.private_bytes.hex(),
            },
        )
        _new_service(self.data_dir)
        # 暂存私钥与孤儿私钥在 data-dir 任何文件中都不复存在
        secrets = staged_privs + [orphan_key.private_bytes.hex()]
        for base, _, files in os.walk(self.data_dir):
            for name in files:
                path = os.path.join(base, name)
                with open(path, "rb") as f:
                    raw = f.read()
                for secret in secrets:
                    self.assertNotIn(secret.encode(), raw, path)
        # 在用钱包的两个份额私钥仍在原处、未被改动
        for sid in ("share-1", "share-2"):
            share = self.store.get_share("w1", sid)
            self.assertIsNotNone(share)
            self.assertEqual(len(bytes.fromhex(share["private_key"])), 32)


class AuditContinuityAcrossRestartTest(_Base):
    """审计 seq 跨重启连续升序、不重复；恢复与清理不产生业务事件。"""

    def _seqs(self):
        return [e["seq"] for e in self.audit_events()]

    def test_seq_continuous_across_restarts(self):
        self.service.put_policy("w1", 1, 3600)
        self.service.create_sign_request("w1", "r1", "m1")
        self.assertEqual(self._seqs(), [1, 2])
        # 重启后续写：seq 接续、不重复、不回退
        service2 = _new_service(self.data_dir)
        service2.create_sign_request("w1", "r2", "m2")
        service2.approve("w1", "r1", "ops-1")
        self.assertEqual(self._seqs(), [1, 2, 3, 4])
        service3 = _new_service(self.data_dir)
        service3.put_policy("w1", 2, 60)
        self.assertEqual(self._seqs(), [1, 2, 3, 4, 5])
        events = self.audit_events()
        self.assertEqual(
            [e["type"] for e in events],
            [
                "policy_updated",
                "request_created",
                "request_created",
                "request_approved",
                "policy_updated",
            ],
        )

    def test_recovery_and_cleanup_add_no_events(self):
        self.service.put_policy("w1", 1, 3600)
        self.prepare()
        before = self.audit_events()
        self.assertEqual(self._seqs(), [1, 2])
        # 制造残留：孤儿目录 + 无效 prepared + activating 崩溃现场
        orphan = _staging_dir(self.data_dir, "w1", "orphan-rot")
        os.makedirs(orphan)
        _write_json(os.path.join(orphan, "x.json"), {"private_key": "00" * 32})
        record = self.rotation_record()
        activating = dict(record)
        activating["state"] = "activating"
        activating["previous_public_key"] = self.wallet["public_key"]
        self.store.update_rotation("w1", "rot-1", activating)
        _new_service(self.data_dir)
        # 恢复与孤儿清理不产生任何新业务事件
        self.assertEqual(self.audit_events(), before)

    def test_replay_after_restart_adds_no_events(self):
        self.service.put_policy("w1", 1, 3600)
        self.service.create_sign_request("w1", "r1", "m")
        self.service.approve("w1", "r1", "ops-1")
        status, first = self.service.sign(
            "w1", "r1", "m", self._two_sigs("r1", "m")
        )
        self.assertEqual(status, 201)
        prep = self.prepare()
        before = self.audit_events()
        service2 = _new_service(self.data_dir)
        # 激活前已完成签名：重启后按原请求重放仍 200，不记事件
        status, replayed = service2.sign("w1", "r1", "m", self._two_sigs("r1", "m"))
        self.assertEqual(status, 200)
        self.assertEqual(replayed["signature"], first["signature"])
        # 审批单创建重放、轮换准备重放：均 200 且不记事件
        status, _ = service2.create_sign_request("w1", "r1", "m")
        self.assertEqual(status, 200)
        status, body = service2.create_share_rotation("w1", "rot-1")
        self.assertEqual(status, 200)
        self.assertEqual(body["public_key"], prep["public_key"])
        self.assertEqual(self.audit_events(), before)

    def _two_sigs(self, request_id, message):
        result = []
        for sid in ("share-1", "share-2"):
            share = self.store.get_share("w1", sid)
            payload = crypto.build_payload(request_id, message)
            result.append(
                {
                    "share_id": sid,
                    "signature": crypto.sign_share(
                        bytes.fromhex(share["private_key"]), payload
                    ).hex(),
                }
            )
        return result


if __name__ == "__main__":
    unittest.main()
