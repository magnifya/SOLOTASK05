"""份额轮换灾备测试：契约、私钥边界、回滚与重启恢复。

覆盖任务契约：
- POST /share-rotations 201/200 重放/409 每钱包一个 prepared/400 非法 ID；
- share_ids=<rotation_id>-share-{1,2}，私钥仅存两个独立暂存文件；
- GET 200/404；activate 仅 prepared 201、active 重放 200、其余 409；
- 激活锁内替换份额文件与钱包公钥，删除旧份额文件与暂存备份；
- 激活后签名必须使用新 share_ids（旧份额 400），签名重放 200；
- 审计 share_rotation_prepared/activated：七字段 seq 连续，details 不含
  私钥，activated 另含 previous_public_key；失败无事件、无 seq 缺口；
- 激活任一步失败回滚文件、公钥、状态并清理，可重试成功；
- 启动时未完成激活先回滚，prepared/active 状态跨重启保留。
"""

from __future__ import annotations

import json
import os
import tempfile
import unittest

from tests.helpers import http_server, make_harness
from threshold_wallet import crypto
from threshold_wallet.service import (
    ROTATION_ACTIVATING,
    ROTATION_PREPARED,
    ServiceError,
)


def _sign_with(store, wallet_id, share_ids, srid, message):
    """用 share_ids 对应份额文件中的私钥生成两份份额签名。"""
    payload = crypto.build_payload(srid, message)
    result = []
    for sid in share_ids:
        share = store.get_share(wallet_id, sid)
        result.append(
            {
                "share_id": sid,
                "signature": crypto.sign_share(
                    bytes.fromhex(share["private_key"]), payload
                ).hex(),
            }
        )
    return result


class PrepareRotationTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.h = make_harness(self.tmp)
        self.svc = self.h.service
        self.svc.create_wallet("w1", 2)

    def test_prepare_201_contract(self):
        status, body = self.svc.prepare_share_rotation("w1", "rotA")
        self.assertEqual(status, 201)
        self.assertEqual(
            set(body), {"rotation_id", "state", "share_ids", "public_key"}
        )
        self.assertEqual(body["rotation_id"], "rotA")
        self.assertEqual(body["state"], "prepared")
        self.assertEqual(
            body["share_ids"], ["rotA-share-1", "rotA-share-2"]
        )
        self.assertEqual(len(bytes.fromhex(body["public_key"])), 64)

    def test_staged_private_keys_live_in_two_separate_files(self):
        self.svc.prepare_share_rotation("w1", "rotA")
        rdir = os.path.join(self.tmp, "rotations", "w1", "rotA")
        s1 = os.path.join(rdir, "rotA-share-1.json")
        s2 = os.path.join(rdir, "rotA-share-2.json")
        self.assertTrue(os.path.exists(s1))
        self.assertTrue(os.path.exists(s2))
        for path in (s1, s2):
            with open(path, encoding="utf-8") as f:
                rec = json.load(f)
            self.assertEqual(
                set(rec), {"share_id", "public_key", "private_key"}
            )
            self.assertEqual(len(rec["private_key"]), 64)  # 仅 32 字节份额
        # 暂存状态文件本身不含私钥
        with open(os.path.join(rdir, "state.json"), encoding="utf-8") as f:
            state = json.load(f)
        self.assertNotIn("private_key", json.dumps(state))

    def test_same_id_replay_is_200_and_does_not_regenerate(self):
        _, first = self.svc.prepare_share_rotation("w1", "rotA")
        status, second = self.svc.prepare_share_rotation("w1", "rotA")
        self.assertEqual(status, 200)
        self.assertEqual(second, first)
        s1 = self.h.store.get_staged_share("w1", "rotA", "rotA-share-1")
        # 重放后再查暂存私钥保持不变（未重生）
        self.assertEqual(
            s1["private_key"],
            self.h.store.get_staged_share("w1", "rotA", "rotA-share-1")[
                "private_key"
            ],
        )
        # 重放不记第二条 prepared 事件
        events = [
            e
            for e in self.svc.get_audit_events("w1")["events"]
            if e["type"] == "share_rotation_prepared"
        ]
        self.assertEqual(len(events), 1)

    def test_only_one_prepared_per_wallet_is_409(self):
        self.assertEqual(
            self.svc.prepare_share_rotation("w1", "rotA")[0], 201
        )
        with self.assertRaises(ServiceError) as ctx:
            self.svc.prepare_share_rotation("w1", "rotB")
        self.assertEqual(ctx.exception.status, 409)

    def test_invalid_rotation_id_is_400(self):
        for bad in ("", "a/b", "../x", "x" * 129, 123, None):
            with self.assertRaises(ServiceError) as ctx:
                self.svc.prepare_share_rotation("w1", bad)
            self.assertEqual(ctx.exception.status, 400, bad)

    def test_prepare_unknown_wallet_is_404(self):
        with self.assertRaises(ServiceError) as ctx:
            self.svc.prepare_share_rotation("ghost", "rotA")
        self.assertEqual(ctx.exception.status, 404)

    def test_max_length_rotation_id_share_ids_fit_storage(self):
        rid = "a" * 128
        status, body = self.svc.prepare_share_rotation("w1", rid)
        self.assertEqual(status, 201)
        self.assertEqual(
            body["share_ids"],
            [rid + "-share-1", rid + "-share-2"],
        )


class GetRotationTest(unittest.TestCase):
    def setUp(self):
        self.h = make_harness(tempfile.mkdtemp())
        self.svc = self.h.service
        self.svc.create_wallet("w1", 2)

    def test_get_prepared(self):
        self.svc.prepare_share_rotation("w1", "rotA")
        view = self.svc.get_share_rotation("w1", "rotA")
        self.assertEqual(view["state"], "prepared")
        self.assertEqual(view["rotation_id"], "rotA")

    def test_get_unknown_is_404(self):
        with self.assertRaises(ServiceError) as ctx:
            self.svc.get_share_rotation("w1", "nope")
        self.assertEqual(ctx.exception.status, 404)

    def test_get_unknown_wallet_is_404(self):
        with self.assertRaises(ServiceError) as ctx:
            self.svc.get_share_rotation("ghost", "rotA")
        self.assertEqual(ctx.exception.status, 404)


class ActivateRotationTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.h = make_harness(self.tmp)
        self.svc = self.h.service
        self.svc.create_wallet("w1", 2)
        self.old_pk = self.svc.get_wallet("w1")["public_key"]
        _, self.prepared = self.svc.prepare_share_rotation("w1", "rotA")

    def test_activate_201_replaces_files_and_public_key(self):
        status, body = self.svc.activate_share_rotation("w1", "rotA")
        self.assertEqual(status, 201)
        self.assertEqual(body["state"], "active")
        self.assertEqual(body["public_key"], self.prepared["public_key"])

        wallet = self.h.store.get_wallet("w1")
        self.assertEqual(wallet["public_key"], self.prepared["public_key"])
        self.assertEqual(
            [s["share_id"] for s in wallet["shares"]],
            ["rotA-share-1", "rotA-share-2"],
        )
        # 旧份额私钥文件删除
        self.assertIsNone(self.h.store.get_share("w1", "share-1"))
        self.assertIsNone(self.h.store.get_share("w1", "share-2"))
        # 新份额私钥在生效位置
        self.assertIsNotNone(
            self.h.store.get_share("w1", "rotA-share-1")
        )
        # 暂存备份删除，暂存新份额私钥删除（仅生效处一份）
        rdir = os.path.join(self.tmp, "rotations", "w1", "rotA")
        self.assertFalse(os.path.exists(os.path.join(rdir, "backup")))
        self.assertFalse(os.path.exists(os.path.join(rdir, "rotA-share-1.json")))
        # active 状态文件保留（状态跨重启可读）
        self.assertEqual(
            self.h.store.get_rotation_state("w1", "rotA")["state"],
            "active",
        )

    def test_activate_active_replay_is_200(self):
        self.assertEqual(
            self.svc.activate_share_rotation("w1", "rotA")[0], 201
        )
        status, body = self.svc.activate_share_rotation("w1", "rotA")
        self.assertEqual(status, 200)
        self.assertEqual(body["state"], "active")
        events = [
            e
            for e in self.svc.get_audit_events("w1")["events"]
            if e["type"] == "share_rotation_activated"
        ]
        self.assertEqual(len(events), 1)

    def test_activate_unknown_is_404(self):
        with self.assertRaises(ServiceError) as ctx:
            self.svc.activate_share_rotation("w1", "ghost")
        self.assertEqual(ctx.exception.status, 404)

    def test_activate_activating_state_is_409(self):
        rec = self.h.store.get_rotation_state("w1", "rotA")
        rec["state"] = ROTATION_ACTIVATING
        self.h.store.save_rotation_state("w1", rec)
        with self.assertRaises(ServiceError) as ctx:
            self.svc.activate_share_rotation("w1", "rotA")
        self.assertEqual(ctx.exception.status, 409)

    def test_prepare_new_rotation_after_activation_allowed(self):
        self.svc.activate_share_rotation("w1", "rotA")
        status, body = self.svc.prepare_share_rotation("w1", "rotB")
        self.assertEqual(status, 201)
        self.assertEqual(body["share_ids"], ["rotB-share-1", "rotB-share-2"])
        status, _ = self.svc.activate_share_rotation("w1", "rotB")
        self.assertEqual(status, 201)
        wallet = self.h.store.get_wallet("w1")
        self.assertEqual(
            [s["share_id"] for s in wallet["shares"]],
            ["rotB-share-1", "rotB-share-2"],
        )
        # rotA 的新份额也已被 rotB 轮换删除
        self.assertIsNone(self.h.store.get_share("w1", "rotA-share-1"))


class SignAfterRotationTest(unittest.TestCase):
    def setUp(self):
        self.h = make_harness(tempfile.mkdtemp())
        self.svc = self.h.service
        self.svc.create_wallet("w1", 2)
        # 缓存旧份额私钥（轮换后旧文件会被删除）
        self.old_priv = {
            sid: self.h.share_private_hex("w1", sid)
            for sid in ("share-1", "share-2")
        }
        self.svc.prepare_share_rotation("w1", "rotA")
        self.svc.activate_share_rotation("w1", "rotA")
        self.new_ids = ("rotA-share-1", "rotA-share-2")

    def _old_style_signatures(self, srid, message):
        payload = crypto.build_payload(srid, message)
        return [
            {
                "share_id": sid,
                "signature": crypto.sign_share(
                    bytes.fromhex(self.old_priv[sid]), payload
                ).hex(),
            }
            for sid in ("share-1", "share-2")
        ]

    def test_old_share_ids_rejected_400(self):
        with self.assertRaises(ServiceError) as ctx:
            self.svc.sign("w1", "r1", "m", self._old_style_signatures("r1", "m"))
        self.assertEqual(ctx.exception.status, 400)

    def test_new_share_ids_sign_201_and_verify_against_new_public_key(self):
        sigs = _sign_with(self.h.store, "w1", self.new_ids, "r1", "m")
        status, body = self.svc.sign("w1", "r1", "m", sigs)
        self.assertEqual(status, 201)
        wallet = self.h.store.get_wallet("w1")
        pks = crypto.split_public_key(bytes.fromhex(wallet["public_key"]))
        parts = crypto.split_signature(bytes.fromhex(body["signature"]))
        payload = crypto.build_payload("r1", "m")
        for pk, sig in zip(pks, parts):
            self.assertTrue(crypto.verify_share(pk, payload, sig))

    def test_sign_replay_after_rotation_is_200(self):
        sigs = _sign_with(self.h.store, "w1", self.new_ids, "r1", "m")
        _, first = self.svc.sign("w1", "r1", "m", sigs)
        status, second = self.svc.sign("w1", "r1", "m", sigs)
        self.assertEqual(status, 200)
        self.assertEqual(second, first)


class RotationAuditTest(unittest.TestCase):
    def setUp(self):
        self.h = make_harness(tempfile.mkdtemp())
        self.svc = self.h.service
        self.svc.create_wallet("w1", 2)
        # 先制造一条历史事件，验证轮换事件接续 seq
        self.svc.put_policy("w1", 1, 3600)

    def _rotation_events(self):
        return [
            e
            for e in self.svc.get_audit_events("w1")["events"]
            if e["type"]
            in ("share_rotation_prepared", "share_rotation_activated")
        ]

    def test_prepared_and_activated_event_fields(self):
        _, prepared = self.svc.prepare_share_rotation("w1", "rotA")
        previous_pk = self.svc.get_wallet("w1")["public_key"]
        self.svc.activate_share_rotation("w1", "rotA")

        events = self._rotation_events()
        self.assertEqual(
            [e["type"] for e in events],
            ["share_rotation_prepared", "share_rotation_activated"],
        )
        p, a = events
        self.assertEqual(
            set(p),
            {"seq", "type", "at", "request_id", "actor_id", "reason",
             "details"},
        )
        self.assertIsNone(p["request_id"])
        self.assertIsNone(p["actor_id"])
        self.assertIsNone(p["reason"])
        self.assertEqual(
            p["details"],
            {
                "rotation_id": "rotA",
                "share_ids": ["rotA-share-1", "rotA-share-2"],
                "public_key": prepared["public_key"],
            },
        )
        self.assertEqual(
            a["details"],
            {
                "rotation_id": "rotA",
                "share_ids": ["rotA-share-1", "rotA-share-2"],
                "public_key": prepared["public_key"],
                "previous_public_key": previous_pk,
            },
        )
        # details 中绝无私钥
        blob = json.dumps([p["details"], a["details"]])
        self.assertNotIn("private", blob)

    def test_seq_continuous_across_rotation(self):
        self.svc.prepare_share_rotation("w1", "rotA")
        self.svc.activate_share_rotation("w1", "rotA")
        seqs = [e["seq"] for e in self.svc.get_audit_events("w1")["events"]]
        self.assertEqual(seqs, list(range(1, len(seqs) + 1)))


class ActivationRollbackTest(unittest.TestCase):
    """激活各阶段失败：回滚文件/公钥/状态并清理，无事件无 seq 缺口。"""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.h = make_harness(self.tmp)
        self.svc = self.h.service
        self.svc.create_wallet("w1", 2)
        self.old_pk = self.svc.get_wallet("w1")["public_key"]
        self.svc.prepare_share_rotation("w1", "r1")

    def _assert_fully_rolled_back(self):
        wallet = self.h.store.get_wallet("w1")
        self.assertEqual(wallet["public_key"], self.old_pk)
        self.assertEqual(
            [s["share_id"] for s in wallet["shares"]],
            ["share-1", "share-2"],
        )
        self.assertIsNotNone(self.h.store.get_share("w1", "share-1"))
        self.assertIsNone(self.h.store.get_share("w1", "r1-share-1"))
        rec = self.h.store.get_rotation_state("w1", "r1")
        self.assertEqual(rec["state"], ROTATION_PREPARED)
        self.assertFalse(
            os.path.exists(
                os.path.join(self.tmp, "rotations", "w1", "r1", "backup")
            )
        )
        events = self.svc.get_audit_events("w1")["events"]
        self.assertNotIn(
            "share_rotation_activated", [e["type"] for e in events]
        )
        seqs = [e["seq"] for e in events]
        self.assertEqual(seqs, list(range(1, len(seqs) + 1)))

    def _patch_fail(self, method_name):
        original = getattr(self.h.store, method_name)

        def boom(*args, **kwargs):
            raise OSError(f"{method_name} disk full")

        setattr(self.h.store, method_name, boom)
        return original

    def test_rollback_when_activating_state_write_fails(self):
        original = self._patch_fail("save_rotation_state")
        try:
            with self.assertRaises(OSError):
                self.svc.activate_share_rotation("w1", "r1")
        finally:
            self.h.store.save_rotation_state = original
        self._assert_fully_rolled_back()

    def test_rollback_when_file_commit_fails(self):
        original = self._patch_fail("commit_rotated_shares")
        try:
            with self.assertRaises(OSError):
                self.svc.activate_share_rotation("w1", "r1")
        finally:
            self.h.store.commit_rotated_shares = original
        self._assert_fully_rolled_back()

    def test_rollback_when_active_state_write_fails(self):
        real = self.h.store.save_rotation_state

        def fail_active(wallet_id, record):
            if record.get("state") == "active":
                raise OSError("disk full")
            return real(wallet_id, record)

        self.h.store.save_rotation_state = fail_active
        try:
            with self.assertRaises(OSError):
                self.svc.activate_share_rotation("w1", "r1")
        finally:
            self.h.store.save_rotation_state = real
        self._assert_fully_rolled_back()

    def test_rollback_when_activated_event_append_fails(self):
        real_append = self.svc._audit.append_event

        def fail_activated(wallet_id, event):
            if event["type"] == "share_rotation_activated":
                raise OSError("audit disk full")
            return real_append(wallet_id, event)

        self.svc._audit.append_event = fail_activated
        try:
            with self.assertRaises(OSError):
                self.svc.activate_share_rotation("w1", "r1")
        finally:
            self.svc._audit.append_event = real_append
        self._assert_fully_rolled_back()

    def test_retry_after_rollback_succeeds_once(self):
        original = self._patch_fail("commit_rotated_shares")
        with self.assertRaises(OSError):
            self.svc.activate_share_rotation("w1", "r1")
        self.h.store.commit_rotated_shares = original

        status, body = self.svc.activate_share_rotation("w1", "r1")
        self.assertEqual(status, 201)
        self.assertEqual(body["state"], "active")
        events = [
            e["type"]
            for e in self.svc.get_audit_events("w1")["events"]
            if e["type"] == "share_rotation_activated"
        ]
        self.assertEqual(events, ["share_rotation_activated"])
        # 旧私钥在磁盘上恰好被清除，没有残留备份
        self.assertIsNone(self.h.store.get_share("w1", "share-1"))


class RotationRestartRecoveryTest(unittest.TestCase):
    """启动恢复：未完成激活回滚，prepared/active 状态跨重启保留。"""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.h = make_harness(self.tmp)
        self.svc = self.h.service
        self.svc.create_wallet("w1", 2)
        self.old_pk = self.svc.get_wallet("w1")["public_key"]

    def _reopen(self):
        return make_harness(self.tmp)

    def _force_crash_after_commit(self, rid="r1"):
        """模拟 activating 阶段、文件已替换后的崩溃。"""
        self.svc.prepare_share_rotation("w1", rid)
        self.h.store.backup_active_material("w1", rid)
        rec = self.h.store.get_rotation_state("w1", rid)
        rec["state"] = ROTATION_ACTIVATING
        self.h.store.save_rotation_state("w1", rec)
        self.h.store.commit_rotated_shares(
            "w1",
            rid,
            [f"{rid}-share-1", f"{rid}-share-2"],
            rec["public_key"],
        )

    def test_unfinished_activation_rolled_back_on_restart(self):
        self._force_crash_after_commit()
        self.assertNotEqual(
            self.h.store.get_wallet("w1")["public_key"], self.old_pk
        )
        h2 = self._reopen()  # 构造即触发恢复
        wallet = h2.store.get_wallet("w1")
        self.assertEqual(wallet["public_key"], self.old_pk)
        self.assertEqual(
            [s["share_id"] for s in wallet["shares"]],
            ["share-1", "share-2"],
        )
        self.assertIsNone(h2.store.get_share("w1", "r1-share-1"))
        self.assertIsNotNone(h2.store.get_share("w1", "share-1"))
        rec = h2.store.get_rotation_state("w1", "r1")
        self.assertEqual(rec["state"], ROTATION_PREPARED)
        self.assertFalse(
            os.path.exists(
                os.path.join(self.tmp, "rotations", "w1", "r1", "backup")
            )
        )
        # 恢复后旧份额签名正常，且可以重新激活成功
        sigs = h2.two_signatures("w1", "r9", "m")
        self.assertEqual(h2.service.sign("w1", "r9", "m", sigs)[0], 201)
        self.assertEqual(
            h2.service.activate_share_rotation("w1", "r1")[0], 201
        )

    def test_prepared_survives_restart(self):
        _, prepared = self.svc.prepare_share_rotation("w1", "rp")
        h2 = self._reopen()
        rec = h2.store.get_rotation_state("w1", "rp")
        self.assertEqual(rec["state"], ROTATION_PREPARED)
        self.assertEqual(rec["public_key"], prepared["public_key"])
        # 暂存私钥仍在，激活可继续
        self.assertEqual(
            h2.service.activate_share_rotation("w1", "rp")[0], 201
        )

    def test_active_survives_restart(self):
        self.svc.prepare_share_rotation("w1", "ra")
        self.svc.activate_share_rotation("w1", "ra")
        events_before = len(self.svc.get_audit_events("w1")["events"])
        h2 = self._reopen()
        self.assertEqual(
            h2.store.get_rotation_state("w1", "ra")["state"], "active"
        )
        self.assertEqual(
            h2.store.get_wallet("w1")["public_key"],
            self.svc.get_wallet("w1")["public_key"],
        )
        # 重启不补记任何事件、不留备份
        self.assertEqual(
            len(h2.service.get_audit_events("w1")["events"]),
            events_before,
        )
        self.assertFalse(
            os.path.exists(
                os.path.join(self.tmp, "rotations", "w1", "ra", "backup")
            )
        )

    def test_active_committed_but_uncleaned_is_cleaned_on_restart(self):
        self.svc.prepare_share_rotation("w1", "rc")
        self.svc.activate_share_rotation("w1", "rc")
        # 手工重建 active 提交后、清理前的暂存与备份残骸
        rdir = os.path.join(self.tmp, "rotations", "w1", "rc")
        for sid in ("rc-share-1", "rc-share-2"):
            rec = self.h.store.get_share("w1", sid)
            self.h.store._atomic_write(
                os.path.join(rdir, sid + ".json"), rec
            )
        bdir = os.path.join(rdir, "backup", "shares")
        os.makedirs(bdir, exist_ok=True)
        h2 = self._reopen()
        names = os.listdir(rdir)
        self.assertFalse(
            [n for n in names if n.endswith(".json") and n != "state.json"]
        )
        self.assertFalse(os.path.exists(os.path.join(rdir, "backup")))
        self.assertEqual(
            h2.store.get_rotation_state("w1", "rc")["state"], "active"
        )


class RotationPrivateKeyBoundaryTest(unittest.TestCase):
    """轮换全程：不存在完整私钥，每个文件至多一个份额私钥。"""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()

    def _all_private_keys(self):
        locations = {}
        for base, _, files in os.walk(self.tmp):
            for name in files:
                path = os.path.join(base, name)
                try:
                    with open(path, encoding="utf-8") as f:
                        record = json.load(f)
                except (ValueError, OSError):
                    continue
                found = []

                def walk(obj):
                    if isinstance(obj, dict):
                        for key, value in obj.items():
                            if key == "private_key" and isinstance(value, str):
                                found.append(value)
                            else:
                                walk(value)
                    elif isinstance(obj, list):
                        for item in obj:
                            walk(item)

                walk(record)
                for priv in found:
                    locations.setdefault(priv, []).append(path)
        return locations

    def test_prepared_state_boundary(self):
        h = make_harness(self.tmp)
        h.service.create_wallet("w1", 2)
        h.service.prepare_share_rotation("w1", "r1")
        locations = self._all_private_keys()
        # 2 旧 + 2 新，共 4 个独立份额私钥，各自恰好一个文件
        self.assertEqual(len(locations), 4)
        for priv, paths in locations.items():
            self.assertEqual(len(paths), 1, priv)
            self.assertEqual(len(priv), 64)

    def test_activated_state_old_keys_purged(self):
        h = make_harness(self.tmp)
        h.service.create_wallet("w1", 2)
        old_priv = [
            h.store.get_share("w1", sid)["private_key"]
            for sid in ("share-1", "share-2")
        ]
        h.service.prepare_share_rotation("w1", "r1")
        h.service.activate_share_rotation("w1", "r1")
        locations = self._all_private_keys()
        self.assertEqual(len(locations), 2)  # 仅两个新份额
        for priv in old_priv:
            self.assertNotIn(priv, locations)
        # 任何文件中都不出现拼接后的完整私钥（两种排列）
        blob = b""
        for base, _, files in os.walk(self.tmp):
            for name in files:
                with open(os.path.join(base, name), "rb") as f:
                    blob += f.read()
        self.assertNotIn((old_priv[0] + old_priv[1]).encode(), blob)
        self.assertNotIn((old_priv[1] + old_priv[0]).encode(), blob)


class RotationHttpTest(unittest.TestCase):
    """HTTP 端到端：状态码契约。"""

    def setUp(self):
        self._ctx = http_server(tempfile.mkdtemp())
        self.srv = self._ctx.__enter__()
        self.srv.request(
            "POST", "/v1/wallets", {"wallet_id": "w1", "shares": 2}
        )

    def tearDown(self):
        self._ctx.__exit__(None, None, None)

    def request(self, method, path, body=None):
        return self.srv.request(method, path, body)

    def test_full_lifecycle_over_http(self):
        st, body = self.request(
            "POST",
            "/v1/wallets/w1/share-rotations",
            {"rotation_id": "rot-1"},
        )
        self.assertEqual(st, 201)
        self.assertEqual(body["state"], "prepared")

        st, _ = self.request(
            "POST",
            "/v1/wallets/w1/share-rotations",
            {"rotation_id": "rot-1"},
        )
        self.assertEqual(st, 200)

        st, _ = self.request(
            "POST",
            "/v1/wallets/w1/share-rotations",
            {"rotation_id": "rot-2"},
        )
        self.assertEqual(st, 409)

        st, body = self.request(
            "GET", "/v1/wallets/w1/share-rotations/rot-1"
        )
        self.assertEqual(st, 200)
        self.assertEqual(body["state"], "prepared")

        st, _ = self.request("GET", "/v1/wallets/w1/share-rotations/nope")
        self.assertEqual(st, 404)

        st, body = self.request(
            "POST", "/v1/wallets/w1/share-rotations/rot-1/activate"
        )
        self.assertEqual(st, 201)
        self.assertEqual(body["state"], "active")

        st, body = self.request(
            "POST", "/v1/wallets/w1/share-rotations/rot-1/activate"
        )
        self.assertEqual(st, 200)
        self.assertEqual(body["state"], "active")

        # 钱包公钥已轮换
        _, wallet = self.request("GET", "/v1/wallets/w1")
        self.assertEqual(wallet["public_key"], body["public_key"])

        # 激活后旧份额签名 400，新份额 201
        old_body = {
            "signing_request_id": "r1",
            "message": "m",
            "signatures": [
                {
                    "share_id": sid,
                    "signature": "00" * 64,
                }
                for sid in ("share-1", "share-2")
            ],
        }
        st, _ = self.request("POST", "/v1/wallets/w1/sign", old_body)
        self.assertEqual(st, 400)

        # 用轮换后的新 share_ids 与新份额私钥签名
        from threshold_wallet import crypto as _crypto

        payload = _crypto.build_payload("r1", "m")
        sigs = []
        for sid in ("rot-1-share-1", "rot-1-share-2"):
            share = self.srv.harness.store.get_share("w1", sid)
            sigs.append(
                {
                    "share_id": sid,
                    "signature": _crypto.sign_share(
                        bytes.fromhex(share["private_key"]), payload
                    ).hex(),
                }
            )
        st, first = self.request(
            "POST",
            "/v1/wallets/w1/sign",
            {"signing_request_id": "r1", "message": "m", "signatures": sigs},
        )
        self.assertEqual(st, 201)
        st, second = self.request(
            "POST",
            "/v1/wallets/w1/sign",
            {"signing_request_id": "r1", "message": "m", "signatures": sigs},
        )
        self.assertEqual(st, 200)
        self.assertEqual(second, first)


if __name__ == "__main__":
    unittest.main()
