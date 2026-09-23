"""兼容灾备 CLI（backup/restore）测试。"""

from __future__ import annotations

import contextlib
import hashlib
import io
import json
import os
import tarfile
import tempfile
import unittest

from tests.helpers import make_harness
from threshold_wallet import drbackup
from threshold_wallet.audit import AuditStore
from threshold_wallet.service import WalletService
from threshold_wallet.store import WalletStore
from threshold_wallet.cli import main as cli_main


def _pack(path, manifest, files):
    with tarfile.open(path, "w") as tar:
        data = (json.dumps(manifest, ensure_ascii=False,
                           sort_keys=True, indent=2) + "\n").encode()
        info = tarfile.TarInfo(drbackup.MANIFEST_MEMBER)
        info.size, info.mtime, info.mode = len(data), 0, 0o600
        tar.addfile(info, io.BytesIO(data))
        for name, blob in files.items():
            info = tarfile.TarInfo(name)
            info.size, info.mtime, info.mode = len(blob), 0, 0o600
            tar.addfile(info, io.BytesIO(blob))


def _read_pack(path):
    files = {}
    with tarfile.open(path) as tar:
        for member in tar.getmembers():
            if member.name == drbackup.MANIFEST_MEMBER:
                manifest = json.loads(tar.extractfile(member).read())
            else:
                files[member.name] = tar.extractfile(member).read()
    return manifest, files


def _repack_with_overrides(src, dst, overrides, *, snapshot_id=None,
                           rebind=True, add_members=None, add_symlinks=None):
    """以 src 快照为底，覆盖若干成员并（默认）重算 manifest 绑定后写到 dst。"""
    manifest, files = _read_pack(src)
    files.update(overrides)
    if snapshot_id is not None:
        manifest["snapshot_id"] = snapshot_id
    entries = []
    for name, blob in sorted(files.items()):
        entries.append({
            "path": name,
            "bytes": len(blob),
            "sha256": hashlib.sha256(blob).hexdigest(),
        })
    manifest["files"] = entries
    if rebind:
        manifest["manifest_sha256"] = hashlib.sha256(
            drbackup._canonical_manifest_body(manifest)
        ).hexdigest()
    with tarfile.open(dst, "w") as tar:
        data = json.dumps(manifest, ensure_ascii=False,
                          sort_keys=True, indent=2).encode()
        info = tarfile.TarInfo(drbackup.MANIFEST_MEMBER)
        info.size, info.mtime, info.mode = len(data), 0, 0o600
        tar.addfile(info, io.BytesIO(data))
        for name, blob in sorted(files.items()):
            info = tarfile.TarInfo(name)
            info.size, info.mtime, info.mode = len(blob), 0, 0o600
            tar.addfile(info, io.BytesIO(blob))
        for name, blob in (add_members or {}).items():
            info = tarfile.TarInfo(name)
            info.size, info.mtime, info.mode = len(blob), 0, 0o600
            tar.addfile(info, io.BytesIO(blob))
        for name, target in (add_symlinks or {}).items():
            info = tarfile.TarInfo(name)
            info.type = tarfile.SYMTYPE
            info.linkname = target
            info.mtime, info.mode = 0, 0o600
            tar.addfile(info)
    return manifest


class BackupTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.data = os.path.join(self.tmp, "data")
        self.h = make_harness(self.data)
        self.h.service.create_wallet("alice", 2)
        self.out = os.path.join(self.tmp, "b.tar")

    def test_backup_manifest_v1_and_binding(self):
        body = drbackup.backup(self.data, "alice", "SNAP_1", self.out)
        self.assertEqual(body["status"], 201)
        self.assertEqual(body["snapshot_id"], "SNAP_1")
        m = body["manifest"]
        self.assertEqual(m["version"], 1)
        self.assertEqual(m["wallet_id"], "alice")
        self.assertEqual(m["snapshot_id"], "SNAP_1")
        self.assertIn("manifest_sha256", m)
        self.assertEqual(
            m["manifest_sha256"],
            hashlib.sha256(
                drbackup._canonical_manifest_body(m)
            ).hexdigest(),
        )
        paths = {f["path"] for f in m["files"]}
        self.assertEqual(
            paths, {"wallets/alice.json",
                    "shares/alice/share-1.json",
                    "shares/alice/share-2.json"}
        )
        # tar 可解，成员路径均安全，无目录/链接
        with tarfile.open(self.out) as tar:
            names = tar.getnames()
            self.assertIn("manifest.json", names)
            for member in tar.getmembers():
                self.assertTrue(member.isfile())
                self.assertFalse(member.issym() or member.islnk())
                self.assertFalse(member.name.startswith("/"))
                self.assertNotIn("..", member.name.split("/"))

    def test_snapshot_id_pattern(self):
        for bad in ("", "a b", "../x", "a" * 129, "a/b", "x:y"):
            with self.assertRaises(drbackup.BackupError) as cm:
                drbackup.backup(self.data, "alice", bad, self.out)
            self.assertEqual(cm.exception.status, 400)
        drbackup.backup(self.data, "alice", "A-z_1", self.out)  # 合法

    def test_missing_wallet_404(self):
        with self.assertRaises(drbackup.BackupError) as cm:
            drbackup.backup(self.data, "ghost", "S1", self.out)
        self.assertEqual(cm.exception.status, 404)

    def test_manifest_never_contains_private_key(self):
        body = drbackup.backup(self.data, "alice", "S1", self.out)
        serialized = json.dumps(body)
        for sid in ("share-1", "share-2"):
            priv = self.h.store.get_share("alice", sid)["private_key"]
            self.assertNotIn(priv, serialized)

    def test_rejects_symlink_and_tmp_and_extra_files(self):
        os.symlink("/etc/hostname",
                   os.path.join(self.data, "shares/alice/evil.json"))
        with self.assertRaises(drbackup.BackupError) as cm:
            drbackup.backup(self.data, "alice", "S1", self.out)
        self.assertEqual(cm.exception.status, 503)
        os.unlink(os.path.join(self.data, "shares/alice/evil.json"))

        open(os.path.join(self.data, "shares/alice/.tmp-x.json"), "w").write("{}")
        with self.assertRaises(drbackup.BackupError) as cm:
            drbackup.backup(self.data, "alice", "S1", self.out)
        self.assertEqual(cm.exception.status, 503)

    def test_backup_includes_all_business_dirs_and_staging(self):
        svc = self.h.service
        svc.put_policy("alice", 1, 3600)
        svc.create_asset_operation("alice", "op1", "BTC", 5)
        svc.commit_asset_operation("alice", "op1")
        svc.create_share_rotation("alice", "rot1")
        svc.create_sign_session("alice", "ses1", "hi", 600)
        body = drbackup.backup(self.data, "alice", "S1", self.out)
        paths = {f["path"] for f in body["manifest"]["files"]}
        for expected in (
            "audit/alice.json", "policies/alice.json", "assets/alice.json",
            "rotations/alice.json", "sign-sessions/alice.json",
            "rotation-staging/alice/rot1/rot1-share-1.json",
            "rotation-staging/alice/rot1/rot1-share-2.json",
        ):
            self.assertIn(expected, paths)
        # 锁与资产意图绝不在快照中
        self.assertFalse(any("locks/" in p for p in paths))
        self.assertFalse(any("asset-intents/" in p for p in paths))

    def test_backup_refuses_corrupt_wallet(self):
        svc = self.h.service
        svc.create_asset_operation("alice", "op1", "BTC", 5)
        with open(os.path.join(self.data, "assets/alice.json"), "w") as f:
            f.write("{broken")
        with self.assertRaises(drbackup.BackupError) as cm:
            drbackup.backup(self.data, "alice", "S1", self.out)
        self.assertEqual(cm.exception.status, 503)
        self.assertFalse(os.path.exists(self.out))

    def test_failed_backup_does_not_overwrite_existing_snapshot(self):
        first = os.path.join(self.tmp, "first.tar")
        drbackup.backup(self.data, "alice", "S0", first)
        with open(first, "rb") as f:
            original_bytes = f.read()
        os.symlink("/etc/hostname",
                   os.path.join(self.data, "shares/alice/evil.json"))
        with self.assertRaises(drbackup.BackupError) as cm:
            drbackup.backup(self.data, "alice", "S1", first)
        self.assertEqual(cm.exception.status, 503)
        with open(first, "rb") as f:
            self.assertEqual(f.read(), original_bytes)

    def test_backup_rejects_bak_json_in_business_dir(self):
        with open(os.path.join(self.data, "wallets/alice.bak.json"), "w") as f:
            f.write("{}")
        with self.assertRaises(drbackup.BackupError) as cm:
            drbackup.backup(self.data, "alice", "S1", self.out)
        self.assertEqual(cm.exception.status, 503)
        self.assertFalse(os.path.exists(self.out))

    def test_backup_rejects_atomic_temp_file(self):
        audit_dir = os.path.join(self.data, "audit")
        os.makedirs(audit_dir, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=audit_dir, prefix=".tmp-", suffix=".json")
        os.close(fd)
        with self.assertRaises(drbackup.BackupError) as cm:
            drbackup.backup(self.data, "alice", "S1", self.out)
        self.assertEqual(cm.exception.status, 503)
        self.assertFalse(os.path.exists(self.out))

    def test_backup_rejects_directory_in_business_dir(self):
        os.makedirs(os.path.join(self.data, "audit", "alice.json"))
        with self.assertRaises(drbackup.BackupError) as cm:
            drbackup.backup(self.data, "alice", "S1", self.out)
        self.assertEqual(cm.exception.status, 503)

    def test_backup_rejects_bak_json_in_rotation_staging(self):
        svc = self.h.service
        svc.create_share_rotation("alice", "rot1")
        with open(
            os.path.join(self.data, "rotation-staging/alice/rot1",
                         "wallet.bak.json"), "w"
        ) as f:
            f.write("{}")
        with self.assertRaises(drbackup.BackupError) as cm:
            drbackup.backup(self.data, "alice", "S1", self.out)
        self.assertEqual(cm.exception.status, 503)
        self.assertFalse(os.path.exists(self.out))

    def test_backup_allows_other_wallets_formal_files(self):
        bob = self.h.service
        bob.create_wallet("bob", 2)
        body = drbackup.backup(self.data, "alice", "S1", self.out)
        paths = {f["path"] for f in body["manifest"]["files"]}
        self.assertTrue(all("bob" not in p for p in paths))


class RestoreManifestContractTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.src = os.path.join(self.tmp, "src")
        self.dst = os.path.join(self.tmp, "dst")
        self.h = make_harness(self.src)
        self.h.service.create_wallet("alice", 2)
        self.pack = os.path.join(self.tmp, "good.tar")
        drbackup.backup(self.src, "alice", "S1", self.pack)

    def test_extra_top_level_manifest_key_503(self):
        manifest, files = _read_pack(self.pack)
        manifest["extra"] = 1
        p = os.path.join(self.tmp, "extra-top.tar")
        _pack(p, manifest, files)
        with self.assertRaises(drbackup.BackupError) as cm:
            drbackup.restore(self.dst, "alice", p)
        self.assertEqual(cm.exception.status, 503)

    def test_extra_manifest_entry_key_503(self):
        manifest, files = _read_pack(self.pack)
        manifest["files"][0]["evil"] = "x"
        manifest["manifest_sha256"] = hashlib.sha256(
            drbackup._canonical_manifest_body(manifest)
        ).hexdigest()
        p = os.path.join(self.tmp, "extra-entry.tar")
        _pack(p, manifest, files)
        with self.assertRaises(drbackup.BackupError) as cm:
            drbackup.restore(self.dst, "alice", p)
        self.assertEqual(cm.exception.status, 503)

    def test_private_key_field_in_wallet_meta_503(self):
        manifest, files = _read_pack(self.pack)
        wallet = json.loads(files["wallets/alice.json"])
        wallet["private_key"] = "00" * 32
        p = os.path.join(self.tmp, "pk.tar")
        _repack_with_overrides(
            self.pack, p,
            {"wallets/alice.json": json.dumps(wallet).encode()},
        )
        with self.assertRaises(drbackup.BackupError) as cm:
            drbackup.restore(self.dst, "alice", p)
        self.assertEqual(cm.exception.status, 503)

    def test_extra_share_record_key_503(self):
        manifest, files = _read_pack(self.pack)
        rec = json.loads(files["shares/alice/share-1.json"])
        rec["extra"] = 1
        p = os.path.join(self.tmp, "sx.tar")
        _repack_with_overrides(
            self.pack, p,
            {"shares/alice/share-1.json": json.dumps(rec).encode()},
        )
        with self.assertRaises(drbackup.BackupError) as cm:
            drbackup.restore(self.dst, "alice", p)
        self.assertEqual(cm.exception.status, 503)

    def test_private_key_nested_in_audit_file_503(self):
        # 审计/业务文件即使嵌套夹带 private_key 字段也必须拒绝
        tmp2 = tempfile.mkdtemp()
        src2 = os.path.join(tmp2, "src")
        h2 = make_harness(src2)
        h2.service.create_wallet("alice", 2)
        h2.service.put_policy("alice", 1, 3600)
        good = os.path.join(tmp2, "good.tar")
        drbackup.backup(src2, "alice", "S1", good)
        manifest, files = _read_pack(good)
        audit_log = json.loads(files["audit/alice.json"])
        audit_log["events"][0]["details"]["private_key"] = "11" * 32
        p = os.path.join(tmp2, "bad.tar")
        _repack_with_overrides(
            good, p,
            {"audit/alice.json": json.dumps(audit_log).encode()},
        )
        with self.assertRaises(drbackup.BackupError) as cm:
            drbackup.restore(os.path.join(tmp2, "dst"), "alice", p)
        self.assertEqual(cm.exception.status, 503)

    def test_unknown_audit_event_type_503(self):
        tmp2 = tempfile.mkdtemp()
        src2 = os.path.join(tmp2, "src")
        h2 = make_harness(src2)
        h2.service.create_wallet("alice", 2)
        h2.service.put_policy("alice", 1, 3600)
        good = os.path.join(tmp2, "good.tar")
        drbackup.backup(src2, "alice", "S1", good)
        manifest, files = _read_pack(good)
        audit_log = json.loads(files["audit/alice.json"])
        audit_log["events"][0]["type"] = "totally_new_event"
        p = os.path.join(tmp2, "bad.tar")
        _repack_with_overrides(
            good, p,
            {"audit/alice.json": json.dumps(audit_log).encode()},
        )
        with self.assertRaises(drbackup.BackupError) as cm:
            drbackup.restore(os.path.join(tmp2, "dst"), "alice", p)
        self.assertEqual(cm.exception.status, 503)

    def test_rotation_record_extra_key_503(self):
        tmp2 = tempfile.mkdtemp()
        src2 = os.path.join(tmp2, "src")
        h2 = make_harness(src2)
        h2.service.create_wallet("alice", 2)
        h2.service.create_share_rotation("alice", "rot1")
        good = os.path.join(tmp2, "good.tar")
        drbackup.backup(src2, "alice", "S1", good)
        manifest, files = _read_pack(good)
        rotations = json.loads(files["rotations/alice.json"])
        rotations["rot1"]["bogus"] = 5
        p = os.path.join(tmp2, "bad.tar")
        _repack_with_overrides(
            good, p,
            {"rotations/alice.json": json.dumps(rotations).encode()},
        )
        with self.assertRaises(drbackup.BackupError) as cm:
            drbackup.restore(os.path.join(tmp2, "dst"), "alice", p)
        self.assertEqual(cm.exception.status, 503)


class RestoreHappyPathTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.src = os.path.join(self.tmp, "src")
        self.dst = os.path.join(self.tmp, "dst")
        self.h = make_harness(self.src)
        self.h.service.create_wallet("alice", 2)
        svc = self.h.service
        svc.put_policy("alice", 1, 3600)
        svc.create_sign_request("alice", "req1", "pay-100")
        svc.approve("alice", "req1", "ops", None)
        self.sigs = self.h.two_signatures("alice", "req1", "pay-100")
        svc.sign("alice", "req1", "pay-100", self.sigs)
        svc.create_asset_operation("alice", "op1", "BTC", 10)
        svc.commit_asset_operation("alice", "op1")
        svc.create_asset_operation("alice", "op2", "BTC", -3)
        svc.commit_asset_operation("alice", "op2")
        self.pack = os.path.join(self.tmp, "b.tar")
        self.body = drbackup.backup(self.src, "alice", "S1", self.pack)

    def test_restore_201_preserves_state(self):
        status, body = drbackup.restore(self.dst, "alice", self.pack)
        self.assertEqual(status, 201)
        self.assertEqual(body["snapshot_id"], "S1")
        self.assertEqual(body["manifest"], self.body["manifest"])

        svc = WalletService(WalletStore(self.dst))
        self.assertEqual(
            svc.get_asset("alice", "BTC"),
            {"asset_id": "BTC", "balance": 7, "version": 2},
        )
        # 历史签名幂等连续
        st, replay = svc.sign("alice", "req1", "pay-100", self.sigs)
        self.assertEqual(st, 200)
        # 审计只有源端既有的事件，恢复不新增
        events = AuditStore(self.dst).list_events("alice")
        self.assertTrue(events)
        seqs = [e["seq"] for e in events]
        self.assertEqual(seqs, list(range(1, len(events) + 1)))

    def test_restore_idempotent_200_same_body(self):
        s1, b1 = drbackup.restore(self.dst, "alice", self.pack)
        s2, b2 = drbackup.restore(self.dst, "alice", self.pack)
        self.assertEqual((s1, s2), (201, 200))
        self.assertEqual(b1["manifest"], b2["manifest"])
        self.assertEqual(b1["manifest_sha256"], b2["manifest_sha256"])

    def test_restore_same_snapshot_different_content_409(self):
        drbackup.restore(self.dst, "alice", self.pack)
        pack2 = os.path.join(self.tmp, "b2.tar")
        self.h.service.create_asset_operation("alice", "op3", "BTC", 2)
        self.h.service.commit_asset_operation("alice", "op3")
        drbackup.backup(self.src, "alice", "S1", pack2)  # 同 S 不同内容
        with self.assertRaises(drbackup.BackupError) as cm:
            drbackup.restore(self.dst, "alice", pack2)
        self.assertEqual(cm.exception.status, 409)
        # 冲突不改变现场：原 BTC 余额仍为 7
        self.assertEqual(
            WalletService(WalletStore(self.dst)).get_asset("alice", "BTC")[
                "balance"], 7
        )

    def test_restore_wrong_wallet_identity_409(self):
        with self.assertRaises(drbackup.BackupError) as cm:
            drbackup.restore(self.dst, "bob", self.pack)
        self.assertEqual(cm.exception.status, 409)

    def test_restore_does_not_touch_other_wallets(self):
        dh = make_harness(self.dst)
        dh.service.create_wallet("alice", 2)
        dh.service.create_wallet("bob", 2)
        dh.service.put_policy("bob", 2, 77)
        drbackup.restore(self.dst, "alice", self.pack)
        self.assertEqual(
            WalletStore(self.dst).get_policy("bob")["required_approvals"], 2
        )
        self.assertIsNotNone(WalletStore(self.dst).get_wallet("bob"))

    def test_restore_replaces_newer_state_and_adds_no_audit(self):
        dh = make_harness(self.dst)
        dh.service.create_wallet("alice", 2)
        dh.service.put_policy("alice", 2, 500)  # 更新但不同的状态
        before = len(AuditStore(self.dst).list_events("alice"))
        drbackup.restore(self.dst, "alice", self.pack)
        after = len(AuditStore(self.dst).list_events("alice"))
        # 恢复成快照里的策略，且审计条数不增
        self.assertEqual(
            WalletStore(self.dst).get_policy("alice")["required_approvals"], 1
        )
        self.assertEqual(after, len(AuditStore(self.src).list_events("alice")))
        self.assertNotEqual(after, before)

    def test_restore_body_has_no_private_key(self):
        _, body = drbackup.restore(self.dst, "alice", self.pack)
        serialized = json.dumps(body)
        for sid in ("share-1", "share-2"):
            priv = self.h.store.get_share("alice", sid)["private_key"]
            self.assertNotIn(priv, serialized)


class RestoreRotationTest(unittest.TestCase):
    def test_prepared_rotation_survives_and_activates(self):
        tmp = tempfile.mkdtemp()
        src, dst = f"{tmp}/src", f"{tmp}/dst"
        h = make_harness(src)
        h.service.create_wallet("alice", 2)
        h.service.create_share_rotation("alice", "rot1")
        drbackup.backup(src, "alice", "S1", f"{tmp}/b.tar")
        status, _ = drbackup.restore(dst, "alice", f"{tmp}/b.tar")
        self.assertEqual(status, 201)
        svc = WalletService(WalletStore(dst))
        self.assertEqual(
            svc.get_share_rotation("alice", "rot1")["state"], "prepared"
        )
        st, view = svc.activate_share_rotation("alice", "rot1")
        self.assertEqual(st, 201)
        self.assertEqual(view["state"], "active")

    def test_historical_signatures_verify_across_rotation(self):
        tmp = tempfile.mkdtemp()
        src, dst = f"{tmp}/src", f"{tmp}/dst"
        h = make_harness(src)
        h.service.create_wallet("carol", 2)
        h.service.put_policy("carol", 1, 3600)
        h.service.create_sign_request("carol", "r1", "m")
        h.service.approve("carol", "r1", "ops", None)
        s1 = h.two_signatures("carol", "r1", "m")
        h.service.sign("carol", "r1", "m", s1)
        h.service.create_share_rotation("carol", "rotX")
        h.service.activate_share_rotation("carol", "rotX")
        h.service.create_sign_request("carol", "r2", "m2")
        h.service.approve("carol", "r2", "ops", None)
        ids = ["rotX-share-1", "rotX-share-2"]
        s2 = [
            {"share_id": sid,
             "signature": h.service.share_sign("carol", sid, "r2", "m2")[
                 "signature"]}
            for sid in ids
        ]
        h.service.sign("carol", "r2", "m2", s2)
        drbackup.backup(src, "carol", "S1", f"{tmp}/b.tar")
        status, _ = drbackup.restore(dst, "carol", f"{tmp}/b.tar")
        self.assertEqual(status, 201)
        svc = WalletService(WalletStore(dst))
        # 两个历史签名在恢复后都能按各自时刻公钥重放
        self.assertEqual(svc.sign("carol", "r1", "m", s1)[0], 200)
        self.assertEqual(svc.sign("carol", "r2", "m2", s2)[0], 200)

    def test_sessions_and_tx_policy_survive_restore(self):
        tmp = tempfile.mkdtemp()
        src, dst = f"{tmp}/src", f"{tmp}/dst"
        h = make_harness(src)
        h.service.create_wallet("erin", 2)
        h.service.put_transaction_policy("erin", "cold", 50, ["BTC", "ETH"])
        h.service.create_sign_session("erin", "ses1", "hello", 600)
        pack = f"{tmp}/b.tar"
        drbackup.backup(src, "erin", "S1", pack)
        status, _ = drbackup.restore(dst, "erin", pack)
        self.assertEqual(status, 201)
        store = WalletStore(dst)
        self.assertEqual(
            store.get_transaction_policy("erin"),
            {"mode": "cold", "max_delta": 50, "allowed_assets": ["BTC", "ETH"]},
        )
        view = WalletService(store).get_sign_session("erin", "ses1")
        self.assertEqual(view["id"], "ses1")
        self.assertEqual(view["state"], "collecting")
        self.assertEqual(view["missing_shares"], ["share-1", "share-2"])

    def test_direct_sign_without_policy_has_no_request_record(self):
        # 无审批策略时 /sign 直接产生 request_signed 事件、没有审批单文件：
        # 恢复校验不得因"有签名事件无审批单"而误判。
        tmp = tempfile.mkdtemp()
        src, dst = f"{tmp}/src", f"{tmp}/dst"
        h = make_harness(src)
        h.service.create_wallet("dave", 2)
        sigs = h.two_signatures("dave", "q1", "msg")
        h.service.sign("dave", "q1", "msg", sigs)
        drbackup.backup(src, "dave", "S1", f"{tmp}/b.tar")
        status, _ = drbackup.restore(dst, "dave", f"{tmp}/b.tar")
        self.assertEqual(status, 201)
        svc = WalletService(WalletStore(dst))
        self.assertEqual(svc.sign("dave", "q1", "msg", sigs)[0], 200)


class RestoreRejectTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.src = os.path.join(self.tmp, "src")
        self.dst = os.path.join(self.tmp, "dst")
        self.h = make_harness(self.src)
        self.h.service.create_wallet("alice", 2)
        self.pack = os.path.join(self.tmp, "good.tar")
        drbackup.backup(self.src, "alice", "S1", self.pack)

    def _restore(self, path):
        return drbackup.restore(self.dst, "alice", path)

    def test_not_a_tar_503(self):
        p = os.path.join(self.tmp, "bad.tar")
        open(p, "wb").write(b"garbage")
        with self.assertRaises(drbackup.BackupError) as cm:
            self._restore(p)
        self.assertEqual(cm.exception.status, 503)

    def test_missing_file_503(self):
        with self.assertRaises(drbackup.BackupError) as cm:
            self._restore(os.path.join(self.tmp, "nope.tar"))
        self.assertEqual(cm.exception.status, 503)

    def test_member_hash_tamper_503_and_no_write(self):
        manifest, files = _read_pack(self.pack)
        rec = json.loads(files["shares/alice/share-1.json"])
        rec["public_key"] = "00" * 32
        p = _repack_with_overrides(
            self.pack, os.path.join(self.tmp, "t.tar"),
            {"shares/alice/share-1.json": json.dumps(rec).encode()},
            rebind=False,
        )
        with self.assertRaises(drbackup.BackupError) as cm:
            self._restore(os.path.join(self.tmp, "t.tar"))
        self.assertEqual(cm.exception.status, 503)
        self.assertFalse(os.path.exists(
            os.path.join(self.dst, "wallets/alice.json")))

    def test_binding_hash_mismatch_503(self):
        p = os.path.join(self.tmp, "rebound.tar")
        _repack_with_overrides(self.pack, p, {}, rebind=False)
        # rebind=False 保留原 files 但…这里文件未变故哈希仍自洽；改为破坏绑定
        manifest, files = _read_pack(self.pack)
        manifest["manifest_sha256"] = "00" * 64
        _pack(p, manifest, files)
        with self.assertRaises(drbackup.BackupError) as cm:
            self._restore(p)
        self.assertEqual(cm.exception.status, 503)

    def test_extra_member_503(self):
        p = os.path.join(self.tmp, "extra.tar")
        _repack_with_overrides(
            self.pack, p, {}, add_members={"locks/alice.lock": b"{}"}
        )
        with self.assertRaises(drbackup.BackupError) as cm:
            self._restore(p)
        self.assertEqual(cm.exception.status, 503)

    def test_symlink_member_503(self):
        p = os.path.join(self.tmp, "link.tar")
        _repack_with_overrides(
            self.pack, p, {}, add_symlinks={"shares/alice/evil.json": "/etc/passwd"}
        )
        with self.assertRaises(drbackup.BackupError) as cm:
            self._restore(p)
        self.assertEqual(cm.exception.status, 503)

    def test_path_traversal_member_503(self):
        manifest, files = _read_pack(self.pack)
        p = os.path.join(self.tmp, "trav.tar")
        files["../escape.json"] = b"x"
        manifest["files"].append(
            {"path": "../escape.json", "bytes": 1,
             "sha256": hashlib.sha256(b"x").hexdigest()}
        )
        # 不重绑（绑定也必然失败），但先应在成员名校验处失败
        with tarfile.open(p, "w") as tar:
            mb = json.dumps(manifest).encode()
            info = tarfile.TarInfo("manifest.json")
            info.size, info.mtime = len(mb), 0
            tar.addfile(info, io.BytesIO(mb))
            for name, blob in files.items():
                info = tarfile.TarInfo(name)
                info.size, info.mtime = len(blob), 0
                tar.addfile(info, io.BytesIO(blob))
        with self.assertRaises(drbackup.BackupError) as cm:
            self._restore(p)
        self.assertEqual(cm.exception.status, 503)

    def test_inconsistent_ledger_snapshot_503(self):
        # 构造一个账本自相矛盾但每项哈希/绑定都自洽的快照：必须 503。
        tmp2 = tempfile.mkdtemp()
        src2 = f"{tmp2}/src"
        h2 = make_harness(src2)
        h2.service.create_wallet("alice", 2)
        h2.service.create_asset_operation("alice", "op1", "BTC", 5)
        h2.service.commit_asset_operation("alice", "op1")
        good = f"{tmp2}/good.tar"
        drbackup.backup(src2, "alice", "S1", good)
        manifest, files = _read_pack(good)
        ledger = json.loads(files["assets/alice.json"])
        # 把末态余额改成与 committed 操作重算不符
        ledger["assets"]["BTC"]["balance"] = 999
        p = _repack_with_overrides(
            good, f"{tmp2}/bad.tar",
            {"assets/alice.json": json.dumps(ledger).encode()},
        )
        with self.assertRaises(drbackup.BackupError) as cm:
            drbackup.restore(f"{tmp2}/dst", "alice", f"{tmp2}/bad.tar")
        self.assertEqual(cm.exception.status, 503)

    def test_bad_private_key_snapshot_503(self):
        manifest, files = _read_pack(self.pack)
        rec = json.loads(files["shares/alice/share-1.json"])
        rec["private_key"] = "11" * 32  # 与公钥不对应
        p = os.path.join(self.tmp, "key.tar")
        _repack_with_overrides(
            self.pack, p,
            {"shares/alice/share-1.json": json.dumps(rec).encode()},
        )
        with self.assertRaises(drbackup.BackupError) as cm:
            self._restore(p)
        self.assertEqual(cm.exception.status, 503)

    def test_request_audit_inconsistency_503(self):
        # 造一个带已签名审批单的钱包快照，再把审批单状态改成与其事件矛盾。
        tmp2 = tempfile.mkdtemp()
        src2 = f"{tmp2}/src"
        h2 = make_harness(src2)
        h2.service.create_wallet("alice", 2)
        h2.service.put_policy("alice", 1, 3600)
        h2.service.create_sign_request("alice", "r1", "m")
        h2.service.approve("alice", "r1", "ops", None)
        good = f"{tmp2}/good.tar"
        drbackup.backup(src2, "alice", "S1", good)
        manifest, files = _read_pack(good)
        reqs = json.loads(files["requests/alice.json"])
        # approved 单被篡改为 signed，但没有 request_signed 事件
        reqs["r1"]["state"] = "signed"
        p = f"{tmp2}/bad.tar"
        _repack_with_overrides(
            good, p,
            {"requests/alice.json": json.dumps(reqs).encode()},
        )
        with self.assertRaises(drbackup.BackupError) as cm:
            drbackup.restore(f"{tmp2}/dst", "alice", p)
        self.assertEqual(cm.exception.status, 503)


class RestoreCrashRecoveryTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.src = f"{self.tmp}/src"
        self.dst = f"{self.tmp}/dst"
        hs = make_harness(self.src)
        hs.service.create_wallet("alice", 2)
        hs.service.put_policy("alice", 1, 3600)
        self.pack = f"{self.tmp}/b.tar"
        self.backup_body = drbackup.backup(
            self.src, "alice", "S1", self.pack
        )
        hd = make_harness(self.dst)
        hd.service.create_wallet("alice", 2)
        hd.service.put_policy("alice", 2, 99)
        self.manifest, self.files = drbackup._read_snapshot(self.pack)

    def _snapshot_tree(self):
        out = {}
        for dp, _, fns in os.walk(self.dst):
            for fn in fns:
                p = os.path.join(dp, fn)
                rel = os.path.relpath(p, self.dst)
                if rel.split(os.sep)[0] in (
                    "restore-txn", "restore-records", "locks"
                ):
                    continue
                out[rel] = hashlib.sha256(open(p, "rb").read()).hexdigest()
        return out

    def test_crash_before_committed_rolls_back_on_startup(self):
        before = self._snapshot_tree()
        txn = drbackup._txn_dir(self.dst, "alice", "S1")
        os.makedirs(txn, exist_ok=True)
        drbackup._commit_restore(
            self.dst, "alice", "S1", self.manifest, self.files
        )
        self.assertTrue(os.path.exists(os.path.join(txn, "prepared.json")))
        self.assertFalse(os.path.exists(os.path.join(txn, "committed.json")))
        # 新进程构造服务即做启动恢复
        WalletService(WalletStore(self.dst))
        self.assertEqual(self._snapshot_tree(), before)
        self.assertFalse(os.path.exists(
            os.path.join(self.dst, "restore-txn")))
        self.assertFalse(os.path.exists(
            os.path.join(self.dst, "restore-records")))
        self.assertEqual(
            WalletStore(self.dst).get_policy("alice")["required_approvals"], 2
        )

    def test_crash_after_committed_rolls_forward_on_startup(self):
        txn = drbackup._txn_dir(self.dst, "alice", "S1")
        os.makedirs(txn, exist_ok=True)
        drbackup._commit_restore(
            self.dst, "alice", "S1", self.manifest, self.files
        )
        mhash = self.backup_body["manifest"]["manifest_sha256"]
        # committed 标记携带与 manifest 同形的完整 files 项
        drbackup._atomic_write_json(os.path.join(txn, "committed.json"), {
            "wallet_id": "alice", "snapshot_id": "S1",
            "manifest_sha256": mhash,
            "files": list(self.manifest["files"]),
        })
        WalletService(WalletStore(self.dst))  # 启动前滚
        records = drbackup._read_restore_records(self.dst, "alice")
        self.assertEqual(
            records["snapshots"]["S1"]["manifest_sha256"], mhash
        )
        self.assertFalse(os.path.exists(
            os.path.join(self.dst, "restore-txn")))
        # 此后重放为 200
        status, _ = drbackup.restore(self.dst, "alice", self.pack)
        self.assertEqual(status, 200)

    def test_heal_path_converges_pending_restore(self):
        # 不触发构造期启动恢复（recover=False），改由持锁自愈收敛
        txn = drbackup._txn_dir(self.dst, "alice", "S1")
        os.makedirs(txn, exist_ok=True)
        drbackup._commit_restore(
            self.dst, "alice", "S1", self.manifest, self.files
        )
        svc = WalletService(WalletStore(self.dst), recover=False)
        # 任意持锁读访问触发自愈 -> 回滚
        svc.get_wallet("alice")
        self.assertFalse(os.path.exists(
            os.path.join(self.dst, "restore-txn")))
        self.assertEqual(
            WalletStore(self.dst).get_policy("alice")["required_approvals"], 2
        )

    def test_no_half_state_visible_during_normal_restore(self):
        # 正常恢复成功后不存在任何 restore-txn 残留
        drbackup.restore(self.dst, "alice", self.pack)
        self.assertFalse(os.path.exists(
            os.path.join(self.dst, "restore-txn")))
        self.assertTrue(os.path.isfile(
            os.path.join(self.dst, "restore-records/alice.json")))


class BackupRestoreCliTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.data = f"{self.tmp}/data"
        self.out = f"{self.tmp}/b.tar"
        h = make_harness(self.data)
        h.service.create_wallet("alice", 2)

    def _cli(self, *argv):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = cli_main(list(argv))
        return code, out.getvalue().strip(), err.getvalue().strip()

    def test_cli_backup_restore_stdout_stderr_exit(self):
        code, out, err = self._cli(
            "backup", "--data-dir", self.data, "--wallet-id", "alice",
            "--snapshot-id", "S1", "--output", self.out)
        self.assertEqual(code, 0)
        self.assertEqual(err, "")
        body = json.loads(out)
        self.assertEqual(body["status"], 201)
        self.assertEqual(body["snapshot_id"], "S1")

        dst = f"{self.tmp}/dst"
        code, out, err = self._cli(
            "restore", "--data-dir", dst, "--wallet-id", "alice",
            "--input", self.out)
        self.assertEqual(code, 0)
        self.assertEqual(err, "")
        self.assertEqual(json.loads(out)["status"], 201)

        code, out, err = self._cli(
            "restore", "--data-dir", dst, "--wallet-id", "alice",
            "--input", self.out)
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(out)["status"], 200)

    def test_cli_backup_bad_snapshot_id_exit1_stderr_json(self):
        code, out, err = self._cli(
            "backup", "--data-dir", self.data, "--wallet-id", "alice",
            "--snapshot-id", "bad id", "--output", self.out)
        self.assertEqual(code, 1)
        self.assertEqual(out, "")
        self.assertEqual(len(err.splitlines()), 1)
        self.assertIn("error", json.loads(err))

    def test_cli_restore_corrupt_exit1(self):
        with open(f"{self.tmp}/bad.tar", "wb") as f:
            f.write(b"nope")
        code, out, err = self._cli(
            "restore", "--data-dir", f"{self.tmp}/dst",
            "--wallet-id", "alice", "--input", f"{self.tmp}/bad.tar")
        self.assertEqual(code, 1)
        self.assertEqual(out, "")
        self.assertEqual(len(err.splitlines()), 1)
        self.assertIn("error", json.loads(err))


class BackupOutputBoundaryTest(unittest.TestCase):
    """--output 绝不能落入 data-dir：否则成功写入会用快照覆盖在线状态。"""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.data = os.path.join(self.tmp, "data")
        self.h = make_harness(self.data)
        self.h.service.create_wallet("alice", 2)
        self.h.service.put_policy("alice", 1, 3600)
        self.wallet_file = os.path.join(self.data, "wallets", "alice.json")
        with open(self.wallet_file, "rb") as f:
            self.before = f.read()
        self.existing = os.path.join(self.tmp, "existing.tar")
        drbackup.backup(self.data, "alice", "S0", self.existing)
        with open(self.existing, "rb") as f:
            self.existing_bytes = f.read()

    def _assert_refused_400(self, output):
        with self.assertRaises(drbackup.BackupError) as cm:
            drbackup.backup(self.data, "alice", "S1", output)
        self.assertEqual(cm.exception.status, 400)
        # 钱包在线文件与既有快照都不得被改动
        with open(self.wallet_file, "rb") as f:
            self.assertEqual(f.read(), self.before)
        with open(self.existing, "rb") as f:
            self.assertEqual(f.read(), self.existing_bytes)

    def test_refuses_business_file(self):
        self._assert_refused_400(self.wallet_file)
        self._assert_refused_400(
            os.path.join(self.data, "policies", "alice.json"))

    def test_refuses_share_and_staging_files(self):
        self._assert_refused_400(
            os.path.join(self.data, "shares", "alice", "share-1.json"))
        # data-dir 内尚不存在的路径同样拒绝（覆盖只是风险之一）
        self._assert_refused_400(
            os.path.join(self.data, "shares", "alice", "new.tar"))

    def test_refuses_nonexistent_and_temp_paths_inside(self):
        self._assert_refused_400(os.path.join(self.data, "snapshot.tar"))
        self._assert_refused_400(
            os.path.join(self.data, "wallets", ".snapshot-x.tmp"))
        self._assert_refused_400(self.data)

    def test_refuses_internal_symlink_pointing_outside(self):
        link = os.path.join(self.data, "audit", "evil.tar")
        os.makedirs(os.path.dirname(link), exist_ok=True)
        os.symlink(os.path.join(self.tmp, "outside.tar"), link)
        self._assert_refused_400(link)

    def test_refuses_external_symlink_pointing_inside(self):
        out_dir = os.path.join(self.tmp, "out")
        os.makedirs(out_dir, exist_ok=True)
        link = os.path.join(out_dir, "link.tar")
        os.symlink(self.wallet_file, link)
        self._assert_refused_400(link)

    def test_refuses_path_traversal_into_datadir(self):
        self._assert_refused_400(
            os.path.join(self.data, "shares", "..", "wallets", "alice.json"))

    def test_external_output_still_writes_atomically(self):
        out = os.path.join(self.tmp, "ok.tar")
        body = drbackup.backup(self.data, "alice", "S1", out)
        self.assertEqual(body["status"], 201)
        # 完整可读 tar，无半包/残留临时文件
        manifest, files = _read_pack(out)
        self.assertEqual(manifest["snapshot_id"], "S1")
        self.assertIn("wallets/alice.json", files)
        leftovers = [
            n for n in os.listdir(os.path.dirname(out))
            if n.startswith(".snapshot-")
        ]
        self.assertEqual(leftovers, [])
        # 在线钱包未被触碰
        with open(self.wallet_file, "rb") as f:
            self.assertEqual(f.read(), self.before)


class BackupRestoreLinearizationTest(unittest.TestCase):
    """同一钱包并发 backup/restore 必须经其事务锁线性化，且快照只来自
    锁内自愈完成的一致闭集；其他钱包不受影响。"""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.src = os.path.join(self.tmp, "src")
        self.dst = os.path.join(self.tmp, "dst")
        hs = make_harness(self.src)
        hs.service.create_wallet("alice", 2)
        hs.service.put_policy("alice", 1, 3600)
        self.pack = os.path.join(self.tmp, "b.tar")
        drbackup.backup(self.src, "alice", "S1", self.pack)
        make_harness(self.dst).service.create_wallet("alice", 2)
        # 另一个钱包，验证其锁/文件不被波及
        make_harness(self.dst).service.create_wallet("bob", 2)

    def test_concurrent_backups_all_complete_and_valid(self):
        import threading

        errors = []
        barrier = threading.Barrier(6)

        def worker(i):
            out = os.path.join(self.tmp, f"c{i}.tar")
            try:
                barrier.wait()
                body = drbackup.backup(self.src, "alice", f"SNAP-{i}", out)
                if body["status"] != 201:
                    errors.append(f"bad status {body['status']}")
                manifest, files = _read_pack(out)
                if manifest["wallet_id"] != "alice":
                    errors.append("bad wallet")
                if "wallets/alice.json" not in files:
                    errors.append("missing wallet member")
            except Exception as exc:  # noqa: BLE001
                errors.append(repr(exc))

        threads = [threading.Thread(target=worker, args=(i,))
                   for i in range(6)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=10)
        self.assertEqual(errors, [])

    def test_concurrent_restore_same_snapshot_one_201_rest_200(self):
        import threading

        results = []
        lock = threading.Lock()
        barrier = threading.Barrier(6)

        def worker():
            try:
                barrier.wait()
                status, body = drbackup.restore(self.dst, "alice", self.pack)
                with lock:
                    results.append((status, body))
            except Exception as exc:  # noqa: BLE001
                with lock:
                    results.append(exc)

        threads = [threading.Thread(target=worker) for _ in range(6)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=15)
        statuses = sorted(r[0] for r in results if isinstance(r, tuple))
        self.assertEqual(len(results), 6)
        self.assertEqual(statuses.count(201), 1)
        self.assertEqual(statuses.count(200), 5)
        # 所有返回体除 status 外逐字段相同（manifest/snapshot/哈希同体）
        def payload(body):
            return {k: v for k, v in body.items() if k != "status"}

        first_payload = payload(results[0][1])
        for _, body in results:
            self.assertEqual(payload(body), first_payload)
        # 多个 200 之间连 status 也完全一致
        two_hundred = [body for status, body in results if status == 200]
        self.assertTrue(all(body == two_hundred[0] for body in two_hundred))
        # 恢复记录只登记一次
        records = drbackup._read_restore_records(self.dst, "alice")
        self.assertEqual(
            list(records["snapshots"].keys()), ["S1"])
        self.assertFalse(
            os.path.exists(os.path.join(self.dst, "restore-txn")))
        # 其他钱包不受影响
        self.assertIsNotNone(
            WalletStore(self.dst).get_wallet("bob"))


if __name__ == "__main__":
    unittest.main()
