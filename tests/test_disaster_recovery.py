"""兼容灾备（backup/restore）测试。

覆盖：
- backup：manifest v1 形状与 S 绑定、白名单打包、坏标识/钱包缺失、
  符号链接/临时/额外文件拒绝、输出不得落入 data-dir；
- restore：首次 201、逐文件一致、余额/version/幂等签名/会话/轮换连续、
  幂等 200 同体、同 S 异内容 409、损坏/篡改/不可对账 503、失败不写、
  覆盖恢复、多钱包隔离、审计不新增、响应不含私钥；
- 崩溃恢复：commit 标记前滚/回滚，常驻服务持锁自愈；
- CLI：stdout 单行 JSON 含 status，失败 stderr 单行 JSON 退出 1。
"""

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
from threshold_wallet import backup as dr
from threshold_wallet.backup import (
    BackupError,
    COMMIT_MARKER_NAME,
    create_backup,
    manifest_hash,
    read_backup_archive,
    recover_interrupted_restores,
    restore_backup,
    _canonical_json,
    _capture_live,
    _materialize_staging,
    _txn_dir,
)
from threshold_wallet.cli import main


def _tar_members(path):
    out = {}
    with tarfile.open(path) as t:
        for info in t:
            f = t.extractfile(info)
            out[info.name] = f.read() if f is not None else b""
    return out


def _repack(path, mutate):
    members = _tar_members(path)
    mutate(members)
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as t:
        for name, data in members.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            info.mode = 0o600
            t.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def _set_member(members, name, obj):
    """修改一个 JSON 成员并同步 manifest 的 bytes/sha256。"""
    data = _canonical_json(obj)
    members[name] = data
    manifest = json.loads(members["manifest.json"])
    for entry in manifest["files"]:
        if entry["path"] == name:
            entry["bytes"] = len(data)
            entry["sha256"] = hashlib.sha256(data).hexdigest()
    members["manifest.json"] = json.dumps(manifest).encode()


class BackupTest(unittest.TestCase):
    def setUp(self):
        self.src = tempfile.mkdtemp()
        self.h = make_harness(self.src)
        self.h.service.create_wallet("alice", 2)
        self.out = tempfile.mktemp(prefix="snap-", suffix=".tar")
        self.priv = self.h.share_private_hex("alice", "share-1")

    def test_manifest_v1_shape_and_whitelist(self):
        res = create_backup(self.src, "alice", "snap-1", self.out)
        manifest = res["manifest"]
        self.assertEqual(manifest["version"], 1)
        self.assertEqual(manifest["wallet_id"], "alice")
        self.assertEqual(manifest["snapshot_id"], "snap-1")
        paths = [f["path"] for f in manifest["files"]]
        self.assertEqual(
            set(paths),
            {
                "wallets/alice.json",
                "shares/alice/share-1.json",
                "shares/alice/share-2.json",
            },
        )
        for entry in manifest["files"]:
            self.assertRegex(entry["sha256"], r"^[0-9a-f]{64}$")
            self.assertGreaterEqual(entry["bytes"], 0)
        # tar 首成员是 manifest.json
        names = tarfile.open(self.out).getnames()
        self.assertEqual(names[0], "manifest.json")
        # 锁文件不入备份
        self.assertFalse(any("locks/" in n for n in names))

    def test_snapshot_id_bound_to_manifest(self):
        res1 = create_backup(self.src, "alice", "snap-a", self.out)
        out2 = tempfile.mktemp(suffix=".tar")
        res2 = create_backup(self.src, "alice", "snap-b", out2)
        # 同一钱包内容、不同 S -> manifest 哈希不同（S 绑定 manifest）
        self.assertNotEqual(
            res1["manifest_sha256"], res2["manifest_sha256"]
        )
        self.assertEqual(
            res1["manifest_sha256"], manifest_hash(res1["manifest"])
        )

    def test_bad_snapshot_id(self):
        for bad in ("", "a/b", "..", "s.id", "x" * 129):
            with self.assertRaises(BackupError) as ctx:
                create_backup(self.src, "alice", bad, self.out)
            self.assertEqual(ctx.exception.status, 400)

    def test_wallet_missing(self):
        with self.assertRaises(BackupError) as ctx:
            create_backup(self.src, "ghost", "s1", self.out)
        self.assertEqual(ctx.exception.status, 404)

    def test_output_inside_data_dir_rejected(self):
        with self.assertRaises(BackupError) as ctx:
            create_backup(
                self.src,
                "alice",
                "s1",
                os.path.join(self.src, "wallets", "x.tar"),
            )
        self.assertEqual(ctx.exception.status, 400)

    def test_temp_and_extra_files_rejected(self):
        # 原子写临时残留
        with open(
            os.path.join(self.src, "shares", "alice", ".tmp-x.json"), "w"
        ) as f:
            f.write("{}")
        with self.assertRaises(BackupError) as ctx:
            create_backup(self.src, "alice", "s1", self.out)
        self.assertEqual(ctx.exception.status, 503)

    def test_symlink_rejected(self):
        os.symlink(
            "share-1.json",
            os.path.join(self.src, "shares", "alice", "evil.json"),
        )
        with self.assertRaises(BackupError) as ctx:
            create_backup(self.src, "alice", "s1", self.out)
        self.assertEqual(ctx.exception.status, 503)

    def test_extra_third_share_rejected(self):
        with open(
            os.path.join(self.src, "shares", "alice", "rogue-1.json"), "w"
        ) as f:
            json.dump(
                {
                    "share_id": "rogue-1",
                    "public_key": "00" * 32,
                    "private_key": "00" * 32,
                },
                f,
            )
        with self.assertRaises(BackupError) as ctx:
            create_backup(self.src, "alice", "s1", self.out)
        self.assertEqual(ctx.exception.status, 503)

    def test_manifest_and_response_contain_no_private_key(self):
        res = create_backup(self.src, "alice", "s1", self.out)
        blob = json.dumps(res["manifest"])
        self.assertNotIn("private_key", blob)
        self.assertNotIn(self.priv, blob)

    def test_backup_after_rotation_and_business_data(self):
        self.h.service.create_asset_operation("alice", "op-1", "BTC", 10)
        self.h.service.commit_asset_operation("alice", "op-1")
        self.h.service.create_share_rotation("alice", "rot-1")
        self.h.service.create_sign_session("alice", "ss", "hi", 600)
        res = create_backup(self.src, "alice", "s1", self.out)
        roots = {f["path"].split("/")[0] for f in res["manifest"]["files"]}
        self.assertIn("assets", roots)
        self.assertIn("audit", roots)
        self.assertIn("sign-sessions", roots)
        self.assertIn("rotation-staging", roots)


class RestoreHappyPathTest(unittest.TestCase):
    def setUp(self):
        self.src = tempfile.mkdtemp()
        self.h = make_harness(self.src)
        self.h.service.create_wallet("alice", 2)
        self.h.service.put_policy("alice", 1, 3600)
        self.h.service.create_sign_request("alice", "r1", "pay-100")
        self.h.service.approve("alice", "r1", "ops-1", None)
        self.sigs = self.h.two_signatures("alice", "r1", "pay-100")
        self.h.service.sign("alice", "r1", "pay-100", self.sigs)
        self.h.service.create_asset_operation("alice", "op-1", "BTC", 10)
        self.h.service.commit_asset_operation("alice", "op-1")
        self.h.service.create_sign_session("alice", "ss", "hello", 600)
        self.snap = tempfile.mktemp(suffix=".tar")
        create_backup(self.src, "alice", "snap-1", self.snap)

    def test_restore_is_byte_identical_and_serviceable(self):
        dst = tempfile.mkdtemp()
        status, body = restore_backup(dst, "alice", self.snap)
        self.assertEqual(status, 201)
        self.assertEqual(body["snapshot_id"], "snap-1")

        def relmap(d):
            out = {}
            for root, _, files in os.walk(d):
                for name in files:
                    p = os.path.join(root, name)
                    rel = os.path.relpath(p, d)
                    if rel.split(os.sep)[0] in (
                        "restore-txn",
                        "restore-records",
                    ):
                        continue
                    with open(p, "rb") as f:
                        out[rel] = f.read()
            return out

        a, b = relmap(self.src), relmap(dst)
        self.assertEqual(a, b)

        h2 = make_harness(dst)
        self.assertEqual(
            h2.service.get_asset("alice", "BTC"),
            {"asset_id": "BTC", "balance": 10, "version": 1},
        )
        # 幂等签名重放（历史签名连续）
        status, _ = h2.service.sign("alice", "r1", "pay-100", self.sigs)
        self.assertEqual(status, 200)
        self.assertEqual(
            h2.service.get_sign_session("alice", "ss")["state"],
            "collecting",
        )

    def test_restore_adds_no_audit_events(self):
        dst = tempfile.mkdtemp()
        restore_backup(dst, "alice", self.snap)
        src_events = json.load(
            open(os.path.join(self.src, "audit", "alice.json"))
        )["events"]
        dst_events = json.load(
            open(os.path.join(dst, "audit", "alice.json"))
        )["events"]
        self.assertEqual(src_events, dst_events)

    def test_idempotent_same_snapshot_200_same_body(self):
        dst = tempfile.mkdtemp()
        status1, body1 = restore_backup(dst, "alice", self.snap)
        status2, body2 = restore_backup(dst, "alice", self.snap)
        self.assertEqual(status1, 201)
        self.assertEqual(status2, 200)
        self.assertEqual(body1["manifest"], body2["manifest"])
        self.assertEqual(
            body1["manifest_sha256"], body2["manifest_sha256"]
        )

    def test_same_snapshot_id_different_content_conflicts(self):
        dst = tempfile.mkdtemp()
        restore_backup(dst, "alice", self.snap)
        # 源钱包继续变化后用同一 snapshot_id 重新备份
        self.h.service.create_asset_operation("alice", "op-2", "BTC", 5)
        self.h.service.commit_asset_operation("alice", "op-2")
        snap2 = tempfile.mktemp(suffix=".tar")
        create_backup(self.src, "alice", "snap-1", snap2)
        with self.assertRaises(BackupError) as ctx:
            restore_backup(dst, "alice", snap2)
        self.assertEqual(ctx.exception.status, 409)

    def test_overwrite_restores_replaces_old_wallet(self):
        dst = tempfile.mkdtemp()
        hd = make_harness(dst)
        hd.service.create_wallet("alice", 2)
        hd.service.create_asset_operation("alice", "x", "ETH", 99)
        hd.service.commit_asset_operation("alice", "x")
        status, _ = restore_backup(dst, "alice", self.snap)
        self.assertEqual(status, 201)
        h2 = make_harness(dst)
        with self.assertRaises(Exception) as ctx:
            h2.service.get_asset("alice", "ETH")
        self.assertEqual(ctx.exception.status, 404)
        self.assertEqual(
            h2.service.get_asset("alice", "BTC")["balance"], 10
        )

    def test_other_wallet_is_untouched(self):
        dst = tempfile.mkdtemp()
        hd = make_harness(dst)
        hd.service.create_wallet("bob", 2)
        before = open(os.path.join(dst, "wallets", "bob.json"), "rb").read()
        restore_backup(dst, "alice", self.snap)
        after = open(os.path.join(dst, "wallets", "bob.json"), "rb").read()
        self.assertEqual(before, after)


class RestoreRejectionTest(unittest.TestCase):
    def setUp(self):
        self.src = tempfile.mkdtemp()
        self.h = make_harness(self.src)
        self.h.service.create_wallet("alice", 2)
        self.sigs = self.h.two_signatures("alice", "r1", "m")
        self.h.service.sign("alice", "r1", "m", self.sigs)
        self.h.service.create_asset_operation("alice", "op-1", "BTC", 10)
        self.h.service.commit_asset_operation("alice", "op-1")
        self.snap = tempfile.mktemp(suffix=".tar")
        create_backup(self.src, "alice", "s1", self.snap)

    def _restore_mutated(self, mutate):
        blob = _repack(self.snap, mutate)
        path = tempfile.mktemp(suffix=".tar")
        with open(path, "wb") as f:
            f.write(blob)
        with self.assertRaises(BackupError) as ctx:
            restore_backup(tempfile.mkdtemp(), "alice", path)
        return ctx.exception

    def test_corrupt_archive_503_and_writes_nothing(self):
        dst = tempfile.mkdtemp()
        bad = tempfile.mktemp(suffix=".tar")
        with open(self.snap, "rb") as f:
            raw = f.read()
        with open(bad, "wb") as f:
            f.write(raw[: len(raw) // 2])
        with self.assertRaises(BackupError) as ctx:
            restore_backup(dst, "alice", bad)
        self.assertEqual(ctx.exception.status, 503)
        # data-dir 内不得留下任何业务文件或工作区
        leftovers = [
            os.path.join(r, f)
            for r, _, fs in os.walk(dst)
            for f in fs
        ]
        self.assertEqual(leftovers, [])

    def test_identity_mismatch_503(self):
        def mutate(members):
            manifest = json.loads(members["manifest.json"])
            manifest["wallet_id"] = "bob"
            members["manifest.json"] = json.dumps(manifest).encode()

        exc = self._restore_mutated(mutate)
        self.assertEqual(exc.status, 503)

    def test_private_key_tamper_hash_mismatch_503(self):
        def mutate(members):
            key = "shares/alice/share-1.json"
            rec = json.loads(members[key])
            rec["private_key"] = "11" * 32
            members[key] = (json.dumps(rec) + "\n").encode()

        self.assertEqual(self._restore_mutated(mutate).status, 503)

    def test_private_key_tamper_with_hashes_503(self):
        def mutate(members):
            key = "shares/alice/share-1.json"
            rec = json.loads(members[key])
            rec["private_key"] = "11" * 32
            _set_member(members, key, rec)

        self.assertEqual(self._restore_mutated(mutate).status, 503)

    def test_ledger_tamper_503(self):
        def mutate(members):
            key = "assets/alice.json"
            ledger = json.loads(members[key])
            ledger["assets"]["BTC"]["balance"] = 999
            _set_member(members, key, ledger)

        self.assertEqual(self._restore_mutated(mutate).status, 503)

    def test_audit_seq_tamper_503(self):
        def mutate(members):
            key = "audit/alice.json"
            log = json.loads(members[key])
            log["events"] = log["events"][1:]
            _set_member(members, key, log)

        self.assertEqual(self._restore_mutated(mutate).status, 503)

    def test_historical_signature_tamper_503(self):
        def mutate(members):
            key = "signatures/alice.json"
            ledger = json.loads(members[key])
            agg = bytearray(bytes.fromhex(ledger["r1"]["signature"]))
            agg[0] ^= 0xFF
            ledger["r1"]["signature"] = agg.hex()
            _set_member(members, key, ledger)

        self.assertEqual(self._restore_mutated(mutate).status, 503)

    def test_extra_member_503(self):
        def mutate(members):
            members["locks/alice.lock"] = b"{}"

        self.assertEqual(self._restore_mutated(mutate).status, 503)

    def test_missing_wallet_metadata_503(self):
        def mutate(members):
            del members["wallets/alice.json"]
            manifest = json.loads(members["manifest.json"])
            manifest["files"] = [
                f
                for f in manifest["files"]
                if f["path"] != "wallets/alice.json"
            ]
            members["manifest.json"] = json.dumps(manifest).encode()

        self.assertEqual(self._restore_mutated(mutate).status, 503)


class RotationAndSessionRestoreTest(unittest.TestCase):
    def test_prepared_rotation_and_session_restore(self):
        src = tempfile.mkdtemp()
        h = make_harness(src)
        h.service.create_wallet("alice", 2)
        h.service.create_share_rotation("alice", "rot-1")
        h.service.create_sign_session("alice", "ss", "hi", 600)
        s1 = h.share_signature("alice", "share-1", "ss", "hi")
        h.service.submit_sign_session_share("alice", "ss", "share-1", s1)
        snap = tempfile.mktemp(suffix=".tar")
        create_backup(src, "alice", "sA", snap)

        dst = tempfile.mkdtemp()
        status, _ = restore_backup(dst, "alice", snap)
        self.assertEqual(status, 201)
        h2 = make_harness(dst)
        view = h2.service.get_sign_session("alice", "ss")
        self.assertEqual(view["state"], "collecting")
        self.assertEqual(view["missing_shares"], ["share-2"])
        status, rotation = h2.service.activate_share_rotation("alice", "rot-1")
        self.assertEqual(status, 201)
        self.assertEqual(rotation["state"], "active")

    def test_activated_rotation_signed_session_replay(self):
        src = tempfile.mkdtemp()
        h = make_harness(src)
        h.service.create_wallet("alice", 2)
        sigs = h.two_signatures("alice", "old-req", "m0")
        h.service.sign("alice", "old-req", "m0", sigs)
        h.service.create_share_rotation("alice", "rA")
        h.service.activate_share_rotation("alice", "rA")
        h.service.create_sign_session("alice", "ss", "hello", 600)
        a = h.share_signature("alice", "rA-share-1", "ss", "hello")
        b = h.share_signature("alice", "rA-share-2", "ss", "hello")
        h.service.submit_sign_session_share("alice", "ss", "rA-share-1", a)
        status, view = h.service.submit_sign_session_share(
            "alice", "ss", "rA-share-2", b
        )
        self.assertEqual(view["state"], "signed")
        snap = tempfile.mktemp(suffix=".tar")
        create_backup(src, "alice", "sB", snap)

        dst = tempfile.mkdtemp()
        restore_backup(dst, "alice", snap)
        h2 = make_harness(dst)
        self.assertEqual(
            h2.service.get_sign_session("alice", "ss")["state"], "signed"
        )
        # 轮换前的历史签名仍可幂等重放（公钥链连续）
        status, _ = h2.service.sign("alice", "old-req", "m0", sigs)
        self.assertEqual(status, 200)


class CrashRecoveryTest(unittest.TestCase):
    def _make_interrupted(self, dst, snap, committed):
        manifest, members = read_backup_archive(snap, "alice")
        snapshot_id = manifest["snapshot_id"]
        txn = _txn_dir(dst, "alice", snapshot_id)
        os.makedirs(txn, exist_ok=True)
        _materialize_staging(os.path.join(txn, "staging"), members)
        with open(os.path.join(txn, "manifest.json"), "wb") as f:
            f.write(_canonical_json(manifest))
        _capture_live(os.path.join(txn, "backup"), dst, "alice")
        # 模拟换入已发生
        from threshold_wallet.backup import _apply_snapshot

        _apply_snapshot(dst, "alice", members)
        if committed:
            marker = {
                "wallet_id": "alice",
                "snapshot_id": snapshot_id,
                "manifest_sha256": manifest_hash(manifest),
                "committed_at": "2026-01-01T00:00:00Z",
            }
            with open(os.path.join(txn, COMMIT_MARKER_NAME), "wb") as f:
                f.write(_canonical_json(marker))
        return txn, snapshot_id

    def test_roll_forward_when_committed(self):
        src = tempfile.mkdtemp()
        h = make_harness(src)
        h.service.create_wallet("alice", 2)
        h.service.create_sign_session("alice", "ss", "hello", 600)
        snap = tempfile.mktemp(suffix=".tar")
        create_backup(src, "alice", "sC", snap)

        dst = tempfile.mkdtemp()
        txn, snapshot_id = self._make_interrupted(dst, snap, True)
        service = make_harness(dst).service
        with service._wallet_lock("alice"):
            recover_interrupted_restores(dst, "alice")
        self.assertFalse(os.path.exists(txn))
        records = json.load(
            open(os.path.join(dst, "restore-records", "alice.json"))
        )
        self.assertIn(snapshot_id, records["snapshots"])
        self.assertEqual(
            make_harness(dst).service.get_sign_session("alice", "ss")[
                "state"
            ],
            "collecting",
        )

    def test_roll_back_when_not_committed(self):
        src = tempfile.mkdtemp()
        h = make_harness(src)
        h.service.create_wallet("alice", 2)
        h.service.create_sign_session("alice", "ss", "hello", 600)
        snap = tempfile.mktemp(suffix=".tar")
        create_backup(src, "alice", "sD", snap)

        # live 是另一个钱包状态（有 ETH 账本），无 restore-records
        dst = tempfile.mkdtemp()
        hd = make_harness(dst)
        hd.service.create_wallet("alice", 2)
        hd.service.create_asset_operation("alice", "x", "ETH", 7)
        hd.service.commit_asset_operation("alice", "x")
        wallet_before = open(
            os.path.join(dst, "wallets", "alice.json"), "rb"
        ).read()

        txn, snapshot_id = self._make_interrupted(dst, snap, False)
        service = make_harness(dst).service
        with service._wallet_lock("alice"):
            recover_interrupted_restores(dst, "alice")
        self.assertFalse(os.path.exists(txn))
        self.assertEqual(
            open(os.path.join(dst, "wallets", "alice.json"), "rb").read(),
            wallet_before,
        )
        self.assertFalse(
            os.path.exists(os.path.join(dst, "sign-sessions", "alice.json"))
        )
        self.assertFalse(
            os.path.exists(os.path.join(dst, "restore-records", "alice.json"))
        )
        self.assertEqual(
            make_harness(dst).service.get_asset("alice", "ETH")["balance"], 7
        )

    def test_resident_service_self_heals_on_request(self):
        src = tempfile.mkdtemp()
        h = make_harness(src)
        h.service.create_wallet("alice", 2)
        snap = tempfile.mktemp(suffix=".tar")
        create_backup(src, "alice", "sE", snap)

        dst = tempfile.mkdtemp()
        harness = make_harness(dst)
        txn, _ = self._make_interrupted(dst, snap, True)
        # 不调用恢复入口，直接走常驻请求路径（持锁自愈）
        wallet = harness.service.get_wallet("alice")
        self.assertEqual(wallet["wallet_id"], "alice")
        self.assertFalse(os.path.exists(txn))


class CliBackupRestoreTest(unittest.TestCase):
    def run_cli(self, *argv):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = main(list(argv))
        return code, out.getvalue().strip(), err.getvalue().strip()

    def test_cli_backup_restore_flow(self):
        src = tempfile.mkdtemp()
        h = make_harness(src)
        h.service.create_wallet("alice", 2)
        out = tempfile.mktemp(suffix=".tar")
        code, stdout, stderr = self.run_cli(
            "backup",
            "--data-dir", src,
            "--wallet-id", "alice",
            "--snapshot-id", "s1",
            "--output", out,
        )
        self.assertEqual(code, 0, stderr)
        body = json.loads(stdout)
        self.assertEqual(body["status"], 201)
        self.assertEqual(body["snapshot_id"], "s1")
        self.assertEqual(body["manifest"]["version"], 1)
        self.assertNotIn("private_key", stdout)

        dst = tempfile.mkdtemp()
        code, stdout, _ = self.run_cli(
            "restore",
            "--data-dir", dst,
            "--wallet-id", "alice",
            "--input", out,
        )
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(stdout)["status"], 201)

        code, stdout, _ = self.run_cli(
            "restore",
            "--data-dir", dst,
            "--wallet-id", "alice",
            "--input", out,
        )
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(stdout)["status"], 200)

    def test_cli_backup_bad_snapshot_id(self):
        src = tempfile.mkdtemp()
        make_harness(src).service.create_wallet("alice", 2)
        code, stdout, stderr = self.run_cli(
            "backup",
            "--data-dir", src,
            "--wallet-id", "alice",
            "--snapshot-id", "bad/id",
            "--output", tempfile.mktemp(suffix=".tar"),
        )
        self.assertEqual(code, 1)
        self.assertEqual(stdout, "")
        self.assertEqual(len(stderr.splitlines()), 1)
        self.assertIn("error", json.loads(stderr))

    def test_cli_restore_corrupt_exit_1(self):
        dst = tempfile.mkdtemp()
        bad = tempfile.mktemp(suffix=".tar")
        with open(bad, "wb") as f:
            f.write(b"not a tar")
        code, stdout, stderr = self.run_cli(
            "restore",
            "--data-dir", dst,
            "--wallet-id", "alice",
            "--input", bad,
        )
        self.assertEqual(code, 1)
        self.assertEqual(stdout, "")
        self.assertEqual(len(stderr.splitlines()), 1)
        self.assertIn("error", json.loads(stderr))


if __name__ == "__main__":
    unittest.main()
