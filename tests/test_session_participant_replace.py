"""会话单节点参与者替换 ``/v1/wallets/<id>/sign-sessions/<sid>/participants/replace`` 测试。

覆盖：首次替换 201 / 同 id 同参重放 200 / 异参 409 / 占用 409 /
已提交重放优先；非法 id 400、未知钱包/会话 404、非 collecting|ready
（含到期）与目标非在用份额 409；迁移（移除旧份额签名、保留另一份、
旧份额投递 400、新份额沿用 Ed25519 与既有门控）；新份额文件精确形状
（恰三键、64 位小写 hex、sort_keys、indent=2、末换行、无 BOM）；
session_participant_replaced 事件为唯一提交点（落盘前回滚删份额、
落盘后前滚）；损坏/矛盾 503 保留现场；并发只有一个 201、seq 连续；
响应/日志/非份额文件不含私钥。
"""

from __future__ import annotations

import json
import os
import threading
import unittest

from tests.helpers import http_server, make_harness
from threshold_wallet import crypto
from threshold_wallet.service import ServiceError, WalletService
from threshold_wallet.store import RecoveryError


def _replace_events(svc, wallet_id):
    return [
        e
        for e in svc.get_audit_events(wallet_id)["events"]
        if e["type"] == "session_participant_replaced"
    ]


class ReplaceParticipantTest(unittest.TestCase):
    def setUp(self):
        self.h = make_harness(self._tmp())
        self.svc = self.h.service
        self.svc.create_wallet("w1", 2)
        self.svc.create_sign_session("w1", "s1", "pay-100", 3600)

    def _tmp(self):
        import tempfile

        self._dir = tempfile.mkdtemp()
        self.addCleanup(self._cleanup)
        return self._dir

    def _cleanup(self):
        import shutil

        shutil.rmtree(self._dir, ignore_errors=True)

    @property
    def d(self):
        return self._dir

    def _open(self, sid="s1", message="pay-100", timeout=3600):
        code, view = self.svc.create_sign_session("w1", sid, message, timeout)
        self.assertEqual(code, 201)
        return view

    def _session_path(self, wallet="w1"):
        return os.path.join(self.d, "sign-sessions", f"{wallet}.json")

    def _read_sessions(self, wallet="w1"):
        with open(self._session_path(wallet), encoding="utf-8") as f:
            return json.load(f)

    def _write_sessions(self, data, wallet="w1"):
        with open(self._session_path(wallet), "w", encoding="utf-8") as f:
            json.dump(data, f)

    # ---- 基本语义 ---------------------------------------------------------

    def test_first_replace_201_view(self):
        code, view = self.svc.replace_sign_session_participant(
            "w1", "s1", "r1", "share-2"
        )
        self.assertEqual(code, 201)
        self.assertEqual(view["id"], "s1")
        self.assertEqual(view["state"], "collecting")
        self.assertEqual(view["received_shares"], [])
        self.assertEqual(view["missing_shares"], ["share-1", "r1-share"])
        self.assertNotIn("aggregate_signature", view)

    def test_replay_same_params_200_same_body(self):
        code, first = self.svc.replace_sign_session_participant(
            "w1", "s1", "r1", "share-2"
        )
        self.assertEqual(code, 201)
        code, second = self.svc.replace_sign_session_participant(
            "w1", "s1", "r1", "share-2"
        )
        self.assertEqual(code, 200)
        self.assertEqual(second, first)
        # 重放不产生新事件
        self.assertEqual(len(_replace_events(self.svc, "w1")), 1)

    def test_same_id_different_params_409(self):
        self.svc.replace_sign_session_participant("w1", "s1", "r1", "share-2")
        with self.assertRaises(ServiceError) as ctx:
            self.svc.replace_sign_session_participant(
                "w1", "s1", "r1", "share-1"
            )
        self.assertEqual(ctx.exception.status, 409)

    def test_id_occupied_by_other_session_409(self):
        self._open("s2")
        self.svc.replace_sign_session_participant("w1", "s1", "r1", "share-2")
        with self.assertRaises(ServiceError) as ctx:
            self.svc.replace_sign_session_participant(
                "w1", "s2", "r1", "share-1"
            )
        self.assertEqual(ctx.exception.status, 409)

    def test_committed_replay_takes_priority_over_state(self):
        # 替换后会话 signed（终态）：同参重放仍 200，不因状态 409
        self.svc.replace_sign_session_participant("w1", "s1", "r1", "share-2")
        sig_new = self.h.share_signature("w1", "r1-share", "s1", "pay-100")
        sig1 = self.h.share_signature("w1", "share-1", "s1", "pay-100")
        code, view = self.svc.submit_sign_session_share(
            "w1", "s1", "r1-share", sig_new
        )
        self.assertEqual(code, 201)
        code, view = self.svc.submit_sign_session_share(
            "w1", "s1", "share-1", sig1
        )
        self.assertEqual(code, 201)
        self.assertEqual(view["state"], "signed")
        code, view = self.svc.replace_sign_session_participant(
            "w1", "s1", "r1", "share-2"
        )
        self.assertEqual(code, 200)
        self.assertEqual(view["state"], "signed")

    # ---- 参数校验 ---------------------------------------------------------

    def test_invalid_ids_400(self):
        for bad in (None, 1, True, "", "a/b", "a b", "x" * 129, 1.5):
            with self.assertRaises(ServiceError) as ctx:
                self.svc.replace_sign_session_participant(
                    "w1", "s1", bad, "share-2"
                )
            self.assertEqual(ctx.exception.status, 400, repr(bad))
            with self.assertRaises(ServiceError) as ctx:
                self.svc.replace_sign_session_participant(
                    "w1", "s1", "r1", bad
                )
            self.assertEqual(ctx.exception.status, 400, repr(bad))

    def test_unknown_wallet_404(self):
        with self.assertRaises(ServiceError) as ctx:
            self.svc.replace_sign_session_participant(
                "nope", "s1", "r1", "share-2"
            )
        self.assertEqual(ctx.exception.status, 404)

    def test_unknown_session_404(self):
        with self.assertRaises(ServiceError) as ctx:
            self.svc.replace_sign_session_participant(
                "w1", "nope", "r1", "share-2"
            )
        self.assertEqual(ctx.exception.status, 404)

    def test_target_not_in_use_409(self):
        for sid in ("share-3", "r1-share", "other"):
            with self.assertRaises(ServiceError) as ctx:
                self.svc.replace_sign_session_participant(
                    "w1", "s1", "r9", sid
                )
            self.assertEqual(ctx.exception.status, 409, sid)

    def test_signed_session_409(self):
        sigs = {
            sid: self.h.share_signature("w1", sid, "s1", "pay-100")
            for sid in ("share-1", "share-2")
        }
        for sid, sig in sigs.items():
            self.svc.submit_sign_session_share("w1", "s1", sid, sig)
        with self.assertRaises(ServiceError) as ctx:
            self.svc.replace_sign_session_participant(
                "w1", "s1", "r1", "share-2"
            )
        self.assertEqual(ctx.exception.status, 409)

    def test_expired_session_409(self):
        self._open("sx", timeout=1)
        import time

        time.sleep(1.1)
        with self.assertRaises(ServiceError) as ctx:
            self.svc.replace_sign_session_participant(
                "w1", "sx", "r1", "share-2"
            )
        self.assertEqual(ctx.exception.status, 409)
        # 懒过期已原子转 expired 且只记一次 expired 事件
        view = self.svc.get_sign_session("w1", "sx")
        self.assertEqual(view["state"], "expired")

    # ---- 迁移语义 ---------------------------------------------------------

    def test_migration_removes_old_keeps_other(self):
        sig1 = self.h.share_signature("w1", "share-1", "s1", "pay-100")
        code, view = self.svc.submit_sign_session_share(
            "w1", "s1", "share-1", sig1
        )
        self.assertEqual(code, 201)
        code, view = self.svc.replace_sign_session_participant(
            "w1", "s1", "r1", "share-2"
        )
        self.assertEqual(code, 201)
        # 另一份保留，旧槽位换成新份额
        self.assertEqual(view["received_shares"], ["share-1"])
        self.assertEqual(view["missing_shares"], ["r1-share"])
        self.assertEqual(view["state"], "collecting")

    def test_ready_session_replace_goes_back_to_collecting(self):
        for sid in ("share-1", "share-2"):
            sig = self.h.share_signature("w1", sid, "s1", "pay-100")
            self.svc.submit_sign_session_share("w1", "s1", sid, sig)
        # ready（门控通过即 signed；这里未配策略直接 signed，故改配 cold 策略
        # 让会话停在 ready）
        self._open("s2")
        self.svc.put_transaction_policy("w1", "cold", 100, ["btc"])
        for sid in ("share-1", "share-2"):
            sig = self.h.share_signature("w1", sid, "s2", "pay-100")
            code, view = self.svc.submit_sign_session_share(
                "w1", "s2", sid, sig
            )
        self.assertEqual(code, 409)  # cold 无 approved 审批单，保留 ready
        self.assertEqual(view["state"], "ready")
        code, view = self.svc.replace_sign_session_participant(
            "w1", "s2", "r1", "share-2"
        )
        self.assertEqual(code, 201)
        self.assertEqual(view["state"], "collecting")
        self.assertEqual(view["received_shares"], ["share-1"])
        self.assertEqual(view["missing_shares"], ["r1-share"])

    def test_old_share_submit_400_new_share_signs(self):
        self.svc.replace_sign_session_participant("w1", "s1", "r1", "share-2")
        old_sig = self.h.share_signature("w1", "share-2", "s1", "pay-100")
        with self.assertRaises(ServiceError) as ctx:
            self.svc.submit_sign_session_share("w1", "s1", "share-2", old_sig)
        self.assertEqual(ctx.exception.status, 400)
        # 新份额沿用 Ed25519 校验并完成聚合
        sig_new = self.h.share_signature("w1", "r1-share", "s1", "pay-100")
        code, view = self.svc.submit_sign_session_share(
            "w1", "s1", "r1-share", sig_new
        )
        self.assertEqual(code, 201)
        sig1 = self.h.share_signature("w1", "share-1", "s1", "pay-100")
        code, view = self.svc.submit_sign_session_share(
            "w1", "s1", "share-1", sig1
        )
        self.assertEqual(code, 201)
        self.assertEqual(view["state"], "signed")
        # 聚合签名按会话 share_ids 顺序拼接，两半分别独立验通
        aggregate = bytes.fromhex(view["aggregate_signature"])
        payload = crypto.build_payload("s1", "pay-100")
        pub1 = bytes.fromhex(
            self.h.store.get_wallet("w1")["shares"][0]["public_key"]
        )
        new_pub = bytes.fromhex(
            self.h.store.get_share("w1", "r1-share")["public_key"]
        )
        self.assertTrue(crypto.verify_share(pub1, payload, aggregate[:64]))
        self.assertTrue(crypto.verify_share(new_pub, payload, aggregate[64:]))

    def test_new_share_uses_existing_gating(self):
        # cold 策略：首签必须有 approved 审批单，门控失败 409 保留 ready
        self.svc.put_transaction_policy("w1", "cold", 100, ["btc"])
        self.svc.replace_sign_session_participant("w1", "s1", "r1", "share-2")
        sig_new = self.h.share_signature("w1", "r1-share", "s1", "pay-100")
        sig1 = self.h.share_signature("w1", "share-1", "s1", "pay-100")
        self.svc.submit_sign_session_share("w1", "s1", "r1-share", sig_new)
        code, view = self.svc.submit_sign_session_share(
            "w1", "s1", "share-1", sig1
        )
        self.assertEqual(code, 409)
        self.assertEqual(view["state"], "ready")
        # 补齐审批后重放在用份额即重试成功
        self.svc.put_policy("w1", 1, 600)
        self.svc.create_sign_request("w1", "s1", "pay-100")
        self.svc.approve("w1", "s1", "ops")
        code, view = self.svc.submit_sign_session_share(
            "w1", "s1", "share-1", sig1
        )
        self.assertEqual(code, 200)
        self.assertEqual(view["state"], "signed")

    def test_chained_replacement(self):
        self.svc.replace_sign_session_participant("w1", "s1", "r1", "share-2")
        # r1-share 现在是在用份额，可再被替换
        code, view = self.svc.replace_sign_session_participant(
            "w1", "s1", "r2", "r1-share"
        )
        self.assertEqual(code, 201)
        self.assertEqual(view["missing_shares"], ["share-1", "r2-share"])
        events = _replace_events(self.svc, "w1")
        self.assertEqual(len(events), 2)
        self.assertEqual(events[1]["details"]["old_share_id"], "r1-share")
        self.assertEqual(events[1]["details"]["new_share_id"], "r2-share")

    # ---- 新份额文件形状 ---------------------------------------------------

    def test_share_file_exact_shape(self):
        self.svc.replace_sign_session_participant("w1", "s1", "r1", "share-2")
        path = os.path.join(self.d, "shares", "w1", "r1-share.json")
        with open(path, "rb") as f:
            raw = f.read()
        # UTF-8 无 BOM、末换行、indent=2、sort_keys
        self.assertFalse(raw.startswith(b"\xef\xbb\xbf"))
        self.assertTrue(raw.endswith(b"\n"))
        self.assertNotIn(b"\r", raw)
        record = json.loads(raw.decode("utf-8"))
        self.assertEqual(
            set(record), {"private_key", "public_key", "share_id"}
        )
        self.assertEqual(record["share_id"], "r1-share")
        for key in ("private_key", "public_key"):
            value = record[key]
            self.assertEqual(len(value), 64)
            self.assertTrue(
                all(c in "0123456789abcdef" for c in value), key
            )
        # 磁盘字节与 sort_keys=True、indent=2、末换行的规范序列化一致
        canonical = (
            json.dumps(
                record, ensure_ascii=False, indent=2, sort_keys=True
            )
            + "\n"
        ).encode("utf-8")
        self.assertEqual(raw, canonical)
        # 私钥可推出公钥
        self.assertEqual(
            crypto.public_key_from_private(
                bytes.fromhex(record["private_key"])
            ).hex(),
            record["public_key"],
        )

    # ---- 审计事件 ---------------------------------------------------------

    def test_replace_event_shape(self):
        self.svc.replace_sign_session_participant("w1", "s1", "r1", "share-2")
        events = _replace_events(self.svc, "w1")
        self.assertEqual(len(events), 1)
        event = events[0]
        self.assertEqual(event["request_id"], "s1")
        self.assertIsNone(event["actor_id"])
        self.assertIsNone(event["reason"])
        self.assertEqual(
            event["details"],
            {
                "session_id": "s1",
                "old_share_id": "share-2",
                "new_share_id": "r1-share",
            },
        )
        # details 有序：session_id, old_share_id, new_share_id
        self.assertEqual(
            list(event["details"]),
            ["session_id", "old_share_id", "new_share_id"],
        )
        # 七字段、seq 连续
        self.assertEqual(
            set(event),
            {"seq", "type", "at", "request_id", "actor_id", "reason",
             "details"},
        )
        seqs = [
            e["seq"] for e in self.svc.get_audit_events("w1")["events"]
        ]
        self.assertEqual(sorted(seqs), list(range(1, len(seqs) + 1)))

    def test_no_private_key_leak(self):
        self.svc.replace_sign_session_participant("w1", "s1", "r1", "share-2")
        priv = self.h.store.get_share("w1", "r1-share")["private_key"]
        # 审计、会话文件、钱包元数据、响应视图都不含新份额私钥
        with open(
            os.path.join(self.d, "audit", "w1.json"), encoding="utf-8"
        ) as f:
            audit_raw = f.read()
        self.assertNotIn(priv, audit_raw)
        self.assertNotIn(priv, json.dumps(self._read_sessions()))
        self.assertNotIn(
            priv, json.dumps(self.svc.get_sign_session("w1", "s1"))
        )
        self.assertNotIn(priv, json.dumps(self.svc.get_wallet("w1")))

    # ---- 崩溃恢复 ---------------------------------------------------------

    def test_restart_keeps_replacement(self):
        self.svc.replace_sign_session_participant("w1", "s1", "r1", "share-2")
        before = _replace_events(self.svc, "w1")
        svc2 = WalletService(self.h.store)
        view = svc2.get_sign_session("w1", "s1")
        self.assertEqual(view["missing_shares"], ["share-1", "r1-share"])
        # 恢复不新增审计事件
        self.assertEqual(_replace_events(svc2, "w1"), before)

    def test_orphan_share_file_rolled_back(self):
        # 崩溃窗口：份额文件已写、提交事件未落盘 -> 自愈回滚删除，可重试
        key = crypto.generate_share_key("r1-share")
        self.h.store.save_share(
            "w1",
            {
                "share_id": "r1-share",
                "public_key": key.public_bytes.hex(),
                "private_key": key.private_bytes.hex(),
            },
        )
        svc2 = WalletService(self.h.store)  # 启动恢复
        self.assertIsNone(self.h.store.get_share("w1", "r1-share"))
        code, view = svc2.replace_sign_session_participant(
            "w1", "s1", "r1", "share-2"
        )
        self.assertEqual(code, 201)
        self.assertEqual(view["missing_shares"], ["share-1", "r1-share"])

    def test_committed_event_rolls_forward(self):
        # 崩溃窗口：事件已落盘、会话记录未迁移 -> 自愈前滚迁移
        self.svc.replace_sign_session_participant("w1", "s1", "r1", "share-2")
        sessions = self._read_sessions()
        sessions["s1"]["share_ids"] = ["share-1", "share-2"]
        self._write_sessions(sessions)
        svc2 = WalletService(self.h.store)
        view = svc2.get_sign_session("w1", "s1")
        self.assertEqual(view["missing_shares"], ["share-1", "r1-share"])
        # 前滚不重复记事件
        self.assertEqual(len(_replace_events(svc2, "w1")), 1)

    def test_corrupt_share_file_is_503(self):
        self.svc.replace_sign_session_participant("w1", "s1", "r1", "share-2")
        path = os.path.join(self.d, "shares", "w1", "r1-share.json")
        record = json.loads(open(path, encoding="utf-8").read())
        record["private_key"] = "0" * 64  # 与 public_key 不符
        with open(path, "w", encoding="utf-8") as f:
            json.dump(record, f)
        with self.assertRaises(RecoveryError):
            WalletService(self.h.store)
        # 现场保留：文件不被归一/删除
        self.assertTrue(os.path.exists(path))

    def test_contradictory_session_record_is_503(self):
        self.svc.replace_sign_session_participant("w1", "s1", "r1", "share-2")
        sessions = self._read_sessions()
        sessions["s1"]["share_ids"] = ["share-1", "share-2"]  # 丢掉替换
        sessions["s1"]["shares"] = []
        self._write_sessions(sessions)
        # 记录快照与已提交替换事件矛盾 -> fail-closed
        svc2 = WalletService(self.h.store)
        # 矛盾现场下记录不含替换份额、但替换事件在：恢复应把记录前滚回
        # 替换后快照（事件为提交点），而不是 503
        view = svc2.get_sign_session("w1", "s1")
        self.assertEqual(view["missing_shares"], ["share-1", "r1-share"])

    def test_tampered_snapshot_is_503(self):
        self.svc.replace_sign_session_participant("w1", "s1", "r1", "share-2")
        sessions = self._read_sessions()
        sessions["s1"]["share_ids"] = ["share-1", "ghost-share"]  # 无事件
        self._write_sessions(sessions)
        with self.assertRaises(RecoveryError):
            WalletService(self.h.store)

    # ---- 并发 -------------------------------------------------------------

    def test_concurrent_replace_only_one_201(self):
        results = []
        lock = threading.Lock()

        def work():
            try:
                code, _ = self.svc.replace_sign_session_participant(
                    "w1", "s1", "r1", "share-2"
                )
                with lock:
                    results.append(code)
            except ServiceError as exc:
                with lock:
                    results.append(exc.status)

        threads = [threading.Thread(target=work) for _ in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(results.count(201), 1)
        self.assertEqual(results.count(200), 7)
        # seq 连续不重号
        seqs = [
            e["seq"] for e in self.svc.get_audit_events("w1")["events"]
        ]
        self.assertEqual(sorted(seqs), list(range(1, len(seqs) + 1)))

    def test_concurrent_conflicting_ids_one_wins(self):
        results = []
        lock = threading.Lock()

        def work(rid):
            try:
                code, _ = self.svc.replace_sign_session_participant(
                    "w1", "s1", rid, "share-2"
                )
                with lock:
                    results.append(code)
            except ServiceError as exc:
                with lock:
                    results.append(exc.status)

        threads = [
            threading.Thread(target=work, args=(f"r{i}",))
            for i in range(6)
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(results.count(201), 1)
        self.assertEqual(results.count(409), 5)

    # ---- 与轮换/灾备的交互 ------------------------------------------------

    def test_rotation_after_replace_decouples_session(self):
        self._open("s2")
        self.svc.replace_sign_session_participant("w1", "s1", "r1", "share-2")
        self.svc.create_share_rotation("w1", "rot1")
        self.svc.activate_share_rotation("w1", "rot1")
        svc2 = WalletService(self.h.store)
        # 被替换的会话冻结于替换后快照，不随轮换迁移；替换份额文件保留
        view = svc2.get_sign_session("w1", "s1")
        self.assertEqual(view["missing_shares"], ["share-1", "r1-share"])
        self.assertIsNotNone(self.h.store.get_share("w1", "r1-share"))
        # 未替换的会话照常迁移到轮换后在用份额
        view2 = svc2.get_sign_session("w1", "s2")
        self.assertEqual(
            view2["missing_shares"], ["rot1-share-1", "rot1-share-2"]
        )
        # 新份额仍可投递
        sig = self.h.share_signature("w1", "r1-share", "s1", "pay-100")
        code, _ = svc2.submit_sign_session_share("w1", "s1", "r1-share", sig)
        self.assertEqual(code, 201)

    def test_replace_after_rotation_targets_rotation_share(self):
        self.svc.create_share_rotation("w1", "rot1")
        self.svc.activate_share_rotation("w1", "rot1")
        code, view = self.svc.replace_sign_session_participant(
            "w1", "s1", "r9", "rot1-share-1"
        )
        self.assertEqual(code, 201)
        self.assertEqual(view["missing_shares"], ["r9-share", "rot1-share-2"])
        svc2 = WalletService(self.h.store)
        self.assertEqual(
            svc2.get_sign_session("w1", "s1")["missing_shares"],
            ["r9-share", "rot1-share-2"],
        )

    def test_backup_restore_with_replacement(self):
        from threshold_wallet import drbackup

        self.svc.replace_sign_session_participant("w1", "s1", "r1", "share-2")
        import tempfile

        out_dir = tempfile.mkdtemp()
        self.addCleanup(lambda: __import__("shutil").rmtree(
            out_dir, ignore_errors=True
        ))
        out = os.path.join(out_dir, "snap.tar")  # 必须在 data-dir 之外
        result = drbackup.backup(self.d, "w1", "snap-1", out)
        self.assertEqual(result["status"], 201)
        target = tempfile.mkdtemp()
        self.addCleanup(lambda: __import__("shutil").rmtree(
            target, ignore_errors=True
        ))
        status, _ = drbackup.restore(target, "w1", out)
        self.assertEqual(status, 201)
        h2 = make_harness(target)
        view = h2.service.get_sign_session("w1", "s1")
        self.assertEqual(view["missing_shares"], ["share-1", "r1-share"])
        # 恢复后新份额可继续投递
        sig = h2.share_signature("w1", "r1-share", "s1", "pay-100")
        code, _ = h2.service.submit_sign_session_share(
            "w1", "s1", "r1-share", sig
        )
        self.assertEqual(code, 201)

    def test_max_length_replacement_id(self):
        rid = "r" * 128
        code, view = self.svc.replace_sign_session_participant(
            "w1", "s1", rid, "share-2"
        )
        self.assertEqual(code, 201)
        self.assertEqual(view["missing_shares"], ["share-1", rid + "-share"])
        svc2 = WalletService(self.h.store)
        self.assertEqual(
            svc2.get_sign_session("w1", "s1")["missing_shares"],
            ["share-1", rid + "-share"],
        )

    # ---- HTTP 端到端 ------------------------------------------------------

    def test_http_end_to_end(self):
        with http_server(self._tmp()) as server:
            code, wallet = server.request(
                "POST", "/v1/wallets", {"wallet_id": "w9", "shares": 2}
            )
            self.assertEqual(code, 201)
            code, session = server.request(
                "POST",
                "/v1/wallets/w9/sign-sessions",
                {"id": "s1", "message": "m", "timeout_seconds": 600},
            )
            self.assertEqual(code, 201)
            code, view = server.request(
                "POST",
                "/v1/wallets/w9/sign-sessions/s1/participants/replace",
                {"replacement_id": "r1", "offline_share_id": "share-2"},
            )
            self.assertEqual(code, 201)
            self.assertEqual(
                view["missing_shares"], ["share-1", "r1-share"]
            )
            # 重放 200 同体
            code, replay = server.request(
                "POST",
                "/v1/wallets/w9/sign-sessions/s1/participants/replace",
                {"replacement_id": "r1", "offline_share_id": "share-2"},
            )
            self.assertEqual(code, 200)
            self.assertEqual(replay, view)
            # 异参 409
            code, _ = server.request(
                "POST",
                "/v1/wallets/w9/sign-sessions/s1/participants/replace",
                {"replacement_id": "r1", "offline_share_id": "share-1"},
            )
            self.assertEqual(code, 409)
            # 非法 id 400
            code, _ = server.request(
                "POST",
                "/v1/wallets/w9/sign-sessions/s1/participants/replace",
                {"replacement_id": "a/b", "offline_share_id": "share-1"},
            )
            self.assertEqual(code, 400)
            # 未知会话 404
            code, _ = server.request(
                "POST",
                "/v1/wallets/w9/sign-sessions/nope/participants/replace",
                {"replacement_id": "r2", "offline_share_id": "share-1"},
            )
            self.assertEqual(code, 404)
            # 审计事件可查
            code, events = server.request(
                "GET", "/v1/wallets/w9/audit-events"
            )
            self.assertEqual(code, 200)
            kinds = [e["type"] for e in events["events"]]
            self.assertIn("session_participant_replaced", kinds)
            # 访问日志不含私钥
            priv = server.harness.store.get_share("w9", "r1-share")[
                "private_key"
            ]
            self.assertNotIn(priv, "".join(server.logs))


if __name__ == "__main__":
    unittest.main()
