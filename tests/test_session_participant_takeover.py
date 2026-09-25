"""会话两阶段参与者接管
``/v1/wallets/<id>/sign-sessions/<sid>/participants/takeover`` 测试。

覆盖：stage 1/2 首提 201、同阶段同参重放 200、异参/跳号/同槽位/终态/
到期/非当前份额/ID 占用 409（重放优先）；非法参数 400、未知钱包/会话
404、请求体多键 400；迁移（删该槽签名、保留另一份、旧份额投递 400、
新份额可完成聚合）；session_takeover 事件形状与唯一提交点（落盘前
回滚删份额、落盘后前滚）；重启保持；与轮换解耦；HTTP 端到端。
"""

from __future__ import annotations

import json
import os
import unittest

from tests.helpers import http_server, make_harness
from threshold_wallet import crypto
from threshold_wallet.service import ServiceError, WalletService
from threshold_wallet.store import RecoveryError


def _takeover_events(svc, wallet_id):
    return [
        e
        for e in svc.get_audit_events(wallet_id)["events"]
        if e["type"] == "session_takeover"
    ]


class TakeoverParticipantTest(unittest.TestCase):
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

    def _takeover(self, sid, tid, stage, offline, wallet="w1"):
        return self.svc.takeover_sign_session_participant(
            wallet, sid, tid, stage, offline
        )

    # ---- 基本语义 ---------------------------------------------------------

    def test_stage1_first_201_view(self):
        code, view = self._takeover("s1", "t1", 1, "share-2")
        self.assertEqual(code, 201)
        self.assertEqual(view["id"], "s1")
        self.assertEqual(view["state"], "collecting")
        self.assertEqual(view["received_shares"], [])
        self.assertEqual(view["missing_shares"], ["share-1", "t1-1-share"])
        self.assertNotIn("aggregate_signature", view)

    def test_two_stages_replace_both_slots(self):
        code, view = self._takeover("s1", "t1", 1, "share-2")
        self.assertEqual(code, 201)
        code, view = self._takeover("s1", "t1", 2, "share-1")
        self.assertEqual(code, 201)
        self.assertEqual(view["missing_shares"], ["t1-2-share", "t1-1-share"])
        self.assertEqual(view["received_shares"], [])

    def test_replay_same_stage_same_params_200(self):
        code, first = self._takeover("s1", "t1", 1, "share-2")
        self.assertEqual(code, 201)
        code, second = self._takeover("s1", "t1", 1, "share-2")
        self.assertEqual(code, 200)
        self.assertEqual(second, first)
        self.assertEqual(len(_takeover_events(self.svc, "w1")), 1)
        # stage 2 同参重放同样 200
        self._takeover("s1", "t1", 2, "share-1")
        code, third = self._takeover("s1", "t1", 2, "share-1")
        self.assertEqual(code, 200)
        self.assertEqual(len(_takeover_events(self.svc, "w1")), 2)

    def test_same_stage_different_params_409(self):
        self._takeover("s1", "t1", 1, "share-2")
        with self.assertRaises(ServiceError) as ctx:
            self._takeover("s1", "t1", 1, "share-1")
        self.assertEqual(ctx.exception.status, 409)
        self._takeover("s1", "t1", 2, "share-1")
        with self.assertRaises(ServiceError) as ctx:
            self._takeover("s1", "t1", 2, "t1-1-share")
        self.assertEqual(ctx.exception.status, 409)

    def test_skip_stage_409(self):
        with self.assertRaises(ServiceError) as ctx:
            self._takeover("s1", "t1", 2, "share-1")
        self.assertEqual(ctx.exception.status, 409)

    def test_stages_must_replace_different_slots_409(self):
        self._takeover("s1", "t1", 1, "share-2")
        # stage 2 指向 stage 1 换入的槽位：同一槽位，409
        with self.assertRaises(ServiceError) as ctx:
            self._takeover("s1", "t1", 2, "t1-1-share")
        self.assertEqual(ctx.exception.status, 409)

    def test_id_occupied_by_other_session_409(self):
        self._open("s2")
        self._takeover("s1", "t1", 1, "share-2")
        with self.assertRaises(ServiceError) as ctx:
            self._takeover("s2", "t1", 1, "share-1")
        self.assertEqual(ctx.exception.status, 409)

    def test_id_occupied_by_replacement_409(self):
        # replacement_id 为 t1-1 的替换与 takeover t1 stage 1 的新份额同名
        self.svc.replace_sign_session_participant("w1", "s1", "t1-1", "share-2")
        with self.assertRaises(ServiceError) as ctx:
            self._takeover("s1", "t1", 1, "share-1")
        self.assertEqual(ctx.exception.status, 409)

    def test_committed_replay_takes_priority_over_state(self):
        # 两阶段完成后会话 signed（终态）：同参重放仍 200
        self._takeover("s1", "t1", 1, "share-2")
        self._takeover("s1", "t1", 2, "share-1")
        for sid in ("t1-1-share", "t1-2-share"):
            sig = self.h.share_signature("w1", sid, "s1", "pay-100")
            self.svc.submit_sign_session_share("w1", "s1", sid, sig)
        view = self.svc.get_sign_session("w1", "s1")
        self.assertEqual(view["state"], "signed")
        code, view = self._takeover("s1", "t1", 1, "share-2")
        self.assertEqual(code, 200)
        self.assertEqual(view["state"], "signed")

    # ---- 参数校验 ---------------------------------------------------------

    def test_invalid_ids_400(self):
        for bad in (None, 1, True, "", "a/b", "a b", "x" * 129, 1.5):
            with self.assertRaises(ServiceError) as ctx:
                self._takeover("s1", bad, 1, "share-2")
            self.assertEqual(ctx.exception.status, 400, repr(bad))
            with self.assertRaises(ServiceError) as ctx:
                self._takeover("s1", "t1", 1, bad)
            self.assertEqual(ctx.exception.status, 400, repr(bad))

    def test_invalid_stage_400(self):
        for bad in (None, True, False, 0, 3, -1, "1", 1.5, 2.0):
            with self.assertRaises(ServiceError) as ctx:
                self._takeover("s1", "t1", bad, "share-2")
            self.assertEqual(ctx.exception.status, 400, repr(bad))

    def test_body_extra_keys_400(self):
        with self.assertRaises(ServiceError) as ctx:
            self.svc.takeover_sign_session_participant(
                "w1",
                "s1",
                "t1",
                1,
                "share-2",
                body_keys={"takeover_id", "stage", "offline_share_id", "x"},
            )
        self.assertEqual(ctx.exception.status, 400)
        with self.assertRaises(ServiceError) as ctx:
            self.svc.takeover_sign_session_participant(
                "w1", "s1", "t1", 1, "share-2",
                body_keys={"takeover_id", "stage"},
            )
        self.assertEqual(ctx.exception.status, 400)

    def test_unknown_wallet_404(self):
        with self.assertRaises(ServiceError) as ctx:
            self._takeover("s1", "t1", 1, "share-2", wallet="nope")
        self.assertEqual(ctx.exception.status, 404)

    def test_unknown_session_404(self):
        with self.assertRaises(ServiceError) as ctx:
            self._takeover("nope", "t1", 1, "share-2")
        self.assertEqual(ctx.exception.status, 404)

    def test_target_not_in_use_409(self):
        for sid in ("share-3", "t1-1-share", "other"):
            with self.assertRaises(ServiceError) as ctx:
                self._takeover("s1", "t9", 1, sid)
            self.assertEqual(ctx.exception.status, 409, sid)

    def test_signed_session_409(self):
        for sid in ("share-1", "share-2"):
            sig = self.h.share_signature("w1", sid, "s1", "pay-100")
            self.svc.submit_sign_session_share("w1", "s1", sid, sig)
        with self.assertRaises(ServiceError) as ctx:
            self._takeover("s1", "t1", 1, "share-2")
        self.assertEqual(ctx.exception.status, 409)

    def test_expired_session_409(self):
        self._open("sx", timeout=1)
        import time

        time.sleep(1.1)
        with self.assertRaises(ServiceError) as ctx:
            self._takeover("sx", "t1", 1, "share-2")
        self.assertEqual(ctx.exception.status, 409)
        view = self.svc.get_sign_session("w1", "sx")
        self.assertEqual(view["state"], "expired")

    # ---- 迁移语义 ---------------------------------------------------------

    def test_migration_removes_old_keeps_other(self):
        sig1 = self.h.share_signature("w1", "share-1", "s1", "pay-100")
        code, view = self.svc.submit_sign_session_share(
            "w1", "s1", "share-1", sig1
        )
        self.assertEqual(code, 201)
        code, view = self._takeover("s1", "t1", 1, "share-2")
        self.assertEqual(code, 201)
        self.assertEqual(view["received_shares"], ["share-1"])
        self.assertEqual(view["missing_shares"], ["t1-1-share"])
        self.assertEqual(view["state"], "collecting")

    def test_old_share_submit_400_new_share_signs(self):
        self._takeover("s1", "t1", 1, "share-2")
        self._takeover("s1", "t1", 2, "share-1")
        for old in ("share-1", "share-2"):
            old_sig = self.h.share_signature("w1", old, "s1", "pay-100")
            with self.assertRaises(ServiceError) as ctx:
                self.svc.submit_sign_session_share("w1", "s1", old, old_sig)
            self.assertEqual(ctx.exception.status, 400)
        for new in ("t1-1-share", "t1-2-share"):
            sig = self.h.share_signature("w1", new, "s1", "pay-100")
            code, view = self.svc.submit_sign_session_share(
                "w1", "s1", new, sig
            )
            self.assertEqual(code, 201)
        self.assertEqual(view["state"], "signed")
        # 聚合签名按会话 share_ids 顺序拼接，两半分别独立验通
        aggregate = bytes.fromhex(view["aggregate_signature"])
        payload = crypto.build_payload("s1", "pay-100")
        pub2 = bytes.fromhex(
            self.h.store.get_share("w1", "t1-2-share")["public_key"]
        )
        pub1 = bytes.fromhex(
            self.h.store.get_share("w1", "t1-1-share")["public_key"]
        )
        self.assertTrue(crypto.verify_share(pub2, payload, aggregate[:64]))
        self.assertTrue(crypto.verify_share(pub1, payload, aggregate[64:]))

    # ---- 新份额文件形状 ---------------------------------------------------

    def test_share_file_exact_shape(self):
        self._takeover("s1", "t1", 1, "share-2")
        path = os.path.join(self.d, "shares", "w1", "t1-1-share.json")
        with open(path, "rb") as f:
            raw = f.read()
        self.assertFalse(raw.startswith(b"\xef\xbb\xbf"))
        self.assertTrue(raw.endswith(b"\n"))
        self.assertNotIn(b"\r", raw)
        record = json.loads(raw.decode("utf-8"))
        self.assertEqual(
            set(record), {"private_key", "public_key", "share_id"}
        )
        self.assertEqual(record["share_id"], "t1-1-share")
        for key in ("private_key", "public_key"):
            value = record[key]
            self.assertEqual(len(value), 64)
            self.assertTrue(
                all(c in "0123456789abcdef" for c in value), key
            )
        canonical = (
            json.dumps(
                record, ensure_ascii=False, indent=2, sort_keys=True
            )
            + "\n"
        ).encode("utf-8")
        self.assertEqual(raw, canonical)
        self.assertEqual(
            crypto.public_key_from_private(
                bytes.fromhex(record["private_key"])
            ).hex(),
            record["public_key"],
        )

    # ---- 审计事件 ---------------------------------------------------------

    def test_takeover_event_shape(self):
        self._takeover("s1", "t1", 1, "share-2")
        self._takeover("s1", "t1", 2, "share-1")
        events = _takeover_events(self.svc, "w1")
        self.assertEqual(len(events), 2)
        for event, stage, old, new in (
            (events[0], 1, "share-2", "t1-1-share"),
            (events[1], 2, "share-1", "t1-2-share"),
        ):
            self.assertEqual(event["request_id"], "s1")
            self.assertIsNone(event["actor_id"])
            self.assertIsNone(event["reason"])
            self.assertEqual(
                event["details"],
                {
                    "takeover_id": "t1",
                    "stage": stage,
                    "old_share_id": old,
                    "new_share_id": new,
                },
            )
            # details 有序：takeover_id, stage, old_share_id, new_share_id
            self.assertEqual(
                list(event["details"]),
                ["takeover_id", "stage", "old_share_id", "new_share_id"],
            )
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
        self._takeover("s1", "t1", 1, "share-2")
        priv = self.h.store.get_share("w1", "t1-1-share")["private_key"]
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

    def test_restart_keeps_takeover(self):
        self._takeover("s1", "t1", 1, "share-2")
        self._takeover("s1", "t1", 2, "share-1")
        before = _takeover_events(self.svc, "w1")
        svc2 = WalletService(self.h.store)
        view = svc2.get_sign_session("w1", "s1")
        self.assertEqual(view["missing_shares"], ["t1-2-share", "t1-1-share"])
        # 恢复不新增审计事件
        self.assertEqual(_takeover_events(svc2, "w1"), before)

    def test_orphan_share_file_rolled_back(self):
        # 崩溃窗口：份额文件已写、提交事件未落盘 -> 自愈回滚删除，可重试
        key = crypto.generate_share_key("t1-1-share")
        self.h.store.save_share(
            "w1",
            {
                "share_id": "t1-1-share",
                "public_key": key.public_bytes.hex(),
                "private_key": key.private_bytes.hex(),
            },
        )
        svc2 = WalletService(self.h.store)  # 启动恢复
        self.assertIsNone(self.h.store.get_share("w1", "t1-1-share"))
        code, view = svc2.takeover_sign_session_participant(
            "w1", "s1", "t1", 1, "share-2"
        )
        self.assertEqual(code, 201)
        self.assertEqual(view["missing_shares"], ["share-1", "t1-1-share"])

    def test_committed_event_rolls_forward(self):
        # 崩溃窗口：事件已落盘、会话记录未迁移 -> 自愈前滚迁移
        self._takeover("s1", "t1", 1, "share-2")
        sessions = self._read_sessions()
        sessions["s1"]["share_ids"] = ["share-1", "share-2"]
        self._write_sessions(sessions)
        svc2 = WalletService(self.h.store)
        view = svc2.get_sign_session("w1", "s1")
        self.assertEqual(view["missing_shares"], ["share-1", "t1-1-share"])
        self.assertEqual(len(_takeover_events(svc2, "w1")), 1)

    def test_corrupt_share_file_is_503(self):
        self._takeover("s1", "t1", 1, "share-2")
        path = os.path.join(self.d, "shares", "w1", "t1-1-share.json")
        with open(path, encoding="utf-8") as f:
            record = json.load(f)
        record["private_key"] = "0" * 64  # 与 public_key 不符
        with open(path, "w", encoding="utf-8") as f:
            json.dump(record, f)
        with self.assertRaises(RecoveryError):
            WalletService(self.h.store)
        # 现场保留：文件不被归一/删除
        self.assertTrue(os.path.exists(path))

    def test_tampered_snapshot_is_503(self):
        self._takeover("s1", "t1", 1, "share-2")
        sessions = self._read_sessions()
        sessions["s1"]["share_ids"] = ["share-1", "ghost-share"]  # 无事件
        self._write_sessions(sessions)
        with self.assertRaises(RecoveryError):
            WalletService(self.h.store)

    def test_out_of_order_stages_in_audit_is_503(self):
        self._takeover("s1", "t1", 1, "share-2")
        self._takeover("s1", "t1", 2, "share-1")
        # 篡改审计：删掉 stage 1 事件并挤压 seq，制造跳号现场
        path = os.path.join(self.d, "audit", "w1.json")
        with open(path, encoding="utf-8") as f:
            log = json.load(f)
        kept = []
        for event in log["events"]:
            if event["type"] == "session_takeover" and event["details"][
                "stage"
            ] == 1:
                continue
            kept.append(event)
        for index, event in enumerate(kept, start=1):
            event["seq"] = index
        log["events"] = kept
        log["next_seq"] = len(kept) + 1
        with open(path, "w", encoding="utf-8") as f:
            json.dump(log, f)
        with self.assertRaises(RecoveryError):
            WalletService(self.h.store)

    # ---- 并发 -------------------------------------------------------------

    def test_concurrent_takeover_only_one_201(self):
        import threading

        results = []
        lock = threading.Lock()

        def work():
            try:
                code, _ = self._takeover("s1", "t1", 1, "share-2")
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

    # ---- 与轮换/替换的交互 ------------------------------------------------

    def test_rotation_after_takeover_decouples_session(self):
        self._open("s2")
        self._takeover("s1", "t1", 1, "share-2")
        self.svc.create_share_rotation("w1", "rot1")
        self.svc.activate_share_rotation("w1", "rot1")
        svc2 = WalletService(self.h.store)
        # 被接管的会话冻结于接管后快照，不随轮换迁移；接管份额文件保留
        view = svc2.get_sign_session("w1", "s1")
        self.assertEqual(view["missing_shares"], ["share-1", "t1-1-share"])
        self.assertIsNotNone(self.h.store.get_share("w1", "t1-1-share"))
        # 未接管的会话照常迁移到轮换后在用份额
        view2 = svc2.get_sign_session("w1", "s2")
        self.assertEqual(
            view2["missing_shares"], ["rot1-share-1", "rot1-share-2"]
        )
        # 新份额仍可投递
        sig = self.h.share_signature("w1", "t1-1-share", "s1", "pay-100")
        code, _ = svc2.submit_sign_session_share("w1", "s1", "t1-1-share", sig)
        self.assertEqual(code, 201)

    def test_takeover_after_rotation_targets_rotation_share(self):
        self.svc.create_share_rotation("w1", "rot1")
        self.svc.activate_share_rotation("w1", "rot1")
        code, view = self._takeover("s1", "t9", 1, "rot1-share-1")
        self.assertEqual(code, 201)
        self.assertEqual(view["missing_shares"], ["t9-1-share", "rot1-share-2"])
        svc2 = WalletService(self.h.store)
        self.assertEqual(
            svc2.get_sign_session("w1", "s1")["missing_shares"],
            ["t9-1-share", "rot1-share-2"],
        )

    def test_backup_restore_with_takeover(self):
        from threshold_wallet import drbackup

        self._takeover("s1", "t1", 1, "share-2")
        self._takeover("s1", "t1", 2, "share-1")
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
        self.assertEqual(view["missing_shares"], ["t1-2-share", "t1-1-share"])
        # 恢复后新份额可继续投递
        sig = h2.share_signature("w1", "t1-1-share", "s1", "pay-100")
        code, _ = h2.service.submit_sign_session_share(
            "w1", "s1", "t1-1-share", sig
        )
        self.assertEqual(code, 201)

    def test_max_length_takeover_id(self):
        tid = "t" * 128
        code, view = self._takeover("s1", tid, 1, "share-2")
        self.assertEqual(code, 201)
        self.assertEqual(
            view["missing_shares"], ["share-1", tid + "-1-share"]
        )
        svc2 = WalletService(self.h.store)
        self.assertEqual(
            svc2.get_sign_session("w1", "s1")["missing_shares"],
            ["share-1", tid + "-1-share"],
        )
        # 最长 id 的新份额可继续投递（公钥从份额文件解析）
        sig = self.h.share_signature("w1", tid + "-1-share", "s1", "pay-100")
        code, _ = svc2.submit_sign_session_share(
            "w1", "s1", tid + "-1-share", sig
        )
        self.assertEqual(code, 201)

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
                "/v1/wallets/w9/sign-sessions/s1/participants/takeover",
                {"takeover_id": "t1", "stage": 1,
                 "offline_share_id": "share-2"},
            )
            self.assertEqual(code, 201)
            self.assertEqual(
                view["missing_shares"], ["share-1", "t1-1-share"]
            )
            # 重放 200 同体
            code, replay = server.request(
                "POST",
                "/v1/wallets/w9/sign-sessions/s1/participants/takeover",
                {"takeover_id": "t1", "stage": 1,
                 "offline_share_id": "share-2"},
            )
            self.assertEqual(code, 200)
            self.assertEqual(replay, view)
            # 跳号 409（stage 2 指向 stage 1 槽位）
            code, _ = server.request(
                "POST",
                "/v1/wallets/w9/sign-sessions/s1/participants/takeover",
                {"takeover_id": "t9", "stage": 2,
                 "offline_share_id": "share-1"},
            )
            self.assertEqual(code, 409)
            # stage 2 完成接管
            code, view2 = server.request(
                "POST",
                "/v1/wallets/w9/sign-sessions/s1/participants/takeover",
                {"takeover_id": "t1", "stage": 2,
                 "offline_share_id": "share-1"},
            )
            self.assertEqual(code, 201)
            self.assertEqual(
                view2["missing_shares"], ["t1-2-share", "t1-1-share"]
            )
            # 请求体多键 400
            code, _ = server.request(
                "POST",
                "/v1/wallets/w9/sign-sessions/s1/participants/takeover",
                {"takeover_id": "t2", "stage": 1,
                 "offline_share_id": "t1-1-share", "extra": 1},
            )
            self.assertEqual(code, 400)
            # 非法 stage 400
            code, _ = server.request(
                "POST",
                "/v1/wallets/w9/sign-sessions/s1/participants/takeover",
                {"takeover_id": "t2", "stage": True,
                 "offline_share_id": "t1-1-share"},
            )
            self.assertEqual(code, 400)
            # 未知会话 404
            code, _ = server.request(
                "POST",
                "/v1/wallets/w9/sign-sessions/nope/participants/takeover",
                {"takeover_id": "t2", "stage": 1,
                 "offline_share_id": "share-1"},
            )
            self.assertEqual(code, 404)
            # 审计事件可查
            code, events = server.request(
                "GET", "/v1/wallets/w9/audit-events"
            )
            self.assertEqual(code, 200)
            kinds = [e["type"] for e in events["events"]]
            self.assertIn("session_takeover", kinds)
            # 访问日志不含私钥
            priv = server.harness.store.get_share("w9", "t1-1-share")[
                "private_key"
            ]
            self.assertNotIn(priv, "".join(server.logs))

    def test_http_replace_body_extra_keys_400(self):
        with http_server(self._tmp()) as server:
            server.request(
                "POST", "/v1/wallets", {"wallet_id": "w9", "shares": 2}
            )
            server.request(
                "POST",
                "/v1/wallets/w9/sign-sessions",
                {"id": "s1", "message": "m", "timeout_seconds": 600},
            )
            # replace 请求体多键 400
            code, _ = server.request(
                "POST",
                "/v1/wallets/w9/sign-sessions/s1/participants/replace",
                {"replacement_id": "r1", "offline_share_id": "share-2",
                 "extra": 1},
            )
            self.assertEqual(code, 400)
            # 恰两键仍 201
            code, view = server.request(
                "POST",
                "/v1/wallets/w9/sign-sessions/s1/participants/replace",
                {"replacement_id": "r1", "offline_share_id": "share-2"},
            )
            self.assertEqual(code, 201)
            self.assertEqual(
                view["missing_shares"], ["share-1", "r1-share"]
            )


if __name__ == "__main__":
    unittest.main()
