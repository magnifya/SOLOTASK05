"""会话单节点替换

``POST /v1/wallets/<id>/sign-sessions/<sid>/participants/replace`` 测试。

覆盖：首替 201 与视图/槽位迁移、同 ID 同参 200、异参/占用 409、非法
ID 400、未知钱包/会话 404、非 collecting|ready 与到期 409、目标非在用
份额 409、旧份额投递 400、新份额 Ed25519 校验与既有门控、链式替换、
份额文件精确形状（恰三键、64 位小写 hex、UTF-8 无 BOM、sort_keys、
indent=2、末换行）、session_participant_replaced 事件七字段与
details 键、重启持久化、崩溃回滚/前滚、损坏/矛盾 503、轮换交互、
并发仅一个 201、灾备备份/恢复兼容，以及响应/日志/非份额文件不含私钥。
"""

from __future__ import annotations

import json
import multiprocessing
import os
import shutil
import tempfile
import threading
import time
import unittest

from tests.helpers import http_server, make_harness
from threshold_wallet import crypto
from threshold_wallet.service import ServiceError, WalletService
from threshold_wallet.store import CorruptDataError, RecoveryError, WalletStore


def _replaced_events(svc, wallet_id):
    return [
        e
        for e in svc.get_audit_events(wallet_id)["events"]
        if e["type"] == "session_participant_replaced"
    ]


class ParticipantReplaceTest(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.d, ignore_errors=True)
        self.h = make_harness(self.d)
        self.svc = self.h.service
        self.svc.create_wallet("w1", 2)
        self.svc.create_sign_session("w1", "s1", "hello", 600)

    def _sig(self, share_id, sid="s1", message="hello"):
        return self.h.share_signature("w1", share_id, sid, message)

    def _replace(self, replacement_id="rep1", offline="share-2", sid="s1"):
        return self.svc.replace_sign_session_participant(
            "w1", sid, replacement_id, offline
        )

    # ---- 首次替换与视图 ---------------------------------------------------

    def test_first_replace_201_and_view(self):
        self.svc.submit_sign_session_share(
            "w1", "s1", "share-1", self._sig("share-1")
        )
        code, view = self._replace()
        self.assertEqual(code, 201)
        self.assertEqual(view["id"], "s1")
        self.assertEqual(view["state"], "collecting")
        # 原槽位换入新 id；旧份额已收签名被剔除、另一份保留
        self.assertEqual(view["received_shares"], ["share-1"])
        self.assertEqual(view["missing_shares"], ["rep1-share"])
        self.assertNotIn("aggregate_signature", view)

    def test_replace_removes_offline_share_signature(self):
        self.svc.submit_sign_session_share(
            "w1", "s1", "share-2", self._sig("share-2")
        )
        code, view = self._replace()
        self.assertEqual(code, 201)
        self.assertEqual(view["received_shares"], [])
        self.assertEqual(view["missing_shares"], ["share-1", "rep1-share"])

    def test_replace_first_slot_preserves_order(self):
        code, view = self._replace(replacement_id="rep0", offline="share-1")
        self.assertEqual(code, 201)
        self.assertEqual(view["missing_shares"], ["rep0-share", "share-2"])

    def test_replace_ready_session_falls_back_to_collecting(self):
        # 审批门控未过 -> ready；替换后剔除旧份额回退 collecting
        self.svc.put_policy("w1", 1, 3600)
        self.svc.submit_sign_session_share(
            "w1", "s1", "share-1", self._sig("share-1")
        )
        code, view = self.svc.submit_sign_session_share(
            "w1", "s1", "share-2", self._sig("share-2")
        )
        self.assertEqual(code, 409)
        self.assertEqual(view["state"], "ready")
        code, view = self._replace()
        self.assertEqual(code, 201)
        self.assertEqual(view["state"], "collecting")
        self.assertEqual(view["received_shares"], ["share-1"])
        self.assertEqual(view["missing_shares"], ["rep1-share"])

    # ---- 份额文件形状 ------------------------------------------------------

    def test_new_share_file_exact_shape(self):
        self._replace()
        path = os.path.join(self.d, "shares", "w1", "rep1-share.json")
        with open(path, "rb") as f:
            raw = f.read()
        # UTF-8 无 BOM、末尾换行
        self.assertFalse(raw.startswith(b"\xef\xbb\xbf"))
        self.assertTrue(raw.endswith(b"\n") and not raw.endswith(b"\n\n"))
        record = json.loads(raw.decode("utf-8"))
        # 恰三键
        self.assertEqual(
            set(record), {"private_key", "public_key", "share_id"}
        )
        self.assertEqual(record["share_id"], "rep1-share")
        for key in ("private_key", "public_key"):
            value = record[key]
            self.assertEqual(len(value), 64)
            self.assertTrue(
                all(c in "0123456789abcdef" for c in value), key
            )
        # 私钥可推出公钥
        self.assertEqual(
            crypto.public_key_from_private(
                bytes.fromhex(record["private_key"])
            ).hex(),
            record["public_key"],
        )
        # sort_keys=True、indent=2、末换行的确定性序列化
        expected = (
            json.dumps(record, ensure_ascii=False, sort_keys=True, indent=2)
            + "\n"
        ).encode("utf-8")
        self.assertEqual(raw, expected)

    # ---- 幂等与冲突 ---------------------------------------------------------

    def test_replay_same_params_200_no_new_event(self):
        code, first = self._replace()
        self.assertEqual(code, 201)
        code, second = self._replace()
        self.assertEqual(code, 200)
        self.assertEqual(second, first)
        self.assertEqual(len(_replaced_events(self.svc, "w1")), 1)

    def test_committed_replay_takes_priority_over_state(self):
        # 已提交重放优先：会话其后 signed，同参重放仍 200 而非 409
        self._replace()
        self.svc.submit_sign_session_share(
            "w1", "s1", "share-1", self._sig("share-1")
        )
        code, view = self.svc.submit_sign_session_share(
            "w1", "s1", "rep1-share", self._sig("rep1-share")
        )
        self.assertEqual(code, 201)
        self.assertEqual(view["state"], "signed")
        code, view = self._replace()
        self.assertEqual(code, 200)
        self.assertEqual(view["state"], "signed")
        self.assertEqual(len(_replaced_events(self.svc, "w1")), 1)

    def test_same_id_different_offline_409(self):
        self._replace()
        with self.assertRaises(ServiceError) as ctx:
            self._replace(replacement_id="rep1", offline="share-1")
        self.assertEqual(ctx.exception.status, 409)

    def test_occupied_by_other_session_409(self):
        self._replace()
        self.svc.create_sign_session("w1", "s2", "hello", 600)
        with self.assertRaises(ServiceError) as ctx:
            self.svc.replace_sign_session_participant(
                "w1", "s2", "rep1", "share-2"
            )
        self.assertEqual(ctx.exception.status, 409)

    # ---- 参数与存在性 -------------------------------------------------------

    def test_invalid_ids_400(self):
        for bad in ("", "bad id", "../x", "a/b", 123, None, True, "x" * 129):
            with self.assertRaises(ServiceError) as ctx:
                self.svc.replace_sign_session_participant(
                    "w1", "s1", bad, "share-2"
                )
            self.assertEqual(ctx.exception.status, 400, bad)
            with self.assertRaises(ServiceError) as ctx:
                self.svc.replace_sign_session_participant(
                    "w1", "s1", "rep1", bad
                )
            self.assertEqual(ctx.exception.status, 400, bad)

    def test_unknown_wallet_404(self):
        with self.assertRaises(ServiceError) as ctx:
            self.svc.replace_sign_session_participant(
                "ghost", "s1", "rep1", "share-2"
            )
        self.assertEqual(ctx.exception.status, 404)

    def test_unknown_session_404(self):
        with self.assertRaises(ServiceError) as ctx:
            self.svc.replace_sign_session_participant(
                "w1", "nope", "rep1", "share-2"
            )
        self.assertEqual(ctx.exception.status, 404)

    def test_signed_session_409(self):
        self.svc.submit_sign_session_share(
            "w1", "s1", "share-1", self._sig("share-1")
        )
        self.svc.submit_sign_session_share(
            "w1", "s1", "share-2", self._sig("share-2")
        )
        with self.assertRaises(ServiceError) as ctx:
            self._replace()
        self.assertEqual(ctx.exception.status, 409)

    def test_expired_session_409(self):
        self.svc.create_sign_session("w1", "sx", "m", 1)
        time.sleep(1.1)
        with self.assertRaises(ServiceError) as ctx:
            self.svc.replace_sign_session_participant(
                "w1", "sx", "rep1", "share-2"
            )
        self.assertEqual(ctx.exception.status, 409)
        # 懒过期持久化：会话转 expired 且只记一次 expired 事件
        self.assertEqual(
            self.svc.get_sign_session("w1", "sx")["state"], "expired"
        )
        actions = [
            e["details"]["action"]
            for e in self.svc.get_audit_events("w1")["events"]
            if e["type"] == "session_event" and e["request_id"] == "sx"
        ]
        self.assertEqual(actions, ["created", "expired"])

    def test_offline_not_active_409(self):
        with self.assertRaises(ServiceError) as ctx:
            self._replace(offline="share-9")
        self.assertEqual(ctx.exception.status, 409)
        # 已被替换走的旧份额也不再是在用份额
        self._replace()
        with self.assertRaises(ServiceError) as ctx:
            self._replace(replacement_id="rep2", offline="share-2")
        self.assertEqual(ctx.exception.status, 409)

    # ---- 替换后的投递 -------------------------------------------------------

    def test_old_share_delivery_400_after_replace(self):
        self._replace()
        with self.assertRaises(ServiceError) as ctx:
            self.svc.submit_sign_session_share(
                "w1", "s1", "share-2", self._sig("share-2")
            )
        self.assertEqual(ctx.exception.status, 400)

    def test_new_share_completes_and_aggregates(self):
        self._replace()
        self.svc.submit_sign_session_share(
            "w1", "s1", "share-1", self._sig("share-1")
        )
        code, view = self.svc.submit_sign_session_share(
            "w1", "s1", "rep1-share", self._sig("rep1-share")
        )
        self.assertEqual(code, 201)
        self.assertEqual(view["state"], "signed")
        # 聚合签名按槽位顺序可独立验证（钱包 share-1 + 替换份额）
        wallet = self.svc.get_wallet("w1")
        first_pk = bytes.fromhex(wallet["public_key"])[:32]
        rep_pk = bytes.fromhex(
            self.h.store.get_share("w1", "rep1-share")["public_key"]
        )
        parts = crypto.split_signature(
            bytes.fromhex(view["aggregate_signature"])
        )
        payload = crypto.build_payload("s1", "hello")
        self.assertTrue(crypto.verify_share(first_pk, payload, parts[0]))
        self.assertTrue(crypto.verify_share(rep_pk, payload, parts[1]))

    def test_new_share_uses_existing_gating(self):
        # 审批门控对新份额同样生效：未批准 409 保留 ready，批准后重放成功
        self.svc.put_policy("w1", 1, 3600)
        self._replace()
        self.svc.submit_sign_session_share(
            "w1", "s1", "share-1", self._sig("share-1")
        )
        code, view = self.svc.submit_sign_session_share(
            "w1", "s1", "rep1-share", self._sig("rep1-share")
        )
        self.assertEqual(code, 409)
        self.assertEqual(view["state"], "ready")
        self.svc.create_sign_request("w1", "s1", "hello")
        self.svc.approve("w1", "s1", "ops-1")
        code, view = self.svc.submit_sign_session_share(
            "w1", "s1", "rep1-share", self._sig("rep1-share")
        )
        self.assertEqual(code, 200)
        self.assertEqual(view["state"], "signed")

    def test_wrong_signature_from_new_share_400(self):
        self._replace()
        with self.assertRaises(ServiceError) as ctx:
            self.svc.submit_sign_session_share(
                "w1", "s1", "rep1-share", "00" * 64
            )
        self.assertEqual(ctx.exception.status, 400)

    def test_chained_replacement(self):
        self._replace()
        code, view = self._replace(replacement_id="rep2", offline="rep1-share")
        self.assertEqual(code, 201)
        self.assertEqual(view["missing_shares"], ["share-1", "rep2-share"])
        # 被换走的 rep1-share 投递 400；rep2-share 可完成会话
        with self.assertRaises(ServiceError) as ctx:
            self.svc.submit_sign_session_share(
                "w1", "s1", "rep1-share", self._sig("rep1-share")
            )
        self.assertEqual(ctx.exception.status, 400)
        self.svc.submit_sign_session_share(
            "w1", "s1", "share-1", self._sig("share-1")
        )
        code, view = self.svc.submit_sign_session_share(
            "w1", "s1", "rep2-share", self._sig("rep2-share")
        )
        self.assertEqual(code, 201)
        self.assertEqual(view["state"], "signed")

    # ---- 审计事件 -----------------------------------------------------------

    def test_event_shape_and_seq(self):
        self._replace()
        events = _replaced_events(self.svc, "w1")
        self.assertEqual(len(events), 1)
        event = events[0]
        self.assertEqual(
            set(event),
            {"seq", "type", "at", "request_id", "actor_id", "reason",
             "details"},
        )
        self.assertEqual(event["request_id"], "s1")
        self.assertIsNone(event["actor_id"])
        self.assertIsNone(event["reason"])
        self.assertEqual(
            event["details"],
            {
                "session_id": "s1",
                "old_share_id": "share-2",
                "new_share_id": "rep1-share",
            },
        )
        # seq 连续：created(1) 之后即替换事件(2)
        all_events = self.svc.get_audit_events("w1")["events"]
        self.assertEqual(
            [e["seq"] for e in all_events], list(range(1, len(all_events) + 1))
        )
        self.assertEqual(event["seq"], 2)

    # ---- 重启持久化 ---------------------------------------------------------

    def test_restart_persists_replacement(self):
        self._replace()
        self.svc.submit_sign_session_share(
            "w1", "s1", "rep1-share", self._sig("rep1-share")
        )
        h2 = make_harness(self.d)
        view = h2.service.get_sign_session("w1", "s1")
        self.assertEqual(view["state"], "collecting")
        self.assertEqual(view["received_shares"], ["rep1-share"])
        self.assertEqual(view["missing_shares"], ["share-1"])
        # 重启后旧份额仍 400，另一份可补齐并完成
        with self.assertRaises(ServiceError) as ctx:
            h2.service.submit_sign_session_share(
                "w1", "s1", "share-2", self._sig("share-2")
            )
        self.assertEqual(ctx.exception.status, 400)
        code, view = h2.service.submit_sign_session_share(
            "w1", "s1", "share-1", self._sig("share-1")
        )
        self.assertEqual(code, 201)
        self.assertEqual(view["state"], "signed")

    # ---- 崩溃恢复：回滚与前滚 -------------------------------------------------

    def test_uncommitted_replacement_is_rolled_back(self):
        # 崩溃窗口：新份额文件已写、替换事件未落盘（会话记录尚未更新）
        key = crypto.generate_share_key("rep1-share")
        self.h.store.save_share(
            "w1",
            {
                "share_id": key.share_id,
                "public_key": key.public_bytes.hex(),
                "private_key": key.private_bytes.hex(),
            },
        )
        # 重启恢复：事件未落盘 -> 孤儿新份额删除，会话记录原样
        h2 = make_harness(self.d)
        view = h2.service.get_sign_session("w1", "s1")
        self.assertEqual(view["received_shares"], [])
        self.assertEqual(view["missing_shares"], ["share-1", "share-2"])
        self.assertNotIn(
            "rep1-share", self.h.store.list_share_files("w1")
        )
        self.assertEqual(_replaced_events(h2.service, "w1"), [])
        # 同一 replacement_id 可重新首次替换（201）
        code, view = h2.service.replace_sign_session_participant(
            "w1", "s1", "rep1", "share-2"
        )
        self.assertEqual(code, 201)
        self.assertEqual(view["missing_shares"], ["share-1", "rep1-share"])

    def test_record_without_event_is_contradiction(self):
        # 会话记录引用了替换份额却无任何已提交替换事件：矛盾现场，
        # fail-closed 保留现场（503），绝不静默归一
        record = self.h.store.get_sign_session("w1", "s1")
        record["share_ids"] = ["share-1", "rep1-share"]
        self.h.store.update_sign_session("w1", "s1", record)
        with self.assertRaises((CorruptDataError, RecoveryError)):
            make_harness(self.d)

    def test_orphan_share_file_without_session_file_is_cleaned(self):
        # 崩溃发生在写会话文件之前：无会话文件，只有孤儿份额文件
        key = crypto.generate_share_key("rep9-share")
        self.h.store.save_share(
            "w1",
            {
                "share_id": key.share_id,
                "public_key": key.public_bytes.hex(),
                "private_key": key.private_bytes.hex(),
            },
        )
        os.unlink(os.path.join(self.d, "sign-sessions", "w1.json"))
        h2 = make_harness(self.d)
        self.assertNotIn(
            "rep9-share", self.h.store.list_share_files("w1")
        )
        # 既有份额不受影响
        self.assertEqual(
            self.h.store.list_share_files("w1"), ["share-1", "share-2"]
        )
        self.assertEqual(h2.service.get_wallet("w1")["wallet_id"], "w1")

    def test_committed_replacement_is_forward_rolled(self):
        # 崩溃窗口：替换事件已落盘、会话记录尚未更新
        self.svc.submit_sign_session_share(
            "w1", "s1", "share-1", self._sig("share-1")
        )
        self._replace()
        stale = self.h.store.get_sign_session("w1", "s1")
        stale["share_ids"] = ["share-1", "share-2"]
        stale["shares"] = [
            {"share_id": "share-1", "signature": self._sig("share-1")}
        ]
        self.h.store.update_sign_session("w1", "s1", stale)
        # 重启恢复：事件在 -> 前滚到替换后快照
        h2 = make_harness(self.d)
        view = h2.service.get_sign_session("w1", "s1")
        self.assertEqual(view["received_shares"], ["share-1"])
        self.assertEqual(view["missing_shares"], ["rep1-share"])
        self.assertIn("rep1-share", self.h.store.list_share_files("w1"))

    # ---- 损坏/矛盾 fail-closed ------------------------------------------------

    def test_malformed_replacement_event_fails_closed(self):
        self._replace()
        path = os.path.join(self.d, "audit", "w1.json")
        with open(path, encoding="utf-8") as f:
            log = json.load(f)
        for event in log["events"]:
            if event["type"] == "session_participant_replaced":
                event["details"]["old_share_id"] = "share-1"
        with open(path, "w", encoding="utf-8") as f:
            json.dump(log, f)
        with self.assertRaises((CorruptDataError, RecoveryError)):
            make_harness(self.d)

    def test_missing_committed_share_file_fails_closed(self):
        self._replace()
        os.unlink(os.path.join(self.d, "shares", "w1", "rep1-share.json"))
        with self.assertRaises((CorruptDataError, RecoveryError)):
            make_harness(self.d)

    def test_duplicate_commit_fails_closed(self):
        # 两个会话各自提交同一派生份额 id：重复提交点，不可对账
        self._replace()
        self.svc.create_sign_session("w1", "s2", "hello", 600)
        path = os.path.join(self.d, "audit", "w1.json")
        with open(path, encoding="utf-8") as f:
            log = json.load(f)
        template = next(
            e
            for e in log["events"]
            if e["type"] == "session_participant_replaced"
        )
        forged = dict(template)
        forged["seq"] = log["next_seq"]
        forged["request_id"] = "s2"
        forged["details"] = dict(template["details"])
        forged["details"]["session_id"] = "s2"
        log["events"].append(forged)
        log["next_seq"] += 1
        with open(path, "w", encoding="utf-8") as f:
            json.dump(log, f)
        with self.assertRaises((CorruptDataError, RecoveryError)):
            make_harness(self.d)

    # ---- 轮换交互 -----------------------------------------------------------

    def test_rotation_after_replace_migrates_to_wallet_shares(self):
        self._replace()
        self.svc.submit_sign_session_share(
            "w1", "s1", "rep1-share", self._sig("rep1-share")
        )
        _, rot = self.svc.create_share_rotation("w1", "rot-1")
        self.assertEqual(
            self.svc.activate_share_rotation("w1", "rot-1")[0], 201
        )
        view = self.svc.get_sign_session("w1", "s1")
        self.assertEqual(view["state"], "collecting")
        self.assertEqual(view["received_shares"], [])
        self.assertEqual(view["missing_shares"], list(rot["share_ids"]))
        # 重启后现场仍一致
        h2 = make_harness(self.d)
        view = h2.service.get_sign_session("w1", "s1")
        self.assertEqual(view["missing_shares"], list(rot["share_ids"]))

    def test_signed_with_replacement_survives_rotation(self):
        self._replace()
        self.svc.submit_sign_session_share(
            "w1", "s1", "share-1", self._sig("share-1")
        )
        _, signed = self.svc.submit_sign_session_share(
            "w1", "s1", "rep1-share", self._sig("rep1-share")
        )
        self.svc.create_share_rotation("w1", "rot-1")
        self.svc.activate_share_rotation("w1", "rot-1")
        # signed 会话冻结快照：旧值重放 200 同体、异值 409
        code, view = self.svc.submit_sign_session_share(
            "w1", "s1", "rep1-share", self._sig("rep1-share")
        )
        self.assertEqual(code, 200)
        self.assertEqual(view, signed)
        with self.assertRaises(ServiceError) as ctx:
            self.svc.submit_sign_session_share(
                "w1", "s1", "rep1-share", "00" * 64
            )
        self.assertEqual(ctx.exception.status, 409)
        # 重启后聚合签名重算一致（历史公钥沿份额文件解析）
        h2 = make_harness(self.d)
        self.assertEqual(
            h2.service.get_sign_session("w1", "s1"), signed
        )

    # ---- 并发：仅一个 201 ------------------------------------------------------

    def test_concurrent_replace_single_201(self):
        results = []

        def race():
            try:
                results.append(self._replace()[0])
            except ServiceError as exc:
                results.append(exc.status)

        threads = [threading.Thread(target=race) for _ in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(results.count(201), 1)
        self.assertEqual(results.count(200), 7)
        self.assertEqual(len(_replaced_events(self.svc, "w1")), 1)
        seqs = [
            e["seq"] for e in self.svc.get_audit_events("w1")["events"]
        ]
        self.assertEqual(seqs, list(range(1, len(seqs) + 1)))

    # ---- 私钥安全边界 ---------------------------------------------------------

    def test_no_private_key_leak(self):
        self._replace()
        self.svc.submit_sign_session_share(
            "w1", "s1", "rep1-share", self._sig("rep1-share")
        )
        private_hex = self.h.share_private_hex("w1", "rep1-share")
        # 响应视图不含私钥
        body = json.dumps(self.svc.get_sign_session("w1", "s1"))
        self.assertNotIn(private_hex, body)
        # 审计事件不含私钥
        events = json.dumps(self.svc.get_audit_events("w1")["events"])
        self.assertNotIn(private_hex, events)
        # 非份额文件不含私钥
        for rel in (
            ("wallets", "w1.json"),
            ("sign-sessions", "w1.json"),
            ("audit", "w1.json"),
        ):
            with open(os.path.join(self.d, *rel), encoding="utf-8") as f:
                self.assertNotIn(private_hex, f.read())


class ParticipantReplaceHttpTest(unittest.TestCase):
    def test_http_route_end_to_end(self):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, ignore_errors=True)
        with http_server(d) as srv:
            srv.request("POST", "/v1/wallets", {"wallet_id": "w1", "shares": 2})
            srv.request(
                "POST",
                "/v1/wallets/w1/sign-sessions",
                {"id": "s1", "message": "m", "timeout_seconds": 600},
            )
            code, view = srv.request(
                "POST",
                "/v1/wallets/w1/sign-sessions/s1/participants/replace",
                {"replacement_id": "rep1", "offline_share_id": "share-2"},
            )
            self.assertEqual(code, 201)
            self.assertEqual(view["missing_shares"], ["share-1", "rep1-share"])
            # 重放 200 同体
            code, replay = srv.request(
                "POST",
                "/v1/wallets/w1/sign-sessions/s1/participants/replace",
                {"replacement_id": "rep1", "offline_share_id": "share-2"},
            )
            self.assertEqual(code, 200)
            self.assertEqual(replay, view)
            # 非法 ID 400、未知会话 404、未知钱包 404
            code, _ = srv.request(
                "POST",
                "/v1/wallets/w1/sign-sessions/s1/participants/replace",
                {"replacement_id": "bad id", "offline_share_id": "share-1"},
            )
            self.assertEqual(code, 400)
            code, _ = srv.request(
                "POST",
                "/v1/wallets/w1/sign-sessions/nope/participants/replace",
                {"replacement_id": "r2", "offline_share_id": "share-1"},
            )
            self.assertEqual(code, 404)
            code, _ = srv.request(
                "POST",
                "/v1/wallets/ghost/sign-sessions/s1/participants/replace",
                {"replacement_id": "r2", "offline_share_id": "share-1"},
            )
            self.assertEqual(code, 404)
            # 访问日志不含私钥
            private_hex = srv.harness.share_private_hex("w1", "rep1-share")
            self.assertNotIn(private_hex, "\n".join(srv.logs))


class ParticipantReplaceCrossProcessTest(unittest.TestCase):
    """跨进程并发替换：恰一个 201，审计 seq 连续。"""

    def test_cross_process_single_201(self):
        tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        svc = WalletService(WalletStore(tmp))
        svc.create_wallet("w1", 2)
        svc.create_sign_session("w1", "s1", "m", 600)
        ctx = multiprocessing.get_context("fork")
        queue = ctx.Queue()

        def child():
            try:
                s = WalletService(WalletStore(tmp))
                code, _ = s.replace_sign_session_participant(
                    "w1", "s1", "rep1", "share-2"
                )
                queue.put(code)
            except ServiceError as exc:
                queue.put(exc.status)
            except BaseException:
                queue.put("ERR")

        procs = [ctx.Process(target=child) for _ in range(6)]
        for p in procs:
            p.start()
        for p in procs:
            p.join(timeout=30)
        results = [queue.get(timeout=30) for _ in range(6)]
        self.assertEqual(results.count(201), 1, results)
        self.assertEqual(results.count(200), 5, results)
        svc2 = WalletService(WalletStore(tmp))
        events = svc2.get_audit_events("w1")["events"]
        self.assertEqual(
            [e["seq"] for e in events], list(range(1, len(events) + 1))
        )
        replaced = [
            e for e in events if e["type"] == "session_participant_replaced"
        ]
        self.assertEqual(len(replaced), 1)


class ParticipantReplaceDrBackupTest(unittest.TestCase):
    """替换现场可随灾备快照备份并恢复。"""

    def test_backup_restore_with_replacement(self):
        import contextlib
        import io

        from threshold_wallet.cli import main as cli_main

        tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        data = os.path.join(tmp, "data")
        h = make_harness(data)
        h.service.create_wallet("alice", 2)
        h.service.create_sign_session("alice", "s1", "m", 600)
        h.service.replace_sign_session_participant(
            "alice", "s1", "rep1", "share-2"
        )
        sig = h.share_signature("alice", "rep1-share", "s1", "m")
        h.service.submit_sign_session_share("alice", "s1", "rep1-share", sig)

        out = os.path.join(tmp, "a.tar")

        def cli(*argv):
            buf_out, buf_err = io.StringIO(), io.StringIO()
            with contextlib.redirect_stdout(buf_out), (
                contextlib.redirect_stderr(buf_err)
            ):
                code = cli_main(list(argv))
            return code, buf_out.getvalue().strip(), buf_err.getvalue().strip()

        code, stdout, _ = cli(
            "backup", "--data-dir", data, "--wallet-id", "alice",
            "--snapshot-id", "S1", "--output", out,
        )
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(stdout)["status"], 201)
        dst = os.path.join(tmp, "dst")
        code, stdout, _ = cli(
            "restore", "--data-dir", dst, "--wallet-id", "alice",
            "--input", out,
        )
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(stdout)["status"], 201)
        # 恢复后的现场与原现场一致，会话可继续完成
        h2 = make_harness(dst)
        view = h2.service.get_sign_session("alice", "s1")
        self.assertEqual(view["received_shares"], ["rep1-share"])
        self.assertEqual(view["missing_shares"], ["share-1"])
        sig1 = h2.share_signature("alice", "share-1", "s1", "m")
        code, view = h2.service.submit_sign_session_share(
            "alice", "s1", "share-1", sig1
        )
        self.assertEqual(code, 201)
        self.assertEqual(view["state"], "signed")


if __name__ == "__main__":
    unittest.main()
