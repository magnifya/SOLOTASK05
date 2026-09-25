"""会话两阶段参与者接管
``/v1/wallets/<id>/sign-sessions/<sid>/participants/takeover`` 测试。

覆盖：两阶段首提 201 / 同阶段同参重放 200 / 异参 409 / 跳号 409 /
同槽位（旧槽与 stage 1 新份额）409 / takeover_id 跨会话占用 409 /
与替换共享新份额 id 命名空间 / 已提交重放优先；非法 id/stage（布尔等）
400、请求体恰三键（多/缺键 400）、未知钱包/会话 404、非 collecting|ready
（含到期）与目标非当前份额 409；迁移（移除旧槽签名、保留另一份、旧份额
投递 400、新阶段份额沿用 Ed25519 与既有门控、聚合签名顺序）；阶段份额
文件精确形状；session_takeover 事件为唯一提交点（落盘前回滚删份额、
落盘后前滚）；阶段序列/槽位矛盾 503 保留现场；并发只有一个 201、
seq 连续；轮换解耦；backup/restore；响应/日志/非份额文件不含私钥。
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


def _takeover_events(svc, wallet_id):
    return [
        e
        for e in svc.get_audit_events(wallet_id)["events"]
        if e["type"] == "session_takeover"
    ]


class TakeoverParticipantTest(unittest.TestCase):
    def setUp(self):
        import tempfile

        self._dir = tempfile.mkdtemp()
        self.h = make_harness(self._dir)
        self.svc = self.h.service
        self.svc.create_wallet("w1", 2)
        self.svc.create_sign_session("w1", "s1", "pay-100", 3600)

    def tearDown(self):
        import shutil

        shutil.rmtree(self._dir, ignore_errors=True)

    @property
    def d(self):
        return self._dir

    def _open(self, sid="s2", message="pay-100", timeout=3600):
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

    def _audit_path(self, wallet="w1"):
        return os.path.join(self.d, "audit", f"{wallet}.json")

    def _backdate_expiry(self, sid):
        """把会话 expires_at 改为过去时刻（确定性懒过期，避免 sleep 抖动）。"""
        sessions = self._read_sessions()
        sessions[sid]["expires_at"] = "2000-01-01T00:00:00Z"
        self._write_sessions(sessions)

    # ---- 基本两阶段语义 ---------------------------------------------------

    def test_stage1_first_201_view(self):
        code, view = self.svc.takeover_sign_session_participant(
            "w1", "s1", "t1", 1, "share-2"
        )
        self.assertEqual(code, 201)
        self.assertEqual(view["state"], "collecting")
        self.assertEqual(view["received_shares"], [])
        self.assertEqual(view["missing_shares"], ["share-1", "t1-1-share"])
        self.assertNotIn("aggregate_signature", view)

    def test_both_stages_replace_different_slots(self):
        code, view = self.svc.takeover_sign_session_participant(
            "w1", "s1", "t1", 1, "share-1"
        )
        self.assertEqual(code, 201)
        self.assertEqual(view["missing_shares"], ["t1-1-share", "share-2"])
        code, view = self.svc.takeover_sign_session_participant(
            "w1", "s1", "t1", 2, "share-2"
        )
        self.assertEqual(code, 201)
        self.assertEqual(view["missing_shares"], ["t1-1-share", "t1-2-share"])
        events = _takeover_events(self.svc, "w1")
        self.assertEqual([e["details"]["stage"] for e in events], [1, 2])

    def test_stage_replay_same_params_200_same_body(self):
        code, first = self.svc.takeover_sign_session_participant(
            "w1", "s1", "t1", 1, "share-2"
        )
        self.assertEqual(code, 201)
        code, second = self.svc.takeover_sign_session_participant(
            "w1", "s1", "t1", 1, "share-2"
        )
        self.assertEqual(code, 200)
        self.assertEqual(second, first)
        self.assertEqual(len(_takeover_events(self.svc, "w1")), 1)

    def test_stage2_replay_after_both_200(self):
        self.svc.takeover_sign_session_participant(
            "w1", "s1", "t1", 1, "share-1"
        )
        code, view = self.svc.takeover_sign_session_participant(
            "w1", "s1", "t1", 2, "share-2"
        )
        self.assertEqual(code, 201)
        code, replay = self.svc.takeover_sign_session_participant(
            "w1", "s1", "t1", 2, "share-2"
        )
        self.assertEqual(code, 200)
        self.assertEqual(replay, view)
        self.assertEqual(len(_takeover_events(self.svc, "w1")), 2)

    def test_same_stage_different_params_409(self):
        self.svc.takeover_sign_session_participant(
            "w1", "s1", "t1", 1, "share-2"
        )
        with self.assertRaises(ServiceError) as ctx:
            self.svc.takeover_sign_session_participant(
                "w1", "s1", "t1", 1, "share-1"
            )
        self.assertEqual(ctx.exception.status, 409)

    def test_stage2_without_stage1_409(self):
        with self.assertRaises(ServiceError) as ctx:
            self.svc.takeover_sign_session_participant(
                "w1", "s1", "t9", 2, "share-2"
            )
        self.assertEqual(ctx.exception.status, 409)

    def test_stage2_same_slot_as_stage1_old_409(self):
        self.svc.takeover_sign_session_participant(
            "w1", "s1", "t1", 1, "share-2"
        )
        with self.assertRaises(ServiceError) as ctx:
            self.svc.takeover_sign_session_participant(
                "w1", "s1", "t1", 2, "share-2"
            )
        self.assertEqual(ctx.exception.status, 409)

    def test_stage2_targets_stage1_new_share_409(self):
        self.svc.takeover_sign_session_participant(
            "w1", "s1", "t1", 1, "share-2"
        )
        with self.assertRaises(ServiceError) as ctx:
            self.svc.takeover_sign_session_participant(
                "w1", "s1", "t1", 2, "t1-1-share"
            )
        self.assertEqual(ctx.exception.status, 409)

    def test_takeover_id_occupied_by_other_session_409(self):
        self._open("s2")
        self.svc.takeover_sign_session_participant(
            "w1", "s1", "t1", 1, "share-2"
        )
        # 其他会话起同 takeover_id 的 stage 1 / stage 2 均 409
        for stage in (1, 2):
            with self.assertRaises(ServiceError) as ctx:
                self.svc.takeover_sign_session_participant(
                    "w1", "s2", "t1", stage, "share-1"
                )
            self.assertEqual(ctx.exception.status, 409, stage)

    def test_share_id_namespace_collision_with_replace_409(self):
        # 替换 replacement_id="t1-1" 生成 t1-1-share，与接管 stage 1
        # 的新份额 id 冲突：两种先后顺序都必须 409。
        self._open("s2")
        self.svc.replace_sign_session_participant("w1", "s1", "t1-1", "share-2")
        with self.assertRaises(ServiceError) as ctx:
            self.svc.takeover_sign_session_participant(
                "w1", "s2", "t1", 1, "share-2"
            )
        self.assertEqual(ctx.exception.status, 409)
        # 反向：接管先提交，替换占用同一新份额 id 也 409
        self._open("s3")
        self.svc.takeover_sign_session_participant(
            "w1", "s3", "t2", 1, "share-2"
        )
        with self.assertRaises(ServiceError) as ctx:
            self.svc.replace_sign_session_participant(
                "w1", "s2", "t2-1", "share-2"
            )
        self.assertEqual(ctx.exception.status, 409)

    def test_committed_replay_priority_over_terminal_state(self):
        # stage 1 后用新份额 + 另一份完成签名（signed 终态），同阶段重放
        # 仍 200 signed 视图，不因终态 409。
        self.svc.takeover_sign_session_participant(
            "w1", "s1", "t1", 1, "share-2"
        )
        sig_new = self.h.share_signature("w1", "t1-1-share", "s1", "pay-100")
        sig1 = self.h.share_signature("w1", "share-1", "s1", "pay-100")
        code, view = self.svc.submit_sign_session_share(
            "w1", "s1", "t1-1-share", sig_new
        )
        self.assertEqual(code, 201)
        code, view = self.svc.submit_sign_session_share(
            "w1", "s1", "share-1", sig1
        )
        self.assertEqual(code, 201)
        self.assertEqual(view["state"], "signed")
        code, view = self.svc.takeover_sign_session_participant(
            "w1", "s1", "t1", 1, "share-2"
        )
        self.assertEqual(code, 200)
        self.assertEqual(view["state"], "signed")

    # ---- 参数校验 ---------------------------------------------------------

    def test_invalid_ids_400(self):
        for bad in (None, 1, True, "", "a/b", "a b", "x" * 129, 1.5):
            with self.assertRaises(ServiceError) as ctx:
                self.svc.takeover_sign_session_participant(
                    "w1", "s1", bad, 1, "share-2"
                )
            self.assertEqual(ctx.exception.status, 400, repr(bad))
            with self.assertRaises(ServiceError) as ctx:
                self.svc.takeover_sign_session_participant(
                    "w1", "s1", "t1", 1, bad
                )
            self.assertEqual(ctx.exception.status, 400, repr(bad))

    def test_invalid_stage_400(self):
        for bad in (None, 0, 3, -1, True, False, "1", 1.0, 1.5, []):
            with self.assertRaises(ServiceError) as ctx:
                self.svc.takeover_sign_session_participant(
                    "w1", "s1", "t1", bad, "share-2"
                )
            self.assertEqual(ctx.exception.status, 400, repr(bad))

    def test_unknown_wallet_404(self):
        with self.assertRaises(ServiceError) as ctx:
            self.svc.takeover_sign_session_participant(
                "nope", "s1", "t1", 1, "share-2"
            )
        self.assertEqual(ctx.exception.status, 404)

    def test_unknown_session_404(self):
        with self.assertRaises(ServiceError) as ctx:
            self.svc.takeover_sign_session_participant(
                "w1", "nope", "t1", 1, "share-2"
            )
        self.assertEqual(ctx.exception.status, 404)

    def test_target_not_in_use_409(self):
        for target in ("share-3", "t1-1-share", "other"):
            with self.assertRaises(ServiceError) as ctx:
                self.svc.takeover_sign_session_participant(
                    "w1", "s1", "t9", 1, target
                )
            self.assertEqual(ctx.exception.status, 409, target)

    def test_signed_session_409(self):
        for sid in ("share-1", "share-2"):
            sig = self.h.share_signature("w1", sid, "s1", "pay-100")
            self.svc.submit_sign_session_share("w1", "s1", sid, sig)
        with self.assertRaises(ServiceError) as ctx:
            self.svc.takeover_sign_session_participant(
                "w1", "s1", "t1", 1, "share-2"
            )
        self.assertEqual(ctx.exception.status, 409)

    def test_expired_session_409(self):
        self._open("sx", timeout=1)
        self._backdate_expiry("sx")
        with self.assertRaises(ServiceError) as ctx:
            self.svc.takeover_sign_session_participant(
                "w1", "sx", "t1", 1, "share-2"
            )
        self.assertEqual(ctx.exception.status, 409)
        self.assertEqual(self.svc.get_sign_session("w1", "sx")["state"], "expired")

    # ---- 迁移语义 ---------------------------------------------------------

    def test_migration_removes_old_keeps_other(self):
        sig1 = self.h.share_signature("w1", "share-1", "s1", "pay-100")
        self.svc.submit_sign_session_share("w1", "s1", "share-1", sig1)
        code, view = self.svc.takeover_sign_session_participant(
            "w1", "s1", "t1", 1, "share-2"
        )
        self.assertEqual(code, 201)
        self.assertEqual(view["received_shares"], ["share-1"])
        self.assertEqual(view["missing_shares"], ["t1-1-share"])
        self.assertEqual(view["state"], "collecting")

    def test_ready_session_stage1_goes_back_to_collecting(self):
        # cold 策略让齐份会话停在 ready
        self.svc.put_transaction_policy("w1", "cold", 100, ["btc"])
        for sid in ("share-1", "share-2"):
            sig = self.h.share_signature("w1", sid, "s1", "pay-100")
            code, view = self.svc.submit_sign_session_share(
                "w1", "s1", sid, sig
            )
        self.assertEqual(code, 409)
        self.assertEqual(view["state"], "ready")
        code, view = self.svc.takeover_sign_session_participant(
            "w1", "s1", "t1", 1, "share-2"
        )
        self.assertEqual(code, 201)
        self.assertEqual(view["state"], "collecting")
        self.assertEqual(view["received_shares"], ["share-1"])
        self.assertEqual(view["missing_shares"], ["t1-1-share"])

    def test_old_share_submit_400_new_shares_sign(self):
        self.svc.takeover_sign_session_participant(
            "w1", "s1", "t1", 1, "share-1"
        )
        self.svc.takeover_sign_session_participant(
            "w1", "s1", "t1", 2, "share-2"
        )
        for old in ("share-1", "share-2"):
            old_sig = self.h.share_signature("w1", old, "s1", "pay-100")
            with self.assertRaises(ServiceError) as ctx:
                self.svc.submit_sign_session_share("w1", "s1", old, old_sig)
            self.assertEqual(ctx.exception.status, 400, old)
        # 两个新阶段份额按 share_ids 顺序聚合，两半独立验通
        sig1 = self.h.share_signature("w1", "t1-1-share", "s1", "pay-100")
        sig2 = self.h.share_signature("w1", "t1-2-share", "s1", "pay-100")
        code, _ = self.svc.submit_sign_session_share(
            "w1", "s1", "t1-1-share", sig1
        )
        self.assertEqual(code, 201)
        code, view = self.svc.submit_sign_session_share(
            "w1", "s1", "t1-2-share", sig2
        )
        self.assertEqual(code, 201)
        self.assertEqual(view["state"], "signed")
        aggregate = bytes.fromhex(view["aggregate_signature"])
        payload = crypto.build_payload("s1", "pay-100")
        pub1 = bytes.fromhex(
            self.h.store.get_share("w1", "t1-1-share")["public_key"]
        )
        pub2 = bytes.fromhex(
            self.h.store.get_share("w1", "t1-2-share")["public_key"]
        )
        self.assertTrue(crypto.verify_share(pub1, payload, aggregate[:64]))
        self.assertTrue(crypto.verify_share(pub2, payload, aggregate[64:]))

    def test_new_share_uses_existing_gating(self):
        self.svc.put_transaction_policy("w1", "cold", 100, ["btc"])
        self.svc.takeover_sign_session_participant(
            "w1", "s1", "t1", 1, "share-2"
        )
        sig_new = self.h.share_signature("w1", "t1-1-share", "s1", "pay-100")
        sig1 = self.h.share_signature("w1", "share-1", "s1", "pay-100")
        self.svc.submit_sign_session_share("w1", "s1", "t1-1-share", sig_new)
        code, view = self.svc.submit_sign_session_share(
            "w1", "s1", "share-1", sig1
        )
        self.assertEqual(code, 409)
        self.assertEqual(view["state"], "ready")
        self.svc.put_policy("w1", 1, 600)
        self.svc.create_sign_request("w1", "s1", "pay-100")
        self.svc.approve("w1", "s1", "ops")
        code, view = self.svc.submit_sign_session_share(
            "w1", "s1", "share-1", sig1
        )
        self.assertEqual(code, 200)
        self.assertEqual(view["state"], "signed")

    def test_takeover_then_replace_mix(self):
        # stage 1 接管 share-2，再用普通替换接管其新槽位：两类事件按 seq
        # 归并同一条换槽序列，最终快照与恢复均自洽。
        self.svc.takeover_sign_session_participant(
            "w1", "s1", "t1", 1, "share-2"
        )
        code, view = self.svc.replace_sign_session_participant(
            "w1", "s1", "r1", "t1-1-share"
        )
        self.assertEqual(code, 201)
        self.assertEqual(view["missing_shares"], ["share-1", "r1-share"])
        svc2 = WalletService(self.h.store)
        self.assertEqual(
            svc2.get_sign_session("w1", "s1")["missing_shares"],
            ["share-1", "r1-share"],
        )

    def test_stage2_slot_is_positional_across_interleaved_replace(self):
        # stage 1 接管槽位 1（share-2 -> t1-1-share），普通替换把该槽再
        # 换成 r1-share：stage 2 以下线 r1-share 仍是命中同一物理槽位
        # （409）；下线另一槽的 share-1 才合法。
        self.svc.takeover_sign_session_participant(
            "w1", "s1", "t1", 1, "share-2"
        )
        code, _ = self.svc.replace_sign_session_participant(
            "w1", "s1", "r1", "t1-1-share"
        )
        self.assertEqual(code, 201)
        with self.assertRaises(ServiceError) as ctx:
            self.svc.takeover_sign_session_participant(
                "w1", "s1", "t1", 2, "r1-share"
            )
        self.assertEqual(ctx.exception.status, 409)
        code, view = self.svc.takeover_sign_session_participant(
            "w1", "s1", "t1", 2, "share-1"
        )
        self.assertEqual(code, 201)
        self.assertEqual(
            view["missing_shares"], ["t1-2-share", "r1-share"]
        )
        # 重启恢复后快照与事件序列仍自洽
        svc2 = WalletService(self.h.store)
        self.assertEqual(
            svc2.get_sign_session("w1", "s1")["missing_shares"],
            ["t1-2-share", "r1-share"],
        )

    # ---- 阶段份额文件形状 -------------------------------------------------

    def test_stage_share_file_exact_shape(self):
        self.svc.takeover_sign_session_participant(
            "w1", "s1", "t1", 1, "share-2"
        )
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

    def test_max_length_takeover_id(self):
        tid = "t" * 128  # 阶段份额 id 长度恰为 136，仍是合法 share_id
        code, view = self.svc.takeover_sign_session_participant(
            "w1", "s1", tid, 1, "share-2"
        )
        self.assertEqual(code, 201)
        new_id = tid + "-1-share"
        self.assertEqual(len(new_id), 136)
        self.assertEqual(
            view["missing_shares"], ["share-1", new_id]
        )
        svc2 = WalletService(self.h.store)
        self.assertEqual(
            svc2.get_sign_session("w1", "s1")["missing_shares"],
            ["share-1", new_id],
        )
        # 136 字符的新份额可正常投递并完成聚合
        sig_new = self.h.share_signature("w1", new_id, "s1", "pay-100")
        code, _ = svc2.submit_sign_session_share("w1", "s1", new_id, sig_new)
        self.assertEqual(code, 201)
        sig1 = self.h.share_signature("w1", "share-1", "s1", "pay-100")
        code, view = svc2.submit_sign_session_share(
            "w1", "s1", "share-1", sig1
        )
        self.assertEqual(code, 201)
        self.assertEqual(view["state"], "signed")

    # ---- 审计事件 ---------------------------------------------------------

    def test_takeover_event_shape(self):
        self.svc.takeover_sign_session_participant(
            "w1", "s1", "t1", 1, "share-2"
        )
        events = _takeover_events(self.svc, "w1")
        self.assertEqual(len(events), 1)
        event = events[0]
        self.assertEqual(event["request_id"], "s1")
        self.assertIsNone(event["actor_id"])
        self.assertIsNone(event["reason"])
        self.assertEqual(
            event["details"],
            {
                "takeover_id": "t1",
                "stage": 1,
                "old_share_id": "share-2",
                "new_share_id": "t1-1-share",
            },
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
        self.svc.takeover_sign_session_participant(
            "w1", "s1", "t1", 1, "share-2"
        )
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
        self.svc.takeover_sign_session_participant(
            "w1", "s1", "t1", 1, "share-1"
        )
        self.svc.takeover_sign_session_participant(
            "w1", "s1", "t1", 2, "share-2"
        )
        before = _takeover_events(self.svc, "w1")
        svc2 = WalletService(self.h.store)
        self.assertEqual(
            svc2.get_sign_session("w1", "s1")["missing_shares"],
            ["t1-1-share", "t1-2-share"],
        )
        self.assertEqual(_takeover_events(svc2, "w1"), before)

    def test_orphan_stage_share_rolled_back(self):
        # stage 1 已提交；stage 2 份额文件已写但事件未落盘 -> 自愈删除，
        # 可重新提交 stage 2。
        self.svc.takeover_sign_session_participant(
            "w1", "s1", "t1", 1, "share-1"
        )
        key = crypto.generate_share_key("t1-2-share")
        self.h.store.save_share(
            "w1",
            {
                "share_id": "t1-2-share",
                "public_key": key.public_bytes.hex(),
                "private_key": key.private_bytes.hex(),
            },
        )
        svc2 = WalletService(self.h.store)
        self.assertIsNone(self.h.store.get_share("w1", "t1-2-share"))
        code, view = svc2.takeover_sign_session_participant(
            "w1", "s1", "t1", 2, "share-2"
        )
        self.assertEqual(code, 201)
        self.assertEqual(
            view["missing_shares"], ["t1-1-share", "t1-2-share"]
        )

    def test_committed_event_rolls_forward(self):
        # 事件已落盘、会话记录未迁移 -> 自愈前滚迁移
        self.svc.takeover_sign_session_participant(
            "w1", "s1", "t1", 1, "share-2"
        )
        sessions = self._read_sessions()
        sessions["s1"]["share_ids"] = ["share-1", "share-2"]
        self._write_sessions(sessions)
        svc2 = WalletService(self.h.store)
        self.assertEqual(
            svc2.get_sign_session("w1", "s1")["missing_shares"],
            ["share-1", "t1-1-share"],
        )
        self.assertEqual(len(_takeover_events(svc2, "w1")), 1)

    def test_corrupt_stage_share_file_is_503(self):
        self.svc.takeover_sign_session_participant(
            "w1", "s1", "t1", 1, "share-2"
        )
        path = os.path.join(self.d, "shares", "w1", "t1-1-share.json")
        record = json.loads(open(path, encoding="utf-8").read())
        record["private_key"] = "0" * 64
        with open(path, "w", encoding="utf-8") as f:
            json.dump(record, f)
        with self.assertRaises(RecoveryError):
            WalletService(self.h.store)
        self.assertTrue(os.path.exists(path))

    def test_stage2_event_without_stage1_is_503(self):
        # 落盘的接管阶段序列为 [2]（跳号矛盾）：fail-closed 保留现场
        self.svc.takeover_sign_session_participant(
            "w1", "s1", "t1", 1, "share-2"
        )
        with open(self._audit_path(), encoding="utf-8") as f:
            log = json.load(f)
        for event in log["events"]:
            if event["type"] == "session_takeover":
                event["details"]["stage"] = 2
                event["details"]["new_share_id"] = "t1-2-share"
        with open(self._audit_path(), "w", encoding="utf-8") as f:
            json.dump(log, f)
        with self.assertRaises(RecoveryError):
            WalletService(self.h.store)

    def test_two_stages_same_slot_is_503(self):
        # 两条事件阶段连续但替换同一槽位（stage 2 的 old 为 stage 1 的
        # old）：事件序列矛盾，fail-closed。
        self.svc.takeover_sign_session_participant(
            "w1", "s1", "t1", 1, "share-2"
        )
        with open(self._audit_path(), encoding="utf-8") as f:
            log = json.load(f)
        # 手工追加一条 stage 2 事件（seq 连续），old 仍为 share-2
        event = dict(
            next(
                e for e in log["events"]
                if e["type"] == "session_takeover"
            )
        )
        event["seq"] = log["next_seq"]
        event["at"] = "2026-01-01T00:00:00Z"
        event["details"] = {
            "takeover_id": "t1",
            "stage": 2,
            "old_share_id": "share-2",
            "new_share_id": "t1-2-share",
        }
        log["events"].append(event)
        log["next_seq"] += 1
        with open(self._audit_path(), "w", encoding="utf-8") as f:
            json.dump(log, f)
        with self.assertRaises(RecoveryError):
            WalletService(self.h.store)

    def test_two_stages_same_slot_positionally_is_503(self):
        # 两阶段的 old 都在其提交时刻快照内（stage 2 的 old 为 stage 1
        # 换入的 t1-1-share），但位置下标相同：矛盾现场 fail-closed。
        self.svc.takeover_sign_session_participant(
            "w1", "s1", "t1", 1, "share-2"
        )
        # 补齐 stage 2 份额文件（否则缺失文件会先于槽位校验 503）
        key2 = crypto.generate_share_key("t1-2-share")
        self.h.store.save_share(
            "w1",
            {
                "share_id": "t1-2-share",
                "public_key": key2.public_bytes.hex(),
                "private_key": key2.private_bytes.hex(),
            },
        )
        with open(self._audit_path(), encoding="utf-8") as f:
            log = json.load(f)
        event = dict(
            next(
                e for e in log["events"]
                if e["type"] == "session_takeover"
            )
        )
        event["seq"] = log["next_seq"]
        event["at"] = "2026-01-01T00:00:00Z"
        event["details"] = {
            "takeover_id": "t1",
            "stage": 2,
            "old_share_id": "t1-1-share",
            "new_share_id": "t1-2-share",
        }
        log["events"].append(event)
        log["next_seq"] += 1
        with open(self._audit_path(), "w", encoding="utf-8") as f:
            json.dump(log, f)
        with self.assertRaises(RecoveryError):
            WalletService(self.h.store)
        # 现场保留：阶段份额文件不被归一/删除
        self.assertTrue(
            os.path.exists(
                os.path.join(self.d, "shares", "w1", "t1-1-share.json")
            )
        )

    def test_concurrent_stage_only_one_201(self):
        results = []
        lock = threading.Lock()

        def work():
            try:
                code, _ = self.svc.takeover_sign_session_participant(
                    "w1", "s1", "t1", 1, "share-2"
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
        seqs = [
            e["seq"] for e in self.svc.get_audit_events("w1")["events"]
        ]
        self.assertEqual(sorted(seqs), list(range(1, len(seqs) + 1)))

    def test_concurrent_conflicting_ids_one_wins(self):
        results = []
        lock = threading.Lock()

        def work(tid):
            try:
                code, _ = self.svc.takeover_sign_session_participant(
                    "w1", "s1", tid, 1, "share-2"
                )
                with lock:
                    results.append(code)
            except ServiceError as exc:
                with lock:
                    results.append(exc.status)

        threads = [
            threading.Thread(target=work, args=(f"t{i}",))
            for i in range(6)
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(results.count(201), 1)
        self.assertEqual(results.count(409), 5)

    # ---- 与轮换/灾备的交互 ------------------------------------------------

    def test_rotation_after_takeover_decouples_session(self):
        self._open("s2")
        self.svc.takeover_sign_session_participant(
            "w1", "s1", "t1", 1, "share-2"
        )
        self.svc.create_share_rotation("w1", "rot1")
        self.svc.activate_share_rotation("w1", "rot1")
        svc2 = WalletService(self.h.store)
        view = svc2.get_sign_session("w1", "s1")
        self.assertEqual(view["missing_shares"], ["share-1", "t1-1-share"])
        self.assertIsNotNone(self.h.store.get_share("w1", "t1-1-share"))
        view2 = svc2.get_sign_session("w1", "s2")
        self.assertEqual(
            view2["missing_shares"], ["rot1-share-1", "rot1-share-2"]
        )
        sig = self.h.share_signature("w1", "t1-1-share", "s1", "pay-100")
        code, _ = svc2.submit_sign_session_share(
            "w1", "s1", "t1-1-share", sig
        )
        self.assertEqual(code, 201)

    def test_takeover_after_rotation_targets_rotation_share(self):
        self.svc.create_share_rotation("w1", "rot1")
        self.svc.activate_share_rotation("w1", "rot1")
        code, view = self.svc.takeover_sign_session_participant(
            "w1", "s1", "t9", 1, "rot1-share-1"
        )
        self.assertEqual(code, 201)
        self.assertEqual(
            view["missing_shares"], ["t9-1-share", "rot1-share-2"]
        )
        svc2 = WalletService(self.h.store)
        self.assertEqual(
            svc2.get_sign_session("w1", "s1")["missing_shares"],
            ["t9-1-share", "rot1-share-2"],
        )

    def test_backup_restore_with_takeover(self):
        from threshold_wallet import drbackup

        self.svc.takeover_sign_session_participant(
            "w1", "s1", "t1", 1, "share-1"
        )
        self.svc.takeover_sign_session_participant(
            "w1", "s1", "t1", 2, "share-2"
        )
        import tempfile

        out_dir = tempfile.mkdtemp()
        self.addCleanup(lambda: __import__("shutil").rmtree(
            out_dir, ignore_errors=True
        ))
        out = os.path.join(out_dir, "snap.tar")
        result = drbackup.backup(self.d, "w1", "snap-1", out)
        self.assertEqual(result["status"], 201)
        target = tempfile.mkdtemp()
        self.addCleanup(lambda: __import__("shutil").rmtree(
            target, ignore_errors=True
        ))
        status, _ = drbackup.restore(target, "w1", out)
        self.assertEqual(status, 201)
        h2 = make_harness(target)
        self.assertEqual(
            h2.service.get_sign_session("w1", "s1")["missing_shares"],
            ["t1-1-share", "t1-2-share"],
        )
        sig = h2.share_signature("w1", "t1-1-share", "s1", "pay-100")
        code, _ = h2.service.submit_sign_session_share(
            "w1", "s1", "t1-1-share", sig
        )
        self.assertEqual(code, 201)

    # ---- HTTP 端到端 ------------------------------------------------------

    def test_http_end_to_end(self):
        with http_server(self._dir) as server:
            code, _ = server.request(
                "POST", "/v1/wallets", {"wallet_id": "w9", "shares": 2}
            )
            self.assertEqual(code, 201)
            code, _ = server.request(
                "POST",
                "/v1/wallets/w9/sign-sessions",
                {"id": "s1", "message": "m", "timeout_seconds": 600},
            )
            self.assertEqual(code, 201)
            path = "/v1/wallets/w9/sign-sessions/s1/participants/takeover"
            code, view = server.request(
                "POST",
                path,
                {
                    "takeover_id": "t1",
                    "stage": 1,
                    "offline_share_id": "share-2",
                },
            )
            self.assertEqual(code, 201)
            self.assertEqual(view["missing_shares"], ["share-1", "t1-1-share"])
            # 同阶段同参重放 200 同体
            code, replay = server.request(
                "POST",
                path,
                {
                    "takeover_id": "t1",
                    "stage": 1,
                    "offline_share_id": "share-2",
                },
            )
            self.assertEqual(code, 200)
            self.assertEqual(replay, view)
            # 未知会话 404（存在性优先于阶段判定）
            code, _ = server.request(
                "POST",
                "/v1/wallets/w9/sign-sessions/sx/participants/takeover",
                {
                    "takeover_id": "t2",
                    "stage": 2,
                    "offline_share_id": "share-1",
                },
            )
            self.assertEqual(code, 404)
            # 布尔 stage -> 400
            code, _ = server.request(
                "POST",
                path,
                {
                    "takeover_id": "t3",
                    "stage": True,
                    "offline_share_id": "share-2",
                },
            )
            self.assertEqual(code, 400)
            # 多键 -> 400
            code, _ = server.request(
                "POST",
                path,
                {
                    "takeover_id": "t3",
                    "stage": 1,
                    "offline_share_id": "share-2",
                    "extra": 1,
                },
            )
            self.assertEqual(code, 400)
            # 缺键 -> 400
            code, _ = server.request(
                "POST",
                path,
                {"takeover_id": "t3", "stage": 1},
            )
            self.assertEqual(code, 400)
            # 旧 replace 接口多键同样 400
            code, _ = server.request(
                "POST",
                "/v1/wallets/w9/sign-sessions/s1/participants/replace",
                {
                    "replacement_id": "r1",
                    "offline_share_id": "share-1",
                    "extra": 1,
                },
            )
            self.assertEqual(code, 400)
            # stage 2 不同槽位成功
            code, view = server.request(
                "POST",
                path,
                {
                    "takeover_id": "t1",
                    "stage": 2,
                    "offline_share_id": "share-1",
                },
            )
            self.assertEqual(code, 201)
            self.assertEqual(
                view["missing_shares"], ["t1-2-share", "t1-1-share"]
            )
            # 审计事件可查且不含私钥
            code, events = server.request(
                "GET", "/v1/wallets/w9/audit-events"
            )
            self.assertEqual(code, 200)
            kinds = [e["type"] for e in events["events"]]
            self.assertEqual(kinds.count("session_takeover"), 2)
            priv = server.harness.store.get_share("w9", "t1-1-share")[
                "private_key"
            ]
            self.assertNotIn(priv, "".join(server.logs))


if __name__ == "__main__":
    unittest.main()
