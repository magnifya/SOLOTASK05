"""连续份额轮换（两次及以上）的恢复与历史公钥一致性回归测试。

覆盖本任务修复的缺陷：
- 连续多轮换干净完成后，重启恢复必须存活（旧实现把每个历史 active 轮
  都当作未完成轮换重做前滚，向后一轮已合法删除的份额索要密钥而崩溃）；
- 恢复按审计 seq 建立连续公钥/份额时间线：缺失、重复、乱序、跨轮次
  不相容、事件与记录不一致一律 fail-closed（503/拒绝就绪），绝不猜写；
- 第二轮换 prepared/activating/active 各崩溃点：事件未落盘恢复上一轮
  完整份额与公钥、置回 prepared；事件已落盘前滚为唯一 active 并清理；
- collecting/ready 会话只迁移到最终当前两份份额并可继续完成；signed
  会话冻结创建快照，历史份额同值重放 200、异值 409（跨重启仍成立）；
- 恢复/清理/幂等重放不新增审计事件，seq 连续，不泄露私钥。
"""

from __future__ import annotations

import json
import os
import shutil
import tempfile
import unittest

from tests.helpers import http_server
from threshold_wallet import audit as audit_mod
from threshold_wallet import crypto
from threshold_wallet.audit import AuditStore
from threshold_wallet.service import ServiceError, WalletService
from threshold_wallet.store import RecoveryError, WalletStore


def _service(data_dir: str) -> WalletService:
    return WalletService(WalletStore(data_dir))


def _activate_crash_scene(data_dir: str, rotation_id: str, point: str) -> None:
    """他进程把指定轮换推进到故障点后崩溃（不清理）。

    point:
    - marker：activating 标记 + 旧份额/元数据备份落盘；
    - swap：新份额换入、钱包元数据改、旧份额删除；
    - state：轮换状态写 active，但激活事件未落盘；
    - event：active 状态与 share_rotation_activated 事件均落盘，
      暂存/备份残留未清理。
    """
    store = WalletStore(data_dir)
    record = store.get_rotation("w1", rotation_id)
    wallet = store.get_wallet("w1")
    old_shares = [
        store.get_share("w1", s["share_id"]) for s in wallet["shares"]
    ]
    activating = dict(record)
    activating["state"] = "activating"
    activating["previous_public_key"] = wallet["public_key"]
    store.update_rotation("w1", rotation_id, activating)
    store.save_activation_backups(
        "w1", rotation_id, old_shares, wallet
    )
    if point == "marker":
        return
    new_records = [
        store.get_staging_share("w1", rotation_id, sid)
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
    if point == "swap":
        return
    active = dict(record)
    active["state"] = "active"
    active["previous_public_key"] = wallet["public_key"]
    store.update_rotation("w1", rotation_id, active)
    if point == "state":
        return
    AuditStore(data_dir).append_event(
        "w1",
        {
            "type": audit_mod.TYPE_SHARE_ROTATION_ACTIVATED,
            "at": "2026-09-20T00:00:00Z",
            "request_id": None,
            "actor_id": None,
            "reason": None,
            "details": {
                "rotation_id": rotation_id,
                "share_ids": list(record["share_ids"]),
                "public_key": record["public_key"],
                "previous_public_key": wallet["public_key"],
            },
        },
    )


def _audit_obj(data_dir: str, wallet_id: str = "w1") -> dict:
    with open(
        os.path.join(data_dir, "audit", wallet_id + ".json"), encoding="utf-8"
    ) as f:
        return json.load(f)


def _write_audit(data_dir: str, data: dict, wallet_id: str = "w1") -> None:
    path = os.path.join(data_dir, "audit", wallet_id + ".json")
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f)
    os.replace(tmp, path)


class ConsecutiveRotationRestartTest(unittest.TestCase):
    """连续多次轮换干净完成后跨重启的一致性。"""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)

    def _rotate_n(self, n: int):
        service = _service(self.tmp)
        service.create_wallet("w1", 2)
        pubs = []
        for i in range(1, n + 1):
            rid = f"rot-{i}"
            code, view = service.create_share_rotation("w1", rid)
            self.assertEqual(code, 201)
            pubs.append(view["public_key"])
            code, active = service.activate_share_rotation("w1", rid)
            self.assertEqual(code, 201)
            self.assertEqual(active["state"], "active")
        return service, pubs

    def test_two_rotations_survive_restart(self):
        service, pubs = self._rotate_n(2)
        store = WalletStore(self.tmp)
        wallet = store.get_wallet("w1")
        self.assertEqual(wallet["public_key"], pubs[1])
        self.assertEqual(
            [s["share_id"] for s in wallet["shares"]],
            ["rot-2-share-1", "rot-2-share-2"],
        )
        # 旧实现在此处重启即 RecoveryError（向 rot-2 已删除的 rot-1 份额
        # 索要密钥）。现在必须正常对账到链顶 rot-2。
        restarted = _service(self.tmp)
        wallet = WalletStore(self.tmp).get_wallet("w1")
        self.assertEqual(wallet["public_key"], pubs[1])
        self.assertEqual(
            WalletStore(self.tmp).list_share_files("w1"),
            ["rot-2-share-1", "rot-2-share-2"],
        )
        # 历史记录仍是 active，previous_public_key 链接正确
        rec1 = restarted.get_share_rotation("w1", "rot-1")
        rec2 = restarted.get_share_rotation("w1", "rot-2")
        self.assertEqual(rec1["state"], "active")
        self.assertEqual(rec2["state"], "active")
        self.assertEqual(rec2["public_key"], pubs[1])
        # 二次重启幂等
        _service(self.tmp)

    def test_three_rotations_survive_restart_and_replay(self):
        service, pubs = self._rotate_n(3)
        restarted = _service(self.tmp)
        self.assertEqual(
            WalletStore(self.tmp).get_wallet("w1")["public_key"], pubs[2]
        )
        self.assertEqual(
            WalletStore(self.tmp).list_share_files("w1"),
            ["rot-3-share-1", "rot-3-share-2"],
        )
        # 全部 active 重放均 200，不新增事件
        for i in range(1, 4):
            self.assertEqual(
                restarted.activate_share_rotation("w1", f"rot-{i}")[0], 200
            )
        events = restarted.get_audit_events("w1")["events"]
        self.assertEqual([e["seq"] for e in events], list(range(1, 7)))
        self.assertEqual(
            [e["type"] for e in events],
            ["share_rotation_prepared", "share_rotation_activated"] * 3,
        )

    def test_recovery_adds_no_events_and_keeps_seq_continuous(self):
        self._rotate_n(2)
        events_before = _service(self.tmp).get_audit_events("w1")["events"]
        seqs_before = [e["seq"] for e in events_before]
        restarted = _service(self.tmp)
        # 多次持锁读访问触发懒恢复，也不产生事件
        restarted.get_wallet("w1")
        restarted.get_share_rotation("w1", "rot-1")
        restarted.get_share_rotation("w1", "rot-2")
        events_after = restarted.get_audit_events("w1")["events"]
        self.assertEqual([e["seq"] for e in events_after], seqs_before)


class SecondRotationCrashPointTest(unittest.TestCase):
    """第二轮换各故障点崩溃后，重启恢复的表现。"""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        service = _service(self.tmp)
        service.create_wallet("w1", 2)
        service.create_share_rotation("w1", "rot-1")
        code, self.rot1 = service.activate_share_rotation("w1", "rot-1")
        self.assertEqual(code, 201)
        self.store = WalletStore(self.tmp)
        self.rot1_shares = {
            sid: self.store.get_share("w1", sid)
            for sid in ("rot-1-share-1", "rot-1-share-2")
        }
        service.create_share_rotation("w1", "rot-2")
        self.rot2_prepared = self.store.get_rotation("w1", "rot-2")

    def _restart(self):
        return _service(self.tmp)

    def _assert_rolled_back_to_rot1(self, service):
        store = WalletStore(self.tmp)
        self.assertEqual(store.get_wallet("w1")["public_key"], self.rot1["public_key"])
        self.assertEqual(
            store.list_share_files("w1"),
            ["rot-1-share-1", "rot-1-share-2"],
        )
        for sid, record in self.rot1_shares.items():
            self.assertEqual(store.get_share("w1", sid), record)
            self.assertIsNone(store.get_share("w1", f"rot-2-share-{sid[-1]}"))
        self.assertEqual(
            service.get_share_rotation("w1", "rot-2")["state"], "prepared"
        )

    def test_marker_rolls_back_to_rot1(self):
        _activate_crash_scene(self.tmp, "rot-2", "marker")
        service = self._restart()
        self._assert_rolled_back_to_rot1(service)
        _service(self.tmp)  # 二次重启幂等

    def test_swap_restores_rot1_shares(self):
        _activate_crash_scene(self.tmp, "rot-2", "swap")
        service = self._restart()
        self._assert_rolled_back_to_rot1(service)
        # 暂存新份额保留、可重新激活
        staging = os.path.join(
            self.tmp, "rotation-staging", "w1", "rot-2"
        )
        self.assertEqual(
            sorted(os.listdir(staging)),
            ["rot-2-share-1.json", "rot-2-share-2.json"],
        )
        code, view = service.activate_share_rotation("w1", "rot-2")
        self.assertEqual(code, 201)
        self.assertEqual(view["state"], "active")
        # seq 无缺口、无重复
        events = service.get_audit_events("w1")["events"]
        self.assertEqual([e["seq"] for e in events], [1, 2, 3, 4])

    def test_state_active_without_event_rolls_back(self):
        _activate_crash_scene(self.tmp, "rot-2", "state")
        service = self._restart()
        self._assert_rolled_back_to_rot1(service)
        events = service.get_audit_events("w1")["events"]
        self.assertEqual(
            [e["type"] for e in events],
            [
                "share_rotation_prepared",
                "share_rotation_activated",
                "share_rotation_prepared",
            ],
        )

    def test_event_landed_forwards_to_rot2(self):
        _activate_crash_scene(self.tmp, "rot-2", "event")
        service = self._restart()
        view = service.get_share_rotation("w1", "rot-2")
        self.assertEqual(view["state"], "active")
        store = WalletStore(self.tmp)
        self.assertEqual(store.get_wallet("w1")["public_key"], view["public_key"])
        self.assertEqual(
            store.list_share_files("w1"),
            ["rot-2-share-1", "rot-2-share-2"],
        )
        # rot-1 历史份额已不在磁盘，暂存目录清干净
        self.assertFalse(
            os.path.exists(
                os.path.join(self.tmp, "rotation-staging", "w1", "rot-2")
            )
        )
        # 激活重放 200，不重复记事件
        self.assertEqual(
            service.activate_share_rotation("w1", "rot-2")[0], 200
        )
        events = service.get_audit_events("w1")["events"]
        self.assertEqual(len(events), 4)
        _service(self.tmp)  # 二次重启仍稳定


class CrossRoundCorruptionFailClosedTest(unittest.TestCase):
    """跨轮次矛盾现场一律 fail-closed，绝不猜写或静默服务。"""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        service = _service(self.tmp)
        service.create_wallet("w1", 2)
        service.create_share_rotation("w1", "rot-1")
        service.activate_share_rotation("w1", "rot-1")
        service.create_share_rotation("w1", "rot-2")
        service.activate_share_rotation("w1", "rot-2")

    def _assert_refuses_ready(self):
        with self.assertRaises(RecoveryError):
            _service(self.tmp)

    def test_missing_first_activation_event_fails_closed(self):
        data = _audit_obj(self.tmp)
        data["events"] = [
            e
            for e in data["events"]
            if not (
                e["type"] == "share_rotation_activated"
                and e["details"]["rotation_id"] == "rot-1"
            )
        ]
        _write_audit(self.tmp, data)
        self._assert_refuses_ready()

    def test_duplicate_activation_event_fails_closed(self):
        data = _audit_obj(self.tmp)
        ev = [
            e
            for e in data["events"]
            if e["type"] == "share_rotation_activated"
            and e["details"]["rotation_id"] == "rot-2"
        ][0]
        duplicate = dict(ev)
        duplicate["seq"] = 5
        data["events"].append(duplicate)
        data["next_seq"] = 6
        _write_audit(self.tmp, data)
        self._assert_refuses_ready()

    def test_record_inconsistent_with_event_fails_closed(self):
        store = WalletStore(self.tmp)
        record = store.get_rotation("w1", "rot-1")
        record["public_key"] = store.get_rotation("w1", "rot-2")["public_key"]
        store.update_rotation("w1", "rot-1", record)
        self._assert_refuses_ready()

    def test_committed_activation_without_record_fails_closed(self):
        WalletStore(self.tmp).delete_rotation("w1", "rot-2")
        self._assert_refuses_ready()

    def test_broken_previous_link_fails_closed(self):
        data = _audit_obj(self.tmp)
        rot1_activated = [
            e
            for e in data["events"]
            if e["type"] == "share_rotation_activated"
            and e["details"]["rotation_id"] == "rot-1"
        ][0]
        genesis = rot1_activated["details"]["previous_public_key"]
        for event in data["events"]:
            if (
                event["type"] == "share_rotation_activated"
                and event["details"]["rotation_id"] == "rot-2"
            ):
                event["details"]["previous_public_key"] = genesis
        _write_audit(self.tmp, data)
        self._assert_refuses_ready()

    def test_runtime_dangling_chain_returns_503(self):
        with http_server(self.tmp) as srv:
            status, _ = srv.request("GET", "/v1/wallets/w1")
            self.assertEqual(status, 200)
            # 服务运行期间他进程删除一条已提交轮换记录 -> 链悬空
            WalletStore(self.tmp).delete_rotation("w1", "rot-1")
            status, body = srv.request("GET", "/v1/wallets/w1")
            self.assertEqual(status, 503, body)
            # 503 不泄露私钥
            self.assertNotIn("private", json.dumps(body))


class SessionAcrossConsecutiveRotationsTest(unittest.TestCase):
    """在途会话迁移到最终份额；signed 会话冻结快照、历史重放跨轮次成立。"""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.service = _service(self.tmp)
        self.service.create_wallet("w1", 2)

    def _share_sig(self, share_id: str, session_id: str, message: str) -> str:
        share = WalletStore(self.tmp).get_share("w1", share_id)
        payload = crypto.build_payload(session_id, message)
        return crypto.sign_share(
            bytes.fromhex(share["private_key"]), payload
        ).hex()

    def test_collecting_session_migrates_to_final_shares(self):
        code, _ = self.service.create_sign_session("w1", "sess", "hi", 3600)
        self.assertEqual(code, 201)
        sig = self._share_sig("share-1", "sess", "hi")
        code, view = self.service.submit_sign_session_share(
            "w1", "sess", "share-1", sig
        )
        self.assertEqual(code, 201)
        self.assertEqual(view["received_shares"], ["share-1"])
        # 连续两次轮换
        self.service.create_share_rotation("w1", "rot-1")
        self.service.activate_share_rotation("w1", "rot-1")
        self.service.create_share_rotation("w1", "rot-2")
        self.service.activate_share_rotation("w1", "rot-2")
        # 下次持锁访问迁移到最终当前两份份额，旧已收份额剔除
        view = self.service.get_sign_session("w1", "sess")
        self.assertEqual(view["state"], "collecting")
        self.assertEqual(view["received_shares"], [])
        self.assertEqual(
            sorted(view["missing_shares"]),
            ["rot-2-share-1", "rot-2-share-2"],
        )
        # 旧份额投递一律 400
        with self.assertRaises(ServiceError) as ctx:
            self.service.submit_sign_session_share(
                "w1", "sess", "share-1", sig
            )
        self.assertEqual(ctx.exception.status, 400)
        # 两份新份额可继续投递并完成
        codes = []
        for sid in ("rot-2-share-1", "rot-2-share-2"):
            code, view = self.service.submit_sign_session_share(
                "w1", "sess", sid, self._share_sig(sid, "sess", "hi")
            )
            codes.append(code)
        self.assertEqual(codes, [201, 201])
        self.assertEqual(view["state"], "signed")
        self.assertEqual(len(view["aggregate_signature"]), 256)
        # 重启后严格恢复（经两轮轮换时间线）仍 signed
        restarted = _service(self.tmp)
        view2 = restarted.get_sign_session("w1", "sess")
        self.assertEqual(view2["state"], "signed")
        self.assertEqual(
            view2["aggregate_signature"], view["aggregate_signature"]
        )

    def test_signed_session_historical_replay_after_second_rotation(self):
        # 在 rot-1 快照下完成 signed
        self.service.create_share_rotation("w1", "rot-1")
        self.service.activate_share_rotation("w1", "rot-1")
        self.service.create_sign_session("w1", "sess", "go", 3600)
        sigs = {}
        for sid in ("rot-1-share-1", "rot-1-share-2"):
            sigs[sid] = self._share_sig(sid, "sess", "go")
        code, _ = self.service.submit_sign_session_share(
            "w1", "sess", "rot-1-share-1", sigs["rot-1-share-1"]
        )
        self.assertEqual(code, 201)
        code, view = self.service.submit_sign_session_share(
            "w1", "sess", "rot-1-share-2", sigs["rot-1-share-2"]
        )
        self.assertEqual(code, 201)
        self.assertEqual(view["state"], "signed")
        aggregate = view["aggregate_signature"]
        # 第二轮换后冻结快照：历史份额同值重放 200 同体、异值 409
        self.service.create_share_rotation("w1", "rot-2")
        self.service.activate_share_rotation("w1", "rot-2")
        code, view = self.service.submit_sign_session_share(
            "w1", "sess", "rot-1-share-1", sigs["rot-1-share-1"]
        )
        self.assertEqual(code, 200)
        self.assertEqual(view["aggregate_signature"], aggregate)
        different = self._share_sig("rot-2-share-1", "sess", "go")
        with self.assertRaises(ServiceError) as ctx:
            self.service.submit_sign_session_share(
                "w1", "sess", "rot-1-share-1", different
            )
        self.assertEqual(ctx.exception.status, 409)
        # 当前份额不属于冻结快照 -> 400
        with self.assertRaises(ServiceError) as ctx:
            self.service.submit_sign_session_share(
                "w1", "sess", "rot-2-share-1", different
            )
        self.assertEqual(ctx.exception.status, 400)
        # 重启后历史公钥沿两轮轮换记录链解析，重放仍 200/409
        restarted = _service(self.tmp)
        code, view = restarted.submit_sign_session_share(
            "w1", "sess", "rot-1-share-2", sigs["rot-1-share-2"]
        )
        self.assertEqual(code, 200)
        self.assertEqual(view["aggregate_signature"], aggregate)
        with self.assertRaises(ServiceError) as ctx:
            restarted.submit_sign_session_share(
                "w1", "sess", "rot-1-share-2", different
            )
        self.assertEqual(ctx.exception.status, 409)


if __name__ == "__main__":
    unittest.main()
