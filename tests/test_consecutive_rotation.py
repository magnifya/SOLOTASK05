"""连续份额轮换（同一钱包两次及以上轮换）的崩溃恢复与历史公钥回归测试。

覆盖任务契约：
- 连续两次以上干净轮换后重启：钱包公钥/share_ids/私钥/轮换记录一致，
  previous_public_key 沿审计链连续，暂存无残留；
- 每次轮换 prepared/activating/active 的崩溃残留在重启或下次持锁访问时
  以 share_rotation_activated 事件为唯一提交点：事件在则前滚为唯一
  active 并清理暂存/备份，事件不在则恢复上一轮完整份额与公钥、置回
  prepared，无法对账则 fail-closed（503/阻止就绪）；
- 恢复按审计 seq 建立连续公钥/份额时间线：断链、重复、事件与记录不一致
  一律 fail-closed，不猜写密钥、不删除有效暂存；
- signed 会话沿用创建快照：历史份额同值重放 200、异值 409；
  collecting/ready 只迁移到最终当前两份并可继续完成；
- 恢复/清理/幂等重放不新增审计事件，seq 连续，无私钥泄漏。
"""

from __future__ import annotations

import json
import os
import shutil
import tempfile
import unittest

from threshold_wallet import audit as audit_mod
from threshold_wallet import crypto
from threshold_wallet.audit import AuditStore
from threshold_wallet.service import WalletService
from threshold_wallet.store import RecoveryError, WalletStore

from tests.helpers import http_server


def _make_service(data_dir: str) -> WalletService:
    return WalletService(WalletStore(data_dir))


def _activate_clean(service: WalletService, rotation_id: str) -> dict:
    status, prepared = service.create_share_rotation("w1", rotation_id)
    assert status == 201
    status, active = service.activate_share_rotation("w1", rotation_id)
    assert status == 201
    assert active["public_key"] == prepared["public_key"]
    assert active["share_ids"] == prepared["share_ids"]
    return active


def _plant_crash(data_dir: str, rotation_id: str, point: str) -> tuple[dict, str]:
    """模拟他进程激活到指定故障点后崩溃（不清理、不记正常事件）。

    point: after_marker / after_swap / after_commit / after_event。
    返回 (prepared 记录, 激活前钱包公钥)。
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
    if point == "after_marker":
        return record, wallet["public_key"]
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
    if point == "after_swap":
        return record, wallet["public_key"]
    active = dict(record)
    active["state"] = "active"
    active["previous_public_key"] = wallet["public_key"]
    store.update_rotation("w1", rotation_id, active)
    if point == "after_commit":
        return record, wallet["public_key"]
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
    return record, wallet["public_key"]


def _assert_wallet_consistent(
    testcase: unittest.TestCase, data_dir: str, expect_pub: str, expect_ids
) -> None:
    store = WalletStore(data_dir)
    wallet = store.get_wallet("w1")
    testcase.assertEqual(wallet["public_key"], expect_pub)
    testcase.assertEqual(
        [s["share_id"] for s in wallet["shares"]], list(expect_ids)
    )
    share_pub = {}
    for sid in expect_ids:
        share = store.get_share("w1", sid)
        testcase.assertIsNotNone(share, sid)
        priv = bytes.fromhex(share["private_key"])
        testcase.assertEqual(
            crypto.public_key_from_private(priv).hex(),
            share["public_key"],
        )
        share_pub[sid] = share["public_key"]
    testcase.assertEqual(
        bytes.fromhex(expect_pub),
        b"".join(bytes.fromhex(share_pub[sid]) for sid in expect_ids),
    )
    on_disk = set(os.listdir(os.path.join(data_dir, "shares", "w1")))
    testcase.assertEqual(on_disk, {sid + ".json" for sid in expect_ids})


class ConsecutiveRotationTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)

    def test_three_clean_rotations_survive_restart(self):
        service = _make_service(self.tmp)
        service.create_wallet("w1", 2)
        genesis = WalletStore(self.tmp).get_wallet("w1")["public_key"]
        act1 = _activate_clean(service, "rot-1")
        act2 = _activate_clean(service, "rot-2")
        act3 = _activate_clean(service, "rot-3")

        # 重启恢复（旧实现在此处误把已淘汰的 rot-1 份额当缺失而 fail-closed）
        service = _make_service(self.tmp)
        view = service.get_share_rotation("w1", "rot-3")
        self.assertEqual(view["state"], "active")
        self.assertEqual(view["public_key"], act3["public_key"])
        _assert_wallet_consistent(
            self, self.tmp, act3["public_key"], act3["share_ids"]
        )
        # previous_public_key 沿审计链连续
        events = AuditStore(self.tmp).list_events("w1")
        activated = [e for e in events if e["type"] == "share_rotation_activated"]
        self.assertEqual(
            [e["details"]["previous_public_key"] for e in activated],
            [genesis, act1["public_key"], act2["public_key"]],
        )
        self.assertEqual([e["seq"] for e in events], list(range(1, 7)))
        # 全部暂存清空
        staging_root = os.path.join(self.tmp, "rotation-staging", "w1")
        self.assertEqual(os.listdir(staging_root), [])

    def test_crash_each_phase_on_second_and_third_rotation(self):
        for point in ("after_marker", "after_swap", "after_commit"):
            with self.subTest(point=point):
                tmp = tempfile.mkdtemp()
                try:
                    service = _make_service(tmp)
                    service.create_wallet("w1", 2)
                    act1 = _activate_clean(service, "rot-1")
                    status, prep2 = service.create_share_rotation("w1", "rot-2")
                    self.assertEqual(status, 201)
                    _plant_crash(tmp, "rot-2", point)

                    # 重启：事件未落盘 -> 回滚 prepared，恢复 rot-1 完整份额
                    service = _make_service(tmp)
                    self.assertEqual(
                        service.get_share_rotation("w1", "rot-2")["state"],
                        "prepared",
                    )
                    _assert_wallet_consistent(
                        self, tmp, act1["public_key"], act1["share_ids"]
                    )
                    # 暂存新份额保留、备份清理，可重新激活
                    staging = os.path.join(
                        tmp, "rotation-staging", "w1", "rot-2"
                    )
                    self.assertEqual(
                        sorted(os.listdir(staging)),
                        [
                            "rot-2-share-1.json",
                            "rot-2-share-2.json",
                        ],
                    )
                    status, act2 = service.activate_share_rotation("w1", "rot-2")
                    self.assertEqual(status, 201)
                    _assert_wallet_consistent(
                        self, tmp, act2["public_key"], act2["share_ids"]
                    )
                    # 再对第三轮换重复一次崩溃/回滚/激活
                    service.create_share_rotation("w1", "rot-3")
                    _plant_crash(tmp, "rot-3", point)
                    service = _make_service(tmp)
                    self.assertEqual(
                        service.get_share_rotation("w1", "rot-3")["state"],
                        "prepared",
                    )
                    _assert_wallet_consistent(
                        self, tmp, act2["public_key"], act2["share_ids"]
                    )
                    status, act3 = service.activate_share_rotation("w1", "rot-3")
                    self.assertEqual(status, 201)
                    _assert_wallet_consistent(
                        self, tmp, act3["public_key"], act3["share_ids"]
                    )
                    events = AuditStore(tmp).list_events("w1")
                    # 每轮换一条 prepared + 一条 activated（重激活不重复
                    # prepared），三轮共 6 条，seq 连续
                    self.assertEqual(
                        [e["seq"] for e in events], list(range(1, 7))
                    )
                    self.assertEqual(
                        [e["type"] for e in events].count(
                            "share_rotation_activated"
                        ),
                        3,
                    )
                finally:
                    shutil.rmtree(tmp, ignore_errors=True)

    def test_committed_crash_forwards_and_cleans_across_rotations(self):
        service = _make_service(self.tmp)
        service.create_wallet("w1", 2)
        act1 = _activate_clean(service, "rot-1")
        service.create_share_rotation("w1", "rot-2")
        prep2, _ = _plant_crash(self.tmp, "rot-2", "after_event")
        staging = os.path.join(self.tmp, "rotation-staging", "w1", "rot-2")
        self.assertTrue(os.path.exists(staging))

        service = _make_service(self.tmp)
        self.assertEqual(
            service.get_share_rotation("w1", "rot-2")["state"], "active"
        )
        self.assertFalse(os.path.exists(staging))
        _assert_wallet_consistent(
            self, self.tmp, prep2["public_key"], prep2["share_ids"]
        )
        # 重放 200，不重复记事件
        self.assertEqual(
            service.activate_share_rotation("w1", "rot-2")[0], 200
        )
        events = AuditStore(self.tmp).list_events("w1")
        self.assertEqual(
            [e["type"] for e in events],
            [
                "share_rotation_prepared",
                "share_rotation_activated",
                "share_rotation_prepared",
                "share_rotation_activated",
            ],
        )

    def test_unrecoverable_second_rotation_fails_closed(self):
        with http_server(self.tmp) as srv:
            srv.request("POST", "/v1/wallets", {"wallet_id": "w1", "shares": 2})
            srv.request(
                "POST", "/v1/wallets/w1/share-rotations", {"rotation_id": "rot-1"}
            )
            srv.request("POST", "/v1/wallets/w1/share-rotations/rot-1/activate")
            srv.request(
                "POST", "/v1/wallets/w1/share-rotations", {"rotation_id": "rot-2"}
            )
            _plant_crash(self.tmp, "rot-2", "after_swap")
            staging = os.path.join(
                self.tmp, "rotation-staging", "w1", "rot-2"
            )
            for name in os.listdir(staging):
                if name.endswith(".bak.json"):
                    os.unlink(os.path.join(staging, name))
            status, body = srv.request("GET", "/v1/wallets/w1")
            self.assertEqual(status, 503)
            self.assertNotIn("private", json.dumps(body))
        # 重启同样阻止就绪
        with self.assertRaises(RecoveryError):
            _make_service(self.tmp)

    def test_broken_previous_public_key_chain_fails_closed(self):
        service = _make_service(self.tmp)
        service.create_wallet("w1", 2)
        _activate_clean(service, "rot-1")
        service.create_share_rotation("w1", "rot-2")
        _plant_crash(self.tmp, "rot-2", "after_event")
        path = os.path.join(self.tmp, "audit", "w1.json")
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        for event in data["events"]:
            if (
                event["type"] == "share_rotation_activated"
                and event["details"]["rotation_id"] == "rot-2"
            ):
                event["details"]["previous_public_key"] = "99" * 64
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f)
        with self.assertRaises(RecoveryError):
            _make_service(self.tmp)

    def test_record_event_mismatch_fails_closed(self):
        service = _make_service(self.tmp)
        service.create_wallet("w1", 2)
        _activate_clean(service, "rot-1")
        service.create_share_rotation("w1", "rot-2")
        _plant_crash(self.tmp, "rot-2", "after_event")
        path = os.path.join(self.tmp, "rotations", "w1.json")
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        data["rot-2"]["public_key"] = "77" * 64
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f)
        with self.assertRaises(RecoveryError):
            _make_service(self.tmp)

    def test_signed_session_history_replay_across_three_rotations(self):
        service = _make_service(self.tmp)
        service.create_wallet("w1", 2)
        act1 = _activate_clean(service, "rot-1")
        store = WalletStore(self.tmp)
        payload = crypto.build_payload("sess-1", "hello")
        signatures = {}
        for sid in act1["share_ids"]:
            private = bytes.fromhex(store.get_share("w1", sid)["private_key"])
            signatures[sid] = crypto.sign_share(private, payload).hex()
        status, _ = service.create_sign_session("w1", "sess-1", "hello", 3600)
        self.assertEqual(status, 201)
        for sid in act1["share_ids"]:
            status, view = service.submit_sign_session_share(
                "w1", "sess-1", sid, signatures[sid]
            )
        self.assertEqual(view["state"], "signed")
        aggregate = view["aggregate_signature"]

        act2 = _activate_clean(service, "rot-2")
        act3 = _activate_clean(service, "rot-3")

        # 重启：严格加载沿时间线解析 rot-1 历史公钥并重验
        service = _make_service(self.tmp)
        view = service.get_sign_session("w1", "sess-1")
        self.assertEqual(view["state"], "signed")
        self.assertEqual(view["aggregate_signature"], aggregate)
        # 历史份额同值重放 200 同体、异值 409
        sid = act1["share_ids"][0]
        status, view = service.submit_sign_session_share(
            "w1", "sess-1", sid, signatures[sid]
        )
        self.assertEqual(status, 200)
        self.assertEqual(view["aggregate_signature"], aggregate)
        forged = crypto.sign_share(b"\x07" * 32, payload).hex()
        with self.assertRaises(Exception) as ctx:
            service.submit_sign_session_share("w1", "sess-1", sid, forged)
        self.assertEqual(ctx.exception.status, 409)
        # 历史份额投递给在途会话一律 400
        status, _ = service.create_sign_session("w1", "sess-2", "yo", 3600)
        self.assertEqual(status, 201)
        with self.assertRaises(Exception) as ctx:
            service.submit_sign_session_share(
                "w1", "sess-2", sid, signatures[sid]
            )
        self.assertEqual(ctx.exception.status, 400)

    def test_inflight_session_migrates_across_multiple_rotations(self):
        service = _make_service(self.tmp)
        service.create_wallet("w1", 2)
        act1 = _activate_clean(service, "rot-1")
        store = WalletStore(self.tmp)
        payload = crypto.build_payload("sess-x", "msg")
        private1 = bytes.fromhex(
            store.get_share("w1", act1["share_ids"][0])["private_key"]
        )
        service.create_sign_session("w1", "sess-x", "msg", 3600)
        service.submit_sign_session_share(
            "w1",
            "sess-x",
            act1["share_ids"][0],
            crypto.sign_share(private1, payload).hex(),
        )
        act2 = _activate_clean(service, "rot-2")
        act3 = _activate_clean(service, "rot-3")
        # 迁移到最终当前两份：旧份额已剔除，会话 collecting 可继续完成
        view = service.get_sign_session("w1", "sess-x")
        self.assertEqual(view["state"], "collecting")
        self.assertEqual(view["received_shares"], [])
        self.assertEqual(view["missing_shares"], list(act3["share_ids"]))

        store = WalletStore(self.tmp)
        for sid in act3["share_ids"]:
            private = bytes.fromhex(store.get_share("w1", sid)["private_key"])
            status, view = service.submit_sign_session_share(
                "w1",
                "sess-x",
                sid,
                crypto.sign_share(private, payload).hex(),
            )
        self.assertEqual(status, 201)
        self.assertEqual(view["state"], "signed")
        # 迁移不删事件：旧份额 share_received 保留，两份新份额各一条，
        # 最后 signed；恢复/迁移本身不产生事件。
        events = AuditStore(self.tmp).list_events("w1")
        session_events = [
            e for e in events if e["type"] == "session_event"
        ]
        self.assertEqual(
            [e["details"]["action"] for e in session_events],
            [
                "created",
                "share_received",
                "share_received",
                "share_received",
                "signed",
            ],
        )
        self.assertTrue(
            all(
                "signature" not in json.dumps(e["details"])
                and "private" not in json.dumps(e)
                for e in session_events
            )
        )


if __name__ == "__main__":
    unittest.main()
