"""审批状态一致性与重启恢复测试。

覆盖任务契约：
- 同 id 同文重放原样返回磁盘中的 pending/approved/rejected/expired/signed，
  重放不改状态、不新增事件；超时 pending 单的 POST 重放仍返回 pending，
  不被临时呈现成 expired；
- 同一 data-dir 重启后审批单、过期结果、签名幂等记录、审计 seq 连续可读；
- sign 提交段任一写入失败都回滚（删签名、恢复 approved）；
- 并发首签 / 并发创建只产生一个首次结果。
"""

from __future__ import annotations

import tempfile
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone

from tests.helpers import make_harness
from threshold_wallet.service import ServiceError


class ReplayStateTest(unittest.TestCase):
    def setUp(self):
        self.h = make_harness(tempfile.mkdtemp())
        self.svc = self.h.service
        self.svc.create_wallet("w1", 2)
        self.svc.put_policy("w1", 1, 3600)

    def _audit_types(self):
        return [e["type"] for e in self.svc.get_audit_events("w1")["events"]]

    def _expire_on_disk(self, rid):
        rec = self.h.store.get_request("w1", rid)
        rec = dict(rec)
        rec["t1"] = (
            datetime.now(timezone.utc) - timedelta(seconds=1)
        ).isoformat().replace("+00:00", "Z")
        self.h.store.update_request("w1", rid, rec)

    def test_replay_returns_pending_as_on_disk(self):
        self.assertEqual(self.svc.create_sign_request("w1", "rp", "m")[0], 201)
        types_before = self._audit_types()
        status, view = self.svc.create_sign_request("w1", "rp", "m")
        self.assertEqual(status, 200)
        self.assertEqual(view["state"], "pending")
        self.assertEqual(self.h.store.get_request("w1", "rp")["state"], "pending")
        self.assertEqual(self._audit_types(), types_before)

    def test_replay_timed_out_pending_is_not_presented_expired(self):
        self.svc.create_sign_request("w1", "rt", "m")
        self._expire_on_disk("rt")
        # POST 重放不是懒过期触发点：原样返回磁盘的 pending
        status, view = self.svc.create_sign_request("w1", "rt", "m")
        self.assertEqual(status, 200)
        self.assertEqual(view["state"], "pending")
        self.assertEqual(self.h.store.get_request("w1", "rt")["state"], "pending")
        # 不记 request_expired
        self.assertNotIn("request_expired", self._audit_types())

    def test_replay_returns_terminal_states_as_on_disk(self):
        # approved
        self.svc.create_sign_request("w1", "ra", "m")
        self.svc.approve("w1", "ra", "alice")
        types_before = self._audit_types()
        status, view = self.svc.create_sign_request("w1", "ra", "m")
        self.assertEqual((status, view["state"]), (200, "approved"))
        self.assertEqual(self._audit_types(), types_before)

        # rejected
        self.svc.create_sign_request("w1", "rr", "m")
        self.svc.reject("w1", "rr", "bob")
        status, view = self.svc.create_sign_request("w1", "rr", "m")
        self.assertEqual((status, view["state"]), (200, "rejected"))

        # expired（已由 GET 持久化到磁盘）
        self.svc.create_sign_request("w1", "re", "m")
        self._expire_on_disk("re")
        self.assertEqual(self.svc.get_sign_request("w1", "re")["state"], "expired")
        status, view = self.svc.create_sign_request("w1", "re", "m")
        self.assertEqual((status, view["state"]), (200, "expired"))

        # signed
        sigs = self.h.two_signatures("w1", "ra", "m")
        self.assertEqual(self.svc.sign("w1", "ra", "m", sigs)[0], 201)
        status, view = self.svc.create_sign_request("w1", "ra", "m")
        self.assertEqual((status, view["state"]), (200, "signed"))


class RestartRecoveryTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.h = make_harness(self.tmp)
        self.svc = self.h.service
        self.svc.create_wallet("w1", 2)
        self.svc.put_policy("w1", 1, 3600)

    def _reopen(self):
        """用同一 data-dir 重启：全新的 store + service（无内存状态）。"""
        return make_harness(self.tmp)

    def _expire_on_disk(self, rid):
        rec = self.h.store.get_request("w1", rid)
        rec = dict(rec)
        rec["t1"] = (
            datetime.now(timezone.utc) - timedelta(seconds=1)
        ).isoformat().replace("+00:00", "Z")
        self.h.store.update_request("w1", rid, rec)

    def test_state_signature_and_seq_survive_restart(self):
        # 重启前：signed 单 + expired 单 + pending 单 + 无策略钱包的签名
        self.svc.create_sign_request("w1", "rs", "m")
        self.svc.approve("w1", "rs", "alice")
        sigs_signed = self.h.two_signatures("w1", "rs", "m")
        code, first = self.svc.sign("w1", "rs", "m", sigs_signed)
        self.assertEqual(code, 201)

        self.svc.create_sign_request("w1", "re", "m")
        self._expire_on_disk("re")
        self.assertEqual(self.svc.get_sign_request("w1", "re")["state"], "expired")

        self.svc.create_sign_request("w1", "rp", "m")

        self.svc.create_wallet("w2", 2)
        sigs_w2 = self.h.two_signatures("w2", "r9", "m")
        self.assertEqual(self.svc.sign("w2", "r9", "m", sigs_w2)[0], 201)

        before = self.svc.get_audit_events("w1")["events"]
        seq_before = [e["seq"] for e in before]
        self.assertEqual(seq_before, list(range(1, len(seq_before) + 1)))
        expired_events_before = [
            e for e in before if e["type"] == "request_expired"
        ]
        n_before = len(before)

        # ---- 重启：同一 data-dir 上全新的 store/service ----
        h2 = self._reopen()
        svc2 = h2.service

        # 审批单各状态连续可读
        self.assertEqual(svc2.get_sign_request("w1", "rs")["state"], "signed")
        self.assertEqual(svc2.get_sign_request("w1", "re")["state"], "expired")
        self.assertEqual(svc2.get_sign_request("w1", "rp")["state"], "pending")

        # 已 expired 单重启后再 GET 不重复记 request_expired
        self.assertEqual(svc2.get_sign_request("w1", "re")["state"], "expired")

        # 签名幂等记录可读：重放 200 且签名与首次一致
        code, replay = svc2.sign(
            "w1", "rs", "m", h2.two_signatures("w1", "rs", "m")
        )
        self.assertEqual(code, 200)
        self.assertEqual(replay["signature"], first["signature"])
        # 无策略钱包的签名幂等同样可读
        code, replay_w2 = svc2.sign(
            "w2", "r9", "m", h2.two_signatures("w2", "r9", "m")
        )
        self.assertEqual(code, 200)
        self.assertEqual(
            replay_w2["signature"],
            self.h.store.get_signature("w2", "r9")["signature"],
        )

        # 审计 seq 连续可读，历史不丢、不重号
        after = svc2.get_audit_events("w1")["events"]
        self.assertEqual([e["seq"] for e in after][:n_before], seq_before)
        expired_events_after = [
            e for e in after if e["type"] == "request_expired"
        ]
        self.assertEqual(len(expired_events_after), len(expired_events_before))

        # 重启后追加事件：seq 接续文件最大值，不覆盖、不跳号
        svc2.put_policy("w1", 2, 7200)
        grown = svc2.get_audit_events("w1")["events"]
        self.assertEqual(
            [e["seq"] for e in grown], list(range(1, len(grown) + 1))
        )
        self.assertEqual(grown[-1]["seq"], n_before + 1)
        self.assertEqual(grown[-1]["type"], "policy_updated")


class SignCommitRollbackTest(unittest.TestCase):
    """sign 提交段任一写入失败：删除本次签名并恢复审批单 approved。"""

    def setUp(self):
        self.h = make_harness(tempfile.mkdtemp())
        self.svc = self.h.service
        self.svc.create_wallet("w1", 2)
        self.svc.put_policy("w1", 1, 3600)
        self.svc.create_sign_request("w1", "r1", "m")
        self.svc.approve("w1", "r1", "alice")

    def test_request_update_failure_rolls_back_signature(self):
        original_update = self.h.store.update_request

        def boom(wallet_id, signing_request_id, record):
            raise OSError("requests disk full")

        sigs = self.h.two_signatures("w1", "r1", "m")
        self.h.store.update_request = boom
        try:
            with self.assertRaises(OSError):
                self.svc.sign("w1", "r1", "m", sigs)
        finally:
            self.h.store.update_request = original_update
        # 无半完成：签名记录被删除，审批单恢复 approved
        self.assertIsNone(self.h.store.get_signature("w1", "r1"))
        self.assertEqual(self.h.store.get_request("w1", "r1")["state"], "approved")
        # 无 request_signed 事件
        types = [e["type"] for e in self.svc.get_audit_events("w1")["events"]]
        self.assertNotIn("request_signed", types)

    def test_signature_write_failure_leaves_nothing(self):
        original_save = self.h.store.save_signature

        def boom(wallet_id, signing_request_id, record):
            raise OSError("signatures disk full")

        sigs = self.h.two_signatures("w1", "r1", "m")
        self.h.store.save_signature = boom
        try:
            with self.assertRaises(OSError):
                self.svc.sign("w1", "r1", "m", sigs)
        finally:
            self.h.store.save_signature = original_save
        self.assertIsNone(self.h.store.get_signature("w1", "r1"))
        self.assertEqual(self.h.store.get_request("w1", "r1")["state"], "approved")

    def test_retry_after_rolled_back_failure_succeeds_once(self):
        # 回滚后允许重试：首签 201，且审批单最终 signed、只有一个签名记录
        original_update = self.h.store.update_request
        attempts = {"n": 0}

        def fail_first_then_ok(wallet_id, signing_request_id, record):
            attempts["n"] += 1
            if attempts["n"] == 1:
                raise OSError("transient")
            return original_update(wallet_id, signing_request_id, record)

        sigs = self.h.two_signatures("w1", "r1", "m")
        self.h.store.update_request = fail_first_then_ok
        with self.assertRaises(OSError):
            self.svc.sign("w1", "r1", "m", sigs)
        self.h.store.update_request = original_update
        code, body = self.svc.sign("w1", "r1", "m", sigs)
        self.assertEqual(code, 201)
        self.assertEqual(self.h.store.get_request("w1", "r1")["state"], "signed")
        # 审批单恢复后重试只补出一条 request_signed
        types = [e["type"] for e in self.svc.get_audit_events("w1")["events"]]
        self.assertEqual(types.count("request_signed"), 1)


class ConcurrentFirstResultTest(unittest.TestCase):
    """并发重放只能产生一个首次结果（一个 201，其余 200 同一签名）。"""

    def setUp(self):
        self.h = make_harness(tempfile.mkdtemp())
        self.svc = self.h.service
        self.svc.create_wallet("w1", 2)
        self.svc.put_policy("w1", 1, 3600)
        self.svc.create_sign_request("w1", "r1", "m")
        self.svc.approve("w1", "r1", "alice")

    def test_concurrent_sign_single_first_result(self):
        def attempt(_):
            sigs = self.h.two_signatures("w1", "r1", "m")
            return self.svc.sign("w1", "r1", "m", sigs)

        with ThreadPoolExecutor(max_workers=8) as pool:
            results = list(pool.map(attempt, range(16)))

        codes = sorted(code for code, _ in results)
        self.assertEqual(codes.count(201), 1, results)
        self.assertEqual(codes.count(200), 15, results)
        signatures = {body["signature"] for _, body in results}
        self.assertEqual(len(signatures), 1)
        # 仅一条签名记录与一个 request_signed 事件
        self.assertIsNotNone(self.h.store.get_signature("w1", "r1"))
        types = [e["type"] for e in self.svc.get_audit_events("w1")["events"]]
        self.assertEqual(types.count("request_signed"), 1)
        self.assertEqual(self.h.store.get_request("w1", "r1")["state"], "signed")

    def test_concurrent_sign_without_policy_single_first_result(self):
        self.svc.create_wallet("w2", 2)

        def attempt(_):
            sigs = self.h.two_signatures("w2", "r9", "m")
            return self.svc.sign("w2", "r9", "m", sigs)

        with ThreadPoolExecutor(max_workers=8) as pool:
            results = list(pool.map(attempt, range(16)))

        codes = sorted(code for code, _ in results)
        self.assertEqual(codes.count(201), 1, results)
        self.assertEqual(codes.count(200), 15, results)
        self.assertEqual(len({b["signature"] for _, b in results}), 1)

    def test_concurrent_create_request_single_201(self):
        def attempt(_):
            return self.svc.create_sign_request("w1", "rc", "m")

        with ThreadPoolExecutor(max_workers=8) as pool:
            results = list(pool.map(attempt, range(16)))

        codes = sorted(code for code, _ in results)
        self.assertEqual(codes.count(201), 1, results)
        self.assertEqual(codes.count(200), 15, results)
        # 只有一个 request_created 事件
        types = [e["type"] for e in self.svc.get_audit_events("w1")["events"]]
        self.assertEqual(types.count("request_created"), 2)  # r1 + rc


class InterleavedReplayTest(unittest.TestCase):
    """首签已落盘签名但事件尚未提交（最终失败回滚）期间，重放不得读到
    半完成签名：它应被每钱包事务锁挡住，回滚后作为新首签 201 成功。"""

    def setUp(self):
        self.h = make_harness(tempfile.mkdtemp())
        self.svc = self.h.service
        self.svc.create_wallet("w1", 2)
        self.svc.put_policy("w1", 1, 3600)
        self.svc.create_sign_request("w1", "r1", "m")
        self.svc.approve("w1", "r1", "alice")

    def test_replay_blocked_until_first_tx_rolls_back(self):
        parked = threading.Event()
        proceed = threading.Event()
        count = {"s": 0}
        real_append = self.svc._audit.append_event

        def gated_emit(wallet_id, event):
            if event.get("type") == "request_signed":
                count["s"] += 1
                if count["s"] == 1:
                    # 签名与审批单已落盘、S 事件尚未提交：把首签卡在这里
                    parked.set()
                    self.assertTrue(proceed.wait(timeout=5))
                    raise OSError("audit disk full")
            return real_append(wallet_id, event)

        self.svc._emit = gated_emit
        first_error = []

        def first_sign():
            try:
                self.svc.sign("w1", "r1", "m", self.h.two_signatures("w1", "r1", "m"))
            except OSError as exc:
                first_error.append(exc)

        t1 = threading.Thread(target=first_sign)
        t1.start()
        self.assertTrue(parked.wait(timeout=5))
        # 此刻首签处于半完成窗口：签名已在盘上、审批单 signed、无 S 事件
        self.assertIsNotNone(self.h.store.get_signature("w1", "r1"))
        self.assertEqual(self.h.store.get_request("w1", "r1")["state"], "signed")

        replay_holder = {}

        def replay():
            replay_holder["result"] = self.svc.sign(
                "w1", "r1", "m", self.h.two_signatures("w1", "r1", "m")
            )

        t2 = threading.Thread(target=replay)
        t2.start()
        # 重放必须被事务锁挡住，而不是立刻读到半完成签名返回 200
        t2.join(timeout=0.2)
        self.assertNotIn("result", replay_holder)

        proceed.set()
        t1.join(timeout=5)
        t2.join(timeout=5)
        self.assertEqual(len(first_error), 1)

        # 回滚后重放作为新首签成功，而非 200 一个随后被删除的签名
        code, body = replay_holder["result"]
        self.assertEqual(code, 201, replay_holder["result"])
        self.assertIsNotNone(self.h.store.get_signature("w1", "r1"))
        self.assertEqual(self.h.store.get_request("w1", "r1")["state"], "signed")
        types = [e["type"] for e in self.svc.get_audit_events("w1")["events"]]
        self.assertEqual(types.count("request_signed"), 1)


class ConcurrentPolicyLinearizationTest(unittest.TestCase):
    """并发更新审批策略 / 创建签名请求的线性一致性。

    无论线程如何交错，落盘后的唯一串行化必须满足：
    - 多个首设并发只有一个 policy_updated 的 operation=created，其余 updated；
    - 每个 request_created 采用其 seq 之前最近一个 policy_updated 已生效的
      required_approvals/timeout_seconds（req/t0/t1 与盘上记录一致）；
    - 锁内判定无策略的 409 不留下请求或事件；事件 seq 连续，
      盘上请求集合恰为 request_created 事件集合。
    """

    def setUp(self):
        self.h = make_harness(tempfile.mkdtemp())
        self.svc = self.h.service
        self.svc.create_wallet("w1", 2)

    def _events(self):
        return self.svc.get_audit_events("w1")["events"]

    def test_concurrent_first_put_yields_single_created(self):
        n = 16
        barrier = threading.Barrier(n)

        def attempt(_):
            barrier.wait()
            return self.svc.put_policy("w1", 1, 3600)

        with ThreadPoolExecutor(max_workers=n) as pool:
            list(pool.map(attempt, range(n)))

        policies = [e for e in self._events() if e["type"] == "policy_updated"]
        self.assertEqual(len(policies), n)
        operations = [e["details"]["operation"] for e in policies]
        self.assertEqual(operations.count("created"), 1, operations)
        self.assertEqual(operations.count("updated"), n - 1, operations)
        # created 必须是 seq 最小的那条（线性化顺序里的第一次提交）
        self.assertEqual(policies[0]["details"]["operation"], "created")
        self.assertTrue(
            all(e["details"]["operation"] == "updated" for e in policies[1:])
        )

    def test_request_binds_policy_at_linearization_point(self):
        n_writers, n_creators = 2, 4
        per_writer, per_creator = 40, 20
        barrier = threading.Barrier(n_writers + n_creators)
        clock = {"i": 0}
        clock_lock = threading.Lock()
        conflicts = []

        def write_policy(_):
            barrier.wait()
            for _ in range(per_writer):
                with clock_lock:
                    clock["i"] += 1
                    timeout = 100 + clock["i"]
                required = 1 if timeout % 2 else 2
                self.svc.put_policy("w1", required, timeout)

        def create_request(idx):
            barrier.wait()
            for k in range(per_creator):
                rid = f"r-{idx}-{k}"
                try:
                    self.svc.create_sign_request("w1", rid, "m")
                except ServiceError as exc:
                    # 仅允许锁内无策略 409，且不留下请求
                    self.assertEqual(exc.status, 409)
                    conflicts.append(rid)

        with ThreadPoolExecutor(max_workers=8) as pool:
            futures = [
                pool.submit(write_policy, i) for i in range(n_writers)
            ]
            futures += [
                pool.submit(create_request, i) for i in range(n_creators)
            ]
            for f in futures:
                f.result()

        events = self._events()
        # seq 连续不重号
        self.assertEqual(
            [e["seq"] for e in events], list(range(1, len(events) + 1))
        )

        # 每个 request_created 必须匹配其线性化时刻（前一个 policy_updated）
        latest_policy = None
        created_ids = []
        for event in events:
            if event["type"] == "policy_updated":
                latest_policy = event["details"]
            elif event["type"] == "request_created":
                self.assertIsNotNone(latest_policy)
                rid = event["request_id"]
                created_ids.append(rid)
                record = self.h.store.get_request("w1", rid)
                self.assertIsNotNone(record, "C 事件必须有对应审批单")
                self.assertEqual(
                    record["req"], latest_policy["required_approvals"]
                )
                t0 = datetime.fromisoformat(record["t0"].replace("Z", "+00:00"))
                t1 = datetime.fromisoformat(record["t1"].replace("Z", "+00:00"))
                self.assertEqual(
                    (t1 - t0).total_seconds(),
                    float(latest_policy["timeout_seconds"]),
                )

        # 盘上请求集合恰为 C 事件集合：409 不留单、重放不重复建
        import json
        import os

        path = os.path.join(self.h.tmpdir, "requests", "w1.json")
        on_disk = json.load(open(path, encoding="utf-8"))
        self.assertEqual(set(on_disk), set(created_ids))
        # 所有 409 冲突 id 都不在盘上、也无事件
        self.assertEqual(set(conflicts) & set(on_disk), set())
        self.assertTrue(
            all(
                e["request_id"] not in conflicts
                for e in events
                if e["type"] == "request_created"
            )
        )


if __name__ == "__main__":
    unittest.main()
