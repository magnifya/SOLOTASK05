"""共享 data-dir 多进程/多线程交错下的策略线性一致性测试。

覆盖任务契约（同钱包审批策略更新与签名请求创建并发时）：

- 读取、校验、持久化、审计追加必须在同一钱包事务锁内完成；
- 请求单只能采用"锁提交时刻"已生效的 required_approvals 与
  timeout_seconds（req/t0/t1 与 policy_updated/request_created 的
  seq 顺序反映该线性化顺序）；
- 锁内判定仍无审批策略时创建请求返回 409，且不留下请求或事件；
- policy 事件 operation(created|updated) 必须依据锁内旧值。

这里用线程 + 外部持有该钱包的 flock 来确定性地制造交错：服务线程先拿到
进程内 threading.Lock 再阻塞在 flock 上，因而可以精确安排两个竞争操作
的提交顺序。跨进程互斥由同一把 flock 提供（既有
test_recovery.CrossProcessConcurrencyTest 已覆盖），本文件聚焦锁内读取
的判定点。
"""

from __future__ import annotations

import multiprocessing
import os
import tempfile
import threading
import time
import unittest
from datetime import datetime

from tests.helpers import make_harness
from threshold_wallet.flock import FileLock, wallet_lock_path
from threshold_wallet.service import ServiceError, WalletService
from threshold_wallet.store import WalletStore


# ---- 跨进程 worker（模块级，fork 可继承）-----------------------------------


def _mp_put_policy(data_dir, wallet_id, required, timeout, queue):
    from threshold_wallet.service import WalletService
    from threshold_wallet.store import WalletStore as _S

    svc = WalletService(_S(data_dir))
    svc.put_policy(wallet_id, required, timeout)
    queue.put(("put", required, timeout))


def _mp_create_request(data_dir, wallet_id, request_id, message, queue):
    from threshold_wallet.service import ServiceError as _SE, WalletService
    from threshold_wallet.store import WalletStore as _S

    svc = WalletService(_S(data_dir))
    try:
        status, view = svc.create_sign_request(
            wallet_id, request_id, message
        )
        queue.put(("create", status, view))
    except _SE as exc:
        queue.put(("create", exc.status, None))


class _Gate:
    """在测试线程手里持有某钱包的跨进程 flock，把服务事务挡在锁外。"""

    def __init__(self, data_dir: str, wallet_id: str):
        self._lock = FileLock(wallet_lock_path(data_dir, wallet_id))

    def acquire(self) -> "_Gate":
        self._lock.acquire()
        return self

    def release(self) -> None:
        self._lock.release()


class PolicyRequestLinearizationTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.h = make_harness(self.tmp)
        self.svc = self.h.service
        self.svc.create_wallet("w1", 2)

    def _events(self):
        return self.svc.get_audit_events("w1")["events"]

    def test_request_uses_policy_committed_while_it_waited_for_lock(self):
        """请求线程先排队、策略线程在它之前持锁提交：请求必须以该策略
        （req=2, timeout=3600）创建，事件顺序为 P(seq=1) -> C(seq=2)。

        旧实现在锁外读策略并预先判定 409：请求线程会在拿到锁之前直接
        409，永远观察不到等待期间提交的策略。
        """
        gate = _Gate(self.tmp, "w1").acquire()
        holder = {}

        def put_policy():
            holder["result"] = self.svc.put_policy("w1", 2, 3600)

        def create_request():
            holder["status"], holder["view"] = (
                self.svc.create_sign_request("w1", "r1", "pay-100")
            )

        t_policy = threading.Thread(target=put_policy)
        t_request = threading.Thread(target=create_request)
        try:
            # 先让策略线程占到进程内锁并阻塞在 flock 上
            t_policy.start()
            time.sleep(0.2)
            self.assertTrue(t_policy.is_alive())
            # 请求线程随后排队（阻塞在进程内锁后），两者都未提交
            t_request.start()
            time.sleep(0.2)
            self.assertTrue(t_policy.is_alive())
            self.assertTrue(t_request.is_alive())
            # 解锁：策略先提交（created），请求随后在锁内读到该策略
            gate.release()
            t_policy.join(timeout=5)
            t_request.join(timeout=5)
        finally:
            gate.release()

        self.assertFalse(t_policy.is_alive())
        self.assertFalse(t_request.is_alive())
        self.assertEqual(holder["status"], 201, holder)
        view = holder["view"]
        self.assertEqual(view["state"], "pending")
        self.assertEqual(view["req"], 2)
        # t1-t0 必须等于锁提交时生效的 timeout_seconds
        t0 = datetime.fromisoformat(view["t0"].replace("Z", "+00:00"))
        t1 = datetime.fromisoformat(view["t1"].replace("Z", "+00:00"))
        self.assertEqual(int((t1 - t0).total_seconds()), 3600)

        events = self._events()
        self.assertEqual(
            [(e["seq"], e["type"]) for e in events],
            [(1, "policy_updated"), (2, "request_created")],
        )
        self.assertEqual(events[0]["details"]["operation"], "created")
        # 磁盘上的请求单同样采用锁内策略
        on_disk = self.h.store.get_request("w1", "r1")
        self.assertEqual(on_disk["req"], 2)

    def test_policy_operation_reflects_in_lock_old_value(self):
        """两个策略更新排队提交：首设为 created，其后为 updated。

        旧实现在锁外读 old_policy：两个线程都在任一提交前看到 None，会
        错误地各记一条 operation=created。
        """
        gate = _Gate(self.tmp, "w1").acquire()
        holder = {}

        def first():
            holder["first"] = self.svc.put_policy("w1", 2, 3600)

        def second():
            holder["second"] = self.svc.put_policy("w1", 1, 60)

        t_first = threading.Thread(target=first)
        t_second = threading.Thread(target=second)
        try:
            t_first.start()
            time.sleep(0.2)
            t_second.start()
            time.sleep(0.2)
            self.assertTrue(t_first.is_alive())
            self.assertTrue(t_second.is_alive())
            gate.release()
            t_first.join(timeout=5)
            t_second.join(timeout=5)
        finally:
            gate.release()

        self.assertFalse(t_first.is_alive())
        self.assertFalse(t_second.is_alive())
        events = self._events()
        self.assertEqual(len(events), 2)
        self.assertEqual([e["seq"] for e in events], [1, 2])
        self.assertEqual(
            [e["details"]["operation"] for e in events],
            ["created", "updated"],
        )
        # 最终生效值为后提交者
        self.assertEqual(self.h.store.get_policy("w1")["required_approvals"], 1)


class NoPolicyLinearizationTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.h = make_harness(self.tmp)
        self.svc = self.h.service
        self.svc.create_wallet("w1", 2)

    def test_no_policy_returns_409_and_leaves_nothing(self):
        """锁内判定仍无策略：409，且不留下请求或事件。"""
        with self.assertRaises(ServiceError) as caught:
            self.svc.create_sign_request("w1", "r1", "pay-100")
        self.assertEqual(caught.exception.status, 409)
        self.assertIsNone(self.h.store.get_request("w1", "r1"))
        self.assertEqual(self.svc.get_audit_events("w1")["events"], [])

        # 之后设置策略，同 id 首次创建 201，事件 seq 从 1 起（无缺口）
        self.svc.put_policy("w1", 1, 3600)
        status, view = self.svc.create_sign_request("w1", "r1", "pay-100")
        self.assertEqual(status, 201)
        self.assertEqual(view["req"], 1)
        events = self.svc.get_audit_events("w1")["events"]
        self.assertEqual(
            [(e["seq"], e["type"]) for e in events],
            [(1, "policy_updated"), (2, "request_created")],
        )

    def test_replay_remains_idempotent_even_after_policy_removed(self):
        """已有请求单的同文重放保持 200，不复查此刻是否仍有策略。"""
        self.svc.put_policy("w1", 2, 3600)
        status, first = self.svc.create_sign_request("w1", "r1", "m")
        self.assertEqual(status, 201)
        # 策略文件被外部移除（模拟交错后的现场）：同文重放仍 200 同体
        os.unlink(self.h.store._policy_path("w1"))
        status, replay = self.svc.create_sign_request("w1", "r1", "m")
        self.assertEqual(status, 200)
        self.assertEqual(replay["req"], first["req"])
        # 异文仍 409
        with self.assertRaises(ServiceError) as caught:
            self.svc.create_sign_request("w1", "r1", "other")
        self.assertEqual(caught.exception.status, 409)
        # 重放/异文冲突都不新增事件
        types = [
            e["type"] for e in self.svc.get_audit_events("w1")["events"]
        ]
        self.assertEqual(types, ["policy_updated", "request_created"])


class CrossProcessPolicyRequestTest(unittest.TestCase):
    """两个独立 serve 进程在同一 data-dir 上交错更新策略与创建请求。

    无论 flock 先唤醒哪一方，线性化不变量都必须成立：
    - 任一首次创建成功（201）的请求，其 req/t0/t1 必须采用审计序中位于
      它的 request_created 之前最近一条 policy_updated 的策略；
    - 任一 409 都不留下请求或事件；
    - policy_updated 中恰有一条 operation=created，seq 全局连续。
    """

    def setUp(self):
        self.data_dir = tempfile.mkdtemp()
        self.addCleanup(
            __import__("shutil").rmtree, self.data_dir, ignore_errors=True
        )
        self.ctx = multiprocessing.get_context("fork")
        WalletService(WalletStore(self.data_dir)).create_wallet("w1", 2)

    def _collect(self, queue, count, timeout=30):
        return [queue.get(timeout=timeout) for _ in range(count)]

    def test_interleaved_policy_puts_and_request_creates(self):
        # 先首设策略（created），再起多个独立进程并发：2 个策略更新 +
        # 6 个不同 id 的请求创建。flock 唤醒顺序任意，但状态码确定
        # （策略始终存在 => 请求全部 201），线性化不变量按审计序校验。
        seed = WalletService(WalletStore(self.data_dir))
        seed.put_policy("w1", 2, 3600)

        batch_policies = [(1, 60), (2, 7200)]
        plan: list[tuple[str, tuple]] = []
        for required, timeout in batch_policies:
            plan.append(("put", (required, timeout)))
        for request_seq in range(1, 7):
            plan.append(("create", (f"r{request_seq}", "pay")))

        queue = self.ctx.Queue()
        procs = []
        for kind, args in plan:
            if kind == "put":
                required, timeout = args
                target = _mp_put_policy
                t_args = (self.data_dir, "w1", required, timeout, queue)
            else:
                request_id, message = args
                target = _mp_create_request
                t_args = (
                    self.data_dir, "w1", request_id, message, queue
                )
            procs.append(self.ctx.Process(target=target, args=t_args))
        for proc in procs:
            proc.start()
        for proc in procs:
            proc.join(30)
        for proc in procs:
            self.assertEqual(proc.exitcode, 0)

        results = self._collect(queue, len(plan))

        # 审计：恰好一条 created，seq 1..N 连续
        svc = WalletService(WalletStore(self.data_dir))
        events = svc.get_audit_events("w1")["events"]
        self.assertEqual(
            [e["seq"] for e in events], list(range(1, len(events) + 1))
        )
        policy_events = [e for e in events if e["type"] == "policy_updated"]
        self.assertEqual(len(policy_events), 3)
        self.assertEqual(
            [e["details"]["operation"] for e in policy_events],
            ["created", "updated", "updated"],
        )
        self.assertEqual(
            [e["request_id"] is None for e in policy_events],
            [True, True, True],
        )

        # 每个 request_created 之前必有 policy_updated；按审计序建立
        # "该 seq 生效策略" 映射，随后逐个请求核对 req 与 t1-t0。
        effective: dict[int, dict] = {}
        current_policy = None
        for event in events:
            if event["type"] == "policy_updated":
                current_policy = event["details"]
            elif event["type"] == "request_created":
                self.assertIsNotNone(
                    current_policy,
                    "request_created without a preceding policy_updated",
                )
                effective[event["seq"]] = current_policy

        create_results = [
            (kind, status, body)
            for kind, status, body in results
            if kind == "create"
        ]
        self.assertTrue(create_results)
        for kind, status, body in create_results:
            self.assertEqual(status, 201, body)
            rid = body["id"]
            create_events = [
                e for e in events
                if e["type"] == "request_created" and e["request_id"] == rid
            ]
            self.assertEqual(len(create_events), 1, rid)
            pol = effective[create_events[0]["seq"]]
            self.assertEqual(body["req"], pol["required_approvals"], rid)
            t0 = datetime.fromisoformat(body["t0"].replace("Z", "+00:00"))
            t1 = datetime.fromisoformat(body["t1"].replace("Z", "+00:00"))
            self.assertEqual(
                int((t1 - t0).total_seconds()),
                pol["timeout_seconds"],
                rid,
            )
            # 磁盘上的请求单与响应一致采用锁内策略
            on_disk = WalletStore(self.data_dir).get_request("w1", rid)
            self.assertEqual(on_disk["req"], pol["required_approvals"], rid)
            self.assertEqual(on_disk["message"], "pay")


if __name__ == "__main__":
    unittest.main()
