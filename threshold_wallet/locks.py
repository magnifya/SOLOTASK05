"""跨进程每钱包事务锁（基于 fcntl.flock 的锁文件）。

多个服务进程可共用同一 data-dir：同一钱包的"状态变更 + 审计事件追加"
必须在跨进程可见的互斥下完成。实现要点：

- 每个钱包对应 ``locks/<sha256(wallet_id)>.lock`` 一个锁文件
  （哈希命名：wallet_id 任意字符串都安全，绝无路径穿越）；
- 用 ``fcntl.flock(LOCK_EX)`` 加锁。锁绑定在打开文件描述上，
  **进程异常退出（崩溃 / kill -9）时内核自动释放**，
  因此不存在"陈旧锁文件阻塞后续进程"的问题——锁文件本身只是
  占位，不需要删除，也不需要记录持有者 pid；
- 同一把锁可被同进程多线程通过外层的 threading.Lock 串行化后
  重入（service 层先拿线程锁再拿文件锁）。
"""

from __future__ import annotations

import fcntl
import hashlib
import os
from collections.abc import Iterator
from contextlib import contextmanager


class WalletLockManager:
    """每钱包一把跨进程文件锁。"""

    def __init__(self, locks_dir: str) -> None:
        self._locks_dir = locks_dir
        os.makedirs(self._locks_dir, exist_ok=True)

    @staticmethod
    def _lock_name(wallet_id: str) -> str:
        digest = hashlib.sha256(wallet_id.encode("utf-8")).hexdigest()
        return digest + ".lock"

    @contextmanager
    def hold(self, wallet_id: str) -> Iterator[None]:
        """持有该钱包的跨进程排他锁（阻塞至获得；进程死亡自动释放）。"""
        path = os.path.join(self._locks_dir, self._lock_name(wallet_id))
        # 锁文件只增不删：删除会与仍在等待的进程产生竞态（旧 fd 锁的是
        # 已 unlink 的 inode），保留空文件无任何副作用。
        fd = os.open(path, os.O_CREAT | os.O_RDWR, 0o600)
        try:
            # 锁文件内容保持为合法 JSON（空对象）：data-dir 下的磁盘审计
            # 会把每个文件当 JSON 解析；内容不参与加锁语义，并发写 "{}"
            # 幂等无害。
            if os.fstat(fd).st_size == 0:
                os.write(fd, b"{}")
            fcntl.flock(fd, fcntl.LOCK_EX)
            yield
        finally:
            try:
                fcntl.flock(fd, fcntl.LOCK_UN)
            finally:
                os.close(fd)
