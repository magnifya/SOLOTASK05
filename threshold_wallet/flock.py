"""跨进程每钱包事务锁（fcntl.flock）。

多个服务进程可共用同一 data-dir；对同一钱包的策略、审批单、签名、
份额轮换与审计追加必须在这把锁内串行提交。锁文件为
``locks/<wallet_id>.lock``。

关键性质：
- fcntl.flock 的锁在内核侧随进程退出（含 SIGKILL 等异常崩溃）自动
  释放，因此异常退出后不会留下陈旧锁阻塞后续进程；
- 锁只约束"拿到同一路径锁文件的进程"，配合服务层每钱包一把锁，
  即可让跨进程的状态变更 + 审计追加构成一个事务；
- 锁文件本身不含任何业务数据与私钥材料。
"""

from __future__ import annotations

import fcntl
import os

from .store import _check_id

#: 锁文件在 data_dir 下的子目录名
LOCKS_DIRNAME = "locks"


def wallet_lock_path(data_dir: str, wallet_id: str) -> str:
    """返回某钱包的跨进程锁文件路径；wallet_id 非法时抛 ValueError。"""
    _check_id("wallet_id", wallet_id)
    return os.path.join(data_dir, LOCKS_DIRNAME, wallet_id + ".lock")


class FileLock:
    """一个路径上的排他文件锁（上下文管理器）。

    同进程内可重复进入（每次进入独立打开 fd，成对释放）；跨进程
    互斥由内核 flock 保证。
    """

    def __init__(self, path: str) -> None:
        self._path = path
        self._fd: int | None = None

    @property
    def path(self) -> str:
        return self._path

    def acquire(self) -> "FileLock":
        os.makedirs(os.path.dirname(self._path), exist_ok=True)
        # 每次获取独立打开 fd：flock 跟随 open file description，
        # 进程死亡时内核自动释放，绝不残留陈旧锁。
        fd = os.open(self._path, os.O_RDWR | os.O_CREAT, 0o600)
        try:
            # 锁文件保持为合法 JSON（空对象）：data-dir 内"每个文件均可
            # JSON 解析"的安全审计不变量不因锁文件而破坏；并发同时写
            # 入的内容相同，无竞态危害。
            if os.fstat(fd).st_size == 0:
                os.write(fd, b"{}")
            fcntl.flock(fd, fcntl.LOCK_EX)
        except BaseException:
            os.close(fd)
            raise
        self._fd = fd
        return self

    def release(self) -> None:
        fd, self._fd = self._fd, None
        if fd is None:
            return
        try:
            fcntl.flock(fd, fcntl.LOCK_UN)
        finally:
            os.close(fd)

    def __enter__(self) -> "FileLock":
        return self.acquire()

    def __exit__(self, *exc_info: object) -> None:
        self.release()
