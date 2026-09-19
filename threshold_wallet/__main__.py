"""支持 python -m threshold_wallet ... 运行 CLI（默认启动 HTTP 服务）。"""

from __future__ import annotations

import sys

from .cli import main

if __name__ == "__main__":
    sys.exit(main())
