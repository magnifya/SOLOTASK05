"""两方门限签名托管后端。

模块划分：
- crypto:  Ed25519 份额密钥与签名原语（不产生任何完整私钥）
- store:   钱包份额的磁盘持久化
- service: 业务规则（建钱包 / 聚合签名 / 查询）
- server:  HTTP 接口
- cli:     命令行入口
"""

__all__ = ["crypto", "store", "service", "server", "cli"]
__version__ = "0.1.0"
