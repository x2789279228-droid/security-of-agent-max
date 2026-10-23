"""
核心资产白名单 (Asset Whitelist)

保护关键基础设施不被响应引擎误封/误隔离。
当 block_ip / isolate_host 等动作的目标 IP 命中白名单时，直接拒绝执行。

白名单来源（优先级从高到低）:
  1. 内置默认保护 —— ⚠ 实测**只有 loopback 一条**
     （docstring 原先写「平台自身组件的 IP/网段」，与实现不符，§9.54）
  2. 环境变量 SHARED_MEMORY_PROTECTED_ASSETS（逗号分隔 IP/CIDR）
  3. 运行时动态添加（API / 管理接口）

调用方式:
    from response_engine.asset_whitelist import asset_whitelist
    blocked, reason = asset_whitelist.check("10.0.0.1", "block_ip")
"""
import ipaddress
import logging
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class ProtectedAsset:
    """受保护资产条目"""
    network: ipaddress.IPv4Network | ipaddress.IPv6Network
    label: str
    source: str = "builtin"  # builtin | env | runtime


# 内置保护列表。
#
# ⚠ 2026-10-20 修正（整改报告 §9.54）：原先这里还有一条
#   ("0.0.0.0/0", "default-route-placeholder", "builtin")，
#   注释写着「仅用于占位，check 中特殊处理」——
#   但 `initialize` 会**直接跳过**它，而 `check()` 里**从来没有**任何
#   0.0.0.0/0 的特殊处理 → 那条注释在**撒谎**（而它正是维护者
#   判断「check 里有没有处理」的唯一依据）。
#   该占位符已删除（死代码）。
#
# ⚠ **实测**：内置默认保护**只有 loopback 一条**。
#   模块 docstring 原先声称这里是「平台自身组件的 IP/网段」——
#   实际并没有（平台自己的 DB/缓存/Kafka 不在保护范围内）→
#   文档承诺落空，登记为**待决项 36**（要不要把平台自身网段加进内置清单）。
#   业务资产靠环境变量 SHARED_MEMORY_PROTECTED_ASSETS 配置。
_BUILTIN_PROTECTED = [
    ("127.0.0.0/8", "loopback", "builtin"),
]


class AssetWhitelist:
    """核心资产白名单"""

    def __init__(self):
        self._assets: list[ProtectedAsset] = []
        self._initialized = False

    def initialize(self, protected_assets_str: str = "", labels_str: str = ""):
        """
        从配置初始化白名单

        Args:
            protected_assets_str: 逗号分隔的 IP/CIDR 列表
            labels_str: 逗号分隔的对应标签（可选）
        """
        self._assets = []

        # 内置保护（排除占位符）
        for cidr, label, source in _BUILTIN_PROTECTED:
            if "placeholder" in label:
                continue
            try:
                net = ipaddress.ip_network(cidr, strict=False)
                self._assets.append(ProtectedAsset(network=net, label=label, source=source))
            except ValueError:
                pass

        # 环境变量 / 配置扩展
        if protected_assets_str:
            ips = [s.strip() for s in protected_assets_str.split(",") if s.strip()]
            labels = [s.strip() for s in labels_str.split(",")] if labels_str else []
            for i, ip_or_cidr in enumerate(ips):
                label = labels[i] if i < len(labels) else f"custom-{i}"
                try:
                    net = ipaddress.ip_network(ip_or_cidr, strict=False)
                    self._assets.append(ProtectedAsset(
                        network=net, label=label, source="env"
                    ))
                except ValueError:
                    logger.warning(f"[AssetWhitelist] Invalid CIDR/IP: {ip_or_cidr}")

        self._initialized = True
        logger.info(
            f"[AssetWhitelist] Initialized with {len(self._assets)} protected assets: "
            f"{[a.label for a in self._assets]}"
        )

    def add_asset(self, ip_or_cidr: str, label: str = "runtime"):
        """运行时动态添加受保护资产"""
        try:
            net = ipaddress.ip_network(ip_or_cidr, strict=False)
            self._assets.append(ProtectedAsset(network=net, label=label, source="runtime"))
            logger.info(f"[AssetWhitelist] Added: {ip_or_cidr} ({label})")
        except ValueError:
            logger.warning(f"[AssetWhitelist] Invalid: {ip_or_cidr}")

    def remove_asset(self, label: str) -> int:
        """按标签移除受保护资产"""
        before = len(self._assets)
        self._assets = [a for a in self._assets if a.label != label]
        removed = before - len(self._assets)
        if removed:
            logger.info(f"[AssetWhitelist] Removed {removed} assets with label '{label}'")
        return removed

    def check(self, target_ip: str, action_name: str = "") -> tuple[bool, str]:
        """
        检查目标 IP 是否为受保护资产

        Args:
            target_ip: 目标 IP 地址
            action_name: 动作名称（用于日志）

        Returns:
            (is_protected, reason)
            is_protected=True 表示该 IP 受保护，应拒绝操作
        """
        if not self._initialized:
            self.initialize()

        if not target_ip:
            return False, ""

        try:
            addr = ipaddress.ip_address(target_ip)
        except ValueError:
            return False, ""

        for asset in self._assets:
            if addr in asset.network:
                reason = (
                    f"目标 {target_ip} 命中受保护资产 '{asset.label}' "
                    f"({asset.network}, source={asset.source})，"
                    f"拒绝执行 {action_name or '该操作'}"
                )
                logger.warning(f"[AssetWhitelist] PROTECTED: {reason}")
                return True, reason

        return False, ""

    def list_assets(self) -> list[dict]:
        """列出所有受保护资产"""
        return [
            {
                "network": str(a.network),
                "label": a.label,
                "source": a.source,
            }
            for a in self._assets
        ]


asset_whitelist = AssetWhitelist()
