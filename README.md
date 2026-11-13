# Minging Net v2 Agent

独立 Linux 节点服务，与 Minging Net 控制台通过版本化 HTTPS 协议通信。

正在实现：VLESS / VMess / Shadowsocks 2022 / Trojan / WireGuard / Hysteria 2 / TUIC v5，主控统一连接租约与流量额度，持久化重试与原子配置回滚。

核心固定为官方 sing-box v1.14.4。该 Agent 链接 GPL-3.0-or-later 协议核心，因此 Agent 源码与分发遵守同一许可证；面板通过独立 HTTP 协议与之通信。仓库维持私有，内部部署不改变许可义务。

此初始版本尚未完成协议实连验收，具体进度与测试证据随分支提交记录。不得把配置解析成功当作网络连接成功。
