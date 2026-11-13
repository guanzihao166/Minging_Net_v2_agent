# Minging Net v2 Agent

独立 Linux 节点服务，与 Minging Net 控制台通过版本化 HTTPS 协议通信。

## 协议与控制

VLESS / VMess / Shadowsocks 2022（AES-128 / AES-256 多用户）/ Trojan / WireGuard（用户态）/ Hysteria 2 / TUIC v5。主控下发独立用户凭据；每次连接领取跨服务器共享租约，流量先预留、实际传输后持久结算。未确认的发送窗口保留给管理员核对，预留额度不会虚构成实际流量。

控制通道使用源 IP 白名单、每服务器 256 字符令牌、HMAC 请求签名、时间窗口与持久 nonce 防重放。主控固定 Agent 管理 TLS 证书摘要。主控配置有效期 90 秒，租约与短期字节许可失效后停止转发。代理流量拒绝私有地址、环回与元数据地址，WireGuard 快速转发路径关闭，以保证计量不被绕过。

## 安装与升级

在管理端创建服务器，点击“安装”，在对应服务器 root 终端运行生成的命令。下载凭据 15 分钟有效且绑定服务器 IP；命令只用于对应节点。安装器验证 RSA-SHA256 签名与 SHA256 摘要，校验配置，使用独立非 root 账号启动，等待主控确认健康，失败则恢复前一个二进制和配置。

支持 amd64 / arm64 静态二进制，systemd（Ubuntu / Debian / CentOS 系）和 OpenRC（Alpine）。依赖 curl、CA 证书、openssl、tar、gzip、sha256sum；缺失时只安装这些基础包。所有协议监听端口至少 1024；WireGuard 使用用户态栈，无需 NET_ADMIN。服务使用 160 MiB Go 内存软目标，systemd 额外设置 240 MiB 上限，可按容量规划调整。

私密配置 `/etc/minging-agent/agent.json` 权限 0600；持久计量、证书与加密快照在 `/var/lib/minging-agent`。本地入站 TLS 证书放入 `/etc/minging-agent/tls/default.crt` 与 `default.key`，由运营方续期并重启服务加载。目录归 minging-agent 所有，权限 0700。

轮换令牌后重新运行安装命令。不要删除计量目录；旧的流量预留仍须结算。升级前备份配置和状态；正常停机等待在途传输完成持久结算。查看 `systemctl status minging-agent` 或 `rc-service minging-agent status`；使用 `minging-agent --status` 检查最近主控确认。

## 构建与分发

Go 1.26：`CGO_ENABLED=0 go build -tags with_gvisor ./cmd/agent`。测试：`go test -race -tags with_gvisor ./...`。Linux 持续集成执行全部七种协议 TCP/UDP 实连、配置失败回滚、管理签名重放、崩溃恢复和停机结算测试。

`python scripts/package_release.py --key /private/release-signing.key --output /private/release-output` 生成两个架构、签名清单、安装脚本及带全部 vendor 依赖的对应源码包。签名私钥始终保留仓库外；公钥固定在 `deploy/release-signing.pub`。首次生成公钥后提交，再对干净提交构建正式发行包。维护者应保护并备份签名私钥，换钥时通过可信渠道重新发布安装脚本。

`minging-agent-source.tar.gz` 与二进制在同一受限下载区域提供，使用安装下载凭据访问 `/agent-releases/minging-agent-source.tar.gz`；包含对应版本、构建说明、许可证及 vendored 依赖。它不是配置备份，不含部署秘密。

## 许可证与验收边界

核心固定官方 sing-box v1.14.4。Agent 链接 GPL-3.0-or-later 协议核心，Agent 以同一许可证提供；面板通过独立 HTTP 协议通信。仓库保持私有，源码和许可证仍随二进制向接收者提供。

回环实连与持续集成不替代生产公网、容量和各发行版安装验收。主项目 `docs/ACCEPTANCE.md` 记录实际证据及尚待通过的项目。Shadowrocket 与 V2Ray 的协议能力不同，订阅格式按支持范围输出。
