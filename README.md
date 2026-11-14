# Minging Net v2 Agent

独立 Linux 节点服务，与 Minging Net 控制台通过版本化 HTTPS 协议通信。

## 协议与控制

两套协议核心按入站选择，共用同一计量、租约与出口策略：

- **Xray-core v26.11.9**（VLESS、Trojan）：安全层 TLS / REALITY（含可选 ML-DSA-65 签名）/ none（仅限已启用 VLESS Encryption）；传输 RAW、XHTTP（auto / packet-up / stream-up / stream-one 及 extra）、WebSocket、gRPC、HTTPUpgrade；VLESS Encryption `mlkem768x25519plus`（native / xorpub / random，X25519 或 ML-KEM-768 认证）；流控 `xtls-rprx-vision`。REALITY 仅组合 RAW / XHTTP / gRPC，XHTTP 仅用于 VLESS。
- **sing-box v1.14.4**：VMess（RAW / WebSocket / gRPC，可选 TLS）、Shadowsocks 2022（AES-128 / AES-256 多用户）、WireGuard（用户态）、Hysteria 2（Salamander 混淆、可选 HTTPS 伪装站）、TUIC v5、AnyTLS。

REALITY 可选“拒绝未认证回落”（0.3.0）：入站的 target 改为本机抽象 Unix 套接字上的守卫。REALITY 会把每个连接的 ClientHello 镜像给 target，守卫按 REALITY 服务端相同的规则（TLS 1.3、serverNames、X25519MLKEM768 密钥份额、会话 ID 认证、Short ID 与时间差）复核：未通过的连接直接关闭，不连接真实目标、不转发任何字节；通过的握手照常借用真实目标的握手，之后若 REALITY 再向目标写入数据即切断。目标站点的握手后记录长度等测量值在守卫启动时直接对真实目标测得，伪装特征与未开启时一致。代价是主动探测不再看到真实站点的响应。

管理接口 `POST /v1/reality/probe`（0.3.0）供主控的目标选择器从节点测速：最多 16 个候选并发，每个候选解析一次后握手两次取最快，报告 TLS 版本、ALPN、密钥交换、证书链是否可信、哪些 serverNames 被证书覆盖与证书链字节数；解析到私有、环回或保留地址的目标不会被连接。同一时间只运行一次测速。

主控下发独立用户凭据；每次连接领取跨服务器共享租约，流量先预留、实际传输后持久结算。未确认的发送窗口保留给管理员核对，预留额度不会虚构成实际流量。Xray 连接强制关闭内核 splice 零拷贝，确保 Vision 等路径同样逐块计量。

客户端兼容性（已用真实客户端验证）：Xray v26 REALITY 只接受带 X25519MLKEM768 密钥交换的 ClientHello，Xray 内核客户端与 mihomo（订阅自动带 `support-x25519mlkem768`）可用；sing-box 1.14 的 REALITY 客户端会被拒绝。Xray 26 客户端的 HTTPUpgrade 与 sing-box 服务端不兼容，因此 HTTPUpgrade 只开放给 Xray 承载的协议。VMess 保留在 sing-box，兼容 sing-box 客户端 TLS 下 `auto` 自动降为 `zero` 的行为。

控制通道使用源 IP 白名单、每服务器 256 字符令牌、HMAC 请求签名、时间窗口与持久 nonce 防重放。主控固定 Agent 管理 TLS 证书摘要。主控配置有效期 90 秒，租约与短期字节许可失效后停止转发。代理流量拒绝私有地址、环回与元数据地址，WireGuard 快速转发路径关闭，以保证计量不被绕过。

## 安装与升级

在管理端创建服务器，点击“安装”，在对应服务器 root 终端运行生成的命令。下载凭据 15 分钟有效且绑定服务器 IP；命令只用于对应节点。安装器验证 RSA-SHA256 签名与 SHA256 摘要，校验配置，使用独立非 root 账号启动，等待主控确认健康，失败则恢复前一个二进制和配置。

支持 amd64 / arm64 静态二进制，systemd（Ubuntu / Debian / CentOS 系）和 OpenRC（Alpine）。依赖 curl、CA 证书、openssl、tar、gzip、sha256sum；缺失时只安装这些基础包。所有协议监听端口至少 1024；WireGuard 使用用户态栈，无需 NET_ADMIN。服务使用 160 MiB Go 内存软目标，systemd 额外设置 240 MiB 上限，可按容量规划调整。

私密配置 `/etc/minging-agent/agent.json` 权限 0600；持久计量、证书与加密快照在 `/var/lib/minging-agent`。本地入站 TLS 证书放入 `/etc/minging-agent/tls/default.crt` 与 `default.key`，由运营方续期并重启服务加载。目录归 minging-agent 所有，权限 0700。

轮换令牌后重新运行安装命令。不要删除计量目录；旧的流量预留仍须结算。升级前备份配置和状态；正常停机等待在途传输完成持久结算。查看 `systemctl status minging-agent` 或 `rc-service minging-agent status`；使用 `minging-agent --status` 检查最近主控确认。

## 构建与分发

Go 1.27：`CGO_ENABLED=0 go build -tags with_gvisor ./cmd/agent`。测试：`go test -race -tags with_gvisor ./...`。Linux 持续集成执行协议 TCP/UDP 实连、REALITY / XHTTP / VLESS Encryption 矩阵、额度截断、私有地址拒绝、配置失败回滚、管理签名重放、崩溃恢复和停机结算测试。`MNET_MIHOMO=<mihomo 可执行文件> go test -tags with_gvisor -run TestMihomoInterop ./internal/engine` 用真实 mihomo 客户端验证全部现代组合；加 `with_utls` 标签可额外运行 sing-box REALITY 客户端对照。

`python scripts/package_release.py --key /private/release-signing.key --output /private/release-output` 生成两个架构、签名清单、安装脚本及带全部 vendor 依赖的对应源码包。签名私钥始终保留仓库外；公钥固定在 `deploy/release-signing.pub`。首次生成公钥后提交，再对干净提交构建正式发行包。维护者应保护并备份签名私钥，换钥时通过可信渠道重新发布安装脚本。

`minging-agent-source.tar.gz` 与二进制在同一受限下载区域提供，使用安装下载凭据访问 `/agent-releases/minging-agent-source.tar.gz`；包含对应版本、构建说明、许可证及 vendored 依赖。它不是配置备份，不含部署秘密。

## 许可证与验收边界

核心固定官方 sing-box v1.14.4（GPL-3.0-or-later）与 Xray-core v26.11.9（MPL-2.0，提交 676eaf6）。Agent 整体以 GPL-3.0-or-later 提供，MPL-2.0 部分的源码随对应源码包一并提供；面板通过独立 HTTP 协议通信。仓库保持私有，源码和许可证仍随二进制向接收者提供。

回环实连与持续集成不替代生产公网、容量和各发行版安装验收。主项目 `docs/ACCEPTANCE.md` 记录实际证据及尚待通过的项目。Shadowrocket 与 V2Ray 的协议能力不同，订阅格式按支持范围输出。
