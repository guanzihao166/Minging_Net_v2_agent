#!/bin/sh
set -eu
umask 077
origin= host= config= token_file= download_source=auto
release_base='@@RELEASE_DOWNLOAD_BASE@@'
phase='检查安装参数'
say() { printf '\n%s\n' "$*"; }
stage() { phase=$2; say "[$1/7] $phase"; }
while [ "$#" -gt 0 ]; do
 case "$1" in
  --origin) origin=$2; shift 2;;
  --host) host=$2; shift 2;;
  --config) config=$2; shift 2;;
  --download-token-file) token_file=$2; shift 2;;
  --download-source) download_source=$2; shift 2;;
  *) echo "Unknown option: $1" >&2; exit 2;;
 esac
done
case "$download_source" in auto|github|controller) ;; *) echo 'Download source must be auto, github or controller.' >&2; exit 2;; esac
stage 1 '检查系统、架构和安装依赖'
[ "$(id -u)" = 0 ] || { echo 'Run installation as root.' >&2; exit 1; }
case "$origin" in https://*) ;; *) echo 'HTTPS controller origin required.' >&2; exit 2;; esac
printf '%s\n' "$origin" | LC_ALL=C grep -Eq '^https://(\[[0-9a-fA-F:]+\]|[a-zA-Z0-9.-]+)(:[0-9]+)?$' || { echo 'Invalid controller origin.' >&2; exit 2; }
if [ -n "$host" ]; then
 printf '%s\n' "$host" | LC_ALL=C grep -Eq '^(\[[0-9a-fA-F:]+\]|[a-zA-Z0-9.-]+)(:[0-9]+)?$' || { echo 'Invalid controller Host.' >&2; exit 2; }
 authority=${origin#https://}
 case "$authority" in
  \[*\]:*) address=${authority#\[}; address=${address%%\]*}; port=${authority##*:};;
  \[*\]) address=${authority#\[}; address=${address%\]}; port=443;;
  *:*) address=${authority%:*}; port=${authority##*:};;
  *) address=$authority; port=443;;
 esac
 case "$host" in \[*\]*) server_name=${host#\[}; server_name=${server_name%%\]*};; *) server_name=${host%%:*};; esac
 case "$address" in *:*) resolve_address="[$address]";; *) resolve_address=$address;; esac
fi
[ -f "$config" ] && [ ! -L "$config" ] && [ -f "$token_file" ] && [ ! -L "$token_file" ] || { echo 'Private configuration and download-token files required.' >&2; exit 2; }
token=$(cat "$token_file")
case "$token" in ''|*[!a-z0-9]*) echo 'Invalid download credential.' >&2; exit 2;; esac
[ "${#token}" -eq 64 ] || exit 2
case "$(uname -s)" in Linux) ;; *) echo 'Linux required.' >&2; exit 2;; esac
case "$(uname -m)" in x86_64|amd64) arch=amd64;; aarch64|arm64) arch=arm64;; *) echo 'Supported architectures: amd64 and arm64.' >&2; exit 2;; esac
if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then init=systemd
elif command -v rc-service >/dev/null 2>&1; then init=openrc
else echo 'An active systemd or OpenRC installation is required.' >&2; exit 2; fi
say "系统：Linux $arch；服务管理：$init；下载策略：$download_source"
missing=
for command in curl openssl tar gzip sha256sum; do
 if ! command -v "$command" >/dev/null 2>&1; then
  case "$command" in sha256sum) missing="$missing coreutils";; *) missing="$missing $command";; esac
 fi
done
need_user=0
if ! command -v useradd >/dev/null 2>&1 && ! command -v adduser >/dev/null 2>&1; then need_user=1; fi
if [ -n "$missing" ] || [ "$need_user" = 1 ]; then
 # Do not replace working curl-minimal/coreutils-single packages on EL systems.
 if command -v apt-get >/dev/null 2>&1; then
  [ "$need_user" != 1 ] || missing="$missing passwd"
  apt-get update && apt-get install -y ca-certificates $missing
 elif command -v dnf >/dev/null 2>&1; then
  [ "$need_user" != 1 ] || missing="$missing shadow-utils"
  dnf install -y ca-certificates $missing
 elif command -v yum >/dev/null 2>&1; then
  [ "$need_user" != 1 ] || missing="$missing shadow-utils"
  yum install -y ca-certificates $missing
 elif command -v apk >/dev/null 2>&1; then apk add --no-cache ca-certificates $missing
 else echo 'Install curl, CA certificates, openssl, tar, gzip and sha256sum first.' >&2; exit 2; fi
fi
base=/opt/minging-agent
for directory in "$base" /etc/minging-agent /var/lib/minging-agent; do
 [ ! -L "$directory" ] || { echo 'Agent directories must not be symlinks.' >&2; exit 1; }
done
mkdir -p "$base/releases"
chmod 755 "$base" "$base/releases"
work=$(mktemp -d "$base/.install.XXXXXXXX")
changed=0 success=0 previous=
service_restart() {
 if [ "$init" = systemd ]; then systemctl daemon-reload; systemctl restart minging-agent
 else rc-service minging-agent restart; fi
}
cleanup() {
 code=$?
 trap - EXIT HUP INT TERM
 if [ "$code" != 0 ]; then
  say "安装未完成：$phase（退出码 $code）。"
  [ "$code" != 130 ] || say '安装已被中断。重新运行安装命令可重试；下载凭据有效期为 15 分钟。'
 fi
 if [ "$changed" = 1 ] && [ "$success" != 1 ]; then
  if [ "$init" = systemd ]; then systemctl stop minging-agent || true; else rc-service minging-agent stop || true; fi
  if [ -n "$previous" ]; then
   ln -sfn "$previous" "$base/current"
   if [ -f "$work/old-config" ]; then
    if ! install_private_file "$work/old-config" /etc/minging-agent/agent.json \
      "$(stat -c %a "$work/old-config")" "$(stat -c %u "$work/old-config")" "$(stat -c %g "$work/old-config")"; then
     echo 'Previous Agent configuration could not be restored.' >&2
     exit "$code"
    fi
   fi
   if [ -f "$work/old-service" ]; then cp "$work/old-service" "$service_file"; fi
   service_restart || true
   echo 'Installation failed; previous binary and configuration restored.' >&2
  else
   if [ "$init" = systemd ]; then systemctl disable minging-agent || true; else rc-update del minging-agent default || true; fi
   echo 'Installation stopped; inspect service logs before retrying.' >&2
  fi
 fi
 case "$work" in /opt/minging-agent/.install.*) rm -rf -- "$work";; esac
 exit "$code"
}
trap cleanup EXIT
trap 'exit 130' HUP INT TERM
printf 'header = "X-Mnet-Install: %s"\n' "$token" > "$work/curl.cfg"
printf 'noproxy = "*"\n' >> "$work/curl.cfg"
if [ -n "$host" ]; then
 # The URL supplies the Host/SNI identity; --resolve pins the TCP destination.
 # Certificate validation stays enabled and no site DNS lookup is performed.
 printf 'resolve = "%s:%s:%s"\nheader = "Host: %s"\n' "$server_name" "$port" "$resolve_address" "$host" >> "$work/curl.cfg"
 origin="https://$host"
fi
unset token
controller_fetch() {
 curl --disable --proto '=https' --tlsv1.2 --connect-timeout 10 --max-time 300 --retry 1 --retry-max-time 330 --speed-limit 1024 --speed-time 25 --config "$work/curl.cfg" --fail --show-error --progress-bar "$origin/agent-releases/$1" -o "$work/$1" --write-out '\n主控下载完成：%{size_download} 字节，平均 %{speed_download} 字节/秒，用时 %{time_total} 秒\n'
}
package_matches() { (cd "$work" && sha256sum -c selected.sum >/dev/null 2>&1); }
github_fetch() {
 # Do not load the controller curl config: neither its installation token nor
 # its Host/resolve settings may follow the public GitHub/CDN request.
 curl --disable --noproxy '*' --proto '=https' --proto-redir '=https' --tlsv1.2 --location --connect-timeout 10 --max-time 180 --retry 1 --retry-max-time 210 --speed-limit 1024 --speed-time 20 --fail --show-error --progress-bar "$release_base/$1" -o "$work/$1" --write-out '\nGitHub 下载结束：%{size_download} 字节，平均 %{speed_download} 字节/秒，用时 %{time_total} 秒\n'
}
cat > "$work/release.pub" <<'MNET_RELEASE_KEY'
@@RELEASE_PUBLIC_KEY@@
MNET_RELEASE_KEY
stage 2 '获取发行清单并验证发布签名'
asset="minging-agent-linux-$arch.tar.gz"
manifest_verified=0
if [ "$download_source" != controller ]; then
 say '正在从 GitHub Release 获取签名清单。'
 if github_fetch SHA256SUMS && github_fetch SHA256SUMS.sig && openssl dgst -sha256 -verify "$work/release.pub" -signature "$work/SHA256SUMS.sig" "$work/SHA256SUMS"; then
  manifest_verified=1
  say 'GitHub 签名清单验证成功。'
 else
  rm -f "$work/SHA256SUMS" "$work/SHA256SUMS.sig"
  say 'GitHub 清单不可用或签名无效。'
  [ "$download_source" != github ] || { echo 'GitHub release manifest verification failed.' >&2; exit 1; }
  say '自动切换到主控获取签名清单。'
 fi
fi
if [ "$manifest_verified" = 0 ]; then
 controller_fetch SHA256SUMS
 controller_fetch SHA256SUMS.sig
 openssl dgst -sha256 -verify "$work/release.pub" -signature "$work/SHA256SUMS.sig" "$work/SHA256SUMS"
fi
awk -v name="$asset" '$2==name {print}' "$work/SHA256SUMS" > "$work/selected.sum"
[ "$(wc -l < "$work/selected.sum")" -eq 1 ] || { echo 'Release checksum missing.' >&2; exit 1; }
stage 3 "下载预编译 Agent（$arch），下方显示实时进度"
downloaded=0
if [ "$download_source" != controller ]; then
 say '正在从 GitHub Release 下载；无需在服务器编译。'
 if github_fetch "$asset" && package_matches; then
  downloaded=1
  say 'GitHub 下载成功，文件摘要与签名清单一致。'
 else
  say 'GitHub 下载失败或文件摘要不匹配。'
  [ "$download_source" != github ] || { echo 'Retry with --download-source controller.' >&2; exit 1; }
  say '自动切换到主控下载。线路较慢时请等待，进度会持续显示。'
 fi
fi
if [ "$downloaded" = 0 ]; then
 if ! controller_fetch "$asset"; then
  say '主控下载失败：请检查网络；HTTP 401 表示下载凭据已过期，请从后台重新获取安装命令。'
  exit 1
 fi
fi
stage 4 '校验安装包、解压并检查配置'
(cd "$work" && sha256sum -c selected.sum)
digest=$(sha256sum "$work/$asset" | cut -d ' ' -f 1)
destination="$base/releases/$digest"
mkdir "$work/package"
tar -xzf "$work/$asset" -C "$work/package"
chmod 755 "$work/package/minging-agent"
"$work/package/minging-agent" --check-config --config "$config"
"$work/package/minging-agent" --version
if [ -e "$destination" ]; then
 [ ! -L "$destination" ] && [ "$(sha256sum "$destination/minging-agent" | cut -d ' ' -f 1)" = "$(sha256sum "$work/package/minging-agent" | cut -d ' ' -f 1)" ] || { echo 'Existing release does not match signed package.' >&2; exit 1; }
else mv "$work/package" "$destination"; fi
chmod 755 "$destination"
if ! id minging-agent >/dev/null 2>&1; then
 if command -v useradd >/dev/null 2>&1; then useradd --system --user-group --home-dir /var/lib/minging-agent --shell /sbin/nologin minging-agent
 else addgroup -S minging-agent; adduser -S -D -H -s /sbin/nologin -G minging-agent minging-agent; fi
fi
[ "$(id -u minging-agent)" != 0 ] || { echo 'Agent must run as a dedicated unprivileged user.' >&2; exit 1; }
config_dir=/etc/minging-agent
config_group=$(id -gn minging-agent)
secure_config_directory() {
 [ ! -L "$1" ] || return 1
 mkdir -p -- "$1" || return 1
 chown -h "root:$config_group" "$1" && chmod 750 "$1"
}
install_private_file() {
 (
  staging=$(mktemp -d "${2%/*}/.install.XXXXXXXX") || exit 1
  trap 'rm -f -- "$staging/file"; rmdir -- "$staging"' EXIT
  install -m "${3:-640}" -o "${4:-root}" -g "${5:-$config_group}" -- "$1" "$staging/file" &&
  mv -fT -- "$staging/file" "$2"
 )
}
secure_config_directory "$config_dir"
secure_config_directory "$config_dir/tls"
for file in "$config_dir/agent.json" "$config_dir/tls/default.crt" "$config_dir/tls/default.key"; do
 [ ! -L "$file" ] || { echo 'Agent configuration and certificates must not be symlinks.' >&2; exit 1; }
 if [ -e "$file" ]; then
  [ -f "$file" ] && [ "$(stat -c %h "$file")" = 1 ] || exit 1
  if [ "$file" != "$config_dir/agent.json" ] && [ "$(stat -c '%u:%g:%a' "$file")" != "0:$(id -g minging-agent):640" ]; then
   install_private_file "$file" "$file"
  fi
 fi
done
mkdir -p /var/lib/minging-agent
chown -h minging-agent:minging-agent /var/lib/minging-agent
chmod 700 /var/lib/minging-agent
if [ -L "$base/current" ]; then previous=$(readlink "$base/current"); case "$previous" in /opt/minging-agent/releases/*) ;; *) echo 'Unexpected current-release link.' >&2; exit 1;; esac; fi
if [ "$init" = systemd ]; then service_file=/etc/systemd/system/minging-agent.service; else service_file=/etc/init.d/minging-agent; fi
if [ -f /etc/minging-agent/agent.json ]; then cp -p /etc/minging-agent/agent.json "$work/old-config"; fi
if [ -f "$service_file" ]; then cp "$service_file" "$work/old-service"; fi
stage 5 '安装服务并启动 Agent'
changed=1
if [ -n "$previous" ]; then
 if [ "$init" = systemd ]; then systemctl stop minging-agent; else rc-service minging-agent stop; fi
fi
install_private_file "$config" "$config_dir/agent.json"
rm -f /var/lib/minging-agent/health.json
ln -sfn "$destination" "$base/current.next"
mv -Tf "$base/current.next" "$base/current"
if [ "$init" = systemd ]; then
 cp "$destination/minging-agent.service" "$service_file"; chmod 644 "$service_file"
 systemctl daemon-reload; systemctl enable minging-agent
else
 cp "$destination/minging-agent.openrc" "$service_file"; chmod 755 "$service_file"
 rc-update add minging-agent default
fi
service_restart
stage 6 '等待主控确认连接健康（最多 30 秒）'
attempt=0
while [ "$attempt" -lt 30 ]; do
 if "$base/current/minging-agent" --status --config /etc/minging-agent/agent.json >/dev/null 2>&1; then success=1; break; fi
 attempt=$((attempt+1))
 if [ "$((attempt % 5))" = 0 ]; then say "仍在等待主控确认：$attempt/30 秒……"; fi
 sleep 1
done
[ "$success" = 1 ] || {
 say '尚未收到主控健康确认，请检查主控 IP、站点域名、令牌和防火墙。'
 if [ "$init" = systemd ]; then say '查看日志：journalctl -u minging-agent -n 50 --no-pager'; else say '查看服务：rc-service minging-agent status'; fi
 exit 1
}
stage 7 '安装完成，主控已确认 Agent 在线'
echo 'Minging Agent installed; controller acknowledgement verified.'
echo 'Configuration: /etc/minging-agent/agent.json (0640); state: /var/lib/minging-agent.'
echo 'Keep the previous release for rollback. Renew local TLS certificates before expiry.'
