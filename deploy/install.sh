#!/bin/sh
set -eu
umask 077
origin= config= token_file=
while [ "$#" -gt 0 ]; do
 case "$1" in
  --origin) origin=$2; shift 2;;
  --config) config=$2; shift 2;;
  --download-token-file) token_file=$2; shift 2;;
  *) echo "Unknown option: $1" >&2; exit 2;;
 esac
done
[ "$(id -u)" = 0 ] || { echo 'Run installation as root.' >&2; exit 1; }
case "$origin" in https://*) ;; *) echo 'HTTPS controller origin required.' >&2; exit 2;; esac
case "$origin" in *[!a-zA-Z0-9.:/-]*) echo 'Invalid controller origin.' >&2; exit 2;; esac
[ -f "$config" ] && [ ! -L "$config" ] && [ -f "$token_file" ] && [ ! -L "$token_file" ] || { echo 'Private configuration and download-token files required.' >&2; exit 2; }
chmod 600 "$config" "$token_file"
token=$(cat "$token_file")
case "$token" in ''|*[!a-z0-9]*) echo 'Invalid download credential.' >&2; exit 2;; esac
[ "${#token}" -eq 64 ] || exit 2
case "$(uname -s)" in Linux) ;; *) echo 'Linux required.' >&2; exit 2;; esac
case "$(uname -m)" in x86_64|amd64) arch=amd64;; aarch64|arm64) arch=arm64;; *) echo 'Supported architectures: amd64 and arm64.' >&2; exit 2;; esac
if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then init=systemd
elif command -v rc-service >/dev/null 2>&1; then init=openrc
else echo 'An active systemd or OpenRC installation is required.' >&2; exit 2; fi
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
 if [ "$changed" = 1 ] && [ "$success" != 1 ]; then
  if [ "$init" = systemd ]; then systemctl stop minging-agent || true; else rc-service minging-agent stop || true; fi
  if [ -n "$previous" ]; then
   ln -sfn "$previous" "$base/current"
   if [ -f "$work/old-config" ]; then cp "$work/old-config" /etc/minging-agent/agent.json; chown minging-agent:minging-agent /etc/minging-agent/agent.json; chmod 600 /etc/minging-agent/agent.json; fi
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
unset token
fetch() { curl --proto '=https' --tlsv1.2 --connect-timeout 10 --max-time 300 --retry 2 --config "$work/curl.cfg" -fsS "$origin/agent-releases/$1" -o "$work/$1"; }
cat > "$work/release.pub" <<'MNET_RELEASE_KEY'
@@RELEASE_PUBLIC_KEY@@
MNET_RELEASE_KEY
fetch SHA256SUMS
fetch SHA256SUMS.sig
openssl dgst -sha256 -verify "$work/release.pub" -signature "$work/SHA256SUMS.sig" "$work/SHA256SUMS"
asset="minging-agent-linux-$arch.tar.gz"
fetch "$asset"
awk -v name="$asset" '$2==name {print}' "$work/SHA256SUMS" > "$work/selected.sum"
[ "$(wc -l < "$work/selected.sum")" -eq 1 ] || { echo 'Release checksum missing.' >&2; exit 1; }
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
mkdir -p /etc/minging-agent/tls /var/lib/minging-agent
chown minging-agent:minging-agent /etc/minging-agent /etc/minging-agent/tls /var/lib/minging-agent
chmod 700 /etc/minging-agent /etc/minging-agent/tls /var/lib/minging-agent
if [ -L "$base/current" ]; then previous=$(readlink "$base/current"); case "$previous" in /opt/minging-agent/releases/*) ;; *) echo 'Unexpected current-release link.' >&2; exit 1;; esac; fi
if [ "$init" = systemd ]; then service_file=/etc/systemd/system/minging-agent.service; else service_file=/etc/init.d/minging-agent; fi
if [ -f /etc/minging-agent/agent.json ]; then cp /etc/minging-agent/agent.json "$work/old-config"; fi
if [ -f "$service_file" ]; then cp "$service_file" "$work/old-service"; fi
changed=1
if [ -n "$previous" ]; then
 if [ "$init" = systemd ]; then systemctl stop minging-agent; else rc-service minging-agent stop; fi
fi
cp "$config" /etc/minging-agent/agent.json.next
chown minging-agent:minging-agent /etc/minging-agent/agent.json.next
chmod 600 /etc/minging-agent/agent.json.next
mv -f /etc/minging-agent/agent.json.next /etc/minging-agent/agent.json
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
attempt=0
while [ "$attempt" -lt 30 ]; do
 if "$base/current/minging-agent" --status --config /etc/minging-agent/agent.json >/dev/null 2>&1; then success=1; break; fi
 attempt=$((attempt+1)); sleep 1
done
[ "$success" = 1 ] || { echo 'Fresh controller health acknowledgement was not received.' >&2; exit 1; }
echo 'Minging Agent installed; controller acknowledgement verified.'
echo 'Configuration: /etc/minging-agent/agent.json (0600); state: /var/lib/minging-agent.'
echo 'Keep the previous release for rollback. Renew local TLS certificates before expiry.'
