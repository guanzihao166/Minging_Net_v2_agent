#!/bin/sh
# Entire script runs in a fresh disposable CI container, using a fixture CA/key.
set -eu
python3 /workspace/scripts/installer_fixture.py prepare
if command -v update-ca-certificates >/dev/null 2>&1; then
 cp /installer-fixture/controller.crt /usr/local/share/ca-certificates/mnet-installer-ci.crt
 update-ca-certificates >/dev/null
else
 cp /installer-fixture/controller.crt /etc/pki/ca-trust/source/anchors/mnet-installer-ci.crt
 update-ca-trust
fi
if command -v rc-service >/dev/null 2>&1; then
 mkdir -p /run/openrc/exclusive
 printf 'default\n' >/run/openrc/softlevel
 cat >/etc/init.d/ci-network <<'EOF'
#!/sbin/openrc-run
depend() { provide net; }
start() { return 0; }
stop() { return 0; }
EOF
 chmod 755 /etc/init.d/ci-network
 rc-update add ci-network default
 rc-service ci-network start
fi
python3 /workspace/scripts/installer_fixture.py serve >/installer-fixture/controller.log 2>&1 &
server_pid=$!
trap 'kill "$server_pid" 2>/dev/null || true' EXIT
sleep 1
# Route only the fixture's public download hostname to its local HTTPS server.
# The installer still uses its independent public curl invocation, with a
# redirect to a CDN fixture; no real GitHub request is made in these tests.
real_curl=$(command -v curl)
mkdir /installer-fixture/bin
printf '#!/bin/sh\nexec "%s" --disable --resolve packages.invalid:24560:127.0.0.1 "$@"\n' "$real_curl" >/installer-fixture/bin/curl
chmod 755 /installer-fixture/bin/curl
PATH=/installer-fixture/bin:$PATH
export PATH
install_agent() {
 sh /installer-fixture/install.sh --origin https://127.0.0.1:24560 --host controller.invalid:24560 --config "$1" --download-token-file /installer-fixture/download.token
}
healthy() {
 count=0
 while [ "$count" -lt 20 ]; do
  if /opt/minging-agent/current/minging-agent --status --config /etc/minging-agent/agent.json; then return 0; fi
  count=$((count+1));sleep 1
 done
 return 1
}
install_agent /installer-fixture/agent.json > /installer-fixture/first-install.log 2>&1 || { cat /installer-fixture/first-install.log; exit 1; }
cat /installer-fixture/first-install.log
[ -f /installer-fixture/public-downloaded ]
[ ! -f /installer-fixture/controller-downloaded ]
grep -F '[3/7]' /installer-fixture/first-install.log
grep -F '[7/7]' /installer-fixture/first-install.log
healthy
original=$(readlink /opt/minging-agent/current)
config_hash=$(sha256sum /etc/minging-agent/agent.json | cut -d ' ' -f1)
[ "$(stat -c %a /etc/minging-agent/agent.json)" = 600 ]
[ "$(stat -c %a /var/lib/minging-agent)" = 700 ]
[ "$(id -u minging-agent)" != 0 ]
install_agent /installer-fixture/agent.json
healthy
[ "$(readlink /opt/minging-agent/current)" = "$original" ]
# A failed public download and a corrupted public asset must both fall back
# to the authenticated controller and preserve the signed digest check.
printf unavailable >/installer-fixture/public-mode
install_agent /installer-fixture/agent.json > /installer-fixture/fallback.log 2>&1 || { cat /installer-fixture/fallback.log; exit 1; }
[ -f /installer-fixture/controller-downloaded ]
grep -F '自动切换到主控下载' /installer-fixture/fallback.log
healthy
rm /installer-fixture/controller-downloaded
printf corrupt >/installer-fixture/public-mode
install_agent /installer-fixture/agent.json
[ -f /installer-fixture/controller-downloaded ]
healthy
printf ok >/installer-fixture/public-mode
sh /installer-fixture/install.sh --origin https://127.0.0.1:24560 --host controller.invalid:24560 --config /installer-fixture/agent.json --download-token-file /installer-fixture/download.token --download-source controller
healthy
cp /installer-fixture/SHA256SUMS.sig /installer-fixture/valid.sig
printf 'tampered-signature' >/installer-fixture/SHA256SUMS.sig
if install_agent /installer-fixture/agent.json; then echo 'Invalid release signature accepted' >&2; exit 1; fi
cp /installer-fixture/valid.sig /installer-fixture/SHA256SUMS.sig
healthy
cp /installer-fixture/minging-agent-linux-amd64.tar.gz /installer-fixture/valid.tar.gz
printf 'tampered-package' >>/installer-fixture/minging-agent-linux-amd64.tar.gz
if install_agent /installer-fixture/agent.json; then echo 'Invalid package digest accepted' >&2; exit 1; fi
cp /installer-fixture/valid.tar.gz /installer-fixture/minging-agent-linux-amd64.tar.gz
healthy
[ ! -f /installer-fixture/credential-leak ]
if install_agent /installer-fixture/unhealthy.json; then echo 'Unhealthy activation accepted' >&2; exit 1; fi
[ "$(readlink /opt/minging-agent/current)" = "$original" ]
[ "$(sha256sum /etc/minging-agent/agent.json | cut -d ' ' -f1)" = "$config_hash" ]
healthy
if command -v systemctl >/dev/null 2>&1; then
 systemctl restart minging-agent;healthy;systemctl stop minging-agent
 if systemctl is-active --quiet minging-agent; then exit 1; fi
else
 rc-service minging-agent restart;healthy;rc-service minging-agent stop
 if rc-service minging-agent status; then exit 1; fi
fi
echo 'PASS: GitHub/CDN download, no credential leakage, fallback on failure/corruption, controller-only override, progress, idempotent upgrade, permissions, signature/digest rejection, health rollback and supervisor lifecycle'
