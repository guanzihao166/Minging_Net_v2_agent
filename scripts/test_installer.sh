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
install_agent() {
 sh /installer-fixture/install.sh --origin https://127.0.0.1:24560 --config "$1" --download-token-file /installer-fixture/download.token
}
healthy() {
 count=0
 while [ "$count" -lt 20 ]; do
  if /opt/minging-agent/current/minging-agent --status --config /etc/minging-agent/agent.json; then return 0; fi
  count=$((count+1));sleep 1
 done
 return 1
}
install_agent /installer-fixture/agent.json
healthy
original=$(readlink /opt/minging-agent/current)
config_hash=$(sha256sum /etc/minging-agent/agent.json | cut -d ' ' -f1)
[ "$(stat -c %a /etc/minging-agent/agent.json)" = 600 ]
[ "$(stat -c %a /var/lib/minging-agent)" = 700 ]
[ "$(id -u minging-agent)" != 0 ]
install_agent /installer-fixture/agent.json
healthy
[ "$(readlink /opt/minging-agent/current)" = "$original" ]
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
echo 'PASS: full installer, idempotent upgrade, permissions, signature/digest rejection, health rollback and real supervisor lifecycle'
