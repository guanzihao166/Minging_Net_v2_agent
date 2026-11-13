#!/bin/sh
# Runs only inside the disposable Alpine CI container.
set -eu
apk add --no-cache openrc ca-certificates
addgroup -S minging-agent
adduser -S -D -H -s /sbin/nologin -G minging-agent minging-agent
mkdir -p /etc/minging-agent /var/lib/minging-agent /opt/minging-agent/current /run/openrc/exclusive
cp /workspace/.local/runtime/minging-agent-amd64 /opt/minging-agent/current/minging-agent
chmod 755 /opt/minging-agent/current/minging-agent
token=$(printf '%0256d' 0)
printf '{"server_id":1,"controller":"https://example.com","token":"%s","controller_ips":["203.0.113.1/32"]}' "$token" >/etc/minging-agent/agent.json
chown -R minging-agent:minging-agent /etc/minging-agent /var/lib/minging-agent
chmod 700 /etc/minging-agent /var/lib/minging-agent
chmod 600 /etc/minging-agent/agent.json
cp /workspace/deploy/minging-agent.openrc /etc/init.d/minging-agent
chmod 755 /etc/init.d/minging-agent
# A Docker container has a working network but no boot sequence. Initialize the
# lock directory/runlevel and register that already-provided network explicitly.
printf 'default\n' >/run/openrc/softlevel
cat >/etc/init.d/ci-network <<'EOF'
#!/sbin/openrc-run
description="Network already provided by the disposable container"
depend() { provide net; }
start() { return 0; }
stop() { return 0; }
EOF
chmod 755 /etc/init.d/ci-network
rc-update add ci-network default
rc-service ci-network start
/opt/minging-agent/current/minging-agent --check-config
rc-service minging-agent start
sleep 2
rc-service minging-agent status
rc-service minging-agent restart
sleep 2
rc-service minging-agent status
rc-service minging-agent stop
if rc-service minging-agent status; then
  echo 'Agent remained running after OpenRC stop' >&2
  exit 1
fi
