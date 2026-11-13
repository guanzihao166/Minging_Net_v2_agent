#!/bin/sh
# Runs only inside the disposable Alpine CI container.
set -eu
apk add --no-cache openrc ca-certificates
addgroup -S minging-agent
adduser -S -D -H -s /sbin/nologin -G minging-agent minging-agent
mkdir -p /etc/minging-agent /var/lib/minging-agent /opt/minging-agent/current /run/openrc
cp /workspace/.local/runtime/minging-agent-amd64 /opt/minging-agent/current/minging-agent
chmod 755 /opt/minging-agent/current/minging-agent
token=$(printf '%0256d' 0)
printf '{"server_id":1,"controller":"https://example.com","token":"%s","controller_ips":["203.0.113.1/32"]}' "$token" >/etc/minging-agent/agent.json
chown -R minging-agent:minging-agent /etc/minging-agent /var/lib/minging-agent
chmod 700 /etc/minging-agent /var/lib/minging-agent
chmod 600 /etc/minging-agent/agent.json
cp /workspace/deploy/minging-agent.openrc /etc/init.d/minging-agent
chmod 755 /etc/init.d/minging-agent
touch /run/openrc/softlevel
/opt/minging-agent/current/minging-agent --check-config
rc-service minging-agent start
sleep 2
rc-service minging-agent status
rc-service minging-agent stop
