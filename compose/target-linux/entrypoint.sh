#!/usr/bin/env bash
set -e

# Enroll (idempotent — skips if a key already exists) then start the agent.
if ! grep -q . /var/ossec/etc/client.keys 2>/dev/null; then
  echo "[target] enrolling with wazuh.manager"
  /var/ossec/bin/agent-auth -m wazuh.manager -A target-linux || \
    echo "[target] agent-auth failed; relying on <enrollment> auto-register"
fi

/var/ossec/bin/wazuh-control start

touch /var/ossec/logs/ossec.log
exec tail -F /var/ossec/logs/ossec.log
