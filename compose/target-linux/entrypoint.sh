#!/usr/bin/env bash
# NOTE: no `set -e` — a non-zero here would crash-loop the container and the
# agent would never come up.

# Best-effort enrollment with retry (authd may not be ready when we start).
for i in $(seq 1 30); do
  [ -s /var/ossec/etc/client.keys ] && break
  if /var/ossec/bin/agent-auth -m wazuh.manager -A target-linux; then
    echo "[target] enrolled on attempt $i"
    break
  fi
  echo "[target] enrollment attempt $i failed; retrying in 5s"
  sleep 5
done

/var/ossec/bin/wazuh-control start || echo "[target] wazuh-control start exit $?"

touch /var/ossec/logs/ossec.log
exec tail -F /var/ossec/logs/ossec.log
