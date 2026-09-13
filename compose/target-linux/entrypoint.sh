#!/usr/bin/env bash
# NOTE: no `set -e` — a non-zero here would crash-loop the container and the
# agent would never come up.

AGENT_NAME="${AGENT_NAME:-target-linux}"

# Second victim host (SSHD_ENABLE=yes): a lab-only lateral-movement target.
# Same image as target-linux, just also runs sshd with one known-bad password
# (same "seed one deterministic credential" trick as Cowrie's userdb.txt) so
# the pivot scenario doesn't depend on guessing real host config.
if [ "${SSHD_ENABLE:-no}" = "yes" ]; then
  id pivot >/dev/null 2>&1 || useradd -m -s /bin/bash pivot
  echo "pivot:${SSHD_PIVOT_PASSWORD:-pivotpass123}" | chpasswd
  mkdir -p /home/pivot/incoming && chown pivot:pivot /home/pivot/incoming
  mkdir -p /var/run/sshd
  /usr/sbin/sshd
fi

# Best-effort enrollment with retry (authd may not be ready when we start).
for i in $(seq 1 30); do
  [ -s /var/ossec/etc/client.keys ] && break
  if /var/ossec/bin/agent-auth -m wazuh.manager -A "$AGENT_NAME"; then
    echo "[target] enrolled as $AGENT_NAME on attempt $i"
    break
  fi
  echo "[target] enrollment attempt $i failed; retrying in 5s"
  sleep 5
done

/var/ossec/bin/wazuh-control start || echo "[target] wazuh-control start exit $?"

touch /var/ossec/logs/ossec.log
exec tail -F /var/ossec/logs/ossec.log
