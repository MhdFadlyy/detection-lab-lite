#!/usr/bin/env bash
set -e

# auditd needs the host to share the audit netlink socket (CAP_AUDIT_*). Best-effort:
service auditd start 2>/dev/null || auditd 2>/dev/null || echo "[target] auditd unavailable (kernel audit not shared) — continuing"
augenrules --load 2>/dev/null || true

# Wazuh agent
/var/ossec/bin/wazuh-control start

# keep container alive, stream agent log
touch /var/ossec/logs/ossec.log
exec tail -F /var/ossec/logs/ossec.log
