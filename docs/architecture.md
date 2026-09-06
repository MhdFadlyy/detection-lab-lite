# Architecture

```
attacks/scenarios/*.yml ──► target-linux (Wazuh agent — FIM / inotify)
                            suricata (host NIC)   cowrie / opencanary
                                   │ logs                     │ eBPF syscalls (pid: host)
                    ┌──────────────┴───────────────┐          ▼
                    ▼                              ▼       Falco ─► /tmp/falco_events.json
          Wazuh (manager / indexer / dashboard) ◄─┘
                    │  alerts API
                    ▼
              harness/verify.py  — engine: wazuh → indexer query
                                   engine: falco → read Falco events file
              harness/report.py  — ATT&CK Navigator layer + coverage.md
              Grafana            — "SOC overview" dashboard
```

## Two detection engines

| Engine | Source | Covers | How `verify.py` checks it |
|---|---|---|---|
| **Wazuh FIM** (`syscheck`) | agent inotify on `target-linux` | file changes: systemd units, cron, `authorized_keys`, `/etc/passwd` | query `wazuh-alerts-*` in the indexer for `rule.id` |
| **Falco** | eBPF syscalls from the host kernel | process exec, sensitive file reads, outbound net | read `/tmp/falco_events.json` in the Falco container for `rule` name |

auditd is deliberately **not** used — the kernel audit subsystem is a single host-owned
context that cannot be scoped to a container.

## Why Docker only

On a Linux host, containers share the host kernel — there is no VM layer, so the whole stack
fits in ~8 GB RAM. Sensors that need kernel visibility (`suricata`, `falco`) run privileged /
with `pid: host`. See `SECURITY.md`.

## Compose file stack

| File | Services |
|---|---|
| `.wazuh-docker/single-node/docker-compose.yml` | wazuh.manager, wazuh.indexer, wazuh.dashboard (upstream, cloned) |
| `compose/compose.overlay.yml` | heap tuning + manager config + shared log volumes |
| `compose/compose.detections.yml` | suricata, falco |
| `compose/compose.honeypots.yml` | cowrie, opencanary |
| `compose/compose.targets.yml` | target-linux |
| `compose/compose.viz.yml` | grafana |
