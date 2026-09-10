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
| `compose/compose.overlay.yml` | indexer heap tuning + drop custom rules into `etc/rules` |
| `compose/compose.detections.yml` | suricata, falco |
| `compose/compose.honeypots.yml` | cowrie, opencanary |
| `compose/compose.targets.yml` | target-linux |
| `compose/compose.viz.yml` | grafana |

## Running & verifying

```
./lab bootstrap     # once: clone wazuh-docker + generate indexer certs
./lab up            # pull (sequential) + build + start all 8 containers
./lab test          # wait for the agent + FIM pipeline, replay every scenario, assert alerts
./lab down -v       # tear down and wipe volumes
```

`./lab test` first runs `wait_ready`: it waits for the `target-linux` agent to report
**Active**, then rewrites a canary file under `/etc/cron.d/` until its FIM alert reaches the
indexer — proving the whole `agent → manager → filebeat → indexer` path is hot. A fresh boot
otherwise absorbs the first file changes into the FIM baseline before real-time monitoring is
ready, so early scenarios would silently miss.

Then each `attacks/scenarios/*.yml` is replayed inside `target-linux` and `verify.py` polls
the matching engine (Falco events file, or the Wazuh indexer) for the expected alert.

**CI note:** the same `./lab test` runs in GitHub Actions but is advisory — hosted runners
are unreliable for eBPF probe loading and a full SIEM boot. The authoritative 12/12 is a
local run on a real Linux host (Falco needs kernel ≥ 5.8; 0.44.x for kernels ≥ 6.x).
