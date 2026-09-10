# Architecture

```
attacks/scenarios/*.yml ──► target-linux (victim)
   │                          │  Wazuh agent: FIM (inotify)  +  tails the shared Falco events file
   │  suricata (host NIC)     │
   │  cowrie / opencanary     ▼ eBPF syscalls (pid: host)
   │                        Falco ─► /var/log/falco/events.json  (shared volume)
   ▼ logs                     │
   └──────────────────────────┴──►  Wazuh (manager → indexer → dashboard)
                                          │  ONE alert store: FIM + Falco both here
                                          ▼
              harness/verify.py  — engine: wazuh → indexer rule.id
                                   engine: falco → indexer data.rule (+ rule.groups: falco)
              harness/report.py  — ATT&CK Navigator layer + coverage.md
              Grafana            — "SOC overview" dashboard (reads the same index)
```

## Two detection engines, one alert store

| Engine | Source | Covers | Lands in the SIEM as |
|---|---|---|---|
| **Wazuh FIM** (`syscheck`) | agent inotify on `target-linux` | file changes: systemd units, cron, `authorized_keys`, `/etc/passwd` | rule `1003xx` (`if_group: syscheck`) |
| **Falco** | eBPF syscalls from the host kernel | process exec, sensitive file reads, outbound net | Falco writes JSON to a shared volume; the `target-linux` agent tails it (`log_format json`); rules `1009xx` match `data.rule` (the Falco rule name) |

`verify.py` queries the Wazuh indexer for both — a single query path.
auditd is deliberately **not** used — the kernel audit subsystem is a single host-owned
context that cannot be scoped to a container.

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
the Wazuh indexer for the expected alert (`rule.id` for FIM, `data.rule` for Falco).

**CI:** the same `./lab test` runs in GitHub Actions as a required check — boots the stack,
replays 12/12, asserts every alert. Falco needs kernel ≥ 5.8 and, for kernels ≥ 6.x, Falco
0.44.x (the pinned version) — older Falco fails `scap_init` on newer kernels.
