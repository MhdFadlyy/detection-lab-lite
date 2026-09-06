# Architecture

```
attacks/scenarios/*.yml ──► target-linux (auditd + Wazuh agent)
                            suricata (host NIC)   cowrie / opencanary
                                   │ logs
                    ┌──────────────┴───────────────┐
                    ▼                              ▼
          Wazuh (manager / indexer / dashboard)  Falco
                    │  alerts API                │ alerts
                    └──────────────┬─────────────┘
                                   ▼
              harness/verify.py  — assert the expected alert fired
              harness/report.py  — ATT&CK Navigator layer + coverage.md
              Grafana            — "SOC overview" dashboard
```

## Why Docker only

On a Linux host, containers share the host kernel — there is no VM layer, so the whole stack
fits in ~8 GB RAM. Sensors that need kernel visibility (`suricata`, `falco`, `target-linux`
auditd) run privileged / with `pid: host`. See `SECURITY.md`.

## Compose file stack

| File | Services |
|---|---|
| `.wazuh-docker/single-node/docker-compose.yml` | wazuh.manager, wazuh.indexer, wazuh.dashboard (upstream, cloned) |
| `compose/compose.overlay.yml` | heap tuning + manager config + shared log volumes |
| `compose/compose.detections.yml` | suricata, falco |
| `compose/compose.honeypots.yml` | cowrie, opencanary |
| `compose/compose.targets.yml` | target-linux |
| `compose/compose.viz.yml` | grafana |
