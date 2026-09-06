# detection-lab-lite

**A laptop-friendly, Linux-first mini-SOC where every detection is code, tested in CI.**

Most detection labs (DetectionLab, Splunk Attack Range) are heavy, Windows/AD-focused, and
VM-based. This one is **Docker only — no Vagrant, no VM images** — boots on a 16 GB laptop with
one command, and proves its detections work by *actually launching the matching attack* and
asserting the alert fires.

```
./lab bootstrap     # clone wazuh-docker + generate certs (once)
./lab up            # pull images (one at a time) + start the stack
./lab attack T1059.004
./lab verify T1059.004     # -> PASS if the expected alert fired
./lab report        # regenerate the ATT&CK coverage matrix
```

## What's in the box

| | |
|---|---|
| **SIEM** | Wazuh single-node (manager + indexer + dashboard) |
| **Network IDS** | Suricata (EVE JSON → Wazuh) |
| **Runtime** | Falco (2nd detection engine, host syscalls) |
| **Endpoint** | `target-linux` container: Wazuh agent + auditd |
| **Honeypots** | Cowrie (SSH/Telnet), OpenCanary (`full` profile) |
| **Attacks** | Atomic Red Team + custom scenarios in `attacks/scenarios/` |
| **Detections** | Sigma (`detections/`) + hand-written Wazuh rules where Sigma falls short |
| **Dashboards** | Wazuh dashboard + provisioned Grafana |
| **Docs** | mkdocs-material site with an auto-generated coverage matrix |

## Architecture

```
attacks/scenarios/*.yml ──► target-linux (auditd + agent)
                            suricata (host NIC)   cowrie/opencanary
                                   │ logs
                    ┌──────────────┴───────────────┐
                    ▼                              ▼
          Wazuh (manager/indexer/dashboard)     Falco
                    │  alerts API                │
                    └──────────────┬─────────────┘
                                   ▼
              harness/verify.py  (assert alert fired)
              harness/report.py  (ATT&CK Navigator layer + coverage.md)
              Grafana "SOC overview"
```

## Requirements

- Linux host (containers use the host kernel directly — no VM layer)
- Docker Engine 24+ and Compose v2
- ~8 GB RAM free, ~15 GB disk

## Sigma caveat

`pySigma-backend-wazuh` maps to standard Wazuh field names and does not emit `if_sid`, so
naive conversions match too broadly. This project:

1. post-processes converted rules with a project pySigma pipeline (`harness/sigma_build.py`),
2. asserts on **fired alerts** in CI, not on converted text, and
3. keeps a `detections/wazuh-native/` escape hatch for detections Sigma can't express cleanly
   (the Sigma file then stays as documentation, flagged under `dll:`).

## Status

**Stage 2 — Detection library** (ongoing). Harness is complete (`runner` / `verify` / `report`
/ `sigma_build` / Atomic Red Team wrapper) and there are **12 detections across 6 ATT&CK
tactics**, each with a self-contained attack scenario. Run `./lab up` once, then `./lab test`
to replay every scenario and assert the alerts.

This is a long-lived project with no deadline — see [coverage](docs/coverage.md), the
[project plan](docs/plan.md), and `CONTRIBUTING.md` for the capability-stage roadmap.

## License

MIT. Offensive tooling — read `SECURITY.md` before running.
