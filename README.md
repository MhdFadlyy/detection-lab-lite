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

| `./lab test` replays 12 attacks and asserts every alert — 12/12, locally and in CI | Wazuh catching the persistence scenarios, ATT&CK-tagged |
|---|---|
| ![CI green](docs/img/ci-green-12-12.jpg) | ![Wazuh FIM detections](docs/img/wazuh-fim-detections.jpg) |

📊 **[Coverage in the MITRE ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/#layerURL=https://mhdfadlyy.github.io/detection-lab-lite/navigator-layer.json)** — auto-generated from the detections + the CI test results.

## What's in the box

| | |
|---|---|
| **SIEM** | Wazuh single-node (manager + indexer + dashboard) |
| **Network IDS** | Suricata (EVE JSON → Wazuh) |
| **Runtime** | Falco (2nd detection engine, host syscalls via eBPF) |
| **Endpoint** | `target-linux` container: Wazuh agent (FIM / inotify) + Falco eBPF |
| **Honeypots** | Cowrie (SSH/Telnet), OpenCanary (`full` profile) |
| **Attacks** | Atomic Red Team + custom scenarios in `attacks/scenarios/` |
| **Detections** | Sigma (`detections/`) + hand-written Wazuh rules where Sigma falls short |
| **Dashboards** | Wazuh dashboard + provisioned Grafana |
| **Docs** | mkdocs-material site with an auto-generated coverage matrix |

## Architecture

```
attacks/scenarios/*.yml ──► target-linux (Wazuh agent: FIM)
                            suricata (host NIC)   cowrie/opencanary
                                   │ logs                    │ eBPF syscalls
                    ┌──────────────┴───────────────┐         ▼
                    ▼                              ▼      Falco  ──► /tmp/falco_events.json
          Wazuh (manager/indexer/dashboard)  ◄────┘
                    │  alerts API
                    ▼
              harness/verify.py   engine: wazuh → query indexer
                                  engine: falco → read Falco events
              harness/report.py   ATT&CK Navigator layer + coverage.md
              Grafana "SOC overview"
```

Two detection engines: **Wazuh FIM** for file changes (persistence, credential-file
writes) and **Falco/eBPF** for process, file-read and network activity. Each scenario
declares which engine verifies it.

## Requirements

- Linux host (containers use the host kernel directly — no VM layer)
- Docker Engine 24+ and Compose v2
- ~8 GB RAM free, ~15 GB disk

## How detections are defined

Each detection is a **Sigma rule** in `detections/<tactic>/` — the portable, human-readable
intent. Its `dll:` block says which engine actually verifies it:

- **`engine: wazuh`** → a hand-written Wazuh FIM rule in `detections/wazuh-native/`
  (`<if_group>syscheck</if_group>`). `verify.py` queries the indexer for `rule.id`.
- **`engine: falco`** → a rule in `detections/falco/dll_rules.yaml` (or a Falco stock rule).
  `verify.py` reads `/tmp/falco_events.json` in the Falco container for the rule name.

Sigma-to-Wazuh auto-conversion (`harness/sigma_build.py`, `pySigma-backend-wazuh`) runs in CI
as a **portability check only** — its backend maps to stock field names and omits `if_sid`,
so the rules that actually fire are the hand-written ones above.

## Status

**Stage 2 — Detection library.** Harness complete (`runner` / `verify` / `report` /
`sigma_build` / Atomic Red Team wrapper). **12 detections across 6 ATT&CK tactics**, each
with a self-contained scenario — `./lab up && ./lab test` replays every attack and asserts
the alert fires. **12/12 green** on a real Linux host (Docker Engine on a modern kernel).

CI (`.github/workflows/ci.yml`) lints on every push **and** boots the whole stack to replay
all 12 attacks and assert every alert — a required check, green end-to-end.

This is a long-lived project with no deadline — see [coverage](docs/coverage.md), the
[project plan](docs/plan.md), and `CONTRIBUTING.md` for the capability-stage roadmap.

## License

MIT. Offensive tooling — read `SECURITY.md` before running.
