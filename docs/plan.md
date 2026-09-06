# Project plan

## Goal

A portfolio-grade detection lab: lightweight, Docker-only, Linux-first, with detections
maintained as code and validated automatically against replayed attacks.

## Milestones

**Week 1 — stack online.** Wazuh single-node + Suricata + Cowrie + `target-linux`, `./lab`
CLI (`bootstrap/up/down/status/logs`), one worked detection (`T1059.004`).

**Week 2 — detection-as-code loop.** `harness/` (runner, verify, `sigma_build`), Atomic Red
Team wrapper, 15–20 Sigma detections across Execution / Persistence / Credential Access /
Discovery / Lateral Movement / C2.

**Week 3 — CI + reporting.** GitHub Actions replays every scenario headless, asserts alerts,
uploads a coverage artifact. `report.py` → Navigator layer + `coverage.md`. Add Falco
scenarios, OpenCanary, provisioned Grafana dashboard.

**Week 4 — polish.** mkdocs-material site on GitHub Pages, per-detection ADS-style pages,
demo GIF, issue/PR templates, `v0.1.0`, blog writeup.

## Non-goals for v0.1.0

Windows / Active Directory, Caldera, multi-node Wazuh. Tracked as "Later".
