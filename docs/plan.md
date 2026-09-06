# Project plan

## Goal

A portfolio-grade detection lab: lightweight, Docker-only, Linux-first, with detections
maintained as code and validated automatically against replayed attacks.

## Roadmap

Capability stages, ordered by dependency — **not** a schedule. Each stage's exit check gates
the next; the project keeps growing detections and sensors indefinitely afterwards.

**Stage 1 — Foundation.** *(done)* Wazuh single-node + Suricata + Cowrie + `target-linux`,
`./lab` CLI (`bootstrap/up/down/status/logs`), one worked detection (`T1059.004`), public repo.

**Stage 2 — Detection library.** *(ongoing)* `harness/` (runner, verify, report, `sigma_build`,
Atomic Red Team wrapper). Sigma intent files + hand-written Wazuh rules across Execution /
Persistence / Credential Access / Discovery / Lateral Movement / C2, each with a self-contained
scenario. `./lab test` replays and verifies. Never really closes — keep adding detections.

**Stage 3 — Continuous validation.** CI boots the tuned stack headless and `./lab test` goes
green (drop `continue-on-error`). ATT&CK Navigator layer artifact. Falco as a 2nd engine with
verified scenarios. OpenCanary. Provisioned Grafana "SOC overview" dashboard.

**Stage 4 — Polish & first release.** mkdocs-material site content, per-detection ADS-style
pages, demo GIF, README screenshots, issue/PR templates, tag `v0.1.0`, blog writeup.

**Ongoing (post-v0.1.0).** Windows + Sysmon target, Caldera integration, scheduled feed
updates, community contributions, periodic minor releases.

## Non-goals for v0.1.0

Windows / Active Directory, Caldera, multi-node Wazuh — all deferred to "Ongoing".
