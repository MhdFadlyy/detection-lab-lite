# Project plan

## Goal

A portfolio-grade detection lab: lightweight, Docker-only, Linux-first, with detections
maintained as code and validated automatically against replayed attacks.

## Roadmap

Capability stages, ordered by dependency — **not** a schedule. Each stage's exit check gates
the next; the project keeps growing detections and sensors indefinitely afterwards.

**Stage 1 — Foundation.** *(done)* Wazuh single-node + Suricata + Cowrie + `target-linux`,
`./lab` CLI (`bootstrap/up/down/status/logs`), one worked detection (`T1059.004`), public repo.

**Stage 2 — Detection library.** *(done, keeps growing)* `harness/` (runner, verify, report,
`sigma_build`, Atomic Red Team wrapper). Sigma intent files + hand-written rules across
Execution / Persistence / Credential Access / Discovery / Lateral Movement / C2 / Priv-Esc /
Defense Evasion, each with a self-contained scenario. `./lab test` replays and verifies.

**Stage 3 — Continuous validation.** *(done)* CI boots the tuned stack headless and
`./lab test` is a required check. ATT&CK Navigator layer published to GitHub Pages. Falco
alerts unified into the Wazuh indexer (one alert store). 15 detections / 8 tactics.

**Stage 4 — Polish & first release.** *(done)* Per-detection docs pages (auto-generated),
demo GIF, README screenshots, issue/PR templates, the [writeup](blog/building-detection-lab-lite.md),
tagged `v0.1.0`.

**Post-v0.1.0.** Suricata and Cowrie were running but backed zero detections at launch,
closed that gap first (17 detections / 8 tactics): a custom Suricata signature
(`T1071.001`) and a Cowrie brute-force detection (`T1110`), both wired into the same one
Wazuh alert store as FIM and Falco. Then closed the 4 ATT&CK tactics with zero coverage:
Collection (`T1560.001`), Impact (`T1485`), Initial Access (`T1078`, a seeded Cowrie
credential so a real `login.success` is reachable), Exfiltration (`T1041`, a second
Suricata signature). Then turned OpenCanary on by default (it was profile-gated *and*
missing a config file, the image won't start without one) and added `T1595.002`, closing
Reconnaissance. **22 detections across 13 tactics.**

**Ongoing.** Windows + Sysmon target, Caldera integration, scheduled feed updates,
community contributions, periodic minor releases.

## Non-goals for v0.1.0

Windows / Active Directory, Caldera, multi-node Wazuh — all deferred to "Ongoing".
