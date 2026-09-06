# Security & safe-use policy

detection-lab-lite runs **offensive tooling** (Atomic Red Team, reverse-shell payloads,
brute-force simulations). It is built to attack **its own containers only**.

## Rules

- Every scenario in `attacks/scenarios/` targets `dll-target-linux` or a honeypot in this
  project. Do not point scenarios at hosts you do not own.
- The `suricata` and `falco` containers need host-kernel access
  (`network_mode: host`, `privileged`, `pid: host`). Run this on a machine you control —
  a laptop or a throwaway VM/cloud instance — not on shared infrastructure.
- Default credentials in `.env.example` are **lab-only**. Never reuse them.
- Cowrie/OpenCanary expose honeypot ports. Do not port-forward them from the public internet
  unless you understand the exposure.

## Reporting a vulnerability

Open a private security advisory on the GitHub repo, or email the maintainer listed in
`CODEOWNERS`. Please do not file public issues for exploitable bugs.
