# Building detection-lab-lite

## Why

Every "detection lab" I could find is heavy. Chris Long's DetectionLab, Splunk's Attack
Range, Wazuh's own PoC environment. Vagrant/VM based, Windows/Active-Directory first, want
16–32 GB of RAM before they even boot, and a lot of them haven't been touched in a while.
Fine for a course. Not what I wanted for "I want to write a detection tonight and actually
know it works."

That last part is the real gap. In most labs the detections just aren't tested. You write a
Sigma rule, eyeball it, move on, and whether it fires against the technique it claims to
catch is left as an exercise for whoever inherits the rule later.

So the idea for this one: a detection isn't done when the rule is written. It's done when a
test launches the real attack against a running SOC and the alert actually shows up.
`./lab test` replays every attack scenario and checks the Wazuh indexer for the expected
alert, and GitHub Actions runs that same replay on every push. I wanted the green badge to
mean something more specific than "the YAML parses."

## The build

- **Docker only.** No VM layer, containers share the host kernel on Linux. Even the victim
  (`target-linux`) is a container. `./lab up` pulls, builds and starts the full stack: Wazuh
  (manager + indexer + dashboard), Suricata, Falco, a honeypot, and the victim.
- **`./lab` CLI + a Python harness.** `attack` execs a scenario's command in the victim,
  `verify` polls the indexer, `report` regenerates the coverage matrix and the ATT&CK
  Navigator layer from the rules.
- **Sigma as the portable intent**, backed by a hand-written Wazuh or Falco rule that's the
  thing that actually fires. Each detection is `detections/<tactic>/T####.yml` plus a
  scenario plus the firing rule.

## Two problems that each ate a day

**auditd doesn't work in a container.** Turns out the kernel audit subsystem is a single
host-owned context, you can't hand a container its own. My first version chained every
detection off `execve` audit events and it caught nothing in CI, zero alerts, for a while I
assumed it was an enrollment bug. It wasn't. Fix: split telemetry. Wazuh FIM (inotify,
plays fine in a container) for file changes (persistence, credential-file writes) and
Falco (eBPF, reads host syscalls) for process execution, sensitive file reads, outbound
network.

**Falco 0.39 dies on a 6.x kernel.** `scap_init` failure, crash loop, same story on the Arch
host and the GitHub runner. 0.44 loads its modern-eBPF probe without complaint. One version
bump. Took hours to find because the log line doesn't say "wrong version," it just says
`scap_init` failed and leaves you guessing.

After that I unified the two engines so there's one place to look: Falco writes JSON to a
shared volume, the Wazuh agent tails it, and Falco alerts land in the same indexer as FIM.
`verify.py` only needs one query path now instead of two.

## Status

22 detections across 13 ATT&CK tactics, all replayed and asserted in CI. Coverage is
published as a [Navigator layer](https://mitre-attack.github.io/attack-navigator/#layerURL=https://mhdfadlyy.github.io/detection-lab-lite/navigator-layer.json).

Next up: more detections (that list never really closes), a Windows + Sysmon target, and
network-layer detections off the honeypot and Suricata.

*[GitHub](https://github.com/MhdFadlyy/detection-lab-lite)*
