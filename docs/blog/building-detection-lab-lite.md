# Building detection-lab-lite

## The gap

Every "detection lab" I could find is heavy. Chris Long's DetectionLab, Splunk's Attack
Range, Wazuh's own PoC environment — they're Vagrant/VM based, Windows/Active-Directory
first, want 16–32 GB of RAM before they boot, and a lot of them are unmaintained. Great for
a course, awkward for "I want to write a detection tonight and know it works."

And that last part is the real gap: in most labs the detections are **not tested**. You
write a Sigma rule, eyeball it, move on. Whether it actually fires against the technique it
claims to catch is left as an exercise.

## The thesis

**Detection-as-code.** A detection isn't done when the rule is written — it's done when an
automated test launches the real attack against a running SOC and asserts the alert fired.
That's the whole project: `./lab test` replays every attack scenario and checks the Wazuh
indexer for the expected alert, and GitHub Actions runs the same thing on every push. The
badge is green because the detections genuinely work, not because the YAML parses.

## The build

- **Docker only.** No VM layer — on Linux the containers share the host kernel. The victim
  (`target-linux`) is a container too. `./lab up` pulls, builds and starts a full stack:
  Wazuh (manager + indexer + dashboard), Suricata, Falco, a honeypot, and the victim.
- **`./lab` CLI + a Python harness.** `attack` execs a scenario's command in the victim,
  `verify` polls the indexer, `report` regenerates the coverage matrix and the ATT&CK
  Navigator layer from the rules.
- **Sigma as the portable intent**, with a hand-written Wazuh or Falco rule as the thing
  that actually fires. Each detection is `detections/<tactic>/T####.yml` + a scenario +
  the firing rule.

## Two problems that ate a day each

1. **auditd doesn't work in a container.** The kernel audit subsystem is a single
   host-owned context — you can't give a container its own. So the first version, which
   chained every detection off `execve` audit events, caught *nothing* in CI. The fix was
   to split telemetry: **Wazuh FIM** (inotify, container-friendly) for file changes —
   persistence, credential-file writes — and **Falco** (eBPF, reads host syscalls) for
   process execution, sensitive file reads, and outbound network.

2. **Falco 0.39 dies on a 6.x kernel.** `scap_init` failure, crash loop, on both the Arch
   host and the GitHub runner. Falco 0.44 loads its modern-eBPF probe fine. One version
   bump, hours to find.

Then I unified the two engines: Falco writes JSON to a shared volume, the Wazuh agent tails
it, so Falco alerts land in the same indexer as FIM and `verify.py` has a single query
path.

## Where it's at

15 detections across 8 ATT&CK tactics, all replayed-and-asserted in CI. Coverage is
published as a [Navigator layer](https://mitre-attack.github.io/attack-navigator/#layerURL=https://mhdfadlyy.github.io/detection-lab-lite/navigator-layer.json).
Next: more detections (the library never really closes), a Windows + Sysmon target, and
network-layer detections off the honeypot and Suricata.

*[GitHub](https://github.com/MhdFadlyy/detection-lab-lite)*
