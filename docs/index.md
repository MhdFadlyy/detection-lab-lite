# detection-lab-lite

A laptop-friendly, Linux-first mini-SOC where **every detection is code, tested in CI**.

![demo — launch an attack, the SOC catches it](img/demo.gif)

- **Docker only** — no Vagrant, no VM images. `./lab up` boots the whole stack.
- **Detection-as-code** — every Sigma rule is proven by replaying the real attack and
  asserting the alert fires; GitHub Actions does this on every push (15/15 green).
- **Two engines, one alert store** — Wazuh FIM for file changes, Falco/eBPF for process,
  file-read and network activity; both land in the Wazuh indexer.
- **ATT&CK-mapped** — the [coverage matrix](coverage.md) and
  [Navigator layer](https://mitre-attack.github.io/attack-navigator/#layerURL=https://mhdfadlyy.github.io/detection-lab-lite/navigator-layer.json)
  are generated from the rules + CI results.

Start with the [Architecture](architecture.md), browse the [Detections](detections/index.md),
or grab it from [GitHub](https://github.com/MhdFadlyy/detection-lab-lite).
