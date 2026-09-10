<!-- Thanks for contributing! Keep it small and focused. -->

## What this changes


## New detection checklist

<!-- Delete this section if the PR isn't a detection. -->

- [ ] Sigma rule in `detections/<tactic>/T####_<name>.yml`, tagged `attack.t####`
- [ ] Firing rule added — `detections/wazuh-native/` (FIM) or `detections/falco/dll_rules.yaml`
- [ ] Self-contained scenario in `attacks/scenarios/T####_<name>.yml` (targets the lab only)
- [ ] `./lab up && ./lab attack T#### && ./lab verify T####` → PASS locally
- [ ] `./lab report` re-run (regenerates `docs/coverage.md`, the Navigator layer, detection pages)

## Anything else

<!-- New telemetry source, a compose change, why a scenario is shaped a certain way… -->

---

CI will boot the full stack and replay **every** scenario — a red `replay` means a
detection doesn't fire. See
[CONTRIBUTING.md](https://github.com/MhdFadlyy/detection-lab-lite/blob/main/CONTRIBUTING.md)
for the walkthrough.
