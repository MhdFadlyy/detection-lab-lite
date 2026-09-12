# Contributing

## Add a detection in ~5 minutes

1. **Write the Sigma rule** in `detections/<tactic>/T<id>_<name>.yml` (portable intent).
   Tag it with `attack.t<id>` so it lands on the coverage matrix, and set `dll.engine`.
2. **Pick an engine and add the firing rule:**
   - **File change** (persistence, credential-file write) → **Wazuh FIM**. Add the watched
     path to `compose/target-linux/ossec.conf` and a rule in
     `detections/wazuh-native/` keyed on `<if_group>syscheck</if_group>`.
   - **Process / file-read / network** → **Falco**. Add a rule to
     `detections/falco/dll_rules.yaml` (or reuse a stock one).
3. **Add an attack scenario** in `attacks/scenarios/T<id>_<name>.yml`:
   ```yaml
   technique: T1053.003
   description: Cron persistence
   runner: script
   command: (crontab -l 2>/dev/null; echo "* * * * * id") | crontab -
   expect:
     engine: wazuh          # or: falco
     rule_id: "100310"      # wazuh rule id  — or `rule: DLL ...` for falco
   ```
4. **Test locally:**
   ```
   ./lab attack T1053.003 && ./lab verify T1053.003
   ./lab report            # updates docs/coverage.md
   ```
5. Open a PR. CI replays every scenario and fails if an expected alert is missing.

## Roadmap

Capability stages, ordered by dependency — not a schedule. This is a long-lived project;
detections keep being added regardless of which stage is "current".

- [x] **Stage 1 — Foundation** — stack + `lab` CLI + first detection + public repo
- [x] **Stage 2 — Detection library** — harness + detections across the ATT&CK tactics, each
  with a self-contained scenario; `./lab test` green. *(Keep adding detections — never closes.)*
- [x] **Stage 3 — Continuous validation** — CI boots the stack and replays every scenario as
  a required check; ATT&CK Navigator layer published to Pages; Falco alerts unified into the
  Wazuh indexer (one alert store); 15 detections across 8 tactics.
- [x] **Stage 4 — Polish & first release** — per-detection docs pages, demo GIF, README
  screenshots, issue/PR templates, writeup, `v0.1.0`
- [x] **Post-v0.1.0** — Suricata and Cowrie were running but wired to zero detections; added
  `T1071.001` (Suricata signature) and `T1110` (Cowrie brute force). 17 detections / 8 tactics.
- [x] **4 empty tactics closed**: Collection (`T1560.001`), Impact (`T1485`), Initial Access
  (`T1078`, Cowrie's first genuine `login.success` detection), Exfiltration (`T1041`).
  21 detections across 12 tactics.
- [x] **OpenCanary default-on**: was `profiles: ["full"]` and never actually configured
  (image refuses to start without a config file). Added one, plus `T1595.002` (Reconnaissance).
  22 detections across 13 tactics.
- [ ] **Ongoing** — Windows + Sysmon target, Caldera, scheduled feed updates, community PRs
