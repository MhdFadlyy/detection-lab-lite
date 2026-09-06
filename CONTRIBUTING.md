# Contributing

## Add a detection in ~5 minutes

1. **Write the Sigma rule** in `detections/<tactic>/T<id>_<name>.yml`. Tag it with
   `attack.t<id>` so it lands on the coverage matrix.
2. **Add an attack scenario** in `attacks/scenarios/T<id>_<name>.yml`:
   ```yaml
   technique: T1053.003
   description: Cron persistence
   runner: script
   command: (crontab -l 2>/dev/null; echo "* * * * * id") | crontab -
   expect:
     engine: wazuh
     rule_id: "100310"
   ```
3. **If Sigma → Wazuh conversion is lossy**, add a hand rule in
   `detections/wazuh-native/` and point `dll.wazuh_rule_id` at it.
4. **Test locally:**
   ```
   ./lab attack T1053.003 && ./lab verify T1053.003
   ./lab report            # updates docs/coverage.md
   ```
5. Open a PR. CI replays every scenario and fails if an expected alert is missing.

## Roadmap

- [x] Week 1 — stack + `lab` CLI + first detection
- [x] Week 2 — harness (`sigma_build`, Atomic Red Team wrapper), 12 detections across 6 tactics
- [ ] Week 3 — CI full replay green, Navigator layer, Grafana dashboard, Falco scenarios
- [ ] Week 4 — mkdocs site + Pages, demo GIF, `v0.1.0`
- [ ] Later — Windows/Sysmon target, Caldera integration
