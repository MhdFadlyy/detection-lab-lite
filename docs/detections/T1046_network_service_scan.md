# T1046 — Network service scan with nc/nmap

| | |
|---|---|
| **ATT&CK** | [T1046](https://attack.mitre.org/techniques/T1046/) |
| **Tactic** | Discovery |
| **Severity** | medium |
| **Engine** | Falco → `DLL Network Service Scan` |
| **Automated test** | ✅ attack replayed + alert asserted in CI |

## What it detects

Detects nmap/masscan, or netcat run with the -z port-probe flag, from a workload — internal network service discovery.

## Detection logic

```yaml
selection_tool:
  Image|endswith:
  - /nmap
  - /masscan
  - /zmap
selection_nc:
  Image|endswith:
  - /nc
  - /ncat
  - /netcat
  CommandLine|contains:
  - ' -z'
  - ' -zv'
condition: selection_tool or selection_nc
```

Falco (eBPF, host syscalls) raises **`DLL Network Service Scan`** from the custom rule in [`detections/falco/dll_rules.yaml`](https://github.com/MhdFadlyy/detection-lab-lite/blob/main/detections/falco/dll_rules.yaml). Falco writes its JSON events to a shared volume; the `target-linux` Wazuh agent tails that file, so the alert lands in the Wazuh indexer as a `1009xx` rule ([`0900-falco.xml`](https://github.com/MhdFadlyy/detection-lab-lite/blob/main/detections/wazuh-native/0900-falco.xml)), matched on `data.rule`.

## Attack scenario — `./lab attack T1046`

*Port-probe in-lab hosts with netcat -z (network service discovery)*

```bash
for p in 22 1514 9200 5601; do timeout 2 nc -zv wazuh.manager $p 2>&1; done
timeout 2 nc -zv wazuh.indexer 9200 2>&1 || true
```

`./lab verify T1046` then asserts the alert reached the indexer.

## Known false positives

- Monitoring/health-check tooling probing ports

## References

- <https://attack.mitre.org/techniques/T1046/>

---

*Source: [`detections/discovery/T1046_network_service_scan.yml`](https://github.com/MhdFadlyy/detection-lab-lite/blob/main/detections/discovery/T1046_network_service_scan.yml)*
