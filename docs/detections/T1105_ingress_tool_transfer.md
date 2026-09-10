# T1071.001 — File download via curl/wget

| | |
|---|---|
| **ATT&CK** | [T1071.001](https://attack.mitre.org/techniques/T1071/001/), [T1105](https://attack.mitre.org/techniques/T1105/) |
| **Tactic** | Command And Control |
| **Severity** | medium |
| **Engine** | Falco → `DLL Ingress Tool Transfer` |
| **Automated test** | ✅ attack replayed + alert asserted in CI |

## What it detects

Detects curl/wget fetching a URL, especially to a temp or shared-memory path — ingress tool transfer.

## Detection logic

```yaml
selection:
  Image|endswith:
  - /curl
  - /wget
  CommandLine|contains:
  - http://
  - https://
  - ftp://
selection_path:
  CommandLine|contains:
  - ' -o '
  - ' -O '
  - --output
  - /tmp/
  - /dev/shm/
condition: selection and selection_path
```

Falco (eBPF, host syscalls) raises **`DLL Ingress Tool Transfer`** from the custom rule in [`detections/falco/dll_rules.yaml`](https://github.com/MhdFadlyy/detection-lab-lite/blob/main/detections/falco/dll_rules.yaml). Falco writes its JSON events to a shared volume; the `target-linux` Wazuh agent tails that file, so the alert lands in the Wazuh indexer as a `1009xx` rule ([`0900-falco.xml`](https://github.com/MhdFadlyy/detection-lab-lite/blob/main/detections/wazuh-native/0900-falco.xml)), matched on `data.rule`.

## Attack scenario — `./lab attack T1071.001`

*Download a file to /tmp with curl (targets an in-lab HTTP service, no external egress)*

```bash
timeout 5 curl -fskS -o /tmp/dll_payload https://wazuh.indexer:9200/ || \
timeout 5 curl -fsS  -o /tmp/dll_payload http://wazuh.dashboard:5601/ || true
ls -l /tmp/dll_payload 2>/dev/null ; rm -f /tmp/dll_payload
```

`./lab verify T1071.001` then asserts the alert reached the indexer.

## Known false positives

- Package managers, update scripts, health checks

## References

- <https://attack.mitre.org/techniques/T1105/>

---

*Source: [`detections/command-and-control/T1105_ingress_tool_transfer.yml`](https://github.com/MhdFadlyy/detection-lab-lite/blob/main/detections/command-and-control/T1105_ingress_tool_transfer.yml)*
