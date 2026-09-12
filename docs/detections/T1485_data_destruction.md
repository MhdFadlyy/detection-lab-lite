# T1485 — Bulk file deletion via rm -rf or shred

| | |
|---|---|
| **ATT&CK** | [T1485](https://attack.mitre.org/techniques/T1485/) |
| **Tactic** | Impact |
| **Severity** | high |
| **Engine** | Falco → `DLL Data Destruction` |
| **Automated test** | ✅ attack replayed + alert asserted in CI |

## What it detects

Detects rm -rf or shred used for bulk file deletion, outside the shell-history-tampering case which has its own detection.

## Detection logic

```yaml
selection:
  Image|endswith: /rm
  CommandLine|contains: -rf
selection_shred:
  Image|endswith: /shred
filter:
  CommandLine|contains: history
condition: (selection or selection_shred) and not filter
```

Falco (eBPF, host syscalls) raises **`DLL Data Destruction`** from the custom rule in [`detections/falco/dll_rules.yaml`](https://github.com/MhdFadlyy/detection-lab-lite/blob/main/detections/falco/dll_rules.yaml). Falco writes its JSON events to a shared volume; the `target-linux` Wazuh agent tails that file, so the alert lands in the Wazuh indexer as a `1009xx` rule ([`0900-falco.xml`](https://github.com/MhdFadlyy/detection-lab-lite/blob/main/detections/wazuh-native/0900-falco.xml)), matched on `data.rule`.

## Attack scenario — `./lab attack T1485`

*Bulk-delete a directory of files with rm -rf*

```bash
mkdir -p /tmp/dll_data && touch /tmp/dll_data/file{1,2,3}
rm -rf /tmp/dll_data
```

`./lab verify T1485` then asserts the alert reached the indexer.

## Known false positives

- Legitimate cleanup scripts removing temp/build directories

## References

- <https://attack.mitre.org/techniques/T1485/>

---

*Source: [`detections/impact/T1485_data_destruction.yml`](https://github.com/MhdFadlyy/detection-lab-lite/blob/main/detections/impact/T1485_data_destruction.yml)*
