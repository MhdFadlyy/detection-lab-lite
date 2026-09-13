# T1570 — File copied to a second internal host via scp

| | |
|---|---|
| **ATT&CK** | [T1570](https://attack.mitre.org/techniques/T1570/) |
| **Tactic** | Lateral Movement |
| **Severity** | medium |
| **Engine** | Falco → `DLL Outbound SSH` |
| **Automated test** | ✅ attack replayed + alert asserted in CI |

## What it detects

Detects scp/ssh/sftp client execution used to move a file onto a second, internal host, a lateral-movement pivot rather than the single-host outbound-SSH case (T1021.004). Reuses the same Falco rule since the process-level signal (an ssh-family client running) is identical; the interesting new part is that target-linux-2 exists at all and correlates in the same Wazuh indexer.

## Detection logic

```yaml
selection:
  Image|endswith: /scp
condition: selection
```

Falco (eBPF, host syscalls) raises **`DLL Outbound SSH`** from the custom rule in [`detections/falco/dll_rules.yaml`](https://github.com/MhdFadlyy/detection-lab-lite/blob/main/detections/falco/dll_rules.yaml). Falco writes its JSON events to a shared volume; the `target-linux` Wazuh agent tails that file, so the alert lands in the Wazuh indexer as a `1009xx` rule ([`0900-falco.xml`](https://github.com/MhdFadlyy/detection-lab-lite/blob/main/detections/wazuh-native/0900-falco.xml)), matched on `data.rule`.

## Attack scenario — `./lab attack T1570`

*Copy a file to a second internal host via scp (lateral pivot)*

```bash
echo "not actually malicious, just proving the pivot" > /tmp/dll_payload.txt
sshpass -p "pivotpass123" scp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
  /tmp/dll_payload.txt pivot@target-linux-2:/home/pivot/incoming/payload.txt
rm -f /tmp/dll_payload.txt
```

`./lab verify T1570` then asserts the alert reached the indexer.

## Known false positives

- Legitimate admin file transfers between hosts you actually operate

## References

- <https://attack.mitre.org/techniques/T1570/>

---

*Source: [`detections/lateral-movement/T1570_lateral_tool_transfer.yml`](https://github.com/MhdFadlyy/detection-lab-lite/blob/main/detections/lateral-movement/T1570_lateral_tool_transfer.yml)*
