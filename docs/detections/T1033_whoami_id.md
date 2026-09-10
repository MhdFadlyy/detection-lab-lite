# T1033 — Account/context discovery via whoami or id

| | |
|---|---|
| **ATT&CK** | [T1033](https://attack.mitre.org/techniques/T1033/) |
| **Tactic** | Discovery |
| **Severity** | low |
| **Engine** | Falco → `DLL Discovery Commands` |
| **Automated test** | ✅ attack replayed + alert asserted in CI |

## What it detects

Detects execution of whoami or id — near-universal first commands after gaining a shell.

## Detection logic

```yaml
selection:
  Image|endswith:
  - /whoami
  - /id
condition: selection
```

Falco (eBPF, host syscalls) raises **`DLL Discovery Commands`** from the custom rule in [`detections/falco/dll_rules.yaml`](https://github.com/MhdFadlyy/detection-lab-lite/blob/main/detections/falco/dll_rules.yaml). Falco writes its JSON events to a shared volume; the `target-linux` Wazuh agent tails that file, so the alert lands in the Wazuh indexer as a `1009xx` rule ([`0900-falco.xml`](https://github.com/MhdFadlyy/detection-lab-lite/blob/main/detections/wazuh-native/0900-falco.xml)), matched on `data.rule`.

## Attack scenario — `./lab attack T1033`

*Run whoami and id (post-exploitation orientation)*

```bash
whoami ; id ; id -un
```

`./lab verify T1033` then asserts the alert reached the indexer.

## Known false positives

- Shell prompts, scripts checking privileges — noisy on its own; value is in correlation

## References

- <https://attack.mitre.org/techniques/T1033/>

---

*Source: [`detections/discovery/T1033_whoami_id.yml`](https://github.com/MhdFadlyy/detection-lab-lite/blob/main/detections/discovery/T1033_whoami_id.yml)*
