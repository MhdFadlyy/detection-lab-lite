# T1078 — Accepted login against the Cowrie honeypot

| | |
|---|---|
| **ATT&CK** | [T1078](https://attack.mitre.org/techniques/T1078/) |
| **Tactic** | Initial Access |
| **Severity** | high |
| **Engine** | Wazuh (Cowrie) → rule `100511` |
| **Automated test** | ✅ attack replayed + alert asserted in CI |

## What it detects

Detects a login the honeypot actually accepted (cowrie.login.success) — a valid-account-style entry into an exposed service, distinct from the T1110 brute-force detection which fires on volume regardless of outcome.

## Detection logic

```yaml
selection:
  eventid: cowrie.login.success
condition: selection
```

Cowrie (SSH/Telnet honeypot) logs the login attempt as JSON to a shared volume; the `target-linux` agent tails it, and rule `100511` in [`0500-cowrie.xml`](https://github.com/MhdFadlyy/detection-lab-lite/blob/main/detections/wazuh-native/0500-cowrie.xml) fires on repeated `cowrie.login.*` events (frequency-based, not on whether the honeypot accepted the credentials).

## Attack scenario — `./lab attack T1078`

*Log into the Cowrie honeypot with a valid (lab-seeded) credential*

```bash
sshpass -p "dllpass123" ssh -p 2222 -o StrictHostKeyChecking=no \
  -o UserKnownHostsFile=/dev/null -o ConnectTimeout=5 dll@cowrie exit 2>/dev/null || true
```

`./lab verify T1078` then asserts the alert reached the indexer.

## Known false positives

- None expected — this honeypot has no legitimate users

## References

- <https://attack.mitre.org/techniques/T1078/>

---

*Source: [`detections/initial-access/T1078_cowrie_login_success.yml`](https://github.com/MhdFadlyy/detection-lab-lite/blob/main/detections/initial-access/T1078_cowrie_login_success.yml)*
