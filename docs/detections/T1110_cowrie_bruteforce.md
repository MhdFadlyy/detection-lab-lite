# T1110 — Repeated login attempts against the Cowrie honeypot

| | |
|---|---|
| **ATT&CK** | [T1110](https://attack.mitre.org/techniques/T1110/) |
| **Tactic** | Credential Access |
| **Severity** | high |
| **Engine** | Wazuh (Cowrie) → rule `100510` |
| **Automated test** | ✅ attack replayed + alert asserted in CI |

## What it detects

Detects a burst of SSH/Telnet login attempts against the Cowrie honeypot. Fires on volume (3+ attempts within 60s), not on whether the honeypot accepted or rejected the credentials — a real brute-force is a pattern of repeated attempts, not any single failed login.

## Detection logic

```yaml
selection:
  eventid|startswith: cowrie.login.
condition: selection | count() by src_ip > 2
```

Cowrie (SSH/Telnet honeypot) logs the login attempt as JSON to a shared volume; the `target-linux` agent tails it, and rule `100510` in [`0500-cowrie.xml`](https://github.com/MhdFadlyy/detection-lab-lite/blob/main/detections/wazuh-native/0500-cowrie.xml) fires on repeated `cowrie.login.*` events (frequency-based, not on whether the honeypot accepted the credentials).

## Attack scenario — `./lab attack T1110`

*Repeated SSH login attempts against the Cowrie honeypot (brute force)*

```bash
for i in 1 2 3 4 5; do
  sshpass -p "wrongpass$i" ssh -p 2222 -o StrictHostKeyChecking=no \
    -o UserKnownHostsFile=/dev/null -o ConnectTimeout=5 root@cowrie exit 2>/dev/null
done
true
```

`./lab verify T1110` then asserts the alert reached the indexer.

## Known false positives

- Legitimate vulnerability scanning against the honeypot itself

## References

- <https://attack.mitre.org/techniques/T1110/>
- <https://github.com/cowrie/cowrie>

---

*Source: [`detections/credential-access/T1110_cowrie_bruteforce.yml`](https://github.com/MhdFadlyy/detection-lab-lite/blob/main/detections/credential-access/T1110_cowrie_bruteforce.yml)*
