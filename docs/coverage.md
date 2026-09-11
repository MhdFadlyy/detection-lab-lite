# ATT&CK coverage

- Detections: **17**
- Techniques covered: **18**
- Techniques with an automated attack test: **17**

**[Open in the ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/#layerURL=https://mhdfadlyy.github.io/detection-lab-lite/navigator-layer.json)** (green = attack replayed + alert asserted in CI, amber = detection only)

| Technique | Detection | Tactic | Level | Engine | Tested |
|---|---|---|---|---|---|
| [T1003.008](detections/T1003.008_etc_shadow.md) | /etc/shadow read or copied | Credential Access | high | falco | ✅ |
| [T1021.004](detections/T1021.004_ssh_outbound.md) | Outbound SSH client execution | Lateral Movement | low | falco | ✅ |
| [T1033](detections/T1033_whoami_id.md) | Account/context discovery via whoami or id | Discovery | low | falco | ✅ |
| [T1046](detections/T1046_network_service_scan.md) | Network service scan with nc/nmap | Discovery | medium | falco | ✅ |
| [T1053.003](detections/T1053.003_cron_persistence.md) | Crontab modified via CLI | Persistence | medium | wazuh | ✅ |
| [T1059.004](detections/T1059.004_bash_reverse_shell.md) | Bash reverse shell via /dev/tcp | Execution, Command And Control | high | falco | ✅ |
| [T1071](detections/T1059.004_bash_reverse_shell.md) | Bash reverse shell via /dev/tcp | Execution, Command And Control | high | falco | — |
| [T1059.006](detections/T1059.006_python_reverse_shell.md) | Python inline socket/subprocess execution | Execution | high | falco | ✅ |
| [T1070.003](detections/T1070.003_history_tampering.md) | Shell history file truncated or deleted | Defense Evasion | medium | falco | ✅ |
| [T1071.001](detections/T1071.001_http_beacon.md) | Cleartext HTTP beacon marker on the wire | Command And Control | medium | wazuh | ✅ |
| [T1071.001](detections/T1105_ingress_tool_transfer.md) | File download via curl/wget | Command And Control | medium | falco | ✅ |
| [T1105](detections/T1105_ingress_tool_transfer.md) | File download via curl/wget | Command And Control | medium | falco | ✅ |
| [T1087.001](detections/T1087.001_account_enum.md) | Local account enumeration via passwd/group | Discovery | low | falco | ✅ |
| [T1098.004](detections/T1098.004_authorized_keys.md) | SSH authorized_keys modified | Persistence, Lateral Movement | high | wazuh | ✅ |
| [T1110](detections/T1110_cowrie_bruteforce.md) | Repeated login attempts against the Cowrie honeypot | Credential Access | high | wazuh | ✅ |
| [T1136.001](detections/T1136.001_local_account.md) | Local account created | Persistence | medium | wazuh | ✅ |
| [T1543.002](detections/T1543.002_systemd_service.md) | systemd unit file created or modified | Persistence, Privilege Escalation | medium | wazuh | ✅ |
| [T1548.001](detections/T1548.001_setuid.md) | Setuid/setgid bit set via chmod | Privilege Escalation | high | falco | ✅ |
| [T1552.001](detections/T1552.001_secrets_in_files.md) | Filesystem grep for secrets | Credential Access | medium | falco | ✅ |
