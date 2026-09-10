# ATT&CK coverage

- Detections: **15**
- Techniques covered: **17**
- Techniques with an automated attack test: **15**

**[Open in the ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/#layerURL=https://mhdfadlyy.github.io/detection-lab-lite/navigator-layer.json)** (green = attack replayed + alert asserted in CI, amber = detection only)

| Technique | Detection | Level | Engine | Tested |
|---|---|---|---|---|
| T1003.008 | /etc/shadow read or copied | high | falco | ✅ |
| T1021.004 | Outbound SSH client execution | low | falco | ✅ |
| T1033 | Account/context discovery via whoami or id | low | falco | ✅ |
| T1046 | Network service scan with nc/nmap | medium | falco | ✅ |
| T1053.003 | Crontab modified via CLI | medium | wazuh | ✅ |
| T1059.004 | Bash reverse shell via /dev/tcp | high | falco | ✅ |
| T1071 | Bash reverse shell via /dev/tcp | high | falco | — |
| T1059.006 | Python inline socket/subprocess execution | high | falco | ✅ |
| T1070.003 | Shell history file truncated or deleted | medium | falco | ✅ |
| T1071.001 | File download via curl/wget | medium | falco | — |
| T1105 | File download via curl/wget | medium | falco | ✅ |
| T1087.001 | Local account enumeration via passwd/group | low | falco | ✅ |
| T1098.004 | SSH authorized_keys modified | high | wazuh | ✅ |
| T1136.001 | Local account created | medium | wazuh | ✅ |
| T1543.002 | systemd unit file created or modified | medium | wazuh | ✅ |
| T1548.001 | Setuid/setgid bit set via chmod | high | falco | ✅ |
| T1552.001 | Filesystem grep for secrets | medium | falco | ✅ |
