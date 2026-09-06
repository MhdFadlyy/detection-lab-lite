# ATT&CK coverage

- Detections: **12**
- Techniques covered: **14**
- Techniques with an automated attack test: **12**

| Technique | Detection | Level | Engine | Tested |
|---|---|---|---|---|
| T1003.008 | /etc/shadow read or copied | high | falco | ✅ |
| T1021.004 | Outbound SSH client execution | low | falco | ✅ |
| T1033 | Account/context discovery via whoami or id | low | falco | ✅ |
| T1053.003 | Crontab modified via CLI | medium | wazuh | ✅ |
| T1059.004 | Bash reverse shell via /dev/tcp | high | falco | ✅ |
| T1071 | Bash reverse shell via /dev/tcp | high | — | — |
| T1059.006 | Python inline socket/subprocess execution | high | falco | ✅ |
| T1071.001 | File download via curl/wget | medium | — | — |
| T1105 | File download via curl/wget | medium | falco | ✅ |
| T1087.001 | Local account enumeration via passwd/group | low | falco | ✅ |
| T1098.004 | SSH authorized_keys modified | high | wazuh | ✅ |
| T1136.001 | Local account created | medium | wazuh | ✅ |
| T1543.002 | systemd unit file created or modified | medium | wazuh | ✅ |
| T1552.001 | Filesystem grep for secrets | medium | falco | ✅ |
