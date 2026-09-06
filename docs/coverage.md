# ATT&CK coverage

- Detections: **12**
- Techniques covered: **14**
- Techniques with an automated attack test: **12**

| Technique | Detection | Level | Tested |
|---|---|---|---|
| T1003.008 | /etc/shadow read or copied | high | ✅ |
| T1021.004 | Outbound SSH client execution | low | ✅ |
| T1033 | Account/context discovery via whoami or id | low | ✅ |
| T1053.003 | Crontab modified via CLI | medium | ✅ |
| T1059.004 | Bash reverse shell via /dev/tcp | high | ✅ |
| T1071 | Bash reverse shell via /dev/tcp | high | — |
| T1059.006 | Python inline socket/subprocess execution | high | ✅ |
| T1071.001 | File download via curl/wget | medium | — |
| T1105 | File download via curl/wget | medium | ✅ |
| T1087.001 | Local account enumeration via passwd/group | low | ✅ |
| T1098.004 | SSH authorized_keys modified | high | ✅ |
| T1136.001 | Local account created | medium | ✅ |
| T1543.002 | systemd unit file created or modified | medium | ✅ |
| T1552.001 | Filesystem grep for secrets | medium | ✅ |
