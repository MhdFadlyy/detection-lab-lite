# Known limitations

Every detection here fires against a real attack in CI, that part is genuinely true. It's
worth being just as specific about what that does *not* prove, mostly so nobody (including
future me) mistakes a green badge for "production-ready."

## Lab-scoped, not threat-intel-derived

The two Suricata signatures (`T1071.001`, `T1041`) match on marker strings I invented,
`DLL_BEACON_MARKER` and `DLL_EXFIL_MARKER`. They exist to prove the ingestion pipeline works
end to end (Suricata sees the packet, Wazuh ingests the alert, the indexer has it), not
because a real attacker's C2 traffic looks like that. A real Suricata deployment runs against
an actual threat-intel ruleset (ET Open, a commercial feed, or rules derived from real
incidents), which this project deliberately doesn't (see the writeup for why: no external
feed dependency, deterministic in CI).

## Several rules are trivially bypassable

Named specifically, not hand-waved:

- **`T1071.001` / `T1041` (Suricata)**: exact content match on a fixed string. Any encoding,
  case change, or splitting the string across packets defeats it.
- **`T1560.001` (Falco, Archive Collection)**: matches `tar`/`zip`/`gzip` with `/etc`,
  `/root`, or `/home` in the command line. Renaming the binary, using a different archiver,
  or referencing the path indirectly (a variable, a symlink) all bypass it.
- **`T1485` (Falco, Data Destruction)**: matches `rm -rf` or `shred` on the command line.
  `find -delete`, a short Python `os.remove` loop, or direct `unlink` calls never show up.
- **`T1046` (Falco, Network Service Scan)**: matches known scanner binary names
  (`nmap`, `masscan`, `nc -z`). A renamed or statically-linked scanner is invisible to it.
- **`T1078` (Cowrie login success)**: only fires for the one credential seeded in
  `userdb.txt`. It proves the ingestion path for an accepted login works, it says nothing
  about detecting real credential-stuffing patterns against varied usernames/passwords.

None of these are bugs, they're the actual coverage boundary of a command-line/content-match
approach without process ancestry correlation, behavioral baselining, or ML scoring. A
production detection stack layers those on top.

## No false-positive tuning against real noise

Every scenario here runs against one clean lab host with no other workload on it. Severity
levels and thresholds (the Cowrie brute-force `frequency=3/timeframe=60`, for instance) were
picked to make the demo scenario reliable, not validated against a busy real endpoint's
background cron jobs, backup scripts, and legitimate admin activity. Real FP tuning needs
real traffic, which a solo lab can't produce.

## No response or triage layer

Alerts land in the Wazuh indexer and that's it. No SOAR integration, no case management, no
playbooks, no auto-containment. Detection and response are different disciplines, this
project only covers the first.

## Single author, no external validation yet

`CONTRIBUTING.md` has a 5-minute "add a detection" walkthrough, but no PR has been merged
from anyone other than the author. Every design decision here has had exactly one set of
eyes on it.

## What this project does prove

The pipeline itself is real: attack runs, telemetry is generated, an engine (Falco or a
Wazuh-native rule) correlates it, the alert reaches one indexer, and CI asserts all of that
happened, on every push, not just once by hand. That's a narrower and more defensible claim
than "these are production-grade detections", and it's the actual scope of what a fresh
`git clone` here gets you.
