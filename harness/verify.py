#!/usr/bin/env python3
"""Assert that the expected alert fired for a scenario.

Both engines land in the Wazuh indexer:
  engine: wazuh  -> match rule.id
  engine: falco  -> match data.rule (the Falco rule name) within rule.groups: falco

Usage: ./lab verify T1059.004        (one scenario)
       ./lab verify --all            (every scenario; used by CI)
"""
from __future__ import annotations

import sys
import time

from common import Scenario, count_wazuh_alerts, query_falco_alert, query_wazuh_alert


def _since(sc: Scenario) -> float:
    marker = sc.path.parent / ".runs" / sc.tid
    if marker.exists():
        try:
            return float(marker.read_text().split()[0])
        except (IndexError, ValueError):
            pass
    return time.time() - 600


def verify_one(tid: str, timeout: int = 90) -> bool:
    sc = Scenario.load(tid)
    since = _since(sc)
    q = query_falco_alert if sc.expect_engine == "falco" else query_wazuh_alert

    hit = q(sc.expect_rule, since, timeout)
    if hit:
        desc = hit.get("rule", {}).get("description", "?")
        print(f"[verify] {tid}: PASS — {sc.expect_engine} '{sc.expect_rule}' ({desc})")
        return True
    total = count_wazuh_alerts(since)
    print(f"[verify] {tid}: FAIL — no {sc.expect_engine} alert for '{sc.expect_rule}' "
          f"({total} total alerts since the run)")
    return False


def main(argv: list[str]) -> int:
    if argv and argv[0] == "--all":
        # attacks already ran; let the pipeline settle, then poll each (returns on hit)
        time.sleep(20)
        results = {p.stem: verify_one(p.stem.split("_")[0]) for p in Scenario.all()}
        failed = [k for k, ok in results.items() if not ok]
        print(f"\n[verify] {len(results) - len(failed)}/{len(results)} passed")
        return 1 if failed else 0
    if not argv:
        print("usage: ./lab verify <TECHNIQUE_ID> | --all", file=sys.stderr)
        return 2
    return 0 if verify_one(argv[0]) else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
