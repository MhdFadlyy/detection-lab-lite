#!/usr/bin/env python3
"""Assert that the expected alert fired for a scenario.

Usage: ./lab verify T1059.004        (one scenario)
       ./lab verify --all            (every scenario; used by CI)
"""
from __future__ import annotations

import sys
import time

from common import (
    Scenario,
    count_wazuh_alerts,
    query_falco_alert,
    query_wazuh_alert,
)


def _since(sc: Scenario) -> float:
    marker = sc.path.parent / ".runs" / sc.tid
    if marker.exists():
        try:
            return float(marker.read_text().split()[0])
        except (IndexError, ValueError):
            pass
    return time.time() - 600


def verify_one(tid: str, falco_timeout: int = 40, wazuh_timeout: int = 90) -> bool:
    sc = Scenario.load(tid)
    since = _since(sc)

    if sc.expect_engine == "falco":
        hit = query_falco_alert(sc.expect_rule, since, falco_timeout)
        if hit:
            print(f"[verify] {tid}: PASS — falco rule '{sc.expect_rule}'")
            return True
        print(f"[verify] {tid}: FAIL — no Falco event for rule '{sc.expect_rule}'")
        return False

    hit = query_wazuh_alert(sc.expect_rule, since, wazuh_timeout)
    if hit:
        print(f"[verify] {tid}: PASS — wazuh rule {sc.expect_rule} "
              f"({hit.get('rule', {}).get('description', '?')})")
        return True
    total = count_wazuh_alerts(since)
    print(f"[verify] {tid}: FAIL — no alert for rule {sc.expect_rule} "
          f"({total} total alerts since the run)")
    return False


def main(argv: list[str]) -> int:
    if argv and argv[0] == "--all":
        # attacks already ran; let the pipelines settle, then poll each (returns on hit)
        time.sleep(20)
        results = {p.stem: verify_one(p.stem.split("_")[0])
                   for p in Scenario.all()}
        failed = [k for k, ok in results.items() if not ok]
        print(f"\n[verify] {len(results) - len(failed)}/{len(results)} passed")
        return 1 if failed else 0
    if not argv:
        print("usage: ./lab verify <TECHNIQUE_ID> | --all", file=sys.stderr)
        return 2
    return 0 if verify_one(argv[0]) else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
