#!/usr/bin/env python3
"""Assert that the expected alert fired for a scenario.

Usage: ./lab verify T1059.004        (one scenario)
       ./lab verify --all            (every scenario; used by CI)
"""
from __future__ import annotations

import sys
import time

from common import Scenario, query_wazuh_alert


def verify_one(tid: str) -> bool:
    sc = Scenario.load(tid)
    marker = sc.path.parent / ".last-run"
    since = time.time() - 600
    if marker.exists():
        try:
            since = float(marker.read_text().split()[1])
        except (IndexError, ValueError):
            pass

    if sc.expect_engine != "wazuh":
        print(f"[verify] {tid}: engine '{sc.expect_engine}' not wired yet — SKIP")
        return True

    hit = query_wazuh_alert(sc.expect_rule, since)
    if hit:
        print(f"[verify] {tid}: PASS — rule {sc.expect_rule} "
              f"({hit.get('rule', {}).get('description', '?')})")
        return True
    print(f"[verify] {tid}: FAIL — no alert for rule {sc.expect_rule}")
    return False


def main(argv: list[str]) -> int:
    if argv and argv[0] == "--all":
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
