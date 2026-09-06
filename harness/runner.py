#!/usr/bin/env python3
"""Run an attack scenario against the victim container.

Usage: ./lab attack T1059.004
"""
from __future__ import annotations

import sys
import time

from common import Scenario, target_exec


def main(argv: list[str]) -> int:
    if not argv:
        print("usage: ./lab attack <TECHNIQUE_ID>", file=sys.stderr)
        return 2
    sc = Scenario.load(argv[0])
    print(f"[runner] {sc.tid}  {sc.description}")
    print(f"[runner] ({sc.runner}) {sc.command}")

    started = time.time()
    if sc.runner == "atomic":
        import atomic
        atomic.run(sc.command)  # command holds the technique id for atomic scenarios
    else:
        cp = target_exec(sc.command)
        print(cp.stdout.strip())
        if cp.stderr.strip():
            print(cp.stderr.strip(), file=sys.stderr)

    # stash the run marker so `verify` only looks at alerts after this point
    (sc.path.parent / ".last-run").write_text(f"{sc.tid} {started}\n")
    print(f"[runner] done in {time.time() - started:.1f}s — now: ./lab verify {sc.tid}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
