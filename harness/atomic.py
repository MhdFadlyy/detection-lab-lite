#!/usr/bin/env python3
"""Thin wrapper around Atomic Red Team.

Scenarios with `runner: atomic` name an Atomic test GUID or a `T####` id plus
`atomic_index`. This clones redcanaryco/atomic-red-team once into the target
container and runs the atomic with its Python-free bash invoker.

Kept deliberately small: most lab scenarios are self-contained scripts. Atomic
is here for coverage of techniques that are tedious to hand-roll.
"""
from __future__ import annotations

import sys

from common import TARGET_CONTAINER, target_exec

ART_REPO = "https://github.com/redcanaryco/atomic-red-team.git"
ART_DIR = "/opt/atomic-red-team"


def ensure_art() -> None:
    check = target_exec(f"test -d {ART_DIR}/atomics && echo yes || echo no")
    if check.stdout.strip() == "yes":
        return
    print(f"[atomic] cloning Atomic Red Team into {TARGET_CONTAINER} (one download)")
    cp = target_exec(f"git clone --depth 1 {ART_REPO} {ART_DIR}")
    if cp.returncode != 0:
        raise SystemExit(f"[atomic] clone failed: {cp.stderr.strip()}")


def run(technique: str, index: int = 1) -> int:
    ensure_art()
    inv = (
        f"cd {ART_DIR} && "
        f"python3 -m pip show invoke-atomicredteam >/dev/null 2>&1 || true; "
        f"bash {ART_DIR}/atomics/{technique}/src/*.sh 2>/dev/null || "
        f"echo '[atomic] no bash src for {technique} index {index}; "
        f"add a custom script instead'"
    )
    cp = target_exec(inv)
    print(cp.stdout.strip())
    if cp.stderr.strip():
        print(cp.stderr.strip(), file=sys.stderr)
    return cp.returncode


if __name__ == "__main__":
    raise SystemExit(run(sys.argv[1], int(sys.argv[2]) if len(sys.argv) > 2 else 1))
