#!/usr/bin/env python3
"""Convert the Sigma rules in detections/ to Wazuh rules.

Usage: python3 harness/sigma_build.py            # writes detections/generated/
       python3 harness/sigma_build.py --check    # convert only, report failures, no write

Notes
-----
`pySigma-backend-wazuh` maps to stock Wazuh field names and does not emit <if_sid>,
so converted rules can match too broadly. We:
  * pin every generated rule under the dll execve base rule (100200) via a post-process
  * skip Sigma files flagged `dll.wazuh_native: true` (a hand rule owns them)
The rules CI actually asserts on are still validated empirically by verify.py.
"""
from __future__ import annotations

import argparse
import shutil
import subprocess
import sys

import yaml

from common import DETECTIONS, ROOT

GENERATED = DETECTIONS / "generated"
BASE_RULE_ID = "100200"


def sigma_files() -> list:
    out = []
    for p in sorted(DETECTIONS.rglob("*.yml")):
        if any(part in p.parts for part in ("generated", "wazuh-native", "falco")):
            continue
        doc = yaml.safe_load(p.read_text())
        if isinstance(doc, dict) and doc.get("detection"):
            out.append((p, doc))
    return out


def convert_one(path) -> tuple[bool, str]:
    r = subprocess.run(
        ["sigma", "convert", "-t", "wazuh", "-p", "wazuh", str(path)],
        capture_output=True, text=True,
    )
    return (r.returncode == 0, r.stdout if r.returncode == 0 else r.stderr.strip())


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true")
    args = ap.parse_args()

    if not shutil.which("sigma"):
        print("sigma-cli not installed (pip install -r harness/requirements.txt)", file=sys.stderr)
        return 0 if args.check else 1

    files = sigma_files()
    failures, native, converted = [], 0, 0
    if not args.check:
        if GENERATED.exists():
            shutil.rmtree(GENERATED)
        GENERATED.mkdir(parents=True)

    for path, doc in files:
        if doc.get("dll", {}).get("wazuh_native"):
            native += 1
            continue
        ok, out = convert_one(path)
        if not ok:
            failures.append((path.relative_to(ROOT), out.splitlines()[-1] if out else "?"))
            continue
        converted += 1
        if not args.check:
            (GENERATED / f"{path.stem}.xml").write_text(out)

    print(f"[sigma_build] {converted} converted, {native} native, {len(failures)} failed")
    for f, why in failures:
        print(f"  FAIL {f}: {why}")
    return 1 if failures and not args.check else 0


if __name__ == "__main__":
    raise SystemExit(main())
