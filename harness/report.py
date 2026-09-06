#!/usr/bin/env python3
"""Regenerate the ATT&CK coverage matrix and Navigator layer from detections/.

Usage: ./lab report
Writes: docs/coverage.md, docs/navigator-layer.json
"""
from __future__ import annotations

import json
import re

import yaml

from common import DETECTIONS, ROOT, Scenario

DOCS = ROOT / "docs"
TID_RE = re.compile(r"T\d{4}(?:\.\d{3})?")


def collect_detections() -> list[dict]:
    out = []
    for path in DETECTIONS.rglob("*.yml"):
        if "wazuh-native" in path.parts or "falco" in path.parts:
            continue
        try:
            doc = yaml.safe_load(path.read_text())
        except yaml.YAMLError:
            continue
        if not isinstance(doc, dict) or "detection" not in doc:
            continue
        tags = doc.get("tags", []) or []
        tids = sorted({m.group(0) for t in tags for m in [TID_RE.search(str(t).upper())] if m})
        out.append({"title": doc.get("title", path.stem), "tids": tids,
                    "level": doc.get("level", "medium"), "path": str(path.relative_to(ROOT))})
    return out


def scenario_engine_by_tid() -> dict[str, str]:
    """Map each tested technique id -> verification engine (wazuh | falco)."""
    out = {}
    for p in Scenario.all():
        d = yaml.safe_load(p.read_text())
        if m := TID_RE.search(str(d.get("technique", ""))):
            out[m.group(0)] = d.get("expect", {}).get("engine", "wazuh")
    return out


def main() -> int:
    dets = collect_detections()
    covered = sorted({t for d in dets for t in d["tids"]})
    engines = scenario_engine_by_tid()
    tested = set(engines)

    DOCS.mkdir(exist_ok=True)
    lines = ["# ATT&CK coverage", "",
             f"- Detections: **{len(dets)}**",
             f"- Techniques covered: **{len(covered)}**",
             f"- Techniques with an automated attack test: **{len(tested & set(covered))}**",
             "", "| Technique | Detection | Level | Engine | Tested |",
             "|---|---|---|---|---|"]
    for d in sorted(dets, key=lambda x: x["tids"]):
        for t in d["tids"] or ["(untagged)"]:
            mark = "✅" if t in tested else "—"
            engine = engines.get(t, "—")
            lines.append(f"| {t} | {d['title']} | {d['level']} | {engine} | {mark} |")
    (DOCS / "coverage.md").write_text("\n".join(lines) + "\n")

    layer = {
        "name": "detection-lab-lite coverage",
        "versions": {"layer": "4.5", "navigator": "4.9.1", "attack": "15"},
        "domain": "enterprise-attack",
        "techniques": [
            {"techniqueID": t, "score": 100 if t in tested else 50,
             "comment": "tested" if t in tested else "detection only"}
            for t in covered
        ],
        "gradient": {"colors": ["#ffe766", "#8ec843"], "minValue": 0, "maxValue": 100},
    }
    (DOCS / "navigator-layer.json").write_text(json.dumps(layer, indent=2) + "\n")
    print(f"[report] {len(dets)} detections, {len(covered)} techniques -> docs/coverage.md")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
