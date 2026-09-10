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

REPO = "https://github.com/MhdFadlyy/detection-lab-lite"
PAGES = "https://mhdfadlyy.github.io/detection-lab-lite"
NAV = f"https://mitre-attack.github.io/attack-navigator/#layerURL={PAGES}/navigator-layer.json"

COLOR_TESTED = "#2e7d32"        # green — attack replayed + alert asserted in CI
COLOR_DETECTION_ONLY = "#f9a825"  # amber — rule exists, no automated test yet


def collect_detections() -> list[dict]:
    out = []
    for path in DETECTIONS.rglob("*.yml"):
        if any(p in path.parts for p in ("wazuh-native", "falco", "generated")):
            continue
        try:
            doc = yaml.safe_load(path.read_text())
        except yaml.YAMLError:
            continue
        if not isinstance(doc, dict) or "detection" not in doc:
            continue
        tags = doc.get("tags", []) or []
        tids = sorted({m.group(0) for t in tags for m in [TID_RE.search(str(t).upper())] if m})
        dll = doc.get("dll", {}) or {}
        out.append({
            "title": doc.get("title", path.stem),
            "tids": tids,
            "level": doc.get("level", "medium"),
            "path": str(path.relative_to(ROOT)),
            "engine": dll.get("engine", "wazuh" if dll.get("wazuh_native") else "wazuh"),
            "rule": dll.get("wazuh_rule_id") or dll.get("falco_rule") or "?",
        })
    return out


def scenario_engine_by_tid() -> dict[str, str]:
    """Map each tested technique id -> verification engine (wazuh | falco)."""
    out = {}
    for p in Scenario.all():
        d = yaml.safe_load(p.read_text())
        if m := TID_RE.search(str(d.get("technique", ""))):
            out[m.group(0)] = d.get("expect", {}).get("engine", "wazuh")
    return out


def build_layer(dets: list[dict], tested: set[str]) -> dict:
    # one entry per technique id, merging metadata from every detection that tags it
    by_tid: dict[str, list[dict]] = {}
    for d in dets:
        for t in d["tids"]:
            by_tid.setdefault(t, []).append(d)

    techniques = []
    for tid, ds in sorted(by_tid.items()):
        is_tested = tid in tested
        d0 = ds[0]
        techniques.append({
            "techniqueID": tid,
            "score": 100 if is_tested else 50,
            "color": COLOR_TESTED if is_tested else COLOR_DETECTION_ONLY,
            "comment": ("tested: attack replayed, alert asserted in CI"
                        if is_tested else "detection rule only (no automated test yet)"),
            "enabled": True,
            "metadata": [
                {"name": "detection", "value": d0["title"]},
                {"name": "engine", "value": d0["engine"]},
                {"name": "rule", "value": str(d0["rule"])},
            ],
            "links": [{"label": "rule source", "url": f"{REPO}/blob/main/{d0['path']}"}],
        })

    return {
        "name": "detection-lab-lite — detection coverage",
        "description": "Auto-generated from detections/ + attacks/scenarios/. "
                       "Green = the attack is replayed and the alert asserted in CI.",
        "domain": "enterprise-attack",
        "versions": {"layer": "4.5", "navigator": "5.1.0", "attack": "16"},
        "techniques": techniques,
        "gradient": {"colors": ["#f9a825", "#2e7d32"], "minValue": 50, "maxValue": 100},
        "legendItems": [
            {"label": "tested in CI", "color": COLOR_TESTED},
            {"label": "detection only", "color": COLOR_DETECTION_ONLY},
        ],
        "sorting": 3,
        "hideDisabled": False,
        "showTacticRowBackground": True,
        "tacticRowBackground": "#205b93",
        "selectTechniquesAcrossTactics": True,
        "layout": {"layout": "side", "showID": True, "showName": True},
    }


def main() -> int:
    dets = collect_detections()
    covered = sorted({t for d in dets for t in d["tids"]})
    engines = scenario_engine_by_tid()
    tested = set(engines)

    DOCS.mkdir(exist_ok=True)
    lines = [
        "# ATT&CK coverage", "",
        f"- Detections: **{len(dets)}**",
        f"- Techniques covered: **{len(covered)}**",
        f"- Techniques with an automated attack test: **{len(tested & set(covered))}**",
        "",
        f"**[Open in the ATT&CK Navigator]({NAV})** "
        "(green = attack replayed + alert asserted in CI, amber = detection only)",
        "",
        "| Technique | Detection | Level | Engine | Tested |",
        "|---|---|---|---|---|",
    ]
    for d in sorted(dets, key=lambda x: x["tids"]):
        for t in d["tids"] or ["(untagged)"]:
            mark = "✅" if t in tested else "—"
            lines.append(f"| {t} | {d['title']} | {d['level']} | {engines.get(t, d['engine'])} | {mark} |")
    (DOCS / "coverage.md").write_text("\n".join(lines) + "\n")

    (DOCS / "navigator-layer.json").write_text(
        json.dumps(build_layer(dets, tested), indent=2) + "\n")
    print(f"[report] {len(dets)} detections, {len(covered)} techniques, "
          f"{len(tested & set(covered))} tested -> docs/coverage.md + navigator-layer.json")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
