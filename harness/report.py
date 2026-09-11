#!/usr/bin/env python3
"""Regenerate the docs coverage matrix, ATT&CK Navigator layer, and per-detection pages.

Usage: ./lab report
Writes: docs/coverage.md, docs/navigator-layer.json, docs/detections/*.md
Pure file reads — no running stack needed.
"""
from __future__ import annotations

import json
import re

import yaml

from common import DETECTIONS, ROOT, SCENARIOS

DOCS = ROOT / "docs"
DET_DOCS = DOCS / "detections"
TID_RE = re.compile(r"T\d{4}(?:\.\d{3})?")

REPO = "https://github.com/MhdFadlyy/detection-lab-lite"
PAGES = "https://mhdfadlyy.github.io/detection-lab-lite"
NAV = f"https://mitre-attack.github.io/attack-navigator/#layerURL={PAGES}/navigator-layer.json"

COLOR_TESTED = "#2e7d32"          # green — attack replayed + alert asserted in CI
COLOR_DETECTION_ONLY = "#f9a825"  # amber — rule exists, no automated test yet


def attack_url(tid: str) -> str:
    return "https://attack.mitre.org/techniques/" + tid.replace(".", "/") + "/"


def tactics_from_tags(tags: list) -> list[str]:
    out = []
    for t in tags:
        t = str(t)
        if t.startswith("attack.") and not TID_RE.search(t.upper()):
            name = t.split(".", 1)[1].replace("_", " ").title()
            if name not in out:
                out.append(name)
    return out


def collect_detections() -> list[dict]:
    out = []
    for path in sorted(DETECTIONS.rglob("*.yml")):
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
        engine = dll.get("engine", "wazuh")
        out.append({
            "doc": doc,
            "stem": path.stem,
            "title": doc.get("title", path.stem),
            "tids": tids,
            "tactics": tactics_from_tags(tags),
            "level": doc.get("level", "medium"),
            "path": str(path.relative_to(ROOT)),
            "engine": engine,
            # what actually fires the wazuh rule: syscheck (FIM) by default,
            # or a named JSON log source like cowrie/suricata tailed by the agent
            "source": dll.get("log_source", "syscheck"),
            "rule": dll.get("wazuh_rule_id") or dll.get("falco_rule") or "?",
            "scenario": dll.get("scenario"),
        })
    return out


def scenario_by_stem() -> dict[str, dict]:
    return {p.stem: yaml.safe_load(p.read_text()) for p in SCENARIOS.glob("*.yml")}


def tested_tids(scenarios: dict[str, dict]) -> set[str]:
    out = set()
    for s in scenarios.values():
        if m := TID_RE.search(str(s.get("technique", ""))):
            out.add(m.group(0))
    return out


# --- coverage matrix --------------------------------------------------------
def write_coverage(dets, covered, tested):
    lines = [
        "# ATT&CK coverage", "",
        f"- Detections: **{len(dets)}**",
        f"- Techniques covered: **{len(covered)}**",
        f"- Techniques with an automated attack test: **{len(tested & set(covered))}**",
        "",
        f"**[Open in the ATT&CK Navigator]({NAV})** "
        "(green = attack replayed + alert asserted in CI, amber = detection only)",
        "",
        "| Technique | Detection | Tactic | Level | Engine | Tested |",
        "|---|---|---|---|---|---|",
    ]
    for d in sorted(dets, key=lambda x: x["tids"]):
        for t in d["tids"] or ["(untagged)"]:
            mark = "✅" if t in tested else "—"
            page = f"detections/{d['stem']}.md"
            lines.append(f"| [{t}]({page}) | {d['title']} | {', '.join(d['tactics'])} "
                         f"| {d['level']} | {d['engine']} | {mark} |")
    (DOCS / "coverage.md").write_text("\n".join(lines) + "\n")


# --- Navigator layer -------------------------------------------------------
def build_layer(dets, tested) -> dict:
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


# --- per-detection pages --------------------------------------------------
def _how_it_fires(d: dict) -> str:
    if d["engine"] == "falco":
        r = d["rule"]
        rules_yaml = f"{REPO}/blob/main/detections/falco/dll_rules.yaml"
        src = ("a Falco stock rule" if not str(r).startswith("DLL ")
               else f"the custom rule in [`detections/falco/dll_rules.yaml`]({rules_yaml})")
        return (f"Falco (eBPF, host syscalls) raises **`{r}`** from {src}. Falco writes its "
                f"JSON events to a shared volume; the `target-linux` Wazuh agent tails that "
                f"file, so the alert lands in the Wazuh indexer as a `1009xx` rule "
                f"([`0900-falco.xml`]({REPO}/blob/main/detections/wazuh-native/0900-falco.xml)), "
                f"matched on `data.rule`.")
    if d["source"] == "cowrie":
        return (f"Cowrie (SSH/Telnet honeypot) logs the login attempt as JSON to a shared "
                f"volume; the `target-linux` agent tails it, and rule `{d['rule']}` in "
                f"[`0500-cowrie.xml`]({REPO}/blob/main/detections/wazuh-native/0500-cowrie.xml) "
                f"fires on repeated `cowrie.login.*` events (frequency-based, not on whether "
                f"the honeypot accepted the credentials).")
    if d["source"] == "suricata":
        rule_xml = f"{REPO}/blob/main/detections/wazuh-native/0600-suricata.xml"
        return (f"Suricata (network IDS, sharing `target-linux`'s network namespace) matches "
                f"a custom signature in [`compose/suricata/dll.rules`]"
                f"({REPO}/blob/main/compose/suricata/dll.rules) and writes EVE JSON to a "
                f"shared volume; the `target-linux` agent tails it, and rule `{d['rule']}` in "
                f"[`0600-suricata.xml`]({rule_xml}) matches on `alert.signature`.")
    return (f"Wazuh FIM (`syscheck`, inotify real-time) fires **rule `{d['rule']}`** from "
            f"[`detections/wazuh-native/0300-persistence.xml`]"
            f"({REPO}/blob/main/detections/wazuh-native/0300-persistence.xml) "
            f"(`<if_group>syscheck</if_group>` + a `file` regex).")


def write_detection_pages(dets, scenarios, tested):
    DET_DOCS.mkdir(parents=True, exist_ok=True)
    for old in DET_DOCS.glob("*.md"):
        old.unlink()

    for d in dets:
        doc = d["doc"]
        tid = d["tids"][0] if d["tids"] else "?"
        sc = scenarios.get(d["scenario"] or "", {})
        is_tested = any(t in tested for t in d["tids"])
        if d["engine"] == "falco":
            engine_cell = f"Falco → `{d['rule']}`"
        elif d["source"] in ("cowrie", "suricata"):
            engine_cell = f"Wazuh ({d['source'].title()}) → rule `{d['rule']}`"
        else:
            engine_cell = f"Wazuh FIM → rule `{d['rule']}`"

        md = [
            f"# {tid} — {d['title']}", "",
            "| | |", "|---|---|",
            "| **ATT&CK** | " + ", ".join(f"[{t}]({attack_url(t)})" for t in d["tids"]) + " |",
            f"| **Tactic** | {', '.join(d['tactics'])} |",
            f"| **Severity** | {d['level']} |",
            f"| **Engine** | {engine_cell} |",
            "| **Automated test** | " + ("✅ attack replayed + alert asserted in CI"
                                          if is_tested else "— not yet") + " |",
            "",
            "## What it detects", "",
            str(doc.get("description", "")).strip(), "",
            "## Detection logic", "",
            "```yaml",
            yaml.safe_dump(doc["detection"], sort_keys=False).strip(),
            "```", "",
            _how_it_fires(d), "",
        ]
        if sc.get("command"):
            md += [
                f"## Attack scenario — `./lab attack {tid}`", "",
                f"*{sc.get('description', '').strip()}*", "",
                "```bash", sc["command"].strip(), "```", "",
                f"`./lab verify {tid}` then asserts the alert reached the indexer.", "",
            ]
        if doc.get("falsepositives"):
            md += ["## Known false positives", ""]
            md += [f"- {fp}" for fp in doc["falsepositives"]]
            md += [""]
        if doc.get("references"):
            md += ["## References", ""]
            md += [f"- <{ref}>" for ref in doc["references"]]
            md += [""]
        md += ["---", "",
               f"*Source: [`{d['path']}`]({REPO}/blob/main/{d['path']})*", ""]
        (DET_DOCS / f"{d['stem']}.md").write_text("\n".join(md))

    # index
    idx = [
        "# Detections", "",
        f"{len(dets)} detections across {len({t for d in dets for t in d['tactics']})} "
        "ATT&CK tactics. Each is a Sigma rule with a self-contained attack scenario; the "
        f"[Navigator layer]({NAV}) and this list are auto-generated by `./lab report`.", "",
        "| Technique | Detection | Tactic | Engine | Tested |",
        "|---|---|---|---|---|",
    ]
    for d in sorted(dets, key=lambda x: x["tids"]):
        t = d["tids"][0] if d["tids"] else "?"
        mark = "✅" if any(x in tested for x in d["tids"]) else "—"
        idx.append(f"| [{t}]({d['stem']}.md) | {d['title']} | {', '.join(d['tactics'])} "
                   f"| {d['engine']} | {mark} |")
    (DET_DOCS / "index.md").write_text("\n".join(idx) + "\n")


def main() -> int:
    dets = collect_detections()
    scenarios = scenario_by_stem()
    covered = sorted({t for d in dets for t in d["tids"]})
    tested = tested_tids(scenarios)

    DOCS.mkdir(exist_ok=True)
    write_coverage(dets, covered, tested)
    (DOCS / "navigator-layer.json").write_text(
        json.dumps(build_layer(dets, tested), indent=2) + "\n")
    write_detection_pages(dets, scenarios, tested)

    print(f"[report] {len(dets)} detections, {len(covered)} techniques, "
          f"{len(tested & set(covered))} tested -> coverage.md + navigator-layer.json "
          f"+ {len(dets)} detection pages")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
