"""Shared helpers for the detection-lab-lite harness."""
from __future__ import annotations

import json
import os
import pathlib
import subprocess
import time
from dataclasses import dataclass

import requests
import urllib3
import yaml

urllib3.disable_warnings()  # lab uses self-signed certs

ROOT = pathlib.Path(__file__).resolve().parent.parent
SCENARIOS = ROOT / "attacks" / "scenarios"
DETECTIONS = ROOT / "detections"

INDEXER_URL = os.environ.get("INDEXER_URL", "https://localhost:9200")
INDEXER_AUTH = (
    os.environ.get("INDEXER_USER", "admin"),
    os.environ.get("INDEXER_PASSWORD", "SecretPassword"),
)
TARGET_CONTAINER = os.environ.get("TARGET_CONTAINER", "dll-target-linux")
FALCO_EVENTS = "/tmp/falco_events.json"


@dataclass
class Scenario:
    tid: str
    description: str
    runner: str            # "atomic" | "script"
    command: str
    expect_engine: str     # "wazuh" | "falco"
    expect_rule: str       # wazuh rule id, or falco rule name
    path: pathlib.Path

    @classmethod
    def load(cls, tid: str) -> Scenario:
        matches = sorted(SCENARIOS.glob(f"{tid}*.yml"))
        if not matches:
            raise SystemExit(f"no scenario for {tid} in {SCENARIOS}")
        data = yaml.safe_load(matches[0].read_text())
        exp = data.get("expect", {})
        return cls(
            tid=data["technique"],
            description=data.get("description", ""),
            runner=data.get("runner", "script"),
            command=data["command"],
            expect_engine=exp.get("engine", "wazuh"),
            expect_rule=str(exp.get("rule_id") or exp.get("rule") or ""),
            path=matches[0],
        )

    @staticmethod
    def all() -> list[pathlib.Path]:
        return sorted(SCENARIOS.glob("*.yml"))


def _docker(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(["docker", *args], capture_output=True, text=True)


def target_exec(command: str) -> subprocess.CompletedProcess:
    """Run a shell command inside the victim container."""
    return _docker("exec", TARGET_CONTAINER, "bash", "-lc", command)


def falco_container() -> str | None:
    r = _docker("ps", "-qf", "name=falco")
    cid = r.stdout.strip().splitlines()
    return cid[0] if cid else None


# --- Wazuh (indexer) ----------------------------------------------------------
def _search(body: dict) -> dict:
    r = requests.get(
        f"{INDEXER_URL}/wazuh-alerts-*/_search",
        json=body, auth=INDEXER_AUTH, verify=False, timeout=10,
    )
    return r.json()


def query_wazuh_alert(rule_id: str, since_epoch: float, timeout: int = 60) -> dict | None:
    """Poll the Wazuh indexer for an alert with the given rule id."""
    body = {
        "size": 1,
        "sort": [{"@timestamp": "desc"}],
        "query": {"bool": {"must": [
            {"term": {"rule.id": rule_id}},
            {"range": {"@timestamp": {"gte": int(since_epoch * 1000), "format": "epoch_millis"}}},
        ]}},
    }
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            hits = _search(body).get("hits", {}).get("hits", [])
            if hits:
                return hits[0]["_source"]
        except requests.RequestException:
            pass
        time.sleep(3)
    return None


def count_wazuh_alerts(since_epoch: float) -> int:
    try:
        body = {"query": {"range": {"@timestamp": {
            "gte": int(since_epoch * 1000), "format": "epoch_millis"}}}}
        return _search({"size": 0, **body}).get("hits", {}).get("total", {}).get("value", -1)
    except requests.RequestException:
        return -1


# --- Falco (events.json in the container) ------------------------------------
def _falco_time_epoch(ev: dict) -> float:
    t = ev.get("time", "")
    try:
        # 2026-09-07T14:00:00.123456789Z -> trim ns to us
        t = t.rstrip("Z")
        if "." in t:
            head, frac = t.split(".", 1)
            t = f"{head}.{frac[:6]}"
        import datetime as _dt
        return _dt.datetime.fromisoformat(t).replace(tzinfo=_dt.timezone.utc).timestamp()
    except ValueError:
        return 0.0


def query_falco_alert(rule_name: str, since_epoch: float, timeout: int = 60) -> dict | None:
    """Poll the Falco events file inside the container for a matching rule."""
    cid = falco_container()
    if not cid:
        return None
    deadline = time.time() + timeout
    while time.time() < deadline:
        r = _docker("exec", cid, "sh", "-c", f"cat {FALCO_EVENTS} 2>/dev/null")
        for line in r.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                ev = json.loads(line)
            except json.JSONDecodeError:
                continue
            if ev.get("rule") == rule_name and _falco_time_epoch(ev) >= since_epoch - 5:
                return ev
        time.sleep(3)
    return None
