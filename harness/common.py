"""Shared helpers for the detection-lab-lite harness."""
from __future__ import annotations

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


@dataclass
class Scenario:
    tid: str
    description: str
    runner: str            # "atomic" | "script"
    command: str
    expect_engine: str     # "wazuh" | "falco"
    expect_rule: str       # wazuh rule id, or Falco rule name (matched via data.rule)
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


def target_exec(command: str) -> subprocess.CompletedProcess:
    """Run a shell command inside the victim container."""
    return subprocess.run(
        ["docker", "exec", TARGET_CONTAINER, "bash", "-lc", command],
        capture_output=True, text=True,
    )


# --- Wazuh indexer — the single alert store (FIM + Falco both land here) ------
def _search(body: dict) -> dict:
    r = requests.get(
        f"{INDEXER_URL}/wazuh-alerts-*/_search",
        json=body, auth=INDEXER_AUTH, verify=False, timeout=10,
    )
    return r.json()


def _poll(body: dict, timeout: int) -> dict | None:
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


def _since_clause(since_epoch: float) -> dict:
    return {"range": {"@timestamp": {"gte": int(since_epoch * 1000), "format": "epoch_millis"}}}


def query_wazuh_alert(rule_id: str, since_epoch: float, timeout: int = 60) -> dict | None:
    """Poll the indexer for a Wazuh alert with the given rule id."""
    return _poll({
        "size": 1, "sort": [{"@timestamp": "desc"}],
        "query": {"bool": {"must": [{"term": {"rule.id": rule_id}}, _since_clause(since_epoch)]}},
    }, timeout)


def query_falco_alert(rule_name: str, since_epoch: float, timeout: int = 60) -> dict | None:
    """Poll the indexer for a Falco-sourced alert (data.rule == the Falco rule name)."""
    return _poll({
        "size": 1, "sort": [{"@timestamp": "desc"}],
        "query": {"bool": {"must": [
            {"match_phrase": {"data.rule": rule_name}},
            {"term": {"rule.groups": "falco"}},
            _since_clause(since_epoch),
        ]}},
    }, timeout)


def count_wazuh_alerts(since_epoch: float) -> int:
    try:
        return _search({"size": 0, "query": _since_clause(since_epoch)}) \
            .get("hits", {}).get("total", {}).get("value", -1)
    except requests.RequestException:
        return -1
