"""Shared helpers for the detection-lab-lite harness."""
from __future__ import annotations

import os
import pathlib
import subprocess
import time
from dataclasses import dataclass

import requests
import yaml

requests.packages.urllib3.disable_warnings()  # lab uses self-signed certs

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
            expect_rule=str(exp.get("rule_id", "")),
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


def query_wazuh_alert(rule_id: str, since_epoch: float, timeout: int = 90) -> dict | None:
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
            r = requests.get(
                f"{INDEXER_URL}/wazuh-alerts-*/_search",
                json=body, auth=INDEXER_AUTH, verify=False, timeout=10,
            )
            hits = r.json().get("hits", {}).get("hits", [])
            if hits:
                return hits[0]["_source"]
        except requests.RequestException:
            pass
        time.sleep(3)
    return None
