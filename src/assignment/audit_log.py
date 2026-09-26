"""
Assignment 11 — Audit Log starter (TODO).

Records every interaction for forensics. Never blocks by itself —
other layers catch attacks; this layer makes them reviewable.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path


def default_audit_log_path() -> str:
    """Always resolve to <repo>/outputs/… (safe when cwd is src/)."""
    repo_root = Path(__file__).resolve().parents[2]
    return str(repo_root / "outputs" / "audit_log.json")


import time


class AuditLogPlugin:
    """Framework-agnostic audit logger (wire into ADK callbacks or your pipeline)."""

    def __init__(self):
        self.name = "audit_log"
        self.logs: list[dict] = []
        self._open: dict[str, dict] = {}

    def record_input(self, *, user_id: str, text: str, request_id: str | None = None):
        """Store input + start timestamp keyed by request_id/user_id."""
        key = request_id or f"{user_id}_{len(self.logs)}"
        self._open[key] = {
            "start_time": time.time(),
            "timestamp": utc_now_iso(),
            "user_id": user_id,
            "input_text": text,
        }

    def record_output(
        self,
        *,
        user_id: str,
        text: str,
        blocked: bool = False,
        layer: str | None = None,
        request_id: str | None = None,
    ):
        """Store output, layer decision, latency; append to self.logs."""
        key = request_id or f"{user_id}_{len(self.logs)}"
        entry_meta = self._open.pop(key, None)
        start_time = entry_meta["start_time"] if entry_meta else time.time()
        timestamp = entry_meta["timestamp"] if entry_meta else utc_now_iso()
        input_text = entry_meta["input_text"] if entry_meta else ""
        latency_ms = round((time.time() - start_time) * 1000, 2)

        log_record = {
            "request_id": key,
            "timestamp": timestamp,
            "user_id": user_id,
            "input": input_text,
            "output": text,
            "blocked": blocked,
            "layer": layer,
            "latency_ms": latency_ms,
        }
        self.logs.append(log_record)

    def export_json(self, filepath: str | None = None) -> str:
        """Write logs to disk (JSON array) under repo-root ``outputs/`` by default."""
        path = Path(filepath) if filepath else Path(default_audit_log_path())
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(self.logs, ensure_ascii=False, indent=2), encoding="utf-8")
        return str(path)


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()
