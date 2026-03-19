"""
swarmhawk.audit
===============
Tamper-evident append-only audit log.
Every agent action is recorded with a SHA-256 hash chain.
Chain integrity is verifiable at any time.

In production: write to immudb or Kafka WORM topic.
Here: SQLite with hash-chained entries.
"""

import json
import sqlite3
import hashlib
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional


class AuditLog:
    """
    Hash-chained audit log stored in SQLite.

    Each entry contains:
    - seq: monotonically increasing sequence number
    - ts: ISO 8601 timestamp
    - agent: which agent performed the action
    - action: what action was taken
    - target: what was acted upon
    - outcome: result (discovered / proposed / blocked / error)
    - metadata: arbitrary JSON
    - prev_hash: hash of the previous entry
    - hash: SHA-256 of this entry (excluding 'hash' field)

    Tampering with any entry breaks all subsequent hashes.
    """

    GENESIS_HASH = "0" * 64   # Sentinel for the first entry

    def __init__(self, db_path: str = ":memory:"):
        self._db_path = db_path
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._init_db()

    def _init_db(self):
        self._conn.execute("""
            CREATE TABLE IF NOT EXISTS audit_log (
                seq      INTEGER PRIMARY KEY AUTOINCREMENT,
                ts       TEXT NOT NULL,
                agent    TEXT NOT NULL,
                action   TEXT NOT NULL,
                target   TEXT NOT NULL,
                outcome  TEXT NOT NULL,
                metadata TEXT NOT NULL DEFAULT '{}',
                prev_hash TEXT NOT NULL,
                hash     TEXT NOT NULL UNIQUE
            )
        """)
        self._conn.commit()

    # ── Writing ───────────────────────────────────────────────────────────────

    def append(
        self,
        agent: str,
        action: str,
        target: str,
        outcome: str,
        metadata: Optional[dict] = None,
    ) -> dict:
        with self._lock:
            prev_hash = self._latest_hash()
            ts = datetime.now(timezone.utc).isoformat()
            entry = {
                "ts": ts,
                "agent": agent,
                "action": action,
                "target": target,
                "outcome": outcome,
                "metadata": metadata or {},
                "prev_hash": prev_hash,
            }
            entry_hash = self._hash_entry(entry)
            self._conn.execute(
                """INSERT INTO audit_log
                   (ts, agent, action, target, outcome, metadata, prev_hash, hash)
                   VALUES (?,?,?,?,?,?,?,?)""",
                (
                    ts, agent, action, target, outcome,
                    json.dumps(entry.get("metadata", {})),
                    prev_hash, entry_hash,
                ),
            )
            self._conn.commit()
            return {**entry, "hash": entry_hash}

    def _latest_hash(self) -> str:
        row = self._conn.execute(
            "SELECT hash FROM audit_log ORDER BY seq DESC LIMIT 1"
        ).fetchone()
        return row[0] if row else self.GENESIS_HASH

    @staticmethod
    def _hash_entry(entry: dict) -> str:
        """Deterministic hash of entry contents (excluding 'hash' key)."""
        payload = json.dumps(
            {k: v for k, v in entry.items() if k != "hash"},
            sort_keys=True,
        ).encode()
        return hashlib.sha256(payload).hexdigest()

    # ── Reading ───────────────────────────────────────────────────────────────

    def get_recent(self, n: int = 50) -> list:
        rows = self._conn.execute(
            "SELECT seq,ts,agent,action,target,outcome,metadata,prev_hash,hash "
            "FROM audit_log ORDER BY seq DESC LIMIT ?",
            (n,),
        ).fetchall()
        return [self._row_to_dict(r) for r in rows]

    def get_all(self) -> list:
        rows = self._conn.execute(
            "SELECT seq,ts,agent,action,target,outcome,metadata,prev_hash,hash "
            "FROM audit_log ORDER BY seq ASC"
        ).fetchall()
        return [self._row_to_dict(r) for r in rows]

    @staticmethod
    def _row_to_dict(row) -> dict:
        return {
            "seq": row[0], "ts": row[1], "agent": row[2],
            "action": row[3], "target": row[4], "outcome": row[5],
            "metadata": json.loads(row[6]), "prev_hash": row[7], "hash": row[8],
        }

    # ── Verification ──────────────────────────────────────────────────────────

    def verify_chain(self) -> tuple[bool, Optional[str]]:
        """
        Returns (True, None) if chain is intact.
        Returns (False, reason) if any entry has been tampered with.
        """
        entries = self.get_all()
        prev = self.GENESIS_HASH
        for entry in entries:
            # Recompute hash
            check_entry = {k: v for k, v in entry.items()
                           if k not in ("hash", "seq")}
            expected = self._hash_entry(check_entry)
            if entry["hash"] != expected:
                return False, f"Entry seq={entry['seq']} hash mismatch (content tampered)"
            if entry["prev_hash"] != prev:
                return False, f"Entry seq={entry['seq']} prev_hash mismatch (chain broken)"
            prev = entry["hash"]
        return True, None

    def export_json(self, path: str):
        """Export full audit log as JSON for legal/compliance purposes."""
        valid, reason = self.verify_chain()
        data = {
            "chain_valid": valid,
            "chain_note": reason or "Chain integrity verified",
            "entries": self.get_all(),
        }
        Path(path).write_text(json.dumps(data, indent=2))
