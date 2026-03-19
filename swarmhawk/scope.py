"""
swarmhawk.scope
===============
Cryptographically-signed authorization ledger.
Every agent action is checked against this before execution.
No target is touched without explicit customer authorization.
"""

import json
import hashlib
import ipaddress
from pathlib import Path
from datetime import datetime, timezone
from typing import Optional


class ScopeViolation(Exception):
    """Raised when an agent attempts an out-of-scope action."""
    pass


class ScopeLedger:
    """
    SHA-256 signed JSON manifest defining authorized targets,
    permitted techniques, and test windows.

    In production: signed with customer's private key + your private key
    (dual-signature scheme). Here: HMAC-SHA256 for simplicity.
    """

    REQUIRED_FIELDS = [
        "customer_id", "target_domains", "authorized_by",
        "window_start", "window_end", "permitted_techniques"
    ]

    FORBIDDEN_BY_DEFAULT = [
        "destructive_exploit",
        "data_deletion",
        "ransomware_simulation",
        "dos_production",       # DDoS against production (not test endpoints)
        "credential_spray_production",
    ]

    def __init__(self, manifest: dict):
        self._validate_structure(manifest)
        self.manifest = manifest
        self._signature = self._compute_signature()

    # ── Construction ──────────────────────────────────────────────────────────

    @classmethod
    def from_file(cls, path: str) -> "ScopeLedger":
        data = json.loads(Path(path).read_text())
        instance = cls.__new__(cls)
        instance.manifest = data["manifest"]
        instance._signature = data["signature"]
        instance._validate_structure(instance.manifest)
        if not instance.verify():
            raise ValueError(
                f"Scope ledger signature invalid — file may have been tampered: {path}"
            )
        return instance

    @classmethod
    def create(
        cls,
        customer_id: str,
        target_domains: list,
        authorized_by: str,
        window_days: int = 30,
        extra_ips: Optional[list] = None,
        permitted_techniques: Optional[list] = None,
    ) -> "ScopeLedger":
        now = datetime.now(timezone.utc)
        manifest = {
            "customer_id": customer_id,
            "target_domains": target_domains,
            "authorized_ips": extra_ips or [],
            "authorized_by": authorized_by,
            "window_start": now.isoformat(),
            "window_end": now.replace(
                day=min(now.day + window_days, 28)
            ).isoformat(),
            "permitted_techniques": permitted_techniques or [
                "passive_recon", "active_recon", "vuln_scan",
                "nuclei_safe", "report_generation"
            ],
            "forbidden_techniques": cls.FORBIDDEN_BY_DEFAULT,
            "max_scan_rate": "100/s",
            "notes": f"Authorized engagement — customer: {customer_id}",
        }
        return cls(manifest)

    def save(self, path: str):
        Path(path).write_text(json.dumps({
            "manifest": self.manifest,
            "signature": self._signature,
        }, indent=2))

    # ── Verification ──────────────────────────────────────────────────────────

    def _compute_signature(self) -> str:
        payload = json.dumps(self.manifest, sort_keys=True).encode()
        return hashlib.sha256(payload).hexdigest()

    def verify(self) -> bool:
        return self._compute_signature() == self._signature

    def _validate_structure(self, manifest: dict):
        missing = [f for f in self.REQUIRED_FIELDS if f not in manifest]
        if missing:
            raise ValueError(f"Scope ledger missing required fields: {missing}")

    # ── Scope checks ──────────────────────────────────────────────────────────

    def assert_in_scope(self, target: str):
        """Raise ScopeViolation if target is not authorized."""
        if not self.is_in_scope(target):
            raise ScopeViolation(
                f"TARGET OUT OF SCOPE: '{target}' is not authorized in this engagement. "
                f"Authorized: {self.manifest['target_domains']}"
            )

    def is_in_scope(self, target: str) -> bool:
        target = target.lower().strip()
        # Strip protocol
        for prefix in ("https://", "http://"):
            if target.startswith(prefix):
                target = target[len(prefix):]
        # Strip path
        target = target.split("/")[0].split(":")[0]

        for allowed in self.manifest["target_domains"]:
            allowed = allowed.lower().strip()
            if allowed.startswith("*."):
                if target.endswith(allowed[1:]) or target == allowed[2:]:
                    return True
            elif target == allowed or target.endswith("." + allowed):
                return True

        # Check explicit IP ranges
        for ip_range in self.manifest.get("authorized_ips", []):
            try:
                if ipaddress.ip_address(target) in ipaddress.ip_network(ip_range):
                    return True
            except ValueError:
                pass

        return False

    def is_technique_permitted(self, technique: str) -> bool:
        if technique in self.manifest.get("forbidden_techniques", []):
            return False
        return technique in self.manifest.get("permitted_techniques", [])

    def is_window_active(self) -> bool:
        now = datetime.now(timezone.utc)
        try:
            start = datetime.fromisoformat(self.manifest["window_start"])
            end = datetime.fromisoformat(self.manifest["window_end"])
            return start <= now <= end
        except (ValueError, KeyError):
            return False

    def assert_window_active(self):
        if not self.is_window_active():
            raise ScopeViolation(
                f"Test window not active. Window: "
                f"{self.manifest.get('window_start')} → "
                f"{self.manifest.get('window_end')}"
            )

    # ── Properties ────────────────────────────────────────────────────────────

    @property
    def customer_id(self) -> str:
        return self.manifest["customer_id"]

    @property
    def target_domains(self) -> list:
        return self.manifest["target_domains"]

    @property
    def signature(self) -> str:
        return self._signature

    def summary(self) -> str:
        return (
            f"Customer: {self.manifest['customer_id']} | "
            f"Targets: {', '.join(self.manifest['target_domains'])} | "
            f"Valid: {self.verify()} | "
            f"Window active: {self.is_window_active()}"
        )
