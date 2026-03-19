"""
swarmhawk.cli
=============
Main CLI entry point.

Usage:
  swarmhawk scan --target acme-corp.com --scope scopes/acme.json
  swarmhawk scope new --customer ACME --domain acme-corp.com
  swarmhawk scope verify --file scopes/acme.json
  swarmhawk audit --file reports/audit.json

Flags:
  --mock          Force mock mode (no real tools required — good for demo)
  --output DIR    Report output directory (default: ./reports)
  --nvd-key KEY   NVD API key for higher rate limits
  --verbose       Debug logging
"""

import argparse
import json
import logging
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

from swarmhawk.scope import ScopeLedger, ScopeViolation
from swarmhawk.audit import AuditLog
from swarmhawk.recon import ReconAgent
from swarmhawk.exploit import ExploitAgent
from swarmhawk.synthesis import SynthesisAgent
from swarmhawk.report import ReportGenerator


# ── ANSI colors ───────────────────────────────────────────────────────────────
class C:
    RESET   = "\033[0m"
    BOLD    = "\033[1m"
    GREEN   = "\033[92m"
    CYAN    = "\033[96m"
    YELLOW  = "\033[93m"
    RED     = "\033[91m"
    DIM     = "\033[2m"
    ORANGE  = "\033[38;5;208m"

def banner():
    print(f"""
{C.CYAN}{C.BOLD}
  ╔═══════════════════════════════════════════════════════╗
  ║                                                       ║
  ║    ✦  S W A R M H A W K   A I                        ║
  ║       Autonomous Offensive Security Platform          ║
  ║       MVP v1.0.0                                      ║
  ║                                                       ║
  ╚═══════════════════════════════════════════════════════╝
{C.RESET}""")

def log_step(icon, msg, color=C.CYAN):
    ts = datetime.now().strftime("%H:%M:%S")
    print(f"  {C.DIM}{ts}{C.RESET}  {color}{icon}{C.RESET}  {msg}")

def log_finding(f):
    sev_color = {
        "critical": C.RED, "high": C.ORANGE,
        "medium": C.YELLOW, "low": C.GREEN
    }.get(f.severity, C.DIM)
    print(
        f"  {C.DIM}      {C.RESET}  "
        f"{sev_color}[{f.severity.upper():8}]{C.RESET}  "
        f"{f.title[:58]}  "
        f"{C.DIM}CVSS {f.cvss_score}{C.RESET}"
    )


# ── SCAN COMMAND ──────────────────────────────────────────────────────────────

def cmd_scan(args):
    banner()

    # ── Load scope ────────────────────────────────────────────────────────────
    if args.scope:
        try:
            scope = ScopeLedger.from_file(args.scope)
            log_step("🔐", f"Scope ledger loaded: {scope.summary()}", C.GREEN)
        except (ValueError, FileNotFoundError) as e:
            print(f"\n{C.RED}  ✗ Scope ledger error: {e}{C.RESET}\n")
            sys.exit(1)
    else:
        # Auto-create a scope for the target (demo/dev mode)
        scope = ScopeLedger.create(
            customer_id="DEMO-CUSTOMER",
            target_domains=[args.target, f"*.{args.target}"],
            authorized_by="auto-demo-scope",
            window_days=1,
        )
        log_step(
            "⚠",
            "No scope file — auto-created demo scope. "
            "Use 'swarmhawk scope new' for production.",
            C.YELLOW
        )

    # ── Validate scope ────────────────────────────────────────────────────────
    try:
        scope.assert_in_scope(args.target)
        scope.assert_window_active()
    except ScopeViolation as e:
        print(f"\n{C.RED}  ✗ SCOPE VIOLATION: {e}{C.RESET}\n")
        sys.exit(1)

    print()
    log_step("◈", f"Target: {C.BOLD}{args.target}{C.RESET}", C.CYAN)
    log_step("◈", f"Customer: {scope.customer_id}", C.CYAN)
    log_step("◈", f"Mode: {'MOCK' if args.mock else 'LIVE'}", C.CYAN)
    log_step("◈", f"Output: {args.output}", C.CYAN)
    print()

    # ── Init services ─────────────────────────────────────────────────────────
    db_path = Path(args.output) / f"audit_{args.target.replace('.','_')}.db"
    Path(args.output).mkdir(parents=True, exist_ok=True)
    audit = AuditLog(str(db_path))
    audit.append("HAWK-OS", "mission_start", args.target, "initiated",
                  {"customer": scope.customer_id, "mock": args.mock})

    start_time = time.time()

    # ════════════════════════════════════════════════════════
    # PHASE 1: RECONNAISSANCE
    # ════════════════════════════════════════════════════════
    print(f"  {C.BOLD}{'─'*54}{C.RESET}")
    print(f"  {C.CYAN}PHASE 1  ▸  RECONNAISSANCE{C.RESET}")
    print(f"  {C.BOLD}{'─'*54}{C.RESET}")

    recon = ReconAgent(scope, audit, mock_mode=args.mock)
    log_step("⬡", "Enumerating subdomains...", C.CYAN)

    assets = recon.run(args.target)

    log_step("✓", f"{len(assets)} live assets discovered", C.GREEN)
    for a in assets[:8]:
        print(f"  {C.DIM}           {C.RESET}  {C.DIM}→{C.RESET}  {a.url}  "
              f"{C.DIM}{a.server or ''}{C.RESET}")
    if len(assets) > 8:
        print(f"  {C.DIM}               + {len(assets)-8} more...{C.RESET}")
    print()

    # ════════════════════════════════════════════════════════
    # PHASE 2: VULNERABILITY DETECTION
    # ════════════════════════════════════════════════════════
    print(f"  {C.BOLD}{'─'*54}{C.RESET}")
    print(f"  {C.ORANGE}PHASE 2  ▸  EXPLOIT DETECTION{C.RESET}")
    print(f"  {C.BOLD}{'─'*54}{C.RESET}")

    exploit = ExploitAgent(
        scope, audit,
        mock_mode=args.mock,
        nvd_api_key=args.nvd_key
    )
    log_step("◈", "Running vulnerability templates...", C.ORANGE)

    findings = exploit.run(assets)

    # Group by severity for display
    crit = [f for f in findings if f.severity == "critical"]
    high = [f for f in findings if f.severity == "high"]
    other = [f for f in findings if f.severity not in ("critical","high")]

    log_step(
        "✓",
        f"{len(findings)} findings validated  "
        f"({len(crit)} critical, {len(high)} high)",
        C.GREEN
    )
    print()

    for f in (crit + high + other):
        log_finding(f)
    print()

    # ════════════════════════════════════════════════════════
    # PHASE 3: AI SYNTHESIS
    # ════════════════════════════════════════════════════════
    print(f"  {C.BOLD}{'─'*54}{C.RESET}")
    print(f"  {C.GREEN}PHASE 3  ▸  AI SYNTHESIS{C.RESET}")
    print(f"  {C.BOLD}{'─'*54}{C.RESET}")

    synthesis = SynthesisAgent(audit, mock_mode=args.mock)
    log_step("✦", "Enriching findings with business context...", C.GREEN)

    for f in findings:
        synthesis.enrich_finding(f)

    duration_secs = int(time.time() - start_time)
    duration_str = f"{duration_secs // 60}m {duration_secs % 60}s"

    exec_summary = synthesis.generate_executive_summary(
        args.target, findings, assets, duration_str
    )
    log_step("✓", "Executive summary generated", C.GREEN)
    print()

    # ════════════════════════════════════════════════════════
    # PHASE 4: REPORT GENERATION
    # ════════════════════════════════════════════════════════
    print(f"  {C.BOLD}{'─'*54}{C.RESET}")
    print(f"  {C.CYAN}PHASE 4  ▸  REPORT GENERATION{C.RESET}")
    print(f"  {C.BOLD}{'─'*54}{C.RESET}")

    reporter = ReportGenerator(output_dir=args.output)
    audit.append("HAWK-OS", "report_start", args.target, "initiated")

    paths = reporter.generate(
        target=args.target,
        assets=assets,
        findings=findings,
        scope=scope,
        audit=audit,
        exec_summary=exec_summary,
        duration=duration_str,
    )

    valid, reason = audit.verify_chain()
    audit.append("HAWK-OS", "mission_complete", args.target, "complete",
                  {"duration": duration_str, "findings": len(findings),
                   "audit_chain_valid": valid})

    # ── Mission complete summary ───────────────────────────────────────────────
    print()
    print(f"  {C.GREEN}{C.BOLD}{'═'*54}{C.RESET}")
    print(f"  {C.GREEN}{C.BOLD}  ✦  MISSION COMPLETE{C.RESET}")
    print(f"  {C.GREEN}{C.BOLD}{'═'*54}{C.RESET}")
    print()
    print(f"  {C.BOLD}Target:{C.RESET}          {args.target}")
    print(f"  {C.BOLD}Assets scanned:{C.RESET}  {len(assets)}")
    print(f"  {C.BOLD}Duration:{C.RESET}        {duration_str}")
    print(f"  {C.BOLD}Findings:{C.RESET}        "
          f"{C.RED}{len(crit)} critical{C.RESET}  "
          f"{C.ORANGE}{len(high)} high{C.RESET}  "
          f"{C.YELLOW}{len(other)} other{C.RESET}")
    print(f"  {C.BOLD}Audit chain:{C.RESET}     "
          f"{'✓ VERIFIED' if valid else '⚠ ' + (reason or 'FAILED')}")
    print()
    print(f"  {C.BOLD}Reports saved:{C.RESET}")
    for label, path in [("HTML", paths["html"]), ("JSON", paths["json"]),
                         ("Audit", paths["audit"]), ("PDF", paths.get("pdf"))]:
        if path:
            print(f"  {C.DIM}  →{C.RESET}  {label:<8} {path}")
    print()


# ── SCOPE COMMANDS ────────────────────────────────────────────────────────────

def cmd_scope_new(args):
    domains = [args.domain, f"*.{args.domain}"]
    scope = ScopeLedger.create(
        customer_id=args.customer,
        target_domains=domains,
        authorized_by=args.authorized_by or "pending-customer-signature",
        window_days=args.days,
    )
    path = args.output or f"scopes/{args.customer.lower().replace(' ', '_')}.json"
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    scope.save(path)

    print(f"\n{C.GREEN}  ✓ Scope ledger created: {path}{C.RESET}")
    print(f"  Signature: {scope.signature[:32]}...")
    print(f"  Targets: {', '.join(domains)}")
    print(f"  Window: {scope.manifest['window_start'][:10]} → "
          f"{scope.manifest['window_end'][:10]}")
    print()

def cmd_scope_verify(args):
    try:
        scope = ScopeLedger.from_file(args.file)
        print(f"\n{C.GREEN}  ✓ Scope ledger VALID{C.RESET}")
        print(f"  {scope.summary()}")
        print()
    except ValueError as e:
        print(f"\n{C.RED}  ✗ Scope ledger INVALID: {e}{C.RESET}\n")
        sys.exit(1)

def cmd_audit(args):
    import sqlite3
    if not Path(args.file).exists():
        print(f"\n{C.RED}  ✗ Audit file not found: {args.file}{C.RESET}\n")
        sys.exit(1)

    # Handle both JSON exports and SQLite databases
    if args.file.endswith(".json"):
        data = json.loads(Path(args.file).read_text())
        print(f"\n  Chain valid: {data.get('chain_valid')}")
        print(f"  Entries: {len(data.get('entries', []))}\n")
        for e in data["entries"][-20:]:
            print(f"  {e['ts'][:19]}  {e['agent']:<12} {e['action']:<20} "
                  f"{e['target'][:30]:<30}  {e['outcome']}")
    else:
        audit = AuditLog(args.file)
        valid, reason = audit.verify_chain()
        print(f"\n  Chain valid: {C.GREEN if valid else C.RED}{valid}{C.RESET}")
        if reason:
            print(f"  Note: {reason}")
        for e in audit.get_recent(20):
            print(f"  {e['ts'][:19]}  {e['agent']:<12} {e['action']:<20} "
                  f"{e['target'][:30]:<30}  {e['outcome']}")
    print()


# ── ARGUMENT PARSING ──────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        prog="swarmhawk",
        description="SwarmHawk AI — Autonomous Offensive Security MVP",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Quick demo (no tools needed):
  swarmhawk scan --target acme-corp.com --mock

  # Real scan with scope file:
  swarmhawk scan --target acme-corp.com --scope scopes/acme.json

  # Create scope ledger for new customer:
  swarmhawk scope new --customer "ACME Corp" --domain acme-corp.com

  # Verify scope ledger integrity:
  swarmhawk scope verify --file scopes/acme_corp.json

  # View audit log:
  swarmhawk audit --file reports/audit_acme_corp_com.db
        """
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # scan
    scan_p = sub.add_parser("scan", help="Run assessment against target")
    scan_p.add_argument("--target", required=True, help="Target domain (e.g. acme-corp.com)")
    scan_p.add_argument("--scope", help="Path to signed scope ledger JSON file")
    scan_p.add_argument("--mock", action="store_true",
                        help="Mock mode — no real tools required (demo/dev)")
    scan_p.add_argument("--output", default="./reports", help="Report output directory")
    scan_p.add_argument("--nvd-key", default="", help="NVD API key (optional, raises rate limits)")
    scan_p.add_argument("--verbose", action="store_true", help="Debug logging")

    # scope new
    scope_p = sub.add_parser("scope", help="Scope ledger management")
    scope_sub = scope_p.add_subparsers(dest="scope_cmd", required=True)

    new_p = scope_sub.add_parser("new", help="Create new scope ledger")
    new_p.add_argument("--customer", required=True, help="Customer name/ID")
    new_p.add_argument("--domain", required=True, help="Target domain")
    new_p.add_argument("--authorized-by", default="", help="Name of authorizing CISO/officer")
    new_p.add_argument("--days", type=int, default=30, help="Engagement window in days")
    new_p.add_argument("--output", help="Output file path")

    verify_p = scope_sub.add_parser("verify", help="Verify scope ledger integrity")
    verify_p.add_argument("--file", required=True, help="Path to scope ledger JSON")

    # audit
    audit_p = sub.add_parser("audit", help="View audit log")
    audit_p.add_argument("--file", required=True, help="Audit DB or JSON export path")

    args = parser.parse_args()

    # Logging
    level = logging.DEBUG if getattr(args, "verbose", False) else logging.WARNING
    logging.basicConfig(level=level, format="%(name)s: %(message)s")

    if args.command == "scan":
        cmd_scan(args)
    elif args.command == "scope":
        if args.scope_cmd == "new":
            cmd_scope_new(args)
        elif args.scope_cmd == "verify":
            cmd_scope_verify(args)
    elif args.command == "audit":
        cmd_audit(args)


if __name__ == "__main__":
    main()
