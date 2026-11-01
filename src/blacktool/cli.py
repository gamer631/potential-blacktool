"""Command-line entry point."""
import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit
from .checks import dns_check, http_check, tls_check
from .scope import Scope

def main():
    parser = argparse.ArgumentParser(prog="blacktool", description="Scoped passive security assessment")
    sub = parser.add_subparsers(dest="command", required=True)
    init = sub.add_parser("init-scope", help="Create an HTTPS scope template")
    init.add_argument("url")
    scan = sub.add_parser("scan", help="Run passive checks against an allowlisted HTTPS URL")
    scan.add_argument("url")
    scan.add_argument("--scope", required=True)
    scan.add_argument("--acknowledge-authorization", action="store_true")
    scan.add_argument("--output", default="reports/latest.json")
    args = parser.parse_args()

    if args.command == "init-scope":
        parsed = urlsplit(args.url)
        if parsed.scheme != "https" or not parsed.hostname:
            parser.error("Provide an absolute HTTPS URL")
        Path("scope.json").write_text(json.dumps({"allowed_hosts": [parsed.hostname],
            "max_requests": 10, "timeout_seconds": 8}, indent=2) + "\\n", encoding="utf-8")
        print("Created scope.json; review it before scanning.")
        return

    if not args.acknowledge_authorization:
        parser.error("Confirm ownership or written permission with --acknowledge-authorization")
    scope = Scope.load(args.scope)
    host = scope.validate_url(args.url)
    http_meta, findings = http_check(args.url, scope)
    findings.extend(tls_check(host, scope.timeout_seconds))
    report = {"tool": "Potential BlackTool", "version": "0.1.0",
        "generated_at": datetime.now(timezone.utc).isoformat(), "target": args.url,
        "dns": dns_check(host), "http": http_meta, "findings": findings,
        "notice": "Passive observations only; manually validate findings."}
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(f"Done: {len(findings)} observation(s). Report: {output}")

if __name__ == "__main__":
    main()
