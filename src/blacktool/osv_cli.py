"""Optional CLI entry point for exact-version OSV advisory lookups."""
import argparse
import json
from pathlib import Path
from .dependencies import audit_dependencies
from .osv import query_advisories

def main():
    parser = argparse.ArgumentParser(description="Check pinned dependencies against OSV.")
    parser.add_argument("path", nargs="?", default=".")
    parser.add_argument("--output", default="reports/osv.json")
    args = parser.parse_args()
    packages, findings = audit_dependencies(args.path)
    matches, checked = query_advisories(packages)
    findings.extend(matches)
    report = {"tool": "Potential BlackTool", "target": str(Path(args.path).resolve()),
              "packages_checked": checked, "dependencies": packages, "findings": findings}
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print("Checked", checked, "exact package versions; advisory matches:", len(matches))
    print("Report:", output)

if __name__ == "__main__":
    main()
