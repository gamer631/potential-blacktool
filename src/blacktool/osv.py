"""Optional read-only dependency advisory lookup using the public OSV API."""
import json
import urllib.error
import urllib.request

_ENDPOINT = "https://api.osv.dev/v1/querybatch"
_ECOSYSTEMS = {"pypi": "PyPI", "npm": "npm", "go": "Go"}

def query_advisories(packages, timeout=12):
    """Query exact package versions only. No project files are uploaded."""
    queries = []
    for item in packages:
        ecosystem = str(item.get("ecosystem", "")).lower()
        name = str(item.get("name", "")).strip()
        version = str(item.get("version") or "").strip()
        if ecosystem in _ECOSYSTEMS and name and version:
            queries.append({"package": {"name": name, "ecosystem": _ECOSYSTEMS[ecosystem]}, "version": version})
    findings = []
    for start in range(0, len(queries), 100):
        batch = queries[start:start + 100]
        request = urllib.request.Request(
            _ENDPOINT, data=json.dumps({"queries": batch}).encode("utf-8"),
            headers={"Content-Type": "application/json", "Accept": "application/json",
                     "User-Agent": "PotentialBlackTool/0.3"}, method="POST")
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                payload = json.loads(response.read(4_000_000).decode("utf-8"))
        except (urllib.error.URLError, TimeoutError, OSError, ValueError) as exc:
            raise RuntimeError("OSV advisory lookup failed; check network access and retry.") from exc
        for package, result in zip(batch, payload.get("results", [])):
            for advisory in result.get("vulns", []):
                advisory_id = str(advisory.get("id") or "UNKNOWN")
                findings.append({
                    "area": "dependencies", "rule_id": "OSV-" + advisory_id,
                    "severity": "high", "title": "OSV advisory: " + advisory_id,
                    "package": package["package"]["name"], "version": package["version"],
                    "ecosystem": package["package"]["ecosystem"],
                    "detail": str(advisory.get("summary") or "OSV reports an advisory for this exact package version.")[:600],
                    "references": [r["url"] for r in advisory.get("references", []) if r.get("url")][:5],
                    "recommendation": "Review the advisory and upgrade to a maintained version outside affected ranges."
                })
    return findings, len(queries)
