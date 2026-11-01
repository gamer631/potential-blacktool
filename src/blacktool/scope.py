"""Exact-host allowlist and safe URL validation."""
import json
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

@dataclass(frozen=True)
class Scope:
    allowed_hosts: frozenset[str]
    max_requests: int = 10
    timeout_seconds: int = 8
    user_agent: str = "PotentialBlackTool/0.1 (authorized assessment)"

    @classmethod
    def load(cls, path):
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        hosts = frozenset(str(x).strip().lower().rstrip(".") for x in data["allowed_hosts"])
        if not hosts or any(not h or "/" in h or ":" in h for h in hosts):
            raise ValueError("allowed_hosts must contain valid exact hostnames")
        limit, timeout = int(data.get("max_requests", 10)), int(data.get("timeout_seconds", 8))
        if not 1 <= limit <= 50 or not 1 <= timeout <= 20:
            raise ValueError("max_requests must be 1-50 and timeout_seconds 1-20")
        return cls(hosts, limit, timeout, str(data.get("user_agent", cls.user_agent)))

    def validate_url(self, url):
        p = urlsplit(url)
        if p.scheme != "https" or not p.hostname or p.username or p.password:
            raise ValueError("Only absolute HTTPS URLs without embedded credentials are accepted")
        host = p.hostname.lower().rstrip(".")
        if host not in self.allowed_hosts:
            raise ValueError(f"Host {host!r} is not explicitly allowlisted")
        if p.port not in (None, 443):
            raise ValueError("Only standard HTTPS port 443 is allowed")
        return host
