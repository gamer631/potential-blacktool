"""Strict target scope controls."""
import json
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

@dataclass(frozen=True)
class Scope:
    allowed_hosts: frozenset[str]
    max_requests: int = 10
    timeout_seconds: int = 8
    user_agent: str = "PotentialBlackTool/0.2 (authorized defensive assessment)"

    @classmethod
    def load(cls, path):
        data=json.loads(Path(path).read_text(encoding="utf-8"))
        raw=data.get("allowed_hosts", [])
        hosts=frozenset(str(x).strip().lower().rstrip(".") for x in raw)
        if not hosts or any(not h or "/" in h or ":" in h or " " in h for h in hosts):
            raise ValueError("allowed_hosts must contain exact hostnames")
        limit=int(data.get("max_requests",10)); timeout=int(data.get("timeout_seconds",8))
        if not 1 <= limit <= 50: raise ValueError("max_requests must be between 1 and 50")
        if not 1 <= timeout <= 20: raise ValueError("timeout_seconds must be between 1 and 20")
        return cls(hosts,limit,timeout,str(data.get("user_agent",cls.user_agent)))

    def validate_url(self,url):
        p=urlsplit(url)
        if p.scheme!="https" or not p.hostname or p.username or p.password:
            raise ValueError("Only absolute HTTPS URLs without embedded credentials are accepted")
        host=p.hostname.lower().rstrip(".")
        if host not in self.allowed_hosts: raise ValueError(f"Host {host!r} is not explicitly allowlisted")
        if p.port not in (None,443): raise ValueError("Only HTTPS port 443 is allowed")
        return host
