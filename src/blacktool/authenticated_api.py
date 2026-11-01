"""Low-impact authenticated API checks for explicitly authorized staging systems.

Only caller-supplied GET endpoints are requested. Redirects are not followed,
response bodies are never stored, and credentials are read from environment variables.
"""
import os
import ssl
import urllib.error
import urllib.request
from urllib.parse import urlsplit

SECURITY_HEADERS = {
    "strict-transport-security": "Enable HSTS on HTTPS services.",
    "x-content-type-options": "Set X-Content-Type-Options: nosniff.",
    "cache-control": "Review caching for authenticated or sensitive API responses.",
}


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def audit_authenticated_endpoints(endpoints, scope, token_env=None, opener=None):
    """Check at most scope.max_requests allowlisted HTTPS GET endpoints."""
    if not isinstance(endpoints, list) or not endpoints:
        raise ValueError("Provide a non-empty JSON list of endpoint URLs")
    if len(endpoints) > scope.max_requests:
        raise ValueError("Endpoint count exceeds the scope request limit")
    token = os.environ.get(token_env, "") if token_env else ""
    if token_env and not token:
        raise ValueError(f"Environment variable {token_env!r} is not set")
    opener = opener or urllib.request.build_opener(
        _NoRedirect(), urllib.request.HTTPSHandler(context=ssl.create_default_context())
    )
    findings, observations = [], []
    for url in endpoints:
        host = scope.validate_url(url)
        parsed = urlsplit(url)
        if parsed.query or parsed.fragment:
            raise ValueError("Endpoint URLs must not contain query strings or fragments")
        headers = {"Accept": "application/json", "User-Agent": scope.user_agent}
        if token:
            headers["Authorization"] = "Bearer " + token
        request = urllib.request.Request(url, headers=headers, method="GET")
        status, response_headers = None, {}
        try:
            with opener.open(request, timeout=scope.timeout_seconds) as response:
                status = response.status
                response_headers = {k.lower(): v for k, v in response.headers.items()}
                # Do not read or retain response bodies; authenticated data may be sensitive.
        except urllib.error.HTTPError as exc:
            status = exc.code
            response_headers = {k.lower(): v for k, v in exc.headers.items()}
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            findings.append({"area":"authenticated_api","severity":"info",
                "title":"Endpoint could not be checked","detail":f"{host}: {type(exc).__name__}",
                "recommendation":"Verify staging availability and network policy; no exploit attempt was made."})
            observations.append({"url":url,"status":None})
            continue
        if status in (301,302,303,307,308):
            findings.append({"area":"authenticated_api","severity":"medium","title":"Endpoint redirects",
                "detail":f"{url} returned HTTP {status}; redirect was deliberately not followed.",
                "recommendation":"Review redirect destination and configure the canonical HTTPS endpoint."})
        elif status in (401,403):
            findings.append({"area":"authenticated_api","severity":"info","title":"Authentication or authorization denied",
                "detail":f"{url} returned HTTP {status}.",
                "recommendation":"Confirm the dedicated test account has only the intended staging permissions."})
        elif status >= 500:
            findings.append({"area":"authenticated_api","severity":"medium","title":"Server error on API endpoint",
                "detail":f"{url} returned HTTP {status}.",
                "recommendation":"Review server-side logs; response bodies and secrets are not collected."})
        for name, recommendation in SECURITY_HEADERS.items():
            if name not in response_headers:
                findings.append({"area":"authenticated_api","severity":"low","title":f"Missing {name} header",
                    "detail":url,"recommendation":recommendation})
        content_type = response_headers.get("content-type", "")
        observations.append({"url":url,"status":status,"content_type":content_type})
    return findings, observations
