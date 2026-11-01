# Authenticated API validation

This mode is designed for a dedicated staging environment and a test account. It is
not an exploit framework or a substitute for a full authorization assessment.

## Run

Create or review an exact-host scope file:

```bash
blacktool init-scope https://staging.example --output staging-scope.json
```

Create `endpoints.json` containing only approved GET URLs, for example:

```json
["https://staging.example/api/me", "https://staging.example/api/profile"]
```

Set a short-lived, least-privilege staging token in the environment (never in a
file or command-line argument):

- PowerShell: `$env:STAGING_TOKEN = "…"`
- macOS/Linux: `export STAGING_TOKEN="…"`

Then run:

```bash
blacktool audit-auth-api endpoints.json --scope staging-scope.json --token-env STAGING_TOKEN --acknowledge-authorization
```

The client sends only GET requests to exact allowlisted HTTPS hosts, uses normal TLS
certificate validation, does not follow redirects, respects the scope request-count
and timeout limits, and never writes response bodies or tokens to reports. It checks
HTTP outcomes and selected response headers. It does not enumerate routes, mutate
data, fuzz parameters, bypass access controls, or prove IDOR/BOLA absence.

Use synthetic records and a dedicated test account. Confirm written authorization,
approved endpoints, test window, rate limits, and emergency contact before running.
