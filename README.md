# Potential BlackTool

A multi-language **defensive security assessment** toolkit for systems you own or are explicitly authorized to test.

> Authorized use only. Passive checks and local source/schema/configuration analysis. No exploitation, authentication bypass, credential attacks, malware, stealth, or unauthorized access.

## Features
- Exact-host scoped HTTPS checks: response headers, TLS certificate expiry and DNS; redirects not followed
- Local source pattern review for Python, JavaScript/TypeScript, Go and common languages
- Secret-pattern detection with matched values redacted
- Docker, Compose, Terraform, Nginx and common configuration pattern review
- Offline OpenAPI/Swagger JSON linting and dependency manifest inventory
- JSON, HTML and SARIF 2.1.0 reports; CI severity gate
- Loopback-only dashboard; JavaScript and Go helpers; Docker and GitHub Actions

## Install
```bash
git clone https://github.com/gamer631/potential-blacktool.git
cd potential-blacktool
python -m venv .venv
# Windows: .venv\\Scripts\\activate
# macOS/Linux: source .venv/bin/activate
pip install -e ".[dev]"
pytest -q
```

## Authenticated staging API checks

For a dedicated staging app, see [the safe authenticated API guide](docs/AUTHENTICATED-API.md). This mode sends bounded, allowlisted HTTPS GET requests only, reads a short-lived bearer token from an environment variable, does not follow redirects, and never reads or stores response bodies.

```bash
blacktool audit-auth-api endpoints.json --scope staging-scope.json --token-env STAGING_TOKEN --acknowledge-authorization
```

Cloud and framework coverage boundaries are documented in [the coverage plan](docs/CLOUD-FRAMEWORK-COVERAGE.md). Production release gates are in [the security checklist](docs/SECURITY-RELEASE-CHECKLIST.md).

## Dashboard
Run `blacktool dashboard` and open http://127.0.0.1:8765.

## CLI
```bash
blacktool init-scope https://your-authorized-domain.example
blacktool scan https://your-authorized-domain.example --scope scope.json --acknowledge-authorization
blacktool scan-code ./project --format sarif
blacktool scan-secrets ./project
blacktool audit-config ./project
blacktool audit-api ./openapi.json
blacktool audit-deps .\nblacktool-osv . --output reports/osv.json
blacktool report-html reports/code.json
blacktool report-sarif reports/code.json
blacktool policy reports/code.json --fail-on high
```

JS helper: `node integrations/javascript/audit.mjs ./src`. Go helper: `cd integrations/go/passive-audit && go run . -path ../../../src`.

## Limitations
Heuristic findings require review. Dependency inventory is not CVE matching; API schema lint is not runtime authorization testing; configuration checks are pattern-based, not full IaC evaluation. Dynamic exploit testing and authenticated application testing are not included.

Only assess systems covered by explicit written authorization. Network checks are low-volume and non-destructive. Never commit credentials, private keys, customer data or scan artifacts. See docs/ and MIT LICENSE.
