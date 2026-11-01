# Potential BlackTool

A multi-language **defensive security assessment toolkit** for systems you own or are explicitly authorized to test.

> Authorized use only. This project focuses on passive checks and local source/schema analysis. It does not exploit vulnerabilities, bypass authentication, brute-force accounts, steal credentials, evade monitoring, or access private data.

## Features
- Scoped HTTPS posture checks: headers, response metadata, TLS certificate expiry and DNS
- Exact-host allowlist; redirects are not followed
- Local source-code pattern review for Python, JavaScript/TypeScript, Go and other common languages
- Offline OpenAPI/Swagger JSON schema linting
- Dependency manifest inventory (not CVE scanning)
- JSON, HTML and SARIF 2.1.0 reports
- CI severity policy gate
- JavaScript and Go audit helpers
- Docker image, tests and GitHub Actions

## Install
Python 3.10+:
```bash
git clone https://github.com/gamer631/potential-blacktool.git
cd potential-blacktool
python -m venv .venv
# Windows: .venv\\Scripts\\activate
# macOS/Linux: source .venv/bin/activate
pip install -e .
```

## Commands
```bash
blacktool init-scope https://your-authorized-domain.example
blacktool scan https://your-authorized-domain.example --scope scope.json --acknowledge-authorization
blacktool scan-code ./your-project --output reports/code.json --format sarif
blacktool audit-api ./openapi.json --output reports/api.json
blacktool audit-deps .
blacktool report-html reports/code.json
blacktool report-sarif reports/code.json
blacktool policy reports/code.json --fail-on high
```

JavaScript/TypeScript helper: `node integrations/javascript/audit.mjs ./src`

Go helper: `cd integrations/go/passive-audit && go run . -path ../../../src`

## Finding interpretation
Rules are heuristic indicators, not proof of exploitability. Review context before assigning severity. The dependency command inventories manifests but performs no CVE matching. The API linter checks declarations only, not runtime authorization enforcement.

## Scope and safety
Only test systems covered by explicit written authorization. Keep hostnames exact; subdomains are not automatically included. HTTPS only, redirects are not followed, and network checks are low-volume and non-destructive. Never commit credentials, tokens, private keys, customer data or scan artifacts.

## Development
`make test` or `python -m pip install -e . pytest && pytest -q`.

See [Usage](docs/USAGE.md) and [Security model](docs/SECURITY_MODEL.md). MIT License.
