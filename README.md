# Potential BlackTool

A modular, multi-language **defensive security assessment** toolkit for systems you own or are explicitly authorized to test.

> Authorized use only. The project is designed for passive checks and local code/schema analysis. It does not exploit vulnerabilities, bypass authentication, brute-force accounts, steal credentials, evade monitoring, or access private data.

## Features
- Scoped HTTPS checks: response metadata, security headers, TLS certificate expiry and DNS resolution
- Exact-host allowlist; redirects are deliberately not followed
- Local source review for risky patterns in Python, JavaScript/TypeScript, Go and other common languages
- Offline OpenAPI/Swagger JSON schema linting
- JSON and standalone HTML reports
- JavaScript and Go read-only source audit helpers
- Pytest tests and GitHub Actions CI

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
Create and review a scope file:
```bash
blacktool init-scope https://your-authorized-domain.example
```
Run passive HTTPS checks (written authorization required):
```bash
blacktool scan https://your-authorized-domain.example --scope scope.json --acknowledge-authorization
```
Analyze a local source tree:
```bash
blacktool scan-code ./your-project --output reports/code.json
```
Lint an OpenAPI/Swagger JSON document offline:
```bash
blacktool audit-api ./openapi.json --output reports/api.json
```
Convert JSON findings to HTML:
```bash
blacktool report-html reports/code.json --output reports/code.html
```

JavaScript/TypeScript helper:
```bash
node integrations/javascript/audit.mjs ./src
```
Go helper:
```bash
go run ./integrations/go/passive-audit -path ./src
```

## Finding interpretation
Rules are heuristic indicators, not proof of exploitability. Review surrounding code and runtime configuration before assigning severity. The OpenAPI linter checks schema declarations only; it does not prove that server-side authorization is correctly enforced. Dependency CVE matching and authenticated testing are not included in this release.

## Safety and scope
- Only assess assets covered by explicit written authorization.
- Keep scope hostnames exact; subdomains are not automatically included.
- HTTPS only; redirects are not followed automatically.
- Network checks are intentionally low-volume and non-destructive.
- Never commit credentials, tokens, private keys, customer data or scan artifacts.

## Development
```bash
pip install -e . pytest
pytest
```

## Roadmap
- [ ] SARIF export and policy thresholds
- [ ] Dependency advisory database integration
- [ ] More framework-specific source rules
- [ ] Dashboard and container packaging
- [ ] Signed engagement configuration and audit logs

## License
MIT. See [LICENSE](LICENSE).
