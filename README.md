# Potential BlackTool

A modular, multi-language security assessment toolkit for systems you own or are explicitly authorized to test.

> Use only against assets you own or have written permission to assess. The initial release focuses on passive checks; it does not exploit vulnerabilities, bypass authentication, brute-force accounts, steal credentials, or access private data.

## Initial capabilities
- Passive HTTPS response and security-header review
- TLS certificate validation
- DNS resolution
- Exact-host scope allowlist
- JSON reporting (planned in the first implementation milestone)

## Responsible use
Only test systems covered by your written authorization. Respect engagement scope, service terms, rate limits and applicable laws.

## Roadmap
- [ ] Python CLI and passive HTTP/TLS/DNS checks
- [ ] Automated tests and CI
- [ ] API schema and source-code analysis
- [ ] Go and JavaScript/TypeScript integrations
- [ ] SARIF, HTML and PDF reports
- [ ] Dashboard and CI policy gates
