# Cloud and framework coverage plan

## Cloud provider integrations

Current local configuration checks are pattern-based. They do not authenticate to
cloud accounts, inspect live resources, or certify compliance.

| Provider | Safe integration target | Minimum permissions |
|---|---|---|
| AWS | Read-only inventory and public exposure/configuration review | Explicit read-only IAM role |
| Azure | Resource and policy configuration review | Reader role |
| Google Cloud | Asset and IAM policy review | Viewer / Security Reviewer as appropriate |

Future adapters must be opt-in, use official SDKs, obtain short-lived credentials from
the provider's normal credential chain, default to read-only, redact account identifiers
where practical, and never create, modify, delete, or expose resources. No credentials
belong in source files, reports, or CLI arguments.

## Framework-specific source coverage

The current source scanner is heuristic and should not be treated as complete
framework analysis. Expand it with versioned rules and positive/negative fixtures for:

- Python: Django, Flask, FastAPI, Starlette
- JavaScript/TypeScript: Express, NestJS, Next.js
- Java: Spring Boot
- PHP: Laravel, Symfony
- Ruby: Rails
- Go: net/http, Gin, Echo

Each rule needs a stable identifier, severity rationale, remediation, safe fixture,
false-positive fixture, and documented limitations. Prefer established analyzers
(Semgrep rules, Bandit, Ruff security plugins, npm audit, govulncheck, and language
native scanners) where licensing and tool availability permit. Never claim exhaustive
coverage from regex rules alone.

## Controlled runtime verification

Runtime checks must run only against isolated intentionally vulnerable training
applications or staging systems with written authorization. Begin with harmless
positive/negative test cases and non-mutating requests. Do not run destructive payloads
or exploit chains against production. Record the environment, app version, test account
role, exact endpoints, timestamps, and cleanup steps.
