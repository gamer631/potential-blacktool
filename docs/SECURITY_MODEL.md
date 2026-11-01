# Security model and limitations

Potential BlackTool is a defensive review aid, not an exploit framework.

## Network behavior
The website command makes a single HTTPS GET to the exact allowlisted hostname and a separate TLS handshake. It does not follow redirects, crawl links, submit forms, mutate data, guess credentials, or inject payloads. Keep target scope and rate limits aligned with written authorization.

## Local analysis
Source scanning reads files and matches patterns. It does not execute project code. OpenAPI auditing parses a local JSON document and does not call declared endpoints.

## Limitations
- Pattern matches can be false positives or miss context-dependent issues.
- A missing security header is not automatically an exploitable vulnerability.
- TLS checks use the host's public/default HTTPS port.
- API schema declarations cannot establish runtime authorization correctness.
- No CVE database is bundled; dependency findings are not yet supported.

## Reporting
Reports may contain local file paths and security-sensitive observations. Store them securely and remove secrets before sharing.
