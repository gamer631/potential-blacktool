# Usage guide

## 1. Website posture review
Create a scope file from a hostname you are authorized to assess. Inspect the generated JSON and keep only exact approved hosts. The scanner sends one HTTPS GET and performs a TLS handshake; it never crawls or follows redirects.

## 2. Local source review
Run `blacktool scan-code ./src`. Review every match in context. Pattern-based static analysis is not a substitute for code review, SAST, or runtime testing.

## 3. API contract review
Run `blacktool audit-api openapi.json`. This checks schema declarations, including explicitly empty security requirements and HTTP server URLs. It cannot establish whether the deployed API enforces access control.

## 4. Dependency inventory
Run `blacktool audit-deps .`. This inventories a small set of manifest formats. It does not query an advisory database and does not declare packages vulnerable or safe.

## 5. CI policy
Convert reports to SARIF for code-scanning ingestion or use `blacktool policy report.json --fail-on high` to fail a pipeline when findings meet a threshold.
