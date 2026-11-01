# Online dependency advisory checks

Run `blacktool audit-deps . --osv` to optionally query the public OSV batch API for exact package versions found in supported manifests and lockfiles.

The request sends only package coordinates (ecosystem, name and exact version). It does not upload source files, environment variables or credentials. Version ranges are not guessed; only exact versions are queried. OSV matches are advisory results, not proof of exploitability. Review each advisory and the package maintainer's remediation guidance.

Supported ecosystems are PyPI, npm and Go. Manifest parsing is intentionally conservative; review the dependency inventory before relying on the results. Network access is required only when `--osv` is supplied.
