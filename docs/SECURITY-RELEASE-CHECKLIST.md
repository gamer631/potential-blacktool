# Security release checklist

A release is not production-ready until an independent reviewer has completed this
checklist and attached evidence.

- [ ] Latest Python matrix, JavaScript checks, Go tests, and CodeQL complete successfully.
- [ ] Dependency advisories triaged; lockfiles committed; secrets scan clean.
- [ ] Threat model covers scope bypass, SSRF, redirect handling, credential handling,
      report confidentiality, denial-of-service, and untrusted repository input.
- [ ] All network requests require exact allowlisted HTTPS hosts, bounded count,
      bounded timeout, verified TLS, and safe redirect behavior.
- [ ] Authenticated mode uses short-lived least-privilege test credentials from
      environment/secret manager; tokens and response bodies never enter logs.
- [ ] Reports redact secrets and are stored with restricted access and retention.
- [ ] Dashboard binds to loopback by default and has no unauthenticated remote mode.
- [ ] Cloud adapters are opt-in, read-only, and tested with least-privilege roles.
- [ ] Framework rules have positive and negative fixtures and documented false positives.
- [ ] Runtime verification was performed only in an isolated lab or authorized staging.
- [ ] Independent reviewer records findings, severity, remediation, and sign-off.
- [ ] License, supported Python versions, installation, rollback, and incident process reviewed.

Do not mark unchecked items complete. CI success is necessary but does not constitute
an independent security review or production approval.
