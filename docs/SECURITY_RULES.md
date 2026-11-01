# Security rule catalog

All rules are heuristic and require manual validation.

Secret patterns: SEC001 private-key PEM marker; SEC002 AWS access-key identifier shape; SEC003 GitHub token-like string; SEC004 Slack token-like string; SEC005 generic credential assignment; SEC006 possible high-entropy token assignment.

Secret findings never include matched values. Treat a real exposure as compromised: revoke or rotate it, inspect access logs, and follow the provider's guidance for removing it from repository history.

Configuration patterns: CFG001 privileged container; CFG002 host networking; CFG003 debug mode; CFG004/CFG005 unrestricted IPv4/IPv6 ingress; CFG006 floating latest image tag; CFG007 obsolete TLS protocol; CFG008 broad allow-all rule.

These checks do not fully parse formats, resolve variables or evaluate effective cloud policy. Review rendered deployment configuration and provider-side controls.
