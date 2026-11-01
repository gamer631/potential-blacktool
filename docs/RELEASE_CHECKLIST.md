# Release readiness checklist

This repository is an active development foundation, not a certified security product.

Before a tagged release:
- [ ] Run the complete Python, JavaScript and Go CI matrix and verify green results.
- [ ] Review all source rules for false positives and false negatives.
- [ ] Add tests for malformed inputs, symlinks, large manifests and unusual encodings.
- [ ] Perform dependency and container image vulnerability review.
- [ ] Add a documented support policy and vulnerability disclosure contact.
- [ ] Validate SARIF output with GitHub Code Scanning.
- [ ] Review network behavior against a local controlled test server.
- [ ] Have an independent security review of scope enforcement and report handling.
- [ ] Tag a version only after all release gates pass.

Do not represent heuristic findings as confirmed vulnerabilities or claim comprehensive coverage.
