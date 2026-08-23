# Security

## Reporting a vulnerability

Please do not disclose suspected vulnerabilities in public issues. Contact the repository owner privately through GitHub with reproduction steps, affected endpoint or file, impact, and a suggested mitigation if available.

## Current security posture

`service.auth` is an MVP security boundary, not a complete production IAM system. The repository includes short-lived JWTs, rotating refresh tokens, least-privilege skill capability tokens, audit events, security headers, and a deterministic skill-instruction policy scanner.

The scanner is a policy guard and is not a malware detector or sandbox. Production deployments should add signed manifests, persistent identity storage, distributed rate limiting, TLS, network egress controls, dependency scanning, sandboxing, and independent security review.

Never use the development JWT secret in production. Set a high-entropy `JWT_SECRET` through a secret manager or environment configuration.
