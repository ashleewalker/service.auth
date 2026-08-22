# service.auth

Secure, auditable authentication and authorization for AI agents and service-to-service workloads.

## Why this exists

Today’s agentic systems are moving from simple API calls to long-running, tool-using workloads. That creates a practical security gap: teams need to know **which workload acted, what it was allowed to do, how long its credential lived, and what happened afterward**.

`service.auth` is a lightweight, self-hostable auth boundary designed around those needs.

## MVP capabilities

- Argon2 password hashing
- Short-lived JWT access tokens
- One-time rotating refresh tokens
- Scope-based authorization
- Privileged-scope escalation protection at registration
- **Skill manifests with least-privilege capability tokens**
- Five-minute skill credentials bound to a specific skill and version
- Structured audit events for authentication and skill activity
- Security response headers
- FastAPI-generated OpenAPI docs
- Docker runtime
- Automated pytest CI

## Why skill-level authorization matters

AI coding agents and tool-using agents increasingly load reusable skills. A skill should not automatically inherit every permission held by the parent identity.

`service.auth` adds a narrow capability-token boundary:

1. A skill declares the minimum scopes it needs.
2. The caller authenticates with its normal access token.
3. `service.auth` checks that the caller already has **every** required scope.
4. The service issues a short-lived capability token with an `aud` claim bound to that skill and a version identifier.
5. The skill receives only the permissions declared by its manifest, never additional privileges.

This makes skills portable without making them all-powerful.

### List available skills

```bash
curl http://localhost:8000/v1/skills
```

### Mint a skill capability token

```bash
curl -X POST http://localhost:8000/v1/skills/token \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H 'content-type: application/json' \
  -d '{"skill":"profile-reader"}'
```

Capability tokens expire after five minutes by default and are cryptographically scoped to the requested skill.

## Quick start

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e '.[test]'
uvicorn app.main:app --reload
```

Then open `/docs` and use the API interactively.

### Register

```bash
curl -X POST http://localhost:8000/v1/auth/register \
  -H 'content-type: application/json' \
  -d '{"email":"you@example.com","password":"correct horse battery staple"}'
```

### Authenticate

```bash
curl http://localhost:8000/v1/me \
  -H "Authorization: Bearer $ACCESS_TOKEN"
```

## Security model

Public registration can only request non-privileged scopes. Administrative scopes such as `audit:read` must be provisioned by a trusted control plane rather than by an end user.

Skill tokens are **not** an escalation mechanism: a caller can only mint a token when its identity already contains every scope declared by the skill manifest. Skill credentials are short-lived and audience-bound.

Refresh tokens are stored only as SHA-256 digests and are invalidated when exchanged, reducing the impact of token theft and replay.

For production, set a high-entropy `JWT_SECRET`, replace the in-memory stores with Postgres/Redis, add distributed rate limiting, configure TLS at the edge, and move privileged provisioning behind an administrator or workload identity flow.

## Architecture direction

The current repository is intentionally small so it can be deployed as a sidecar or central auth service. The next production layers are:

1. Postgres-backed identity and policy storage.
2. Redis-backed refresh-token revocation and distributed rate limits.
3. OIDC/JWKS federation for external identity providers.
4. Workload identity for agent-to-agent calls.
5. Signed, externally managed skill manifests.
6. Tamper-evident audit export to an observability/SIEM pipeline.
7. Policy evaluation for resource-level authorization.

## Inspiration

Today’s GitHub trend is heavily focused on reusable AI-agent skills and making agent workflows more systematic. `service.auth` takes a complementary security-first approach: instead of only defining what a skill can do, it makes **identity, least privilege, credential lifecycle, and accountability** enforceable at runtime.
