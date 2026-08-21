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
- Structured audit events for authentication activity
- Security response headers
- FastAPI-generated OpenAPI docs
- Docker runtime
- Automated pytest CI

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

Refresh tokens are stored only as SHA-256 digests and are invalidated when exchanged, reducing the impact of token theft and replay.

For production, set a high-entropy `JWT_SECRET`, replace the in-memory stores with Postgres/Redis, add distributed rate limiting, configure TLS at the edge, and move privileged provisioning behind an administrator or workload identity flow.

## Architecture direction

The current repository is intentionally small so it can be deployed as a sidecar or central auth service. The next production layers are:

1. Postgres-backed identity and policy storage.
2. Redis-backed refresh-token revocation and distributed rate limits.
3. OIDC/JWKS federation for external identity providers.
4. Workload identity for agent-to-agent calls.
5. Tamper-evident audit export to an observability/SIEM pipeline.
6. Policy evaluation for resource-level authorization.

## Inspiration

The project is a focused substitute in the same broader problem space as today’s fast-growing agent/accountability infrastructure: instead of building a general AI context graph, it makes the **identity, permission, credential lifecycle, and audit boundary** explicit and reusable.
