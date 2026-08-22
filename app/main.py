from __future__ import annotations

import hashlib
import secrets
import time
from datetime import datetime, timedelta, timezone
from typing import Annotated

import jwt
from fastapi import Depends, FastAPI, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pwdlib import PasswordHash
from pydantic import BaseModel, Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")
    app_name: str = "service.auth"
    jwt_secret: str = "dev-only-change-this-secret"
    access_token_minutes: int = 15
    refresh_token_days: int = 30
    skill_token_minutes: int = 5
    issuer: str = "service.auth"


settings = Settings()
password_hash = PasswordHash.recommended()
bearer = HTTPBearer(auto_error=False)

# Demo storage keeps the starter self-contained. Replace with Postgres/Redis adapters for production.
users: dict[str, dict] = {}
refresh_tokens: dict[str, dict] = {}
audit_events: list[dict] = []

# Privileged scopes are never self-assigned during public registration.
PUBLIC_SCOPES = {"profile:read", "profile:write"}
PRIVILEGED_SCOPES = {"audit:read", "admin"}

# Skill manifests define the minimum capability set a skill needs. A caller can only
# receive a skill token when every required scope is already present on its identity.
SKILLS: dict[str, dict] = {
    "profile-reader": {
        "version": "1.0.0",
        "description": "Read the authenticated user's profile.",
        "scopes": ["profile:read"],
    },
    "profile-writer": {
        "version": "1.0.0",
        "description": "Update the authenticated user's profile.",
        "scopes": ["profile:write"],
    },
    "audit-reader": {
        "version": "1.0.0",
        "description": "Read recent authentication audit events.",
        "scopes": ["audit:read"],
    },
}

app = FastAPI(title=settings.app_name, version="0.2.0")


class RegisterIn(BaseModel):
    email: str = Field(min_length=5, max_length=320)
    password: str = Field(min_length=12, max_length=128)
    scopes: list[str] = Field(default_factory=lambda: ["profile:read"])


class LoginIn(BaseModel):
    email: str
    password: str


class RefreshIn(BaseModel):
    refresh_token: str = Field(min_length=32)


class SkillGrantIn(BaseModel):
    skill: str = Field(min_length=1, max_length=100)


class TokenOut(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int
    scopes: list[str]


class SkillTokenOut(BaseModel):
    capability_token: str
    token_type: str = "bearer"
    expires_in: int
    skill: str
    version: str
    scopes: list[str]


class MeOut(BaseModel):
    sub: str
    email: str
    scopes: list[str]


class SkillOut(BaseModel):
    name: str
    version: str
    description: str
    scopes: list[str]


def now() -> datetime:
    return datetime.now(timezone.utc)


def digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def audit(event: str, subject: str | None, request: Request, outcome: str = "success") -> None:
    audit_events.append(
        {
            "timestamp": now().isoformat(),
            "event": event,
            "subject": subject,
            "outcome": outcome,
            "ip": request.client.host if request.client else None,
        }
    )


def issue_access_token(user: dict) -> tuple[str, int]:
    ttl = settings.access_token_minutes * 60
    exp = int(time.time()) + ttl
    payload = {
        "sub": user["id"],
        "scope": " ".join(user["scopes"]),
        "iss": settings.issuer,
        "iat": int(time.time()),
        "exp": exp,
    }
    return jwt.encode(payload, settings.jwt_secret, algorithm="HS256"), ttl


def issue_refresh_token(user: dict) -> str:
    raw = secrets.token_urlsafe(48)
    refresh_tokens[digest(raw)] = {
        "user_id": user["id"],
        "expires_at": now() + timedelta(days=settings.refresh_token_days),
    }
    return raw


def tokens_for(user: dict) -> TokenOut:
    access, ttl = issue_access_token(user)
    return TokenOut(
        access_token=access,
        refresh_token=issue_refresh_token(user),
        expires_in=ttl,
        scopes=user["scopes"],
    )


def issue_skill_token(user: dict, skill_name: str) -> SkillTokenOut:
    skill = SKILLS[skill_name]
    ttl = settings.skill_token_minutes * 60
    now_epoch = int(time.time())
    payload = {
        "sub": user["id"],
        "aud": skill_name,
        "skill": skill_name,
        "skill_version": skill["version"],
        "scope": " ".join(skill["scopes"]),
        "iss": settings.issuer,
        "iat": now_epoch,
        "exp": now_epoch + ttl,
    }
    token = jwt.encode(payload, settings.jwt_secret, algorithm="HS256")
    return SkillTokenOut(
        capability_token=token,
        expires_in=ttl,
        skill=skill_name,
        version=skill["version"],
        scopes=skill["scopes"],
    )


async def current_user(
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(bearer)],
) -> dict:
    if not credentials:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing bearer token")
    try:
        payload = jwt.decode(
            credentials.credentials,
            settings.jwt_secret,
            algorithms=["HS256"],
            issuer=settings.issuer,
        )
    except jwt.PyJWTError as exc:
        raise HTTPException(status_code=401, detail="Invalid or expired access token") from exc
    user = next((u for u in users.values() if u["id"] == payload.get("sub")), None)
    if not user:
        raise HTTPException(status_code=401, detail="Unknown subject")
    return user


def require_scope(scope: str):
    async def dependency(user: Annotated[dict, Depends(current_user)]) -> dict:
        if scope not in user["scopes"]:
            raise HTTPException(status_code=403, detail=f"Missing scope: {scope}")
        return user

    return dependency


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Cache-Control"] = "no-store"
    return response


@app.get("/healthz")
def healthz():
    return {"status": "ok", "service": settings.app_name}


@app.get("/v1/skills", response_model=list[SkillOut])
def list_skills():
    return [SkillOut(name=name, **manifest) for name, manifest in sorted(SKILLS.items())]


@app.post("/v1/skills/token", response_model=SkillTokenOut)
def skill_token(
    body: SkillGrantIn,
    request: Request,
    user: Annotated[dict, Depends(current_user)],
):
    skill = SKILLS.get(body.skill)
    if not skill:
        audit("skill_token", user["id"], request, "unknown_skill")
        raise HTTPException(status_code=404, detail="Unknown skill")
    required = set(skill["scopes"])
    granted = set(user["scopes"])
    if not required.issubset(granted):
        audit("skill_token", user["id"], request, "insufficient_scope")
        raise HTTPException(status_code=403, detail="Identity lacks required skill scopes")
    audit("skill_token", user["id"], request)
    return issue_skill_token(user, body.skill)


@app.post("/v1/auth/register", response_model=TokenOut, status_code=201)
def register(body: RegisterIn, request: Request):
    email = body.email.strip().lower()
    requested = set(body.scopes)
    if requested - PUBLIC_SCOPES:
        audit("register", None, request, "forbidden_scope")
        raise HTTPException(status_code=403, detail="Privileged scopes require an administrator")
    if email in users:
        audit("register", None, request, "duplicate")
        raise HTTPException(status_code=409, detail="Account already exists")
    user = {
        "id": secrets.token_urlsafe(16),
        "email": email,
        "password_hash": password_hash.hash(body.password),
        "scopes": sorted(requested),
    }
    users[email] = user
    audit("register", user["id"], request)
    return tokens_for(user)


@app.post("/v1/auth/login", response_model=TokenOut)
def login(body: LoginIn, request: Request):
    email = body.email.strip().lower()
    user = users.get(email)
    if not user or not password_hash.verify(body.password, user["password_hash"]):
        audit("login", None, request, "denied")
        raise HTTPException(status_code=401, detail="Invalid credentials")
    audit("login", user["id"], request)
    return tokens_for(user)


@app.post("/v1/auth/refresh", response_model=TokenOut)
def refresh(body: RefreshIn, request: Request):
    key = digest(body.refresh_token)
    record = refresh_tokens.pop(key, None)  # rotation: a token can be used only once
    if not record or record["expires_at"] <= now():
        audit("refresh", None, request, "denied")
        raise HTTPException(status_code=401, detail="Invalid or expired refresh token")
    user = next((u for u in users.values() if u["id"] == record["user_id"]), None)
    if not user:
        raise HTTPException(status_code=401, detail="Unknown subject")
    audit("refresh", user["id"], request)
    return tokens_for(user)


@app.get("/v1/me", response_model=MeOut)
async def me(user: Annotated[dict, Depends(current_user)]):
    return MeOut(sub=user["id"], email=user["email"], scopes=user["scopes"])


@app.get("/v1/audit", response_model=list[dict])
async def audit_log(user: Annotated[dict, Depends(require_scope("audit:read"))]):
    return audit_events[-100:]
