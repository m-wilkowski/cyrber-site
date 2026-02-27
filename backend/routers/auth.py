"""Authentication routes: login, current user."""

from fastapi import APIRouter, Depends, Request
from passlib.hash import sha256_crypt
from datetime import datetime, timezone

from backend.deps import (
    limiter, create_token, get_current_user, JWT_EXPIRE_HOURS,
)
from backend.schemas import LoginRequest
from modules.database import (
    get_user_by_username_raw, update_user, save_audit_log,
)

router = APIRouter(tags=["auth"])


@router.post("/auth/login")
@limiter.limit("10/minute")
async def auth_login(request: Request, body: LoginRequest):
    ip = request.client.host if request.client else "unknown"
    user = get_user_by_username_raw(body.username)
    if user and user["is_active"] and sha256_crypt.verify(body.password, user["password_hash"]):
        token = create_token(user["username"], user["role"])
        update_user(user["id"], last_login=datetime.now(timezone.utc))
        save_audit_log(user=user["username"], action="login", ip_address=ip)
        return {
            "token": token,
            "token_type": "bearer",
            "expires_in": JWT_EXPIRE_HOURS * 3600,
            "role": user["role"],
            "username": user["username"],
        }
    save_audit_log(user=body.username, action="login_failed", ip_address=ip)
    from fastapi import HTTPException
    raise HTTPException(status_code=401, detail="Invalid credentials")


@router.get("/auth/me")
async def auth_me(current_user: dict = Depends(get_current_user)):
    return current_user
