"""Admin routes: user CRUD + license management."""

from fastapi import APIRouter, Depends, HTTPException, Request
from passlib.hash import sha256_crypt

from backend.deps import get_current_user, require_role, audit
from backend.schemas import (
    UserCreate, UserUpdate, PasswordReset, LicenseActivateRequest,
)
from modules.database import (
    get_user_by_username, get_user_by_id, create_user, update_user,
    delete_user, list_users, count_admins, count_active_users,
    get_scans_this_month,
)
from modules.license import (
    get_license_info, check_user_limit, activate_license,
)

router = APIRouter(tags=["admin"])


# ── User CRUD ──

@router.get("/admin/users")
async def admin_list_users(current_user: dict = Depends(require_role("admin"))):
    return list_users()


@router.post("/admin/users")
async def admin_create_user(
    request: Request,
    body: UserCreate,
    current_user: dict = Depends(require_role("admin")),
):
    if not check_user_limit(count_active_users()):
        raise HTTPException(status_code=402, detail="User limit reached — upgrade your license")
    if body.role not in ("admin", "operator", "viewer"):
        raise HTTPException(status_code=400, detail="Role must be admin, operator, or viewer")
    if get_user_by_username(body.username):
        raise HTTPException(status_code=409, detail="Username already exists")
    if len(body.password) < 8:
        raise HTTPException(status_code=400, detail="Password must be at least 8 characters")
    hashed = sha256_crypt.hash(body.password)
    user = create_user(
        username=body.username,
        password_hash=hashed,
        role=body.role,
        email=body.email,
        created_by=current_user["username"],
        notes=body.notes,
    )
    audit(request, current_user, "user_create", body.username)
    return user


@router.get("/admin/users/{user_id}")
async def admin_get_user(
    user_id: int,
    current_user: dict = Depends(require_role("admin")),
):
    user = get_user_by_id(user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return user


@router.put("/admin/users/{user_id}")
async def admin_update_user(
    request: Request,
    user_id: int,
    body: UserUpdate,
    current_user: dict = Depends(require_role("admin")),
):
    user = get_user_by_id(user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    updates = {}
    if body.role is not None:
        if body.role not in ("admin", "operator", "viewer"):
            raise HTTPException(status_code=400, detail="Role must be admin, operator, or viewer")
        if user["role"] == "admin" and body.role != "admin" and count_admins() <= 1:
            raise HTTPException(status_code=400, detail="Cannot remove role from the last admin")
        updates["role"] = body.role
    if body.email is not None:
        updates["email"] = body.email
    if body.is_active is not None:
        if user["role"] == "admin" and not body.is_active and count_admins() <= 1:
            raise HTTPException(status_code=400, detail="Cannot disable the last admin")
        updates["is_active"] = body.is_active
    if body.notes is not None:
        updates["notes"] = body.notes
    result = update_user(user_id, **updates)
    audit(request, current_user, "user_update", user["username"])
    return result


@router.delete("/admin/users/{user_id}")
async def admin_delete_user(
    request: Request,
    user_id: int,
    current_user: dict = Depends(require_role("admin")),
):
    user = get_user_by_id(user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    if user["role"] == "admin" and count_admins() <= 1:
        raise HTTPException(status_code=400, detail="Cannot delete the last admin")
    if user["id"] == current_user["id"]:
        raise HTTPException(status_code=400, detail="Cannot delete yourself")
    delete_user(user_id)
    audit(request, current_user, "user_delete", user["username"])
    return {"status": "deleted", "id": user_id}


@router.post("/admin/users/{user_id}/reset-password")
async def admin_reset_password(
    request: Request,
    user_id: int,
    body: PasswordReset,
    current_user: dict = Depends(require_role("admin")),
):
    user = get_user_by_id(user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    if len(body.new_password) < 8:
        raise HTTPException(status_code=400, detail="Password must be at least 8 characters")
    hashed = sha256_crypt.hash(body.new_password)
    update_user(user_id, password_hash=hashed)
    audit(request, current_user, "password_reset", user["username"])
    return {"status": "password_reset", "username": user["username"]}


# ── License ──

@router.get("/license")
async def license_info(user: dict = Depends(get_current_user)):
    info = get_license_info()
    info["scans_this_month"] = get_scans_this_month()
    info["active_users"] = count_active_users()
    return info


@router.get("/license/usage")
async def license_usage(user: dict = Depends(require_role("admin"))):
    info = get_license_info()
    scans = get_scans_this_month()
    users = count_active_users()
    return {
        "tier": info["tier"],
        "scans_this_month": scans,
        "max_scans_per_month": info["max_scans_per_month"],
        "active_users": users,
        "max_users": info["max_users"],
    }


@router.post("/license/activate")
async def license_activate_endpoint(
    request: Request,
    body: LicenseActivateRequest,
    current_user: dict = Depends(require_role("admin")),
):
    result = activate_license(body.key)
    if result["ok"]:
        audit(request, current_user, "license_activate", result["license"]["tier"])
    return result
