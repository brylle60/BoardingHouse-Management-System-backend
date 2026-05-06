from fastapi import APIRouter, Depends, HTTPException, status, Query
from pydantic import BaseModel
from typing import Optional, Any
from datetime import datetime

from models.user import User, RoleName, UserStatus
from models.role import get_all_roles
from repository.user_repository import find_by_id, find_all, delete_user
from config.jwt_config import jwt_config
from config.jwt_middleware import require_roles  # ✅ use centralized require_roles

router = APIRouter(prefix="/api/admin", tags=["admin"])

APP_STARTED_AT = datetime.utcnow()
AUDIT_LOGS: list[dict[str, Any]] = []
SYSTEM_SETTINGS: dict[str, Any] = {
    "site_name": "ResidEase",
    "maintenance_mode": False,
    "allow_registration": True,
    "default_user_role": RoleName.TENANT.value,
    "session_timeout_minutes": 60,
    "support_email": "support@residease.local",
}


# ── Request / Response schemas ────────────────────────────────────────────────

class UserSummary(BaseModel):
    id:         str
    username:   str
    email:      str
    full_name:  Optional[str] = None
    role:       RoleName
    status:     UserStatus
    last_login: Optional[datetime] = None
    created_at: datetime


class UpdateRoleRequest(BaseModel):
    role: RoleName


class UpdateStatusRequest(BaseModel):
    status: UserStatus


class UserListResponse(BaseModel):
    total:  int
    page:   int
    limit:  int
    users:  list[UserSummary]


class SystemSettingsRequest(BaseModel):
    site_name:               Optional[str]      = None
    maintenance_mode:        Optional[bool]     = None
    allow_registration:      Optional[bool]     = None
    default_user_role:       Optional[RoleName] = None
    session_timeout_minutes: Optional[int]      = None
    support_email:           Optional[str]      = None


# ── Helper ────────────────────────────────────────────────────────────────────

def to_user_summary(user: User) -> UserSummary:
    full_name = None
    if user.first_name and user.last_name:
        full_name = f"{user.first_name} {user.last_name}"

    return UserSummary(
        id         = str(user.id),
        username   = user.username,
        email      = user.email,
        full_name  = full_name,
        role       = user.role,
        status     = user.status,
        last_login = user.last_login,
        created_at = user.created_at,
    )


def add_audit_log(
    *,
    action:         str,
    actor_username: str,
    target_type:    str,
    target_id:      str,
    details:        dict[str, Any] | None = None,
) -> None:
    AUDIT_LOGS.append({
        "id":          str(len(AUDIT_LOGS) + 1),
        "timestamp":   datetime.utcnow().isoformat(),
        "action":      action,
        "actor":       actor_username,
        "target_type": target_type,
        "target_id":   target_id,
        "details":     details or {},
    })


# ── Endpoints ─────────────────────────────────────────────────────────────────

@router.get(
    "/users",
    response_model=UserListResponse,
    summary="List all user accounts",
)
async def list_users(
    page:   int                  = Query(default=1,   ge=1),
    limit:  int                  = Query(default=10,  ge=1, le=100),
    role:   Optional[RoleName]   = Query(default=None),
    status: Optional[UserStatus] = Query(default=None),
    search: Optional[str]        = Query(default=None),
    _: User = Depends(require_roles(RoleName.ADMIN)),  # ✅
):
    all_users = await User.find_all().to_list()

    if search:
        search_lower = search.lower()
        all_users = [
            u for u in all_users
            if search_lower in u.username.lower()
            or search_lower in u.email.lower()
        ]

    if role:
        all_users = [u for u in all_users if u.role == role]
    if status:
        all_users = [u for u in all_users if u.status == status]

    total  = len(all_users)
    offset = (page - 1) * limit
    paged  = all_users[offset: offset + limit]

    return UserListResponse(
        total = total,
        page  = page,
        limit = limit,
        users = [to_user_summary(u) for u in paged],
    )


@router.get(
    "/users/{user_id}",
    response_model=UserSummary,
    summary="Get a single user account",
)
async def get_user(
    user_id: str,
    _: User = Depends(require_roles(RoleName.ADMIN)),  # ✅
):
    user = await find_by_id(user_id)
    if not user:
        raise HTTPException(404, "User not found.")
    return to_user_summary(user)


@router.patch(
    "/users/{user_id}/role",
    response_model=UserSummary,
    summary="Assign or change a user's role",
)
async def update_role(
    user_id: str,
    body: UpdateRoleRequest,
    current_admin: User = Depends(require_roles(RoleName.ADMIN)),  # ✅
):
    user = await find_by_id(user_id)
    if not user:
        raise HTTPException(404, "User not found.")

    if str(user.id) == str(current_admin.id):
        raise HTTPException(400, "You cannot change your own role.")

    old_role        = user.role
    user.role       = body.role
    user.updated_at = datetime.utcnow()
    await user.save()

    add_audit_log(
        action         = "user.role.updated",
        actor_username = current_admin.username,
        target_type    = "user",
        target_id      = str(user.id),
        details        = {"old_role": old_role.value, "new_role": body.role.value},
    )
    print(f"[AUDIT] Role changed: {user.username} | {old_role} → {body.role} | by {current_admin.username}")

    return to_user_summary(user)


@router.patch(
    "/users/{user_id}/status",
    response_model=UserSummary,
    summary="Suspend, restore, or deactivate a user account",
)
async def update_status(
    user_id: str,
    body: UpdateStatusRequest,
    current_admin: User = Depends(require_roles(RoleName.ADMIN)),  # ✅
):
    user = await find_by_id(user_id)
    if not user:
        raise HTTPException(404, "User not found.")

    if str(user.id) == str(current_admin.id):
        raise HTTPException(400, "You cannot change your own status.")

    old_status      = user.status
    user.status     = body.status
    user.updated_at = datetime.utcnow()
    await user.save()

    add_audit_log(
        action         = "user.status.updated",
        actor_username = current_admin.username,
        target_type    = "user",
        target_id      = str(user.id),
        details        = {"old_status": old_status.value, "new_status": body.status.value},
    )
    print(f"[AUDIT] Status changed: {user.username} | {old_status} → {body.status} | by {current_admin.username}")

    return to_user_summary(user)


@router.delete(
    "/users/{user_id}",
    summary="Permanently delete a user account",
    status_code=status.HTTP_200_OK,
)
async def delete_user_account(
    user_id: str,
    current_admin: User = Depends(require_roles(RoleName.ADMIN)),  # ✅
):
    user = await find_by_id(user_id)
    if not user:
        raise HTTPException(404, "User not found.")

    if str(user.id) == str(current_admin.id):
        raise HTTPException(400, "You cannot delete your own account.")

    username = user.username
    await user.delete()

    add_audit_log(
        action         = "user.deleted",
        actor_username = current_admin.username,
        target_type    = "user",
        target_id      = user_id,
        details        = {"username": username},
    )
    print(f"[AUDIT] Account deleted: {username} | by {current_admin.username}")

    return {"message": f"Account '{username}' has been permanently deleted."}


@router.get(
    "/stats",
    summary="Get user account statistics for admin dashboard",
)
async def get_user_stats(_: User = Depends(require_roles(RoleName.ADMIN))):  # ✅
    all_users = await User.find_all().to_list()

    return {
        "total":     len(all_users),
        "active":    sum(1 for u in all_users if u.status == UserStatus.ACTIVE),
        "inactive":  sum(1 for u in all_users if u.status == UserStatus.INACTIVE),
        "suspended": sum(1 for u in all_users if u.status == UserStatus.SUSPENDED),
        "by_role": {
            "admin":       sum(1 for u in all_users if u.role == RoleName.ADMIN),
            "manager":     sum(1 for u in all_users if u.role == RoleName.MANAGER),
            "maintenance": sum(1 for u in all_users if u.role == RoleName.MAINTENANCE),
            "tenant":      sum(1 for u in all_users if u.role == RoleName.TENANT),
        }
    }


@router.get(
    "/roles-permissions",
    summary="Get all roles with hierarchy and permissions",
)
async def get_roles_permissions(_: User = Depends(require_roles(RoleName.ADMIN))):  # ✅
    return {"roles": get_all_roles()}


@router.get(
    "/audit-logs",
    summary="Get admin audit logs",
)
async def get_audit_logs(
    page:        int           = Query(default=1,  ge=1),
    limit:       int           = Query(default=20, ge=1, le=100),
    action:      Optional[str] = Query(default=None),
    actor:       Optional[str] = Query(default=None),
    target_type: Optional[str] = Query(default=None),
    _: User = Depends(require_roles(RoleName.ADMIN)),  # ✅
):
    logs = list(reversed(AUDIT_LOGS))
    if action:
        logs = [log for log in logs if log["action"] == action]
    if actor:
        logs = [log for log in logs if log["actor"] == actor]
    if target_type:
        logs = [log for log in logs if log["target_type"] == target_type]

    total  = len(logs)
    offset = (page - 1) * limit
    paged  = logs[offset: offset + limit]

    return {"total": total, "page": page, "limit": limit, "logs": paged}


@router.get(
    "/system-health",
    summary="Get backend system health for admin dashboard",
)
async def get_system_health(_: User = Depends(require_roles(RoleName.ADMIN))):  # ✅
    db_connected = True
    user_count   = 0
    try:
        user_count = await User.find_all().count()
    except Exception:
        db_connected = False

    uptime_seconds = int((datetime.utcnow() - APP_STARTED_AT).total_seconds())
    return {
        "status":          "healthy" if db_connected else "degraded",
        "timestamp":       datetime.utcnow().isoformat(),
        "uptime_seconds":  uptime_seconds,
        "database":        {"connected": db_connected},
        "stats":           {"users": user_count},
    }


@router.get(
    "/system-settings",
    summary="Get system settings",
)
async def get_system_settings(_: User = Depends(require_roles(RoleName.ADMIN))):  # ✅
    return SYSTEM_SETTINGS


@router.patch(
    "/system-settings",
    summary="Update system settings",
)
async def update_system_settings(
    body: SystemSettingsRequest,
    current_admin: User = Depends(require_roles(RoleName.ADMIN)),  # ✅
):
    updates = body.model_dump(exclude_none=True)
    if "default_user_role" in updates and isinstance(updates["default_user_role"], RoleName):
        updates["default_user_role"] = updates["default_user_role"].value

    if "session_timeout_minutes" in updates and updates["session_timeout_minutes"] <= 0:
        raise HTTPException(400, "session_timeout_minutes must be greater than 0.")

    SYSTEM_SETTINGS.update(updates)
    add_audit_log(
        action         = "system.settings.updated",
        actor_username = current_admin.username,
        target_type    = "system_settings",
        target_id      = "global",
        details        = {"updated_fields": list(updates.keys())},
    )
    return {"message": "System settings updated successfully.", "settings": SYSTEM_SETTINGS}