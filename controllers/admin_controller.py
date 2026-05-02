

from fastapi import APIRouter, Depends, HTTPException, status, Query
from pydantic import BaseModel
from typing import Optional
from datetime import datetime

from models.user import User, RoleName, UserStatus
from repository.user_repository import (
    find_by_id,
    find_all,
    delete_user,
)
from config.jwt_config import jwt_config
from config.jwt_middleware import get_current_user   # adjust import to match yours

router = APIRouter(prefix="/api/admin", tags=["admin"])


# ── Auth dependency ───────────────────────────────────────────────────────────

async def require_admin(current_user: User = Depends(get_current_user)):
    """
    Reusable dependency — raises 403 if caller is not ADMIN.
    Equivalent to @PreAuthorize("hasRole('ADMIN')") in Spring.
    """
    if current_user.role != RoleName.ADMIN:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access required.",
        )
    return current_user


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


# ── Endpoints ─────────────────────────────────────────────────────────────────

@router.get(
    "/users",
    response_model=UserListResponse,
    summary="List all user accounts",
)
async def list_users(
    page:   int            = Query(default=1,    ge=1),
    limit:  int            = Query(default=10,   ge=1, le=100),
    role:   Optional[RoleName]   = Query(default=None),
    status: Optional[UserStatus] = Query(default=None),
    search: Optional[str]        = Query(default=None),
    _: User = Depends(require_admin),
):
    """
    Returns paginated list of all users.
    Supports filtering by role, status, and search (username/email).
    """
    # Build query filter
    query = {}
    if role:
        query["role"] = role
    if status:
        query["status"] = status

    # Fetch all then filter/search in memory (simple approach)
    # For large datasets, use Motor's find() with filter dict instead
    all_users = await User.find_all().to_list()

    # Apply search filter
    if search:
        search_lower = search.lower()
        all_users = [
            u for u in all_users
            if search_lower in u.username.lower()
            or search_lower in u.email.lower()
        ]

    # Apply role + status filters
    if role:
        all_users = [u for u in all_users if u.role == role]
    if status:
        all_users = [u for u in all_users if u.status == status]

    # Paginate
    total  = len(all_users)
    offset = (page - 1) * limit
    paged  = all_users[offset: offset + limit]

    return UserListResponse(
        total  = total,
        page   = page,
        limit  = limit,
        users  = [to_user_summary(u) for u in paged],
    )


@router.get(
    "/users/{user_id}",
    response_model=UserSummary,
    summary="Get a single user account",
)
async def get_user(
    user_id: str,
    _: User = Depends(require_admin),
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
    current_admin: User = Depends(require_admin),
):
    """
    Admin can assign any role to any user.
    Cannot change your own role — prevents accidental self-demotion.
    """
    user = await find_by_id(user_id)
    if not user:
        raise HTTPException(404, "User not found.")

    # Prevent admin from changing their own role
    if str(user.id) == str(current_admin.id):
        raise HTTPException(400, "You cannot change your own role.")

    old_role   = user.role
    user.role  = body.role
    user.updated_at = datetime.utcnow()
    await user.save()

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
    current_admin: User = Depends(require_admin),
):
    """
    ACTIVE    → normal access
    SUSPENDED → blocked from login
    INACTIVE  → soft-deleted, pending cleanup
    Cannot suspend yourself.
    """
    user = await find_by_id(user_id)
    if not user:
        raise HTTPException(404, "User not found.")

    # Prevent admin from suspending themselves
    if str(user.id) == str(current_admin.id):
        raise HTTPException(400, "You cannot change your own status.")

    old_status   = user.status
    user.status  = body.status
    user.updated_at = datetime.utcnow()
    await user.save()

    print(f"[AUDIT] Status changed: {user.username} | {old_status} → {body.status} | by {current_admin.username}")

    return to_user_summary(user)


@router.delete(
    "/users/{user_id}",
    summary="Permanently delete a user account",
    status_code=status.HTTP_200_OK,
)
async def delete_user_account(
    user_id: str,
    current_admin: User = Depends(require_admin),
):
    """
    Permanently deletes the account and all associated data.
    Cannot delete your own admin account.
    """
    user = await find_by_id(user_id)
    if not user:
        raise HTTPException(404, "User not found.")

    # Prevent admin from deleting themselves
    if str(user.id) == str(current_admin.id):
        raise HTTPException(400, "You cannot delete your own account.")

    username = user.username
    await user.delete()

    print(f"[AUDIT] Account deleted: {username} | by {current_admin.username}")

    return {"message": f"Account '{username}' has been permanently deleted."}


@router.get(
    "/stats",
    summary="Get user account statistics for admin dashboard",
)
async def get_user_stats(_: User = Depends(require_admin)):
    """
    Returns counts for the admin dashboard stat cards.
    """
    all_users = await User.find_all().to_list()

    return {
        "total":     len(all_users),
        "active":    sum(1 for u in all_users if u.status == UserStatus.ACTIVE),
        "inactive":  sum(1 for u in all_users if u.status == UserStatus.INACTIVE),
        "suspended": sum(1 for u in all_users if u.status == UserStatus.SUSPENDED),
        "by_role": {
            "admin":       sum(1 for u in all_users if u.role == RoleName.ADMIN),
            "manager":     sum(1 for u in all_users if u.role == RoleName.MANAGER),
            "staff":       sum(1 for u in all_users if u.role == RoleName.STAFF),
            "maintenance": sum(1 for u in all_users if u.role == RoleName.MAINTENANCE),
            "tenant":      sum(1 for u in all_users if u.role == RoleName.TENANT),
        }
    }