"""
controllers/manager_role_request_controller.py

Endpoints for:
- Tenants applying to become a Manager
- Admins reviewing / approving / rejecting those applications
"""

from fastapi import APIRouter, Depends, HTTPException, status, Query, Body
from beanie import PydanticObjectId
from typing import Optional
from datetime import datetime

from models.user import User, RoleName
from models.manager_role_request import ManagerRoleRequest, ManagerRequestStatus
from config.jwt_middleware import get_current_user, require_roles

router = APIRouter(prefix="/api/manager-requests", tags=["Manager Role Requests"])


# ── Request / Response schemas ────────────────────────────────────────────

from pydantic import BaseModel


class ManagerRoleApplyRequest(BaseModel):
    property_name: str
    location:      str
    address:       str
    room_count:    int
    description:   Optional[str] = None
    documents:     list[str] = []


class ReviewManagerRequest(BaseModel):
    status:       ManagerRequestStatus
    review_notes: Optional[str] = None


# ── Helpers ───────────────────────────────────────────────────────────────

async def get_request_or_404(request_id: str) -> ManagerRoleRequest:
    req = await ManagerRoleRequest.get(PydanticObjectId(request_id))
    if not req:
        raise HTTPException(404, "Manager role request not found.")
    return req


# ============================================================================
# TENANT ENDPOINTS
# ============================================================================

@router.post(
    "/apply",
    status_code=status.HTTP_201_CREATED,
    summary="Apply to become a property manager",
)
async def apply_manager_role(
    body: ManagerRoleApplyRequest,
    current_user: User = Depends(require_roles(RoleName.TENANT)),
):
    """Any authenticated tenant may submit a manager-role application."""
    existing = await ManagerRoleRequest.find_one(
        {"user_id": str(current_user.id), "status": ManagerRequestStatus.PENDING.value}
    )
    if existing:
        raise HTTPException(
            400,
            "You already have a pending manager role application. Please wait for admin review.",
        )

    req = ManagerRoleRequest(
        user_id       = str(current_user.id),
        property_name = body.property_name,
        location      = body.location,
        address       = body.address,
        room_count    = body.room_count,
        description   = body.description,
        documents     = body.documents,
    )
    await req.insert()
    return {"message": "Application submitted successfully. Awaiting admin review.", "id": str(req.id)}


@router.get(
    "/my",
    summary="Get my manager role application(s)",
)
async def get_my_manager_requests(
    current_user: User = Depends(require_roles(RoleName.TENANT)),
):
    """Returns all manager-role requests made by the current tenant."""
    reqs = await ManagerRoleRequest.find({"user_id": str(current_user.id)}).sort(-ManagerRoleRequest.created_at).to_list()
    return {
        "requests": [
            {
                "id":              str(r.id),
                "property_name":   r.property_name,
                "location":        r.location,
                "address":         r.address,
                "room_count":      r.room_count,
                "status":          r.status.value,
                "review_notes":    r.review_notes,
                "created_at":      r.created_at.isoformat(),
                "updated_at":      r.updated_at.isoformat(),
            }
            for r in reqs
        ]
    }


# ============================================================================
# ADMIN ENDPOINTS
# ============================================================================

@router.get(
    "/admin/all",
    summary="List all manager role applications (admin)",
)
async def list_all_manager_requests(
    status: Optional[ManagerRequestStatus] = Query(default=None),
    skip:   int = Query(default=0, ge=0),
    limit:  int = Query(default=20, ge=1, le=100),
    _: User = Depends(require_roles(RoleName.ADMIN)),
):
    """Admin-only. Filter by PENDING, APPROVED, or REJECTED."""
    query = {}
    if status:
        query["status"] = status.value

    reqs = await ManagerRoleRequest.find(query).sort(-ManagerRoleRequest.created_at).skip(skip).limit(limit).to_list()
    total = await ManagerRoleRequest.find(query).count()

    return {
        "total": total,
        "skip":  skip,
        "limit": limit,
        "requests": [
            {
                "id":              str(r.id),
                "user_id":         r.user_id,
                "property_name":   r.property_name,
                "location":        r.location,
                "address":         r.address,
                "room_count":      r.room_count,
                "description":     r.description,
                "documents":       r.documents,
                "status":          r.status.value,
                "reviewed_by":     r.reviewed_by,
                "reviewed_at":     r.reviewed_at.isoformat() if r.reviewed_at else None,
                "review_notes":    r.review_notes,
                "created_at":      r.created_at.isoformat(),
            }
            for r in reqs
        ],
    }


@router.get(
    "/admin/{request_id}",
    summary="Get single manager role application (admin)",
)
async def get_manager_request_detail(
    request_id: str,
    _: User = Depends(require_roles(RoleName.ADMIN)),
):
    r = await get_request_or_404(request_id)
    return {
        "id":              str(r.id),
        "user_id":         r.user_id,
        "property_name":   r.property_name,
        "location":        r.location,
        "address":         r.address,
        "room_count":      r.room_count,
        "description":     r.description,
        "documents":       r.documents,
        "status":          r.status.value,
        "reviewed_by":     r.reviewed_by,
        "reviewed_at":     r.reviewed_at.isoformat() if r.reviewed_at else None,
        "review_notes":    r.review_notes,
        "created_at":      r.created_at.isoformat(),
    }


@router.patch(
    "/admin/{request_id}/review",
    summary="Approve or reject a manager role application",
)
async def review_manager_request(
    request_id: str,
    body: ReviewManagerRequest,
    current_admin: User = Depends(require_roles(RoleName.ADMIN)),
):
    """Admin reviews an application. If APPROVED, the applicant's role is upgraded to MANAGER."""
    req = await get_request_or_404(request_id)

    if req.status != ManagerRequestStatus.PENDING:
        raise HTTPException(400, "This request has already been reviewed.")

    req.status = body.status
    req.reviewed_by = str(current_admin.id)
    req.reviewed_at = datetime.utcnow()
    req.review_notes = body.review_notes
    req.updated_at = datetime.utcnow()
    await req.save()

    # If approved, upgrade the user role
    if body.status == ManagerRequestStatus.APPROVED:
        from models.user import User
        applicant = await User.get(PydanticObjectId(req.user_id))
        if applicant:
            applicant.role = RoleName.MANAGER
            applicant.updated_at = datetime.utcnow()
            await applicant.save()

    action_word = "approved" if body.status == ManagerRequestStatus.APPROVED else "rejected"
    return {
        "message": f"Application {action_word} successfully.",
        "request_id": str(req.id),
        "status": req.status.value,
    }


@router.delete(
    "/admin/{request_id}",
    summary="Delete a manager role application (admin)",
    status_code=status.HTTP_200_OK,
)
async def delete_manager_request(
    request_id: str,
    _: User = Depends(require_roles(RoleName.ADMIN)),
):
    req = await get_request_or_404(request_id)
    await req.delete()
    return {"message": "Application deleted successfully."}
