"""
controllers/maintenance_request_controller.py

Endpoints for:
- Tenants submitting / viewing maintenance requests
- Managers / Admins accepting, starting, completing, rejecting, closing requests
"""

from fastapi import APIRouter, Depends, HTTPException, status, Query
from beanie import PydanticObjectId
from typing import Optional

from models.user import User, RoleName
from models.maintenance import MaintenanceCategory, MaintenancePriority, MaintenanceStatus
from config.jwt_middleware import get_current_user, require_roles
from services.maintenance_service import maintenance_service          # ← use service layer

router = APIRouter(prefix="/api/maintenance", tags=["Maintenance Requests"])


# ── Request / Response schemas ─────────────────────────────────────────────

from pydantic import BaseModel, Field


class SubmitMaintenanceRequestBody(BaseModel):
    room_id:     Optional[str] = None
    title:       str = Field(..., min_length=3, max_length=200)
    description: str = Field(..., min_length=3, max_length=2000)
    category:    MaintenanceCategory = MaintenanceCategory.OTHER
    priority:    MaintenancePriority = MaintenancePriority.MEDIUM
    photos:      list[str] = []


class AcceptMaintenanceBody(BaseModel):
    """Manager accepts (assigns) the request — optionally to someone else."""
    assigned_to: Optional[str] = None   # defaults to current manager if omitted


class CompleteMaintenanceBody(BaseModel):
    resolution: str = Field(..., min_length=3, max_length=2000)


class RejectMaintenanceBody(BaseModel):
    rejection_reason: str = Field(..., min_length=3, max_length=1000)


# ============================================================================
# TENANT ENDPOINTS
# ============================================================================

@router.post(
    "/submit",
    status_code=status.HTTP_201_CREATED,
    summary="Submit a maintenance request",
)
async def submit_maintenance(
    body: SubmitMaintenanceRequestBody,
    current_user: User = Depends(get_current_user),
):
    """Any authenticated user may submit a maintenance request."""
    req = await maintenance_service.submit_request(
        tenant_id   = str(current_user.id),
        room_id     = body.room_id,          # service handles None
        title       = body.title,
        description = body.description,
        category    = body.category,
        priority    = body.priority,
        photos      = body.photos,
    )
    return {
        "message": "Maintenance request submitted successfully.",
        "id":      str(req.id),
    }


@router.get("/my", summary="Get current tenant's maintenance requests")
async def get_my_maintenance(
    current_user: User = Depends(get_current_user),
):
    reqs = await maintenance_service.get_tenant_requests(str(current_user.id))
    return {
        "requests": [
            {
                "id":          str(r.id),
                "room_id":     str(r.room_id) if r.room_id else None,
                "title":       r.title,
                "description": r.description,
                "category":    r.category.value,
                "priority":    r.priority.value,
                "status":      r.status.value,
                "photos":      r.photos,
                "resolution":  r.resolution,
                "created_at":  r.created_at.isoformat(),
                "updated_at":  r.updated_at.isoformat(),
            }
            for r in reqs
        ]
    }


@router.patch(
    "/close/{request_id}",
    summary="Tenant confirms issue is resolved — closes the ticket",
)
async def tenant_close_request(
    request_id: str,
    current_user: User = Depends(get_current_user),
):
    """Tenant closes the ticket after confirming the fix."""
    req = await maintenance_service.get_request_by_id(request_id)

    # Ensure the requesting user owns this ticket
    if str(req.tenant_id) != str(current_user.id):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Not your maintenance request.")

    closed = await maintenance_service.close_request(request_id)
    return {
        "message":    "Maintenance request closed. Thank you for confirming!",
        "request_id": str(closed.id),
        "status":     closed.status.value,
    }


# ============================================================================
# MANAGER / ADMIN ENDPOINTS
# ============================================================================

@router.get(
    "/manager/all",
    summary="List all maintenance requests (manager / admin)",
)
async def list_all_maintenance(
    filter_status: Optional[MaintenanceStatus] = Query(default=None, alias="status"),
    skip:          int = Query(default=0, ge=0),
    limit:         int = Query(default=20, ge=1, le=100),
    _: User = Depends(require_roles(RoleName.ADMIN, RoleName.MANAGER)),
):
    """Manager / Admin view with optional status filter."""
    if filter_status:
        reqs = await maintenance_service.get_requests_by_status(filter_status)
    else:
        reqs = await maintenance_service.get_all_requests()

    # Manual pagination (repository layer can be extended later)
    total    = len(reqs)
    paginated = reqs[skip : skip + limit]

    return {
        "total": total,
        "skip":  skip,
        "limit": limit,
        "requests": [
            {
                "id":               str(r.id),
                "tenant_id":        str(r.tenant_id),
                "room_id":          str(r.room_id) if r.room_id else None,
                "title":            r.title,
                "description":      r.description,
                "category":         r.category.value,
                "priority":         r.priority.value,
                "status":           r.status.value,
                "photos":           r.photos,
                "assigned_to":      str(r.assigned_to)      if r.assigned_to      else None,
                "resolution":       r.resolution,
                "rejection_reason": r.rejection_reason      if hasattr(r, "rejection_reason") else None,
                "created_at":       r.created_at.isoformat(),
                "updated_at":       r.updated_at.isoformat(),
            }
            for r in paginated
        ],
    }


@router.patch(
    "/manager/{request_id}/accept",
    summary="Accept (assign) a maintenance request",
)
async def accept_maintenance(
    request_id:   str,
    body:         AcceptMaintenanceBody = AcceptMaintenanceBody(),
    current_user: User = Depends(require_roles(RoleName.ADMIN, RoleName.MANAGER)),
):
    """
    Move request from SUBMITTED → ASSIGNED.
    Assigns to `assigned_to` if provided, otherwise to the current manager.
    """
    assigned_to = body.assigned_to or str(current_user.id)
    req = await maintenance_service.assign_request(request_id, assigned_to)
    return {
        "message":     "Maintenance request accepted and assigned.",
        "request_id":  str(req.id),
        "status":      req.status.value,
        "assigned_to": str(req.assigned_to),
    }


@router.patch(
    "/manager/{request_id}/start",
    summary="Start working on a maintenance request",
)
async def start_maintenance(
    request_id: str,
    _: User = Depends(require_roles(RoleName.ADMIN, RoleName.MANAGER)),
):
    """Move request from ASSIGNED → IN_PROGRESS."""
    req = await maintenance_service.start_request(request_id)
    return {
        "message":    "Maintenance request is now in progress.",
        "request_id": str(req.id),
        "status":     req.status.value,
    }


@router.patch(
    "/manager/{request_id}/complete",
    summary="Mark a maintenance request as completed",
)
async def complete_maintenance(
    request_id: str,
    body:       CompleteMaintenanceBody,
    _: User = Depends(require_roles(RoleName.ADMIN, RoleName.MANAGER)),
):
    """Move request from IN_PROGRESS → COMPLETED. Requires a resolution note."""
    req = await maintenance_service.complete_request(request_id, body.resolution)
    return {
        "message":    "Maintenance request marked as completed.",
        "request_id": str(req.id),
        "status":     req.status.value,
        "resolution": req.resolution,
    }


@router.patch(
    "/manager/{request_id}/reject",
    summary="Reject a maintenance request",
)
async def reject_maintenance(
    request_id: str,
    body:       RejectMaintenanceBody,
    _: User = Depends(require_roles(RoleName.ADMIN, RoleName.MANAGER)),
):
    """
    Move request from SUBMITTED or ASSIGNED → REJECTED.
    Sends a notification to the tenant with the reason.
    """
    req = await maintenance_service.reject_request(request_id, body.rejection_reason)
    return {
        "message":          "Maintenance request rejected.",
        "request_id":       str(req.id),
        "status":           req.status.value,
        "rejection_reason": req.rejection_reason,
    }


@router.patch(
    "/manager/{request_id}/close",
    summary="Manager force-closes a completed maintenance request",
)
async def manager_close_request(
    request_id: str,
    _: User = Depends(require_roles(RoleName.ADMIN, RoleName.MANAGER)),
):
    """
    Move request from COMPLETED → CLOSED (manager-initiated).
    Normally the tenant closes; this is an override.
    """
    req = await maintenance_service.close_request(request_id)
    return {
        "message":    "Maintenance request closed.",
        "request_id": str(req.id),
        "status":     req.status.value,
    }


@router.delete(
    "/manager/{request_id}",
    summary="Delete a maintenance request (manager / admin)",
    status_code=status.HTTP_200_OK,
)
async def delete_maintenance(
    request_id: str,
    _: User = Depends(require_roles(RoleName.ADMIN, RoleName.MANAGER)),
):
    return await maintenance_service.delete_request(request_id)