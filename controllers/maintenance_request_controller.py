"""
controllers/maintenance_request_controller.py

Endpoints for:
- Tenants submitting maintenance requests
- Managers / Admins viewing and updating maintenance request status
"""

from fastapi import APIRouter, Depends, HTTPException, status, Query
from beanie import PydanticObjectId
from typing import Optional
from datetime import datetime

from models.user import User, RoleName
from models.maintenance import MaintenanceRequest, MaintenanceCategory, MaintenancePriority, MaintenanceStatus
from config.jwt_middleware import get_current_user, require_roles

router = APIRouter(prefix="/api/maintenance", tags=["Maintenance Requests"])


# ── Request / Response schemas ────────────────────────────────────────────

from pydantic import BaseModel, Field


class SubmitMaintenanceRequestBody(BaseModel):
    room_id:     str
    title:       str = Field(..., min_length=3, max_length=200)
    description: str = Field(..., min_length=10, max_length=2000)
    category:    MaintenanceCategory = MaintenanceCategory.OTHER
    priority:    MaintenancePriority = MaintenancePriority.MEDIUM
    photos:      list[str] = []


class UpdateMaintenanceStatusBody(BaseModel):
    status: MaintenanceStatus
    resolution: Optional[str] = None


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
    """Any authenticated user may submit a maintenance request for a room."""
    req = MaintenanceRequest(
        tenant_id       = PydanticObjectId(current_user.id),
        room_id         = PydanticObjectId(body.room_id),
        title           = body.title,
        description     = body.description,
        category        = body.category,
        priority        = body.priority,
        photos          = body.photos,
        status          = MaintenanceStatus.SUBMITTED,
        assigned_to     = None,
    )
    await req.insert()
    return {
        "message": "Maintenance request submitted successfully.",
        "id": str(req.id),
    }


@router.get(
    "/my",
    summary="Get my maintenance requests",
)
async def get_my_maintenance(
    current_user: User = Depends(get_current_user),
):
    """Returns all maintenance requests submitted by the current user."""
    reqs = await MaintenanceRequest.find({"tenant_id": str(current_user.id)}).sort(-MaintenanceRequest.created_at).to_list()
    return {
        "requests": [
            {
                "id":              str(r.id),
                "room_id":         r.room_id,
                "title":           r.title,
                "description":     r.description,
                "category":        r.category.value,
                "priority":        r.priority.value,
                "status":          r.status.value,
                "photos":          r.photos,
                "created_at":      r.created_at.isoformat(),
                "updated_at":      r.updated_at.isoformat(),
            }
            for r in reqs
        ]
    }


# ============================================================================
# MANAGER / ADMIN ENDPOINTS
# ============================================================================

@router.get(
    "/manager/all",
    summary="List all maintenance requests (manager / admin)",
)
async def list_all_maintenance(
    status: Optional[MaintenanceStatus] = Query(default=None),
    skip:   int = Query(default=0, ge=0),
    limit:  int = Query(default=20, ge=1, le=100),
    _: User = Depends(require_roles(RoleName.ADMIN, RoleName.MANAGER)),
):
    """Manager / Admin view. Filter by PENDING, IN_PROGRESS, COMPLETED."""
    query = {}
    if status:
        query["status"] = status.value

    reqs = await MaintenanceRequest.find(query).sort(-MaintenanceRequest.created_at).skip(skip).limit(limit).to_list()
    total = await MaintenanceRequest.find(query).count()

    return {
        "total": total,
        "skip":  skip,
        "limit": limit,
        "requests": [
            {
                "id":              str(r.id),
                "tenant_id":       r.tenant_id,
                "room_id":         r.room_id,
                "title":           r.title,
                "description":     r.description,
                "category":        r.category.value,
                "priority":        r.priority.value,
                "status":          r.status.value,
                "photos":          r.photos,
                "assigned_to":     str(r.assigned_to) if r.assigned_to else None,
                "resolution":      r.resolution,
                "created_at":      r.created_at.isoformat(),
                "updated_at":      r.updated_at.isoformat(),
            }
            for r in reqs
        ],
    }


@router.patch(
    "/manager/{request_id}/status",
    summary="Update maintenance request status",
)
async def update_maintenance_status(
    request_id: str,
    body: UpdateMaintenanceStatusBody,
    current_user: User = Depends(require_roles(RoleName.ADMIN, RoleName.MANAGER)),
):
    """Manager/Admin updates the status of a maintenance request."""
    req = await MaintenanceRequest.get(PydanticObjectId(request_id))
    if not req:
        raise HTTPException(404, "Maintenance request not found.")

    req.status = body.status
    if body.resolution:
        req.resolution = body.resolution
    if body.status == MaintenanceStatus.COMPLETED:
        req.completed_at = datetime.utcnow()
    req.updated_at = datetime.utcnow()
    req.assigned_to = PydanticObjectId(current_user.id)
    await req.save()

    return {
        "message": "Maintenance request updated successfully.",
        "request_id": str(req.id),
        "status": req.status.value,
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
    req = await MaintenanceRequest.get(PydanticObjectId(request_id))
    if not req:
        raise HTTPException(404, "Maintenance request not found.")
    await req.delete()
    return {"message": "Maintenance request deleted successfully."}
