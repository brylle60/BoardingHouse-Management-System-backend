"""
controllers/manager_controller.py

All HTTP endpoints for manager-facing operations.
Requires ROLE_MANAGER or ROLE_ADMIN.

NOTE: This controller uses your groupmates' existing function-based
services — no singleton instances needed.

Routes:
  /api/manager/rooms/**
  /api/manager/leases/**
  /api/manager/payments/**
  /api/manager/maintenance/**
  /api/manager/dashboard
"""

from fastapi import APIRouter, Depends, HTTPException, status, Query
from beanie import PydanticObjectId
from typing import Optional

from models.user import User, RoleName
from models.room import RoomStatus
from models.lease import LeaseStatus
from models.maintenance import MaintenanceStatus
from config.jwt_middleware import get_current_user

# ── Import your groupmates' existing services (function-based) ────────────────
from services import room_service
from services import lease_service
from services import payment_service
from services import maintenance_service

# ── Import your groupmates' existing DTOs ────────────────────────────────────
from dto.request.room_request       import RoomCreateRequest, RoomUpdateRequest
from dto.request.lease_request      import LeaseCreateRequest, LeaseUpdateRequest, LeaseRenewRequest, LeaseTerminateRequest
from dto.request.manager_requests   import (
    RecordPaymentRequest,
    SubmitMaintenanceRequest,
    AssignMaintenanceRequest,
    CompleteMaintenanceRequest,
    RejectMaintenanceRequest,
    UpdateRoomStatusRequest,
)
from dto.response.manager_responses import (
    PaymentResponse, MaintenanceResponse,
    ManagerDashboardResponse,
    to_payment_response, to_maintenance_response,
)

router = APIRouter(prefix="/api/manager", tags=["manager"])


# ── Auth dependency ───────────────────────────────────────────────────────────

async def require_manager(current_user: User = Depends(get_current_user)):
    """Requires ROLE_MANAGER or ROLE_ADMIN."""
    if current_user.role not in [RoleName.MANAGER, RoleName.ADMIN]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Manager or Admin access required.",
        )
    return current_user


# ============================================================================
# DASHBOARD
# ============================================================================

@router.get("/dashboard", summary="Manager dashboard stats")
async def get_manager_dashboard(_: User = Depends(require_manager)):
    """Combined stats — occupancy + leases + maintenance."""
    room_stats        = await room_service.get_room_stats()
    lease_stats       = await lease_service.get_lease_stats()
    maintenance_stats = await maintenance_service.get_maintenance_stats()

    return {
        "rooms":       room_stats,
        "leases":      lease_stats,
        "maintenance": maintenance_stats,
    }


# ============================================================================
# ROOM ENDPOINTS — uses your groupmate's room_service functions
# ============================================================================

@router.get("/rooms", summary="List all rooms")
async def list_rooms(
    status: Optional[RoomStatus] = Query(default=None),
    skip:   int = Query(default=0, ge=0),
    limit:  int = Query(default=20, ge=1, le=100),
    _: User = Depends(require_manager),
):
    if status:
        return await room_service.get_rooms_by_status(status, skip=skip, limit=limit)
    return await room_service.get_all_rooms(skip=skip, limit=limit)


@router.get("/rooms/vacant", summary="List vacant rooms")
async def list_vacant_rooms(
    skip:  int = Query(default=0, ge=0),
    limit: int = Query(default=20, ge=1, le=100),
    _: User = Depends(require_manager),
):
    return await room_service.get_vacant_rooms(skip=skip, limit=limit)


@router.get("/rooms/stats", summary="Room occupancy stats")
async def get_room_stats(_: User = Depends(require_manager)):
    return await room_service.get_room_stats()


@router.get("/rooms/maintenance", summary="Rooms under maintenance")
async def list_maintenance_rooms(
    skip:  int = Query(default=0, ge=0),
    limit: int = Query(default=20, ge=1, le=100),
    _: User = Depends(require_manager),
):
    return await room_service.get_rooms_under_maintenance(skip=skip, limit=limit)


@router.get("/rooms/search", summary="Search rooms")
async def search_rooms(
    q:     str = Query(..., min_length=1),
    skip:  int = Query(default=0, ge=0),
    limit: int = Query(default=20, ge=1, le=100),
    _: User = Depends(require_manager),
):
    return await room_service.search_rooms(query=q, skip=skip, limit=limit)


@router.get("/rooms/{room_id}", summary="Get room by ID")
async def get_room(room_id: str, _: User = Depends(require_manager)):
    return await room_service.get_room_by_id(PydanticObjectId(room_id))


@router.post("/rooms", status_code=201, summary="Create a new room")
async def create_room(
    body: RoomCreateRequest,
    current_user: User = Depends(require_manager),
):
    return await room_service.create_room(
        request    = body,
        created_by = str(current_user.id),
    )


@router.patch("/rooms/{room_id}", summary="Update room details")
async def update_room(
    room_id: str,
    body: RoomUpdateRequest,
    current_user: User = Depends(require_manager),
):
    return await room_service.update_room(
        room_id    = PydanticObjectId(room_id),
        request    = body,
        updated_by = str(current_user.id),
    )


@router.patch("/rooms/{room_id}/status", summary="Update room status")
async def update_room_status(
    room_id: str,
    body: UpdateRoomStatusRequest,
    current_user: User = Depends(require_manager),
):
    return await room_service.update_room_status(
        room_id    = PydanticObjectId(room_id),
        status     = body.status,
        updated_by = str(current_user.id),
    )


@router.patch("/rooms/{room_id}/maintenance/start", summary="Set room under maintenance")
async def start_room_maintenance(
    room_id: str,
    notes: str = Query(..., min_length=1),
    current_user: User = Depends(require_manager),
):
    return await room_service.set_room_under_maintenance(
        room_id            = PydanticObjectId(room_id),
        maintenance_notes  = notes,
        updated_by         = str(current_user.id),
    )


@router.patch("/rooms/{room_id}/maintenance/complete", summary="Complete room maintenance")
async def complete_room_maintenance(
    room_id: str,
    current_user: User = Depends(require_manager),
):
    return await room_service.complete_room_maintenance(
        room_id    = PydanticObjectId(room_id),
        updated_by = str(current_user.id),
    )


@router.delete("/rooms/{room_id}", summary="Delete a room")
async def delete_room(room_id: str, _: User = Depends(require_manager)):
    return await room_service.delete_room(PydanticObjectId(room_id))


# ============================================================================
# LEASE ENDPOINTS — uses your groupmate's lease_service functions
# ============================================================================

@router.get("/leases", summary="List all leases")
async def list_leases(
    status: Optional[LeaseStatus] = Query(default=None),
    skip:   int = Query(default=0, ge=0),
    limit:  int = Query(default=20, ge=1, le=100),
    _: User = Depends(require_manager),
):
    if status:
        return await lease_service.get_leases_by_status(status, skip=skip, limit=limit)
    return await lease_service.get_all_leases(skip=skip, limit=limit)


@router.get("/leases/stats", summary="Lease statistics")
async def get_lease_stats(_: User = Depends(require_manager)):
    return await lease_service.get_lease_stats()


@router.get("/leases/expiring", summary="Leases expiring soon")
async def get_expiring_leases(
    days:  int = Query(default=30, ge=1),
    skip:  int = Query(default=0, ge=0),
    limit: int = Query(default=20, ge=1, le=100),
    _: User = Depends(require_manager),
):
    return await lease_service.get_expiring_leases(days_ahead=days, skip=skip, limit=limit)


@router.get("/leases/tenant/{tenant_id}", summary="Get leases by tenant")
async def get_tenant_leases(
    tenant_id: str,
    skip:  int = Query(default=0, ge=0),
    limit: int = Query(default=20, ge=1, le=100),
    _: User = Depends(require_manager),
):
    return await lease_service.get_leases_by_tenant(tenant_id, skip=skip, limit=limit)


@router.get("/leases/tenant/{tenant_id}/active", summary="Get active lease for tenant")
async def get_active_tenant_lease(tenant_id: str, _: User = Depends(require_manager)):
    return await lease_service.get_active_lease_by_tenant(tenant_id)


@router.get("/leases/room/{room_id}", summary="Get leases by room")
async def get_room_leases(
    room_id: str,
    skip:  int = Query(default=0, ge=0),
    limit: int = Query(default=20, ge=1, le=100),
    _: User = Depends(require_manager),
):
    return await lease_service.get_leases_by_room(room_id, skip=skip, limit=limit)


@router.get("/leases/{lease_id}", summary="Get lease by ID")
async def get_lease(lease_id: str, _: User = Depends(require_manager)):
    return await lease_service.get_lease_by_id(PydanticObjectId(lease_id))


@router.post("/leases", status_code=201, summary="Create a new lease")
async def create_lease(
    body: LeaseCreateRequest,
    current_user: User = Depends(require_manager),
):
    return await lease_service.create_lease(
        request    = body,
        created_by = str(current_user.id),
    )


@router.patch("/leases/{lease_id}", summary="Update lease details")
async def update_lease(
    lease_id: str,
    body: LeaseUpdateRequest,
    current_user: User = Depends(require_manager),
):
    return await lease_service.update_lease(
        lease_id   = PydanticObjectId(lease_id),
        request    = body,
        updated_by = str(current_user.id),
    )


@router.patch("/leases/{lease_id}/activate", summary="Activate a pending lease")
async def activate_lease(
    lease_id: str,
    current_user: User = Depends(require_manager),
):
    return await lease_service.activate_lease(
        lease_id   = PydanticObjectId(lease_id),
        updated_by = str(current_user.id),
    )


@router.patch("/leases/{lease_id}/renew", summary="Renew a lease")
async def renew_lease(
    lease_id: str,
    body: LeaseRenewRequest,
    current_user: User = Depends(require_manager),
):
    return await lease_service.renew_lease(
        lease_id   = PydanticObjectId(lease_id),
        request    = body,
        updated_by = str(current_user.id),
    )


@router.patch("/leases/{lease_id}/terminate", summary="Terminate a lease")
async def terminate_lease(
    lease_id: str,
    body: LeaseTerminateRequest,
    current_user: User = Depends(require_manager),
):
    return await lease_service.terminate_lease(
        lease_id   = PydanticObjectId(lease_id),
        request    = body,
        updated_by = str(current_user.id),
    )


@router.patch("/leases/{lease_id}/deposit/return", summary="Return security deposit")
async def return_deposit(
    lease_id:   str,
    deductions: float = Query(default=0.0, ge=0),
    current_user: User = Depends(require_manager),
):
    return await lease_service.return_deposit(
        lease_id   = PydanticObjectId(lease_id),
        deductions = deductions,
        updated_by = str(current_user.id),
    )


@router.delete("/leases/{lease_id}", summary="Delete a lease")
async def delete_lease(lease_id: str, _: User = Depends(require_manager)):
    return await lease_service.delete_lease(PydanticObjectId(lease_id))


# ============================================================================
# PAYMENT ENDPOINTS — uses payment_service
# ============================================================================

@router.get("/payments", response_model=list[PaymentResponse], summary="List all payments")
async def list_payments(_: User = Depends(require_manager)):
    payments = await payment_service.get_all_payments()
    return [to_payment_response(p) for p in payments]


@router.get("/payments/stats", summary="Payment statistics")
async def get_payment_stats(_: User = Depends(require_manager)):
    return await payment_service.get_payment_stats()


@router.get("/payments/tenant/{tenant_id}", response_model=list[PaymentResponse])
async def get_tenant_payments(tenant_id: str, _: User = Depends(require_manager)):
    payments = await payment_service.get_tenant_payments(tenant_id)
    return [to_payment_response(p) for p in payments]


@router.get("/payments/{payment_id}", response_model=PaymentResponse)
async def get_payment(payment_id: str, _: User = Depends(require_manager)):
    payment = await payment_service.get_payment_by_id(payment_id)
    return to_payment_response(payment)


@router.post("/payments", response_model=PaymentResponse, status_code=201)
async def record_payment(
    body: RecordPaymentRequest,
    current_user: User = Depends(require_manager),
):
    payment = await payment_service.record_payment(
        tenant_id    = body.tenant_id,
        lease_id     = body.lease_id,
        room_id      = body.room_id,
        amount       = body.amount,
        method       = body.method,
        type         = body.type,
        reference_no = body.reference_no,
        notes        = body.notes,
        period_start = body.period_start,
        period_end   = body.period_end,
        recorded_by  = str(current_user.id),
    )
    return to_payment_response(payment)


@router.patch("/payments/{payment_id}/confirm", response_model=PaymentResponse)
async def confirm_payment(payment_id: str, _: User = Depends(require_manager)):
    payment = await payment_service.confirm_payment(payment_id)
    return to_payment_response(payment)


@router.delete("/payments/{payment_id}")
async def delete_payment(payment_id: str, _: User = Depends(require_manager)):
    return await payment_service.delete_payment(payment_id)


# ============================================================================
# MAINTENANCE ENDPOINTS — uses maintenance_service
# ============================================================================

@router.get("/maintenance", response_model=list[MaintenanceResponse])
async def list_maintenance(
    status: Optional[MaintenanceStatus] = Query(default=None),
    _: User = Depends(require_manager),
):
    if status:
        reqs = await maintenance_service.get_requests_by_status(status)
    else:
        reqs = await maintenance_service.get_all_requests()
    return [to_maintenance_response(r) for r in reqs]


@router.get("/maintenance/pending", response_model=list[MaintenanceResponse])
async def get_pending_maintenance(_: User = Depends(require_manager)):
    reqs = await maintenance_service.get_pending_requests()
    return [to_maintenance_response(r) for r in reqs]


@router.get("/maintenance/stats")
async def get_maintenance_stats(_: User = Depends(require_manager)):
    return await maintenance_service.get_maintenance_stats()


@router.get("/maintenance/tenant/{tenant_id}", response_model=list[MaintenanceResponse])
async def get_tenant_maintenance(tenant_id: str, _: User = Depends(require_manager)):
    reqs = await maintenance_service.get_tenant_requests(tenant_id)
    return [to_maintenance_response(r) for r in reqs]


@router.get("/maintenance/{request_id}", response_model=MaintenanceResponse)
async def get_maintenance_request(request_id: str, _: User = Depends(require_manager)):
    req = await maintenance_service.get_request_by_id(request_id)
    return to_maintenance_response(req)


@router.post("/maintenance", response_model=MaintenanceResponse, status_code=201)
async def submit_maintenance(
    body: SubmitMaintenanceRequest,
    _: User = Depends(require_manager),
):
    req = await maintenance_service.submit_request(
        tenant_id   = body.tenant_id,
        room_id     = body.room_id,
        title       = body.title,
        description = body.description,
        category    = body.category,
        priority    = body.priority,
        photos      = body.photos,
    )
    return to_maintenance_response(req)


@router.patch("/maintenance/{request_id}/assign", response_model=MaintenanceResponse)
async def assign_maintenance(
    request_id: str,
    body: AssignMaintenanceRequest,
    _: User = Depends(require_manager),
):
    req = await maintenance_service.assign_request(request_id, body.assigned_to)
    return to_maintenance_response(req)


@router.patch("/maintenance/{request_id}/start", response_model=MaintenanceResponse)
async def start_maintenance(request_id: str, _: User = Depends(require_manager)):
    req = await maintenance_service.start_request(request_id)
    return to_maintenance_response(req)


@router.patch("/maintenance/{request_id}/complete", response_model=MaintenanceResponse)
async def complete_maintenance(
    request_id: str,
    body: CompleteMaintenanceRequest,
    _: User = Depends(require_manager),
):
    req = await maintenance_service.complete_request(request_id, body.resolution)
    return to_maintenance_response(req)


@router.patch("/maintenance/{request_id}/close", response_model=MaintenanceResponse)
async def close_maintenance(request_id: str, _: User = Depends(require_manager)):
    req = await maintenance_service.close_request(request_id)
    return to_maintenance_response(req)


@router.patch("/maintenance/{request_id}/reject", response_model=MaintenanceResponse)
async def reject_maintenance(
    request_id: str,
    body: RejectMaintenanceRequest,
    _: User = Depends(require_manager),
):
    req = await maintenance_service.reject_request(request_id, body.rejection_reason)
    return to_maintenance_response(req)


@router.delete("/maintenance/{request_id}")
async def delete_maintenance(request_id: str, _: User = Depends(require_manager)):
    return await maintenance_service.delete_request(request_id)