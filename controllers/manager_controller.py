
from fastapi import APIRouter, Depends, HTTPException, status, Query
from beanie import PydanticObjectId
from typing import Optional
from datetime import datetime, timedelta

from models.user import User, RoleName
from models.room import Room, RoomStatus
from models.lease import Lease, LeaseStatus
from models.payment import Payment, PaymentStatus
from models.maintenance import MaintenanceStatus
from config.jwt_middleware import get_current_user

# ── Import services ────────────────────────────────────────────────────────────
from services import room_service
from services import lease_service
from services.payment_service import payment_service
from services.maintenance_service import maintenance_service
from services.communication_service import communication_service
from models.message import MessageDirection

# ── Import repositories for direct manager-scoped queries ──────────────────────
from repository import room_repository

# ── Import DTOs ────────────────────────────────────────────────────────────────
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
# HELPERS — manager-scoped queries
# ============================================================================

async def _auto_claim_unassigned_rooms(manager_id: str) -> int:
    """
    Auto-claim rooms that have no manager_id assigned yet.
    This handles the migration case where existing rooms were created
    before the manager_id field was added.
    Returns count of rooms claimed.
    """
    unassigned = await Room.find(
        {"$or": [{"manager_id": None}, {"manager_id": {"$exists": False}}]}
    ).to_list()
    if not unassigned:
        return 0
    for room in unassigned:
        room.manager_id = manager_id
        await room.save()
    return len(unassigned)


async def _get_manager_room_ids(manager_id: str) -> list[str]:
    """Returns room IDs owned by this manager (auto-claims unassigned rooms first)."""
    ids = await room_repository.get_room_ids_by_manager(manager_id)
    if not ids:
        claimed = await _auto_claim_unassigned_rooms(manager_id)
        if claimed > 0:
            ids = await room_repository.get_room_ids_by_manager(manager_id)
    return ids


async def _get_manager_rooms(manager_id: str) -> list[Room]:
    """Returns Room documents owned by this manager (auto-claims unassigned rooms first)."""
    rooms = await room_repository.get_rooms_by_manager(manager_id)
    if not rooms:
        claimed = await _auto_claim_unassigned_rooms(manager_id)
        if claimed > 0:
            rooms = await room_repository.get_rooms_by_manager(manager_id)
    return rooms


async def _get_scoped_leases(room_ids: list[str]) -> list[Lease]:
    """Returns all leases for the given room IDs (room_id stored as str)."""
    if not room_ids:
        return []
    return await Lease.find({"room_id": {"$in": room_ids}}).to_list()


async def _get_scoped_payments(room_ids: list[str]) -> list[Payment]:
    """Returns all payments for the given room IDs."""
    if not room_ids:
        return []
    oids = [PydanticObjectId(rid) for rid in room_ids]
    return await Payment.find({"room_id": {"$in": oids}}).sort("-payment_date").to_list()


# ============================================================================
# DASHBOARD
# ============================================================================

@router.get("/dashboard", summary="Manager dashboard stats")
async def get_manager_dashboard(current_user: User = Depends(require_manager)):
    """Combined stats scoped to manager's rooms."""
    import logging
    logger = logging.getLogger(__name__)

    manager_id = str(current_user.id)
    rooms = await _get_manager_rooms(manager_id)
    room_ids = [str(r.id) for r in rooms]

    total    = len(rooms)
    vacant   = sum(1 for r in rooms if r.status == RoomStatus.VACANT)
    occupied = sum(1 for r in rooms if r.status == RoomStatus.OCCUPIED)
    reserved = sum(1 for r in rooms if r.status == RoomStatus.RESERVED)
    maint    = sum(1 for r in rooms if r.status == RoomStatus.MAINTENANCE)
    occ_rate = round((occupied / total * 100), 2) if total > 0 else 0.0

    room_stats = {
        "total": total, "vacant": vacant, "occupied": occupied,
        "reserved": reserved, "under_maintenance": maint,
        "occupancy_rate_pct": occ_rate,
    }

    # Scoped lease stats
    leases = await _get_scoped_leases(room_ids)
    from datetime import date, timedelta as td
    lease_stats = {
        "total":         len(leases),
        "active":        sum(1 for l in leases if l.status == LeaseStatus.ACTIVE),
        "pending":       sum(1 for l in leases if l.status == LeaseStatus.PENDING),
        "terminated":    sum(1 for l in leases if l.status == LeaseStatus.TERMINATED),
        "expired":       sum(1 for l in leases if l.status == LeaseStatus.EXPIRED),
        "expiring_soon": sum(1 for l in leases if l.status == LeaseStatus.ACTIVE and l.end_date and l.end_date <= date.today() + td(days=30)),
    }

    try:
        maintenance_stats = await maintenance_service.get_maintenance_stats()
    except Exception as exc:
        logger.error("maintenance_service.get_maintenance_stats() failed: %s", exc, exc_info=True)
        maintenance_stats = {"submitted": 0, "in_progress": 0}

    return {
        "rooms":       room_stats,
        "leases":      lease_stats,
        "maintenance": maintenance_stats,
    }


# ============================================================================
# ROOM ENDPOINTS — uses your groupmate's room_service functions
# ============================================================================

@router.get("/rooms", summary="List manager's rooms")
async def list_rooms(
    skip:  int = Query(default=0, ge=0),
    limit: int = Query(default=50, ge=1, le=200),
    current_user: User = Depends(require_manager),
):
    from dto.response.room_response import RoomResponse
    rooms = await _get_manager_rooms(str(current_user.id))
    return [RoomResponse.from_room(r) for r in rooms]


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
        manager_id = str(current_user.id),
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


@router.post("/rooms/claim", summary="Claim all unassigned rooms")
async def claim_unassigned_rooms(current_user: User = Depends(require_manager)):
    """Assign all rooms with no manager_id to the current manager."""
    count = await _auto_claim_unassigned_rooms(str(current_user.id))
    return {"claimed": count, "message": f"Claimed {count} room(s)."}


# ============================================================================
# LEASE ENDPOINTS — uses your groupmate's lease_service functions
# ============================================================================

@router.get("/leases", summary="List manager's leases")
async def list_leases(
    current_user: User = Depends(require_manager),
):
    from dto.response.lease_response import LeaseResponse
    room_ids = await _get_manager_room_ids(str(current_user.id))
    leases = await _get_scoped_leases(room_ids)
    return [LeaseResponse.from_lease(l) for l in leases]


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
# PAYMENT ENDPOINTS — uses payment_service singleton
# ============================================================================

@router.get("/payments", response_model=list[PaymentResponse], summary="List manager's payments")
async def list_payments(current_user: User = Depends(require_manager)):
    room_ids = await _get_manager_room_ids(str(current_user.id))
    payments = await _get_scoped_payments(room_ids)
    return [to_payment_response(p) for p in payments]


@router.get("/payments/stats", summary="Payment statistics (scoped)")
async def get_payment_stats(current_user: User = Depends(require_manager)):
    room_ids = await _get_manager_room_ids(str(current_user.id))
    payments = await _get_scoped_payments(room_ids)

    confirmed = [p for p in payments if p.status == PaymentStatus.CONFIRMED]
    pending   = [p for p in payments if p.status == PaymentStatus.PENDING]
    partial   = [p for p in payments if p.status == PaymentStatus.PARTIAL]

    total_collected  = sum(p.amount for p in confirmed)
    total_outstanding = sum(p.amount for p in pending) + sum(p.amount for p in partial)

    # Monthly revenue: confirmed payments in the current month
    now = datetime.utcnow()
    month_start = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    monthly_collected = sum(
        p.amount for p in confirmed
        if p.payment_date and p.payment_date >= month_start
    )

    return {
        "total_payments":    len(payments),
        "paid_count":        len(confirmed),
        "unpaid_count":      len(pending),
        "partial_count":     len(partial),
        "total_collected":   total_collected,
        "total_outstanding": total_outstanding,
        "monthly_revenue":   monthly_collected,
        "monthly_collected": monthly_collected,
    }


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


# ============================================================================
# ANALYTICS — scoped to manager's rooms
# ============================================================================

@router.get("/analytics", summary="Manager analytics")
async def get_manager_analytics(current_user: User = Depends(require_manager)):
    """
    Returns rich analytics for the manager:
    - Revenue per month (last 6 months)
    - Occupancy trend
    - Payment collection rate
    - Top-earning rooms
    - Outstanding balances per tenant
    """
    from datetime import date
    from models.tenant import Tenant

    manager_id = str(current_user.id)
    rooms = await _get_manager_rooms(manager_id)
    room_ids = [str(r.id) for r in rooms]
    room_map = {str(r.id): r.room_number for r in rooms}

    payments = await _get_scoped_payments(room_ids)
    leases = await _get_scoped_leases(room_ids)

    # ── Revenue per month (last 6 months) ──────────────────────
    now = datetime.utcnow()
    monthly_revenue = []
    for i in range(5, -1, -1):
        m = now.month - i
        y = now.year
        while m <= 0:
            m += 12
            y -= 1
        month_start = datetime(y, m, 1)
        if m == 12:
            month_end = datetime(y + 1, 1, 1)
        else:
            month_end = datetime(y, m + 1, 1)

        month_total = sum(
            p.amount for p in payments
            if p.status == PaymentStatus.CONFIRMED
            and p.payment_date
            and month_start <= p.payment_date < month_end
        )
        monthly_revenue.append({
            "month": month_start.strftime("%b %Y"),
            "revenue": round(month_total, 2),
        })

    # ── Collection rate ────────────────────────────────────────
    total_all = len(payments)
    total_confirmed = sum(1 for p in payments if p.status == PaymentStatus.CONFIRMED)
    collection_rate = round((total_confirmed / total_all * 100), 1) if total_all > 0 else 0.0

    # ── Top-earning rooms ──────────────────────────────────────
    room_earnings: dict[str, float] = {}
    for p in payments:
        if p.status == PaymentStatus.CONFIRMED:
            rid = str(p.room_id)
            room_earnings[rid] = room_earnings.get(rid, 0) + p.amount
    top_rooms = sorted(room_earnings.items(), key=lambda x: x[1], reverse=True)[:5]
    top_rooms_data = [
        {"room_id": rid, "room_number": room_map.get(rid, rid[:8]), "total_earned": round(amt, 2)}
        for rid, amt in top_rooms
    ]

    # ── Outstanding per tenant ─────────────────────────────────
    active_leases = [l for l in leases if l.status == LeaseStatus.ACTIVE]
    outstanding_list = []
    for lease in active_leases:
        tenant = await Tenant.get(PydanticObjectId(lease.tenant_id)) if lease.tenant_id else None
        outstanding_list.append({
            "tenant_id": str(lease.tenant_id),
            "tenant_name": tenant.full_name if tenant else str(lease.tenant_id)[:8],
            "room_number": room_map.get(str(lease.room_id), str(lease.room_id)[:8]),
            "outstanding_balance": lease.outstanding_balance,
            "monthly_rate": lease.monthly_rate,
        })

    # ── Occupancy trend (simple: current snapshot) ─────────────
    total_rooms = len(rooms)
    occupied = sum(1 for r in rooms if r.status == RoomStatus.OCCUPIED)
    vacant = sum(1 for r in rooms if r.status == RoomStatus.VACANT)

    # ── Revenue target per month (sum of monthly_rate for active leases)
    monthly_target = round(sum(l.monthly_rate for l in active_leases), 2)
    for entry in monthly_revenue:
        entry["target"] = monthly_target

    # ── Occupancy breakdown by room type ──────────────────────
    from collections import Counter
    type_total = Counter(r.room_type.value for r in rooms)
    type_occupied = Counter(
        r.room_type.value for r in rooms if r.status == RoomStatus.OCCUPIED
    )
    occupancy_by_type = []
    for rt in type_total:
        total_t = type_total[rt]
        occ_t = type_occupied.get(rt, 0)
        occupancy_by_type.append({
            "type": rt.capitalize(),
            "occupied": occ_t,
            "total": total_t,
            "pct": round((occ_t / total_t * 100)) if total_t > 0 else 0,
        })

    return {
        "monthly_revenue":   monthly_revenue,
        "collection_rate":   collection_rate,
        "top_rooms":         top_rooms_data,
        "outstanding_tenants": outstanding_list,
        "occupancy": {
            "total":    total_rooms,
            "occupied": occupied,
            "vacant":   vacant,
            "rate_pct": round((occupied / total_rooms * 100), 1) if total_rooms > 0 else 0,
        },
        "occupancy_by_type": occupancy_by_type,
        "summary": {
            "total_rooms":      total_rooms,
            "active_leases":    len(active_leases),
            "total_payments":   len(payments),
            "total_collected":  round(sum(p.amount for p in payments if p.status == PaymentStatus.CONFIRMED), 2),
            "total_outstanding": round(sum(p.amount for p in payments if p.status in (PaymentStatus.PENDING, PaymentStatus.PARTIAL)), 2),
        }
    }


# ============================================================================
# MESSAGING — manager sends/receives messages to/from tenants
# ============================================================================

@router.get("/messages/tenants", summary="List tenants the manager can message")
async def list_messageable_tenants(current_user: User = Depends(require_manager)):
    """Returns tenants in manager's rooms (for message recipient selection)."""
    from models.tenant import Tenant
    room_ids = await _get_manager_room_ids(str(current_user.id))
    if not room_ids:
        return []
    tenants = await Tenant.find({"room_id": {"$in": room_ids}}).to_list()
    return [
        {
            "id": str(t.id),
            "user_id": str(t.user_id) if t.user_id else "",
            "full_name": t.full_name,
            "email": t.email,
            "phone": t.phone,
            "room_id": str(t.room_id) if t.room_id else None,
        }
        for t in tenants
    ]


@router.get("/messages", summary="Get all messages for manager's tenants")
async def get_manager_messages(current_user: User = Depends(require_manager)):
    """Returns all message threads for tenants in manager's rooms."""
    from models.message import Message
    from models.tenant import Tenant

    room_ids = await _get_manager_room_ids(str(current_user.id))
    if not room_ids:
        return []

    tenants = await Tenant.find({"room_id": {"$in": room_ids}}).to_list()
    tenant_ids = [t.id for t in tenants]
    tenant_map = {str(t.id): t.full_name for t in tenants}

    if not tenant_ids:
        return []

    messages = await Message.find(
        {"tenant_id": {"$in": tenant_ids}}
    ).sort("-created_at").to_list()

    return [
        {
            "id": str(m.id),
            "sender_id": str(m.sender_id),
            "receiver_id": str(m.receiver_id),
            "tenant_id": str(m.tenant_id),
            "tenant_name": tenant_map.get(str(m.tenant_id), "Unknown"),
            "subject": m.subject,
            "body": m.body,
            "direction": m.direction.value if m.direction else None,
            "status": m.status.value if m.status else None,
            "thread_id": m.thread_id,
            "created_at": m.created_at.isoformat() if m.created_at else None,
            "read_at": m.read_at.isoformat() if m.read_at else None,
        }
        for m in messages
    ]


@router.post("/messages/send", summary="Manager sends a message to a tenant")
async def send_manager_message(
    body: dict,
    current_user: User = Depends(require_manager),
):
    """Send a message from manager to tenant."""
    receiver_id = body.get("receiver_id", "")
    tenant_id   = body.get("tenant_id", "")
    msg_body    = body.get("body", "")

    if not receiver_id:
        raise HTTPException(status_code=400, detail="receiver_id is required.")
    if not tenant_id:
        raise HTTPException(status_code=400, detail="tenant_id is required.")
    if not msg_body.strip():
        raise HTTPException(status_code=400, detail="Message body cannot be empty.")

    result = await communication_service.send_message(
        sender_id=str(current_user.id),
        receiver_id=receiver_id,
        tenant_id=tenant_id,
        body=msg_body,
        subject=body.get("subject"),
        direction=MessageDirection.MANAGEMENT_TO_TENANT,
        thread_id=body.get("thread_id"),
    )
    return {
        "id": str(result.id),
        "thread_id": result.thread_id,
        "message": "Message sent successfully.",
    }


@router.get("/messages/thread/{thread_id}", summary="Get conversation thread")
async def get_thread(thread_id: str, _: User = Depends(require_manager)):
    """Returns a full conversation thread."""
    from models.tenant import Tenant
    msgs = await communication_service.get_thread(thread_id)
    # Build tenant name map
    tenant_ids = list({m.tenant_id for m in msgs})
    tenants = await Tenant.find({"_id": {"$in": tenant_ids}}).to_list() if tenant_ids else []
    tenant_map = {str(t.id): t.full_name for t in tenants}
    return [
        {
            "id": str(m.id),
            "sender_id": str(m.sender_id),
            "receiver_id": str(m.receiver_id),
            "tenant_id": str(m.tenant_id),
            "tenant_name": tenant_map.get(str(m.tenant_id), "Unknown"),
            "subject": m.subject,
            "body": m.body,
            "direction": m.direction.value if m.direction else None,
            "status": m.status.value if m.status else None,
            "thread_id": m.thread_id,
            "created_at": m.created_at.isoformat() if m.created_at else None,
            "read_at": m.read_at.isoformat() if m.read_at else None,
        }
        for m in msgs
    ]