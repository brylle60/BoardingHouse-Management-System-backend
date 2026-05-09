"""
controllers/booking_request_controller.py

Endpoints for:
- Tenants applying to book a room
- Managers / Admins reviewing / approving / rejecting bookings
"""

from fastapi import APIRouter, Depends, HTTPException, status, Query, Body
from beanie import PydanticObjectId
from typing import Optional
from datetime import datetime, date

from models.user import User, RoleName
from models.booking_request import BookingRequest, BookingStatus
from models.room import Room, RoomStatus
from models.tenant import Tenant, TenantStatus
from models.lease import Lease, LeaseStatus, PaymentFrequency
from config.jwt_middleware import get_current_user, require_roles

router = APIRouter(prefix="/api/bookings", tags=["Booking Requests"])


# ── Request / Response schemas ────────────────────────────────────────────

from pydantic import BaseModel


class BookingApplyRequest(BaseModel):
    room_id:              str
    full_name:            str
    email:                str
    phone:                str
    address:              str
    city:                 Optional[str] = None
    province:             Optional[str] = None
    desired_move_in_date: Optional[date] = None
    message:              Optional[str] = None
    id_document:          Optional[str] = None


class ReviewBookingRequest(BaseModel):
    status:       BookingStatus
    review_notes: Optional[str] = None


# ── Helpers ───────────────────────────────────────────────────────────────

async def get_booking_or_404(booking_id: str) -> BookingRequest:
    b = await BookingRequest.get(PydanticObjectId(booking_id))
    if not b:
        raise HTTPException(404, "Booking request not found.")
    return b


async def get_room_or_404(room_id: str) -> Room:
    r = await Room.get(PydanticObjectId(room_id))
    if not r:
        raise HTTPException(404, "Room not found.")
    return r


# ============================================================================
# TENANT / PUBLIC ENDPOINTS
# ============================================================================

@router.post(
    "/apply",
    status_code=status.HTTP_201_CREATED,
    summary="Apply to book a room",
)
async def apply_booking(
    body: BookingApplyRequest,
    current_user: User = Depends(get_current_user),
):
    """Authenticated users may submit a booking application for a vacant room."""
    room = await get_room_or_404(body.room_id)

    if not room.is_vacant:
        raise HTTPException(400, "This room is no longer available for booking.")

    # Prevent duplicate pending applications for same room by same user
    existing = await BookingRequest.find_one(
        {
            "user_id": str(current_user.id),
            "room_id": body.room_id,
            "status": BookingStatus.PENDING.value,
        }
    )
    if existing:
        raise HTTPException(
            400,
            "You already have a pending booking request for this room.",
        )

    req = BookingRequest(
        user_id              = str(current_user.id),
        room_id              = body.room_id,
        room_number          = room.room_number,
        monthly_rent         = room.monthly_rate,
        full_name            = body.full_name,
        email                = body.email,
        phone                = body.phone,
        address              = body.address,
        city                 = body.city,
        province             = body.province,
        desired_move_in_date = body.desired_move_in_date,
        message              = body.message,
        id_document          = body.id_document,
    )
    await req.insert()
    return {
        "message": "Booking request submitted successfully. Awaiting manager review.",
        "id": str(req.id),
    }


@router.get(
    "/my",
    summary="Get my booking requests",
)
async def get_my_bookings(
    current_user: User = Depends(get_current_user),
):
    """Returns all booking requests made by the current user."""
    reqs = await BookingRequest.find({"user_id": str(current_user.id)}).sort(-BookingRequest.created_at).to_list()
    return {
        "bookings": [
            {
                "id":                 str(r.id),
                "room_id":            r.room_id,
                "room_number":        r.room_number,
                "monthly_rent":       r.monthly_rent,
                "full_name":          r.full_name,
                "email":              r.email,
                "phone":              r.phone,
                "address":            r.address,
                "desired_move_in_date": r.desired_move_in_date.isoformat() if r.desired_move_in_date else None,
                "message":            r.message,
                "status":             r.status.value,
                "review_notes":       r.review_notes,
                "created_at":         r.created_at.isoformat(),
            }
            for r in reqs
        ]
    }


# ============================================================================
# MANAGER / ADMIN ENDPOINTS
# ============================================================================

@router.get(
    "/manager/all",
    summary="List all booking applications (manager / admin)",
)
async def list_all_bookings(
    status: Optional[BookingStatus] = Query(default=None),
    skip:   int = Query(default=0, ge=0),
    limit:  int = Query(default=20, ge=1, le=100),
    _: User = Depends(require_roles(RoleName.ADMIN, RoleName.MANAGER)),
):
    """Manager / Admin view. Filter by PENDING, APPROVED, REJECTED, or CANCELLED."""
    query = {}
    if status:
        query["status"] = status.value

    reqs = await BookingRequest.find(query).sort(-BookingRequest.created_at).skip(skip).limit(limit).to_list()
    total = await BookingRequest.find(query).count()

    return {
        "total": total,
        "skip":  skip,
        "limit": limit,
        "bookings": [
            {
                "id":                 str(r.id),
                "user_id":            r.user_id,
                "room_id":            r.room_id,
                "room_number":        r.room_number,
                "monthly_rent":       r.monthly_rent,
                "full_name":          r.full_name,
                "email":              r.email,
                "phone":              r.phone,
                "address":            r.address,
                "city":               r.city,
                "province":           r.province,
                "desired_move_in_date": r.desired_move_in_date.isoformat() if r.desired_move_in_date else None,
                "message":            r.message,
                "id_document":        r.id_document,
                "status":             r.status.value,
                "reviewed_by":        r.reviewed_by,
                "reviewed_at":        r.reviewed_at.isoformat() if r.reviewed_at else None,
                "review_notes":       r.review_notes,
                "created_at":         r.created_at.isoformat(),
            }
            for r in reqs
        ],
    }


@router.get(
    "/manager/{booking_id}",
    summary="Get single booking detail (manager / admin)",
)
async def get_booking_detail(
    booking_id: str,
    _: User = Depends(require_roles(RoleName.ADMIN, RoleName.MANAGER)),
):
    r = await get_booking_or_404(booking_id)
    return {
        "id":                 str(r.id),
        "user_id":            r.user_id,
        "room_id":            r.room_id,
        "room_number":        r.room_number,
        "monthly_rent":       r.monthly_rent,
        "full_name":          r.full_name,
        "email":              r.email,
        "phone":              r.phone,
        "address":            r.address,
        "city":               r.city,
        "province":           r.province,
        "desired_move_in_date": r.desired_move_in_date.isoformat() if r.desired_move_in_date else None,
        "message":            r.message,
        "id_document":        r.id_document,
        "status":             r.status.value,
        "reviewed_by":        r.reviewed_by,
        "reviewed_at":        r.reviewed_at.isoformat() if r.reviewed_at else None,
        "review_notes":       r.review_notes,
        "created_at":         r.created_at.isoformat(),
    }


@router.patch(
    "/manager/{booking_id}/review",
    summary="Approve or reject a booking request",
)
async def review_booking(
    booking_id: str,
    body: ReviewBookingRequest,
    current_user: User = Depends(require_roles(RoleName.ADMIN, RoleName.MANAGER)),
):
    """
    Manager/Admin reviews a booking.
    If APPROVED, the room is marked RESERVED (actual lease creation is separate).
    """
    req = await get_booking_or_404(booking_id)

    if req.status != BookingStatus.PENDING:
        raise HTTPException(400, "This booking has already been reviewed.")

    req.status = body.status
    req.reviewed_by = str(current_user.id)
    req.reviewed_at = datetime.utcnow()
    req.review_notes = body.review_notes
    req.updated_at = datetime.utcnow()
    await req.save()

    if body.status == BookingStatus.APPROVED:
        room = await Room.get(PydanticObjectId(req.room_id))
        if room and room.is_vacant:
            # ── 1. Create Tenant profile from booking data (if not exists) ──
            existing_tenant = await Tenant.find_one({"user_id": req.user_id})
            if existing_tenant:
                tenant = existing_tenant
            else:
                name_parts = req.full_name.strip().split()
                first_name = name_parts[0] if name_parts else req.full_name
                last_name = name_parts[-1] if len(name_parts) > 1 else ""

                tenant = Tenant(
                    user_id       = req.user_id,
                    first_name    = first_name,
                    last_name     = last_name,
                    phone         = req.phone,
                    email         = req.email,
                    room_id       = req.room_id,
                    status        = TenantStatus.ACTIVE,
                    move_in_date  = req.desired_move_in_date or datetime.utcnow(),
                    created_by    = str(current_user.id),
                )
                await tenant.insert()

            # ── 2. Create Lease ──
            today = date.today()
            end_dt = date(today.year + 1, today.month, min(today.day, 28))
            lease = Lease(
                tenant_id        = str(tenant.id),
                room_id          = req.room_id,
                start_date       = today,
                end_date         = end_dt,
                status           = LeaseStatus.ACTIVE,
                monthly_rate     = req.monthly_rent,
                payment_frequency= PaymentFrequency.MONTHLY,
                deposit_amount   = req.monthly_rent * 2,
                advance_amount   = req.monthly_rent,
                due_day          = 1,
                created_by       = str(current_user.id),
            )
            await lease.insert()

            # ── 3. Update room ──
            room.status = RoomStatus.OCCUPIED
            room.current_occupants = min(room.current_occupants + 1, room.max_occupants)
            room.updated_at = datetime.utcnow()
            await room.save()

    action_word = "approved" if body.status == BookingStatus.APPROVED else "rejected"
    return {
        "message": f"Booking {action_word} successfully.",
        "booking_id": str(req.id),
        "status": req.status.value,
    }


@router.delete(
    "/manager/{booking_id}",
    summary="Delete a booking request (manager / admin)",
    status_code=status.HTTP_200_OK,
)
async def delete_booking(
    booking_id: str,
    _: User = Depends(require_roles(RoleName.ADMIN, RoleName.MANAGER)),
):
    req = await get_booking_or_404(booking_id)
    await req.delete()
    return {"message": "Booking request deleted successfully."}
