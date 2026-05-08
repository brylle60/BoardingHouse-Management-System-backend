

from pydantic import BaseModel
from typing import Optional
from datetime import datetime
from models.room import RoomStatus, RoomType
from models.lease import LeaseStatus
from models.payment import PaymentStatus, PaymentMethod, PaymentType
from models.maintenance import (
    MaintenanceStatus, MaintenanceCategory, MaintenancePriority
)


# ── Room responses ────────────────────────────────────────────────────────────

class RoomResponse(BaseModel):
    id:                str
    room_number:       str
    floor:             Optional[int]
    wing:              Optional[str]
    room_type:         RoomType
    capacity:          int
    current_occupants: int
    monthly_rent:      float
    deposit:           float
    amenities:         list[str]
    description:       Optional[str]
    status:            RoomStatus
    created_at:        datetime
    updated_at:        datetime


class RoomOccupancyStats(BaseModel):
    total:              int
    vacant:             int
    occupied:           int
    reserved:           int
    under_maintenance:  int
    occupancy_rate_pct: float


# ── Lease responses ───────────────────────────────────────────────────────────

class LeaseResponse(BaseModel):
    id:               str
    tenant_id:        str
    room_id:          str
    start_date:       datetime
    end_date:         Optional[datetime]
    move_in_date:     Optional[datetime]
    move_out_date:    Optional[datetime]
    monthly_rent:     float
    deposit_amount:   float
    deposit_paid:     bool
    deposit_paid_at:  Optional[datetime]
    billing_day:      int
    next_due_date:    Optional[datetime]
    status:           LeaseStatus
    notes:            Optional[str]
    previous_lease_id: Optional[str]
    created_at:       datetime
    updated_at:       datetime


# ── Payment responses ─────────────────────────────────────────────────────────

class PaymentResponse(BaseModel):
    id:             str
    tenant_id:      str
    lease_id:       str
    room_id:        str
    amount:         float
    type:           PaymentType
    method:         PaymentMethod
    status:         PaymentStatus
    reference_no:   Optional[str]
    receipt_number: Optional[str]
    notes:          Optional[str]
    period_start:   Optional[datetime]
    period_end:     Optional[datetime]
    payment_date:   datetime
    confirmed_at:   Optional[datetime]
    created_at:     datetime


class PaymentStats(BaseModel):
    total_collected: float
    total_pending:   float
    confirmed_count: int
    pending_count:   int


# ── Maintenance responses ─────────────────────────────────────────────────────

class MaintenanceResponse(BaseModel):
    id:               str
    tenant_id:        str
    room_id:          str
    assigned_to:      Optional[str]
    title:            str
    description:      str
    category:         MaintenanceCategory
    priority:         MaintenancePriority
    photos:           list[str]
    status:           MaintenanceStatus
    resolution:       Optional[str]
    rejection_reason: Optional[str]
    assigned_at:      Optional[datetime]
    started_at:       Optional[datetime]
    completed_at:     Optional[datetime]
    closed_at:        Optional[datetime]
    created_at:       datetime
    updated_at:       datetime


class MaintenanceStats(BaseModel):
    submitted:   int
    assigned:    int
    in_progress: int
    completed:   int
    closed:      int


# ── Manager dashboard response ────────────────────────────────────────────────

class ManagerDashboardResponse(BaseModel):
    occupancy:   RoomOccupancyStats
    payments:    PaymentStats
    maintenance: MaintenanceStats


# ── Mapper helpers ────────────────────────────────────────────────────────────

def to_room_response(room) -> RoomResponse:
    return RoomResponse(
        id                = str(room.id),
        room_number       = room.room_number,
        floor             = room.floor,
        wing              = room.wing,
        room_type         = room.room_type,
        capacity          = room.capacity,
        current_occupants = room.current_occupants,
        monthly_rent      = room.monthly_rent,
        deposit           = room.deposit,
        amenities         = room.amenities,
        description       = room.description,
        status            = room.status,
        created_at        = room.created_at,
        updated_at        = room.updated_at,
    )


def to_lease_response(lease) -> LeaseResponse:
    return LeaseResponse(
        id                = str(lease.id),
        tenant_id         = str(lease.tenant_id),
        room_id           = str(lease.room_id),
        start_date        = lease.start_date,
        end_date          = lease.end_date,
        move_in_date      = lease.move_in_date,
        move_out_date     = lease.move_out_date,
        monthly_rent      = lease.monthly_rent,
        deposit_amount    = lease.deposit_amount,
        deposit_paid      = lease.deposit_paid,
        deposit_paid_at   = lease.deposit_paid_at,
        billing_day       = lease.billing_day,
        next_due_date     = lease.next_due_date,
        status            = lease.status,
        notes             = lease.notes,
        previous_lease_id = str(lease.previous_lease_id) if lease.previous_lease_id else None,
        created_at        = lease.created_at,
        updated_at        = lease.updated_at,
    )


def to_payment_response(payment) -> PaymentResponse:
    return PaymentResponse(
        id             = str(payment.id),
        tenant_id      = str(payment.tenant_id),
        lease_id       = str(payment.lease_id),
        room_id        = str(payment.room_id),
        amount         = payment.amount,
        type           = payment.type,
        method         = payment.method,
        status         = payment.status,
        reference_no   = payment.reference_no,
        receipt_number = payment.receipt_number,
        notes          = payment.notes,
        period_start   = payment.period_start,
        period_end     = payment.period_end,
        payment_date   = payment.payment_date,
        confirmed_at   = payment.confirmed_at,
        created_at     = payment.created_at,
    )


def to_maintenance_response(req) -> MaintenanceResponse:
    return MaintenanceResponse(
        id               = str(req.id),
        tenant_id        = str(req.tenant_id),
        room_id          = str(req.room_id),
        assigned_to      = str(req.assigned_to) if req.assigned_to else None,
        title            = req.title,
        description      = req.description,
        category         = req.category,
        priority         = req.priority,
        photos           = req.photos,
        status           = req.status,
        resolution       = req.resolution,
        rejection_reason = req.rejection_reason,
        assigned_at      = req.assigned_at,
        started_at       = req.started_at,
        completed_at     = req.completed_at,
        closed_at        = req.closed_at,
        created_at       = req.created_at,
        updated_at       = req.updated_at,
    )
