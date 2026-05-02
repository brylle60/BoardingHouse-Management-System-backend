# ============================================================
# dto/response/lease_response.py
# ResidEase – Boarding House Management System
# ============================================================

from pydantic import BaseModel
from typing import Optional
from datetime import datetime, date

from models.lease import (
    Lease,
    LeaseStatus,
    PaymentFrequency,
    TerminationReason,
)


# ================================================================
# EMBEDDED RESPONSE SCHEMAS
# ================================================================

class LeaseTerminationResponse(BaseModel):
    """
    Embedded termination details returned when a lease
    has been TERMINATED or EXPIRED.
    """
    reason:                  TerminationReason
    terminated_by:           str
    terminated_at:           datetime
    notes:                   Optional[str]  = None
    deposit_returned:        bool
    deposit_deductions:      float
    deposit_returned_amount: float


class LeaseRenewalRecordResponse(BaseModel):
    """
    Single renewal event returned inside renewal_history list.
    """
    renewed_at:        datetime
    renewed_by:        str
    previous_end_date: date
    new_end_date:      date
    new_monthly_rate:  Optional[float] = None
    notes:             Optional[str]   = None


# ================================================================
# MAIN LEASE RESPONSE
# ================================================================

class LeaseResponse(BaseModel):
    """
    Full lease data returned by all lease endpoints.
    Consistent shape across GET, POST, PATCH responses.
    """

    # ── Identity ──────────────────────────────────────────────
    id:        str
    tenant_id: str
    room_id:   str

    # ── Lease Period ──────────────────────────────────────────
    start_date: date
    end_date:   date
    status:     LeaseStatus

    # ── Computed Period Info ───────────────────────────────────
    duration_days:   int
    duration_months: int
    days_remaining:  int

    # ── Payment Terms ─────────────────────────────────────────
    payment_frequency: PaymentFrequency
    monthly_rate:      float
    deposit_amount:    float
    advance_amount:    float
    due_day:           int

    # ── Financial Summary ─────────────────────────────────────
    total_paid:          float
    outstanding_balance: float
    move_in_total:       float
    has_outstanding_balance: bool

    # ── Special Terms ─────────────────────────────────────────
    special_terms:   Optional[str] = None
    contract_number: Optional[str] = None

    # ── Flags ─────────────────────────────────────────────────
    is_active:        bool
    is_pending:       bool
    is_expired:       bool
    is_terminated:    bool
    is_expiring_soon: bool
    auto_renew:       bool

    # ── Renewal ───────────────────────────────────────────────
    renewal_count:   int
    was_renewed:     bool
    renewal_history: list[LeaseRenewalRecordResponse] = []

    # ── Termination ───────────────────────────────────────────
    termination_details: Optional[LeaseTerminationResponse] = None

    # ── Audit ─────────────────────────────────────────────────
    created_at: datetime
    updated_at: datetime
    created_by: Optional[str] = None
    updated_by: Optional[str] = None

    # ── Factory Method ────────────────────────────────────────

    @classmethod
    def from_lease(cls, lease: Lease) -> "LeaseResponse":
        """
        Constructs a LeaseResponse from a Lease Beanie document.
        Called by lease_service.py — never construct this manually.

        All computed @property values from lease.py are
        resolved here so the frontend receives pre-calculated data.
        """

        # ── Termination Details ───────────────────────────────
        termination_response = None
        if lease.termination_details:
            termination_response = LeaseTerminationResponse(
                reason=lease.termination_details.reason,
                terminated_by=lease.termination_details.terminated_by,
                terminated_at=lease.termination_details.terminated_at,
                notes=lease.termination_details.notes,
                deposit_returned=lease.termination_details.deposit_returned,
                deposit_deductions=lease.termination_details.deposit_deductions,
                deposit_returned_amount=lease.termination_details.deposit_returned_amount,
            )

        # ── Renewal History ───────────────────────────────────
        renewal_history_response = [
            LeaseRenewalRecordResponse(
                renewed_at=r.renewed_at,
                renewed_by=r.renewed_by,
                previous_end_date=r.previous_end_date,
                new_end_date=r.new_end_date,
                new_monthly_rate=r.new_monthly_rate,
                notes=r.notes,
            )
            for r in lease.renewal_history
        ]

        return cls(
            # Identity
            id=str(lease.id),
            tenant_id=lease.tenant_id,
            room_id=lease.room_id,

            # Lease Period
            start_date=lease.start_date,
            end_date=lease.end_date,
            status=lease.status,

            # Computed — from @property
            duration_days=lease.duration_days,
            duration_months=lease.duration_months,
            days_remaining=lease.days_remaining,

            # Payment Terms
            payment_frequency=lease.payment_frequency,
            monthly_rate=lease.monthly_rate,
            deposit_amount=lease.deposit_amount,
            advance_amount=lease.advance_amount,
            due_day=lease.due_day,

            # Financial Summary — from @property
            total_paid=lease.total_paid,
            outstanding_balance=lease.outstanding_balance,
            move_in_total=lease.move_in_total,
            has_outstanding_balance=lease.has_outstanding_balance,

            # Special Terms
            special_terms=lease.special_terms,
            contract_number=lease.contract_number,

            # Flags — from @property
            is_active=lease.is_active,
            is_pending=lease.is_pending,
            is_expired=lease.is_expired,
            is_terminated=lease.is_terminated,
            is_expiring_soon=lease.is_expiring_soon,
            auto_renew=lease.auto_renew,

            # Renewal — from @property
            renewal_count=lease.renewal_count,
            was_renewed=lease.was_renewed,
            renewal_history=renewal_history_response,

            # Termination
            termination_details=termination_response,

            # Audit
            created_at=lease.created_at,
            updated_at=lease.updated_at,
            created_by=lease.created_by,
            updated_by=lease.updated_by,
        )

    model_config = {
        "json_schema_extra": {
            "example": {
                "id":                    "665f1c2e8a4b2c001f3d9c33",
                "tenant_id":             "665f1c2e8a4b2c001f3d9a11",
                "room_id":               "665f1c2e8a4b2c001f3d9b22",
                "start_date":            "2024-07-01",
                "end_date":              "2025-06-30",
                "status":                "ACTIVE",
                "duration_days":         365,
                "duration_months":       12,
                "days_remaining":        180,
                "payment_frequency":     "MONTHLY",
                "monthly_rate":          5000.00,
                "deposit_amount":        10000.00,
                "advance_amount":        5000.00,
                "due_day":               1,
                "total_paid":            25000.00,
                "outstanding_balance":   0.00,
                "move_in_total":         15000.00,
                "has_outstanding_balance": False,
                "special_terms":         "No pets. Utilities up to PHP 500.",
                "contract_number":       "CONTRACT-2024-001",
                "is_active":             True,
                "is_pending":            False,
                "is_expired":            False,
                "is_terminated":         False,
                "is_expiring_soon":      False,
                "auto_renew":            False,
                "renewal_count":         0,
                "was_renewed":           False,
                "renewal_history":       [],
                "termination_details":   None,
                "created_at":            "2024-07-01T08:00:00",
                "updated_at":            "2024-07-01T08:00:00",
                "created_by":            "admin_user",
                "updated_by":            "admin_user"
            }
        }
    }


# ================================================================
# LEASE SUMMARY RESPONSE  (lightweight — for listings)
# ================================================================

class LeaseSummaryResponse(BaseModel):
    """
    Lightweight lease shape used in:
    - Tenant profile (showing current lease summary)
    - Room detail (showing current occupancy)
    - Dashboard recent activity feed

    Does NOT include renewal_history, termination_details,
    financial totals, or audit fields.
    Use LeaseResponse for full detail views.
    """
    id:              str
    tenant_id:       str
    room_id:         str
    start_date:      date
    end_date:        date
    status:          LeaseStatus
    monthly_rate:    float
    days_remaining:  int
    is_active:       bool
    is_expiring_soon: bool
    outstanding_balance: float

    @classmethod
    def from_lease(cls, lease: Lease) -> "LeaseSummaryResponse":
        return cls(
            id=str(lease.id),
            tenant_id=lease.tenant_id,
            room_id=lease.room_id,
            start_date=lease.start_date,
            end_date=lease.end_date,
            status=lease.status,
            monthly_rate=lease.monthly_rate,
            days_remaining=lease.days_remaining,
            is_active=lease.is_active,
            is_expiring_soon=lease.is_expiring_soon,
            outstanding_balance=lease.outstanding_balance,
        )

    model_config = {
        "json_schema_extra": {
            "example": {
                "id":                  "665f1c2e8a4b2c001f3d9c33",
                "tenant_id":           "665f1c2e8a4b2c001f3d9a11",
                "room_id":             "665f1c2e8a4b2c001f3d9b22",
                "start_date":          "2024-07-01",
                "end_date":            "2025-06-30",
                "status":              "ACTIVE",
                "monthly_rate":        5000.00,
                "days_remaining":      180,
                "is_active":           True,
                "is_expiring_soon":    False,
                "outstanding_balance": 0.00
            }
        }
    }