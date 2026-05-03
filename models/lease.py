# ============================================================
# models/lease.py
# ResidEase – Boarding House Management System
# ============================================================

from beanie import Document, Link
from pydantic import BaseModel, Field
from typing import Optional
from datetime import datetime, date
from enum import Enum


# ================================================================
# ENUMS
# ================================================================

class LeaseStatus(str, Enum):
    ACTIVE      = "ACTIVE"       # Currently running lease
    EXPIRED     = "EXPIRED"      # End date has passed, not renewed
    TERMINATED  = "TERMINATED"   # Ended early by admin/manager
    PENDING     = "PENDING"      # Created but not yet started
    RENEWED     = "RENEWED"      # Superseded by a new lease


class PaymentFrequency(str, Enum):
    MONTHLY     = "MONTHLY"      # Standard monthly billing
    WEEKLY      = "WEEKLY"       # Weekly billing cycle
    DAILY       = "DAILY"        # Daily rate (short-term stays)


class TerminationReason(str, Enum):
    VOLUNTARY       = "VOLUNTARY"       # Tenant chose to leave
    NON_PAYMENT     = "NON_PAYMENT"     # Evicted for unpaid rent
    VIOLATION       = "VIOLATION"       # House rules violation
    UNIT_SOLD       = "UNIT_SOLD"       # Property sold
    RENOVATION      = "RENOVATION"      # Room undergoing renovation
    MUTUAL_AGREEMENT= "MUTUAL_AGREEMENT"# Both parties agreed
    OTHER           = "OTHER"


# ================================================================
# EMBEDDED SUB-DOCUMENTS
# ================================================================

class LeaseTerminationDetails(BaseModel):
    """
    Embedded record of how and why a lease was terminated.
    Only populated when status is TERMINATED or EXPIRED.
    """
    reason:           TerminationReason
    terminated_by:    str               
    terminated_at:    datetime          = Field(default_factory=datetime.utcnow)
    notes:            Optional[str]     = None
    deposit_returned: bool              = False
    deposit_deductions: float           = 0.0   # amount deducted from deposit
    deposit_returned_amount: float      = 0.0   # actual amount returned


class LeaseRenewalRecord(BaseModel):
    """
    Embedded record of a single lease renewal event.
    Appended to renewal_history each time a lease is renewed.
    """
    renewed_at:       datetime  = Field(default_factory=datetime.utcnow)
    renewed_by:       str      
    previous_end_date: date     # end date before renewal
    new_end_date:     date      # end date after renewal
    new_monthly_rate: Optional[float] = None   # rate change on renewal
    notes:            Optional[str]  = None


# ================================================================
# MAIN DOCUMENT
# ================================================================

class Lease(Document):
    """
    Represents a rental agreement between a tenant and a room.

    Relationships:
    - tenant_id   → references Tenant document
    - room_id     → references Room document

    Embedded:
    - LeaseTerminationDetails  (populated on termination)
    - LeaseRenewalRecord list  (one entry per renewal event)

    Financial:
    - monthly_rate is locked at lease creation time
      (rate changes on renewal create a new LeaseRenewalRecord)
    - BillingService reads this to generate monthly billing cycles
    - outstanding_balance is a running total updated by PaymentService

    Lifecycle:
    PENDING → ACTIVE → EXPIRED   (natural end)
                     → TERMINATED (early end)
                     → RENEWED    (superseded by new lease)
    """

    # ── Links ─────────────────────────────────────────────────
    tenant_id: str   # stores Tenant ObjectId as string
    room_id:   str   # stores Room ObjectId as string

    # ── Lease Period ──────────────────────────────────────────
    start_date:  date
    end_date:    date
    status:      LeaseStatus      = LeaseStatus.PENDING

    # ── Payment Terms ─────────────────────────────────────────
    payment_frequency: PaymentFrequency = PaymentFrequency.MONTHLY

    # monthly_rate is LOCKED at lease creation — does not change
    # mid-lease. Rate changes are recorded in renewal_history.
    monthly_rate: float = Field(..., gt=0)

    # Deposit and advance collected at move-in
    deposit_amount:  float = Field(default=0.0, ge=0)
    advance_amount:  float = Field(default=0.0, ge=0)

    # Running financial totals — updated by PaymentService only
    total_paid:          float = 0.0
    outstanding_balance: float = 0.0

    # ── Due Date ──────────────────────────────────────────────
    # Day of the month rent is due (1-28)
    # e.g. due_day=1 means rent is due every 1st of the month
    due_day: int = Field(default=1, ge=1, le=28)

    # ── Special Terms ─────────────────────────────────────────
    # Free-text special conditions agreed upon at signing
    # e.g. "No pets", "Includes utility bill up to PHP 500"
    special_terms: Optional[str] = None

    # ── Contract Reference ────────────────────────────────────
    # Physical or digital contract reference number
    contract_number: Optional[str] = None

    # ── Termination ───────────────────────────────────────────
    # Populated only when lease is TERMINATED or EXPIRED
    termination_details: Optional[LeaseTerminationDetails] = None

    # ── Renewal History ───────────────────────────────────────
    # Append-only log of all renewal events
    renewal_history: list[LeaseRenewalRecord] = Field(default_factory=list)

    # ── Flags ─────────────────────────────────────────────────
    is_expiring_soon: bool = False   # set by scheduler when within 30 days of end
    auto_renew:       bool = False   # if True, scheduler auto-renews on expiry

    # ── Audit Fields ──────────────────────────────────────────
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)
    created_by: Optional[str] = None  
    updated_by: Optional[str] = None   # username of last editor

    # ── Beanie Settings ───────────────────────────────────────
    class Settings:
        name = "leases"   # MongoDB collection name
        indexes = [
            [("tenant_id", 1)],              # fast lookup by tenant
            [("room_id",   1)],              # fast lookup by room
            [("status",    1)],              # fast filter by status
            [("end_date",  1)],              # fast sort for expiry checks
            [("tenant_id", 1), ("status", 1)],  # compound: active lease per tenant
            [("room_id",   1), ("status", 1)],  # compound: active lease per room
        ]

    # ── Computed Properties ───────────────────────────────────

    @property
    def is_active(self) -> bool:
        return self.status == LeaseStatus.ACTIVE

    @property
    def is_terminated(self) -> bool:
        return self.status == LeaseStatus.TERMINATED

    @property
    def is_expired(self) -> bool:
        return self.status == LeaseStatus.EXPIRED

    @property
    def is_pending(self) -> bool:
        return self.status == LeaseStatus.PENDING

    @property
    def duration_days(self) -> int:
        """Total lease duration in days."""
        return (self.end_date - self.start_date).days

    @property
    def duration_months(self) -> int:
        """Approximate lease duration in months."""
        return round(self.duration_days / 30)

    @property
    def days_remaining(self) -> int:
        """Days remaining until lease end date. Negative if overdue."""
        return (self.end_date - date.today()).days

    @property
    def has_outstanding_balance(self) -> bool:
        return self.outstanding_balance > 0

    @property
    def move_in_total(self) -> float:
        """
        Total amount collected at move-in:
        deposit + advance payment.
        """
        return round(self.deposit_amount + self.advance_amount, 2)

    @property
    def renewal_count(self) -> int:
        """Number of times this lease has been renewed."""
        return len(self.renewal_history)

    @property
    def was_renewed(self) -> bool:
        """True if this lease has been renewed at least once."""
        return len(self.renewal_history) > 0

    # ── String Representation ─────────────────────────────────

    def __str__(self) -> str:
        return (
            f"Lease("
            f"tenant={self.tenant_id}, "
            f"room={self.room_id}, "
            f"status={self.status.value}, "
            f"period={self.start_date} → {self.end_date}, "
            f"rate=₱{self.monthly_rate:,.2f}"
            f")"
        )

    def __repr__(self) -> str:
        return (
            f"<Lease id={self.id} "
            f"tenant='{self.tenant_id}' "
            f"room='{self.room_id}' "
            f"status='{self.status.value}'>"
        )