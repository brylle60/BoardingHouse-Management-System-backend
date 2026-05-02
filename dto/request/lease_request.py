# ============================================================
# dto/request/lease_request.py
# ResidEase – Boarding House Management System
# ============================================================

from pydantic import BaseModel, Field, field_validator, model_validator
from typing import Optional
from datetime import date, datetime

from models.lease import LeaseStatus, PaymentFrequency, TerminationReason


# ================================================================
# LEASE CREATE REQUEST
# ================================================================

class LeaseCreateRequest(BaseModel):
    """
    Payload for POST /api/leases

    Required:
    - tenant_id       → must reference an existing Tenant
    - room_id         → must reference an existing Room
    - start_date      → lease start date
    - end_date        → lease end date (must be after start_date)
    - monthly_rate    → rent amount in PHP (must be > 0)

    Optional:
    - payment_frequency  → defaults to MONTHLY
    - deposit_amount     → security deposit collected at move-in
    - advance_amount     → advance payment collected at move-in
    - due_day            → day of month rent is due (1–28)
    - special_terms      → free-text contract conditions
    - contract_number    → physical/digital contract reference
    - auto_renew         → auto-renew on expiry flag
    """

    # ── Links ─────────────────────────────────────────────────
    tenant_id: str = Field(
        ...,
        description="MongoDB ObjectId string of the Tenant."
    )
    room_id: str = Field(
        ...,
        description="MongoDB ObjectId string of the Room."
    )

    # ── Lease Period ──────────────────────────────────────────
    start_date: date = Field(
        ...,
        description="Lease start date (YYYY-MM-DD)."
    )
    end_date: date = Field(
        ...,
        description="Lease end date (YYYY-MM-DD). Must be after start_date."
    )

    # ── Payment Terms ─────────────────────────────────────────
    payment_frequency: PaymentFrequency = Field(
        default=PaymentFrequency.MONTHLY,
        description="Billing cycle frequency."
    )
    monthly_rate: float = Field(
        ...,
        gt=0,
        description="Base monthly rent in PHP."
    )
    deposit_amount: float = Field(
        default=0.0,
        ge=0,
        description="Security deposit collected at move-in (PHP)."
    )
    advance_amount: float = Field(
        default=0.0,
        ge=0,
        description="Advance payment collected at move-in (PHP)."
    )

    # ── Due Date ──────────────────────────────────────────────
    due_day: int = Field(
        default=1,
        ge=1,
        le=28,
        description="Day of the month rent is due (1–28)."
    )

    # ── Special Terms ─────────────────────────────────────────
    special_terms: Optional[str] = Field(
        default=None,
        max_length=1000,
        description="Free-text special conditions agreed at signing."
    )

    # ── Contract Reference ────────────────────────────────────
    contract_number: Optional[str] = Field(
        default=None,
        max_length=50,
        description="Physical or digital contract reference number."
    )

    # ── Flags ─────────────────────────────────────────────────
    auto_renew: bool = Field(
        default=False,
        description="If True, lease is auto-renewed by scheduler on expiry."
    )

    # ── Validators ────────────────────────────────────────────

    @field_validator("tenant_id", "room_id")
    @classmethod
    def strip_ids(cls, v: str) -> str:
        v = v.strip()
        if len(v) != 24:
            raise ValueError(
                "tenant_id and room_id must be valid 24-character MongoDB ObjectIds."
            )
        return v

    @field_validator("monthly_rate", "deposit_amount", "advance_amount")
    @classmethod
    def round_amounts(cls, v: float) -> float:
        return round(v, 2)

    @field_validator("special_terms", "contract_number")
    @classmethod
    def strip_optional_strings(cls, v: Optional[str]) -> Optional[str]:
        return v.strip() if v else None

    @model_validator(mode="after")
    def end_date_after_start_date(self) -> "LeaseCreateRequest":
        if self.end_date <= self.start_date:
            raise ValueError(
                "end_date must be after start_date."
            )
        return self

    @model_validator(mode="after")
    def start_date_not_too_far_past(self) -> "LeaseCreateRequest":
        from datetime import timedelta
        min_start = date.today() - timedelta(days=7)
        if self.start_date < min_start:
            raise ValueError(
                "start_date cannot be more than 7 days in the past."
            )
        return self

    @model_validator(mode="after")
    def deposit_reasonable(self) -> "LeaseCreateRequest":
        """
        Warns if deposit is unusually high (> 6 months rent).
        Hard cap at 12 months to prevent data entry errors.
        """
        if self.deposit_amount > self.monthly_rate * 12:
            raise ValueError(
                f"deposit_amount (₱{self.deposit_amount:,.2f}) exceeds "
                f"12 months of rent. Please verify the amount."
            )
        return self

    model_config = {
        "json_schema_extra": {
            "example": {
                "tenant_id":          "665f1c2e8a4b2c001f3d9a11",
                "room_id":            "665f1c2e8a4b2c001f3d9b22",
                "start_date":         "2024-07-01",
                "end_date":           "2025-06-30",
                "payment_frequency":  "MONTHLY",
                "monthly_rate":       5000.00,
                "deposit_amount":     10000.00,
                "advance_amount":     5000.00,
                "due_day":            1,
                "special_terms":      "No pets allowed. Utilities included up to PHP 500.",
                "contract_number":    "CONTRACT-2024-001",
                "auto_renew":         False
            }
        }
    }


# ================================================================
# LEASE UPDATE REQUEST
# ================================================================

class LeaseUpdateRequest(BaseModel):
    """
    Payload for PATCH /api/leases/{lease_id}

    All fields are optional — only fields included in the
    request body will be updated (true PATCH behavior).

    NOT updatable here:
    - tenant_id       → cannot change tenant on a lease
    - room_id         → cannot change room on a lease
    - monthly_rate    → use LeaseRenewRequest for rate changes
    - start_date      → cannot change lease start date
    - status          → use dedicated status endpoints
    """

    # ── Editable Fields Only ──────────────────────────────────
    end_date:          Optional[date]             = None
    due_day:           Optional[int]              = Field(default=None, ge=1, le=28)
    payment_frequency: Optional[PaymentFrequency] = None
    special_terms:     Optional[str]              = Field(default=None, max_length=1000)
    contract_number:   Optional[str]              = Field(default=None, max_length=50)
    auto_renew:        Optional[bool]             = None
    is_expiring_soon:  Optional[bool]             = None

    # ── Validators ────────────────────────────────────────────

    @field_validator("special_terms", "contract_number")
    @classmethod
    def strip_optional_strings(cls, v: Optional[str]) -> Optional[str]:
        return v.strip() if v else None

    @model_validator(mode="after")
    def at_least_one_field_required(self) -> "LeaseUpdateRequest":
        provided = {
            k: v for k, v in self.model_dump().items()
            if v is not None
        }
        if not provided:
            raise ValueError(
                "At least one field must be provided for update."
            )
        return self

    model_config = {
        "json_schema_extra": {
            "example": {
                "end_date":    "2025-12-31",
                "due_day":     5,
                "auto_renew":  True,
                "special_terms": "No pets. Utilities included up to PHP 800."
            }
        }
    }


# ================================================================
# LEASE RENEW REQUEST
# ================================================================

class LeaseRenewRequest(BaseModel):
    """
    Payload for PATCH /api/leases/{lease_id}/renew

    Extends the lease end date and optionally adjusts the rate.
    Creates an audit entry in renewal_history.

    Required:
    - new_end_date    → must be after the current end_date

    Optional:
    - new_monthly_rate → if provided, updates the rate from renewal date
    - due_day          → optionally change the due day on renewal
    - notes            → reason for renewal or rate change
    """
    new_end_date: date = Field(
        ...,
        description="New lease end date. Must be after current end_date."
    )
    new_monthly_rate: Optional[float] = Field(
        default=None,
        gt=0,
        description="Updated monthly rent in PHP from renewal date onwards."
    )
    due_day: Optional[int] = Field(
        default=None,
        ge=1,
        le=28,
        description="Updated due day of the month (1–28)."
    )
    notes: Optional[str] = Field(
        default=None,
        max_length=500,
        description="Reason for renewal or notes about rate change."
    )

    # ── Validators ────────────────────────────────────────────

    @field_validator("new_monthly_rate")
    @classmethod
    def round_rate(cls, v: Optional[float]) -> Optional[float]:
        return round(v, 2) if v is not None else None

    @field_validator("notes")
    @classmethod
    def strip_notes(cls, v: Optional[str]) -> Optional[str]:
        return v.strip() if v else None

    model_config = {
        "json_schema_extra": {
            "example": {
                "new_end_date":      "2026-06-30",
                "new_monthly_rate":  5500.00,
                "due_day":           1,
                "notes":             "Annual renewal with 10% rate increase."
            }
        }
    }


# ================================================================
# LEASE TERMINATE REQUEST
# ================================================================

class LeaseTerminateRequest(BaseModel):
    """
    Payload for PATCH /api/leases/{lease_id}/terminate

    Required:
    - reason          → TerminationReason enum value

    Optional:
    - move_out_date      → defaults to today if not provided
    - notes              → additional context for termination
    - deposit_returned   → whether deposit was returned to tenant
    - deposit_deductions → amount deducted from deposit (PHP)
    """
    reason: TerminationReason = Field(
        ...,
        description="Reason for early lease termination."
    )
    move_out_date: Optional[date] = Field(
        default=None,
        description="Actual move-out date. Defaults to today if not provided."
    )
    notes: Optional[str] = Field(
        default=None,
        max_length=1000,
        description="Additional context or notes about the termination."
    )
    deposit_returned: bool = Field(
        default=False,
        description="Whether the security deposit has been returned to the tenant."
    )
    deposit_deductions: float = Field(
        default=0.0,
        ge=0,
        description="Amount deducted from deposit for damages or unpaid rent (PHP)."
    )

    # ── Validators ────────────────────────────────────────────

    @field_validator("deposit_deductions")
    @classmethod
    def round_deductions(cls, v: float) -> float:
        return round(v, 2)

    @field_validator("notes")
    @classmethod
    def strip_notes(cls, v: Optional[str]) -> Optional[str]:
        return v.strip() if v else None

    @model_validator(mode="after")
    def move_out_not_in_future(self) -> "LeaseTerminateRequest":
        if self.move_out_date and self.move_out_date > date.today():
            raise ValueError(
                "move_out_date cannot be in the future."
            )
        return self

    @model_validator(mode="after")
    def deposit_returned_requires_no_balance(self) -> "LeaseTerminateRequest":
        """
        If deposit_returned is True, deductions must be >= 0.
        Actual balance check is handled in lease_service.py.
        """
        if self.deposit_returned and self.deposit_deductions < 0:
            raise ValueError(
                "deposit_deductions cannot be negative when deposit_returned is True."
            )
        return self

    model_config = {
        "json_schema_extra": {
            "example": {
                "reason":             "VOLUNTARY",
                "move_out_date":      "2024-08-31",
                "notes":              "Tenant relocated for work.",
                "deposit_returned":   True,
                "deposit_deductions": 500.00
            }
        }
    }


# ================================================================
# DEPOSIT RETURN REQUEST
# ================================================================

class DepositReturnRequest(BaseModel):
    """
    Payload for PATCH /api/leases/{lease_id}/return-deposit

    Used when deposit return is processed separately
    from termination — e.g. after damage assessment.

    Required:
    - deductions  → amount deducted (0.0 if full refund)
    """
    deductions: float = Field(
        default=0.0,
        ge=0,
        description="Amount deducted from deposit for damages or unpaid balance (PHP)."
    )
    notes: Optional[str] = Field(
        default=None,
        max_length=500,
        description="Reason for deductions or notes about the deposit return."
    )

    @field_validator("deductions")
    @classmethod
    def round_deductions(cls, v: float) -> float:
        return round(v, 2)

    @field_validator("notes")
    @classmethod
    def strip_notes(cls, v: Optional[str]) -> Optional[str]:
        return v.strip() if v else None

    model_config = {
        "json_schema_extra": {
            "example": {
                "deductions": 500.00,
                "notes":      "Deducted for broken window repair."
            }
        }
    }