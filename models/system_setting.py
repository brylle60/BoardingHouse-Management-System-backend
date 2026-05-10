# ============================================================
# models/system_setting.py
# ResidEase – Boarding House Management System
#
# Stores global system configuration managed by ADMIN.
# Single-document pattern — only ONE settings document
# exists in the collection at all times.
# ============================================================

from beanie import Document
from pydantic import BaseModel, Field
from typing import Optional
from datetime import datetime
from enum import Enum


# ================================================================
# ENUMS
# ================================================================

class CurrencyCode(str, Enum):
    PHP = "PHP"
    USD = "USD"
    EUR = "EUR"


class DateFormat(str, Enum):
    MDY  = "MM/DD/YYYY"
    DMY  = "DD/MM/YYYY"
    YMD  = "YYYY-MM-DD"


class PenaltyType(str, Enum):
    FIXED      = "FIXED"       # flat fee per overdue day/month
    PERCENTAGE = "PERCENTAGE"  # percentage of outstanding balance


class MaintenancePriority(str, Enum):
    LOW    = "LOW"
    NORMAL = "NORMAL"
    HIGH   = "HIGH"
    URGENT = "URGENT"


# ================================================================
# EMBEDDED SUB-DOCUMENTS
# ================================================================

class BusinessInfo(BaseModel):
    """
    Basic boarding house identity and contact info.
    Displayed on receipts, contracts, and reports.
    """
    business_name:    str            = "ResidEase Boarding House"
    owner_name:       Optional[str]  = None
    address:          Optional[str]  = None
    city:             Optional[str]  = None
    province:         Optional[str]  = None
    zip_code:         Optional[str]  = None
    country:          str            = "Philippines"
    phone:            Optional[str]  = None
    email:            Optional[str]  = None
    website:          Optional[str]  = None
    logo_url:         Optional[str]  = None    # filepath or URL
    tin_number:       Optional[str]  = None    # Tax Identification Number


class BillingSettings(BaseModel):
    """
    Controls how billing cycles are generated and
    how late payment penalties are calculated.
    """
    # Currency
    currency_code:   CurrencyCode = CurrencyCode.PHP
    currency_symbol: str          = "₱"

    # Billing cycle
    billing_day:     int  = Field(default=1,  ge=1,  le=28)
    grace_period_days: int = Field(default=5, ge=0, le=30)

    # Penalty settings
    penalty_enabled:    bool         = True
    penalty_type:       PenaltyType  = PenaltyType.FIXED
    penalty_amount:     float        = Field(default=100.0, ge=0)
    penalty_percentage: float        = Field(default=2.0,   ge=0, le=100)

    # Maximum penalty cap
    max_penalty_amount: Optional[float] = None

    # Auto-generate billing cycles
    auto_generate_billing: bool = True


class LeaseSettings(BaseModel):
    """
    Default values used when creating new leases.
    Staff can override these per lease.
    """
    default_deposit_multiplier:  float = Field(default=2.0, gt=0)
    default_advance_multiplier:  float = Field(default=1.0, gt=0)
    default_due_day:             int   = Field(default=1,   ge=1, le=28)
    default_lease_duration_months: int = Field(default=12,  ge=1)
    expiry_reminder_days:        int   = Field(default=30,  ge=1)
    auto_renew_by_default:       bool  = False


class NotificationSettings(BaseModel):
    """
    Controls which notification events are enabled
    and which channels are used by default.
    """
    # Master switch
    notifications_enabled: bool = True

    # Channel switches
    in_app_enabled: bool = True
    email_enabled:  bool = False   # enable when email service is ready
    sms_enabled:    bool = False   # enable when SMS service is ready
    push_enabled:   bool = False   # enable when push service is ready

    # Event switches
    notify_on_lease_created:       bool = True
    notify_on_lease_expiring:      bool = True
    notify_on_lease_expired:       bool = True
    notify_on_lease_terminated:    bool = True
    notify_on_lease_renewed:       bool = True
    notify_on_payment_received:    bool = True
    notify_on_payment_overdue:     bool = True
    notify_on_payment_reminder:    bool = True
    notify_on_maintenance_updates: bool = True
    notify_on_room_assignment:     bool = True
    notify_on_announcements:       bool = True

    # Reminder schedule (days before due date)
    payment_reminder_days_before: int = Field(default=3, ge=1, le=30)


class MaintenanceSettings(BaseModel):
    """
    Controls maintenance request workflow defaults.
    """
    auto_assign_enabled:      bool                = False
    default_priority:         MaintenancePriority = MaintenancePriority.NORMAL
    max_open_requests_per_room: int               = Field(default=3, ge=1)
    resolution_target_days:   int                 = Field(default=7, ge=1)


class SecuritySettings(BaseModel):
    """
    Controls authentication and session security.
    """
    max_login_attempts:       int   = Field(default=5,    ge=1)
    lockout_duration_minutes: int   = Field(default=15,   ge=1)
    session_timeout_minutes:  int   = Field(default=60,   ge=1)
    password_min_length:      int   = Field(default=8,    ge=6)
    require_strong_password:  bool  = True
    allow_multiple_sessions:  bool  = True


class ReportSettings(BaseModel):
    """
    Controls report generation defaults.
    """
    default_date_format:        DateFormat = DateFormat.MDY
    include_logo_on_reports:    bool       = True
    include_logo_on_receipts:   bool       = True
    receipt_footer_text:        Optional[str] = None
    report_footer_text:         Optional[str] = None


# ================================================================
# MAIN DOCUMENT
# ================================================================

class SystemSetting(Document):
    """
    Global system configuration for ResidEase.

    IMPORTANT:
    - Only ONE document should exist in this collection.
    - Always use SystemSettingService.get_settings() to read.
    - Never insert more than one document.
    - Use SystemSettingService.update_settings() to modify.

    Initialized with safe defaults on first startup.
    All sections are embedded sub-documents for clean
    grouped access: settings.billing.penalty_enabled, etc.
    """

    # ── Sections ──────────────────────────────────────────────
    business:     BusinessInfo        = Field(default_factory=BusinessInfo)
    billing:      BillingSettings     = Field(default_factory=BillingSettings)
    lease:        LeaseSettings       = Field(default_factory=LeaseSettings)
    notification: NotificationSettings = Field(default_factory=NotificationSettings)
    maintenance:  MaintenanceSettings = Field(default_factory=MaintenanceSettings)
    security:     SecuritySettings    = Field(default_factory=SecuritySettings)
    report:       ReportSettings      = Field(default_factory=ReportSettings)

    # ── System Flags ──────────────────────────────────────────
    is_initialized:    bool = False   # True after first-run setup
    maintenance_mode:  bool = False   # True = system is under maintenance
    allow_registration: bool = True   # False = disable new user registration

    # ── Audit ─────────────────────────────────────────────────
    created_at:  datetime       = Field(default_factory=datetime.utcnow)
    updated_at:  datetime       = Field(default_factory=datetime.utcnow)
    updated_by:  Optional[str]  = None   # username of last admin who edited

    # ── Beanie Settings ───────────────────────────────────────
    class Settings:
        name = "system_settings"   # MongoDB collection name

    # ── Computed Properties ───────────────────────────────────

    @property
    def is_in_maintenance_mode(self) -> bool:
        return self.maintenance_mode

    @property
    def is_email_enabled(self) -> bool:
        return (
            self.notification.notifications_enabled
            and self.notification.email_enabled
        )

    @property
    def is_sms_enabled(self) -> bool:
        return (
            self.notification.notifications_enabled
            and self.notification.sms_enabled
        )

    @property
    def currency_display(self) -> str:
        """Returns e.g. 'PHP (₱)'"""
        return (
            f"{self.billing.currency_code.value} "
            f"({self.billing.currency_symbol})"
        )

    @property
    def penalty_description(self) -> str:
        """
        Returns a human-readable penalty description.
        e.g. '₱100.00 per month' or '2.0% of balance'
        """
        if not self.billing.penalty_enabled:
            return "No penalty"
        if self.billing.penalty_type == PenaltyType.FIXED:
            return (
                f"{self.billing.currency_symbol}"
                f"{self.billing.penalty_amount:,.2f} per overdue month"
            )
        return f"{self.billing.penalty_percentage:.1f}% of outstanding balance"

    # ── String Representation ─────────────────────────────────

    def __str__(self) -> str:
        return (
            f"SystemSetting("
            f"business='{self.business.business_name}', "
            f"maintenance_mode={self.maintenance_mode}, "
            f"initialized={self.is_initialized}"
            f")"
        )

    def __repr__(self) -> str:
        return (
            f"<SystemSetting id={self.id} "
            f"updated_by='{self.updated_by}' "
            f"updated_at='{self.updated_at}'>"
        )