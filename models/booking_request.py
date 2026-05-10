from beanie import Document, Indexed
from pydantic import Field, EmailStr
from typing import Optional
from datetime import datetime, date
from enum import Enum


class BookingStatus(str, Enum):
    PENDING   = "PENDING"
    APPROVED  = "APPROVED"
    REJECTED  = "REJECTED"
    CANCELLED = "CANCELLED"


class BookingRequest(Document):
    """
    Stores a tenant's application to book / move into a specific room.
    Manager reviews and approves or rejects.
    Once APPROVED, the document is migrated to the `tenant_bookings` collection
    (AcceptedBookingRequest) and removed from here.
    """

    # Applicant
    user_id:     str = Field(..., description="User._id of the applicant")
    full_name:   str = Field(..., min_length=2, max_length=200)
    email:       str = Field(..., min_length=3, max_length=200)
    phone:       str = Field(..., min_length=5, max_length=50)

    # Address info
    address:     str = Field(..., min_length=5, max_length=500)
    city:        Optional[str] = Field(default=None, max_length=100)
    province:    Optional[str] = Field(default=None, max_length=100)

    # Target room
    room_id:      str            = Field(..., description="Room._id the tenant wants")
    room_number:  Optional[str]  = None
    monthly_rent: Optional[float] = None

    # Desired move-in
    desired_move_in_date: Optional[date] = None

    # Personal details (used to populate Tenant profile on approval)
    last_name:      Optional[str]   = None
    date_of_birth:  Optional[date]  = None
    gender:         Optional[str]   = None
    civil_status:   Optional[str]   = None
    nationality:    Optional[str]   = "Filipino"
    occupation:     Optional[str]   = None
    employer:       Optional[str]   = None
    monthly_income: Optional[float] = None

    # Emergency contact
    emergency_contact_name:         Optional[str] = None
    emergency_contact_phone:        Optional[str] = None
    emergency_contact_relationship: Optional[str] = None

    # Additional info
    message:     Optional[str] = Field(default=None, max_length=1000)
    id_document: Optional[str] = None   # URL / file path of uploaded ID

    # Review state
    status:       BookingStatus   = BookingStatus.PENDING
    reviewed_by:  Optional[str]   = None   # User._id of manager/admin
    reviewed_at:  Optional[datetime] = None
    review_notes: Optional[str]   = None

    # Audit
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)

    class Settings:
        name = "booking_requests"
        indexes = [
            [("user_id", 1)],
            [("room_id", 1)],
            [("status", 1)],
            # Prevent duplicate pending bookings for the same room by the same user
            [("user_id", 1), ("room_id", 1), ("status", 1)],
            # Speed up manager dashboard queries (filter by status, sorted by date)
            [("status", 1), ("created_at", -1)],
        ]

    @property
    def is_pending(self) -> bool:
        return self.status == BookingStatus.PENDING

    @property
    def is_approved(self) -> bool:
        return self.status == BookingStatus.APPROVED

    @property
    def is_rejected(self) -> bool:
        return self.status == BookingStatus.REJECTED

    def __str__(self) -> str:
        return (
            f"BookingRequest("
            f"user={self.user_id}, "
            f"room={self.room_id}, "
            f"status={self.status.value}"
            f")"
        )


class AcceptedBookingRequest(Document):
    """
    Archive of approved booking requests.
    Written to the `tenant_bookings` MongoDB collection when a manager
    approves a BookingRequest; the original BookingRequest is then deleted
    from `booking_requests`.

    Mirrors all fields of BookingRequest and adds the IDs of the Tenant and
    Lease records that were created at approval time.
    """

    # Original booking reference
    original_booking_id: str = Field(..., description="BookingRequest._id that was approved")

    # Applicant
    user_id:     str = Field(..., description="User._id of the applicant")
    full_name:   str
    email:       str
    phone:       str

    # Address info
    address:  str
    city:     Optional[str] = None
    province: Optional[str] = None

    # Target room
    room_id:      str
    room_number:  Optional[str]  = None
    monthly_rent: Optional[float] = None

    # Desired move-in
    desired_move_in_date: Optional[date] = None

    # Personal details
    last_name:      Optional[str]   = None
    date_of_birth:  Optional[date]  = None
    gender:         Optional[str]   = None
    civil_status:   Optional[str]   = None
    nationality:    Optional[str]   = "Filipino"
    occupation:     Optional[str]   = None
    employer:       Optional[str]   = None
    monthly_income: Optional[float] = None

    # Emergency contact
    emergency_contact_name:         Optional[str] = None
    emergency_contact_phone:        Optional[str] = None
    emergency_contact_relationship: Optional[str] = None

    # Additional info
    message:     Optional[str] = None
    id_document: Optional[str] = None

    # Approval details
    reviewed_by:  str               # User._id of approving manager/admin
    reviewed_at:  datetime
    review_notes: Optional[str] = None

    # Created records on approval
    tenant_id: Optional[str] = None  # Tenant._id created / found
    lease_id:  Optional[str] = None  # Lease._id created

    # Audit (carries over original timestamps)
    original_created_at: datetime
    accepted_at: datetime = Field(default_factory=datetime.utcnow)

    class Settings:
        name = "tenant_bookings"
        indexes = [
            [("user_id", 1)],
            [("room_id", 1)],
            [("tenant_id", 1)],
            [("lease_id", 1)],
            # One accepted booking per user per room (unique constraint)
            [("user_id", 1), ("room_id", 1)],
            # Fast lookup by approval date
            [("accepted_at", -1)],
        ]

    def __str__(self) -> str:
        return (
            f"AcceptedBookingRequest("
            f"user={self.user_id}, "
            f"room={self.room_id}, "
            f"tenant={self.tenant_id}"
            f")"
        )