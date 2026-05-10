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
    room_id:     str = Field(..., description="Room._id the tenant wants")
    room_number: Optional[str] = None
    monthly_rent: Optional[float] = None

    # Desired move-in
    desired_move_in_date: Optional[date] = None

    # Personal details (used to populate Tenant profile on approval)
    last_name:        Optional[str]   = None
    date_of_birth:    Optional[date]  = None
    gender:           Optional[str]   = None
    civil_status:     Optional[str]   = None
    nationality:      Optional[str]   = "Filipino"
    occupation:       Optional[str]   = None
    employer:         Optional[str]   = None
    monthly_income:   Optional[float] = None

    # Emergency contact
    emergency_contact_name:         Optional[str] = None
    emergency_contact_phone:        Optional[str] = None
    emergency_contact_relationship: Optional[str] = None

    # Additional info
    message:     Optional[str] = Field(default=None, max_length=1000)
    id_document: Optional[str] = None   # URL / file path of uploaded ID

    # Review state
    status:        BookingStatus = BookingStatus.PENDING
    reviewed_by:   Optional[str] = None   # User._id of manager/admin
    reviewed_at:   Optional[datetime] = None
    review_notes:  Optional[str] = None

    # Audit
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)

    class Settings:
        name = "booking_requests"
        indexes = [
            [("user_id", 1)],
            [("room_id", 1)],
            [("status", 1)],
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
