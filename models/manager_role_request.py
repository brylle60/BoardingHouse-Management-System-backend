from beanie import Document, Indexed
from pydantic import Field, EmailStr
from typing import Optional
from datetime import datetime
from enum import Enum


class ManagerRequestStatus(str, Enum):
    PENDING  = "PENDING"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"


class ManagerRoleRequest(Document):
    """
    Stores a tenant's application to become a Property Manager.
    Admin reviews and approves or rejects.
    """

    # Link to the applicant (User)
    user_id: str = Field(..., description="User._id of the applicant")

    # Property details
    property_name: str              = Field(..., min_length=2, max_length=200)
    location:      str              = Field(..., min_length=2, max_length=200)
    address:       str              = Field(..., min_length=5, max_length=500)
    room_count:    int              = Field(..., ge=1, le=1000)
    description:   Optional[str]    = Field(default=None, max_length=2000)

    # Documents (file paths / URLs uploaded by applicant)
    documents: list[str] = Field(default_factory=list)

    # Review state
    status:        ManagerRequestStatus = ManagerRequestStatus.PENDING
    reviewed_by:   Optional[str]        = None   # User._id of admin
    reviewed_at:   Optional[datetime]   = None
    review_notes:  Optional[str]        = None

    # Audit
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)

    class Settings:
        name = "manager_role_requests"
        indexes = [
            [("user_id", 1)],
            [("status", 1)],
        ]

    @property
    def is_pending(self) -> bool:
        return self.status == ManagerRequestStatus.PENDING

    @property
    def is_approved(self) -> bool:
        return self.status == ManagerRequestStatus.APPROVED

    @property
    def is_rejected(self) -> bool:
        return self.status == ManagerRequestStatus.REJECTED

    def __str__(self) -> str:
        return (
            f"ManagerRoleRequest("
            f"user={self.user_id}, "
            f"property={self.property_name}, "
            f"status={self.status.value}"
            f")"
        )
