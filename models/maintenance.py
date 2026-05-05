

from beanie import Document, PydanticObjectId
from pydantic import Field
from typing import Optional
from datetime import datetime
from enum import Enum


class MaintenanceCategory(str, Enum):
    PLUMBING    = "PLUMBING"
    ELECTRICAL  = "ELECTRICAL"
    CARPENTRY   = "CARPENTRY"
    APPLIANCE   = "APPLIANCE"
    PEST        = "PEST"
    CLEANING    = "CLEANING"
    SECURITY    = "SECURITY"
    OTHER       = "OTHER"


class MaintenancePriority(str, Enum):
    LOW      = "LOW"
    MEDIUM   = "MEDIUM"
    HIGH     = "HIGH"
    URGENT   = "URGENT"


class MaintenanceStatus(str, Enum):
    SUBMITTED   = "SUBMITTED"   # tenant submitted
    ASSIGNED    = "ASSIGNED"    # assigned to staff
    IN_PROGRESS = "IN_PROGRESS" # staff working on it
    COMPLETED   = "COMPLETED"   # work done, awaiting confirmation
    CLOSED      = "CLOSED"      # tenant confirmed, ticket closed
    REJECTED    = "REJECTED"    # not valid / duplicate


class MaintenanceRequest(Document):
    """
    A maintenance request submitted by a tenant.
    Collection: maintenance_requests
    """

    # ── Participants ──────────────────────────────────────────────────────
    tenant_id:      PydanticObjectId            # who submitted
    room_id:        PydanticObjectId            # affected room
    assigned_to:    Optional[PydanticObjectId] = None  # maintenance staff user_id

    # ── Request details ───────────────────────────────────────────────────
    title:          str                         = Field(..., min_length=3, max_length=200)
    description:    str                         = Field(..., min_length=10, max_length=2000)
    category:       MaintenanceCategory         = MaintenanceCategory.OTHER
    priority:       MaintenancePriority         = MaintenancePriority.MEDIUM

    # ── Photos ────────────────────────────────────────────────────────────
    photos:         list[str]                   = Field(default_factory=list)

    # ── Status & resolution ───────────────────────────────────────────────
    status:         MaintenanceStatus           = MaintenanceStatus.SUBMITTED
    resolution:     Optional[str]              = Field(default=None, max_length=1000)
    rejection_reason: Optional[str]            = Field(default=None, max_length=500)

    # ── Timeline ──────────────────────────────────────────────────────────
    assigned_at:    Optional[datetime] = None
    started_at:     Optional[datetime] = None
    completed_at:   Optional[datetime] = None
    closed_at:      Optional[datetime] = None

    # ── Audit ─────────────────────────────────────────────────────────────
    created_at:     datetime = Field(default_factory=datetime.utcnow)
    updated_at:     datetime = Field(default_factory=datetime.utcnow)

    class Settings:
        name = "maintenance_requests"
