

from beanie import Document, Indexed, PydanticObjectId
from pydantic import Field
from typing import Optional
from datetime import datetime
from enum import Enum


# ── Enums ─────────────────────────────────────────────────────────────────────

class MessageStatus(str, Enum):
    UNREAD = "UNREAD"
    READ   = "READ"

class MessageDirection(str, Enum):
    TENANT_TO_MANAGEMENT = "TENANT_TO_MANAGEMENT"
    MANAGEMENT_TO_TENANT = "MANAGEMENT_TO_TENANT"

class AnnouncementPriority(str, Enum):
    LOW    = "LOW"
    NORMAL = "NORMAL"
    HIGH   = "HIGH"
    URGENT = "URGENT"

class AnnouncementStatus(str, Enum):
    DRAFT     = "DRAFT"
    PUBLISHED = "PUBLISHED"
    ARCHIVED  = "ARCHIVED"


# ── Message Document ──────────────────────────────────────────────────────────

class Message(Document):
    """
    Direct message between a tenant and management.
    Stored as a thread — each document is one message in the conversation.

    Collection: messages
    """

    # ── Participants ──────────────────────────────────────────────────────
    sender_id:    PydanticObjectId          # User._id of the sender
    receiver_id:  PydanticObjectId          # User._id of the receiver
    tenant_id:    PydanticObjectId          # Tenant._id (always the tenant side)

    # ── Content ───────────────────────────────────────────────────────────
    subject:    Optional[str] = Field(default=None, max_length=200)
    body:       str           = Field(..., min_length=1, max_length=2000)
    direction:  MessageDirection

    # ── State ─────────────────────────────────────────────────────────────
    status:     MessageStatus = MessageStatus.UNREAD
    read_at:    Optional[datetime] = None

    # ── Thread grouping ───────────────────────────────────────────────────
    # All messages in the same conversation share a thread_id
    thread_id:  Optional[str] = None

    # ── Audit ─────────────────────────────────────────────────────────────
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)

    class Settings:
        name = "messages"


# ── Announcement Document ─────────────────────────────────────────────────────

class Announcement(Document):
    """
    Broadcast message from management to all tenants or a specific group.
    Equivalent to a noticeboard post.

    Collection: announcements
    """

    # ── Author ────────────────────────────────────────────────────────────
    author_id:   PydanticObjectId          # User._id of the manager/admin who posted

    # ── Content ───────────────────────────────────────────────────────────
    title:       str            = Field(..., min_length=3, max_length=200)
    body:        str            = Field(..., min_length=1, max_length=5000)
    priority:    AnnouncementPriority = AnnouncementPriority.NORMAL

    # ── Targeting ─────────────────────────────────────────────────────────
    # None = broadcast to all tenants
    # Populated = only specific tenants see it
    target_tenant_ids: list[PydanticObjectId] = Field(default_factory=list)

    # ── State ─────────────────────────────────────────────────────────────
    status:       AnnouncementStatus = AnnouncementStatus.DRAFT
    published_at: Optional[datetime] = None
    expires_at:   Optional[datetime] = None   # auto-archive after this date

    # ── Read tracking ─────────────────────────────────────────────────────
    read_by: list[PydanticObjectId] = Field(default_factory=list)

    # ── Audit ─────────────────────────────────────────────────────────────
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)

    class Settings:
        name = "announcements"