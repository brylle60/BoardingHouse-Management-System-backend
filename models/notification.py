# ============================================================
# models/notification.py
# ResidEase – Boarding House Management System
# ============================================================

from beanie import Document
from pydantic import Field
from typing import Optional
from datetime import datetime
from enum import Enum


# ================================================================
# ENUMS
# ================================================================

class NotificationType(str, Enum):
    # ── Lease ─────────────────────────────────────────────────
    LEASE_CREATED       = "LEASE_CREATED"
    LEASE_EXPIRING_SOON = "LEASE_EXPIRING_SOON"
    LEASE_EXPIRED       = "LEASE_EXPIRED"
    LEASE_TERMINATED    = "LEASE_TERMINATED"
    LEASE_RENEWED       = "LEASE_RENEWED"

    # ── Payment ───────────────────────────────────────────────
    PAYMENT_RECEIVED    = "PAYMENT_RECEIVED"
    PAYMENT_OVERDUE     = "PAYMENT_OVERDUE"
    PAYMENT_REMINDER    = "PAYMENT_REMINDER"
    DEPOSIT_RETURNED    = "DEPOSIT_RETURNED"

    # ── Maintenance ───────────────────────────────────────────
    MAINTENANCE_SUBMITTED  = "MAINTENANCE_SUBMITTED"
    MAINTENANCE_ASSIGNED   = "MAINTENANCE_ASSIGNED"
    MAINTENANCE_COMPLETED  = "MAINTENANCE_COMPLETED"
    MAINTENANCE_CANCELLED  = "MAINTENANCE_CANCELLED"

    # ── Room ──────────────────────────────────────────────────
    ROOM_ASSIGNED       = "ROOM_ASSIGNED"
    ROOM_VACATED        = "ROOM_VACATED"
    ROOM_MAINTENANCE    = "ROOM_MAINTENANCE"

    # ── User / Account ────────────────────────────────────────
    ACCOUNT_CREATED     = "ACCOUNT_CREATED"
    ACCOUNT_SUSPENDED   = "ACCOUNT_SUSPENDED"
    PASSWORD_CHANGED    = "PASSWORD_CHANGED"
    ROLE_CHANGED        = "ROLE_CHANGED"

    # ── Announcements ─────────────────────────────────────────
    ANNOUNCEMENT        = "ANNOUNCEMENT"
    SYSTEM_ALERT        = "SYSTEM_ALERT"


class NotificationPriority(str, Enum):
    LOW      = "LOW"       # informational, no action needed
    NORMAL   = "NORMAL"    # standard notification
    HIGH     = "HIGH"      # requires attention
    URGENT   = "URGENT"    # immediate action required


class NotificationChannel(str, Enum):
    IN_APP   = "IN_APP"    # shown in the app notification bell
    EMAIL    = "EMAIL"     # sent via email
    SMS      = "SMS"       # sent via SMS
    PUSH     = "PUSH"      # mobile push notification


# ================================================================
# MAIN DOCUMENT
# ================================================================

class Notification(Document):
    """
    Represents a single notification sent to a user.

    Relationships:
    - recipient_id  → User who receives the notification
    - sender_id     → User or system that triggered it
    - reference_id  → Optional ObjectId of the related document
                      (lease_id, payment_id, room_id, etc.)

    Lifecycle:
    - Created by NotificationService (never manually)
    - Read status tracked by is_read + read_at
    - Soft deleted via is_deleted flag (never hard deleted)
    """

    # ── Recipients ────────────────────────────────────────────
    # recipient_id stores the User ObjectId as string
    recipient_id: str = Field(
        ...,
        description="ObjectId string of the User receiving the notification."
    )

    # sender_id is None for system-generated notifications
    sender_id: Optional[str] = Field(
        default=None,
        description="ObjectId string of the User who triggered the notification. "
                    "None for system/scheduler-generated notifications."
    )

    # ── Notification Content ──────────────────────────────────
    notification_type: NotificationType
    priority:          NotificationPriority = NotificationPriority.NORMAL
    title:             str   = Field(..., max_length=150)
    message:           str   = Field(..., max_length=1000)

    # ── Reference ─────────────────────────────────────────────
    # Links the notification to the document that triggered it.
    # e.g. lease_id for LEASE_EXPIRING_SOON,
    #      payment_id for PAYMENT_RECEIVED
    reference_id:   Optional[str] = None   # ObjectId of related document
    reference_type: Optional[str] = None   # e.g. "lease", "payment", "room"

    # ── Delivery Channels ─────────────────────────────────────
    # Tracks which channels this notification was sent through
    channels: list[NotificationChannel] = Field(
        default_factory=lambda: [NotificationChannel.IN_APP]
    )

    # ── Read Status ───────────────────────────────────────────
    is_read: bool               = False
    read_at: Optional[datetime] = None

    # ── Delivery Status ───────────────────────────────────────
    is_sent:    bool               = False
    sent_at:    Optional[datetime] = None
    send_error: Optional[str]      = None   # error message if delivery failed

    # ── Soft Delete ───────────────────────────────────────────
    # Notifications are never hard deleted — soft delete only
    is_deleted:  bool               = False
    deleted_at:  Optional[datetime] = None

    # ── Expiry ────────────────────────────────────────────────
    # Optional expiry — notification auto-hides after this date
    expires_at: Optional[datetime] = None

    # ── Audit ─────────────────────────────────────────────────
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)

    # ── Beanie Settings ───────────────────────────────────────
    class Settings:
        name = "notifications"
        indexes = [
            [("recipient_id", 1)],                          # all notifications for a user
            [("recipient_id", 1), ("is_read",    1)],       # unread notifications
            [("recipient_id", 1), ("is_deleted", 1)],       # non-deleted notifications
            [("notification_type", 1)],                     # filter by type
            [("priority",          1)],                     # filter by priority
            [("created_at",        -1)],                    # latest first
            [("reference_id",      1), ("reference_type", 1)],  # find by related doc
            [("expires_at",        1)],                     # for expiry cleanup job
        ]

    # ── Computed Properties ───────────────────────────────────

    @property
    def is_unread(self) -> bool:
        return not self.is_read

    @property
    def is_expired(self) -> bool:
        if not self.expires_at:
            return False
        return datetime.utcnow() > self.expires_at

    @property
    def is_urgent(self) -> bool:
        return self.priority == NotificationPriority.URGENT

    @property
    def is_high_priority(self) -> bool:
        return self.priority in (
            NotificationPriority.HIGH,
            NotificationPriority.URGENT,
        )

    @property
    def is_system_generated(self) -> bool:
        """True if sent by the scheduler or system, not a human user."""
        return self.sender_id is None

    @property
    def was_delivered(self) -> bool:
        """True if notification was successfully sent."""
        return self.is_sent and self.send_error is None

    # ── String Representation ─────────────────────────────────

    def __str__(self) -> str:
        return (
            f"Notification("
            f"type={self.notification_type.value}, "
            f"recipient={self.recipient_id}, "
            f"priority={self.priority.value}, "
            f"read={self.is_read}"
            f")"
        )

    def __repr__(self) -> str:
        return (
            f"<Notification id={self.id} "
            f"type='{self.notification_type.value}' "
            f"recipient='{self.recipient_id}' "
            f"read={self.is_read}>"
        )