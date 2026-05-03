# ============================================================
# dto/response/notification_response.py
# ResidEase – Boarding House Management System
# ============================================================

from pydantic import BaseModel
from typing import Optional
from datetime import datetime

from models.notification import (
    Notification,
    NotificationType,
    NotificationPriority,
    NotificationChannel,
)


class NotificationResponse(BaseModel):
    """
    Full notification shape returned by all notification endpoints.
    """

    # ── Identity ──────────────────────────────────────────────
    id:           str
    recipient_id: str
    sender_id:    Optional[str] = None

    # ── Content ───────────────────────────────────────────────
    notification_type: NotificationType
    priority:          NotificationPriority
    title:             str
    message:           str

    # ── Reference ─────────────────────────────────────────────
    reference_id:   Optional[str] = None
    reference_type: Optional[str] = None

    # ── Channels ──────────────────────────────────────────────
    channels: list[NotificationChannel]

    # ── Read Status ───────────────────────────────────────────
    is_read:  bool
    read_at:  Optional[datetime] = None

    # ── Delivery ──────────────────────────────────────────────
    is_sent:    bool
    sent_at:    Optional[datetime] = None
    send_error: Optional[str]      = None

    # ── Flags ─────────────────────────────────────────────────
    is_unread:            bool
    is_urgent:            bool
    is_high_priority:     bool
    is_system_generated:  bool
    was_delivered:        bool
    is_expired:           bool

    # ── Expiry ────────────────────────────────────────────────
    expires_at: Optional[datetime] = None

    # ── Soft Delete ───────────────────────────────────────────
    is_deleted: bool
    deleted_at: Optional[datetime] = None

    # ── Audit ─────────────────────────────────────────────────
    created_at: datetime
    updated_at: datetime

    # ── Factory Method ────────────────────────────────────────

    @classmethod
    def from_notification(
        cls, notification: Notification
    ) -> "NotificationResponse":
        """
        Constructs a NotificationResponse from a Notification document.
        Called by notification_service.py only.
        """
        return cls(
            id=str(notification.id),
            recipient_id=notification.recipient_id,
            sender_id=notification.sender_id,
            notification_type=notification.notification_type,
            priority=notification.priority,
            title=notification.title,
            message=notification.message,
            reference_id=notification.reference_id,
            reference_type=notification.reference_type,
            channels=notification.channels,
            is_read=notification.is_read,
            read_at=notification.read_at,
            is_sent=notification.is_sent,
            sent_at=notification.sent_at,
            send_error=notification.send_error,

            # computed from @property
            is_unread=notification.is_unread,
            is_urgent=notification.is_urgent,
            is_high_priority=notification.is_high_priority,
            is_system_generated=notification.is_system_generated,
            was_delivered=notification.was_delivered,
            is_expired=notification.is_expired,

            expires_at=notification.expires_at,
            is_deleted=notification.is_deleted,
            deleted_at=notification.deleted_at,
            created_at=notification.created_at,
            updated_at=notification.updated_at,
        )

    model_config = {
        "json_schema_extra": {
            "example": {
                "id":                  "665f1c2e8a4b2c001f3d9d44",
                "recipient_id":        "665f1c2e8a4b2c001f3d9a11",
                "sender_id":           None,
                "notification_type":   "LEASE_EXPIRING_SOON",
                "priority":            "HIGH",
                "title":               "Lease Expiring Soon",
                "message":             "Your lease expires in 7 days on 2025-06-30.",
                "reference_id":        "665f1c2e8a4b2c001f3d9c33",
                "reference_type":      "lease",
                "channels":            ["IN_APP"],
                "is_read":             False,
                "read_at":             None,
                "is_sent":             True,
                "sent_at":             "2024-06-23T08:00:00",
                "send_error":          None,
                "is_unread":           True,
                "is_urgent":           False,
                "is_high_priority":    True,
                "is_system_generated": True,
                "was_delivered":       True,
                "is_expired":          False,
                "expires_at":          None,
                "is_deleted":          False,
                "deleted_at":          None,
                "created_at":          "2024-06-23T08:00:00",
                "updated_at":          "2024-06-23T08:00:00"
            }
        }
    }