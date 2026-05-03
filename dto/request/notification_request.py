# ============================================================
# dto/request/notification_request.py
# ResidEase – Boarding House Management System
# ============================================================

from pydantic import BaseModel, Field, field_validator
from typing import Optional
from datetime import datetime

from models.notification import (
    NotificationType,
    NotificationPriority,
    NotificationChannel,
)


class NotificationCreateRequest(BaseModel):
    """
    Payload for POST /api/notifications/send
    Used by admin/manager to manually send a notification.
    """
    recipient_id:       str                          = Field(..., min_length=24, max_length=24)
    notification_type:  NotificationType
    title:              str                          = Field(..., min_length=1, max_length=150)
    message:            str                          = Field(..., min_length=1, max_length=1000)
    priority:           NotificationPriority         = NotificationPriority.NORMAL
    reference_id:       Optional[str]                = None
    reference_type:     Optional[str]                = None
    channels:           list[NotificationChannel]    = Field(
                            default_factory=lambda: [NotificationChannel.IN_APP]
                        )
    expires_at:         Optional[datetime]           = None
    skip_duplicate_check: bool                       = False

    @field_validator("title", "message")
    @classmethod
    def strip_strings(cls, v: str) -> str:
        return v.strip()

    @field_validator("reference_type")
    @classmethod
    def strip_reference_type(cls, v: Optional[str]) -> Optional[str]:
        return v.strip().lower() if v else None

    model_config = {
        "json_schema_extra": {
            "example": {
                "recipient_id":       "665f1c2e8a4b2c001f3d9a11",
                "notification_type":  "ANNOUNCEMENT",
                "title":              "Water Interruption Notice",
                "message":            "There will be no water supply on July 5 from 8AM to 5PM.",
                "priority":           "HIGH",
                "channels":           ["IN_APP"],
                "expires_at":         None,
                "skip_duplicate_check": False
            }
        }
    }


class NotificationBroadcastRequest(BaseModel):
    """
    Payload for POST /api/notifications/broadcast
    Sends the same notification to multiple recipients.
    """
    recipient_ids:   list[str] = Field(..., min_length=1)
    title:           str       = Field(..., min_length=1, max_length=150)
    message:         str       = Field(..., min_length=1, max_length=1000)
    expires_in_days: Optional[int] = Field(default=7, ge=1, le=365)

    @field_validator("title", "message")
    @classmethod
    def strip_strings(cls, v: str) -> str:
        return v.strip()

    @field_validator("recipient_ids")
    @classmethod
    def validate_recipient_ids(cls, v: list[str]) -> list[str]:
        for rid in v:
            if len(rid) != 24:
                raise ValueError(
                    f"Invalid recipient_id: '{rid}'. "
                    "Must be a 24-character MongoDB ObjectId."
                )
        # remove duplicates while preserving order
        seen = set()
        return [x for x in v if not (x in seen or seen.add(x))]

    model_config = {
        "json_schema_extra": {
            "example": {
                "recipient_ids": [
                    "665f1c2e8a4b2c001f3d9a11",
                    "665f1c2e8a4b2c001f3d9a22",
                ],
                "title":           "Water Interruption Notice",
                "message":         "No water supply on July 5 from 8AM–5PM.",
                "expires_in_days": 7
            }
        }
    }