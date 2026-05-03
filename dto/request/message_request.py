

from pydantic import BaseModel, Field
from typing import Optional
from datetime import datetime
from models.message import AnnouncementPriority, MessageDirection


class SendMessageRequest(BaseModel):
    """POST /api/messages/send"""
    receiver_id: str
    tenant_id:   str
    body:        str      = Field(..., min_length=1, max_length=2000)
    subject:     Optional[str] = Field(default=None, max_length=200)
    direction:   MessageDirection
    thread_id:   Optional[str] = None   # None = start new thread

    model_config = {
        "json_schema_extra": {
            "example": {
                "receiver_id": "665f1c2e8a4b2c001f3d9a11",
                "tenant_id":   "665f1c2e8a4b2c001f3d9a22",
                "body":        "Hello, I have a question about my lease.",
                "subject":     "Lease inquiry",
                "direction":   "TENANT_TO_MANAGEMENT",
                "thread_id":   None,
            }
        }
    }


class CreateAnnouncementRequest(BaseModel):
    """POST /api/announcements"""
    title:             str               = Field(..., min_length=3, max_length=200)
    body:              str               = Field(..., min_length=1, max_length=5000)
    priority:          AnnouncementPriority = AnnouncementPriority.NORMAL
    target_tenant_ids: list[str]         = Field(default_factory=list)
    expires_at:        Optional[datetime] = None
    publish_now:       bool              = False

    model_config = {
        "json_schema_extra": {
            "example": {
                "title":       "Water interruption notice",
                "body":        "There will be a water interruption on April 20, 8am-12pm.",
                "priority":    "HIGH",
                "target_tenant_ids": [],
                "expires_at":  None,
                "publish_now": True,
            }
        }
    }