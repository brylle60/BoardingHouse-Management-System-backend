

from pydantic import BaseModel
from typing import Optional
from datetime import datetime
from models.message import MessageStatus, MessageDirection, AnnouncementStatus, AnnouncementPriority


class MessageResponse(BaseModel):
    id:          str
    sender_id:   str
    receiver_id: str
    tenant_id:   str
    subject:     Optional[str]
    body:        str
    direction:   MessageDirection
    status:      MessageStatus
    read_at:     Optional[datetime]
    thread_id:   Optional[str]
    created_at:  datetime


class ThreadResponse(BaseModel):
    thread_id: str
    messages:  list[MessageResponse]
    total:     int


class AnnouncementResponse(BaseModel):
    id:                str
    author_id:         str
    title:             str
    body:              str
    priority:          AnnouncementPriority
    status:            AnnouncementStatus
    target_tenant_ids: list[str]
    read_by_count:     int
    published_at:      Optional[datetime]
    expires_at:        Optional[datetime]
    created_at:        datetime


class UnreadCountResponse(BaseModel):
    messages:      int
    notifications: int
    total:         int


# ── Mapper helpers ────────────────────────────────────────────────────────────

def to_message_response(msg) -> MessageResponse:
    return MessageResponse(
        id          = str(msg.id),
        sender_id   = str(msg.sender_id),
        receiver_id = str(msg.receiver_id),
        tenant_id   = str(msg.tenant_id),
        subject     = msg.subject,
        body        = msg.body,
        direction   = msg.direction,
        status      = msg.status,
        read_at     = msg.read_at,
        thread_id   = msg.thread_id,
        created_at  = msg.created_at,
    )


def to_announcement_response(ann) -> AnnouncementResponse:
    return AnnouncementResponse(
        id                = str(ann.id),
        author_id         = str(ann.author_id),
        title             = ann.title,
        body              = ann.body,
        priority          = ann.priority,
        status            = ann.status,
        target_tenant_ids = [str(tid) for tid in ann.target_tenant_ids],
        read_by_count     = len(ann.read_by),
        published_at      = ann.published_at,
        expires_at        = ann.expires_at,
        created_at        = ann.created_at,
    )