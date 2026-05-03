
from beanie import PydanticObjectId
from models.message import Message, Announcement, MessageStatus, AnnouncementStatus
from datetime import datetime


# ============================================================================
# MESSAGE QUERIES
# ============================================================================

async def find_messages_for_tenant(tenant_id: str) -> list[Message]:
    """All messages in a tenant's inbox — both sent and received."""
    oid = PydanticObjectId(tenant_id)
    return await Message.find(Message.tenant_id == oid).sort("-created_at").to_list()


async def find_thread(thread_id: str) -> list[Message]:
    """All messages in a conversation thread, ordered oldest first."""
    return await Message.find(
        Message.thread_id == thread_id
    ).sort("created_at").to_list()


async def find_unread_for_user(user_id: str) -> list[Message]:
    """Unread messages received by a specific user."""
    oid = PydanticObjectId(user_id)
    return await Message.find(
        Message.receiver_id == oid,
        Message.status == MessageStatus.UNREAD,
    ).sort("-created_at").to_list()


async def count_unread_for_user(user_id: str) -> int:
    """Count of unread messages — used for notification badge."""
    oid = PydanticObjectId(user_id)
    return await Message.find(
        Message.receiver_id == oid,
        Message.status == MessageStatus.UNREAD,
    ).count()


async def save_message(message: Message) -> Message:
    """Create or update a message document."""
    await message.save()
    return message


async def mark_message_read(message: Message) -> Message:
    """Mark a single message as read."""
    message.status = MessageStatus.READ
    message.read_at = datetime.utcnow()
    await message.save()
    return message


async def mark_thread_read(thread_id: str, user_id: str) -> int:
    """Mark all messages in a thread as read for a specific user. Returns count updated."""
    oid = PydanticObjectId(user_id)
    messages = await Message.find(
        Message.thread_id == thread_id,
        Message.receiver_id == oid,
        Message.status == MessageStatus.UNREAD,
    ).to_list()

    for msg in messages:
        msg.status = MessageStatus.READ
        msg.read_at = datetime.utcnow()
        await msg.save()

    return len(messages)


async def delete_message(message: Message) -> None:
    """Delete a message document."""
    await message.delete()


# ============================================================================
# ANNOUNCEMENT QUERIES
# ============================================================================

async def find_all_announcements() -> list[Announcement]:
    """All announcements — for admin/manager view."""
    return await Announcement.find_all().sort("-created_at").to_list()


async def find_published_announcements() -> list[Announcement]:
    """Published announcements visible to tenants."""
    return await Announcement.find(
        Announcement.status == AnnouncementStatus.PUBLISHED
    ).sort("-created_at").to_list()


async def find_announcements_for_tenant(tenant_id: str) -> list[Announcement]:
    """
    Announcements relevant to a specific tenant.
    Includes global announcements (empty target list) and
    announcements targeted at this specific tenant.
    """
    oid = PydanticObjectId(tenant_id)
    all_published = await find_published_announcements()

    return [
        a for a in all_published
        if len(a.target_tenant_ids) == 0       # global broadcast
        or oid in a.target_tenant_ids           # targeted at this tenant
    ]


async def find_announcement_by_id(announcement_id: str) -> Announcement | None:
    """Find a single announcement by ID."""
    try:
        return await Announcement.get(PydanticObjectId(announcement_id))
    except Exception:
        return None


async def save_announcement(announcement: Announcement) -> Announcement:
    """Create or update an announcement."""
    await announcement.save()
    return announcement


async def mark_announcement_read(announcement: Announcement, tenant_id: str) -> Announcement:
    """Track that a specific tenant has read an announcement."""
    oid = PydanticObjectId(tenant_id)
    if oid not in announcement.read_by:
        announcement.read_by.append(oid)
        await announcement.save()
    return announcement


async def delete_announcement(announcement: Announcement) -> None:
    """Delete an announcement."""
    await announcement.delete()