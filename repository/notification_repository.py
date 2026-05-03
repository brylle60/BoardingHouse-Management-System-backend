# ============================================================
# repository/notification_repository.py
# ResidEase – Boarding House Management System
# ============================================================

from beanie import PydanticObjectId
from beanie.operators import Set
from typing import Optional
from datetime import datetime

from models.notification import (
    Notification,
    NotificationType,
    NotificationPriority,
    NotificationChannel,
)


# ================================================================
# READ
# ================================================================

async def get_all_notifications(
    skip: int = 0,
    limit: int = 20,
) -> list[Notification]:
    """
    Returns a paginated list of all notifications.
    Excludes soft-deleted notifications.
    """
    return await Notification.find(
        Notification.is_deleted == False                                 # noqa: E712
    ).sort(-Notification.created_at).skip(skip).limit(limit).to_list()


async def get_notification_by_id(
    notification_id: PydanticObjectId,
) -> Optional[Notification]:
    """
    Returns a single notification by MongoDB ObjectId.
    Returns None if not found or soft-deleted.
    """
    return await Notification.find_one(
        Notification.id         == notification_id,
        Notification.is_deleted == False,                               # noqa: E712
    )


async def get_notifications_by_recipient(
    recipient_id: str,
    skip: int = 0,
    limit: int = 20,
) -> list[Notification]:
    """
    Returns all non-deleted notifications for a specific user.
    Sorted by latest first.
    """
    return await Notification.find(
        Notification.recipient_id == recipient_id,
        Notification.is_deleted   == False,                             # noqa: E712
    ).sort(-Notification.created_at).skip(skip).limit(limit).to_list()


async def get_unread_notifications(
    recipient_id: str,
    skip: int = 0,
    limit: int = 20,
) -> list[Notification]:
    """
    Returns all unread notifications for a specific user.
    Used by the notification bell badge count.
    """
    return await Notification.find(
        Notification.recipient_id == recipient_id,
        Notification.is_read      == False,                             # noqa: E712
        Notification.is_deleted   == False,                             # noqa: E712
    ).sort(-Notification.created_at).skip(skip).limit(limit).to_list()


async def get_notifications_by_type(
    recipient_id: str,
    notification_type: NotificationType,
    skip: int = 0,
    limit: int = 20,
) -> list[Notification]:
    """
    Returns notifications filtered by type for a specific user.
    e.g. get all PAYMENT_REMINDER notifications for a tenant.
    """
    return await Notification.find(
        Notification.recipient_id      == recipient_id,
        Notification.notification_type == notification_type,
        Notification.is_deleted        == False,                        # noqa: E712
    ).sort(-Notification.created_at).skip(skip).limit(limit).to_list()


async def get_notifications_by_priority(
    recipient_id: str,
    priority: NotificationPriority,
    skip: int = 0,
    limit: int = 20,
) -> list[Notification]:
    """
    Returns notifications filtered by priority for a specific user.
    e.g. get all URGENT notifications.
    """
    return await Notification.find(
        Notification.recipient_id == recipient_id,
        Notification.priority     == priority,
        Notification.is_deleted   == False,                             # noqa: E712
    ).sort(-Notification.created_at).skip(skip).limit(limit).to_list()


async def get_notifications_by_reference(
    reference_id: str,
    reference_type: str,
) -> list[Notification]:
    """
    Returns all notifications linked to a specific document.
    e.g. all notifications for a specific lease or payment.

    Example:
        await get_notifications_by_reference(
            reference_id="665f1c2e...",
            reference_type="lease"
        )
    """
    return await Notification.find(
        Notification.reference_id   == reference_id,
        Notification.reference_type == reference_type,
        Notification.is_deleted     == False,                           # noqa: E712
    ).sort(-Notification.created_at).to_list()


async def get_urgent_notifications(
    recipient_id: str,
) -> list[Notification]:
    """
    Returns all unread URGENT notifications for a user.
    Used by the dashboard alert banner.
    """
    return await Notification.find(
        Notification.recipient_id == recipient_id,
        Notification.priority     == NotificationPriority.URGENT,
        Notification.is_read      == False,                             # noqa: E712
        Notification.is_deleted   == False,                             # noqa: E712
    ).sort(-Notification.created_at).to_list()


async def get_expired_notifications() -> list[Notification]:
    """
    Returns all notifications whose expires_at has passed
    and have not yet been soft-deleted.
    Used by the cleanup scheduler job.
    """
    now = datetime.utcnow()
    return await Notification.find(
        Notification.expires_at  != None,                               # noqa: E711
        Notification.expires_at  <= now,
        Notification.is_deleted  == False,                              # noqa: E712
    ).to_list()


async def count_unread(recipient_id: str) -> int:
    """
    Returns the count of unread notifications for a user.
    Used by the notification bell badge in the topbar.
    """
    return await Notification.find(
        Notification.recipient_id == recipient_id,
        Notification.is_read      == False,                             # noqa: E712
        Notification.is_deleted   == False,                             # noqa: E712
    ).count()


async def count_all_notifications(recipient_id: str) -> int:
    """
    Returns total count of non-deleted notifications for a user.
    """
    return await Notification.find(
        Notification.recipient_id == recipient_id,
        Notification.is_deleted   == False,                             # noqa: E712
    ).count()


async def count_by_type(
    notification_type: NotificationType,
) -> int:
    """
    Returns count of notifications by type across all users.
    Used by admin analytics.
    """
    return await Notification.find(
        Notification.notification_type == notification_type,
        Notification.is_deleted        == False,                        # noqa: E712
    ).count()


async def exists_unread_by_reference(
    recipient_id: str,
    reference_id: str,
    reference_type: str,
) -> bool:
    """
    Returns True if an unread notification already exists
    for this recipient and reference document.
    Used to prevent duplicate notifications.
    """
    existing = await Notification.find_one(
        Notification.recipient_id   == recipient_id,
        Notification.reference_id   == reference_id,
        Notification.reference_type == reference_type,
        Notification.is_read        == False,                           # noqa: E712
        Notification.is_deleted     == False,                           # noqa: E712
    )
    return existing is not None


# ================================================================
# WRITE
# ================================================================

async def create_notification(
    notification: Notification,
) -> Notification:
    """
    Inserts a new Notification document.
    Always called by NotificationService — never directly.

    Example:
        notification = Notification(
            recipient_id="665f...",
            notification_type=NotificationType.LEASE_EXPIRING_SOON,
            title="Lease Expiring Soon",
            message="Your lease expires in 30 days.",
        )
        created = await create_notification(notification)
    """
    return await notification.insert()


async def create_bulk_notifications(
    notifications: list[Notification],
) -> list[Notification]:
    """
    Inserts multiple notifications in a single operation.
    Used for announcements sent to all tenants at once.
    Returns the list of created notifications.
    """
    created = []
    for notification in notifications:
        inserted = await notification.insert()
        created.append(inserted)
    return created


async def mark_as_read(
    notification_id: PydanticObjectId,
) -> Optional[Notification]:
    """
    Marks a single notification as read.
    Records the read_at timestamp.
    """
    notification = await Notification.get(notification_id)
    if not notification:
        return None

    await notification.update(Set({
        "is_read":   True,
        "read_at":   datetime.utcnow(),
        "updated_at": datetime.utcnow(),
    }))
    return await Notification.get(notification_id)


async def mark_all_as_read(recipient_id: str) -> int:
    """
    Marks all unread notifications as read for a specific user.
    Returns the count of notifications marked as read.
    Used by the 'Mark all as read' button in the notification panel.
    """
    unread = await Notification.find(
        Notification.recipient_id == recipient_id,
        Notification.is_read      == False,                             # noqa: E712
        Notification.is_deleted   == False,                             # noqa: E712
    ).to_list()

    now = datetime.utcnow()
    count = 0
    for notification in unread:
        await notification.update(Set({
            "is_read":    True,
            "read_at":    now,
            "updated_at": now,
        }))
        count += 1

    return count


async def mark_as_sent(
    notification_id: PydanticObjectId,
    channel: NotificationChannel,
) -> Optional[Notification]:
    """
    Marks a notification as successfully sent via the given channel.
    Called by email/SMS delivery services after successful send.
    """
    notification = await Notification.get(notification_id)
    if not notification:
        return None

    channels = notification.channels
    if channel not in channels:
        channels.append(channel)

    await notification.update(Set({
        "is_sent":    True,
        "sent_at":    datetime.utcnow(),
        "send_error": None,
        "channels":   channels,
        "updated_at": datetime.utcnow(),
    }))
    return await Notification.get(notification_id)


async def mark_send_failed(
    notification_id: PydanticObjectId,
    error_message: str,
) -> Optional[Notification]:
    """
    Records a failed delivery attempt with the error message.
    Called by email/SMS delivery services on failure.
    """
    notification = await Notification.get(notification_id)
    if not notification:
        return None

    await notification.update(Set({
        "is_sent":    False,
        "send_error": error_message,
        "updated_at": datetime.utcnow(),
    }))
    return await Notification.get(notification_id)


async def soft_delete_notification(
    notification_id: PydanticObjectId,
) -> bool:
    """
    Soft deletes a single notification by setting is_deleted=True.
    Notifications are NEVER hard deleted.
    Returns True if deleted, False if not found.
    """
    notification = await Notification.get(notification_id)
    if not notification:
        return False

    await notification.update(Set({
        "is_deleted":  True,
        "deleted_at":  datetime.utcnow(),
        "updated_at":  datetime.utcnow(),
    }))
    return True


async def soft_delete_all_for_recipient(
    recipient_id: str,
) -> int:
    """
    Soft deletes all notifications for a specific user.
    Used by the 'Clear all' button in the notification panel.
    Returns the count of notifications deleted.
    """
    notifications = await Notification.find(
        Notification.recipient_id == recipient_id,
        Notification.is_deleted   == False,                             # noqa: E712
    ).to_list()

    now = datetime.utcnow()
    count = 0
    for notification in notifications:
        await notification.update(Set({
            "is_deleted":  True,
            "deleted_at":  now,
            "updated_at":  now,
        }))
        count += 1

    return count


async def soft_delete_expired_notifications() -> int:
    """
    Soft deletes all notifications whose expires_at has passed.
    Called by the cleanup scheduler job.
    Returns the count of notifications cleaned up.
    """
    expired = await get_expired_notifications()

    now = datetime.utcnow()
    count = 0
    for notification in expired:
        await notification.update(Set({
            "is_deleted":  True,
            "deleted_at":  now,
            "updated_at":  now,
        }))
        count += 1

    return count


async def update_notification(
    notification_id: PydanticObjectId,
    updates: dict,
) -> Optional[Notification]:
    """
    Generic update for a notification document.
    Used internally — prefer specific methods above.
    Always stamps updated_at.
    """
    notification = await Notification.get(notification_id)
    if not notification:
        return None

    updates["updated_at"] = datetime.utcnow()
    await notification.update(Set(updates))
    return await Notification.get(notification_id)