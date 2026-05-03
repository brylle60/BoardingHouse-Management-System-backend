# ============================================================
# services/notification_service.py
# ResidEase – Boarding House Management System
# ============================================================

from beanie import PydanticObjectId
from datetime import datetime, timedelta
from typing import Optional

from models.notification import (
    Notification,
    NotificationType,
    NotificationPriority,
    NotificationChannel,
)
from repository import notification_repository
from dto.request.notification_request import (
    NotificationCreateRequest,
    NotificationBroadcastRequest,
)
from dto.response.notification_response import NotificationResponse
from exception.resource_not_found_exception import ResourceNotFoundException
from exception.bad_request_exception import BadRequestException


# ================================================================
# INTERNAL HELPERS
# ================================================================

async def _assert_notification_exists(
    notification_id: PydanticObjectId,
) -> Notification:
    """Fetches a notification or raises 404."""
    notification = await notification_repository.get_notification_by_id(
        notification_id
    )
    if not notification:
        raise ResourceNotFoundException(
            f"Notification not found: {notification_id}"
        )
    return notification


async def _assert_belongs_to_recipient(
    notification: Notification,
    recipient_id: str,
) -> None:
    """
    Raises 400 if the notification does not belong to the recipient.
    Prevents tenants from reading or deleting other users' notifications.
    """
    if notification.recipient_id != recipient_id:
        raise BadRequestException(
            "You do not have permission to access this notification."
        )


def _build_notification(
    recipient_id:      str,
    notification_type: NotificationType,
    title:             str,
    message:           str,
    priority:          NotificationPriority   = NotificationPriority.NORMAL,
    sender_id:         Optional[str]          = None,
    reference_id:      Optional[str]          = None,
    reference_type:    Optional[str]          = None,
    channels:          Optional[list[NotificationChannel]] = None,
    expires_at:        Optional[datetime]     = None,
) -> Notification:
    """
    Constructs a Notification document.
    Does not persist — caller must call create_notification() after.
    """
    return Notification(
        recipient_id=recipient_id,
        sender_id=sender_id,
        notification_type=notification_type,
        priority=priority,
        title=title,
        message=message,
        reference_id=reference_id,
        reference_type=reference_type,
        channels=channels or [NotificationChannel.IN_APP],
        expires_at=expires_at,
    )


# ================================================================
# CORE SEND  (used by all other services internally)
# ================================================================

async def send_notification(
    recipient_id:      str,
    notification_type: NotificationType,
    title:             str,
    message:           str,
    priority:          NotificationPriority            = NotificationPriority.NORMAL,
    sender_id:         Optional[str]                   = None,
    reference_id:      Optional[str]                   = None,
    reference_type:    Optional[str]                   = None,
    channels:          Optional[list[NotificationChannel]] = None,
    expires_at:        Optional[datetime]              = None,
    skip_duplicate_check: bool                         = False,
) -> NotificationResponse:
    """
    Creates and saves a single notification to a recipient.

    Called internally by:
    - LeaseService     (lease events)
    - PaymentService   (payment events)
    - RoomService      (room events)
    - MaintenanceService (maintenance events)
    - Scheduler        (expiry reminders)

    Duplicate check:
    - If an unread notification already exists for the same
      recipient + reference + type, it is skipped unless
      skip_duplicate_check=True.

    Returns the created NotificationResponse.
    """
    # ── Duplicate check ───────────────────────────────────────
    if not skip_duplicate_check and reference_id and reference_type:
        already_exists = await notification_repository.exists_unread_by_reference(
            recipient_id=recipient_id,
            reference_id=reference_id,
            reference_type=reference_type,
        )
        if already_exists:
            raise BadRequestException(
                f"An unread notification already exists for "
                f"reference {reference_type}:{reference_id}."
            )

    notification = _build_notification(
        recipient_id=recipient_id,
        notification_type=notification_type,
        title=title,
        message=message,
        priority=priority,
        sender_id=sender_id,
        reference_id=reference_id,
        reference_type=reference_type,
        channels=channels,
        expires_at=expires_at,
    )

    created = await notification_repository.create_notification(notification)
    return NotificationResponse.from_notification(created)


async def send_bulk_notification(
    recipient_ids:     list[str],
    notification_type: NotificationType,
    title:             str,
    message:           str,
    priority:          NotificationPriority            = NotificationPriority.NORMAL,
    sender_id:         Optional[str]                   = None,
    reference_id:      Optional[str]                   = None,
    reference_type:    Optional[str]                   = None,
    channels:          Optional[list[NotificationChannel]] = None,
    expires_at:        Optional[datetime]              = None,
) -> dict:
    """
    Sends the same notification to multiple recipients at once.
    Used for announcements and broadcast messages.

    Returns a summary dict with sent and failed counts.
    """
    if not recipient_ids:
        raise BadRequestException(
            "recipient_ids must not be empty."
        )

    notifications = [
        _build_notification(
            recipient_id=recipient_id,
            notification_type=notification_type,
            title=title,
            message=message,
            priority=priority,
            sender_id=sender_id,
            reference_id=reference_id,
            reference_type=reference_type,
            channels=channels,
            expires_at=expires_at,
        )
        for recipient_id in recipient_ids
    ]

    created = await notification_repository.create_bulk_notifications(
        notifications
    )

    return {
        "sent":    len(created),
        "failed":  len(recipient_ids) - len(created),
        "total":   len(recipient_ids),
    }


# ================================================================
# DOMAIN-SPECIFIC SENDERS
# Called by other services — not from controllers
# ================================================================

async def notify_lease_created(
    recipient_id: str,
    lease_id:     str,
    room_number:  str,
    start_date:   str,
    end_date:     str,
) -> None:
    """Notifies tenant that their lease has been created."""
    await send_notification(
        recipient_id=recipient_id,
        notification_type=NotificationType.LEASE_CREATED,
        title="Lease Agreement Created",
        message=(
            f"Your lease for Room {room_number} has been created. "
            f"Lease period: {start_date} to {end_date}."
        ),
        priority=NotificationPriority.NORMAL,
        reference_id=lease_id,
        reference_type="lease",
        skip_duplicate_check=True,
    )


async def notify_lease_expiring_soon(
    recipient_id:  str,
    lease_id:      str,
    room_number:   str,
    days_remaining: int,
    end_date:      str,
) -> None:
    """
    Notifies tenant that their lease is expiring soon.
    Priority escalates based on days remaining.
    """
    if days_remaining <= 3:
        priority = NotificationPriority.URGENT
    elif days_remaining <= 7:
        priority = NotificationPriority.HIGH
    else:
        priority = NotificationPriority.NORMAL

    await send_notification(
        recipient_id=recipient_id,
        notification_type=NotificationType.LEASE_EXPIRING_SOON,
        title="Lease Expiring Soon",
        message=(
            f"Your lease for Room {room_number} expires in "
            f"{days_remaining} day(s) on {end_date}. "
            f"Please contact management to renew."
        ),
        priority=priority,
        reference_id=lease_id,
        reference_type="lease",
        skip_duplicate_check=False,
    )


async def notify_lease_expired(
    recipient_id: str,
    lease_id:     str,
    room_number:  str,
) -> None:
    """Notifies tenant that their lease has expired."""
    await send_notification(
        recipient_id=recipient_id,
        notification_type=NotificationType.LEASE_EXPIRED,
        title="Lease Expired",
        message=(
            f"Your lease for Room {room_number} has expired. "
            f"Please contact management if you wish to renew."
        ),
        priority=NotificationPriority.HIGH,
        reference_id=lease_id,
        reference_type="lease",
        skip_duplicate_check=True,
    )


async def notify_lease_terminated(
    recipient_id: str,
    lease_id:     str,
    room_number:  str,
    reason:       str,
) -> None:
    """Notifies tenant that their lease has been terminated."""
    await send_notification(
        recipient_id=recipient_id,
        notification_type=NotificationType.LEASE_TERMINATED,
        title="Lease Terminated",
        message=(
            f"Your lease for Room {room_number} has been terminated. "
            f"Reason: {reason}."
        ),
        priority=NotificationPriority.HIGH,
        reference_id=lease_id,
        reference_type="lease",
        skip_duplicate_check=True,
    )


async def notify_lease_renewed(
    recipient_id:     str,
    lease_id:         str,
    room_number:      str,
    new_end_date:     str,
    new_monthly_rate: Optional[float] = None,
) -> None:
    """Notifies tenant that their lease has been renewed."""
    rate_note = (
        f" New monthly rate: ₱{new_monthly_rate:,.2f}."
        if new_monthly_rate else ""
    )
    await send_notification(
        recipient_id=recipient_id,
        notification_type=NotificationType.LEASE_RENEWED,
        title="Lease Renewed",
        message=(
            f"Your lease for Room {room_number} has been renewed "
            f"until {new_end_date}.{rate_note}"
        ),
        priority=NotificationPriority.NORMAL,
        reference_id=lease_id,
        reference_type="lease",
        skip_duplicate_check=True,
    )


async def notify_payment_received(
    recipient_id:  str,
    payment_id:    str,
    amount:        float,
    reference_no:  str,
) -> None:
    """Notifies tenant that their payment has been received."""
    await send_notification(
        recipient_id=recipient_id,
        notification_type=NotificationType.PAYMENT_RECEIVED,
        title="Payment Received",
        message=(
            f"Your payment of ₱{amount:,.2f} has been received. "
            f"Reference No: {reference_no}."
        ),
        priority=NotificationPriority.NORMAL,
        reference_id=payment_id,
        reference_type="payment",
        skip_duplicate_check=True,
    )


async def notify_payment_overdue(
    recipient_id: str,
    lease_id:     str,
    amount_due:   float,
    due_date:     str,
) -> None:
    """Notifies tenant of an overdue payment."""
    await send_notification(
        recipient_id=recipient_id,
        notification_type=NotificationType.PAYMENT_OVERDUE,
        title="Payment Overdue",
        message=(
            f"Your payment of ₱{amount_due:,.2f} was due on {due_date} "
            f"and has not been received. "
            f"Please settle immediately to avoid penalties."
        ),
        priority=NotificationPriority.URGENT,
        reference_id=lease_id,
        reference_type="lease",
        skip_duplicate_check=False,
    )


async def notify_payment_reminder(
    recipient_id: str,
    lease_id:     str,
    amount_due:   float,
    due_date:     str,
) -> None:
    """Sends a payment reminder before the due date."""
    await send_notification(
        recipient_id=recipient_id,
        notification_type=NotificationType.PAYMENT_REMINDER,
        title="Payment Reminder",
        message=(
            f"Your monthly rent of ₱{amount_due:,.2f} is due on {due_date}. "
            f"Please prepare your payment."
        ),
        priority=NotificationPriority.HIGH,
        reference_id=lease_id,
        reference_type="lease",
        skip_duplicate_check=False,
    )


async def notify_deposit_returned(
    recipient_id:     str,
    lease_id:         str,
    returned_amount:  float,
    deductions:       float,
) -> None:
    """Notifies tenant that their deposit has been returned."""
    deduction_note = (
        f" Deductions: ₱{deductions:,.2f}."
        if deductions > 0 else ""
    )
    await send_notification(
        recipient_id=recipient_id,
        notification_type=NotificationType.DEPOSIT_RETURNED,
        title="Security Deposit Returned",
        message=(
            f"Your security deposit of ₱{returned_amount:,.2f} "
            f"has been returned.{deduction_note}"
        ),
        priority=NotificationPriority.NORMAL,
        reference_id=lease_id,
        reference_type="lease",
        skip_duplicate_check=True,
    )


async def notify_maintenance_submitted(
    recipient_id:    str,
    maintenance_id:  str,
    room_number:     str,
    issue_title:     str,
) -> None:
    """Notifies staff that a maintenance request has been submitted."""
    await send_notification(
        recipient_id=recipient_id,
        notification_type=NotificationType.MAINTENANCE_SUBMITTED,
        title="Maintenance Request Submitted",
        message=(
            f"A maintenance request for Room {room_number} has been submitted: "
            f"'{issue_title}'. Our team will review it shortly."
        ),
        priority=NotificationPriority.NORMAL,
        reference_id=maintenance_id,
        reference_type="maintenance",
        skip_duplicate_check=True,
    )


async def notify_maintenance_completed(
    recipient_id:   str,
    maintenance_id: str,
    room_number:    str,
    issue_title:    str,
) -> None:
    """Notifies tenant that their maintenance request is complete."""
    await send_notification(
        recipient_id=recipient_id,
        notification_type=NotificationType.MAINTENANCE_COMPLETED,
        title="Maintenance Completed",
        message=(
            f"The maintenance request '{issue_title}' for Room {room_number} "
            f"has been completed."
        ),
        priority=NotificationPriority.NORMAL,
        reference_id=maintenance_id,
        reference_type="maintenance",
        skip_duplicate_check=True,
    )


async def notify_room_assigned(
    recipient_id: str,
    room_id:      str,
    room_number:  str,
    move_in_date: str,
) -> None:
    """Notifies tenant that they have been assigned a room."""
    await send_notification(
        recipient_id=recipient_id,
        notification_type=NotificationType.ROOM_ASSIGNED,
        title="Room Assigned",
        message=(
            f"You have been assigned to Room {room_number}. "
            f"Move-in date: {move_in_date}."
        ),
        priority=NotificationPriority.NORMAL,
        reference_id=room_id,
        reference_type="room",
        skip_duplicate_check=True,
    )


async def send_announcement(
    recipient_ids: list[str],
    title:         str,
    message:       str,
    sender_id:     str,
    expires_in_days: Optional[int] = 7,
) -> dict:
    """
    Broadcasts an announcement to multiple users.
    Used by admin/manager for house-wide announcements.

    Returns summary: { sent, failed, total }
    """
    if not title.strip():
        raise BadRequestException("Announcement title must not be empty.")
    if not message.strip():
        raise BadRequestException("Announcement message must not be empty.")
    if not recipient_ids:
        raise BadRequestException("At least one recipient is required.")

    expires_at = None
    if expires_in_days and expires_in_days > 0:
        expires_at = datetime.utcnow() + timedelta(days=expires_in_days)

    return await send_bulk_notification(
        recipient_ids=recipient_ids,
        notification_type=NotificationType.ANNOUNCEMENT,
        title=title.strip(),
        message=message.strip(),
        priority=NotificationPriority.NORMAL,
        sender_id=sender_id,
        expires_at=expires_at,
    )


# ================================================================
# READ
# ================================================================

async def get_my_notifications(
    recipient_id: str,
    skip: int = 0,
    limit: int = 20,
) -> list[NotificationResponse]:
    """
    Returns all non-deleted notifications for the current user.
    Used by the notification panel / inbox.
    """
    notifications = await notification_repository.get_notifications_by_recipient(
        recipient_id=recipient_id, skip=skip, limit=limit
    )
    return [NotificationResponse.from_notification(n) for n in notifications]


async def get_my_unread(
    recipient_id: str,
    skip: int = 0,
    limit: int = 20,
) -> list[NotificationResponse]:
    """
    Returns unread notifications for the current user.
    Used by the notification bell dropdown.
    """
    notifications = await notification_repository.get_unread_notifications(
        recipient_id=recipient_id, skip=skip, limit=limit
    )
    return [NotificationResponse.from_notification(n) for n in notifications]


async def get_unread_count(recipient_id: str) -> dict:
    """
    Returns the unread notification count for the current user.
    Used by the notification bell badge in the topbar.
    """
    count = await notification_repository.count_unread(recipient_id)
    return {"unread_count": count}


async def get_urgent_notifications(
    recipient_id: str,
) -> list[NotificationResponse]:
    """
    Returns all unread URGENT notifications for the current user.
    Used by the dashboard alert banner.
    """
    notifications = await notification_repository.get_urgent_notifications(
        recipient_id
    )
    return [NotificationResponse.from_notification(n) for n in notifications]


async def get_notification_by_id(
    notification_id: PydanticObjectId,
    recipient_id: str,
) -> NotificationResponse:
    """
    Returns a single notification by ID.
    Validates it belongs to the requesting user.
    Raises 404 if not found.
    """
    notification = await _assert_notification_exists(notification_id)
    await _assert_belongs_to_recipient(notification, recipient_id)
    return NotificationResponse.from_notification(notification)


async def get_all_notifications_admin(
    skip: int = 0,
    limit: int = 20,
) -> list[NotificationResponse]:
    """
    Returns all notifications across all users.
    Admin only — used for system monitoring.
    """
    notifications = await notification_repository.get_all_notifications(
        skip=skip, limit=limit
    )
    return [NotificationResponse.from_notification(n) for n in notifications]


# ================================================================
# MARK READ / DELETE
# ================================================================

async def mark_as_read(
    notification_id: PydanticObjectId,
    recipient_id: str,
) -> NotificationResponse:
    """
    Marks a single notification as read.
    Validates it belongs to the requesting user.
    Raises 400 if already read.
    """
    notification = await _assert_notification_exists(notification_id)
    await _assert_belongs_to_recipient(notification, recipient_id)

    if notification.is_read:
        raise BadRequestException(
            f"Notification {notification_id} is already marked as read."
        )

    updated = await notification_repository.mark_as_read(notification_id)
    return NotificationResponse.from_notification(updated)


async def mark_all_as_read(recipient_id: str) -> dict:
    """
    Marks all unread notifications as read for the current user.
    Used by the 'Mark all as read' button.
    Returns count of notifications marked.
    """
    count = await notification_repository.mark_all_as_read(recipient_id)
    return {"marked_as_read": count}


async def delete_notification(
    notification_id: PydanticObjectId,
    recipient_id: str,
) -> dict:
    """
    Soft deletes a single notification.
    Validates it belongs to the requesting user.
    Notifications are NEVER hard deleted.
    """
    notification = await _assert_notification_exists(notification_id)
    await _assert_belongs_to_recipient(notification, recipient_id)

    await notification_repository.soft_delete_notification(notification_id)
    return {"message": "Notification deleted successfully."}


async def clear_all_notifications(recipient_id: str) -> dict:
    """
    Soft deletes all notifications for the current user.
    Used by the 'Clear all' button in the notification panel.
    Returns count of notifications cleared.
    """
    count = await notification_repository.soft_delete_all_for_recipient(
        recipient_id
    )
    return {"cleared": count}


# ================================================================
# CLEANUP  (called by scheduler)
# ================================================================

async def cleanup_expired_notifications() -> dict:
    """
    Soft deletes all expired notifications.
    Called by the scheduler cleanup job — not from controllers.
    Returns count of notifications cleaned up.
    """
    count = await notification_repository.soft_delete_expired_notifications()
    return {"cleaned_up": count}