# ============================================================
# controllers/notification_controller.py
# ResidEase – Boarding House Management System
# ============================================================

from fastapi import APIRouter, Depends, Query, Path, Body, status
from beanie import PydanticObjectId

from services import notification_service
from dto.request.notification_request import (
    NotificationCreateRequest,
    NotificationBroadcastRequest,
)
from dto.response.notification_response import NotificationResponse
from dto.response.api_response import ApiResponse
from config.jwt_middleware import get_current_user, require_roles
from models.user import RoleName

router = APIRouter(
    prefix="/api/notifications",
    tags=["Notifications"],
)


# ================================================================
# GET /api/notifications/me
# ================================================================

@router.get(
    "/me",
    response_model=ApiResponse[list[NotificationResponse]],
    status_code=status.HTTP_200_OK,
    summary="Get my notifications",
    description="Returns all non-deleted notifications for the "
                "currently logged-in user. Sorted by latest first. "
                "Accessible by all authenticated roles.",
)
async def get_my_notifications(
    skip:  int = Query(default=0,  ge=0),
    limit: int = Query(default=20, ge=1, le=100),
    current_user=Depends(get_current_user),
):
    data = await notification_service.get_my_notifications(
        recipient_id=current_user["sub"],
        skip=skip,
        limit=limit,
    )
    return ApiResponse.success(
        data=data,
        message="Notifications retrieved successfully.",
    )


# ================================================================
# GET /api/notifications/me/unread
# ================================================================

@router.get(
    "/me/unread",
    response_model=ApiResponse[list[NotificationResponse]],
    status_code=status.HTTP_200_OK,
    summary="Get my unread notifications",
    description="Returns all unread notifications for the "
                "currently logged-in user. "
                "Used by the notification bell dropdown. "
                "Accessible by all authenticated roles.",
)
async def get_my_unread_notifications(
    skip:  int = Query(default=0,  ge=0),
    limit: int = Query(default=20, ge=1, le=100),
    current_user=Depends(get_current_user),
):
    data = await notification_service.get_my_unread(
        recipient_id=current_user["sub"],
        skip=skip,
        limit=limit,
    )
    return ApiResponse.success(
        data=data,
        message="Unread notifications retrieved successfully.",
    )


# ================================================================
# GET /api/notifications/me/unread-count
# ================================================================

@router.get(
    "/me/unread-count",
    response_model=ApiResponse[dict],
    status_code=status.HTTP_200_OK,
    summary="Get unread notification count",
    description="Returns the count of unread notifications "
                "for the currently logged-in user. "
                "Used by the notification bell badge in the topbar. "
                "Accessible by all authenticated roles.",
)
async def get_unread_count(
    current_user=Depends(get_current_user),
):
    data = await notification_service.get_unread_count(
        recipient_id=current_user["sub"]
    )
    return ApiResponse.success(
        data=data,
        message="Unread count retrieved successfully.",
    )


# ================================================================
# GET /api/notifications/me/urgent
# ================================================================

@router.get(
    "/me/urgent",
    response_model=ApiResponse[list[NotificationResponse]],
    status_code=status.HTTP_200_OK,
    summary="Get my urgent notifications",
    description="Returns all unread URGENT notifications "
                "for the currently logged-in user. "
                "Used by the dashboard alert banner. "
                "Accessible by all authenticated roles.",
)
async def get_urgent_notifications(
    current_user=Depends(get_current_user),
):
    data = await notification_service.get_urgent_notifications(
        recipient_id=current_user["sub"]
    )
    return ApiResponse.success(
        data=data,
        message="Urgent notifications retrieved successfully.",
    )


# ================================================================
# GET /api/notifications/admin/all
# ================================================================

@router.get(
    "/admin/all",
    response_model=ApiResponse[list[NotificationResponse]],
    status_code=status.HTTP_200_OK,
    summary="Get all notifications (admin)",
    description="Returns all notifications across all users. "
                "Used for system monitoring and admin oversight. "
                "Accessible by ADMIN only.",
)
async def get_all_notifications_admin(
    skip:  int = Query(default=0,  ge=0),
    limit: int = Query(default=20, ge=1, le=100),
    current_user=Depends(require_roles(RoleName.ADMIN)),
):
    data = await notification_service.get_all_notifications_admin(
        skip=skip,
        limit=limit,
    )
    return ApiResponse.success(
        data=data,
        message="All notifications retrieved successfully.",
    )


# ================================================================
# POST /api/notifications/send
# ================================================================

@router.post(
    "/send",
    response_model=ApiResponse[NotificationResponse],
    status_code=status.HTTP_201_CREATED,
    summary="Send a notification to a user",
    description="Sends a single notification to a specific user. "
                "Used by admin/manager for manual notifications. "
                "Accessible by ADMIN and MANAGER only.",
)
async def send_notification(
    request: NotificationCreateRequest = Body(...),
    current_user=Depends(require_roles(RoleName.ADMIN, RoleName.MANAGER)),
):
    data = await notification_service.send_notification(
        recipient_id=request.recipient_id,
        notification_type=request.notification_type,
        title=request.title,
        message=request.message,
        priority=request.priority,
        sender_id=current_user["sub"],
        reference_id=request.reference_id,
        reference_type=request.reference_type,
        channels=request.channels,
        expires_at=request.expires_at,
        skip_duplicate_check=request.skip_duplicate_check,
    )
    return ApiResponse.success(
        data=data,
        message="Notification sent successfully.",
        status_code=status.HTTP_201_CREATED,
    )


# ================================================================
# POST /api/notifications/broadcast
# ================================================================

@router.post(
    "/broadcast",
    response_model=ApiResponse[dict],
    status_code=status.HTTP_201_CREATED,
    summary="Broadcast announcement to multiple users",
    description="Sends the same notification to multiple recipients. "
                "Used for house-wide announcements. "
                "Accessible by ADMIN and MANAGER only.",
)
async def broadcast_notification(
    request: NotificationBroadcastRequest = Body(...),
    current_user=Depends(require_roles(RoleName.ADMIN, RoleName.MANAGER)),
):
    data = await notification_service.send_announcement(
        recipient_ids=request.recipient_ids,
        title=request.title,
        message=request.message,
        sender_id=current_user["sub"],
        expires_in_days=request.expires_in_days,
    )
    return ApiResponse.success(
        data=data,
        message=f"Announcement sent to {data['sent']} recipient(s).",
        status_code=status.HTTP_201_CREATED,
    )


# ================================================================
# GET /api/notifications/{notification_id}
# ================================================================

@router.get(
    "/{notification_id}",
    response_model=ApiResponse[NotificationResponse],
    status_code=status.HTTP_200_OK,
    summary="Get notification by ID",
    description="Returns a single notification by its MongoDB ObjectId. "
                "Validates the notification belongs to the requesting user. "
                "Accessible by all authenticated roles.",
)
async def get_notification_by_id(
    notification_id: PydanticObjectId = Path(
        ..., description="Notification MongoDB ObjectId"
    ),
    current_user=Depends(get_current_user),
):
    data = await notification_service.get_notification_by_id(
        notification_id=notification_id,
        recipient_id=current_user["sub"],
    )
    return ApiResponse.success(
        data=data,
        message="Notification retrieved successfully.",
    )


# ================================================================
# PATCH /api/notifications/{notification_id}/read
# ================================================================

@router.patch(
    "/{notification_id}/read",
    response_model=ApiResponse[NotificationResponse],
    status_code=status.HTTP_200_OK,
    summary="Mark notification as read",
    description="Marks a single notification as read. "
                "Validates the notification belongs to the requesting user. "
                "Raises 400 if already read. "
                "Accessible by all authenticated roles.",
)
async def mark_as_read(
    notification_id: PydanticObjectId = Path(
        ..., description="Notification MongoDB ObjectId"
    ),
    current_user=Depends(get_current_user),
):
    data = await notification_service.mark_as_read(
        notification_id=notification_id,
        recipient_id=current_user["sub"],
    )
    return ApiResponse.success(
        data=data,
        message="Notification marked as read.",
    )


# ================================================================
# PATCH /api/notifications/me/read-all
# ================================================================

@router.patch(
    "/me/read-all",
    response_model=ApiResponse[dict],
    status_code=status.HTTP_200_OK,
    summary="Mark all notifications as read",
    description="Marks all unread notifications as read "
                "for the currently logged-in user. "
                "Used by the 'Mark all as read' button. "
                "Accessible by all authenticated roles.",
)
async def mark_all_as_read(
    current_user=Depends(get_current_user),
):
    data = await notification_service.mark_all_as_read(
        recipient_id=current_user["sub"]
    )
    return ApiResponse.success(
        data=data,
        message=f"{data['marked_as_read']} notification(s) marked as read.",
    )


# ================================================================
# DELETE /api/notifications/{notification_id}
# ================================================================

@router.delete(
    "/{notification_id}",
    response_model=ApiResponse[dict],
    status_code=status.HTTP_200_OK,
    summary="Delete a notification",
    description="Soft deletes a single notification. "
                "Validates the notification belongs to the requesting user. "
                "Notifications are never hard deleted. "
                "Accessible by all authenticated roles.",
)
async def delete_notification(
    notification_id: PydanticObjectId = Path(
        ..., description="Notification MongoDB ObjectId"
    ),
    current_user=Depends(get_current_user),
):
    data = await notification_service.delete_notification(
        notification_id=notification_id,
        recipient_id=current_user["sub"],
    )
    return ApiResponse.success(
        data=data,
        message=data.get("message", "Notification deleted successfully."),
    )


# ================================================================
# DELETE /api/notifications/me/clear-all
# ================================================================

@router.delete(
    "/me/clear-all",
    response_model=ApiResponse[dict],
    status_code=status.HTTP_200_OK,
    summary="Clear all notifications",
    description="Soft deletes all notifications for the "
                "currently logged-in user. "
                "Used by the 'Clear all' button. "
                "Accessible by all authenticated roles.",
)
async def clear_all_notifications(
    current_user=Depends(get_current_user),
):
    data = await notification_service.clear_all_notifications(
        recipient_id=current_user["sub"]
    )
    return ApiResponse.success(
        data=data,
        message=f"{data['cleared']} notification(s) cleared.",
    )