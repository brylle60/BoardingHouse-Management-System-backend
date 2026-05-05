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
)
async def get_my_notifications(
    skip:  int = Query(default=0,  ge=0),
    limit: int = Query(default=20, ge=1, le=100),
    current_user=Depends(get_current_user),
):
    data = await notification_service.get_my_notifications(
        recipient_id=str(current_user.id),   # ✅ fixed
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
)
async def get_my_unread_notifications(
    skip:  int = Query(default=0,  ge=0),
    limit: int = Query(default=20, ge=1, le=100),
    current_user=Depends(get_current_user),
):
    data = await notification_service.get_my_unread(
        recipient_id=str(current_user.id),   # ✅ fixed
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
)
async def get_unread_count(
    current_user=Depends(get_current_user),
):
    data = await notification_service.get_unread_count(
        recipient_id=str(current_user.id)    # ✅ fixed
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
)
async def get_urgent_notifications(
    current_user=Depends(get_current_user),
):
    data = await notification_service.get_urgent_notifications(
        recipient_id=str(current_user.id)    # ✅ fixed
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
        sender_id=str(current_user.id),      # ✅ fixed
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
)
async def broadcast_notification(
    request: NotificationBroadcastRequest = Body(...),
    current_user=Depends(require_roles(RoleName.ADMIN, RoleName.MANAGER)),
):
    data = await notification_service.send_announcement(
        recipient_ids=request.recipient_ids,
        title=request.title,
        message=request.message,
        sender_id=str(current_user.id),      # ✅ fixed
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
)
async def get_notification_by_id(
    notification_id: PydanticObjectId = Path(
        ..., description="Notification MongoDB ObjectId"
    ),
    current_user=Depends(get_current_user),
):
    data = await notification_service.get_notification_by_id(
        notification_id=notification_id,
        recipient_id=str(current_user.id),   # ✅ fixed
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
)
async def mark_as_read(
    notification_id: PydanticObjectId = Path(
        ..., description="Notification MongoDB ObjectId"
    ),
    current_user=Depends(get_current_user),
):
    data = await notification_service.mark_as_read(
        notification_id=notification_id,
        recipient_id=str(current_user.id),   # ✅ fixed
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
)
async def mark_all_as_read(
    current_user=Depends(get_current_user),
):
    data = await notification_service.mark_all_as_read(
        recipient_id=str(current_user.id)    # ✅ fixed
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
)
async def delete_notification(
    notification_id: PydanticObjectId = Path(
        ..., description="Notification MongoDB ObjectId"
    ),
    current_user=Depends(get_current_user),
):
    data = await notification_service.delete_notification(
        notification_id=notification_id,
        recipient_id=str(current_user.id),   # ✅ fixed
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
)
async def clear_all_notifications(
    current_user=Depends(get_current_user),
):
    data = await notification_service.clear_all_notifications(
        recipient_id=str(current_user.id)    # ✅ fixed
    )
    return ApiResponse.success(
        data=data,
        message=f"{data['cleared']} notification(s) cleared.",
    )