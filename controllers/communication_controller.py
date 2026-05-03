

from fastapi import APIRouter, Depends, HTTPException, status
from models.user import User
from config.jwt_middleware import get_current_user
from services.communication_service import communication_service
from dto.request.message_request import SendMessageRequest, CreateAnnouncementRequest
from dto.response.message_response import (
    MessageResponse, ThreadResponse, AnnouncementResponse,
    UnreadCountResponse, to_message_response, to_announcement_response
)
from models.message import AnnouncementPriority

router = APIRouter(prefix="/api", tags=["communication"])


# ============================================================================
# MESSAGE ENDPOINTS
# ============================================================================

@router.post(
    "/messages/send",
    response_model=MessageResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Send a message (tenant ↔ management)",
)
async def send_message(
    body: SendMessageRequest,
    current_user: User = Depends(get_current_user),
):
    message = await communication_service.send_message(
        sender_id   = str(current_user.id),
        receiver_id = body.receiver_id,
        tenant_id   = body.tenant_id,
        body        = body.body,
        direction   = body.direction,
        subject     = body.subject,
        thread_id   = body.thread_id,
    )
    return to_message_response(message)


@router.get(
    "/messages/tenant/{tenant_id}",
    response_model=list[MessageResponse],
    summary="Get all messages for a tenant",
)
async def get_tenant_messages(
    tenant_id: str,
    current_user: User = Depends(get_current_user),
):
    messages = await communication_service.get_tenant_inbox(tenant_id)
    return [to_message_response(m) for m in messages]


@router.get(
    "/messages/thread/{thread_id}",
    response_model=ThreadResponse,
    summary="Get full conversation thread",
)
async def get_thread(
    thread_id: str,
    current_user: User = Depends(get_current_user),
):
    messages = await communication_service.get_thread(thread_id)
    return ThreadResponse(
        thread_id = thread_id,
        messages  = [to_message_response(m) for m in messages],
        total     = len(messages),
    )


@router.get(
    "/messages/unread",
    response_model=list[MessageResponse],
    summary="Get unread messages for current user",
)
async def get_unread_messages(
    current_user: User = Depends(get_current_user),
):
    messages = await communication_service.get_unread_messages(str(current_user.id))
    return [to_message_response(m) for m in messages]


@router.get(
    "/messages/unread/count",
    summary="Get unread message count for notification badge",
)
async def get_unread_count(
    current_user: User = Depends(get_current_user),
):
    count = await communication_service.get_unread_count(str(current_user.id))
    return {"unread_messages": count}


@router.patch(
    "/messages/thread/{thread_id}/read",
    summary="Mark all messages in a thread as read",
)
async def mark_thread_read(
    thread_id: str,
    current_user: User = Depends(get_current_user),
):
    return await communication_service.read_thread(thread_id, str(current_user.id))


@router.delete(
    "/messages/{message_id}",
    summary="Delete a message",
)
async def delete_message(
    message_id: str,
    current_user: User = Depends(get_current_user),
):
    return await communication_service.delete_message(message_id)


# ============================================================================
# ANNOUNCEMENT ENDPOINTS
# ============================================================================

@router.post(
    "/announcements",
    response_model=AnnouncementResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create an announcement (Manager/Admin only)",
)
async def create_announcement(
    body: CreateAnnouncementRequest,
    current_user: User = Depends(get_current_user),
):
    from models.user import RoleName
    if current_user.role not in [RoleName.ADMIN, RoleName.MANAGER]:
        raise HTTPException(403, "Manager or Admin access required.")

    announcement = await communication_service.create_announcement(
        author_id         = str(current_user.id),
        title             = body.title,
        body              = body.body,
        priority          = body.priority,
        target_tenant_ids = body.target_tenant_ids,
        expires_at        = body.expires_at,
        publish_now       = body.publish_now,
    )
    return to_announcement_response(announcement)


@router.get(
    "/announcements",
    response_model=list[AnnouncementResponse],
    summary="Get all announcements (Manager/Admin view)",
)
async def get_all_announcements(
    current_user: User = Depends(get_current_user),
):
    from models.user import RoleName
    if current_user.role not in [RoleName.ADMIN, RoleName.MANAGER]:
        raise HTTPException(403, "Manager or Admin access required.")
    announcements = await communication_service.get_all_announcements()
    return [to_announcement_response(a) for a in announcements]


@router.get(
    "/announcements/published",
    response_model=list[AnnouncementResponse],
    summary="Get published announcements (tenant view)",
)
async def get_published_announcements(
    current_user: User = Depends(get_current_user),
):
    announcements = await communication_service.get_published_announcements()
    return [to_announcement_response(a) for a in announcements]


@router.get(
    "/announcements/tenant/{tenant_id}",
    response_model=list[AnnouncementResponse],
    summary="Get announcements relevant to a specific tenant",
)
async def get_tenant_announcements(
    tenant_id: str,
    current_user: User = Depends(get_current_user),
):
    announcements = await communication_service.get_announcements_for_tenant(tenant_id)
    return [to_announcement_response(a) for a in announcements]


@router.patch(
    "/announcements/{announcement_id}/publish",
    response_model=AnnouncementResponse,
    summary="Publish a draft announcement",
)
async def publish_announcement(
    announcement_id: str,
    current_user: User = Depends(get_current_user),
):
    from models.user import RoleName
    if current_user.role not in [RoleName.ADMIN, RoleName.MANAGER]:
        raise HTTPException(403, "Manager or Admin access required.")
    announcement = await communication_service.publish_announcement(announcement_id)
    return to_announcement_response(announcement)


@router.patch(
    "/announcements/{announcement_id}/archive",
    response_model=AnnouncementResponse,
    summary="Archive a published announcement",
)
async def archive_announcement(
    announcement_id: str,
    current_user: User = Depends(get_current_user),
):
    from models.user import RoleName
    if current_user.role not in [RoleName.ADMIN, RoleName.MANAGER]:
        raise HTTPException(403, "Manager or Admin access required.")
    announcement = await communication_service.archive_announcement(announcement_id)
    return to_announcement_response(announcement)


@router.patch(
    "/announcements/{announcement_id}/read",
    response_model=AnnouncementResponse,
    summary="Mark an announcement as read by current tenant",
)
async def mark_announcement_read(
    announcement_id: str,
    tenant_id: str,
    current_user: User = Depends(get_current_user),
):
    announcement = await communication_service.mark_announcement_read(
        announcement_id, tenant_id
    )
    return to_announcement_response(announcement)


@router.delete(
    "/announcements/{announcement_id}",
    summary="Delete an announcement (Manager/Admin only)",
)
async def delete_announcement(
    announcement_id: str,
    current_user: User = Depends(get_current_user),
):
    from models.user import RoleName
    if current_user.role not in [RoleName.ADMIN, RoleName.MANAGER]:
        raise HTTPException(403, "Manager or Admin access required.")
    return await communication_service.delete_announcement(announcement_id)