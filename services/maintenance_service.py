
from fastapi import HTTPException
from datetime import datetime
from beanie import PydanticObjectId
from models.maintenance import (
    MaintenanceRequest, MaintenanceStatus,
    MaintenanceCategory, MaintenancePriority,
)
from repository.maintenance_repository import (
    find_all_requests, find_request_by_id,
    find_requests_by_tenant, find_requests_by_status,
    find_requests_assigned_to, find_pending_requests,
    save_request, delete_request, count_by_status,
)
from repository.notification_repository import create_notification
from models.notification import NotificationType


class MaintenanceService:

    async def get_all_requests(self) -> list[MaintenanceRequest]:
        return await find_all_requests()

    async def get_request_by_id(self, request_id: str) -> MaintenanceRequest:
        req = await find_request_by_id(request_id)
        if not req:
            raise HTTPException(404, "Maintenance request not found.")
        return req

    async def get_tenant_requests(self, tenant_id: str) -> list[MaintenanceRequest]:
        return await find_requests_by_tenant(tenant_id)

    async def get_pending_requests(self) -> list[MaintenanceRequest]:
        return await find_pending_requests()

    async def get_requests_by_status(self, status: MaintenanceStatus) -> list[MaintenanceRequest]:
        return await find_requests_by_status(status)

    async def submit_request(
        self,
        tenant_id:   str,
        room_id:     str,
        title:       str,
        description: str,
        category:    MaintenanceCategory = MaintenanceCategory.OTHER,
        priority:    MaintenancePriority = MaintenancePriority.MEDIUM,
        photos:      list[str]           = [],
    ) -> MaintenanceRequest:
        req = MaintenanceRequest(
            tenant_id   = PydanticObjectId(tenant_id),
            room_id     = PydanticObjectId(room_id),
            title       = title.strip(),
            description = description.strip(),
            category    = category,
            priority    = priority,
            photos      = photos,
            status      = MaintenanceStatus.SUBMITTED,
        )
        saved = await save_request(req)
        return saved

    async def assign_request(
        self,
        request_id:  str,
        assigned_to: str,
    ) -> MaintenanceRequest:
        req = await self.get_request_by_id(request_id)

        if req.status not in [MaintenanceStatus.SUBMITTED, MaintenanceStatus.ASSIGNED]:
            raise HTTPException(400, "Request cannot be reassigned at this stage.")

        req.assigned_to  = PydanticObjectId(assigned_to)
        req.status       = MaintenanceStatus.ASSIGNED
        req.assigned_at  = datetime.utcnow()
        req.updated_at   = datetime.utcnow()
        saved = await save_request(req)

        # Notify tenant
        await create_notification(
            user_id        = str(req.tenant_id),
            type           = NotificationType.MAINTENANCE_ASSIGNED,
            title          = "Maintenance request assigned",
            message        = f"Your request '{req.title}' has been assigned and will be worked on soon.",
            reference_id   = str(saved.id),
            reference_type = "maintenance",
        )

        return saved

    async def start_request(self, request_id: str) -> MaintenanceRequest:
        req = await self.get_request_by_id(request_id)

        if req.status != MaintenanceStatus.ASSIGNED:
            raise HTTPException(400, "Request must be assigned before starting.")

        req.status     = MaintenanceStatus.IN_PROGRESS
        req.started_at = datetime.utcnow()
        req.updated_at = datetime.utcnow()
        return await save_request(req)

    async def complete_request(
        self,
        request_id: str,
        resolution: str,
    ) -> MaintenanceRequest:
        req = await self.get_request_by_id(request_id)

        if req.status != MaintenanceStatus.IN_PROGRESS:
            raise HTTPException(400, "Request must be in progress before completing.")

        req.status       = MaintenanceStatus.COMPLETED
        req.resolution   = resolution.strip()
        req.completed_at = datetime.utcnow()
        req.updated_at   = datetime.utcnow()
        saved = await save_request(req)

        # Notify tenant to confirm
        await create_notification(
            user_id        = str(req.tenant_id),
            type           = NotificationType.MAINTENANCE_COMPLETED,
            title          = "Maintenance completed",
            message        = f"Your request '{req.title}' has been resolved. Please confirm if the issue is fixed.",
            reference_id   = str(saved.id),
            reference_type = "maintenance",
        )

        return saved

    async def close_request(self, request_id: str) -> MaintenanceRequest:
        """Tenant confirms the issue is resolved — closes the ticket."""
        req = await self.get_request_by_id(request_id)

        if req.status != MaintenanceStatus.COMPLETED:
            raise HTTPException(400, "Request must be completed before closing.")

        req.status    = MaintenanceStatus.CLOSED
        req.closed_at = datetime.utcnow()
        req.updated_at = datetime.utcnow()
        return await save_request(req)

    async def reject_request(
        self,
        request_id:        str,
        rejection_reason:  str,
    ) -> MaintenanceRequest:
        req = await self.get_request_by_id(request_id)

        if req.status not in [MaintenanceStatus.SUBMITTED, MaintenanceStatus.ASSIGNED]:
            raise HTTPException(400, "Only submitted or assigned requests can be rejected.")

        req.status           = MaintenanceStatus.REJECTED
        req.rejection_reason = rejection_reason.strip()
        req.updated_at       = datetime.utcnow()
        saved = await save_request(req)

        # Notify tenant
        await create_notification(
            user_id        = str(req.tenant_id),
            type           = NotificationType.GENERAL,
            title          = "Maintenance request rejected",
            message        = f"Your request '{req.title}' was rejected. Reason: {rejection_reason}",
            reference_id   = str(saved.id),
            reference_type = "maintenance",
        )

        return saved

    async def delete_request(self, request_id: str) -> dict:
        req = await self.get_request_by_id(request_id)
        await delete_request(req)
        return {"message": "Maintenance request deleted."}

    async def get_maintenance_stats(self) -> dict:
        return {
            "submitted":   await count_by_status(MaintenanceStatus.SUBMITTED),
            "assigned":    await count_by_status(MaintenanceStatus.ASSIGNED),
            "in_progress": await count_by_status(MaintenanceStatus.IN_PROGRESS),
            "completed":   await count_by_status(MaintenanceStatus.COMPLETED),
            "closed":      await count_by_status(MaintenanceStatus.CLOSED),
        }


maintenance_service = MaintenanceService()
