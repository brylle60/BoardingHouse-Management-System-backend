

from beanie import PydanticObjectId
from models.maintenance import MaintenanceRequest, MaintenanceStatus


async def find_all_requests() -> list[MaintenanceRequest]:
    return await MaintenanceRequest.find_all().sort("-created_at").to_list()

async def find_request_by_id(request_id: str) -> MaintenanceRequest | None:
    try:
        return await MaintenanceRequest.get(PydanticObjectId(request_id))
    except Exception:
        return None

async def find_requests_by_tenant(tenant_id: str) -> list[MaintenanceRequest]:
    oid = PydanticObjectId(tenant_id)
    return await MaintenanceRequest.find(
        MaintenanceRequest.tenant_id == oid
    ).sort("-created_at").to_list()

async def find_requests_by_status(status: MaintenanceStatus) -> list[MaintenanceRequest]:
    return await MaintenanceRequest.find(
        MaintenanceRequest.status == status
    ).sort("-created_at").to_list()

async def find_requests_assigned_to(user_id: str) -> list[MaintenanceRequest]:
    oid = PydanticObjectId(user_id)
    return await MaintenanceRequest.find(
        MaintenanceRequest.assigned_to == oid
    ).sort("-created_at").to_list()

async def find_pending_requests() -> list[MaintenanceRequest]:
    return await MaintenanceRequest.find(
        MaintenanceRequest.status == MaintenanceStatus.SUBMITTED
    ).sort("created_at").to_list()

async def save_request(request: MaintenanceRequest) -> MaintenanceRequest:
    await request.save()
    return request

async def delete_request(request: MaintenanceRequest) -> None:
    await request.delete()

async def count_by_status(status: MaintenanceStatus) -> int:
    return await MaintenanceRequest.find(
        MaintenanceRequest.status == status
    ).count()
