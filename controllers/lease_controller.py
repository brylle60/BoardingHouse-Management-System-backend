# ============================================================
# controllers/lease_controller.py
# ResidEase – Boarding House Management System
# ============================================================

from fastapi import APIRouter, Depends, Query, Path, Body, status
from beanie import PydanticObjectId

from services import lease_service
from models.lease import LeaseStatus
from dto.request.lease_request import (
    LeaseCreateRequest,
    LeaseUpdateRequest,
    LeaseRenewRequest,
    LeaseTerminateRequest,
    DepositReturnRequest,
)
from dto.response.lease_response import LeaseResponse
from dto.response.api_response import ApiResponse
from config.jwt_middleware import get_current_user, require_roles
from models.user import RoleName

router = APIRouter(
    prefix="/api/leases",
    tags=["Leases"],
)


# ================================================================
# POST /api/leases
# ================================================================

@router.post(
    "/",
    response_model=ApiResponse[LeaseResponse],
    status_code=status.HTTP_201_CREATED,
    summary="Create a new lease",
    description="Creates a new lease agreement between a tenant and a room. "
                "Automatically occupies the room and activates the tenant. "
                "Lease is set to PENDING if start_date is in the future, "
                "ACTIVE if start_date is today or in the past. "
                "Accessible by ADMIN and MANAGER only.",
)
async def create_lease(
    request: LeaseCreateRequest = Body(...),
    current_user=Depends(require_roles(RoleName.ADMIN, RoleName.MANAGER)),
):
    data = await lease_service.create_lease(
        request=request,
        created_by=current_user["username"],
    )
    return ApiResponse.success(
        data=data,
        message="Lease created successfully.",
        status_code=status.HTTP_201_CREATED,
    )


# ================================================================
# GET /api/leases
# ================================================================

@router.get(
    "/",
    response_model=ApiResponse[list[LeaseResponse]],
    status_code=status.HTTP_200_OK,
    summary="Get all leases",
    description="Returns a paginated list of all leases across all tenants and rooms. "
                "Includes all statuses: ACTIVE, PENDING, EXPIRED, TERMINATED, RENEWED. "
                "Accessible by ADMIN, and MANAGER.",
)
async def get_all_leases(
    skip:  int = Query(default=0,  ge=0),
    limit: int = Query(default=20, ge=1, le=100),
    current_user=Depends(require_roles(
        RoleName.ADMIN, RoleName.MANAGER
    )),
):
    data = await lease_service.get_all_leases(skip=skip, limit=limit)
    return ApiResponse.success(
        data=data,
        message="Leases retrieved successfully.",
    )


# ================================================================
# GET /api/leases/stats
# ================================================================

@router.get(
    "/stats",
    response_model=ApiResponse[dict],
    status_code=status.HTTP_200_OK,
    summary="Get lease statistics",
    description="Returns lease counts grouped by status plus expiring-soon count. "
                "Used by the dashboard stats grid. "
                "Accessible by ADMIN and MANAGER.",
)
async def get_lease_stats(
    current_user=Depends(require_roles(RoleName.ADMIN, RoleName.MANAGER)),
):
    data = await lease_service.get_lease_stats()
    return ApiResponse.success(
        data=data,
        message="Lease statistics retrieved successfully.",
    )


# ================================================================
# GET /api/leases/expiring
# ================================================================

@router.get(
    "/expiring",
    response_model=ApiResponse[list[LeaseResponse]],
    status_code=status.HTTP_200_OK,
    summary="Get expiring leases",
    description="Returns active leases expiring within the given number of days. "
                "Default is 30 days. Used by the dashboard expiring-soon alert. "
                "Accessible by ADMIN and MANAGER.",
)
async def get_expiring_leases(
    days_ahead: int = Query(default=30, ge=1, le=365),
    skip:       int = Query(default=0,  ge=0),
    limit:      int = Query(default=20, ge=1, le=100),
    current_user=Depends(require_roles(RoleName.ADMIN, RoleName.MANAGER)),
):
    data = await lease_service.get_expiring_leases(
        days_ahead=days_ahead, skip=skip, limit=limit
    )
    return ApiResponse.success(
        data=data,
        message=f"Leases expiring within {days_ahead} day(s) retrieved successfully.",
    )


# ================================================================
# GET /api/leases/status/{lease_status}
# ================================================================

@router.get(
    "/status/{lease_status}",
    response_model=ApiResponse[list[LeaseResponse]],
    status_code=status.HTTP_200_OK,
    summary="Get leases by status",
    description="Returns leases filtered by status: "
                "ACTIVE, PENDING, EXPIRED, TERMINATED, or RENEWED. "
                "Accessible by ADMIN, and MANAGER.",
)
async def get_leases_by_status(
    lease_status: LeaseStatus = Path(..., description="Lease status filter"),
    skip:  int = Query(default=0,  ge=0),
    limit: int = Query(default=20, ge=1, le=100),
    current_user=Depends(require_roles(
        RoleName.ADMIN, RoleName.MANAGER
    )),
):
    data = await lease_service.get_leases_by_status(
        status=lease_status, skip=skip, limit=limit
    )
    return ApiResponse.success(
        data=data,
        message=f"Leases with status '{lease_status.value}' retrieved successfully.",
    )


# ================================================================
# GET /api/leases/tenant/{tenant_id}
# ================================================================

@router.get(
    "/tenant/{tenant_id}",
    response_model=ApiResponse[list[LeaseResponse]],
    status_code=status.HTTP_200_OK,
    summary="Get all leases for a tenant",
    description="Returns the full lease history for a specific tenant. "
                "Includes all statuses. "
                "Accessible by ADMIN,and MANAGE. "
                "TENANT role can only access their own leases via /me.",
)
async def get_leases_by_tenant(
    tenant_id: str = Path(..., description="Tenant MongoDB ObjectId string"),
    skip:  int = Query(default=0,  ge=0),
    limit: int = Query(default=20, ge=1, le=100),
    current_user=Depends(require_roles(
        RoleName.ADMIN, RoleName.MANAGER
    )),
):
    data = await lease_service.get_leases_by_tenant(
        tenant_id=tenant_id, skip=skip, limit=limit
    )
    return ApiResponse.success(
        data=data,
        message="Tenant lease history retrieved successfully.",
    )


# ================================================================
# GET /api/leases/tenant/{tenant_id}/active
# ================================================================

@router.get(
    "/tenant/{tenant_id}/active",
    response_model=ApiResponse[LeaseResponse],
    status_code=status.HTTP_200_OK,
    summary="Get active lease for a tenant",
    description="Returns the currently active lease for a specific tenant. "
                "Raises 404 if no active lease exists. "
                "Accessible by ADMIN, and MANAGER.",
)
async def get_active_lease_by_tenant(
    tenant_id: str = Path(..., description="Tenant MongoDB ObjectId string"),
    current_user=Depends(require_roles(
        RoleName.ADMIN, RoleName.MANAGER
    )),
):
    data = await lease_service.get_active_lease_by_tenant(tenant_id)
    return ApiResponse.success(
        data=data,
        message="Active lease retrieved successfully.",
    )


# ================================================================
# GET /api/leases/room/{room_id}
# ================================================================

@router.get(
    "/room/{room_id}",
    response_model=ApiResponse[list[LeaseResponse]],
    status_code=status.HTTP_200_OK,
    summary="Get all leases for a room",
    description="Returns the full lease history for a specific room. "
                "Accessible by ADMIN, and MANAGER.",
)
async def get_leases_by_room(
    room_id: str = Path(..., description="Room MongoDB ObjectId string"),
    skip:  int = Query(default=0,  ge=0),
    limit: int = Query(default=20, ge=1, le=100),
    current_user=Depends(require_roles(
        RoleName.ADMIN, RoleName.MANAGER
    )),
):
    data = await lease_service.get_leases_by_room(
        room_id=room_id, skip=skip, limit=limit
    )
    return ApiResponse.success(
        data=data,
        message="Room lease history retrieved successfully.",
    )


# ================================================================
# GET /api/leases/room/{room_id}/active
# ================================================================

@router.get(
    "/room/{room_id}/active",
    response_model=ApiResponse[LeaseResponse],
    status_code=status.HTTP_200_OK,
    summary="Get active lease for a room",
    description="Returns the currently active lease for a specific room. "
                "Raises 404 if no active lease exists. "
                "Accessible by ADMIN, and MANAGER.",
)
async def get_active_lease_by_room(
    room_id: str = Path(..., description="Room MongoDB ObjectId string"),
    current_user=Depends(require_roles(
        RoleName.ADMIN, RoleName.MANAGER
    )),
):
    data = await lease_service.get_active_lease_by_room(room_id)
    return ApiResponse.success(
        data=data,
        message="Active room lease retrieved successfully.",
    )


# ================================================================
# GET /api/leases/me  (tenant views their own active lease)
# ================================================================

@router.get(
    "/me",
    response_model=ApiResponse[LeaseResponse],
    status_code=status.HTTP_200_OK,
    summary="Get my active lease",
    description="Returns the currently active lease for the logged-in tenant. "
                "Accessible by TENANT role only.",
)
async def get_my_lease(
    current_user=Depends(require_roles(RoleName.TENANT)),
):
    data = await lease_service.get_active_lease_by_tenant(
        tenant_id=current_user["sub"]
    )
    return ApiResponse.success(
        data=data,
        message="Your active lease retrieved successfully.",
    )


# ================================================================
# GET /api/leases/{lease_id}
# ================================================================

@router.get(
    "/{lease_id}",
    response_model=ApiResponse[LeaseResponse],
    status_code=status.HTTP_200_OK,
    summary="Get lease by ID",
    description="Returns a single lease by its MongoDB ObjectId. "
                "Accessible by ADMIN, and MANAGER.",
)
async def get_lease_by_id(
    lease_id: PydanticObjectId = Path(..., description="Lease MongoDB ObjectId"),
    current_user=Depends(require_roles(
        RoleName.ADMIN, RoleName.MANAGER
    )),
):
    data = await lease_service.get_lease_by_id(lease_id)
    return ApiResponse.success(
        data=data,
        message="Lease retrieved successfully.",
    )


# ================================================================
# PATCH /api/leases/{lease_id}
# ================================================================

@router.patch(
    "/{lease_id}",
    response_model=ApiResponse[LeaseResponse],
    status_code=status.HTTP_200_OK,
    summary="Update lease details",
    description="Partially updates editable lease fields. "
                "Cannot change tenant_id, room_id, start_date, monthly_rate, or status here. "
                "Use /renew for rate changes. "
                "Accessible by ADMIN and MANAGER.",
)
async def update_lease(
    lease_id: PydanticObjectId    = Path(..., description="Lease MongoDB ObjectId"),
    request:  LeaseUpdateRequest  = Body(...),
    current_user=Depends(require_roles(RoleName.ADMIN, RoleName.MANAGER)),
):
    data = await lease_service.update_lease(
        lease_id=lease_id,
        request=request,
        updated_by=current_user["username"],
    )
    return ApiResponse.success(
        data=data,
        message="Lease updated successfully.",
    )


# ================================================================
# PATCH /api/leases/{lease_id}/activate
# ================================================================

@router.patch(
    "/{lease_id}/activate",
    response_model=ApiResponse[LeaseResponse],
    status_code=status.HTTP_200_OK,
    summary="Activate a pending lease",
    description="Manually activates a PENDING lease before its start_date. "
                "Lease must currently be in PENDING status. "
                "Accessible by ADMIN and MANAGER.",
)
async def activate_lease(
    lease_id: PydanticObjectId = Path(..., description="Lease MongoDB ObjectId"),
    current_user=Depends(require_roles(RoleName.ADMIN, RoleName.MANAGER)),
):
    data = await lease_service.activate_lease(
        lease_id=lease_id,
        updated_by=current_user["username"],
    )
    return ApiResponse.success(
        data=data,
        message="Lease activated successfully.",
    )


# ================================================================
# PATCH /api/leases/{lease_id}/renew
# ================================================================

@router.patch(
    "/{lease_id}/renew",
    response_model=ApiResponse[LeaseResponse],
    status_code=status.HTTP_200_OK,
    summary="Renew a lease",
    description="Extends the lease end date and optionally adjusts the monthly rate. "
                "Creates an audit entry in renewal_history. "
                "Lease must be ACTIVE. "
                "Accessible by ADMIN and MANAGER.",
)
async def renew_lease(
    lease_id: PydanticObjectId  = Path(..., description="Lease MongoDB ObjectId"),
    request:  LeaseRenewRequest = Body(...),
    current_user=Depends(require_roles(RoleName.ADMIN, RoleName.MANAGER)),
):
    data = await lease_service.renew_lease(
        lease_id=lease_id,
        request=request,
        updated_by=current_user["username"],
    )
    return ApiResponse.success(
        data=data,
        message="Lease renewed successfully.",
    )


# ================================================================
# PATCH /api/leases/{lease_id}/terminate
# ================================================================

@router.patch(
    "/{lease_id}/terminate",
    response_model=ApiResponse[LeaseResponse],
    status_code=status.HTTP_200_OK,
    summary="Terminate a lease",
    description="Terminates an active or pending lease early. "
                "Automatically vacates the room and unassigns the tenant. "
                "Records termination reason, move-out date, and deposit details. "
                "Accessible by ADMIN and MANAGER.",
)
async def terminate_lease(
    lease_id: PydanticObjectId      = Path(..., description="Lease MongoDB ObjectId"),
    request:  LeaseTerminateRequest = Body(...),
    current_user=Depends(require_roles(RoleName.ADMIN, RoleName.MANAGER)),
):
    data = await lease_service.terminate_lease(
        lease_id=lease_id,
        request=request,
        updated_by=current_user["username"],
    )
    return ApiResponse.success(
        data=data,
        message="Lease terminated successfully.",
    )


# ================================================================
# PATCH /api/leases/{lease_id}/return-deposit
# ================================================================

@router.patch(
    "/{lease_id}/return-deposit",
    response_model=ApiResponse[LeaseResponse],
    status_code=status.HTTP_200_OK,
    summary="Return security deposit",
    description="Records that the security deposit has been returned to the tenant. "
                "Lease must be TERMINATED or EXPIRED. "
                "Deposit cannot be returned more than once. "
                "Accessible by ADMIN and MANAGER.",
)
async def return_deposit(
    lease_id: PydanticObjectId    = Path(..., description="Lease MongoDB ObjectId"),
    request:  DepositReturnRequest = Body(...),
    current_user=Depends(require_roles(RoleName.ADMIN, RoleName.MANAGER)),
):
    data = await lease_service.return_deposit(
        lease_id=lease_id,
        deductions=request.deductions,
        updated_by=current_user["username"],
    )
    return ApiResponse.success(
        data=data,
        message="Security deposit return recorded successfully.",
    )


# ================================================================
# DELETE /api/leases/{lease_id}
# ================================================================

@router.delete(
    "/{lease_id}",
    response_model=ApiResponse[dict],
    status_code=status.HTTP_200_OK,
    summary="Delete lease",
    description="Permanently deletes a lease record. "
                "Lease must NOT be ACTIVE or PENDING. "
                "Use terminate_lease() to end an active lease first. "
                "Prefer keeping records for audit history. "
                "Accessible by ADMIN only.",
)
async def delete_lease(
    lease_id: PydanticObjectId = Path(..., description="Lease MongoDB ObjectId"),
    current_user=Depends(require_roles(RoleName.ADMIN)),
):
    data = await lease_service.delete_lease(lease_id)
    return ApiResponse.success(
        data=data,
        message=data.get("message", "Lease deleted successfully."),
    )