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
)
async def create_lease(
    request: LeaseCreateRequest = Body(...),
    current_user=Depends(require_roles(RoleName.ADMIN, RoleName.MANAGER)),
):
    data = await lease_service.create_lease(
        request=request,
        created_by=current_user.username,        # ✅ fixed
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
)
async def get_all_leases(
    skip:  int = Query(default=0,  ge=0),
    limit: int = Query(default=20, ge=1, le=100),
    current_user=Depends(require_roles(RoleName.ADMIN, RoleName.MANAGER)),
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
)
async def get_leases_by_status(
    lease_status: LeaseStatus = Path(..., description="Lease status filter"),
    skip:  int = Query(default=0,  ge=0),
    limit: int = Query(default=20, ge=1, le=100),
    current_user=Depends(require_roles(RoleName.ADMIN, RoleName.MANAGER)),
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
)
async def get_leases_by_tenant(
    tenant_id: str = Path(..., description="Tenant MongoDB ObjectId string"),
    skip:  int = Query(default=0,  ge=0),
    limit: int = Query(default=20, ge=1, le=100),
    current_user=Depends(require_roles(RoleName.ADMIN, RoleName.MANAGER)),
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
)
async def get_active_lease_by_tenant(
    tenant_id: str = Path(..., description="Tenant MongoDB ObjectId string"),
    current_user=Depends(require_roles(RoleName.ADMIN, RoleName.MANAGER)),
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
)
async def get_leases_by_room(
    room_id: str = Path(..., description="Room MongoDB ObjectId string"),
    skip:  int = Query(default=0,  ge=0),
    limit: int = Query(default=20, ge=1, le=100),
    current_user=Depends(require_roles(RoleName.ADMIN, RoleName.MANAGER)),
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
)
async def get_active_lease_by_room(
    room_id: str = Path(..., description="Room MongoDB ObjectId string"),
    current_user=Depends(require_roles(RoleName.ADMIN, RoleName.MANAGER)),
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
)
async def get_my_lease(
    current_user=Depends(require_roles(RoleName.TENANT)),
):
    data = await lease_service.get_active_lease_by_tenant(
        tenant_id=str(current_user.id)           # ✅ fixed
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
)
async def get_lease_by_id(
    lease_id: PydanticObjectId = Path(..., description="Lease MongoDB ObjectId"),
    current_user=Depends(require_roles(RoleName.ADMIN, RoleName.MANAGER)),
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
)
async def update_lease(
    lease_id: PydanticObjectId   = Path(..., description="Lease MongoDB ObjectId"),
    request:  LeaseUpdateRequest = Body(...),
    current_user=Depends(require_roles(RoleName.ADMIN, RoleName.MANAGER)),
):
    data = await lease_service.update_lease(
        lease_id=lease_id,
        request=request,
        updated_by=current_user.username,        # ✅ fixed
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
)
async def activate_lease(
    lease_id: PydanticObjectId = Path(..., description="Lease MongoDB ObjectId"),
    current_user=Depends(require_roles(RoleName.ADMIN, RoleName.MANAGER)),
):
    data = await lease_service.activate_lease(
        lease_id=lease_id,
        updated_by=current_user.username,        # ✅ fixed
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
)
async def renew_lease(
    lease_id: PydanticObjectId  = Path(..., description="Lease MongoDB ObjectId"),
    request:  LeaseRenewRequest = Body(...),
    current_user=Depends(require_roles(RoleName.ADMIN, RoleName.MANAGER)),
):
    data = await lease_service.renew_lease(
        lease_id=lease_id,
        request=request,
        updated_by=current_user.username,        # ✅ fixed
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
)
async def terminate_lease(
    lease_id: PydanticObjectId      = Path(..., description="Lease MongoDB ObjectId"),
    request:  LeaseTerminateRequest = Body(...),
    current_user=Depends(require_roles(RoleName.ADMIN, RoleName.MANAGER)),
):
    data = await lease_service.terminate_lease(
        lease_id=lease_id,
        request=request,
        updated_by=current_user.username,        # ✅ fixed
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
)
async def return_deposit(
    lease_id: PydanticObjectId     = Path(..., description="Lease MongoDB ObjectId"),
    request:  DepositReturnRequest = Body(...),
    current_user=Depends(require_roles(RoleName.ADMIN, RoleName.MANAGER)),
):
    data = await lease_service.return_deposit(
        lease_id=lease_id,
        deductions=request.deductions,
        updated_by=current_user.username,        # ✅ fixed
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