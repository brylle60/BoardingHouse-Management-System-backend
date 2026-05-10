from beanie import PydanticObjectId
from datetime import datetime
from typing import Optional

from fastapi import HTTPException

from models.booking_request import BookingRequest, BookingStatus
from models.lease import Lease, LeaseStatus
from models.tenant import (
    Tenant,
    TenantStatus,
    GovernmentID,
    EmergencyContact,
    Address,
)
from models.room import Room, RoomStatus
from repository import tenant_repository, room_repository, user_repository
from dto.request.tenant_request import TenantCreateRequest, TenantUpdateRequest
from dto.response.tenant_response import TenantResponse, to_tenant_response, to_tenant_summary
from exception.resource_not_found_exception import ResourceNotFoundException
from exception.bad_request_exception import BadRequestException
from exception.duplicate_resource_exception import DuplicateResourceException


# ================================================================
# INTERNAL HELPERS  (private — not called from controllers)
# ================================================================

async def _assert_tenant_exists(tenant_id: PydanticObjectId) -> Tenant:
    tenant = await tenant_repository.get_tenant_by_id(tenant_id)
    if not tenant:
        raise ResourceNotFoundException(f"Tenant not found: {tenant_id}")
    return tenant


async def _assert_no_duplicate_email(email: str, exclude_id: Optional[PydanticObjectId] = None) -> None:
    existing = await tenant_repository.get_tenant_by_email(email)
    if existing and existing.id != exclude_id:
        raise DuplicateResourceException(f"Email already registered to another tenant: {email}")


async def _assert_no_duplicate_phone(phone: str, exclude_id: Optional[PydanticObjectId] = None) -> None:
    existing = await tenant_repository.get_tenant_by_phone(phone)
    if existing and existing.id != exclude_id:
        raise DuplicateResourceException(f"Phone already registered to another tenant: {phone}")


async def _assert_room_is_vacant(room_id: PydanticObjectId) -> None:
    occupant = await tenant_repository.get_tenant_by_room(room_id)
    if occupant:
        raise BadRequestException(
            f"Room {room_id} is already occupied by tenant: {occupant.full_name}"
        )


async def _assert_room_exists(room_id: PydanticObjectId) -> None:
    room = await room_repository.get_room_by_id(room_id)
    if not room:
        raise ResourceNotFoundException(f"Room not found: {room_id}")


async def _assert_user_exists(user_id: PydanticObjectId) -> None:
    user = await user_repository.get_user_by_id(user_id)
    if not user:
        raise ResourceNotFoundException(f"User not found: {user_id}")


async def _assert_no_existing_tenant_profile(user_id: PydanticObjectId) -> None:
    existing = await tenant_repository.get_tenant_by_user_id(user_id)
    if existing:
        raise BadRequestException(
            f"A tenant profile already exists for user: {user_id}"
        )


def _build_tenant_from_request(
    request: TenantCreateRequest,
    created_by: str
) -> Tenant:
    government_id = None
    if request.government_id:
        government_id = GovernmentID(
            id_type=request.government_id.id_type,
            id_number=request.government_id.id_number,
            issued_date=request.government_id.issued_date,
            expiry_date=request.government_id.expiry_date,
        )

    emergency_contact = None
    if request.emergency_contact:
        emergency_contact = EmergencyContact(
            full_name=request.emergency_contact.full_name,
            phone=request.emergency_contact.phone,
            relationship=request.emergency_contact.relationship,
            email=request.emergency_contact.email,
            address=request.emergency_contact.address,
        )

    home_address = None
    if request.home_address:
        home_address = Address(
            street=request.home_address.street,
            barangay=request.home_address.barangay,
            city=request.home_address.city,
            province=request.home_address.province,
            zip_code=request.home_address.zip_code,
            country=request.home_address.country,
        )

    return Tenant(
        user_id=request.user_id,
        first_name=request.first_name,
        last_name=request.last_name,
        middle_name=request.middle_name,
        date_of_birth=request.date_of_birth,
        gender=request.gender,
        civil_status=request.civil_status,
        nationality=request.nationality,
        phone=request.phone,
        email=request.email,
        occupation=request.occupation,
        employer=request.employer,
        monthly_income=request.monthly_income,
        government_id=government_id,
        emergency_contact=emergency_contact,
        home_address=home_address,
        status=TenantStatus.PENDING,
        created_by=created_by,
        updated_by=created_by,
    )


# ================================================================
# CREATE
# ================================================================

async def register_tenant(
    request: TenantCreateRequest,
    created_by: str
) -> TenantResponse:
    await _assert_user_exists(request.user_id)
    await _assert_no_existing_tenant_profile(request.user_id)
    await _assert_no_duplicate_email(request.email)
    await _assert_no_duplicate_phone(request.phone)

    tenant = _build_tenant_from_request(request, created_by)
    created = await tenant_repository.create_tenant(tenant)
    return to_tenant_response(created)


# ================================================================
# READ
# ================================================================

async def get_all_tenants(
    skip: int = 0,
    limit: int = 20
) -> list[TenantResponse]:
    tenants = await tenant_repository.get_all_tenants(skip=skip, limit=limit)
    return [to_tenant_response(t) for t in tenants]


async def get_tenant_by_id(tenant_id: PydanticObjectId) -> TenantResponse:
    tenant = await _assert_tenant_exists(tenant_id)
    return to_tenant_response(tenant)


async def get_tenant_by_user_id(user_id: PydanticObjectId) -> TenantResponse:
    tenant = await tenant_repository.get_tenant_by_user_id(user_id)
    if not tenant:
        raise ResourceNotFoundException(f"No tenant profile found for user: {user_id}")
    return to_tenant_response(tenant)


async def get_tenants_by_status(
    status: TenantStatus,
    skip: int = 0,
    limit: int = 20
) -> list[TenantResponse]:
    tenants = await tenant_repository.get_tenants_by_status(
        status=status, skip=skip, limit=limit
    )
    return [to_tenant_response(t) for t in tenants]


async def get_tenants_with_outstanding_balance(
    skip: int = 0,
    limit: int = 20
) -> list[TenantResponse]:
    tenants = await tenant_repository.get_tenants_with_outstanding_balance(
        skip=skip, limit=limit
    )
    return [to_tenant_response(t) for t in tenants]


async def get_unverified_tenants(
    skip: int = 0,
    limit: int = 20
) -> list[TenantResponse]:
    tenants = await tenant_repository.get_unverified_tenants(
        skip=skip, limit=limit
    )
    return [to_tenant_response(t) for t in tenants]


async def search_tenants(
    query: str,
    skip: int = 0,
    limit: int = 20
) -> list[TenantResponse]:
    if not query or not query.strip():
        raise BadRequestException("Search query must not be empty.")

    tenants = await tenant_repository.search_tenants(
        query=query.strip(), skip=skip, limit=limit
    )
    return [to_tenant_response(t) for t in tenants]


async def get_tenant_stats() -> dict:
    total     = await tenant_repository.count_all_tenants()
    active    = await tenant_repository.count_tenants_by_status(TenantStatus.ACTIVE)
    pending   = await tenant_repository.count_tenants_by_status(TenantStatus.PENDING)
    inactive  = await tenant_repository.count_tenants_by_status(TenantStatus.INACTIVE)
    moved_out = await tenant_repository.count_tenants_by_status(TenantStatus.MOVED_OUT)

    return {
        "total":     total,
        "active":    active,
        "pending":   pending,
        "inactive":  inactive,
        "moved_out": moved_out,
    }


# ================================================================
# UPDATE
# ================================================================

async def update_tenant(
    tenant_id: PydanticObjectId,
    request: TenantUpdateRequest,
    updated_by: str
) -> TenantResponse:
    tenant = await _assert_tenant_exists(tenant_id)

    updates: dict = {}

    if request.first_name     is not None: updates["first_name"]     = request.first_name
    if request.last_name      is not None: updates["last_name"]      = request.last_name
    if request.middle_name    is not None: updates["middle_name"]    = request.middle_name
    if request.date_of_birth  is not None: updates["date_of_birth"]  = request.date_of_birth
    if request.gender         is not None: updates["gender"]         = request.gender
    if request.civil_status   is not None: updates["civil_status"]   = request.civil_status
    if request.nationality    is not None: updates["nationality"]    = request.nationality
    if request.occupation     is not None: updates["occupation"]     = request.occupation
    if request.employer       is not None: updates["employer"]       = request.employer
    if request.monthly_income is not None: updates["monthly_income"] = request.monthly_income
    if request.notes          is not None: updates["notes"]          = request.notes

    if request.phone is not None and request.phone != tenant.phone:
        await _assert_no_duplicate_phone(request.phone, exclude_id=tenant_id)
        updates["phone"] = request.phone

    if request.email is not None and request.email != tenant.email:
        await _assert_no_duplicate_email(request.email, exclude_id=tenant_id)
        updates["email"] = request.email

    if request.home_address is not None:
        updates["home_address"] = Address(
            street=request.home_address.street,
            barangay=request.home_address.barangay,
            city=request.home_address.city,
            province=request.home_address.province,
            zip_code=request.home_address.zip_code,
            country=request.home_address.country,
        ).model_dump()

    if request.emergency_contact is not None:
        updates["emergency_contact"] = EmergencyContact(
            full_name=request.emergency_contact.full_name,
            phone=request.emergency_contact.phone,
            relationship=request.emergency_contact.relationship,
            email=request.emergency_contact.email,
            address=request.emergency_contact.address,
        ).model_dump()

    if request.government_id is not None:
        updates["government_id"] = GovernmentID(
            id_type=request.government_id.id_type,
            id_number=request.government_id.id_number,
            issued_date=request.government_id.issued_date,
            expiry_date=request.government_id.expiry_date,
            verified=False,
            verified_by=None,
            verified_at=None,
        ).model_dump()

    if not updates:
        raise BadRequestException("No valid fields provided for update.")

    updated = await tenant_repository.update_tenant(
        tenant_id=tenant_id,
        updates=updates,
        updated_by=updated_by
    )
    return to_tenant_response(updated)


async def update_tenant_status(
    tenant_id: PydanticObjectId,
    status: TenantStatus,
    updated_by: str
) -> TenantResponse:
    tenant = await _assert_tenant_exists(tenant_id)

    if status == TenantStatus.ACTIVE and not tenant.is_occupying:
        raise BadRequestException(
            "Cannot set tenant to ACTIVE without an assigned room. "
            "Use assign_room_to_tenant() instead."
        )

    if status == TenantStatus.PENDING and tenant.is_occupying:
        raise BadRequestException(
            "Cannot set an occupying tenant back to PENDING. "
            "Unassign their room first."
        )

    updated = await tenant_repository.update_tenant_status(
        tenant_id=tenant_id,
        status=status,
        updated_by=updated_by
    )
    return to_tenant_response(updated)


async def update_profile_picture(
    tenant_id: PydanticObjectId,
    filepath_or_url: str,
    updated_by: str
) -> TenantResponse:
    await _assert_tenant_exists(tenant_id)

    updated = await tenant_repository.update_profile_picture(
        tenant_id=tenant_id,
        filepath_or_url=filepath_or_url,
        updated_by=updated_by
    )
    return to_tenant_response(updated)


# ================================================================
# ROOM ASSIGNMENT
# ================================================================

async def assign_room_to_tenant(
    tenant_id: PydanticObjectId,
    room_id: PydanticObjectId,
    move_in_date: datetime,
    updated_by: str
) -> TenantResponse:
    tenant = await _assert_tenant_exists(tenant_id)

    if tenant.is_occupying:
        raise BadRequestException(
            f"Tenant {tenant.full_name} is already assigned to a room. "
            "Unassign current room before reassigning."
        )

    await _assert_room_exists(room_id)
    await _assert_room_is_vacant(room_id)

    updated = await tenant_repository.assign_room(
        tenant_id=tenant_id,
        room_id=room_id,
        move_in_date=move_in_date,
        updated_by=updated_by
    )
    return to_tenant_response(updated)


async def unassign_room_from_tenant(
    tenant_id: PydanticObjectId,
    move_out_date: datetime,
    updated_by: str
) -> TenantResponse:
    tenant = await _assert_tenant_exists(tenant_id)

    if not tenant.is_occupying:
        raise BadRequestException(
            f"Tenant {tenant.full_name} is not currently assigned to any room."
        )

    updated = await tenant_repository.unassign_room(
        tenant_id=tenant_id,
        move_out_date=move_out_date,
        updated_by=updated_by
    )
    return to_tenant_response(updated)


# ================================================================
# FINANCIAL
# ================================================================

async def record_deposit_payment(
    tenant_id: PydanticObjectId,
    amount: float,
    deposit_date: datetime,
    updated_by: str
) -> TenantResponse:
    tenant = await _assert_tenant_exists(tenant_id)

    if tenant.deposit_paid:
        raise BadRequestException(
            f"Deposit already recorded for tenant: {tenant.full_name}"
        )

    if amount <= 0:
        raise BadRequestException("Deposit amount must be greater than zero.")

    updated = await tenant_repository.record_deposit(
        tenant_id=tenant_id,
        amount=amount,
        deposit_date=deposit_date,
        updated_by=updated_by
    )
    return to_tenant_response(updated)


async def update_tenant_balance(
    tenant_id: PydanticObjectId,
    outstanding_balance: float,
    total_paid: float
) -> TenantResponse:
    await _assert_tenant_exists(tenant_id)

    if outstanding_balance < 0:
        raise BadRequestException("Outstanding balance cannot be negative.")

    if total_paid < 0:
        raise BadRequestException("Total paid cannot be negative.")

    updated = await tenant_repository.update_balance(
        tenant_id=tenant_id,
        outstanding_balance=outstanding_balance,
        total_paid=total_paid
    )
    return to_tenant_response(updated)


# ================================================================
# ID VERIFICATION
# ================================================================

async def verify_tenant_id(
    tenant_id: PydanticObjectId,
    verified_by: str
) -> TenantResponse:
    tenant = await _assert_tenant_exists(tenant_id)

    if not tenant.government_id:
        raise BadRequestException(
            f"Tenant {tenant.full_name} has not submitted a government ID."
        )

    if tenant.is_id_verified:
        raise BadRequestException(
            f"Government ID for tenant {tenant.full_name} is already verified."
        )

    updated = await tenant_repository.verify_government_id(
        tenant_id=tenant_id,
        verified_by=verified_by
    )
    return to_tenant_response(updated)


# ================================================================
# DELETE
# ================================================================

async def delete_tenant(tenant_id: PydanticObjectId) -> dict:
    tenant = await _assert_tenant_exists(tenant_id)

    if tenant.is_occupying:
        raise BadRequestException(
            f"Cannot delete tenant {tenant.full_name} while they are assigned to a room. "
            "Unassign the room first."
        )

    if tenant.has_outstanding_balance:
        raise BadRequestException(
            f"Cannot delete tenant {tenant.full_name} with an outstanding balance "
            f"of ₱{tenant.outstanding_balance:,.2f}. Settle the balance first."
        )

    deleted = await tenant_repository.delete_tenant(tenant_id)
    if not deleted:
        raise ResourceNotFoundException(f"Tenant not found: {tenant_id}")

    return {"message": f"Tenant {tenant.full_name} has been permanently deleted."}


# ================================================================
# UNASSIGN  (manager removes tenant from room — full cleanup)
#
# FIX: The old version deleted bookings by email which is unreliable.
#      Now deletes by user_id (the correct foreign key), terminates
#      any active leases, resets the room occupant count, and deletes
#      the tenant profile — leaving the User account intact so the
#      person can log in and book again.
# ================================================================

async def unassign_tenant(
    tenant_id: PydanticObjectId,
    updated_by: str,
) -> dict:
    """
    Full cleanup when a manager unassigns a tenant:
      1. Set the room back to VACANT and reset occupant count
      2. Terminate any active leases for this tenant
      3. Delete ALL booking records for this user_id (not email!)
      4. Delete the tenant profile
      → The User account is preserved so they can book again.
    """
    tenant = await Tenant.get(tenant_id)
    if not tenant:
        raise HTTPException(status_code=404, detail="Tenant not found")

    full_name = tenant.full_name
    user_id   = tenant.user_id   # preserve before deletion
    room_id   = tenant.room_id   # preserve before deletion

    # ── 1. Free the room ─────────────────────────────────────────
    if room_id:
        room = await Room.get(PydanticObjectId(room_id))
        if room:
            room.status = RoomStatus.VACANT
            # Reset occupant count safely
            room.current_occupants = max(0, (room.current_occupants or 1) - 1)
            room.updated_at = datetime.utcnow()
            await room.save()

    # ── 2. Terminate active leases ───────────────────────────────
    # Leaves a history record — just marks them TERMINATED
    active_leases = await Lease.find(
        Lease.tenant_id == str(tenant_id),
        Lease.status    == LeaseStatus.ACTIVE,
    ).to_list()
    for lease in active_leases:
        lease.status     = LeaseStatus.TERMINATED
        lease.updated_at = datetime.utcnow()
        await lease.save()

    # ── 3. Delete ALL booking records for this user ───────────────
    # Uses user_id (not email) — the correct and stable foreign key.
    # This clears PENDING, APPROVED, CONFIRMED, and REJECTED bookings
    # so the user can submit a fresh booking without conflicts.
    if user_id:
        await BookingRequest.find(
            BookingRequest.user_id == str(user_id)
        ).delete()

    # ── 4. Delete the tenant profile ─────────────────────────────
    # The User account (login) is NOT touched — they can book again.
    await tenant.delete()

    return {
        "message": (
            f"Tenant {full_name} has been unassigned. "
            "Room is now vacant and the user can book again."
        )
    }