# ============================================================
# services/lease_service.py
# ResidEase – Boarding House Management System
# ============================================================

from beanie import PydanticObjectId
from datetime import datetime, date
from typing import Optional

from models.lease import (
    Lease,
    LeaseStatus,
    LeaseTerminationDetails,
    LeaseRenewalRecord,
    TerminationReason,
    PaymentFrequency,
)
from repository import lease_repository
from services import room_service, tenant_service
from dto.request.lease_request import LeaseCreateRequest, LeaseUpdateRequest, LeaseRenewRequest, LeaseTerminateRequest
from dto.response.lease_response import LeaseResponse
from exception.resource_not_found_exception import ResourceNotFoundException
from exception.bad_request_exception import BadRequestException
from exception.duplicate_resource_exception import DuplicateResourceException


# ================================================================
# INTERNAL HELPERS
# ================================================================

async def _assert_lease_exists(lease_id: PydanticObjectId) -> Lease:
    """Fetches a lease or raises 404."""
    lease = await lease_repository.get_lease_by_id(lease_id)
    if not lease:
        raise ResourceNotFoundException(f"Lease not found: {lease_id}")
    return lease


async def _assert_tenant_has_no_active_lease(tenant_id: str) -> None:
    """
    Raises 400 if the tenant already has an active or pending lease.
    One tenant can only have one active lease at a time.
    """
    existing = await lease_repository.get_active_lease_by_tenant(tenant_id)
    if existing:
        raise BadRequestException(
            f"Tenant already has an active lease: {existing.id}. "
            "Terminate the existing lease before creating a new one."
        )


async def _assert_room_has_no_active_lease(room_id: str) -> None:
    """
    Raises 400 if the room already has an active or pending lease.
    One room can only have one active lease at a time.
    """
    existing = await lease_repository.get_active_lease_by_room(room_id)
    if existing:
        raise BadRequestException(
            f"Room already has an active lease: {existing.id}. "
            "Terminate the existing lease before creating a new one."
        )


def _assert_valid_lease_period(start_date: date, end_date: date) -> None:
    """
    Raises 400 if lease dates are invalid.
    - end_date must be after start_date
    - start_date must not be in the past (more than 7 days ago)
    """
    if end_date <= start_date:
        raise BadRequestException(
            "end_date must be after start_date."
        )

    min_start = date.today().replace(
        day=max(1, date.today().day - 7)
    )
    if start_date < min_start:
        raise BadRequestException(
            "start_date cannot be more than 7 days in the past."
        )


def _assert_lease_is_active(lease: Lease) -> None:
    """Raises 400 if the lease is not currently ACTIVE."""
    if not lease.is_active:
        raise BadRequestException(
            f"Lease {lease.id} is not active. "
            f"Current status: {lease.status.value}."
        )


def _assert_lease_is_active_or_pending(lease: Lease) -> None:
    """Raises 400 if the lease is not ACTIVE or PENDING."""
    if lease.status not in (LeaseStatus.ACTIVE, LeaseStatus.PENDING):
        raise BadRequestException(
            f"Lease {lease.id} cannot be modified. "
            f"Current status: {lease.status.value}."
        )


def _assert_deposit_not_yet_returned(lease: Lease) -> None:
    """Raises 400 if deposit was already returned."""
    if (
        lease.termination_details
        and lease.termination_details.deposit_returned
    ):
        raise BadRequestException(
            f"Deposit for lease {lease.id} has already been returned."
        )


# ================================================================
# CREATE
# ================================================================

async def create_lease(
    request: LeaseCreateRequest,
    created_by: str,
) -> LeaseResponse:
    """
    Creates a new lease and occupies the room.

    Validations:
    - Tenant must exist
    - Room must exist
    - Tenant must not already have an active lease
    - Room must not already have an active lease
    - Lease dates must be valid

    Side effects:
    - Calls room_service.occupy_room()    → sets room to OCCUPIED
    - Calls tenant_service.assign_room_to_tenant() → sets tenant to ACTIVE
    """
    # ── Validate tenant and room exist ────────────────────────
    await tenant_service.get_tenant_by_id(
        PydanticObjectId(request.tenant_id)
    )
    await room_service.get_room_by_id(
        PydanticObjectId(request.room_id)
    )

    # ── Validate no conflicting active leases ─────────────────
    await _assert_tenant_has_no_active_lease(request.tenant_id)
    await _assert_room_has_no_active_lease(request.room_id)

    # ── Validate lease period ─────────────────────────────────
    _assert_valid_lease_period(request.start_date, request.end_date)

    # ── Build lease document ──────────────────────────────────
    lease = Lease(
        tenant_id=request.tenant_id,
        room_id=request.room_id,
        start_date=request.start_date,
        end_date=request.end_date,
        payment_frequency=request.payment_frequency,
        monthly_rate=request.monthly_rate,
        deposit_amount=request.deposit_amount,
        advance_amount=request.advance_amount,
        due_day=request.due_day,
        special_terms=request.special_terms,
        contract_number=request.contract_number,
        auto_renew=request.auto_renew,
        status=LeaseStatus.PENDING,
        created_by=created_by,
        updated_by=created_by,
    )

    created = await lease_repository.create_lease(lease)

    # ── Occupy room and activate tenant ───────────────────────
    await room_service.occupy_room(
        room_id=PydanticObjectId(request.room_id),
        updated_by=created_by,
    )
    await tenant_service.assign_room_to_tenant(
        tenant_id=PydanticObjectId(request.tenant_id),
        room_id=PydanticObjectId(request.room_id),
        move_in_date=datetime.combine(request.start_date, datetime.min.time()),
        updated_by=created_by,
    )

    # ── Activate lease if start date is today or past ─────────
    if request.start_date <= date.today():
        created = await lease_repository.update_lease_status(
            lease_id=created.id,
            status=LeaseStatus.ACTIVE,
            updated_by=created_by,
        )

    return LeaseResponse.from_lease(created)


# ================================================================
# READ
# ================================================================

async def get_all_leases(
    skip: int = 0,
    limit: int = 20,
) -> list[LeaseResponse]:
    """Returns a paginated list of all leases."""
    leases = await lease_repository.get_all_leases(skip=skip, limit=limit)
    return [LeaseResponse.from_lease(l) for l in leases]


async def get_lease_by_id(lease_id: PydanticObjectId) -> LeaseResponse:
    """
    Returns a single lease by ID.
    Raises 404 if not found.
    """
    lease = await _assert_lease_exists(lease_id)
    return LeaseResponse.from_lease(lease)


async def get_leases_by_tenant(
    tenant_id: str,
    skip: int = 0,
    limit: int = 20,
) -> list[LeaseResponse]:
    """
    Returns all leases for a specific tenant (full history).
    Includes ACTIVE, EXPIRED, TERMINATED, and RENEWED leases.
    """
    leases = await lease_repository.get_leases_by_tenant(
        tenant_id=tenant_id, skip=skip, limit=limit
    )
    return [LeaseResponse.from_lease(l) for l in leases]


async def get_leases_by_room(
    room_id: str,
    skip: int = 0,
    limit: int = 20,
) -> list[LeaseResponse]:
    """
    Returns all leases for a specific room (full history).
    """
    leases = await lease_repository.get_leases_by_room(
        room_id=room_id, skip=skip, limit=limit
    )
    return [LeaseResponse.from_lease(l) for l in leases]


async def get_active_lease_by_tenant(tenant_id: str) -> LeaseResponse:
    """
    Returns the currently active lease for a tenant.
    Raises 404 if no active lease exists.
    """
    lease = await lease_repository.get_active_lease_by_tenant(tenant_id)
    if not lease:
        raise ResourceNotFoundException(
            f"No active lease found for tenant: {tenant_id}"
        )
    return LeaseResponse.from_lease(lease)


async def get_active_lease_by_room(room_id: str) -> LeaseResponse:
    """
    Returns the currently active lease for a room.
    Raises 404 if no active lease exists.
    """
    lease = await lease_repository.get_active_lease_by_room(room_id)
    if not lease:
        raise ResourceNotFoundException(
            f"No active lease found for room: {room_id}"
        )
    return LeaseResponse.from_lease(lease)


async def get_leases_by_status(
    status: LeaseStatus,
    skip: int = 0,
    limit: int = 20,
) -> list[LeaseResponse]:
    """Returns leases filtered by status."""
    leases = await lease_repository.get_leases_by_status(
        status=status, skip=skip, limit=limit
    )
    return [LeaseResponse.from_lease(l) for l in leases]


async def get_expiring_leases(
    days_ahead: int = 30,
    skip: int = 0,
    limit: int = 20,
) -> list[LeaseResponse]:
    """
    Returns active leases expiring within the given number of days.
    Used by the dashboard expiring-soon alert and scheduler.
    Raises 400 if days_ahead is less than 1.
    """
    if days_ahead < 1:
        raise BadRequestException("days_ahead must be at least 1.")

    leases = await lease_repository.get_expiring_leases(
        days_ahead=days_ahead, skip=skip, limit=limit
    )
    return [LeaseResponse.from_lease(l) for l in leases]


async def get_lease_stats() -> dict:
    """
    Returns lease counts grouped by status.
    Used by DashboardService for the stats grid.
    """
    total      = await lease_repository.count_all_leases()
    active     = await lease_repository.count_leases_by_status(LeaseStatus.ACTIVE)
    pending    = await lease_repository.count_leases_by_status(LeaseStatus.PENDING)
    expired    = await lease_repository.count_leases_by_status(LeaseStatus.EXPIRED)
    terminated = await lease_repository.count_leases_by_status(LeaseStatus.TERMINATED)
    renewed    = await lease_repository.count_leases_by_status(LeaseStatus.RENEWED)
    expiring   = await lease_repository.count_expiring_leases(days_ahead=30)

    return {
        "total":           total,
        "active":          active,
        "pending":         pending,
        "expired":         expired,
        "terminated":      terminated,
        "renewed":         renewed,
        "expiring_soon":   expiring,
    }


# ================================================================
# UPDATE
# ================================================================

async def update_lease(
    lease_id: PydanticObjectId,
    request: LeaseUpdateRequest,
    updated_by: str,
) -> LeaseResponse:
    """
    Partially updates a lease's editable fields.
    Only PENDING or ACTIVE leases can be updated.
    monthly_rate, tenant_id, and room_id cannot be changed here —
    use renew_lease() for rate changes.
    """
    lease = await _assert_lease_exists(lease_id)
    _assert_lease_is_active_or_pending(lease)

    updates: dict = {}

    if request.end_date is not None:
        if request.end_date <= lease.start_date:
            raise BadRequestException(
                "end_date must be after the lease start_date."
            )
        updates["end_date"] = request.end_date

    if request.due_day is not None:
        updates["due_day"] = request.due_day

    if request.payment_frequency is not None:
        updates["payment_frequency"] = request.payment_frequency

    if request.special_terms is not None:
        updates["special_terms"] = request.special_terms

    if request.contract_number is not None:
        updates["contract_number"] = request.contract_number

    if request.auto_renew is not None:
        updates["auto_renew"] = request.auto_renew

    if request.is_expiring_soon is not None:
        updates["is_expiring_soon"] = request.is_expiring_soon

    if not updates:
        raise BadRequestException(
            "No valid fields provided for update."
        )

    updated = await lease_repository.update_lease(
        lease_id=lease_id,
        updates=updates,
        updated_by=updated_by,
    )
    return LeaseResponse.from_lease(updated)


async def activate_lease(
    lease_id: PydanticObjectId,
    updated_by: str,
) -> LeaseResponse:
    """
    Activates a PENDING lease manually.
    Used when the start_date is in the future and
    admin wants to activate it early.

    Validations:
    - Lease must be in PENDING status
    """
    lease = await _assert_lease_exists(lease_id)

    if not lease.is_pending:
        raise BadRequestException(
            f"Only PENDING leases can be activated. "
            f"Current status: {lease.status.value}."
        )

    updated = await lease_repository.update_lease_status(
        lease_id=lease_id,
        status=LeaseStatus.ACTIVE,
        updated_by=updated_by,
    )
    return LeaseResponse.from_lease(updated)


# ================================================================
# RENEWAL
# ================================================================

async def renew_lease(
    lease_id: PydanticObjectId,
    request: LeaseRenewRequest,
    updated_by: str,
) -> LeaseResponse:
    """
    Renews an active lease with a new end date and optional rate change.

    Validations:
    - Lease must be ACTIVE
    - New end date must be after current end date
    - New monthly rate must be > 0 if provided

    Side effects:
    - Appends a LeaseRenewalRecord to renewal_history
    - Updates monthly_rate if a new rate is provided
    - Sets status to ACTIVE (resets EXPIRING_SOON flag)
    """
    lease = await _assert_lease_exists(lease_id)
    _assert_lease_is_active(lease)

    if request.new_end_date <= lease.end_date:
        raise BadRequestException(
            f"new_end_date must be after the current end_date "
            f"({lease.end_date})."
        )

    if request.new_monthly_rate is not None and request.new_monthly_rate <= 0:
        raise BadRequestException(
            "new_monthly_rate must be greater than zero."
        )

    renewal_record = LeaseRenewalRecord(
        renewed_by=updated_by,
        previous_end_date=lease.end_date,
        new_end_date=request.new_end_date,
        new_monthly_rate=request.new_monthly_rate,
        notes=request.notes,
    )

    updates: dict = {
        "end_date":         request.new_end_date,
        "status":           LeaseStatus.ACTIVE,
        "is_expiring_soon": False,
    }

    if request.new_monthly_rate is not None:
        updates["monthly_rate"] = request.new_monthly_rate

    if request.due_day is not None:
        updates["due_day"] = request.due_day

    updated = await lease_repository.renew_lease(
        lease_id=lease_id,
        updates=updates,
        renewal_record=renewal_record,
        updated_by=updated_by,
    )
    return LeaseResponse.from_lease(updated)


# ================================================================
# TERMINATION
# ================================================================

async def terminate_lease(
    lease_id: PydanticObjectId,
    request: LeaseTerminateRequest,
    updated_by: str,
) -> LeaseResponse:
    """
    Terminates an active or pending lease early.

    Validations:
    - Lease must be ACTIVE or PENDING
    - Termination reason must be provided

    Side effects:
    - Sets lease status to TERMINATED
    - Embeds LeaseTerminationDetails
    - Calls room_service.vacate_room()
    - Calls tenant_service.unassign_room_from_tenant()
    """
    lease = await _assert_lease_exists(lease_id)
    _assert_lease_is_active_or_pending(lease)

    termination = LeaseTerminationDetails(
        reason=request.reason,
        terminated_by=updated_by,
        terminated_at=datetime.utcnow(),
        notes=request.notes,
        deposit_returned=request.deposit_returned,
        deposit_deductions=request.deposit_deductions,
        deposit_returned_amount=max(
            0.0,
            lease.deposit_amount - request.deposit_deductions
        ),
    )

    updated = await lease_repository.terminate_lease(
        lease_id=lease_id,
        termination_details=termination,
        updated_by=updated_by,
    )

    # ── Vacate room and unassign tenant ───────────────────────
    move_out = datetime.combine(
        request.move_out_date or date.today(),
        datetime.min.time()
    )

    await room_service.vacate_room(
        room_id=PydanticObjectId(lease.room_id),
        updated_by=updated_by,
    )
    await tenant_service.unassign_room_from_tenant(
        tenant_id=PydanticObjectId(lease.tenant_id),
        move_out_date=move_out,
        updated_by=updated_by,
    )

    return LeaseResponse.from_lease(updated)


async def expire_lease(
    lease_id: PydanticObjectId,
    updated_by: str,
) -> LeaseResponse:
    """
    Marks an active lease as EXPIRED when its end_date has passed.
    Called by the scheduler — not exposed as a controller endpoint.

    Side effects:
    - Sets lease status to EXPIRED
    - Calls room_service.vacate_room()
    - Calls tenant_service.unassign_room_from_tenant()
    """
    lease = await _assert_lease_exists(lease_id)

    if not lease.is_active:
        raise BadRequestException(
            f"Only ACTIVE leases can be expired. "
            f"Current status: {lease.status.value}."
        )

    if lease.end_date > date.today():
        raise BadRequestException(
            f"Lease {lease_id} has not yet reached its end_date "
            f"({lease.end_date}). Cannot expire a lease early — "
            "use terminate_lease() instead."
        )

    updated = await lease_repository.update_lease_status(
        lease_id=lease_id,
        status=LeaseStatus.EXPIRED,
        updated_by=updated_by,
    )

    await room_service.vacate_room(
        room_id=PydanticObjectId(lease.room_id),
        updated_by=updated_by,
    )
    await tenant_service.unassign_room_from_tenant(
        tenant_id=PydanticObjectId(lease.tenant_id),
        move_out_date=datetime.utcnow(),
        updated_by=updated_by,
    )

    return LeaseResponse.from_lease(updated)


# ================================================================
# DEPOSIT
# ================================================================

async def return_deposit(
    lease_id: PydanticObjectId,
    deductions: float,
    updated_by: str,
) -> LeaseResponse:
    """
    Records that the security deposit has been returned to the tenant.

    Validations:
    - Lease must be TERMINATED or EXPIRED
    - Deposit must not have already been returned
    - Deductions cannot exceed the original deposit amount

    Updates:
    - termination_details.deposit_returned = True
    - termination_details.deposit_deductions = deductions
    - termination_details.deposit_returned_amount = deposit - deductions
    """
    lease = await _assert_lease_exists(lease_id)

    if lease.status not in (LeaseStatus.TERMINATED, LeaseStatus.EXPIRED):
        raise BadRequestException(
            "Deposit can only be returned for TERMINATED or EXPIRED leases."
        )

    _assert_deposit_not_yet_returned(lease)

    if deductions < 0:
        raise BadRequestException(
            "Deposit deductions cannot be negative."
        )

    if deductions > lease.deposit_amount:
        raise BadRequestException(
            f"Deductions (₱{deductions:,.2f}) cannot exceed "
            f"the original deposit (₱{lease.deposit_amount:,.2f})."
        )

    returned_amount = round(lease.deposit_amount - deductions, 2)

    updated = await lease_repository.update_deposit_return(
        lease_id=lease_id,
        deductions=deductions,
        returned_amount=returned_amount,
        updated_by=updated_by,
    )
    return LeaseResponse.from_lease(updated)


# ================================================================
# FINANCIAL  (called by PaymentService — not from controllers)
# ================================================================

async def update_lease_balance(
    lease_id: PydanticObjectId,
    outstanding_balance: float,
    total_paid: float,
) -> LeaseResponse:
    """
    Updates the lease's financial summary.
    Called exclusively by PaymentService and BillingService.
    Do NOT call this from a controller.
    """
    await _assert_lease_exists(lease_id)

    if outstanding_balance < 0:
        raise BadRequestException(
            "outstanding_balance cannot be negative."
        )

    if total_paid < 0:
        raise BadRequestException(
            "total_paid cannot be negative."
        )

    updated = await lease_repository.update_balance(
        lease_id=lease_id,
        outstanding_balance=outstanding_balance,
        total_paid=total_paid,
    )
    return LeaseResponse.from_lease(updated)


# ================================================================
# DELETE
# ================================================================

async def delete_lease(lease_id: PydanticObjectId) -> dict:
    """
    Hard deletes a lease record.

    WARNING: Never delete an ACTIVE lease.
    Use terminate_lease() instead.
    Only use for test data cleanup or admin corrections.

    Validations:
    - Lease must exist
    - Lease must NOT be ACTIVE or PENDING
    """
    lease = await _assert_lease_exists(lease_id)

    if lease.status in (LeaseStatus.ACTIVE, LeaseStatus.PENDING):
        raise BadRequestException(
            f"Cannot delete an {lease.status.value} lease. "
            "Use terminate_lease() to end it first."
        )

    deleted = await lease_repository.delete_lease(lease_id)
    if not deleted:
        raise ResourceNotFoundException(f"Lease not found: {lease_id}")

    return {"message": f"Lease {lease_id} has been permanently deleted."}