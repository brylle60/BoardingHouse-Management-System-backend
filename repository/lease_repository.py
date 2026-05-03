# ============================================================
# repository/lease_repository.py
# ResidEase – Boarding House Management System
# ============================================================

from beanie import PydanticObjectId
from beanie.operators import Set
from typing import Optional
from datetime import datetime, date, timedelta

from models.lease import Lease, LeaseStatus, LeaseTerminationDetails, LeaseRenewalRecord


# ================================================================
# READ
# ================================================================

async def get_all_leases(
    skip: int = 0,
    limit: int = 20,
) -> list[Lease]:
    return await Lease.find_all().skip(skip).limit(limit).to_list()


async def get_lease_by_id(lease_id: PydanticObjectId) -> Optional[Lease]:
    return await Lease.get(lease_id)


async def get_leases_by_tenant(
    tenant_id: str,
    skip: int = 0,
    limit: int = 20,
) -> list[Lease]:
    return await Lease.find(
        Lease.tenant_id == tenant_id
    ).skip(skip).limit(limit).to_list()


async def get_leases_by_room(
    room_id: str,
    skip: int = 0,
    limit: int = 20,
) -> list[Lease]:
    return await Lease.find(
        Lease.room_id == room_id
    ).skip(skip).limit(limit).to_list()


async def get_active_lease_by_tenant(tenant_id: str) -> Optional[Lease]:
    return await Lease.find_one(
        Lease.tenant_id == tenant_id,
        Lease.status    == LeaseStatus.ACTIVE,
    )


async def get_active_lease_by_room(room_id: str) -> Optional[Lease]:
    return await Lease.find_one(
        Lease.room_id == room_id,
        Lease.status  == LeaseStatus.ACTIVE,
    )


async def get_leases_by_status(
    status: LeaseStatus,
    skip: int = 0,
    limit: int = 20,
) -> list[Lease]:
    return await Lease.find(
        Lease.status == status
    ).skip(skip).limit(limit).to_list()


async def get_expiring_leases(
    days_ahead: int = 30,
    skip: int = 0,
    limit: int = 1000,
) -> list[Lease]:
    """Returns ACTIVE leases expiring within days_ahead days."""
    target = date.today() + timedelta(days=days_ahead)
    return await Lease.find(
        Lease.status   == LeaseStatus.ACTIVE,
        Lease.end_date <= target,
    ).skip(skip).limit(limit).to_list()


async def get_overdue_leases(as_of_date: date) -> list[Lease]:
    """Returns ACTIVE leases whose end_date has passed."""
    return await Lease.find(
        Lease.status   == LeaseStatus.ACTIVE,
        Lease.end_date <  as_of_date,
    ).to_list()


async def get_auto_renew_candidates(days_ahead: int = 3) -> list[Lease]:
    """Returns ACTIVE leases with auto_renew=True expiring within days_ahead."""
    target = date.today() + timedelta(days=days_ahead)
    return await Lease.find(
        Lease.status     == LeaseStatus.ACTIVE,
        Lease.auto_renew == True,                                       # noqa: E712
        Lease.end_date   <= target,
    ).to_list()


async def get_wrongly_flagged_leases(days_ahead: int = 30) -> list[Lease]:
    """Returns leases flagged is_expiring_soon=True but end_date is now far away."""
    target = date.today() + timedelta(days=days_ahead)
    return await Lease.find(
        Lease.status           == LeaseStatus.ACTIVE,
        Lease.is_expiring_soon == True,                                 # noqa: E712
        Lease.end_date         >  target,
    ).to_list()


async def count_all_leases() -> int:
    return await Lease.count()


async def count_leases_by_status(status: LeaseStatus) -> int:
    return await Lease.find(Lease.status == status).count()


async def count_expiring_leases(days_ahead: int = 30) -> int:
    target = date.today() + timedelta(days=days_ahead)
    return await Lease.find(
        Lease.status   == LeaseStatus.ACTIVE,
        Lease.end_date <= target,
    ).count()


# ================================================================
# WRITE
# ================================================================

async def create_lease(lease: Lease) -> Lease:
    return await lease.insert()


async def update_lease(
    lease_id: PydanticObjectId,
    updates: dict,
    updated_by: str,
) -> Optional[Lease]:
    lease = await Lease.get(lease_id)
    if not lease:
        return None
    updates["updated_at"] = datetime.utcnow()
    updates["updated_by"] = updated_by
    await lease.update(Set(updates))
    return await Lease.get(lease_id)


async def update_lease_status(
    lease_id: PydanticObjectId,
    status: LeaseStatus,
    updated_by: str,
) -> Optional[Lease]:
    return await update_lease(
        lease_id=lease_id,
        updates={"status": status},
        updated_by=updated_by,
    )


async def renew_lease(
    lease_id: PydanticObjectId,
    updates: dict,
    renewal_record: LeaseRenewalRecord,
    updated_by: str,
) -> Optional[Lease]:
    """
    Updates lease fields and appends a renewal record
    to renewal_history in a single operation.
    """
    lease = await Lease.get(lease_id)
    if not lease:
        return None

    updated_history = lease.renewal_history + [renewal_record]
    updates["renewal_history"] = [r.model_dump() for r in updated_history]
    updates["updated_at"]      = datetime.utcnow()
    updates["updated_by"]      = updated_by

    await lease.update(Set(updates))
    return await Lease.get(lease_id)


async def terminate_lease(
    lease_id: PydanticObjectId,
    termination_details: LeaseTerminationDetails,
    updated_by: str,
) -> Optional[Lease]:
    """
    Sets lease status to TERMINATED and embeds termination details.
    """
    return await update_lease(
        lease_id=lease_id,
        updates={
            "status":               LeaseStatus.TERMINATED,
            "termination_details":  termination_details.model_dump(),
        },
        updated_by=updated_by,
    )


async def update_balance(
    lease_id: PydanticObjectId,
    outstanding_balance: float,
    total_paid: float,
) -> Optional[Lease]:
    """
    Updates financial summary fields.
    Called by PaymentService and BillingService only.
    """
    lease = await Lease.get(lease_id)
    if not lease:
        return None
    await lease.update(Set({
        "outstanding_balance": outstanding_balance,
        "total_paid":          total_paid,
        "updated_at":          datetime.utcnow(),
    }))
    return await Lease.get(lease_id)


async def update_deposit_return(
    lease_id: PydanticObjectId,
    deductions: float,
    returned_amount: float,
    updated_by: str,
) -> Optional[Lease]:
    """
    Records deposit return in termination_details.
    """
    lease = await Lease.get(lease_id)
    if not lease:
        return None
    await lease.update(Set({
        "termination_details.deposit_returned":        True,
        "termination_details.deposit_deductions":      deductions,
        "termination_details.deposit_returned_amount": returned_amount,
        "updated_at":                                  datetime.utcnow(),
        "updated_by":                                  updated_by,
    }))
    return await Lease.get(lease_id)


async def delete_lease(lease_id: PydanticObjectId) -> bool:
    lease = await Lease.get(lease_id)
    if not lease:
        return False
    await lease.delete()
    return True