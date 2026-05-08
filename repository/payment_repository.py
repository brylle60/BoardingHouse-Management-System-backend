"""
repository/payment_repository.py

DB query layer for Payment documents.
Follows your existing repository pattern — no business logic.
"""

from beanie import PydanticObjectId
from models.payment import Payment, PaymentStatus


async def get_all_payments() -> list[Payment]:
    return await Payment.find_all().sort("-payment_date").to_list()


async def find_payment_by_id(payment_id: str) -> Payment | None:
    try:
        return await Payment.get(PydanticObjectId(payment_id))
    except Exception:
        return None


async def find_payments_by_tenant(tenant_id: str) -> list[Payment]:
    oid = PydanticObjectId(tenant_id)
    return await Payment.find(
        Payment.tenant_id == oid
    ).sort("-payment_date").to_list()


async def find_payments_by_lease(lease_id: str) -> list[Payment]:
    oid = PydanticObjectId(lease_id)
    return await Payment.find(
        Payment.lease_id == oid
    ).sort("-payment_date").to_list()


async def find_payments_by_status(status: PaymentStatus) -> list[Payment]:
    return await Payment.find(
        Payment.status == status
    ).sort("-payment_date").to_list()


async def save_payment(payment: Payment) -> Payment:
    await payment.save()
    return payment


async def delete_payment(payment: Payment) -> None:
    await payment.delete()
