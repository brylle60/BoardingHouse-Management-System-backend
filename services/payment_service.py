"""
services/payment_service.py

Business logic for payment recording and tracking.
Uses repository import pattern matching your existing codebase.
"""

import uuid
from fastapi import HTTPException
from datetime import datetime
from beanie import PydanticObjectId

from models.payment import Payment, PaymentStatus, PaymentMethod, PaymentType
from repository import payment_repository
from repository import lease_repository
from repository.notification_repository import create_notification
from models.notification import NotificationType


class PaymentService:

    async def get_all_payments(self) -> list[Payment]:
        return await payment_repository.get_all_payments()

    async def get_payment_by_id(self, payment_id: str) -> Payment:
        payment = await payment_repository.find_payment_by_id(payment_id)
        if not payment:
            raise HTTPException(404, "Payment not found.")
        return payment

    async def get_tenant_payments(self, tenant_id: str) -> list[Payment]:
        return await payment_repository.find_payments_by_tenant(tenant_id)

    async def get_lease_payments(self, lease_id: str) -> list[Payment]:
        return await payment_repository.find_payments_by_lease(lease_id)

    async def record_payment(
        self,
        tenant_id:    str,
        lease_id:     str,
        room_id:      str,
        amount:       float,
        method:       PaymentMethod      = PaymentMethod.CASH,
        type:         PaymentType        = PaymentType.RENT,
        reference_no: str | None         = None,
        notes:        str | None         = None,
        period_start: datetime | None    = None,
        period_end:   datetime | None    = None,
        recorded_by:  str | None         = None,
    ) -> Payment:
        payment = Payment(
            tenant_id    = PydanticObjectId(tenant_id),
            lease_id     = PydanticObjectId(lease_id),
            room_id      = PydanticObjectId(room_id),
            amount       = amount,
            method       = method,
            type         = type,
            status       = PaymentStatus.PENDING,
            reference_no = reference_no,
            notes        = notes,
            period_start = period_start,
            period_end   = period_end,
            recorded_by  = PydanticObjectId(recorded_by) if recorded_by else None,
            receipt_number = self._generate_receipt_number(),
        )
        saved = await payment_repository.save_payment(payment)

        # Notify tenant
        try:
            # Get tenant_user_id from lease using your existing repository pattern
            lease = await lease_repository.get_lease_by_id(PydanticObjectId(lease_id))
            if lease and hasattr(lease, 'tenant_user_id'):
                await create_notification(
                    user_id        = str(lease.tenant_user_id),
                    type           = NotificationType.PAYMENT_RECEIVED,
                    title          = "Payment recorded",
                    message        = f"Your payment of ₱{amount:,.2f} has been recorded and is awaiting confirmation.",
                    reference_id   = str(saved.id),
                    reference_type = "payment",
                )
        except Exception:
            pass  # notification failure should not block payment recording

        return saved

    async def confirm_payment(self, payment_id: str) -> Payment:
        payment = await self.get_payment_by_id(payment_id)

        if payment.status == PaymentStatus.CONFIRMED:
            raise HTTPException(400, "Payment is already confirmed.")

        payment.status       = PaymentStatus.CONFIRMED
        payment.confirmed_at = datetime.utcnow()
        payment.updated_at   = datetime.utcnow()
        return await payment_repository.save_payment(payment)

    async def delete_payment(self, payment_id: str) -> dict:
        payment = await self.get_payment_by_id(payment_id)
        if payment.status == PaymentStatus.CONFIRMED:
            raise HTTPException(400, "Cannot delete a confirmed payment.")
        await payment_repository.delete_payment(payment)
        return {"message": "Payment deleted."}

    async def get_payment_stats(self) -> dict:
        all_payments = await payment_repository.get_all_payments()
        confirmed    = [p for p in all_payments if p.status == PaymentStatus.CONFIRMED]
        pending      = [p for p in all_payments if p.status == PaymentStatus.PENDING]
        return {
            "total_collected": sum(p.amount for p in confirmed),
            "total_pending":   sum(p.amount for p in pending),
            "confirmed_count": len(confirmed),
            "pending_count":   len(pending),
        }

    def _generate_receipt_number(self) -> str:
        date_part = datetime.utcnow().strftime("%Y%m%d")
        rand_part = uuid.uuid4().hex[:4].upper()
        return f"RE-{date_part}-{rand_part}"


payment_service = PaymentService()