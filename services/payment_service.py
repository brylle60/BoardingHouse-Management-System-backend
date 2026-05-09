"""
services/payment_service.py

Extends the existing PaymentService with PayPal REST API v2 support.
All existing methods are preserved unchanged.

PayPal flow:
  1. POST /api/payments/paypal/initiate
       → creates PayPal order, saves PENDING Payment, returns approval_url
  2. Tenant approves on PayPal redirect page
  3. POST /api/payments/paypal/capture
       → captures the order, confirms the Payment, notifies tenant
"""

import uuid
import base64
import httpx
from datetime import datetime
from typing import Optional

from beanie import PydanticObjectId
from fastapi import HTTPException

from models.payment import Payment, PaymentStatus, PaymentMethod, PaymentType
from repository import payment_repository
from repository import lease_repository
from repository.notification_repository import create_notification
from models.notification import NotificationType
from config.payment_gateway_config import paypal_cfg
from dto.request.payment_request import (
    CashPaymentRequest,
    PayPalPaymentRequest,
    PayPalCaptureRequest,
)
from dto.response.payment_response import (
    PaymentResponse,
    PayPalInitResponse,
    PaymentStatsResponse,
    PaymentListResponse,
)


# ═══════════════════════════════════════════════════════════════
#  PAYPAL HELPERS  (module-level, not on the class)
# ═══════════════════════════════════════════════════════════════

async def _get_paypal_access_token() -> str:
    """Exchange client_id:secret for a short-lived Bearer token."""
    credentials = base64.b64encode(
        f"{paypal_cfg.client_id}:{paypal_cfg.secret_key}".encode()
    ).decode()
    async with httpx.AsyncClient() as client:
        resp = await client.post(
            f"{paypal_cfg.base_url}/v1/oauth2/token",
            headers={
                "Authorization": f"Basic {credentials}",
                "Content-Type":  "application/x-www-form-urlencoded",
            },
            data={"grant_type": "client_credentials"},
        )
    if resp.status_code != 200:
        raise HTTPException(502, f"PayPal auth failed: {resp.text}")
    return resp.json()["access_token"]


async def _paypal_headers() -> dict:
    token = await _get_paypal_access_token()
    return {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}


def _find_approval_url(links: list) -> Optional[str]:
    for link in links:
        if link.get("rel") == "approve":
            return link["href"]
    return None


# ═══════════════════════════════════════════════════════════════
#  SERVICE
# ═══════════════════════════════════════════════════════════════

class PaymentService:

    # ─────────────────────────────────────────────────────────────
    #  Helpers (kept from original)
    # ─────────────────────────────────────────────────────────────

    def _generate_receipt_number(self) -> str:
        date_part = datetime.utcnow().strftime("%Y%m%d")
        rand_part = uuid.uuid4().hex[:4].upper()
        return f"RE-{date_part}-{rand_part}"

    async def _notify_tenant(
        self,
        lease_id:      str,
        title:         str,
        message:       str,
        reference_id:  str,
    ) -> None:
        """Fire-and-forget notification — failure never blocks the payment."""
        try:
            lease = await lease_repository.get_lease_by_id(PydanticObjectId(lease_id))
            if lease and hasattr(lease, "tenant_user_id"):
                await create_notification(
                    user_id        = str(lease.tenant_user_id),
                    type           = NotificationType.PAYMENT_RECEIVED,
                    title          = title,
                    message        = message,
                    reference_id   = reference_id,
                    reference_type = "payment",
                )
        except Exception:
            pass

    # ─────────────────────────────────────────────────────────────
    #  Original read methods (unchanged)
    # ─────────────────────────────────────────────────────────────

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

    async def get_payment_stats(self) -> PaymentStatsResponse:
        all_payments = await payment_repository.get_all_payments()
        confirmed    = [p for p in all_payments if p.status == PaymentStatus.CONFIRMED]
        pending      = [p for p in all_payments if p.status == PaymentStatus.PENDING]
        return PaymentStatsResponse(
            total_collected = sum(p.amount for p in confirmed),
            total_pending   = sum(p.amount for p in pending),
            confirmed_count = len(confirmed),
            pending_count   = len(pending),
        )

    # ─────────────────────────────────────────────────────────────
    #  Original write methods (unchanged, just wrapped in DTO)
    # ─────────────────────────────────────────────────────────────

    async def record_payment(
        self,
        tenant_id:    str,
        lease_id:     str,
        room_id:      str,
        amount:       float,
        method:       PaymentMethod   = PaymentMethod.CASH,
        type:         PaymentType     = PaymentType.RENT,
        reference_no: str | None      = None,
        notes:        str | None      = None,
        period_start: datetime | None = None,
        period_end:   datetime | None = None,
        recorded_by:  str | None      = None,
    ) -> Payment:
        payment = Payment(
            tenant_id      = PydanticObjectId(tenant_id),
            lease_id       = PydanticObjectId(lease_id),
            room_id        = PydanticObjectId(room_id),
            amount         = amount,
            method         = method,
            type           = type,
            status         = PaymentStatus.PENDING,
            reference_no   = reference_no,
            notes          = notes,
            period_start   = period_start,
            period_end     = period_end,
            recorded_by    = PydanticObjectId(recorded_by) if recorded_by else None,
            receipt_number = self._generate_receipt_number(),
        )
        saved = await payment_repository.save_payment(payment)

        await self._notify_tenant(
            lease_id     = lease_id,
            title        = "Payment recorded",
            message      = f"Your payment of ₱{amount:,.2f} has been recorded and is awaiting confirmation.",
            reference_id = str(saved.id),
        )
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

    # ─────────────────────────────────────────────────────────────
    #  NEW — Cash payment via DTO (controller convenience)
    # ─────────────────────────────────────────────────────────────

    async def record_cash_payment(
        self, data: CashPaymentRequest, recorded_by: str
    ) -> PaymentResponse:
        saved = await self.record_payment(
            tenant_id    = data.tenant_id,
            lease_id     = data.lease_id,
            room_id      = data.room_id,
            amount       = data.amount,
            method       = data.method,
            type         = data.type,
            reference_no = data.reference_no,
            notes        = data.notes,
            period_start = data.period_start,
            period_end   = data.period_end,
            recorded_by  = recorded_by,
        )
        return PaymentResponse.from_payment(saved)

    # ─────────────────────────────────────────────────────────────
    #  NEW — PayPal: initiate (create order)
    # ─────────────────────────────────────────────────────────────

    async def initiate_paypal_payment(
        self, data: PayPalPaymentRequest, recorded_by: str
    ) -> PayPalInitResponse:
        receipt_number = self._generate_receipt_number()
        headers        = await _paypal_headers()

        order_payload = {
            "intent": "CAPTURE",
            "purchase_units": [{
                "reference_id": receipt_number,
                "description":  f"ResidEase {data.type} – {receipt_number}",
                "amount": {
                    "currency_code": paypal_cfg.currency,
                    "value":         f"{data.amount:.2f}",
                },
            }],
            "application_context": {
                "brand_name":  "ResidEase",
                "landing_page": "BILLING",
                "user_action":  "PAY_NOW",
                "return_url":   f"{paypal_cfg.return_url}?ref={receipt_number}",
                "cancel_url":   paypal_cfg.cancel_url,
            },
        }

        async with httpx.AsyncClient() as client:
            resp = await client.post(
                f"{paypal_cfg.base_url}/v2/checkout/orders",
                headers=headers,
                json=order_payload,
            )
        if resp.status_code not in (200, 201):
            raise HTTPException(502, f"PayPal order creation failed: {resp.text}")

        order_data   = resp.json()
        order_id     = order_data["id"]
        approval_url = _find_approval_url(order_data.get("links", []))
        if not approval_url:
            raise HTTPException(502, "PayPal did not return an approval URL.")

        # Save a PENDING payment; stash PayPal order_id in reference_no
        payment = Payment(
            tenant_id      = PydanticObjectId(data.tenant_id),
            lease_id       = PydanticObjectId(data.lease_id),
            room_id        = PydanticObjectId(data.room_id),
            amount         = data.amount,
            method         = PaymentMethod.OTHER,   # "PAYPAL" — add to enum if desired
            type           = data.type,
            status         = PaymentStatus.PENDING,
            reference_no   = order_id,              # PayPal order ID stored here
            notes          = data.notes,
            period_start   = data.period_start,
            period_end     = data.period_end,
            recorded_by    = PydanticObjectId(recorded_by) if recorded_by else None,
            receipt_number = receipt_number,
        )
        saved = await payment_repository.save_payment(payment)

        return PayPalInitResponse(
            payment_id     = str(saved.id),
            receipt_number = receipt_number,
            order_id       = order_id,
            approval_url   = approval_url,
            amount         = data.amount,
            currency       = paypal_cfg.currency,
        )

    # ─────────────────────────────────────────────────────────────
    #  NEW — PayPal: capture (after tenant approves)
    # ─────────────────────────────────────────────────────────────

    async def capture_paypal_payment(
        self, data: PayPalCaptureRequest, recorded_by: str
    ) -> PaymentResponse:
        # 1. Load and validate internal payment
        payment = await self.get_payment_by_id(data.payment_id)
        if payment.status != PaymentStatus.PENDING:
            raise HTTPException(400, "Payment is not in PENDING status.")
        if payment.reference_no != data.order_id:
            raise HTTPException(400, "order_id does not match this payment record.")

        # 2. Call PayPal capture
        headers = await _paypal_headers()
        async with httpx.AsyncClient() as client:
            resp = await client.post(
                f"{paypal_cfg.base_url}/v2/checkout/orders/{data.order_id}/capture",
                headers=headers,
                json={},
            )

        if resp.status_code not in (200, 201):
            # Mark FAILED so it's not left dangling as PENDING
            payment.status     = PaymentStatus.FAILED
            payment.updated_at = datetime.utcnow()
            await payment_repository.save_payment(payment)
            raise HTTPException(502, f"PayPal capture failed: {resp.text}")

        capture_data    = resp.json()
        capture_unit    = capture_data["purchase_units"][0]["payments"]["captures"][0]
        capture_id      = capture_unit["id"]
        captured_amount = float(capture_unit["amount"]["value"])
        payer           = capture_data.get("payer", {})

        # 3. Confirm payment — reuse existing confirm logic pattern
        payment.status       = PaymentStatus.CONFIRMED
        payment.confirmed_at = datetime.utcnow()
        payment.updated_at   = datetime.utcnow()
        # Store capture details in receipt_url field (no schema change needed)
        # If you prefer a dedicated field, add paypal_capture_id to the model.
        payment.receipt_url  = capture_id                            # capture_id for refunds
        # Attach transient attrs for the response DTO
        payment.paypal_order_id    = data.order_id                  # type: ignore[attr-defined]
        payment.paypal_capture_id  = capture_id                     # type: ignore[attr-defined]
        payment.paypal_payer_id    = payer.get("payer_id")          # type: ignore[attr-defined]
        payment.paypal_payer_email = payer.get("email_address")     # type: ignore[attr-defined]

        saved = await payment_repository.save_payment(payment)

        # 4. Notify tenant
        await self._notify_tenant(
            lease_id     = str(payment.lease_id),
            title        = "Payment confirmed",
            message      = f"Your PayPal payment of ₱{captured_amount:,.2f} has been confirmed. Receipt: {payment.receipt_number}",
            reference_id = str(saved.id),
        )

        return PaymentResponse.from_payment(saved)


# Singleton — matches your existing pattern
payment_service = PaymentService()