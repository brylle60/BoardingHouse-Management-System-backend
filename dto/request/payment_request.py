from pydantic import BaseModel, Field
from typing import Optional
from datetime import datetime
from enum import Enum


class PaymentMethod(str, Enum):
    CASH          = "CASH"
    BANK_TRANSFER = "BANK_TRANSFER"
    GCASH         = "GCASH"
    PAYMAYA       = "PAYMAYA"
    CARD          = "CARD"
    OTHER         = "OTHER"


class PaymentType(str, Enum):
    RENT    = "RENT"
    DEPOSIT = "DEPOSIT"
    ADVANCE = "ADVANCE"
    PENALTY = "PENALTY"
    UTILITY = "UTILITY"
    OTHER   = "OTHER"


# ── Cash / Manual ─────────────────────────────────────────────────────────────

class CashPaymentRequest(BaseModel):
    tenant_id:    str
    lease_id:     str
    room_id:      str
    amount:       float         = Field(..., gt=0)
    type:         PaymentType   = PaymentType.RENT
    method:       PaymentMethod = PaymentMethod.CASH
    reference_no: Optional[str] = None
    notes:        Optional[str] = Field(default=None, max_length=500)
    period_start: Optional[datetime] = None
    period_end:   Optional[datetime] = None

    class Config:
        json_schema_extra = {
            "example": {
                "tenant_id":    "64f1a2b3c4d5e6f7a8b9c0d1",
                "lease_id":     "64f1a2b3c4d5e6f7a8b9c0d2",
                "room_id":      "64f1a2b3c4d5e6f7a8b9c0d3",
                "amount":       5000.00,
                "type":         "RENT",
                "method":       "GCASH",
                "reference_no": "GC-20240701-XYZ",
                "period_start": "2024-07-01T00:00:00",
                "period_end":   "2024-07-31T23:59:59"
            }
        }


# ── PayPal ────────────────────────────────────────────────────────────────────

class PayPalPaymentRequest(BaseModel):
    tenant_id:    str
    lease_id:     str
    room_id:      str
    amount:       float       = Field(..., gt=0)
    type:         PaymentType = PaymentType.RENT
    notes:        Optional[str] = Field(default=None, max_length=500)
    period_start: Optional[datetime] = None
    period_end:   Optional[datetime] = None

    class Config:
        json_schema_extra = {
            "example": {
                "tenant_id":    "64f1a2b3c4d5e6f7a8b9c0d1",
                "lease_id":     "64f1a2b3c4d5e6f7a8b9c0d2",
                "room_id":      "64f1a2b3c4d5e6f7a8b9c0d3",
                "amount":       5000.00,
                "type":         "RENT",
                "period_start": "2024-07-01T00:00:00",
                "period_end":   "2024-07-31T23:59:59"
            }
        }


class PayPalCaptureRequest(BaseModel):
    order_id:   str = Field(..., description="PayPal order ID returned from POST /paypal/initiate")
    payment_id: str = Field(..., description="Internal Payment document _id")

    class Config:
        json_schema_extra = {
            "example": {
                "order_id":   "5O190127TN364715T",
                "payment_id": "64f1a2b3c4d5e6f7a8b9c0d4"
            }
        }
