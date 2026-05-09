import pytest
from unittest.mock import AsyncMock, patch
from test.conftest import AUTH_HEADERS # You can keep this if you use it for manual patches
from main import app

BASE = "/api/payments"

# ── Fake IDs (format must be valid 24-char hex for PydanticObjectId) ──────────
TENANT_ID = "64f1000000000000000000a1"
LEASE_ID  = "64f1000000000000000000a2"
ROOM_ID   = "64f1000000000000000000a3"

# ── Fake admin user — injected via mock so no real JWT is needed ───────────────
FAKE_ADMIN = {
    "sub":      TENANT_ID,   # used for ownership checks
    "username": "test_admin",
    "role":     "ROLE_ADMIN",
}

# ── PayPal mock data ───────────────────────────────────────────────────────────
FAKE_ORDER_ID   = "FAKE-PAYPAL-ORDER-001"
FAKE_CAPTURE_ID = "FAKE-CAPTURE-001"
FAKE_APPROVAL   = "https://sandbox.paypal.com/approve?token=FAKE"

MOCK_ORDER_RESP = {
    "id":     FAKE_ORDER_ID,
    "status": "CREATED",
    "links":  [{"rel": "approve", "href": FAKE_APPROVAL}],
}

MOCK_CAPTURE_RESP = {
    "status": "COMPLETED",
    "purchase_units": [{
        "payments": {
            "captures": [{
                "id":     FAKE_CAPTURE_ID,
                "amount": {"value": "5000.00", "currency_code": "PHP"},
            }]
        }
    }],
    "payer": {
        "payer_id":      "PAYER123",
        "email_address": "buyer@sandbox.paypal.com",
    },
}


# ── httpx response stand-in for PayPal API calls ──────────────────────────────
class FakePayPalResponse:
    """
    Mimics an httpx.Response for PayPal REST calls only.
    The test AsyncClient (ASGI transport) is patched separately,
    so this class is only returned when the service calls PayPal.
    """
    def __init__(self, status_code: int, body: dict):
        self.status_code = status_code
        self._body = body

    def json(self):
        return self._body


# ═══════════════════════════════════════════════════════════════
#  FIXTURES
# ═══════════════════════════════════════════════════════════════

def mock_paypal_initiate():
    """
    Patches only the PayPal HTTP calls inside payment_service,
    not the httpx transport used by the test client itself.
    """
    return patch(
        "services.payment_service.httpx.AsyncClient",
        new_callable=lambda: _PayPalClientMock(MOCK_ORDER_RESP),
    )


def mock_paypal_capture():
    return patch(
        "services.payment_service.httpx.AsyncClient",
        new_callable=lambda: _PayPalClientMock(MOCK_CAPTURE_RESP),
    )


class _PayPalClientMock:
    """
    Context-manager mock that replaces `httpx.AsyncClient` inside the service.
    Always returns a FakePayPalResponse regardless of which URL is called.
    """
    def __init__(self, response_body: dict):
        self._body = response_body

    def __call__(self):
        return self  # __new__ equivalent — returns self as the instance

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        pass

    async def post(self, *args, **kwargs):
        return FakePayPalResponse(201, self._body)

    async def get(self, *args, **kwargs):
        return FakePayPalResponse(200, self._body)


# ═══════════════════════════════════════════════════════════════
#  TESTS — Cash payments
# ═══════════════════════════════════════════════════════════════

@pytest.mark.anyio
async def test_record_cash_payment(client):
    resp = await client.post(
        f"{BASE}/cash",
        json={
            "tenant_id": TENANT_ID,
            "lease_id":  LEASE_ID,
            "room_id":   ROOM_ID,
            "amount":    5000.00,
            "type":      "RENT",
            "method":    "CASH",
        },
    )
    assert resp.status_code == 200, resp.text
    data = resp.json()["data"]
    assert data["status"]  == "PENDING"
    assert data["amount"]  == 5000.00
    assert data["receipt_number"].startswith("RE-")
    print(f"\n✓ Cash payment created: {data['id']}")


@pytest.mark.anyio
async def test_confirm_payment(client):
    # 1. Create
    create = await client.post(
        f"{BASE}/cash",
        json={
            "tenant_id": TENANT_ID, "lease_id": LEASE_ID,
            "room_id":   ROOM_ID,   "amount":   1000.0, "method": "CASH",
        },
    )
    assert create.status_code == 200, create.text
    payment_id = create.json()["data"]["id"]

    # 2. Confirm
    resp = await client.patch(f"{BASE}/{payment_id}/confirm")
    assert resp.status_code == 200, resp.text
    assert resp.json()["data"]["status"] == "CONFIRMED"
    print(f"\n✓ Payment confirmed: {payment_id}")


@pytest.mark.anyio
async def test_cannot_delete_confirmed_payment(client):
    # 1. Create + confirm
    create = await client.post(
        f"{BASE}/cash",
        json={
            "tenant_id": TENANT_ID, "lease_id": LEASE_ID,
            "room_id":   ROOM_ID,   "amount":   500.0, "method": "CASH",
        },
    )
    assert create.status_code == 200, create.text
    payment_id = create.json()["data"]["id"]
    await client.patch(f"{BASE}/{payment_id}/confirm")

    # 2. Try to delete — must be rejected
    delete = await client.delete(f"{BASE}/{payment_id}")
    assert delete.status_code == 400, delete.text
    print(f"\n✓ Confirmed payment correctly blocked from deletion")


@pytest.mark.anyio
async def test_get_single_payment(client):
    # Create one first
    create = await client.post(
        f"{BASE}/cash",
        json={
            "tenant_id": TENANT_ID, "lease_id": LEASE_ID,
            "room_id":   ROOM_ID,   "amount":   750.0, "method": "GCASH",
        },
    )
    assert create.status_code == 200, create.text
    payment_id = create.json()["data"]["id"]

    resp = await client.get(f"{BASE}/{payment_id}")
    assert resp.status_code == 200, resp.text
    assert resp.json()["data"]["id"] == payment_id
    print(f"\n✓ Single payment retrieved: {payment_id}")


# ═══════════════════════════════════════════════════════════════
#  TESTS — PayPal
# ═══════════════════════════════════════════════════════════════

@pytest.mark.anyio
async def test_initiate_paypal_payment(client):
    with patch("services.payment_service._get_paypal_access_token",
               new=AsyncMock(return_value="FAKE-TOKEN")), \
         patch("services.payment_service.httpx.AsyncClient",
               new=lambda: _PayPalClientMock(MOCK_ORDER_RESP)()):
        resp = await client.post(
            f"{BASE}/paypal/initiate",
            json={
                "tenant_id": TENANT_ID,
                "lease_id":  LEASE_ID,
                "room_id":   ROOM_ID,
                "amount":    5000.00,
                "type":      "RENT",
            },
        )

    assert resp.status_code == 200, resp.text
    data = resp.json()["data"]
    assert data["order_id"]     == FAKE_ORDER_ID
    assert data["approval_url"] == FAKE_APPROVAL
    assert data["amount"]       == 5000.00
    assert data["currency"]     == "PHP"
    print(f"\n✓ PayPal order initiated: {data['order_id']}")


@pytest.mark.anyio
async def test_capture_paypal_payment(client):
    # 1. Initiate
    with patch("services.payment_service._get_paypal_access_token",
               new=AsyncMock(return_value="FAKE-TOKEN")), \
         patch("services.payment_service.httpx.AsyncClient",
               new=lambda: _PayPalClientMock(MOCK_ORDER_RESP)()):
        init = await client.post(
            f"{BASE}/paypal/initiate",
            json={
                "tenant_id": TENANT_ID,
                "lease_id":  LEASE_ID,
                "room_id":   ROOM_ID,
                "amount":    5000.00,
            },
        )
    assert init.status_code == 200, init.text
    payment_id = init.json()["data"]["payment_id"]

    # 2. Capture
    with patch("services.payment_service._get_paypal_access_token",
               new=AsyncMock(return_value="FAKE-TOKEN")), \
         patch("services.payment_service.httpx.AsyncClient",
               new=lambda: _PayPalClientMock(MOCK_CAPTURE_RESP)()):
        resp = await client.post(
            f"{BASE}/paypal/capture",
            json={"order_id": FAKE_ORDER_ID, "payment_id": payment_id},
        )

    assert resp.status_code == 200, resp.text
    data = resp.json()["data"]
    assert data["status"] == "CONFIRMED"
    assert data["receipt_url"] == FAKE_CAPTURE_ID   # capture_id stored here
    print(f"\n✓ PayPal payment captured and confirmed: {payment_id}")


# ═══════════════════════════════════════════════════════════════
#  TESTS — Stats & list
# ═══════════════════════════════════════════════════════════════

@pytest.mark.anyio
async def test_get_stats(client):
    resp = await client.get(f"{BASE}/stats")
    assert resp.status_code == 200, resp.text
    data = resp.json()["data"]
    assert "total_collected" in data
    assert "confirmed_count" in data
    assert "pending_count"   in data
    print(f"\n✓ Stats: {data}")


@pytest.mark.anyio
async def test_get_all_payments(client):
    resp = await client.get(f"{BASE}/")
    assert resp.status_code == 200, resp.text
    data = resp.json()["data"]
    assert "total"    in data
    assert "payments" in data
    print(f"\n✓ All payments retrieved, total: {data['total']}")