from models.booking_request import BookingRequest, BookingStatus
from beanie import PydanticObjectId
from typing import List, Optional

# ─── READ OPERATIONS ────────────────────────────────────────────────────────

async def find_by_id(booking_id: str) -> Optional[BookingRequest]:
    """Retrieves a single booking request by its ID."""
    try:
        return await BookingRequest.get(PydanticObjectId(booking_id))
    except Exception:
        return None

async def find_by_user_id(user_id: str) -> List[BookingRequest]:
    """Retrieves all booking requests associated with a specific user ID."""
    return await BookingRequest.find(BookingRequest.user_id == user_id).to_list()

async def find_all(skip: int = 0, limit: int = 20) -> List[BookingRequest]:
    """Retrieves a paginated list of all booking requests."""
    return await BookingRequest.find_all().skip(skip).limit(limit).to_list()

# ─── WRITE OPERATIONS ───────────────────────────────────────────────────────

async def save_booking(booking: BookingRequest) -> BookingRequest:
    """Creates or updates a booking request record."""
    await booking.save()
    return booking

# ─── DELETE OPERATIONS ──────────────────────────────────────────────────────

async def delete_booking(booking: BookingRequest):
    """Permanently deletes a specific booking request document."""
    await booking.delete()

async def delete_bookings_by_user_id(user_id: str) -> int:
    """
    Delete ALL booking records tied to a user_id.
    Called when a tenant is unassigned so no ghost records remain.
    Returns the count of deleted documents.
    """
    # Using the correct model name 'BookingRequest' from your project
    result = await BookingRequest.find(BookingRequest.user_id == user_id).delete()
    return result.deleted_count if result else 0