# models/__init__.py
from .user import User
from .room import Room
from .tenant import Tenant
from .lease import Lease
from .payment import Payment
from .maintenance import MaintenanceRequest
from .notification import Notification
from .message import Message, Announcement
from .manager_role_request import ManagerRoleRequest
from .booking_request import BookingRequest

# This list makes it easy for Beanie to find everything
__all_models__ = [
    User, Room, Tenant, Lease, Payment,
    MaintenanceRequest, Notification,
    Message, Announcement,
    ManagerRoleRequest, BookingRequest,
]