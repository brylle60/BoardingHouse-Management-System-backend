import os
from beanie import init_beanie
from motor.motor_asyncio import AsyncIOMotorClient
from pydantic import Field
from pydantic_settings import BaseSettings
from models.maintenance import MaintenanceRequest
from models.payment import Payment
from models.tenant import Tenant
from models.user import User
from models.room import Room
from models.otp import OtpCode
from models.lease import Lease
from models.notification import Notification
from models.message import Message, Announcement
from models.manager_role_request import ManagerRoleRequest
from models.booking_request import BookingRequest
from models.system_setting import SystemSetting


class DataSettings(BaseSettings):
    mongodb_url: str = Field(..., alias="DATABASE_URL")
    mongodb_name: str = Field(..., alias="MONGODB_NAME")

    model_config = {
        "env_file": ".env",
        "extra": "ignore",
    }


async def init_database():
    settings = DataSettings()
    client = AsyncIOMotorClient(settings.mongodb_url)
    database = client[settings.mongodb_name]

    await init_beanie(
        database=database,
        document_models=[
            User,
            Tenant,
            OtpCode,
            Room,
            Message,
            Announcement,
            Notification,
            Lease,
            Payment,
            MaintenanceRequest,
            ManagerRoleRequest,
            BookingRequest,
            SystemSetting,   # ← was imported but never registered
        ]
    )
    print("Connected to MongoDB:", settings.mongodb_name)
    print("Registered models: User, Tenant, OtpCode, Room, Message, Announcement, Notification, Lease, Payment, MaintenanceRequest, ManagerRoleRequest, BookingRequest, SystemSetting")