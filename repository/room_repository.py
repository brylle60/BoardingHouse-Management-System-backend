from config.database import rooms_col
from bson import ObjectId
from datetime import datetime

def get_all_rooms():
    return list(rooms_col.find())

def get_room_by_id(room_id: str):
    return rooms_col.find_one({"_id": ObjectId(room_id)})

def get_room_by_number(room_number: str):
    return rooms_col.find_one({"room_number": room_number})

def get_rooms_by_status(status: str):
    return list(rooms_col.find({"status": status}))

def create_room(room_data: dict):
    result = rooms_col.insert_one(room_data)
    return str(result.inserted_id)

def update_room(room_id: str, updated_data: dict):
    updated_data["updated_at"] = datetime.utcnow()
    result = rooms_col.update_one(
        {"_id": ObjectId(room_id)},
        {"$set": updated_data}
    )
    return result.modified_count

def delete_room(room_id: str):
    result = rooms_col.delete_one({"_id": ObjectId(room_id)})
    return result.deleted_count