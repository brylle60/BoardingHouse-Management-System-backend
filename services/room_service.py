from repository.room_repository import (
    get_all_rooms, get_room_by_id, get_room_by_number,
    get_rooms_by_status, create_room, update_room, delete_room
)
from models.rooms import room_model, rooms_list_model
from datetime import datetime

def fetch_all_rooms():
    rooms = get_all_rooms()
    return rooms_list_model(rooms)

def fetch_room(room_id: str):
    room = get_room_by_id(room_id)
    if not room:
        return None
    return room_model(room)

def fetch_rooms_by_status(status: str):
    rooms = get_rooms_by_status(status)
    return rooms_list_model(rooms)

def add_room(data: dict):
    # Check for duplicate room number
    existing = get_room_by_number(data["room_number"])
    if existing:
        return {"error": f"Room {data['room_number']} already exists"}
    
    data["created_at"] = datetime.utcnow()
    data["updated_at"] = datetime.utcnow()
    room_id = create_room(data)
    return {"message": "Room created successfully", "id": room_id}

def modify_room(room_id: str, data: dict):
    room = get_room_by_id(room_id)
    if not room:
        return {"error": "Room not found"}
    
    updated = update_room(room_id, data)
    if updated:
        return {"message": "Room updated successfully"}
    return {"error": "No changes made"}

def remove_room(room_id: str):
    room = get_room_by_id(room_id)
    if not room:
        return {"error": "Room not found"}
    
    delete_room(room_id)
    return {"message": "Room deleted successfully"}