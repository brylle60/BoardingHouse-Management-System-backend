from fastapi import APIRouter, HTTPException
from dto.room_dto import RoomCreateDTO, RoomUpdateDTO
from services.room_service import (
    fetch_all_rooms, fetch_room, fetch_rooms_by_status,
    add_room, modify_room, remove_room
)

router = APIRouter()

# GET all rooms
@router.get("/")
def get_rooms():
    return fetch_all_rooms()

# GET rooms by status
@router.get("/status/{status}")
def get_by_status(status: str):
    return fetch_rooms_by_status(status)

# GET single room
@router.get("/{room_id}")
def get_room(room_id: str):
    room = fetch_room(room_id)
    if not room:
        raise HTTPException(status_code=404, detail="Room not found")
    return room

# POST create room
@router.post("/")
def create_room(payload: RoomCreateDTO):
    result = add_room(payload.dict())
    if "error" in result:
        raise HTTPException(status_code=400, detail=result["error"])
    return result

# PUT update room
@router.put("/{room_id}")
def update_room(room_id: str, payload: RoomUpdateDTO):
    data = {k: v for k, v in payload.dict().items() if v is not None}
    result = modify_room(room_id, data)
    if "error" in result:
        raise HTTPException(status_code=404, detail=result["error"])
    return result

# DELETE room
@router.delete("/{room_id}")
def delete_room(room_id: str):
    result = remove_room(room_id)
    if "error" in result:
        raise HTTPException(status_code=404, detail=result["error"])
    return result