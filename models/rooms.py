from datetime import datetime
from bson import ObjectId

def room_model(data: dict) -> dict:
    return {
        "_id":          str(data.get("_id", ObjectId())),
        "room_number":  data.get("room_number"),
        "floor":        data.get("floor"),
        "type":         data.get("type"),         # single | double | shared
        "status":       data.get("status"),        # available | occupied | maintenance
        "monthly_rate": data.get("monthly_rate"),
        "amenities":    data.get("amenities", []), # ["wifi", "aircon", ...]
        "max_occupants":data.get("max_occupants"),
        "created_at":   data.get("created_at", datetime.utcnow()),
        "updated_at":   data.get("updated_at", datetime.utcnow()),
    }

def rooms_list_model(rooms) -> list:
    return [room_model(room) for room in rooms]