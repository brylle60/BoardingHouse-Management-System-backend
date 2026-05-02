from pydantic import BaseModel, Field
from typing import List, Optional
from enum import Enum

class RoomType(str, Enum):
    single  = "single"
    double  = "double"
    shared  = "shared"

class RoomStatus(str, Enum):
    available   = "available"
    occupied    = "occupied"
    maintenance = "maintenance"

class RoomCreateDTO(BaseModel):
    room_number:  str
    floor:        int
    type:         RoomType
    status:       RoomStatus = RoomStatus.available
    monthly_rate: float
    amenities:    List[str] = []
    max_occupants: int

    class Config:
        use_enum_values = True

class RoomUpdateDTO(BaseModel):
    floor:         Optional[int]        = None
    type:          Optional[RoomType]   = None
    status:        Optional[RoomStatus] = None
    monthly_rate:  Optional[float]      = None
    amenities:     Optional[List[str]]  = None
    max_occupants: Optional[int]        = None

    class Config:
        use_enum_values = True