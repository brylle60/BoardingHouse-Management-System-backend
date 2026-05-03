from pydantic import BaseModel
from typing import TypeVar, Generic, Optional

T = TypeVar("T")


class ApiResponse(BaseModel, Generic[T]):
    is_success:  bool
    message:     str
    data:        Optional[T] = None
    status_code: int         = 200

    @classmethod
    def success(
        cls,
        data:        Optional[T] = None,
        message:     str         = "Success",
        status_code: int         = 200,
    ) -> "ApiResponse[T]":
        return cls(is_success=True, message=message, data=data, status_code=status_code)

    @classmethod
    def error(
        cls,
        message:     str = "An error occurred",
        status_code: int = 400,
    ) -> "ApiResponse[None]":
        return cls(is_success=False, message=message, data=None, status_code=status_code)