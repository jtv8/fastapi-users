from datetime import datetime
from typing import Generic, List

from pydantic import BaseModel

from fastapi_users import models


class TokenData(BaseModel, Generic[models.UP]):
    user: models.UP
    issued_at: datetime
    expires_at: datetime
    last_authenticated: datetime
    scopes: List[str]

    @property
    def fresh(self) -> bool:
        return self.issued_at == self.last_authenticated

    class Config:
        arbitrary_types_allowed = True
