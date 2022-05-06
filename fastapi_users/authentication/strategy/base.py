import sys
from typing import Generic, Optional

if sys.version_info < (3, 8):
    from typing_extensions import Protocol  # pragma: no cover
else:
    from typing import Protocol  # pragma: no cover

from typing import Optional

from pydantic import BaseModel

from fastapi_users import models
from fastapi_users.manager import BaseUserManager


class StrategyTokenResponse(BaseModel):
    access_token: str
    refresh_token: Optional[str] = None


class StrategyDestroyNotSupportedError(Exception):
    pass


class Strategy(Protocol, Generic[models.UP, models.ID]):
    async def read_token(
        self, token: Optional[str], user_manager: BaseUserManager[models.UP, models.ID]
    ) -> Optional[models.UP]:
        ...  # pragma: no cover

    async def write_token(self, user: models.UP) -> StrategyTokenResponse:
        ...  # pragma: no cover

    async def destroy_token(self, token: str, user: models.UP) -> None:
        ...  # pragma: no cover
