import sys
from typing import Any, Dict, Generic, Optional

if sys.version_info < (3, 8):
    from typing_extensions import Protocol  # pragma: no cover
else:
    from typing import Protocol  # pragma: no cover

from fastapi_users import models
from fastapi_users.authentication.token import TokenData
from fastapi_users.manager import BaseUserManager


class StrategyDestroyNotSupportedError(Exception):
    pass


class Strategy(Protocol, Generic[models.UP, models.ID]):
    async def read_token(
        self, token: Optional[str], user_manager: BaseUserManager[models.UP, models.ID]
    ) -> Optional[TokenData[models.UP]]:
        ...  # pragma: no cover

    async def write_token(
        self,
        token_data: TokenData[models.UP],
    ) -> str:
        ...  # pragma: no cover

    async def destroy_token(self, token: str, user: models.UP) -> None:
        ...  # pragma: no cover
