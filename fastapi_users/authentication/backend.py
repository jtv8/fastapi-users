from typing import Any, Generic, Optional

from fastapi import Response

from fastapi_users import models
from fastapi_users.authentication.strategy import (
    Strategy,
    StrategyDestroyNotSupportedError,
)
from fastapi_users.authentication.transport import (
    Transport,
    TransportLogoutNotSupportedError,
)
from fastapi_users.types import DependencyCallable


class AuthenticationBackend(Generic[models.UC, models.UD]):
    """
    Combination of an authentication transport and strategy.

    Together, they provide a full authentication method logic.

    :param name: Name of the backend.
    :param transport: Authentication transport instance.
    :param get_strategy: Dependency callable returning
    an authentication strategy instance.
    """

    name: str
    transport: Transport

    def __init__(
        self,
        name: str,
        transport: Transport,
        get_strategy: DependencyCallable[Strategy[models.UC, models.UD]],
        get_refresh_token_strategy: Optional[
            DependencyCallable[Strategy[models.UC, models.UD]]
        ],
    ):
        self.name = name
        self.transport = transport
        self.get_strategy = get_strategy
        if get_refresh_token_strategy:
            self.get_refresh_token_strategy = get_refresh_token_strategy
        else:
            self.get_refresh_token_strategy = lambda: None

    async def login(
        self,
        strategy: Strategy[models.UC, models.UD],
        user: models.UD,
        response: Response,
        refresh_token_strategy: Optional[Strategy[models.UC, models.UD]] = None,
    ) -> Any:
        access_token = await strategy.write_token(user)

        if refresh_token_strategy:
            refresh_token = await refresh_token_strategy.write_token(user)
        else:
            refresh_token = None

        return await self.transport.get_login_response(
            access_token,
            response,
            refresh_token=refresh_token,
        )

    async def logout(
        self,
        strategy: Strategy[models.UC, models.UD],
        user: models.UD,
        token: str,
        response: Response,
    ) -> Any:
        try:
            await strategy.destroy_token(token, user)
        except StrategyDestroyNotSupportedError:
            pass

        try:
            await self.transport.get_logout_response(response)
        except TransportLogoutNotSupportedError:
            return None
