from typing import Any, Dict, Generic, Optional

from fastapi import Response

from fastapi_users import models
from fastapi_users.authentication.strategy import (
    Strategy,
    StrategyDestroyNotSupportedError,
)
from fastapi_users.authentication.transport import (
    Transport,
    TransportLogoutNotSupportedError,
    TransportTokenResponse,
)
from fastapi_users.types import DependencyCallable


class AuthenticationBackend(Generic[models.UP, models.ID]):
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
        get_strategy: DependencyCallable[Strategy[models.UP, models.ID]],
        get_refresh_strategy: Optional[
            DependencyCallable[Strategy[models.UP, models.ID]]
        ] = None,
    ):
        self.name = name
        self.transport = transport
        self.get_strategy = get_strategy
        self.get_refresh_strategy = get_refresh_strategy

    async def login(
        self,
        strategy: Strategy[models.UP, models.ID],
        user: models.UP,
        response: Response,
        refresh_strategy: Optional[Strategy[models.UP, models.ID]] = None,
        access_token_additional_properties: Optional[Dict[str, Any]] = None,
        refresh_token_additional_properties: Optional[Dict[str, Any]] = None,
    ) -> Any:
        token_response = TransportTokenResponse(
            access_token=await strategy.write_token(
                user, access_token_additional_properties
            )
        )
        if refresh_strategy:
            token_response.refresh_token = await refresh_strategy.write_token(
                user, refresh_token_additional_properties
            )
        return await self.transport.get_login_response(token_response, response)

    async def logout(
        self,
        strategy: Strategy[models.UP, models.ID],
        user: models.UP,
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
