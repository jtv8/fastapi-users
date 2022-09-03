from typing import Any, Callable, Dict, Generic, Optional, Type, cast

import pytest
from fastapi import Response

from fastapi_users import models
from fastapi_users.authentication import (
    AuthenticationBackend,
    BearerTransport,
    Strategy,
)
from fastapi_users.authentication.strategy import StrategyDestroyNotSupportedError
from fastapi_users.authentication.transport.base import Transport
from fastapi_users.authentication.transport.bearer import BearerResponse
from tests.conftest import (
    IDType,
    MockStrategy,
    MockTransport,
    UserModel,
    assert_valid_token_response,
)


class MockTransportLogoutNotSupported(BearerTransport):
    pass


class MockStrategyDestroyNotSupported(MockStrategy, Generic[models.ID]):
    async def destroy_token(self, token: str, user: UserModel) -> None:
        raise StrategyDestroyNotSupportedError


@pytest.fixture(params=[MockTransport, MockTransportLogoutNotSupported])
def transport(request) -> Transport:
    transport_class: Type[BearerTransport] = request.param  # type: ignore
    return transport_class(tokenUrl="/login")


@pytest.fixture(params=[MockStrategy, MockStrategyDestroyNotSupported])
def get_strategy(request) -> Callable[..., Strategy[UserModel, IDType]]:
    strategy_class: Type[Strategy[UserModel, IDType]] = request.param  # type: ignore
    return lambda: strategy_class()


@pytest.fixture(params=[False, True])
def get_refresh_strategy(
    request,
) -> Optional[Callable[..., Strategy[UserModel, IDType]]]:
    if request.param:  # type: ignore
        return lambda: MockStrategy("refresh")
    else:
        return None


@pytest.fixture
def backend(
    transport: Transport,
    get_strategy: Callable[..., Strategy[UserModel, IDType]],
    get_refresh_strategy: Optional[Callable[..., Strategy[UserModel, IDType]]],
) -> AuthenticationBackend[UserModel, IDType]:
    return AuthenticationBackend(
        name="mock",
        transport=transport,
        get_strategy=get_strategy,
        get_refresh_strategy=get_refresh_strategy,
    )


@pytest.mark.asyncio
@pytest.mark.authentication
@pytest.mark.parametrize("access_token_additional_properties", [None, {"foo": "bar"}])
@pytest.mark.parametrize("refresh_token_additional_properties", [None, {"baz": "quux"}])
async def test_login(
    backend: AuthenticationBackend[UserModel, IDType],
    user: UserModel,
    access_token_additional_properties: Optional[Dict[str, Any]],
    refresh_token_additional_properties: Optional[Dict[str, Any]],
):
    strategy = cast(Strategy[UserModel, IDType], backend.get_strategy())

    if backend.get_refresh_strategy:
        refresh_strategy = cast(
            Strategy[UserModel, IDType], backend.get_refresh_strategy()
        )
        expecting_refresh_token = True
    else:
        refresh_strategy = None
        expecting_refresh_token = False

    result: BearerResponse = await backend.login(
        strategy,
        user,
        Response(),
        refresh_strategy,
        access_token_additional_properties,
        refresh_token_additional_properties,
    )

    assert_valid_token_response(
        user,
        result.dict(exclude_none=True),
        expecting_refresh_token,
        access_token_additional_properties,
        refresh_token_additional_properties if expecting_refresh_token else None,
    )


@pytest.mark.asyncio
@pytest.mark.authentication
async def test_logout(
    backend: AuthenticationBackend[UserModel, IDType], user: UserModel
):
    strategy = cast(Strategy[UserModel, IDType], backend.get_strategy())
    result = await backend.logout(strategy, user, "TOKEN", Response())
    assert result is None
