from typing import AsyncGenerator, Tuple

import httpx
import pytest
from fastapi import FastAPI, status

from fastapi_users.authentication import Authenticator
from fastapi_users.router import get_auth_router, get_refresh_router
from tests.conftest import (
    UserModel,
    assert_valid_token_response,
    get_mock_authentication,
    mock_valid_access_token,
    mock_valid_refresh_token,
)


@pytest.fixture
def app_factory(get_user_manager, mock_authentication, with_refresh_strategy: bool):
    def _app_factory(requires_verification: bool) -> FastAPI:
        mock_authentication_bis = get_mock_authentication(
            name="mock-bis", has_refresh_strategy=with_refresh_strategy
        )
        authenticator = Authenticator(
            [mock_authentication, mock_authentication_bis], get_user_manager
        )

        mock_auth_router = get_auth_router(
            mock_authentication,
            get_user_manager,
            authenticator,
            requires_verification=requires_verification,
        )
        mock_bis_auth_router = get_auth_router(
            mock_authentication_bis,
            get_user_manager,
            authenticator,
            requires_verification=requires_verification,
        )

        mock_refresh_router = get_refresh_router(
            mock_authentication,
            get_user_manager,
        )
        mock_bis_refresh_router = get_refresh_router(
            mock_authentication_bis,
            get_user_manager,
        )

        app = FastAPI()
        app.include_router(mock_auth_router, prefix="/mock")
        app.include_router(mock_bis_auth_router, prefix="/mock-bis")
        app.include_router(mock_refresh_router, prefix="/mock")
        app.include_router(mock_bis_refresh_router, prefix="/mock-bis")

        return app

    return _app_factory


@pytest.fixture(
    params=[True, False], ids=["required_verification", "not_required_verification"]
)
@pytest.mark.asyncio
async def test_app_client(
    request, get_test_client, app_factory
) -> AsyncGenerator[Tuple[httpx.AsyncClient, bool], None]:
    requires_verification = request.param
    app = app_factory(requires_verification)

    async for client in get_test_client(app):
        yield client, requires_verification


@pytest.mark.router
@pytest.mark.parametrize("with_refresh_strategy", [True], indirect=True)
@pytest.mark.parametrize("path", ["/mock", "/mock-bis"])
@pytest.mark.asyncio
class TestRefresh:
    async def test_malformed_token(
        self,
        path,
        test_app_client: Tuple[httpx.AsyncClient, bool],
    ):
        client, _ = test_app_client
        data = {"grant_type": "refresh_token", "refresh_token": "foo"}
        response = await client.post(f"{path}/refresh", data=data)
        assert response.status_code == status.HTTP_400_BAD_REQUEST

    async def test_access_token_used_as_refresh_token(
        self,
        path,
        test_app_client: Tuple[httpx.AsyncClient, bool],
        verified_user: UserModel,
    ):
        client, _ = test_app_client

        data = {
            "grant_type": "refresh_token",
            "refresh_token": mock_valid_access_token(verified_user),
        }
        response = await client.post(f"{path}/refresh", data=data)
        assert response.status_code == status.HTTP_400_BAD_REQUEST

    async def test_valid_refresh_token(
        self,
        path,
        test_app_client: Tuple[httpx.AsyncClient, bool],
        verified_user: UserModel,
    ):
        client, _ = test_app_client

        data = {
            "grant_type": "refresh_token",
            "refresh_token": mock_valid_refresh_token(verified_user),
        }
        response = await client.post(f"{path}/refresh", data=data)
        assert response.status_code == status.HTTP_200_OK
        assert_valid_token_response(
            verified_user, response.json(), expecting_refresh_token=True
        )


@pytest.mark.router
@pytest.mark.parametrize("with_refresh_strategy", [False], indirect=True)
@pytest.mark.parametrize("path", ["/mock", "/mock-bis"])
@pytest.mark.asyncio
class TestMisconfiguredRefresh:
    async def test_valid_refresh_token(
        self,
        path,
        test_app_client: Tuple[httpx.AsyncClient, bool],
        verified_user: UserModel,
    ):
        client, _ = test_app_client

        data = {
            "grant_type": "refresh_token",
            "refresh_token": mock_valid_refresh_token(verified_user),
        }
        response = await client.post(f"{path}/refresh", data=data)
        assert response.status_code == status.HTTP_500_INTERNAL_SERVER_ERROR
        assert response.json() == {"detail": "refresh_strategy_not_configured"}
