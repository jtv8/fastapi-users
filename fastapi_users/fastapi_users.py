from typing import Any, Generic, Optional, Sequence, Type

from fastapi import APIRouter

from fastapi_users import models
from fastapi_users.authentication import AuthenticationBackend, Authenticator
from fastapi_users.jwt import SecretType
from fastapi_users.manager import UserManagerDependency
from fastapi_users.router import (
    get_auth_router,
    get_refresh_router,
    get_register_router,
    get_reset_password_router,
    get_users_router,
    get_verify_router,
)

try:
    from httpx_oauth.oauth2 import BaseOAuth2

    OAuthClientType = BaseOAuth2[Any]

    from fastapi_users.router import get_oauth_router
except ModuleNotFoundError:  # pragma: no cover
    OAuthClientType = Any


class FastAPIUsers(Generic[models.U, models.UC, models.UU, models.UD]):
    """
    Main object that ties together the component for users authentication.

    :param get_user_manager: Dependency callable getter to inject the
    user manager class instance.
    :param auth_backends: List of authentication backends.
    :param user_model: Pydantic model of a user.
    :param user_create_model: Pydantic model for creating a user.
    :param user_update_model: Pydantic model for updating a user.
    :param user_db_model: Pydantic model of a DB representation of a user.

    :attribute current_user: Dependency callable getter to inject authenticated user
    with a specific set of parameters.
    """

    authenticator: Authenticator
    _user_model: Type[models.U]
    _user_create_model: Type[models.UC]
    _user_update_model: Type[models.UU]
    _user_db_model: Type[models.UD]

    def __init__(
        self,
        get_user_manager: UserManagerDependency[models.UC, models.UD],
        auth_backends: Sequence[AuthenticationBackend[models.UC, models.UD]],
        user_model: Type[models.U],
        user_create_model: Type[models.UC],
        user_update_model: Type[models.UU],
        user_db_model: Type[models.UD],
    ):
        self.authenticator = Authenticator(auth_backends, get_user_manager)

        self._user_model = user_model
        self._user_db_model = user_db_model
        self._user_create_model = user_create_model
        self._user_update_model = user_update_model

        self.get_user_manager = get_user_manager
        self.current_user = self.authenticator.current_user

    def get_register_router(self) -> APIRouter:
        """Return a router with a register route."""
        return get_register_router(
            self.get_user_manager,
            self._user_model,
            self._user_create_model,
        )

    def get_verify_router(self) -> APIRouter:
        """Return a router with e-mail verification routes."""
        return get_verify_router(self.get_user_manager, self._user_model)

    def get_reset_password_router(self) -> APIRouter:
        """Return a reset password process router."""
        return get_reset_password_router(self.get_user_manager)

    def get_auth_router(
        self,
        backend: AuthenticationBackend[models.UC, models.UD],
        requires_verification: bool = False,
    ) -> APIRouter:
        """
        Return an auth router for a given authentication backend.

        :param backend: The authentication backend instance.
        :param requires_verification: Whether the authentication
        require the user to be verified or not.
        """
        return get_auth_router(
            backend,
            self.get_user_manager,
            self.authenticator,
            requires_verification,
        )

    def get_refresh_router(
        self,
        backend: AuthenticationBackend[models.UC, models.UD],
    ) -> APIRouter:
        """
        Return a token refresh router for a given authentication backend.

        :param backend: The authentication backend instance.
        """
        return get_refresh_router(backend, self.get_user_manager)
 
    def get_oauth_router(
        self,
        oauth_client: OAuthClientType,
        backend: AuthenticationBackend[models.UC, models.UD],
        state_secret: SecretType,
        redirect_url: Optional[str] = None,
    ) -> APIRouter:
        """
        Return an OAuth router for a given OAuth client and authentication backend.

        :param oauth_client: The HTTPX OAuth client instance.
        :param backend: The authentication backend instance.
        :param state_secret: Secret used to encode the state JWT.
        :param redirect_url: Optional arbitrary redirect URL for the OAuth2 flow.
        If not given, the URL to the callback endpoint will be generated.
        """
        return get_oauth_router(
            oauth_client,
            backend,
            self.get_user_manager,
            state_secret,
            redirect_url,
        )

    def get_users_router(
        self,
        requires_verification: bool = False,
    ) -> APIRouter:
        """
        Return a router with routes to manage users.

        :param requires_verification: Whether the endpoints
        require the users to be verified or not.
        """
        return get_users_router(
            self.get_user_manager,
            self._user_model,
            self._user_update_model,
            self._user_db_model,
            self.authenticator,
            requires_verification,
        )
