import sys
from typing import Any, Optional, Type

if sys.version_info < (3, 8):
    from typing_extensions import Protocol  # pragma: no cover
else:
    from typing import Protocol  # pragma: no cover

from fastapi import Response
from fastapi.security.base import SecurityBase
from pydantic import BaseModel

from fastapi_users.openapi import OpenAPIResponseType


class TransportLogoutNotSupportedError(Exception):
    pass


class TransportTokenResponse(BaseModel):
    access_token: str
    refresh_token: Optional[str] = None


class Transport(Protocol):
    response_model: Optional[Type[BaseModel]] = None
    scheme: SecurityBase

    async def get_login_response(
        self, token: TransportTokenResponse, response: Response
    ) -> Any:
        ...  # pragma: no cover

    async def get_logout_response(self, response: Response) -> Any:
        ...  # pragma: no cover

    @staticmethod
    def get_openapi_login_responses_success() -> OpenAPIResponseType:
        """Return a dictionary to use for the openapi responses route parameter."""
        ...  # pragma: no cover

    @staticmethod
    def get_openapi_logout_responses_success() -> OpenAPIResponseType:
        """Return a dictionary to use for the openapi responses route parameter."""
        ...  # pragma: no cover
