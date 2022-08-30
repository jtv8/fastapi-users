from typing import Any

from fastapi import Response, status
from fastapi.security import OAuth2, OAuth2PasswordBearer
from pydantic import Field

from fastapi_users.authentication.transport.base import (
    TransportTokenResponse,
    Transport,
    TransportLogoutNotSupportedError,
)
from fastapi_users.openapi import OpenAPIResponseType


class BearerResponse(TransportTokenResponse):
    token_type: str = Field(default="bearer", regex="bearer")


class BaseBearerTransport(Transport):
    response_model = BearerResponse
    scheme: OAuth2

    def __init__(self, scheme: OAuth2):
        self.scheme = scheme

    async def get_login_response(
        self, token: TransportTokenResponse, response: Response
    ) -> Any:
        return BearerResponse(**dict(token))

    async def get_logout_response(self, response: Response) -> Any:
        raise TransportLogoutNotSupportedError()

    @staticmethod
    def get_openapi_login_responses_success() -> OpenAPIResponseType:
        return {
            status.HTTP_200_OK: {
                "model": BearerResponse,
                "content": {
                    "application/json": {
                        "example": {
                            "access_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1"
                            "c2VyX2lkIjoiOTIyMWZmYzktNjQwZi00MzcyLTg2Z"
                            "DMtY2U2NDJjYmE1NjAzIiwiYXVkIjoiZmFzdGFwaS"
                            "11c2VyczphdXRoIiwiZXhwIjoxNTcxNTA0MTkzfQ."
                            "M10bjOe45I5Ncu_uXvOmVV8QxnL-nZfcH96U90JaocI",
                            "token_type": "bearer",
                        }
                    }
                },
            },
        }

    @staticmethod
    def get_openapi_logout_responses_success() -> OpenAPIResponseType:
        return {}


class BearerTransport(BaseBearerTransport):
    scheme: OAuth2PasswordBearer

    def __init__(self, tokenUrl: str):
        super().__init__(OAuth2PasswordBearer(tokenUrl, auto_error=False))
