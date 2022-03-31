from typing import Generic, List, Optional

import jwt
from pydantic import UUID4

from fastapi_users import models
from fastapi_users.authentication.strategy.base import (
    Strategy,
    StrategyDestroyNotSupportedError,
    StrategyTokenResponse,
)
from fastapi_users.jwt import SecretType, decode_jwt, generate_jwt
from fastapi_users.manager import BaseUserManager, UserNotExists


class JWTStrategy(Strategy[models.UC, models.UD]):
    def __init__(
        self,
        secret: SecretType,
        lifetime_seconds: Optional[int] = None,
        token_audience: List[str] = ["fastapi-users:auth"],
        algorithm: str = "HS256",
        public_key: Optional[SecretType] = None,
        refresh_token: bool = False,
        refresh_token_lifetime_seconds: Optional[int] = None,
    ):
        self.secret = secret
        self.lifetime_seconds = lifetime_seconds
        self.token_audience = token_audience
        self.algorithm = algorithm
        self.public_key = public_key
        self.refresh_token = refresh_token
        self.refresh_token_lifetime_seconds = refresh_token_lifetime_seconds

    @property
    def encode_key(self) -> SecretType:
        return self.secret

    @property
    def decode_key(self) -> SecretType:
        return self.public_key or self.secret

    async def read_token(
        self, token: Optional[str], user_manager: BaseUserManager[models.UC, models.UD]
    ) -> Optional[models.UD]:
        if token is None:
            return None

        try:
            data = decode_jwt(
                token, self.decode_key, self.token_audience, algorithms=[self.algorithm]
            )
            user_id = data.get("user_id")
            if user_id is None:
                return None
        except jwt.PyJWTError:
            return None

        try:
            user_uiid = UUID4(user_id)
            return await user_manager.get(user_uiid)
        except ValueError:
            return None
        except UserNotExists:
            return None

    async def write_token(self, user: models.UD) -> StrategyTokenResponse:
        data = {
            "user_id": str(user.id),  # retained for backward compatibility
            "sub": str(user.id),
            "aud": self.token_audience,
        }

        access_token = generate_jwt(
            data, self.encode_key, self.lifetime_seconds, algorithm=self.algorithm
        )

        if self.refresh_token:
            refresh_token = generate_jwt(
                data,
                self.encode_key,
                self.refresh_token_lifetime_seconds,
                algorithm=self.algorithm,
            )
        else:
            refresh_token = None

        return StrategyTokenResponse(
            access_token=access_token,
            refresh_token=refresh_token,
        )

    async def destroy_token(self, token: str, user: models.UD) -> None:
        raise StrategyDestroyNotSupportedError(
            "A JWT can't be invalidated: it's valid until it expires."
        )
