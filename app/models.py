"""
app.models
~~~~~~~~~~

This module contains pydantic validation schemas for the API.
"""
import typing
import uuid

import pydantic


class IssuanceRequest(pydantic.BaseModel):
    callback_endpoint: pydantic.HttpUrl
    correlation_id: uuid.UUID
    recipient_meta: list[dict[str, typing.Any]]

    @pydantic.validator("recipient_meta")
    @classmethod
    def recipient_meta_has_valid_fields(cls, value: list[dict[str, typing.Any]]):
        for recipient in value:
            if "description" not in recipient:
                raise ValueError("Missing description in recipient_meta.")
            if "email" not in recipient:
                raise ValueError("Missing email in recipient_meta.")
            if "recipient_name" not in recipient:
                raise ValueError("Missing recipient_name in recipient_meta.")
            if "user_id" not in recipient:
                raise ValueError("Missing user_id in recipient_meta.")
            if "wallet_address" not in recipient:
                raise ValueError("Missing wallet_address in recipient_meta.")


class NonFungibleTokenMetadata(pydantic.BaseModel):
    ...
