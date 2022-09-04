"""
app.models
~~~~~~~~~~

This module contains pydantic validation schemas for the API.
"""
import uuid

import pydantic
from nacl.bindings import crypto_core
from solana import publickey


class RecipientMeta(pydantic.BaseModel):
    issuance_description: str
    recipient_email: pydantic.EmailStr
    recipient_name: str
    recipient_user_id: pydantic.UUID1
    recipient_wallet_address: str
    recipient_ecert_url: pydantic.HttpUrl

    @pydantic.validator("recipient_wallet_address")
    @classmethod
    def recipient_wallet_address_on_curve(cls, value: str):
        try:
            crypto_core.crypto_core_ed25519_is_valid_point(
                bytes(publickey.PublicKey(value))
            )
        except ValueError as val_err:
            val_err.args = ("the point must be on the curve",)
            raise val_err from val_err

        return value


class IssuerMeta(pydantic.BaseModel):
    external_url: pydantic.HttpUrl
    issuer_email: pydantic.EmailStr
    issuer_pubkey: str
    issuer_pvtket: str

    @pydantic.validator("issuer_pubkey")
    @classmethod
    def issuer_pubkey_on_curve(cls, value: str):
        try:
            crypto_core.crypto_core_ed25519_is_valid_point(
                bytes(publickey.PublicKey(value))
            )
        except ValueError as val_err:
            val_err.args = ("the point must be on the curve",)
            raise val_err from val_err

        return value


class IssuanceRequest(pydantic.BaseModel):
    callback_endpoint: pydantic.HttpUrl
    correlation_id: uuid.UUID
    issuer_meta: IssuerMeta
    recipient_meta: list[RecipientMeta]


class NonFungibleTokenMetadata(pydantic.BaseModel):
    """Pydantic model for validating NFT meta according to Metaplex's standard."""

    name: str
    description: str
    image: pydantic.HttpUrl
    symbol: str | None = None
    attributes: list[dict[str, str]] | None = None
    external_url: pydantic.HttpUrl | None = None
