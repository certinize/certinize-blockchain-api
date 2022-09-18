"""
app.models
~~~~~~~~~~

This module contains pydantic validation schemas for the API.
"""
import re

import pydantic
import solders.keypair as solders_keypair  # type: ignore # pylint: disable=E0401
from nacl.bindings import crypto_core
from solana import publickey

PanicException = re.compile(r"\((.*?)\)")


class RecipientMeta(pydantic.BaseModel):
    recipient_email: pydantic.EmailStr
    recipient_name: str
    recipient_pubkey: str
    recipient_ecert_url: pydantic.HttpUrl

    @pydantic.validator("recipient_pubkey")
    @classmethod
    def recipient_pubkey_on_curve(cls, value: str):
        try:
            crypto_core.crypto_core_ed25519_is_valid_point(
                bytes(publickey.PublicKey(value))
            )
        except ValueError as val_err:
            val_err.args = ("the point must be on the curve",)
            raise val_err from val_err

        return value


class IssuerMeta(pydantic.BaseModel):
    issuer_name: str
    issuer_email: pydantic.EmailStr
    issuer_pubkey: str
    issuer_pvtket: str
    issuer_address: str | None = None
    issuer_website: pydantic.HttpUrl | None = None

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

    @pydantic.validator("issuer_pvtket")
    @classmethod
    def recipient_pvtkey_on_curve(cls, value: str):
        try:
            solders_keypair.Keypair().from_base58_string(value)
        except BaseException as base_err:
            raise ValueError(PanicException.findall(str(base_err))[1]) from base_err

        return value


class IssuanceRequest(pydantic.BaseModel):
    callback_endpoint: pydantic.AnyHttpUrl
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
