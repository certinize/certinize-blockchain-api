"""
app.models
~~~~~~~~~~

This module contains pydantic validation schemas for the API.
"""
import re

import pydantic

from app.utils import crypto

PANIC_EXCEPTION = re.compile(r"\((.*?)\)")


class RecipientMeta(pydantic.BaseModel):
    recipient_email: pydantic.EmailStr
    recipient_name: str
    recipient_pubkey: str
    recipient_ecert_url: pydantic.HttpUrl

    @pydantic.validator("recipient_pubkey")
    @classmethod
    def recipient_pubkey_on_curve(cls, value: str):
        return crypto.pubkey_on_curve(value)


class IssuerMeta(pydantic.BaseModel):
    issuer_name: str
    issuer_email: pydantic.EmailStr
    issuer_pubkey: str
    issuer_website: pydantic.HttpUrl

    @pydantic.validator("issuer_pubkey")
    @classmethod
    def issuer_pubkey_on_curve(cls, value: str):
        return crypto.pubkey_on_curve(value)


class IssuanceRequest(pydantic.BaseModel):
    issuer_meta: IssuerMeta
    recipient_meta: list[RecipientMeta]
    request_id: pydantic.UUID1
    signature: str
    event_title: str


class Keypair(pydantic.BaseModel):
    pubkey: str = pydantic.Field(title="pubkey")
    pvtkey: str = pydantic.Field(title="pvtkey")

    @pydantic.root_validator()
    @classmethod
    def pvtkey_matches_pubkey(cls, values: dict[str, str]) -> dict[str, str]:
        if not crypto.verify_keypair(values["pubkey"], values["pvtkey"]):
            raise ValueError("Private key does not match public key")

        return values


class NonFungibleTokenMetadata(pydantic.BaseModel):
    """Pydantic model for validating NFT meta according to Metaplex's standard."""

    name: str
    description: str
    image: pydantic.HttpUrl
    symbol: str | None = None
    attributes: list[dict[str, str]] | None = None
    external_url: pydantic.AnyHttpUrl
