import re

import solders.keypair as solders_keypair  # type: ignore # pylint: disable=E0401
from nacl.bindings import crypto_core
from solana import publickey

PANIC_EXCEPTION = re.compile(r"\((.*?)\)")


def pubkey_on_curve(value: str) -> str:
    """Check if the point is on the curve.

    Args:
        value (str): The point to check.

    Raises:
        ValueError: If the point is not on the curve.

    Returns:
        str: The point.
    """
    try:
        crypto_core.crypto_core_ed25519_is_valid_point(
            bytes(publickey.PublicKey(value))
        )
    except ValueError as val_err:
        val_err.args = ("the point must be on the curve",)
        raise val_err from val_err

    return value


def pvtkey_on_curve(value: str) -> str:
    """Check if the point is on the curve.

    Args:
        value (str): The point to check.

    Raises:
        ValueError: If the point is not on the curve.

    Returns:
        str: The point.
    """
    try:
        solders_keypair.Keypair().from_base58_string(value)
    except BaseException as base_err:
        raise ValueError(PANIC_EXCEPTION.findall(str(base_err))[1]) from base_err

    return value


def verify_keypair(public_key: str, private_key: str | list[int]) -> bool:
    """Verify the keypair.

    Args:
        public_key (str): The public key.
        private_key (str | list[int]): The private key.

    Raises:
        ValueError: If the keypair is invalid.
    """
    if isinstance(private_key, list):
        pvtkey = publickey.PublicKey(bytes(private_key)).to_base58()
    else:
        pvtkey = bytes(private_key, "utf-8")

    return publickey.PublicKey(public_key).to_base58() != pvtkey
