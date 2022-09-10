# flake8: noqa
# pylint: disable=R0913,R0914
"""
app.metadata
~~~~~~~~~~~~

This module contains the metadata program.
"""
import asyncio
import base64
import enum
import struct
import typing

import base58
import construct
from solana import publickey, transaction
from solana.rpc import api

# https://solerscan.com/programs
METADATA_PROGRAM_ID = publickey.PublicKey("metaqbxxUerdq28cj1RbAWkYQm3ybzjb6a8bt518x1s")
SYSTEM_PROGRAM_ID = publickey.PublicKey("1" * 32)
SYSVAR_RENT_PUBKEY = publickey.PublicKey("SysvarRent111111111111111111111111111111111")
TOKEN_PROGRAM_ID = publickey.PublicKey("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA")
ASSOCIATED_TOKEN_ACCOUNT_PROGRAM_ID = publickey.PublicKey(
    "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL"
)


class InstructionType(enum.IntEnum):
    CREATE_METADATA = 0
    UPDATE_METADATA = 1


async def get_metadata_account(mint_key: publickey.PublicKey) -> publickey.PublicKey:
    return publickey.PublicKey.find_program_address(
        [b"metadata", bytes(METADATA_PROGRAM_ID), bytes(mint_key)],
        METADATA_PROGRAM_ID,
    )[0]


def unpack_metadata_account(
    data: bytes,
) -> dict[str, bytes | dict[str, str | typing.Any | list[bytes] | list[int]] | bool]:
    assert data[0] == 4
    i = 1
    source_account = base58.b58encode(
        bytes(struct.unpack("<" + "B" * 32, data[i : i + 32]))
    )
    i += 32
    mint_account = base58.b58encode(
        bytes(struct.unpack("<" + "B" * 32, data[i : i + 32]))
    )
    i += 32
    name_len = struct.unpack("<I", data[i : i + 4])[0]
    i += 4
    name = struct.unpack("<" + "B" * name_len, data[i : i + name_len])
    i += name_len
    symbol_len = struct.unpack("<I", data[i : i + 4])[0]
    i += 4
    symbol = struct.unpack("<" + "B" * symbol_len, data[i : i + symbol_len])
    i += symbol_len
    uri_len = struct.unpack("<I", data[i : i + 4])[0]
    i += 4
    uri = struct.unpack("<" + "B" * uri_len, data[i : i + uri_len])
    i += uri_len
    fee = struct.unpack("<h", data[i : i + 2])[0]
    i += 2
    has_creator = data[i]
    i += 1
    creators: list[bytes] = []
    verified: list[int] = []
    share: list[int] = []

    if has_creator:
        creator_len = struct.unpack("<I", data[i : i + 4])[0]
        i += 4
        for _ in range(creator_len):
            creator = base58.b58encode(
                bytes(struct.unpack("<" + "B" * 32, data[i : i + 32]))
            )
            creators.append(creator)
            i += 32
            verified.append(data[i])
            i += 1
            share.append(data[i])
            i += 1

    primary_sale_happened = bool(data[i])
    i += 1
    is_mutable = bool(data[i])
    metadata = {
        "update_authority": source_account,
        "mint": mint_account,
        "data": {
            "name": bytes(name).decode("utf-8").strip("\x00"),
            "symbol": bytes(symbol).decode("utf-8").strip("\x00"),
            "uri": bytes(uri).decode("utf-8").strip("\x00"),
            "seller_fee_basis_points": fee,
            "creators": creators,
            "verified": verified,
            "share": share,
        },
        "primary_sale_happened": primary_sale_happened,
        "is_mutable": is_mutable,
    }

    return metadata


async def _get_acc_val(
    loop: asyncio.AbstractEventLoop,
    client: api.Client,
    metadata_account: publickey.PublicKey,
):
    account_info = await loop.run_in_executor(
        None, client.get_account_info, metadata_account
    )
    return account_info.get("result")


async def get_metadata(
    client: api.Client, mint_key: publickey.PublicKey
) -> dict[str, typing.Any]:
    metadata_account = await get_metadata_account(mint_key)
    result: dict[str, typing.Any] | None = None
    value = None
    loop = asyncio.get_running_loop()

    # Only wait for the account value until a reasonable amount of time. We don't want
    # the process to run for too long. If the value is still not available, we simply
    # give up. Just log the error, notify the issuer, and give a refund.
    max_attempts = 60
    for _ in range(max_attempts):
        result = await _get_acc_val(loop, client, metadata_account)

        if result is not None:
            value = result["value"]
        else:
            # For now, we won't count this as an attempt as there hasn't been any
            # reported issue regarding retrieval of account info for a public key.
            max_attempts += 1
            continue

        if value is not None:
            break

        await asyncio.sleep(1)

    if value is None:
        raise RuntimeError("Could not get account value")

    if result is not None:
        data = base64.b64decode(result["value"]["data"][0])
        metadata = unpack_metadata_account(data)
        return metadata

    return {}


async def get_edition(mint_key: publickey.PublicKey):
    return publickey.PublicKey.find_program_address(
        [b"metadata", bytes(METADATA_PROGRAM_ID), bytes(mint_key), b"edition"],
        METADATA_PROGRAM_ID,
    )[0]


async def get_data_buffer(
    name: str,
    symbol: str,
    uri: str,
    fee: int,
    creators: list[str],
    verified: list[int] | None = None,
    share: list[int] | None = None,
) -> bytes:
    if isinstance(share, list):
        assert len(share) == len(creators)

    if isinstance(verified, list):
        assert len(verified) == len(creators)

    args = [
        len(name),
        *list(name.encode()),
        len(symbol),
        *list(symbol.encode()),
        len(uri),
        *list(uri.encode()),
        fee,
    ]

    byte_fmt = "<"
    byte_fmt += "I" + "B" * len(name)
    byte_fmt += "I" + "B" * len(symbol)
    byte_fmt += "I" + "B" * len(uri)
    byte_fmt += "h"
    byte_fmt += "B"

    if creators:
        args.append(1)
        byte_fmt += "I"
        args.append(len(creators))

        for index, creator in enumerate(creators):
            byte_fmt += "B" * 32 + "B" + "B"
            args.extend(list(base58.b58decode(creator)))

            if isinstance(verified, list):
                args.append(verified[index])
            else:
                args.append(1)

            if isinstance(share, list):
                args.append(share[index])
            else:
                args.append(100)
    else:
        args.append(0)

    return struct.pack(byte_fmt, *args)


async def update_metadata_instruction_data(
    name: str,
    symbol: str,
    uri: str,
    fee: int,
    creators: list[str],
    verified: list[int],
    share: list[int],
) -> bytes:
    data_buffer = await get_data_buffer(
        name,
        symbol,
        uri,
        fee,
        creators,
        verified,
        share,
    )
    data = bytes([1]) + data_buffer + bytes([0, 0])
    instruc_type = "instruction_type" / construct.Int8ul
    struct_args = "args" / construct.Bytes(len(data))
    instruction_layout = construct.Struct(instruc_type, struct_args)

    return instruction_layout.build(
        dict(
            instruction_type=InstructionType.UPDATE_METADATA,
            args=data,
        )
    )


async def update_metadata_instruction(
    data: bytes, update_authority: publickey.PublicKey, mint_key: publickey.PublicKey
):
    metadata_account = await get_metadata_account(mint_key)
    keys = [
        transaction.AccountMeta(
            pubkey=metadata_account, is_signer=False, is_writable=True
        ),
        transaction.AccountMeta(
            pubkey=update_authority, is_signer=True, is_writable=False
        ),
    ]

    return transaction.TransactionInstruction(
        keys=keys, program_id=METADATA_PROGRAM_ID, data=data
    )


async def create_master_edition_instruction(
    mint: publickey.PublicKey,
    update_authority: publickey.PublicKey,
    mint_authority: publickey.PublicKey,
    payer: publickey.PublicKey,
    supply: int | None = None,
):
    edition_account = await get_edition(mint)
    metadata_account = await get_metadata_account(mint)

    if supply is None:
        data = struct.pack("<BB", 10, 0)
    else:
        data = struct.pack("<BBQ", 10, 1, supply)

    keys = [
        transaction.AccountMeta(
            pubkey=edition_account, is_signer=False, is_writable=True
        ),
        transaction.AccountMeta(pubkey=mint, is_signer=False, is_writable=True),
        transaction.AccountMeta(
            pubkey=update_authority, is_signer=True, is_writable=False
        ),
        transaction.AccountMeta(
            pubkey=mint_authority, is_signer=True, is_writable=False
        ),
        transaction.AccountMeta(pubkey=payer, is_signer=True, is_writable=False),
        transaction.AccountMeta(
            pubkey=metadata_account, is_signer=False, is_writable=False
        ),
        transaction.AccountMeta(
            pubkey=TOKEN_PROGRAM_ID,
            is_signer=False,
            is_writable=False,
        ),
        transaction.AccountMeta(
            pubkey=SYSTEM_PROGRAM_ID,
            is_signer=False,
            is_writable=False,
        ),
        transaction.AccountMeta(
            pubkey=SYSVAR_RENT_PUBKEY,
            is_signer=False,
            is_writable=False,
        ),
    ]

    return transaction.TransactionInstruction(
        keys=keys,
        program_id=METADATA_PROGRAM_ID,
        data=data,
    )


async def create_associated_token_account_instruction(
    associated_token_account: publickey.PublicKey,
    payer: publickey.PublicKey,
    wallet_address: publickey.PublicKey,
    token_mint_address: publickey.PublicKey,
) -> transaction.TransactionInstruction:
    keys = [
        transaction.AccountMeta(pubkey=payer, is_signer=True, is_writable=True),
        transaction.AccountMeta(
            pubkey=associated_token_account, is_signer=False, is_writable=True
        ),
        transaction.AccountMeta(
            pubkey=wallet_address, is_signer=False, is_writable=False
        ),
        transaction.AccountMeta(
            pubkey=token_mint_address, is_signer=False, is_writable=False
        ),
        transaction.AccountMeta(
            pubkey=SYSTEM_PROGRAM_ID, is_signer=False, is_writable=False
        ),
        transaction.AccountMeta(
            pubkey=TOKEN_PROGRAM_ID, is_signer=False, is_writable=False
        ),
        transaction.AccountMeta(
            pubkey=SYSVAR_RENT_PUBKEY, is_signer=False, is_writable=False
        ),
    ]

    return transaction.TransactionInstruction(
        keys=keys, program_id=ASSOCIATED_TOKEN_ACCOUNT_PROGRAM_ID
    )


async def create_metadata_instruction_data(
    name: str, symbol: str, seller_fee_basis: int, creators: list[str]
) -> bytes:
    data_buffer = await get_data_buffer(
        name, symbol, " " * 64, seller_fee_basis, creators
    )
    metadata_args_layout = construct.Struct(
        "data" / construct.Bytes(len(data_buffer)),
        "is_mutable" / construct.Flag,
    )
    metadata_args = dict(data=data_buffer, is_mutable=True)
    instruction_layout = construct.Struct(
        "instruction_type" / construct.Int8ul,
        "args" / metadata_args_layout,
    )
    return instruction_layout.build(
        dict(
            instruction_type=InstructionType.CREATE_METADATA,
            args=metadata_args,
        )
    )


async def create_metadata_instruction(
    data: bytes,
    update_authority: publickey.PublicKey,
    mint_key: publickey.PublicKey,
    mint_authority_key: publickey.PublicKey,
    payer: publickey.PublicKey,
) -> transaction.TransactionInstruction:
    metadata_account = await get_metadata_account(mint_key)
    keys = [
        transaction.AccountMeta(
            pubkey=metadata_account, is_signer=False, is_writable=True
        ),
        transaction.AccountMeta(pubkey=mint_key, is_signer=False, is_writable=False),
        transaction.AccountMeta(
            pubkey=mint_authority_key, is_signer=True, is_writable=False
        ),
        transaction.AccountMeta(pubkey=payer, is_signer=True, is_writable=False),
        transaction.AccountMeta(
            pubkey=update_authority, is_signer=False, is_writable=False
        ),
        transaction.AccountMeta(
            pubkey=SYSTEM_PROGRAM_ID, is_signer=False, is_writable=False
        ),
        transaction.AccountMeta(
            pubkey=SYSVAR_RENT_PUBKEY, is_signer=False, is_writable=False
        ),
    ]

    return transaction.TransactionInstruction(
        keys=keys, program_id=METADATA_PROGRAM_ID, data=data
    )
