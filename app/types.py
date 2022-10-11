import typing

from solana.rpc import types as rpc_types

NftMetadataTup = tuple[dict[str, dict[str, typing.Any]], list[dict[str, typing.Any]]]
EcertsUploadMeta = tuple[dict[str, dict[str, typing.Any]], typing.Any]
FnamesUpload = tuple[dict[str, str], typing.Any]
PubkeyMap = dict[str, dict[str, typing.Any]]
MintResult = tuple[PubkeyMap, dict[str, str | None]]
CreateTokenResult = tuple[
    dict[str, dict[str, rpc_types.RPCResponse | str | None]],
    dict[str, str | None],
    typing.Any,
    list[str],
]
