"""
app.server
~~~~~~~~~~

This module contains the server startup logic.
"""
import asyncio
import dataclasses
import datetime
import platform
import time
import typing
import uuid

import aiohttp
import blacksheep
import orjson
import pydantic
import uvloop
import xxhash

from app import bindings, errors, events, middlewares, models, services
from app.utils import requests

if platform.system() == "Linux":
    asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())

app = blacksheep.Application()

# Exception handlers
app.exceptions_handlers[errors.BadRequest] = errors.error_400_handler  # type: ignore

# Middlewares
app.middlewares.append(middlewares.MediaTypeValidator())

# Dependencies
app.on_start += events.create_client
app.on_stop += events.dispose_client


@dataclasses.dataclass
class AssetLink:
    nft_storage_link = "https://{cid}.ipfs.nftstorage.link/{filename}"
    filebase_link = "https://ipfs.filebase.io/ipfs/{cid}"


@app.router.get("/")
async def index() -> dict[str, str]:
    return {
        "message": "Hello, World!",
        "documentation": "https://github.com/certinize/certinize-blockchain-api",
    }


@app.router.post("/issuances")
async def issue_certificate(
    data: bindings.FromIssuanceRequestModel[models.IssuanceRequest],
    permanent_storage: services.PermanentStorage,
) -> typing.Any:
    # * We have to store the generated file names (xxh3_64) for later retreival with
    # * their corresponding RecipientMeta.recipient_user_id as the key. File names are
    # * used to associate recipients to their respective certificates.
    filenames: dict[str, str] = {}

    http_client = aiohttp.ClientSession()
    image_files: dict[str, tuple[str, bytes]] = {}

    # Construct the request body for the upload of e-Certificates.
    for recipient in data.value.recipient_meta:
        filename = f"{xxhash.xxh3_64(str(datetime.datetime.now().timestamp())).hexdigest()}.jpeg"
        filenames[str(recipient.recipient_user_id)] = filename

        certificate_src = await requests.get_files(
            http_client, recipient.recipient_ecert_url
        )

        # We use JPEG as the content-type, the global default, as the ecert processor
        # service produces jpegs to generate e-Certificates.
        image_files[filename] = ("image/jpeg", certificate_src)

    # Upload e-Certificates to permanent storage (IPFS). The response values will be
    # used later to verify if the files were uploaded successfully.
    response = await permanent_storage.upload_permanent_object(image_files)
    resp_val = response["response_meta"]["value"]
    cid = resp_val["cid"]
    files: list[dict[str, str]] = resp_val["files"]

    # * Store the filenames with the wallet addresses as keys so that we don't have to
    # * map them later. The content of this dict will be used to mint e-Certificates
    # * and email the issuer and recipients.
    # Example structure: {
    #   "B7KN...": {
    #     "filename": "filename",
    #     "nft_meta": "https://...",
    #     "transaction_sig": "46Kyz...",
    #   }
    # }
    recipient_ecerts: dict[str, dict[str, typing.Any]] = {}

    # Use the current year and month as the first part of the certificate's unique
    # identifier. This will be used to name the public data storage (JSON file) that
    # that will help verify e-Certificate legitimacy.
    yr_mth = datetime.datetime.today().strftime("%Y-%m")

    # nft_meta_coll is a collection of dictionaries containing NFT metadata. They will
    # be converted to JSON and uploaded to a permanent storage.
    nft_metas_coll: list[dict[str, typing.Any]] = []

    for recipient in data.value.recipient_meta:
        # Although we stored the generated file names earlier, we still have to check
        # if they were successfully uploaded. To do so, we simply have to check if file
        # name is in the response. We retrieve the file/ecert name from the response
        # using the recipient_user_id and construct the ecert URL. This is much safer
        # than matching by index, which might cause recipients to receive incorrect
        # e-Certifiactes.
        ecert_url = ""

        for file in files:
            # A `file` contains the name of the file and its content-type. Example:
            # {"name": "5c630887.jpeg", "type": "image/jpeg"}
            ecert_fname = file.get("name")

            if ecert_fname == filenames[str(recipient.recipient_user_id)]:
                ecert_url = AssetLink.nft_storage_link.format(
                    cid=cid, filename=file["name"]
                )

                recipient_ecerts[recipient.recipient_wallet_address] = {
                    "filename": ecert_fname,
                    "nft_meta": "",
                    "transaction_sig": "",
                }
                break

        # Naturally, if ecert_fname is empty, then the file was not uploaded. We skip
        # the current iteration.
        if ecert_url == "":
            continue

        # The certificate ID is composed of two xxh3_64 hashed values. The former part
        # of the certificate ID identifies the data storage that can help verify the
        # legitimacy of the e-Certificate. The latter part is a unique identifier
        # assigned to the e-Certificate.
        certificate_id = (
            f"""{xxhash.xxh3_64(yr_mth).hexdigest()}-"""
            f"""{xxhash.xxh3_64(f"{uuid.uuid1()}").hexdigest()}"""
        )

        # The symbol can be anything, but it must be unique. To create a symbol, we
        # combibe the recipient's initials and the xxhash of the current date and time.
        symbol = (
            "".join([name[0].upper() for name in recipient.recipient_name.split(" ")])
            + f"""-{xxhash.xxh3_64(str(datetime.datetime.today())).hexdigest().upper()}"""
        )

        # We have to generate the nft_meta inside a pydantic model to ensure the
        # key-value pairs conform with Metaplex's standard, we return a 500 otherwise.
        # NOTE: external_url should be a link that leads to the JSON file containing
        # public information about the issuer.
        try:
            nft_meta = dict(
                models.NonFungibleTokenMetadata(
                    name=recipient.recipient_name,
                    symbol=symbol,
                    description=recipient.issuance_description,
                    image=pydantic.HttpUrl(url=ecert_url, scheme="https"),
                    external_url=data.value.issuer_meta.external_url,
                    attributes=[
                        {"trait_type": "identification", "value": certificate_id},
                        {
                            "trait_type": "issuer",
                            "value": data.value.issuer_meta.issuer_pubkey,
                        },
                    ],
                )
            )

            nft_metas_coll.append(nft_meta)
            recipient_ecerts[recipient.recipient_wallet_address][
                "nft_meta"
            ] = f"""{nft_meta["symbol"]}.json"""
        except ValueError as val_err:
            raise blacksheep.exceptions.InternalServerError(str(val_err))

    # TODO: Return error code generating NFT metadata for all recipients failed.
    # * This could mean that the e-Certificates were not uploaded successfully.
    # * Email issuer if issuance failed for certain recipients.

    # Upload the constructed NFT JSON metadata to permanent storage (IPFS).
    json_meta: dict[str, tuple[str, bytes]] = {}

    for nft_meta in nft_metas_coll:
        json_meta[f"""{nft_meta["symbol"]}.json"""] = (
            "application/json",
            orjson.dumps(nft_meta),
        )

    response = await permanent_storage.upload_permanent_object(json_meta)

    # Mint token.
    cfg = {
        "public_key": data.value.issuer_meta.issuer_pubkey,
        "private_key": data.value.issuer_meta.issuer_pvtket,
    }
    txn_intf = services.TokenFlow(cfg=cfg)

    for recipient in data.value.recipient_meta:
        nft_meta_url = ""
        nft_meta = recipient_ecerts[recipient.recipient_wallet_address]["nft_meta"]
        nft_id = str(time.time())

        for resp in response["response_meta"]:
            if resp["Key"] == nft_meta:
                nft_meta_url = AssetLink.filebase_link.format(
                    cid=resp["HTTPHeaders"]["x-amz-meta-cid"]
                )
                break

        result = await txn_intf.deploy(
            api_endpoint=services.SOLANA_API_ENDPOINT,
            name=xxhash.xxh32(nft_id).hexdigest(),
            symbol="-".join([char for char in xxhash.xxh3_64(nft_id).hexdigest()[:5]]),
        )

        if isinstance(contract_key := result["contract"], str):
            mint_res = await txn_intf.mint(
                api_endpoint=services.SOLANA_API_ENDPOINT,
                contract_key=contract_key,
                destination_key=recipient.recipient_wallet_address,
                link=nft_meta_url,
            )

            if (rpc_resp := mint_res["response"]) is not None:
                recipient_ecerts[recipient.recipient_wallet_address][
                    "transaction_sig"
                ] = dict(rpc_resp)["result"]

    # TODO:
    # Insert issuance information into immediate database (API Call to recipient-db)
    # Email recipients and notify them of the issuance
    # Email issuer and notify them of the issuance

    await http_client.close()

    return {}
