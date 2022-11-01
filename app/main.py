# pylint: disable=E1101
"""
app.main
~~~~~~~~~~

This module contains the server startup logic.
"""
import asyncio
import platform
import uuid

import blacksheep
import orjson
import uvloop

from app import bindings, errors, events, models, services
from app.utils import crypto

if platform.system() == "Linux":
    asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())

app = blacksheep.Application()

# Exception handlers
app.exceptions_handlers[errors.BadRequest] = errors.error_400_handler  # type: ignore

# Dependencies
app.on_start += events.create_storage_svcs_client
app.on_start += events.create_gmail_client
app.on_start += events.create_logger_svcs_client
app.on_start += events.create_issuance_util
app.on_start += events.create_redis_client
app.on_stop += events.dispose_storage_svcs_client
app.on_stop += events.dispose_gmail_client
app.on_stop += events.dispose_logger_svcs_client

app.services.add_exact_singleton(services.TransactionUtil)  # type: ignore


@app.router.get("/")
async def index() -> dict[str, str]:
    return {"message": "ok"}


@app.router.post("/issuances")
async def issue_certificate(
    data: bindings.FromIssuanceRequestModel[models.IssuanceRequest],
    storage_svcs: services.StorageService,
    issuance_util: services.IssuanceUtil,
    emailer: services.Emailer,
    logger: services.LoggerService,
    transaction_util: services.TransactionUtil,
    redis: services.Redis,
) -> blacksheep.Response:
    issuer_request_info = await redis.hgetall(str(data.value.request_id))
    pubkey = issuer_request_info["pubkey"]
    message = issuer_request_info["message"]

    assert isinstance(pubkey, str)
    assert isinstance(message, str)

    if issuer_request_info is not None:
        try:
            _ = await transaction_util.verify_signature(
                pubkey, message, data.value.signature
            )
        except ValueError as invalid_sig:
            # Perhaps data.value.signature is a private key?
            is_keypair = crypto.verify_keypair(pubkey, data.value.signature)

            if not is_keypair:
                raise errors.BadRequest(
                    details=str(invalid_sig), status=422
                ) from invalid_sig

        asyncio.create_task(
            issuance_util.issue_certificate(
                data.value, storage_svcs, emailer, data.value.request_id, logger
            )
        )

        return blacksheep.Response(
            status=202,
            content=blacksheep.Content(
                b"application/json",
                orjson.dumps(
                    {
                        "message": "Issuance request accepted",
                        "request_id": str(data.value.request_id),
                    }
                ),
            ),
        )

    return blacksheep.Response(
        status=404,
        content=blacksheep.Content(
            b"application/json",
            orjson.dumps(
                {
                    "message": "Issuance request not found",
                    "request_id": str(data.value.request_id),
                }
            ),
        ),
    )


@app.router.get("/issuances/{pubkey}")
async def get_unsigned_message(
    transaction_util: services.TransactionUtil, redis: services.Redis, pubkey: str
) -> blacksheep.Response:
    pubkey = crypto.pubkey_on_curve(pubkey)
    request_id = str(uuid.uuid1())
    message = await transaction_util.generate_message(request_id)

    await redis.hset(request_id, {"message": f"{message}", "pubkey": pubkey})

    return blacksheep.Response(
        status=200,
        content=blacksheep.Content(
            b"application/json",
            orjson.dumps(
                {
                    "message": message,
                    "request_id": request_id,
                }
            ),
        ),
    )
