# pylint: disable=E1101
"""
app.main
~~~~~~~~~~

This module contains the server startup logic.
"""
import asyncio
import platform

import blacksheep
import orjson
import uvloop

from app import bindings, errors, events, models, services

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
    data: bindings.FromIssuanceRequest[models.IssuanceRequest],
    storage_svcs: services.StorageService,
    issuance_util: services.IssuanceUtil,
    emailer: services.Emailer,
    logger: services.LoggerService,
    transaction_util: services.TransactionUtil,
    redis: services.Redis,
) -> blacksheep.Response:
    issuer_request_info = await redis.hgetall(str(data.value.request_id))
    pubkey = issuer_request_info.get("pubkey")
    pvtkey = issuer_request_info.get("pvtkey")
    message = issuer_request_info.get("message")

    if pubkey is None:
        raise errors.BadRequest(
            "Invalid request ID", details="Request ID not found", status=404
        )

    assert isinstance(pubkey, str)
    assert isinstance(pvtkey, str)
    assert isinstance(message, str)

    if issuer_request_info is not None:
        # try:
        #     _ = await transaction_util.verify_signature(
        #         pubkey, message, data.value.signature
        #     )
        # except ValueError as invalid_sig:
        #     raise errors.BadRequest(
        #         details=str(invalid_sig), status=422
        #     ) from invalid_sig

        # We have to overwrite the signature as
        # services.IssuanceUtil.issue_certificate() uses it for the keypair that will
        # sign the transaction
        data.value.signature = pvtkey

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


@app.router.get("/issuances")
async def get_unsigned_message(
    data: bindings.FromKeypairBindedr[models.Keypair],
    transaction_util: services.TransactionUtil,
    redis: services.Redis,
) -> blacksheep.Response:
    message, request_id = await transaction_util.generate_message(redis, data.value)

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
