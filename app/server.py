# pylint: disable=E1101
"""
app.server
~~~~~~~~~~

This module contains the server startup logic.
"""
import asyncio
import platform
import typing

import blacksheep
import orjson
import uvloop

from app import bindings, errors, events, middlewares, models, services

if platform.system() == "Linux":
    asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())

app = blacksheep.Application()

# Exception handlers
app.exceptions_handlers[errors.BadRequest] = errors.error_400_handler  # type: ignore

# Middlewares
app.middlewares.append(middlewares.MediaTypeValidator())

# Dependencies
app.on_start += events.create_storage_svcs_client
app.on_start += events.create_gmail_client
app.on_start += events.get_issuance_util
app.on_stop += events.dispose_storage_svcs_client
app.on_stop += events.dispose_gmail_client


@app.router.get("/")
async def index() -> dict[str, str]:
    return {
        "message": "Hello, World!",
        "documentation": "https://github.com/certinize/certinize-blockchain-api",
    }


@app.router.post("/issuances")
async def issue_certificate(
    data: bindings.FromIssuanceRequestModel[models.IssuanceRequest],
    storage_svcs: services.StorageService,
    issuance_util: services.IssuanceUtil,
    emailer: services.Emailer,
) -> typing.Any:
    asyncio.create_task(
        issuance_util.issue_certificate(data.value, storage_svcs, emailer)
    )

    return blacksheep.Response(
        status=202,
        content=blacksheep.Content(
            b"application/json", orjson.dumps({"message": "Issuance request accepted"})
        ),
    )
