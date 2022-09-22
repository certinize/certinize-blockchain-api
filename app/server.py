# pylint: disable=E1101
"""
app.server
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
app.on_start += events.get_issuance_util
app.on_stop += events.dispose_storage_svcs_client
app.on_stop += events.dispose_gmail_client


@app.router.get("/")
async def index() -> dict[str, str]:
    return {"message": "ok"}


@app.router.post("/issuances")
async def issue_certificate(
    data: bindings.FromIssuanceRequestModel[models.IssuanceRequest],
    storage_svcs: services.StorageService,
    issuance_util: services.IssuanceUtil,
    emailer: services.Emailer,
) -> blacksheep.Response:
    asyncio.create_task(
        issuance_util.issue_certificate(data.value, storage_svcs, emailer)
    )

    return blacksheep.Response(
        status=202,
        content=blacksheep.Content(
            b"application/json", orjson.dumps({"message": "Issuance request accepted"})
        ),
    )
