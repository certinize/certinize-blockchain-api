"""
app.server
~~~~~~~~~~

This module contains the server startup logic.
"""
import asyncio
import platform

import blacksheep
import uvloop

from app import bindings, errors, middlewares, models, settings

_settings = settings

if platform.system() == "Linux":
    asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())

app = blacksheep.Application()

# Exception handlers
app.exceptions_handlers[errors.BadRequest] = errors.error_400_handler  # type: ignore

# Middlewares
app.middlewares.append(middlewares.MediaTypeValidator())


@app.router.get("/")
async def index() -> dict[str, str]:
    return {
        "message": "Hello, World!",
        "documentation": "https://github.com/certinize/certinize-blockchain-api",
    }


@app.router.post("/issuances")
async def issue_certificate(
    data: bindings.FromIssuanceRequestModel[models.IssuanceRequest],
) -> models.IssuanceRequest:
    return data.value
