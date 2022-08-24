"""
app.server
~~~~~~~~~~

This module contains the server startup logic.
"""
import asyncio
import platform
import typing

import blacksheep
import uvloop

from app import dependencies, errors, middlewares

if platform.system() == "Linux":
    asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())

app = blacksheep.Application()
app.services.add_exact_scoped(dependencies.Validator)  # type: ignore
app.exceptions_handlers[errors.BadRequest] = errors.error_400_handler  # type: ignore
app.middlewares.append(middlewares.MediaTypeValidator())

get = app.router.get
post = app.router.post


@get("/")
async def index() -> dict[str, str]:
    return {
        "message": "Hello, World!",
        "documentation": "https://github.com/certinize/certinize-blockchain-api",
    }


@post("/issuances")
async def issue_certificate(
    request: blacksheep.Request, test: dependencies.Validator
) -> dict[str, typing.Any]:

    request = await test.validate_issuance_request(request)
    request_body = await request.json()

    return request_body
