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

from app import dependencies, exceptions

if platform.system() == "Linux":
    asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())

app = blacksheep.Application()
app.services.add_exact_scoped(dependencies.Validator)  # type: ignore
app.exceptions_handlers[  # type: ignore
    exceptions.BadRequest
] = exceptions.bad_request_exception_handler

get = app.router.get
post = app.router.post


@get("/")
async def index() -> dict[str, str]:
    return {
        "message": "Hello World!",
        "documentation": "https://github.com/certinize/certinize-blockchain-api",
    }


@post("/issuances")
async def issue_certificate(
    request: blacksheep.Request, test: dependencies.Validator
) -> dict[str, typing.Any]:
    if request.content_type() != b"application/json":
        raise exceptions.BadRequest("something went wrong")

    result = await test.validate_issuance_request(request)

    if "err" in result:
        return {
            "details": result["details"],
            "code": result["code"],
        }

    return {}
