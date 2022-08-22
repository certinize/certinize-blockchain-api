# pylint: disable=E1101

import typing

import blacksheep
import orjson

BAD_REQUEST = 400
UNPROCESSABLE_ENTITY = 422


class BadRequest(Exception):
    pass


async def bad_request_exception_handler(
    _self: typing.Any, _request: blacksheep.Request, exc: BadRequest
) -> blacksheep.Response:
    assert isinstance(exc, BadRequest)
    return blacksheep.Response(
        400,
        content=blacksheep.Content(
            data=orjson.dumps({"details": "Bad Request", "code": BAD_REQUEST}),
            content_type=b"application/json",
        ),
    )
