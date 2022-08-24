# pylint: disable=E1101,I1101

import typing
from http.client import UNSUPPORTED_MEDIA_TYPE

import blacksheep
import orjson
from blacksheep import exceptions


class BadRequest(Exception):
    def __init__(
        self,
        message: str | None = None,
        details: dict[str, typing.Any] | None = None,
        status: int | None = None,
    ):
        super().__init__(message)
        self.status = status or 400
        self.details = details or {"details": ""}


class UnsupportedMediaType(exceptions.HTTPException):  # pylint: disable=R0903
    def __init__(self, message: str = "Unsupported Media Type"):
        super().__init__(UNSUPPORTED_MEDIA_TYPE, message)


async def error_400_handler(
    _self: typing.Any, _request: blacksheep.Request, exc: BadRequest
) -> blacksheep.Response:
    assert isinstance(exc, BadRequest)

    content = blacksheep.Content(
        data=orjson.dumps(exc.details | {"status": exc.status}),
        content_type=b"application/json",
    )

    return blacksheep.Response(exc.status, content=content)
