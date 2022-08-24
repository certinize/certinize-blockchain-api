import typing

import blacksheep

from app import errors


class MediaTypeValidator:  # pylint: disable=R0903
    async def __call__(
        self,
        request: blacksheep.Request,
        handler: typing.Callable[[blacksheep.Request], typing.Any],
    ):

        if request.content_type() != b"application/json":
            raise errors.UnsupportedMediaType()

        response = await handler(request)

        return response
