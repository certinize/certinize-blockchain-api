import typing

import orjson
from blacksheep.plugins import json


def serialize(value: typing.Any) -> str:
    return orjson.dumps(value).decode("utf8")


json.use(  # type: ignore
    loads=orjson.loads,  # type: ignore
    dumps=serialize,  # type: ignore
)
