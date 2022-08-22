"""
app.dependencies
~~~~~~~~~~~~~~~~

This module contains dependencies for the API.
"""
import blacksheep
from pydantic import error_wrappers

from app import exceptions, models


class Validator:  # pylint: disable=R0903
    @staticmethod
    async def validate_issuance_request(request: blacksheep.Request):
        req = await request.json()

        try:
            models.IssuanceRequest(**req)
        except error_wrappers.ValidationError as error:
            return {
                "details": [dict(err) for err in error.errors()],
                "code": exceptions.UNPROCESSABLE_ENTITY,
                "err": "",
            }

        return req
