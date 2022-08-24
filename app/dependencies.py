"""
app.dependencies
~~~~~~~~~~~~~~~~

This module contains dependencies for the API.
"""
import typing
from http import client

import blacksheep
from pydantic import error_wrappers

from app import errors, models


class Validator:  # pylint: disable=R0903
    @staticmethod
    async def validate_issuance_request(request: blacksheep.Request):
        req = await request.json()

        try:
            models.IssuanceRequest(**req)
        except error_wrappers.ValidationError as validation_err:
            errors_: list[dict[str, typing.Any]] = []

            for error in validation_err.errors():
                err_idx = {}

                for err_item in error.items():
                    err_idx[err_item[0]] = str(err_item[1])

                errors_.append(err_idx)

            raise errors.BadRequest(
                details={"details": errors_},
                message="Invalid request body",
                status=client.UNPROCESSABLE_ENTITY,
            ) from validation_err

        return request
