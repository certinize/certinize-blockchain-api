import blacksheep

from app import services, settings


async def create_client(app: blacksheep.Application):
    storage = services.PermanentStorage(
        endpoint_url=settings.app_settings.certinize_image_processor,
        headers={"X-API-Key": str(settings.app_settings.certinize_api_key)},
    )
    app.services.add_instance(storage)  # type: ignore


async def dispose_client(app: blacksheep.Application):
    http_client: services.PermanentStorage = app.service_provider[
        services.PermanentStorage
    ]
    await http_client.session.close()
