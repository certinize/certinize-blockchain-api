import blacksheep

from app import services, settings


async def create_storage_svcs_client(app: blacksheep.Application):
    storage = services.StorageService(
        endpoint_url=settings.app_settings.certinize_object_processor,
        headers={"X-API-Key": str(settings.app_settings.certinize_api_key)},
    )
    app.services.add_instance(storage)  # type: ignore


async def dispose_storage_svcs_client(app: blacksheep.Application):
    http_client: services.StorageService = app.service_provider[services.StorageService]
    await http_client.session.close()


async def create_gmail_client(app: blacksheep.Application):
    email = services.Emailer(
        sender_address=settings.app_settings.gmail_address,
        sender_password=settings.app_settings.gmail_password,
        smtp_server_url=settings.app_settings.gmail_smtp_server,
    )
    app.services.add_instance(email)  # type: ignore


async def dispose_gmail_client(app: blacksheep.Application):
    email: services.Emailer = app.service_provider[services.Emailer]
    email.smtp_session.close()


async def create_logger_svcs_client(app: blacksheep.Application):
    logger = services.LoggerService(
        endpoint_url=settings.app_settings.cerog,
        timezone=settings.app_settings.timezone,
    )
    app.services.add_instance(logger)  # type: ignore


async def dispose_logger_svcs_client(app: blacksheep.Application):
    logger: services.LoggerService = app.service_provider[services.LoggerService]
    await logger.client.close()

async def create_issuance_util(app: blacksheep.Application):
    issuance_util = services.IssuanceUtil(solana_api_endpoint=settings.app_settings.solana_api_endpoint)
    app.services.add_instance(issuance_util)  # type: ignore