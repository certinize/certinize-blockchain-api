import aiohttp


async def get_files(http_client: aiohttp.ClientSession, url: str) -> bytes:
    resp = await http_client.get(url)
    return await resp.read()
