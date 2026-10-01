import _asyncio


def probe():
    return _asyncio.get_running_loop()
