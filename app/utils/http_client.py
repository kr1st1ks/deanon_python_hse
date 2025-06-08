from aiohttp import ClientSession, ClientTimeout


class HttpClient:
    """
    Асинхронный HTTP-клиент на базе aiohttp с единым timeout и reuse sessions.
    """

    def __init__(self, timeout: float = 0):
        self._timeout = ClientTimeout(total=timeout)
        self._session: ClientSession | None = None

    async def __aenter__(self) -> ClientSession:
        if self._session is None or self._session.closed:
            self._session = ClientSession(timeout=self._timeout)
        return self._session

    async def __aexit__(self, exc_type, exc, tb):
        if self._session and not self._session.closed:
            await self._session.close()
