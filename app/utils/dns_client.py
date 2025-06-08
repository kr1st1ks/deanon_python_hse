import dns.asyncresolver


class DnsClient:
    """
    Обёртка над dns.asyncresolver.Resolver для асинхронных DNS-запросов.
    Можно передать список nameservers, иначе будет использоваться системный резолвер.
    """

    def __init__(self, nameservers: list[str] = None):
        # если переданы nameservers — используем их, иначе системные из /etc/resolv.conf
        self.resolver = dns.asyncresolver.Resolver(configure=nameservers is None)
        if nameservers:
            self.resolver.nameservers = nameservers

    async def query(self, name: str, rdtype: str) -> list[str]:
        """
        Выполняет DNS-запрос указанного типа (A, AAAA, MX, NS, CNAME и т.д.).
        Возвращает список строковых представлений записей, или [] при ошибке/отсутствии.
        """
        try:
            answer = await self.resolver.resolve(name, rdtype=rdtype)
            return [r.to_text() for r in answer]
        except Exception:
            return []
