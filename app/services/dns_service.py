import asyncio
import logging
import re
import socket
import uuid

from dnslib import QTYPE, RR, A
from dnslib.server import BaseResolver, DNSServer

from app.core.config import settings
from app.schemas.dns_info import DnsLeakResult, DnsLeakTest, FullResolve
from app.utils.cache import Cache
from app.utils.dns_client import DnsClient
from app.utils.http_client import HttpClient

_cache = Cache()
_dns_leak_tests: dict[str, set[str]] = {}

logger = logging.getLogger(__name__)


async def enumerate_subdomains(domain: str) -> list[str]:
    """
    Получает список поддоменов для указанного домена через публичный API crt.sh.
    Результат кэшируется на 24 часа. Если сервис недоступен — возвращает пустой список.

    Args:
        domain (str): Базовый домен для поиска поддоменов.

    Returns:
        list[str]: Отсортированный список обнаруженных поддоменов.
    """
    cache_key = f"subs:{domain}"
    cached = _cache.get(cache_key)
    if cached is not None:
        return cached  # type: ignore

    url = settings.CRTSH_API_URL.format(domain=domain)
    try:
        async with HttpClient() as session:
            response = await session.get(url)
            data = await response.json()
    except Exception as e:
        logger.error(f"Не удалось получить поддомены для {domain}: {e}")
        return []

    subs = set()
    for entry in data:
        if "name_value" in entry:
            name = entry["name_value"].lstrip("*.").lower()
            subs.add(name)

    result = sorted(subs)
    _cache.set(cache_key, result, ttl=86400)
    return result


async def full_dns_resolve(identifier: str) -> FullResolve:
    """
    Выполняет полный DNS-resolve для указанного IP-адреса или доменного имени:
      1. Если identifier — это IPv4-адрес, делает обратный PTR-запрос (hostname).
      2. Получает поддомены для найденного домена
      (или самого IP, если PTR не определён).
      3. Для всех имён (домен + поддомены) делает
      DNS-запросы типов A, AAAA, CNAME, MX, NS.
      4. Формирует Pydantic-модель FullResolve с результатами.

    Args:
        identifier (str): IP-адрес или доменное имя.

    Returns:
        FullResolve: Pydantic-модель с полным списком поддоменов и всеми DNS-записями.
    """
    ip_pattern = r"^(?:\d{1,3}\.){3}\d{1,3}$"
    if re.match(ip_pattern, identifier):
        try:
            ptr_result = await asyncio.to_thread(socket.gethostbyaddr, identifier)
            domain = ptr_result[0]
        except Exception:
            domain = identifier
    else:
        domain = identifier

    subdomains = await enumerate_subdomains(domain)
    hosts = [domain] + subdomains

    client = DnsClient()
    full_records: dict[str, list[str]] = {}

    async def resolve_one(host: str):
        record_types = ["A", "AAAA", "CNAME", "MX", "NS"]
        flat_list: list[str] = []
        tasks = {rtype: client.query(host, rtype) for rtype in record_types}
        for rtype, task in tasks.items():
            recs = await task
            flat_list.extend(recs)
        full_records[host] = flat_list

    await asyncio.gather(*(resolve_one(h) for h in hosts))
    return FullResolve(subdomains=hosts, full_records=full_records)


class LeakTestResolver(BaseResolver):
    """
    Класс-резолвер для DNS-leak теста.
    Обслуживает запросы к сгенерированным тестовым поддоменам.
    """

    def __init__(self, test_id: str):
        self.test_id = test_id

    def resolve(self, request, handler):
        """
        Обрабатывает входящий DNS-запрос,
        отмечает факт запроса к одному из тестовых поддоменов.
        Возвращает фиктивную A-запись с IP 127.0.0.1.
        """
        qname = str(request.q.qname).rstrip(".")
        if self.test_id in _dns_leak_tests:
            _dns_leak_tests[self.test_id].add(qname)  # фиксируем любой запрос

        reply = request.reply()
        reply.add_question(request.q)
        reply.add_answer(
            RR(
                rname=request.q.qname,
                rtype=QTYPE.A,
                rclass=1,
                ttl=60,
                rdata=A("127.0.0.1"),
            )
        )
        return reply


def generate_dns_leak_test(
    count: int = 3, base_domain: str = "example.com"
) -> DnsLeakTest:
    """
    Генерирует уникальный test_id и список случайных поддоменов для DNS-leak теста.
    Сохраняет пары test_id: {domains} во внутреннем словаре.

    Args:
        count (int): Сколько поддоменов создать (по умолчанию 3).
        base_domain (str): Базовый домен для генерации поддоменов.

    Returns:
        DnsLeakTest: Pydantic-модель с test_id и списком доменов.
    """
    test_id = str(uuid.uuid4())
    domains = [f"{uuid.uuid4().hex[:8]}.{base_domain}" for _ in range(count)]
    _dns_leak_tests[test_id] = set(domains)
    return DnsLeakTest(test_id=test_id, domains=domains)


async def analyze_dns_leak(test_id: str, wait_time: int = 2) -> DnsLeakResult:
    """
    Анализирует, были ли резолвлены клиентом все сгенерированные тестовые поддомены
    (проверка на DNS-leak).
    Ожидает, пока все поддомены не запросятся, либо не истечёт таймаут.
    """
    if test_id not in _dns_leak_tests:
        raise ValueError(f"Test ID {test_id} не найден")

    resolver = LeakTestResolver(test_id)
    try:
        server = DNSServer(resolver, port=55353, address="0.0.0.0", tcp=False)
        server.start_thread()
    except Exception as e:
        logger.error(f"Не удалось запустить временный DNS сервер: {e}")
        raise RuntimeError("DNS leak test server start failed")

    expected = _dns_leak_tests[test_id].copy()
    seen = set()
    t0 = asyncio.get_event_loop().time()
    timeout = wait_time

    while True:
        seen = _dns_leak_tests[test_id]
        if expected <= seen:
            break
        if asyncio.get_event_loop().time() - t0 > timeout:
            break
        await asyncio.sleep(0.05)

    server.stop()
    missing = expected - seen
    leak_detected = len(missing) > 0

    result = DnsLeakResult(
        test_id=test_id,
        expected=sorted(expected),
        seen=sorted(seen),
        missing=sorted(missing),
        leak_detected=leak_detected,
    )
    del _dns_leak_tests[test_id]
    return result
