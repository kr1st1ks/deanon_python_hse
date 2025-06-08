import asyncio
import socket

from app.schemas.security import DNSBLEntry, SecurityInfoResponse

DNSBL_SERVERS = [
    "bl.spamcop.net",
    "b.barracudacentral.org",
    "spam.dnsbl.sorbs.net",
    "bl.blocklist.de",
    "all.s5h.net",
    "blacklist.woody.ch",
    "bogons.cymru.com",
    "cbl.abuseat.org",
    "cdl.anti-spam.org.cn",
    "combined.abuse.ch",
    "db.wpbl.info",
    "dnsbl-1.uceprotect.net",
    "dnsbl-2.uceprotect.net",
    "dnsbl-3.uceprotect.net",
    "dnsbl.anticaptcha.net",
    "dnsbl.cyberlogic.net",
    "dnsbl.dronebl.org",
    "dnsbl.inps.de",
    "dnsbl.sorbs.net",
    "drone.abuse.ch",
    "duinv.aupads.org",
    "dul.dnsbl.sorbs.net",
    "dyna.spamrats.com",
    "dynip.rothen.com",
    "exitnodes.tor.dnsbl.sectoor.de",
    "http.dnsbl.sorbs.net",
    "ips.backscatterer.org",
    "ix.dnsbl.manitu.net",
    "korea.services.net",
    "misc.dnsbl.sorbs.net",
    "noptr.spamrats.com",
    "orvedb.aupads.org",
    "pbl.spamhaus.org",
    "proxy.bl.gweep.ca",
    "psbl.surriel.com",
    "relays.bl.gweep.ca",
    "relays.nether.net",
    "sbl.spamhaus.org",
    "short.rbl.jp",
    "singular.ttk.pte.hu",
    "smtp.dnsbl.sorbs.net",
    "socks.dnsbl.sorbs.net",
    "spam.abuse.ch",
    "spam.dnsbl.anonmails.de",
    "spam.dnsbl.sorbs.net",
    "spam.spamrats.com",
    "spambot.bls.digibase.ca",
    "spamrbl.imp.ch",
    "spamsources.fabel.dk",
    "ubl.lashback.com",
    "ubl.unsubscore.com",
    "virus.rbl.jp",
    "web.dnsbl.sorbs.net",
    "wormrbl.imp.ch",
    "xbl.spamhaus.org",
    "z.mailspike.net",
    "zen.spamhaus.org",
    "zombie.dnsbl.sorbs.net",
]


def reverse_ip(ip: str) -> str:
    """
    Реверсирует порядок октетов в IP-адресе для DNSBL-запроса.

    Args:
        ip (str): IPv4-адрес, например "1.2.3.4"

    Returns:
        str: IP-адрес в обратном порядке ("4.3.2.1")
    """
    return ".".join(reversed(ip.split(".")))


def validate_ip(ip: str) -> bool:
    """
    Проверяет, является ли строка валидным IPv4-адресом.

    Args:
        ip (str): Строка для проверки.

    Returns:
        bool: True, если адрес валиден, иначе False.
    """
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    for part in parts:
        if not part.isdigit():
            return False
        num = int(part)
        if num < 0 or num > 255:
            return False
    return True


async def check_dnsbl(ip: str, dnsbl: str, timeout: float = 1.0) -> dict:
    """
    Проверяет, занесён ли IP-адрес в конкретный DNSBL-сервер.

    Args:
        ip (str): Проверяемый IP.
        dnsbl (str): Имя DNSBL.
        timeout (float): Таймаут на запрос (секунд).

    Returns:
        dict: Словарь с результатом проверки или None при ошибке/таймауте.
    """
    reversed_ip = reverse_ip(ip)
    query = f"{reversed_ip}.{dnsbl}"
    try:
        await asyncio.wait_for(
            asyncio.get_event_loop().getaddrinfo(query, None), timeout=timeout
        )
        return {"dnsbl": dnsbl, "listed": True, "reason": None}
    except asyncio.TimeoutError:
        return None
    except socket.gaierror:
        return {"dnsbl": dnsbl, "listed": False, "reason": None}
    except Exception as e:
        return {"dnsbl": dnsbl, "listed": False, "reason": str(e)}


async def check_all_dnsbl(
    ip: str, max_concurrent: int = 50, timeout: float = 1.5
) -> list[dict]:
    """
    Параллельно проверяет IP по всем DNSBL-серверам с
    ограничением одновременных запросов и таймаутом.

    Args:
        ip (str): Проверяемый IP.
        max_concurrent (int): Максимум одновременных запросов.
        timeout (float): Таймаут на один DNSBL-запрос.

    Returns:
        list[dict]: Список словарей-результатов по каждому серверу.
    """
    sem = asyncio.Semaphore(max_concurrent)

    async def sem_check(dnsbl):
        async with sem:
            return await check_dnsbl(ip, dnsbl, timeout=timeout)

    tasks = [sem_check(dnsbl) for dnsbl in DNSBL_SERVERS]
    results = await asyncio.gather(*tasks)
    # Отбрасываем None (например, таймауты)
    return [r for r in results if r is not None]


async def check_spam_lists(ip: str) -> list[dict]:
    """
    Проверяет IP по всем DNSBL, если IP корректен.

    Args:
        ip (str): Проверяемый IP.

    Returns:
        list[dict]: Список результатов check_dnsbl.
    """
    if not validate_ip(ip):
        raise ValueError("Invalid IP address")
    results = await check_all_dnsbl(ip)
    return results


async def get_security_info(ip: str) -> SecurityInfoResponse:
    """
    Выполняет полный анализ по DNSBL-спискам и возвращает структурированный ответ.

    Args:
        ip (str): Проверяемый IP.

    Returns:
        SecurityInfoResponse:
            - blacklisted=False, если IP не найден ни в одном списке.
            - blacklisted=[DNSBLEntry(...), ...], если найден хотя бы в одном.
    """
    raw_results = await check_spam_lists(ip)
    listed_entries = [
        DNSBLEntry(dnsbl=entry["dnsbl"], reason=entry["reason"])
        for entry in raw_results
        if entry.get("listed")
    ]
    if not listed_entries:
        return SecurityInfoResponse(blacklisted=False)
    return SecurityInfoResponse(blacklisted=listed_entries)
