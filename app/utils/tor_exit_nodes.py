import asyncio
import os

from app.core.config import settings
from app.utils.cache import Cache
from app.utils.http_client import HttpClient

_tor_cache = Cache()
_LOCAL_EXIT_PATH = os.path.join(os.path.dirname(__file__), "../utils/tor_exits.txt")


def _load_exits_from_file() -> set[str]:
    """
    Подгружает exit-ноды из локального файла.
    """
    try:
        with open(_LOCAL_EXIT_PATH, "r", encoding="utf-8") as f:
            ips = {ln.strip() for ln in f if ln and not ln.startswith("#")}
        return ips
    except Exception as e:
        print(f"[Tor] Ошибка чтения файла exit-нод: {e}")
        return set()


async def load_exit_nodes() -> set[str]:
    """
    Загрузить и закэшировать список Tor выходных узлов.
    Если не удаётся скачать онлайн за 0.5 сек — подгружает из файла.
    """
    if cached := _tor_cache.get("tor_exits"):
        return cached

    # Пытаемся скачать онлайн-версию с таймаутом
    async def download():
        async with HttpClient() as session:
            resp = await session.get(settings.TOR_EXIT_LIST_URL)
            text = await resp.text()
            return {
                ln.strip() for ln in text.splitlines() if ln and not ln.startswith("#")
            }

    try:
        ips = await asyncio.wait_for(download(), timeout=0.5)
        _tor_cache.set("tor_exits", ips, ttl=settings.CACHE_TTL_SECONDS)
        return ips
    except Exception as e:
        print(f"[Tor] Не удалось скачать exit-ноды онлайн: {e}")

    # Фолбэк: грузим из файла
    file_ips = _load_exits_from_file()
    _tor_cache.set("tor_exits", file_ips, ttl=settings.CACHE_TTL_SECONDS)
    return file_ips
