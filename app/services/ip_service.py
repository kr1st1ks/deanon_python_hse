import asyncio

import aiohttp
from ipwhois import IPWhois, WhoisLookupError

from app.exceptions import DataUnavailableError
from app.schemas.ip_info import LocationInfo, NetInfo, WhoisInfo


async def get_whois_info(ip: str) -> WhoisInfo:
    """
    Получает информацию WHOIS для заданного IP-адреса.

    Выполняет асинхронный запрос к локальной базе whois с помощью ipwhois
    и возвращает основную информацию, включая данные о сети (CIDR, название,
    описание, страна и т.д.), а также ASN, страну, дату и реестр.

    Args:
        ip (str): IP-адрес для поиска информации WHOIS.

    Returns:
        WhoisInfo: Pydantic-модель с основной whois-информацией и списком сетей.

    Raises:
        DataUnavailableError: Если не удалось получить данные о WHOIS.
    """
    loop = asyncio.get_event_loop()

    def lookup():
        # Инициализация объекта IPWhois и выполнение поиска
        obj = IPWhois(ip)
        try:
            return obj.lookup_whois()
        except WhoisLookupError as e:
            # Ошибка поиска whois — выбрасываем кастомное исключение
            raise DataUnavailableError(f"WHOIS lookup failed: {e}")
        except Exception as e:
            # Любая другая ошибка — также в кастомное исключение
            raise DataUnavailableError(f"Unknown WHOIS error: {e}")

    try:
        result = await loop.run_in_executor(None, lookup)
    except DataUnavailableError:
        # Пробрасываем дальше (обрабатывается выше по стеку)
        raise
    except Exception as e:
        # Неизвестная ошибка на уровне event loop
        raise DataUnavailableError(f"WHOIS unexpected error: {e}")

    nets = []
    for net in result.get("nets", []):
        # Формируем список сетей на основе результата whois
        nets.append(
            NetInfo(
                cidr=net.get("cidr"),
                name=net.get("name"),
                description=net.get("description"),
                country=net.get("country"),
                city=net.get("city"),
                address=net.get("address"),
                postal_code=net.get("postal_code"),
                state=net.get("state"),
                abuse_emails=net.get("abuse_emails"),
                tech_emails=net.get("tech_emails"),
                created=net.get("created"),
                updated=net.get("updated"),
            )
        )
    return WhoisInfo(
        ip=ip,
        asn=result.get("asn"),
        asn_cidr=result.get("asn_cidr"),
        asn_country_code=result.get("asn_country_code"),
        asn_date=result.get("asn_date"),
        asn_registry=result.get("asn_registry"),
        nets=nets,
    )


async def get_location_by_ip(ip_address: str) -> LocationInfo | None:
    """
    Определяет геолокацию и провайдера по IP-адресу.

    Выполняет запрос к публичному API ipinfo.io и возвращает данные о городе, регионе,
    стране, координатах, провайдере, индексе и временной зоне.

    Args:
        ip_address (str): IP-адрес для определения местоположения.

    Returns:
        LocationInfo | None: Pydantic-модель с локацией,
        либо None, если определить не удалось.
    """
    url = f"https://ipinfo.io/{ip_address}/json"

    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(url) as response:
                data = await response.json()

                # Обработка координат в формате "lat,lon"
                latitude = longitude = None
                if loc := data.get("loc"):
                    try:
                        lat_str, lon_str = loc.split(",")
                        latitude = float(lat_str)
                        longitude = float(lon_str)
                    except (ValueError, TypeError):
                        # Если координаты некорректные — оставляем None
                        pass

                return LocationInfo(
                    ip=data.get("ip"),
                    city=data.get("city"),
                    region=data.get("region"),
                    country=data.get("country"),
                    provider=data.get("org"),
                    latitude=latitude,
                    longitude=longitude,
                    postal_index=data.get("postal"),
                    timezone=data.get("timezone"),
                )

    except Exception:
        # В случае любой ошибки — возвращаем None (местоположение не определено)
        return None
