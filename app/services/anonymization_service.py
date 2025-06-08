import aiohttp
import dns.asyncresolver

from app.schemas.anonymization import AnonymizationInfo, TorInfo, VPNAndProxyInfo
from app.services.ip_service import get_location_by_ip
from app.utils.tor_exit_nodes import load_exit_nodes

# Глобальный асинхронный резолвер (singleton)
_resolver = dns.asyncresolver.Resolver()


async def detect_tor_usage(ip: str) -> TorInfo:
    """
    Проверяет, является ли указанный IP-адрес выходным узлом Tor.

    Использует два метода:
      1. Сравнение IP с локально загруженным списком выходных узлов.
      2. DNS-запрос к dnsel.torproject.org по IP.

    Args:
        ip (str): Проверяемый IP-адрес.

    Returns:
        TorInfo: Pydantic-модель с флагом is_tor, IP узла и страной выходного узла.
    """
    # Проверяем по локальному списку
    try:
        exits = await load_exit_nodes()
        is_member = ip in exits
    except Exception as e:
        print(f"[Tor] Error in load_exit_nodes: {e}")
        is_member = False

    # Проверяем через DNS-запрос (Tor Project)
    parts = ip.split(".")[::-1]
    query_name = ".".join(parts) + ".dnsel.torproject.org"
    try:
        answers = await _resolver.resolve(query_name, rdtype="A")
        dns_flag = any(r.to_text() == "127.0.0.2" for r in answers)
    except Exception:
        dns_flag = False

    # Если оба метода не сработали — считаем что это не Tor
    if not (is_member or dns_flag):
        return TorInfo(is_tor=False, exit_node_ip=None, exit_location=None)

    exit_location_info = await get_location_by_ip(ip)

    return TorInfo(
        is_tor=True,
        exit_node_ip=ip,
        exit_location=exit_location_info.country if exit_location_info else None,
    )


async def detect_vpn_proxy_usage(ip: str) -> VPNAndProxyInfo:
    """
    Проверяет, используется ли для данного IP VPN или прокси, с помощью API iphub.

    Args:
        ip (str): IP-адрес для проверки.

    Returns:
        VPNAndProxyInfo: Pydantic-модель с признаком обнаружения
        и (при наличии) названием сервиса.
    """
    url = f"http://v2.api.iphub.info/ip/{ip}"
    headers = {"X-Key": "MjgzNDA6aXRYOU4wMHBvN2lzc2lpTWZKRzJJV2wweXRqU1pwOEY="}

    async with aiohttp.ClientSession() as client:
        try:
            response = await client.get(url, headers=headers)
            response.raise_for_status()
            data = await response.json()

            # Если block == 1 — вероятен VPN/Proxy
            if data.get("block") == 1:
                return VPNAndProxyInfo(detected=True, service=data.get("isp"))
            return VPNAndProxyInfo(detected=False, service=None)
        except (aiohttp.ClientError, ValueError, KeyError):
            return VPNAndProxyInfo(detected=False, service=None)


async def get_anonymization_info(ip: str) -> AnonymizationInfo:
    """
    Собирает обобщённую информацию об анонимизации для IP:
      - Используется ли VPN (и его название)
      - Используется ли прокси (тип/провайдер — сейчас всегда None)
      - Используется ли Tor и геолокация exit-узла

    Args:
        ip (str): IP-адрес для анализа.

    Returns:
        AnonymizationInfo: Общая Pydantic-модель с данными по VPN, proxy, Tor.
    """
    vpn_proxy_info = await detect_vpn_proxy_usage(ip)
    tor_info = await detect_tor_usage(ip)

    return AnonymizationInfo(
        vpn_detected=vpn_proxy_info.detected,
        vpn_provider=vpn_proxy_info.service,
        proxy_detected=vpn_proxy_info.detected,
        proxy_type=None,
        proxy_provider=None,
        tor_detected=tor_info.is_tor,
        tor_exit_location=tor_info.exit_location,
    )
