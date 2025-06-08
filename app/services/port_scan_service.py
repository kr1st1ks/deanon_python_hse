import asyncio
import socket
from typing import Union

from app.schemas.port_scan_info import PortScanResponse


async def check_port(ip: str, port: int, timeout: float = 0.3) -> int | None:
    """
    Асинхронно проверяет доступность указанного порта на IP-адресе.

    Args:
        ip (str): IP-адрес для проверки.
        port (int): Проверяемый порт.
        timeout (float): Таймаут (секунд) на каждую попытку.

    Returns:
        int | None: Порт, если открыт, иначе None.
    """
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port), timeout=timeout
        )
        writer.close()
        await writer.wait_closed()
        return port
    except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
        return None
    except Exception:
        return None


def get_service_name(port: int) -> str:
    """
    Определяет имя службы по TCP-порту (например, 80 -> 'http').

    Args:
        port (int): Номер порта.

    Returns:
        str: Название службы, если определено, иначе 'UNKNOWN'.
    """
    try:
        return socket.getservbyport(port, "tcp")
    except OSError:
        return "UNKNOWN"


async def port_scan(
    ip: str, max_ports: int = 10000, concurrency: int = 2000
) -> list[int]:
    """
    Асинхронно сканирует порты заданного IP-адреса в диапазоне 1..max_ports.

    Args:
        ip (str): IP-адрес для сканирования.
        max_ports (int): Максимальный порт (по умолчанию 10000).
        concurrency (int): Максимальное число одновременных запросов.

    Returns:
        list[int]: Список открытых портов.
    """
    semaphore = asyncio.Semaphore(concurrency)

    async def limited_check(port: int) -> int | None:
        async with semaphore:
            return await check_port(ip, port)

    tasks = [limited_check(port) for port in range(1, max_ports + 1)]
    results = await asyncio.gather(*tasks)
    return [port for port in results if port is not None]


async def port_scan_info(
    client_ip: str, max_ports: int = 10000, concurrency: int = 500, deep: int = 3
) -> Union[PortScanResponse, None]:
    """
    Выполняет глубокое сканирование портов: повторяет скан несколько раз (deep),
    собирает открытые порты с названиями сервисов.

    Args:
        client_ip (str): IP-адрес клиента для сканирования.
        max_ports (int): Диапазон портов (по умолчанию до 10000).
        concurrency (int): Максимальное число одновременных проверок.
        deep (int): Количество повторных проходов (устойчивость результата).

    Returns:
        set[str] | None: Множество строк в формате '{порт}:{сервис}',
        либо None если не найдено.
    """
    result_ip = set()
    for _ in range(deep):
        open_ports = await port_scan(client_ip, max_ports, concurrency)
        if open_ports:
            ports_with_services = {
                f"{port}:{get_service_name(port)}" for port in open_ports
            }
            result_ip.update(ports_with_services)
    if not result_ip:
        return PortScanResponse(
            open_ports=None,
            scanned_ports_count=max_ports,
            ip=client_ip,
        )
    return PortScanResponse(
        open_ports=result_ip,
        scanned_ports_count=max_ports,
        ip=client_ip,
    )
