import socket
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

from app.dependencies import get_client_ip
from app.exceptions import DataUnavailableError
from app.schemas.anonymization import AnonymizationInfo
from app.schemas.ip_info import LocationInfo, WhoisInfo
from app.schemas.os_info import OSInfo
from app.schemas.port_scan_info import PortScanResponse
from app.schemas.security import SecurityInfoResponse
from app.schemas.tunnel_ping import PingResponse, TunnelInfo
from app.services.anonymization_service import get_anonymization_info
from app.services.ip_service import get_location_by_ip, get_whois_info
from app.services.os_service import get_os_results
from app.services.port_scan_service import port_scan_info
from app.services.security_service import get_security_info
from app.services.tunnel_service import check_ip_for_tunnel, get_double_ping

router = APIRouter()
templates = Jinja2Templates(directory="app/templates")


@router.get("/analyze", response_class=HTMLResponse, tags=["Analyze"])
async def analyze_page(request: Request):
    """
    Возвращает HTML-страницу с UI для анализа.

    - Отдаёт шаблон analyze.html (кнопка, поле вывода JSON).
    - Используется как основной web-интерфейс сервиса.

    Args:
        request (Request): Starlette/FastAPI Request-объект.

    Returns:
        HTMLResponse: Отрендеренный HTML.
    """
    return templates.TemplateResponse("analyze.html", {"request": request})


@router.get(
    "/anonymization", response_model=AnonymizationInfo, tags=["Deanonymization"]
)
async def anonymization_endpoint(client_ip: str = Depends(get_client_ip)):
    """
    Выполняет анализ анонимизации пользователя по IP-адресу.

    - Определяет использование VPN, прокси, TOR-узлов и географию выхода.
    - Строит полную картину средств анонимизации, включая имена
     провайдеров, типы туннелей и exit-локацию TOR (если есть).
    - Используется для deanonymization-функций на бэкенде.

    Args:
        client_ip (str): IP-адрес пользователя (подставляется Depends).

    Returns:
        AnonymizationInfo: Pydantic-модель с результатами анализа.
    """
    anon_info: AnonymizationInfo = await get_anonymization_info(client_ip)
    return anon_info


@router.get("/whois_info", response_model=WhoisInfo, tags=["Deanonymization"])
async def ip_info_endpoint(client_ip: str = Depends(get_client_ip)):
    """
    Возвращает расширенную информацию по IP
     (геолокация, ASN, провайдер, автономная система).

    - Сначала валидирует IP.
    - Затем получает геолокационные данные, ASN, и info из WHOIS-базы.
    - Поддерживает единую pydantic-схему.

    Args:
        client_ip (str): IP-адрес пользователя.

    Returns:
        WhoisInfo: Pydantic-модель с полями по геолокации,
         ASN, провайдеру и автономной системе.
    """
    if not client_ip or not isinstance(client_ip, str):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Поле 'client_ip' должно быть непустой строкой",
        )
    try:
        whois_info = await get_whois_info(client_ip)
        return whois_info
    except DataUnavailableError:
        raise HTTPException(status_code=421, detail="Ошибка получения WHOIS информации")


@router.get(
    "/security_info", response_model=SecurityInfoResponse, tags=["Deanonymization"]
)
async def security_info_endpoint(client_ip: str = Depends(get_client_ip)):
    """
    Предоставляет сетевую и защитную информацию по IP-адресу.

    - Проверяет, занесён ли IP в спам-листы (DNSBL).
    - Содержит результаты безопасности, пригодные для
     использования в антифрод и сетевых решениях.

    Args:
        client_ip (str): IP-адрес пользователя.

    Returns:
        SecurityInfoResponse: Pydantic-модель с данными о безопасности IP.
    """
    if not client_ip or not isinstance(client_ip, str):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Поле 'client_ip' должно быть непустой строкой",
        )

    sec_info = await get_security_info(client_ip)
    return sec_info


@router.get("/port_scan", response_model=PortScanResponse, tags=["Deanonymization"])
async def port_scan_endpoint(
    client_ip: str = Depends(get_client_ip),
    max_ports: int = Query(1000, description="Число портов для проверки"),
):
    """
    Сканирует открытые порты на IP-адресе.

    - Валидирует корректность IP.
    - Запускает асинхронное сканирование (по умолчанию до 1000 портов).
    - Возвращает список найденных портов
    и краткую информацию о каждом (номер:имя_службы).

    Args:
        client_ip (str): IP пользователя.
        max_ports (int): Количество портов для сканирования (по умолчанию 1000).

    Returns:
        PortScanResponse: Pydantic-модель с открытыми портами,
        количеством сканирований и IP.
    """
    try:
        try:
            socket.inet_aton(client_ip)
        except socket.error:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST, detail="Некорректный IP-адрес"
            )
        result = await port_scan_info(
            client_ip=client_ip,
            max_ports=max_ports,
        )
        return result
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Ошибка сканирования: {str(e)}",
        )


@router.get(
    "/tunnel_check", response_model=Optional[TunnelInfo], tags=["Deanonymization"]
)
async def tunnel_check_endpoint(client_ip: str = Depends(get_client_ip)):
    """
    Проверяет IP на использование сетевого туннелирования
    (GRE, VXLAN, OpenVPN, L2TP и др.).

    - Анализирует сетевые пакеты для обнаружения типовых туннелей.
    - Работает асинхронно.
    - Возвращает TunnelInfo или None (если не найдено).

    Args:
        client_ip (str): IP-адрес пользователя.

    Returns:
        Optional[TunnelInfo]: Данные о найденном туннеле или None.
    """
    if not client_ip or not isinstance(client_ip, str):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Поле 'client_ip' должно быть непустой строкой",
        )

    try:
        tunnel_info = await check_ip_for_tunnel(target_ip=client_ip)
        return tunnel_info if tunnel_info else None
    except Exception:
        return None


@router.get("/double_ping", response_model=PingResponse, tags=["Deanonymization"])
async def double_ping_endpoint(client_ip: str = Depends(get_client_ip)):
    """
    Отправляет два ICMP-пинга и сравнивает ответы.

    - Сравнивает TTL и разницу времени отклика (RTT) по двум пакетам.
    - Выявляет возможные аномалии в маршруте до IP.
    - Используется для дополнительной проверки NAT/proxy/tunnel.

    Args:
        client_ip (str): IP-адрес или домен для пинга.

    Returns:
        PingResponse: Модель с результатом сравнения ICMP-ответов.
    """
    if not client_ip or not isinstance(client_ip, str):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Поле 'client_ip' должно быть непустой строкой",
        )

    try:
        ping_result = await get_double_ping(client_ip)
        return ping_result
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Ошибка при выполнении {str(e)}",
        )


@router.get(
    "/ip_location", response_model=Optional[LocationInfo], tags=["Deanonymization"]
)
async def ip_location_endpoint(client_ip: str = Depends(get_client_ip)):
    """
    Возвращает геолокационную информацию по IP-адресу.

    - Определяет город, страну, провайдера, координаты, индекс, таймзону.
    - Поддерживает неполные ответы (null, если ничего не найдено).

    Args:
        client_ip (str): IP пользователя.

    Returns:
        Optional[LocationInfo]: Pydantic-модель с геолокацией или None.
    """
    try:
        location_info = await get_location_by_ip(client_ip)
        return location_info if location_info else None
    except Exception:
        return None


@router.get("/os_detection", response_model=OSInfo, tags=["Deanonymization"])
async def os_detection_endpoint(request: Request):
    """
    Анализирует HTTP-заголовки для определения операционной системы клиента.

    - Парсит заголовки (User-Agent, sec-ch-ua-platform и др.).
    - Определяет наиболее вероятную ОС.
    - Возвращает результат как {"os": "..."}.

    Args:
        request (Request): Объект запроса FastAPI/Starlette.

    Returns:
        OSInfo: Pydantic-модель с наиболее вероятной ОС пользователя.
    """
    try:
        headers = dict(request.headers)
        detected_os = await get_os_results(headers)
        return detected_os
    except Exception as e:
        raise HTTPException(
            status_code=500, detail=f"Ошибка при анализе заголовков: {str(e)}"
        )
