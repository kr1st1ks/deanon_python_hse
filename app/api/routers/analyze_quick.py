from fastapi import APIRouter, Depends, HTTPException, Query, Request

from app.dependencies import get_client_ip
from app.exceptions import DataUnavailableError
from app.schemas.analysis import AnalysisResult
from app.services.anonymization_service import get_anonymization_info
from app.services.dns_service import full_dns_resolve
from app.services.ip_service import get_location_by_ip, get_whois_info
from app.services.os_service import get_os_results
from app.services.port_scan_service import port_scan_info
from app.services.security_service import get_security_info
from app.services.tunnel_service import check_ip_for_tunnel, get_double_ping

router = APIRouter(prefix="/analyze", tags=["QuickAnalyze"])


@router.get("/quick", response_model=AnalysisResult)
async def quick_analysis(
    request: Request,
    client_ip: str = Depends(get_client_ip),
    max_ports: int = Query(10000, description="Количество сканируемых портов"),
):
    """
    Выполняет быстрый анализ по IP без DNS-leak.

    Args:
        request (Request): Заголовки запроса пользователя.
        client_ip (str): IP пользователя.
        max_ports (int): Число портов для сканирования.

    Returns:
        QuickAnalysisResult: Все результаты анализа (анонимизация, порты, geo и т.д.).
    """
    try:
        anonymization = await get_anonymization_info(client_ip)
        try:
            ip_info = await get_whois_info(client_ip)
        except DataUnavailableError:
            ip_info = None
        security_info = await get_security_info(client_ip)
        port_scan = await port_scan_info(client_ip=client_ip, max_ports=max_ports)
        try:
            tunnel_check = await check_ip_for_tunnel(target_ip=client_ip)
        except Exception:
            tunnel_check = None
        double_ping = await get_double_ping(client_ip)
        ip_location = await get_location_by_ip(client_ip)
        os_detection = await get_os_results(dict(request.headers))
        full_dns_resolve_info = await full_dns_resolve(client_ip)

        return AnalysisResult(
            anonymization_info=anonymization,
            whois_info=ip_info,
            security_info=security_info,
            port_scan_info=port_scan,
            tunnel_check_info=tunnel_check,
            double_ping_info=double_ping,
            ip_location=ip_location,
            os_info=os_detection,
            full_resolve=full_dns_resolve_info,
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Ошибка анализа: {e}")
