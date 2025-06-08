from pydantic import BaseModel

from app.schemas.anonymization import AnonymizationInfo
from app.schemas.dns_info import FullResolve
from app.schemas.ip_info import LocationInfo, WhoisInfo
from app.schemas.os_info import OSInfo
from app.schemas.port_scan_info import PortScanResponse
from app.schemas.security import SecurityInfoResponse
from app.schemas.tunnel_ping import PingResponse, TunnelInfo


class AnalysisResult(BaseModel):
    """
    Итоговая модель анализа IP/клиента.

    Содержит сведения, собранные по результатам различных проверок и анализов,
    агрегируя данные из других pydantic-моделей:
    - anonymization_info: информация об использовании анонимайзеров (VPN, Tor и т.п.)
    - whois_info: данные о владельце IP из базы Whois
    - security_info: информация о наличии IP в черных списках и безопасности
    - port_scan_info: результаты сканирования открытых портов
    - tunnel_check_info: сведения о наличии туннелирования трафика
    - double_ping_info: результаты двойного пинга (сравнение доступности)
    - ip_location: геолокация IP-адреса
    - os_info: информация об используемой ОС
    - full_resolve: полная информация по DNS-резолву
    """

    anonymization_info: AnonymizationInfo | None = None
    whois_info: WhoisInfo | None = None
    security_info: SecurityInfoResponse | None = None
    port_scan_info: PortScanResponse | None = None
    tunnel_check_info: TunnelInfo | None = None
    double_ping_info: PingResponse | None = None
    ip_location: LocationInfo | None = None
    os_info: OSInfo | None = None
    full_resolve: FullResolve | None = None
