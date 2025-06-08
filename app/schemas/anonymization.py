from pydantic import BaseModel


class VPNAndProxyInfo(BaseModel):
    """
    Модель сведений о VPN и прокси.

    - detected: найден ли VPN или прокси
    - service: название сервиса (если определено)
    """

    detected: bool
    service: str | None = None


class TorInfo(BaseModel):
    """
    Модель сведений о Tor exit-node.

    - is_tor: обнаружен ли Tor exit-node
    - exit_node_ip: IP exit-узла Tor (если найден)
    - exit_location: геолокация exit-узла Tor (если найдена)
    """

    is_tor: bool
    exit_node_ip: str | None = None
    exit_location: str | None = None


class AnonymizationInfo(BaseModel):
    """
    Сводная модель об анонимайзерах (VPN, прокси, Tor).

    - vpn_detected: нашёлся ли VPN
    - vpn_provider: VPN-провайдер
    - proxy_detected: нашёлся ли прокси
    - proxy_type: тип прокси
    - proxy_provider: провайдер прокси
    - tor_detected: нашёлся ли Tor exit-node
    - tor_exit_location: геолокация Tor exit-node
    """

    vpn_detected: bool
    vpn_provider: str | None = None
    proxy_detected: bool
    proxy_type: str | None = None
    proxy_provider: str | None = None
    tor_detected: bool
    tor_exit_location: str | None = None
