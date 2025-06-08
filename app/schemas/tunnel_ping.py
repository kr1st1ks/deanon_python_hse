from typing import Optional

from pydantic import BaseModel


class TunnelInfo(BaseModel):
    """
    Модель сведений о туннелировании.

    - tunnel_type: тип туннеля (например, VPN, GRE, и т.д.)
    - src_ip: внешний IP-адрес источника
    - dst_ip: внешний IP-адрес назначения
    - inner_src: внутренний (туннелируемый) IP-источник, если есть
    - inner_dst: внутренний (туннелируемый) IP-назначение, если есть
    """

    tunnel_type: str
    src_ip: str
    dst_ip: str
    inner_src: str | None = None
    inner_dst: str | None = None


class PingInfo(BaseModel):
    """
    Модель результата одного пинга.

    - seq: номер последовательности пакета
    - src_ip: IP-адрес источника
    - dst_ip: IP-адрес назначения
    - rtt: round-trip time (время в пути, мс)
    - ttl: time-to-live пакета
    """

    seq: int
    src_ip: str
    dst_ip: str
    rtt: float
    ttl: int


class PingResponse(BaseModel):
    """
    Модель ответа на серию пингов.

    - result: результат проверки (успешно/неуспешно)
    - info: дополнительная информация (например, текст ошибки или детали)
    """

    result: bool
    info: Optional[str] = None
