from pydantic import BaseModel


class PortScanResponse(BaseModel):
    """
    Модель результата сканирования портов.

    - open_ports: множество открытых портов в формате {"80:http", "443:https"}
    - scanned_ports_count: количество просканированных портов
    - ip: IP-адрес, по которому проводилось сканирование
    """

    open_ports: set[str] | None = None
    scanned_ports_count: int | None = None
    ip: str
