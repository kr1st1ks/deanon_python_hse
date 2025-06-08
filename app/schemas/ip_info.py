from pydantic import BaseModel


class NetInfo(BaseModel):
    """
    Модель сведений о подсети из WHOIS.

    - cidr: CIDR-подсеть
    - name: имя подсети
    - description: описание подсети
    - country: страна подсети
    - city: город подсети
    - address: адрес подсети
    - postal_code: почтовый индекс
    - state: регион/штат подсети
    - abuse_emails: email для жалоб
    - tech_emails: email для тех. поддержки
    - created: дата создания записи
    - updated: дата обновления записи
    """

    cidr: str | None = None
    name: str | None = None
    description: str | None = None
    country: str | None = None
    city: str | None = None
    address: str | None = None
    postal_code: str | None = None
    state: str | None = None
    abuse_emails: list[str] | None = None
    tech_emails: list[str] | None = None
    created: str | None = None
    updated: str | None = None


class WhoisInfo(BaseModel):
    """
    Модель сведений WHOIS по IP.

    - ip: IP-адрес
    - asn: автономная система (ASN)
    - asn_cidr: CIDR ASN
    - asn_country_code: страна ASN
    - asn_date: дата регистрации ASN
    - asn_registry: реестр ASN
    - nets: список подсетей (NetInfo)
    """

    ip: str
    asn: str | None = None
    asn_cidr: str | None = None
    asn_country_code: str | None = None
    asn_date: str | None = None
    asn_registry: str | None = None
    nets: list[NetInfo]


class LocationInfo(BaseModel):
    """
    Модель сведений о геолокации IP.

    - ip: IP-адрес
    - city: город
    - region: регион/область
    - country: страна
    - provider: интернет-провайдер
    - latitude: широта
    - longitude: долгота
    - postal_index: почтовый индекс
    - timezone: часовой пояс
    """

    ip: str | None = None
    city: str | None = None
    region: str | None = None
    country: str | None = None
    provider: str | None = None
    latitude: float | None = None
    longitude: float | None = None
    postal_index: str | None = None
    timezone: str | None = None
