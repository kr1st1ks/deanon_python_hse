from typing import Union

from pydantic import BaseModel


class DNSBLEntry(BaseModel):
    """
    Описание одной записи из DNSBL, где IP оказался занесён в чёрный список.

    - dnsbl: имя DNSBL-сервера, в котором найден IP
    - reason: причина занесения в список (если есть), иначе None
    """

    dnsbl: str
    reason: str | None = None


class SecurityInfoResponse(BaseModel):
    """
    Схема ответа get_security_info.

    - blacklisted: False, если IP нигде не числится;
    либо список объектов DNSBLEntry для всех найденных чёрных списков
    """

    blacklisted: Union[list[DNSBLEntry], bool]
