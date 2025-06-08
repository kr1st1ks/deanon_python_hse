from pydantic import BaseModel


class DnsLeakTest(BaseModel):
    """
    Модель для теста на DNS-leak.

    - test_id: идентификатор теста
    - domains: список сгенерированных доменов для проверки утечки
    """

    test_id: str
    domains: list[str]


class DnsLeakResult(BaseModel):
    """
    Результаты проверки на DNS-leak.

    - test_id: идентификатор теста
    - expected: ожидаемые домены (которые должен был резолвить клиент)
    - seen: домены, реально резолвленные клиентом
    - missing: домены, которые не были резолвлены
    - leak_detected: флаг, указывающий на наличие утечки DNS
    """

    test_id: str
    expected: list[str]
    seen: list[str]
    missing: list[str]
    leak_detected: bool


class FullResolve(BaseModel):
    """
    Модель для полной информации о DNS-resolve.

    - subdomains: список поддоменов для резолва
    - full_records: словарь с результатами резолва по каждому поддомену
    """

    subdomains: list[str]
    full_records: dict[str, list[str]]
