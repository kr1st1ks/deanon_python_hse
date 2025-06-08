from fastapi import Query


def get_client_ip(client_ip: str = Query(..., description="IP адрес клиента")):
    """
    Зависимость FastAPI для извлечения IP-адреса клиента из запроса.

    Аргументы:
        client_ip: IP адрес клиента (ожидается как query-параметр).

    Возвращает:
        client_ip: строка с IP адресом клиента.
    """
    return client_ip
