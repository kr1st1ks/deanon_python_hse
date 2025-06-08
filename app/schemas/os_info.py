from pydantic import BaseModel


class OSInfo(BaseModel):
    """
    Модель сведений об операционной системе клиента.

    - os: строка с наиболее вероятной ОС (например, 'Windows', 'Linux', 'Android')
    """

    os: str
