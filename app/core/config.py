from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """
    Класс с основными настройками приложения.

    Атрибуты:
        APP_NAME: Название приложения.
        VERSION: Версия приложения.
        TOR_EXIT_LIST_URL: URL для загрузки списка exit-нод Tor.
        CRTSH_API_URL: API-адрес для получения сертификатов по домену.
        CACHE_TTL_SECONDS: Время жизни кеша в секундах.

    model_config:
        Определяет параметры загрузки конфигурации из файла .env.
    """

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
    )

    APP_NAME: str = "FingerprintingService"
    VERSION: str = "0.1.0"
    TOR_EXIT_LIST_URL: str = "https://check.torproject.org/torbulkexitlist"
    CRTSH_API_URL: str = "https://crt.sh/?q=%25.{domain}&output=json"
    CACHE_TTL_SECONDS: int = 3600


settings = Settings()
