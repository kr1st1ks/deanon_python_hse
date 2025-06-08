import time
from typing import Any


class Cache:
    """
    Простейший in-memory TTL-кэш.
    Хранит пары (значение, время создания, TTL).
    """

    def __init__(self):
        self._store: dict[str, tuple[Any, float, float]] = {}

    def set(self, key: str, value: Any, ttl: float):
        self._store[key] = (value, time.time(), ttl)

    def get(self, key: str):
        entry = self._store.get(key)
        if not entry:
            return None
        value, created, ttl = entry
        if time.time() - created > ttl:
            del self._store[key]
            return None
        return value
