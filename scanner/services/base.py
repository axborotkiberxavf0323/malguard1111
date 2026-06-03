"""Tashqi API mijozlari uchun umumiy bazaviy klass."""
import logging

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

logger = logging.getLogger("scanner")


def build_session(retries: int = 2, backoff: float = 0.5) -> requests.Session:
    """Qayta urinish (retry) sozlangan requests sessiyasini yaratadi."""
    session = requests.Session()
    retry = Retry(
        total=retries,
        backoff_factor=backoff,
        status_forcelist=(429, 500, 502, 503, 504),
        allowed_methods=frozenset(["GET", "POST"]),
        raise_on_status=False,
    )
    adapter = HTTPAdapter(max_retries=retry)
    session.mount("https://", adapter)
    session.mount("http://", adapter)
    return session


def empty_result(service: str, reason: str = "", available: bool = False) -> dict:
    """Manba so'rab bo'lmaganda (kalit yo'q yoki xato) standart natija."""
    return {
        "service": service,
        "available": available,
        "found": False,
        "verdict": "unknown",
        "error": reason or None,
    }


class BaseClient:
    """Barcha API mijozlari uchun umumiy logika."""

    service_name = "base"

    def __init__(self, api_key: str, timeout: int = 30):
        self.api_key = (api_key or "").strip()
        self.timeout = timeout
        self.session = build_session()

    @property
    def is_configured(self) -> bool:
        return bool(self.api_key)

    def lookup(self, file_bytes: bytes, hashes: dict, file_name: str) -> dict:
        """Asosiy metod — har bir mijoz o'zicha amalga oshiradi."""
        raise NotImplementedError
