"""VirusTotal API v3 integratsiyasi.

Strategiya (kvotani tejash uchun):
  1. Avval fayl SHA256 hash bo'yicha tekshiriladi (yuklamasdan).
  2. Topilmasa va `allow_upload=True` bo'lsa — fayl yuklanadi va natija kutiladi.
"""
import logging
import time

import requests

from .base import BaseClient, empty_result

logger = logging.getLogger("scanner")

API_BASE = "https://www.virustotal.com/api/v3"


class VirusTotalClient(BaseClient):
    service_name = "virustotal"

    def __init__(self, api_key: str, timeout: int = 30, poll_timeout: int = 90):
        super().__init__(api_key, timeout)
        self.poll_timeout = poll_timeout

    @property
    def headers(self) -> dict:
        return {"x-apikey": self.api_key, "Accept": "application/json"}

    def lookup(self, file_bytes: bytes, hashes: dict, file_name: str, allow_upload: bool = True) -> dict:
        if not self.is_configured:
            return empty_result(self.service_name, "API kaliti sozlanmagan")

        sha256 = hashes["sha256"]
        try:
            # 1) Hash bo'yicha qidirish
            resp = self.session.get(
                f"{API_BASE}/files/{sha256}", headers=self.headers, timeout=self.timeout
            )
            if resp.status_code == 200:
                return self._parse_file_report(resp.json(), scanned_now=False)

            if resp.status_code == 404:
                # 2) Hisobotda yo'q — yuklab tekshiramiz
                if not allow_upload:
                    return empty_result(self.service_name, "Bazada topilmadi", available=True)
                return self._upload_and_wait(file_bytes, file_name)

            if resp.status_code in (401, 403):
                return empty_result(self.service_name, "API kaliti noto'g'ri yoki ruxsat yo'q", available=False)

            if resp.status_code == 429:
                return empty_result(self.service_name, "VirusTotal kvota limiti tugagan", available=True)

            return empty_result(self.service_name, f"Kutilmagan javob: HTTP {resp.status_code}", available=True)

        except requests.RequestException as exc:
            logger.warning("VirusTotal xatolik: %s", exc)
            return empty_result(self.service_name, f"Tarmoq xatosi: {exc}", available=True)

    # ----------------------------------------------------------------
    def _upload_and_wait(self, file_bytes: bytes, file_name: str) -> dict:
        try:
            up = self.session.post(
                f"{API_BASE}/files",
                headers=self.headers,
                files={"file": (file_name, file_bytes)},
                timeout=self.timeout,
            )
            if up.status_code not in (200, 201):
                return empty_result(self.service_name, f"Yuklashda xato: HTTP {up.status_code}", available=True)

            analysis_id = up.json().get("data", {}).get("id")
            if not analysis_id:
                return empty_result(self.service_name, "Tahlil ID olinmadi", available=True)

            # Natijani kutish (polling)
            deadline = time.time() + self.poll_timeout
            while time.time() < deadline:
                an = self.session.get(
                    f"{API_BASE}/analyses/{analysis_id}", headers=self.headers, timeout=self.timeout
                )
                if an.status_code == 200:
                    data = an.json().get("data", {})
                    attrs = data.get("attributes", {})
                    if attrs.get("status") == "completed":
                        stats = attrs.get("stats", {})
                        results = attrs.get("results", {})
                        return self._build(stats, results, scanned_now=True)
                time.sleep(8)

            return empty_result(
                self.service_name,
                "Tahlil hali yakunlanmadi (vaqt tugadi). Birozdan keyin qayta urinib ko'ring.",
                available=True,
            )
        except requests.RequestException as exc:
            logger.warning("VirusTotal upload xatolik: %s", exc)
            return empty_result(self.service_name, f"Tarmoq xatosi: {exc}", available=True)

    def _parse_file_report(self, payload: dict, scanned_now: bool) -> dict:
        attrs = payload.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        results = attrs.get("last_analysis_results", {})
        out = self._build(stats, results, scanned_now=scanned_now)
        out["type_description"] = attrs.get("type_description", "")
        out["meaningful_name"] = attrs.get("meaningful_name", "")
        out["reputation"] = attrs.get("reputation", 0)
        return out

    def _build(self, stats: dict, results: dict, scanned_now: bool) -> dict:
        malicious = int(stats.get("malicious", 0))
        suspicious = int(stats.get("suspicious", 0))
        harmless = int(stats.get("harmless", 0))
        undetected = int(stats.get("undetected", 0))
        total = malicious + suspicious + harmless + undetected + int(stats.get("timeout", 0))

        detections = []
        for engine, res in (results or {}).items():
            if res.get("category") in ("malicious", "suspicious") and res.get("result"):
                detections.append({"engine": engine, "result": res.get("result")})

        return {
            "service": self.service_name,
            "available": True,
            "found": total > 0,
            "malicious_count": malicious,
            "suspicious_count": suspicious,
            "harmless_count": harmless,
            "undetected_count": undetected,
            "total_engines": total,
            "detections": detections[:25],
            "scanned_now": scanned_now,
            "error": None,
        }
