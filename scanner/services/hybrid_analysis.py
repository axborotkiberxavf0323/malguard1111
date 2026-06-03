"""Hybrid Analysis (CrowdStrike Falcon Sandbox) integratsiyasi.

Fayl SHA256 hash bo'yicha mavjud sandbox hisobotlari qidiriladi.
"""
import logging

import requests

from .base import BaseClient, empty_result

logger = logging.getLogger("scanner")

API_BASE = "https://www.hybrid-analysis.com/api/v2"


class HybridAnalysisClient(BaseClient):
    service_name = "hybrid_analysis"

    @property
    def headers(self) -> dict:
        return {
            "api-key": self.api_key,
            "User-Agent": "Falcon Sandbox",
            "Accept": "application/json",
        }

    def lookup(self, file_bytes: bytes, hashes: dict, file_name: str) -> dict:
        if not self.is_configured:
            return empty_result(self.service_name, "API kaliti sozlanmagan")

        try:
            resp = self.session.post(
                f"{API_BASE}/search/hash",
                headers=self.headers,
                data={"hash": hashes["sha256"]},
                timeout=self.timeout,
            )
            if resp.status_code in (401, 403):
                return empty_result(self.service_name, "API kaliti noto'g'ri yoki ruxsat yo'q", available=False)
            if resp.status_code != 200:
                return empty_result(self.service_name, f"HTTP {resp.status_code}", available=True)

            reports = resp.json()
            if not isinstance(reports, list) or not reports:
                return {
                    "service": self.service_name,
                    "available": True,
                    "found": False,
                    "verdict": "unknown",
                    "error": None,
                }

            # Eng "yomon" hisobotni tanlaymiz
            best = self._pick_worst(reports)
            verdict_raw = (best.get("verdict") or "").lower()
            verdict = {
                "malicious": "dangerous",
                "suspicious": "suspicious",
                "no specific threat": "safe",
                "whitelisted": "safe",
            }.get(verdict_raw, "unknown")

            return {
                "service": self.service_name,
                "available": True,
                "found": True,
                "verdict": verdict,
                "verdict_raw": verdict_raw or "unknown",
                "threat_score": best.get("threat_score") or 0,
                "av_detect": best.get("av_detect") or 0,
                "threat_family": best.get("vx_family") or "",
                "environment": best.get("environment_description", ""),
                "type": best.get("type_short") or best.get("type") or "",
                "error": None,
            }

        except requests.RequestException as exc:
            logger.warning("Hybrid Analysis xatolik: %s", exc)
            return empty_result(self.service_name, f"Tarmoq xatosi: {exc}", available=True)
        except ValueError:
            return empty_result(self.service_name, "JSON tahlil qilinmadi", available=True)

    @staticmethod
    def _pick_worst(reports: list) -> dict:
        priority = {"malicious": 3, "suspicious": 2, "no specific threat": 1, "whitelisted": 0}

        def score(r):
            return (
                priority.get((r.get("verdict") or "").lower(), 0),
                r.get("threat_score") or 0,
            )

        return max(reports, key=score)
