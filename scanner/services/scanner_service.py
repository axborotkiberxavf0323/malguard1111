"""Skaner orkestratori.

Vazifasi:
  1. Fayl hashlarini hisoblash.
  2. Hash bo'yicha keshni tekshirish (avval skanlangan bo'lsa — API chaqirilmaydi).
  3. 3 ta manbani PARALLEL chaqirish (ThreadPoolExecutor).
  4. Natijalarni birlashtirib yakuniy xulosa chiqarish.
  5. ScanResult yozuvini bazaga saqlash.
"""
import logging
import mimetypes
import os
from concurrent.futures import ThreadPoolExecutor

from django.conf import settings

from ..models import ScanResult
from .aggregator import aggregate
from .base import empty_result
from .hybrid_analysis import HybridAnalysisClient
from .malwarebazaar import MalwareBazaarClient
from .virustotal import VirusTotalClient

logger = logging.getLogger("scanner")


def guess_file_type(file_name: str, file_bytes: bytes) -> str:
    ext = os.path.splitext(file_name)[1].lower().lstrip(".")
    mime, _ = mimetypes.guess_type(file_name)
    if mime:
        return mime
    return ext.upper() if ext else "noma'lum"


class ScannerService:
    def __init__(self):
        timeout = settings.SCAN_HTTP_TIMEOUT
        self.vt = VirusTotalClient(settings.VIRUSTOTAL_API_KEY, timeout, settings.VT_POLL_TIMEOUT)
        self.mb = MalwareBazaarClient(settings.MALWAREBAZAAR_API_KEY, timeout)
        self.ha = HybridAnalysisClient(settings.HYBRID_ANALYSIS_API_KEY, timeout)

    # ------------------------------------------------------------------
    def scan(
        self,
        file_bytes: bytes,
        file_name: str = "file",
        source: str = "web",
        telegram_user_id=None,
        telegram_username: str = "",
        file_type: str = "",
        use_cache: bool = True,
    ) -> ScanResult:
        """Faylni tekshiradi va ScanResult yozuvini qaytaradi."""
        hashes = ScanResult.compute_hashes(file_bytes)
        file_type = file_type or guess_file_type(file_name, file_bytes)
        file_size = len(file_bytes)

        # 1) KESH: bir xil fayl avval skanlanganmi?
        if use_cache:
            cached = (
                ScanResult.objects.filter(file_sha256=hashes["sha256"], status="completed")
                .order_by("-created_at")
                .first()
            )
            if cached:
                logger.info("Kesh ishlatildi (SHA256=%s)", hashes["sha256"][:12])
                return self._clone_from_cache(
                    cached, file_name, file_size, file_type, source,
                    telegram_user_id, telegram_username, hashes,
                )

        # 2) Yangi yozuv
        scan = ScanResult.objects.create(
            file_name=file_name,
            file_size=file_size,
            file_type=file_type,
            file_md5=hashes["md5"],
            file_sha1=hashes["sha1"],
            file_sha256=hashes["sha256"],
            source=source,
            status="scanning",
            telegram_user_id=telegram_user_id,
            telegram_username=telegram_username or "",
        )

        try:
            results = self._run_parallel(file_bytes, hashes, file_name)

            scan.virustotal_result = results["virustotal"]
            scan.malwarebazaar_result = results["malwarebazaar"]
            scan.hybrid_analysis_result = results["hybrid_analysis"]

            agg = aggregate(
                results["virustotal"], results["malwarebazaar"], results["hybrid_analysis"]
            )
            scan.verdict = agg["verdict"]
            scan.danger_score = agg["danger_score"]
            scan.detections = agg["detections"]
            scan.summary_uz = agg["summary_uz"]
            scan.mark_completed()
            scan.save()
            logger.info("Skan yakunlandi: %s -> %s (%s)", file_name, scan.verdict, scan.danger_score)

        except Exception as exc:  # noqa: BLE001
            logger.exception("Skan xatolik: %s", exc)
            scan.status = "error"
            scan.error_message = str(exc)
            scan.summary_uz = "⚠️ Tekshirish vaqtida texnik xatolik yuz berdi. Birozdan keyin qayta urinib ko'ring."
            scan.save()

        return scan

    # ------------------------------------------------------------------
    def _run_parallel(self, file_bytes: bytes, hashes: dict, file_name: str) -> dict:
        """3 ta API'ni bir vaqtning o'zida (parallel) chaqiradi."""
        tasks = {
            "virustotal": lambda: self.vt.lookup(file_bytes, hashes, file_name),
            "malwarebazaar": lambda: self.mb.lookup(file_bytes, hashes, file_name),
            "hybrid_analysis": lambda: self.ha.lookup(file_bytes, hashes, file_name),
        }
        results = {}
        # VT yuklash + polling sekin bo'lishi mumkin — umumiy timeout kengroq
        overall_timeout = settings.VT_POLL_TIMEOUT + settings.SCAN_HTTP_TIMEOUT + 15

        with ThreadPoolExecutor(max_workers=3) as executor:
            futures = {key: executor.submit(fn) for key, fn in tasks.items()}
            for key, future in futures.items():
                try:
                    results[key] = future.result(timeout=overall_timeout)
                except Exception as exc:  # noqa: BLE001
                    logger.warning("%s xizmati xato berdi: %s", key, exc)
                    results[key] = empty_result(key, f"Xizmat javob bermadi: {exc}", available=True)
        return results

    # ------------------------------------------------------------------
    def _clone_from_cache(
        self, cached, file_name, file_size, file_type, source,
        telegram_user_id, telegram_username, hashes,
    ) -> ScanResult:
        """Keshdagi natijani yangi yozuvga ko'chiradi (API chaqirmasdan)."""
        return ScanResult.objects.create(
            file_name=file_name,
            file_size=file_size,
            file_type=file_type or cached.file_type,
            file_md5=hashes["md5"],
            file_sha1=hashes["sha1"],
            file_sha256=hashes["sha256"],
            source=source,
            status="completed",
            telegram_user_id=telegram_user_id,
            telegram_username=telegram_username or "",
            verdict=cached.verdict,
            danger_score=cached.danger_score,
            virustotal_result=cached.virustotal_result,
            malwarebazaar_result=cached.malwarebazaar_result,
            hybrid_analysis_result=cached.hybrid_analysis_result,
            detections=cached.detections,
            summary_uz=cached.summary_uz,
            completed_at=cached.completed_at,
        )
