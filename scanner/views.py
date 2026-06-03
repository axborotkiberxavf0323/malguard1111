"""Web interfeys ko'rinishlari (views)."""
import logging

from django.conf import settings
from django.db.models import Count, Q
from django.http import JsonResponse
from django.shortcuts import get_object_or_404, render
from django.utils.decorators import method_decorator
from django.views import View
from django.views.decorators.csrf import ensure_csrf_cookie

from .models import ScanResult
from .services.scanner_service import ScannerService

logger = logging.getLogger("scanner")

# Qo'llab-quvvatlanadigan kengaytmalar
ALLOWED_EXTENSIONS = {
    "exe", "dll", "msi", "bat", "cmd", "ps1", "vbs", "js", "jar", "py", "sh",
    "doc", "docx", "xls", "xlsx", "ppt", "pptx", "pdf", "rtf",
    "zip", "rar", "7z", "tar", "gz", "iso",
    "apk", "dmg", "pkg", "deb", "rpm",
    "txt", "html", "htm", "xml", "json", "csv",
    "jpg", "jpeg", "png", "gif", "svg", "bmp",
    "mp3", "mp4", "avi", "mkv",
}


def get_global_stats() -> dict:
    """Bosh sahifa va statistika uchun umumiy ko'rsatkichlar."""
    agg = ScanResult.objects.aggregate(
        total=Count("id"),
        dangerous=Count("id", filter=Q(verdict="dangerous")),
        suspicious=Count("id", filter=Q(verdict="suspicious")),
        safe=Count("id", filter=Q(verdict="safe")),
    )
    return {
        "total": agg["total"] or 0,
        "dangerous": agg["dangerous"] or 0,
        "suspicious": agg["suspicious"] or 0,
        "safe": agg["safe"] or 0,
    }


class HomeView(View):
    """Bosh sahifa — fayl yuklash + statistika + so'nggi tekshiruvlar."""

    @method_decorator(ensure_csrf_cookie)
    def get(self, request):
        recent_scans = ScanResult.objects.filter(status="completed")[:6]
        return render(
            request,
            "scanner/home.html",
            {
                "recent_scans": recent_scans,
                "stats": get_global_stats(),
                "allowed_extensions": sorted(ALLOWED_EXTENSIONS),
            },
        )


class ScanView(View):
    """Faylni qabul qilib, tekshiruvni boshlaydi (AJAX, JSON qaytaradi)."""

    def post(self, request):
        file = request.FILES.get("file")
        if not file:
            return JsonResponse({"success": False, "error": "Fayl yuborilmadi."}, status=400)

        # Hajm tekshiruvi
        max_size = settings.MAX_UPLOAD_SIZE_MB * 1024 * 1024
        if file.size > max_size:
            return JsonResponse(
                {
                    "success": False,
                    "error": f"Fayl juda katta. Maksimal hajm: {settings.MAX_UPLOAD_SIZE_MB} MB.",
                },
                status=400,
            )

        # Kengaytma tekshiruvi
        file_name = file.name
        ext = file_name.rsplit(".", 1)[-1].lower() if "." in file_name else ""
        if ext and ext not in ALLOWED_EXTENSIONS:
            return JsonResponse(
                {"success": False, "error": f"Bu fayl turi qo'llab-quvvatlanmaydi: .{ext}"},
                status=400,
            )

        try:
            file_bytes = file.read()
            service = ScannerService()
            scan = service.scan(
                file_bytes=file_bytes,
                file_name=file_name,
                source="web",
                file_type=file.content_type or "",
            )
            return JsonResponse(
                {
                    "success": True,
                    "scan_id": scan.id,
                    "verdict": scan.verdict,
                    "verdict_label": scan.verdict_label,
                    "verdict_emoji": scan.verdict_emoji,
                    "danger_score": scan.danger_score,
                    "status": scan.status,
                    "summary": scan.summary_uz,
                    "result_url": f"/result/{scan.id}/",
                }
            )
        except Exception as exc:  # noqa: BLE001
            logger.exception("Web skan xatolik: %s", exc)
            return JsonResponse(
                {"success": False, "error": "Server xatosi. Birozdan keyin urinib ko'ring."},
                status=500,
            )


class ScanResultView(View):
    """Bitta tekshiruv natijasi (batafsil sahifa yoki JSON)."""

    def get(self, request, scan_id):
        scan = get_object_or_404(ScanResult, id=scan_id)
        if request.headers.get("Accept") == "application/json" or request.GET.get("format") == "json":
            return JsonResponse(
                {
                    "id": scan.id,
                    "file_name": scan.file_name,
                    "file_size": scan.file_size,
                    "file_type": scan.file_type,
                    "md5": scan.file_md5,
                    "sha256": scan.file_sha256,
                    "verdict": scan.verdict,
                    "danger_score": scan.danger_score,
                    "status": scan.status,
                    "summary": scan.summary_uz,
                    "detections": scan.detections,
                    "created_at": scan.created_at.isoformat(),
                    "virustotal": scan.virustotal_result,
                    "hybrid_analysis": scan.hybrid_analysis_result,
                    "malwarebazaar": scan.malwarebazaar_result,
                }
            )
        return render(request, "scanner/result.html", {"scan": scan})


class HistoryView(View):
    """Oxirgi tekshiruvlar ro'yxati."""

    def get(self, request):
        scans = ScanResult.objects.filter(status="completed")[:100]
        return render(
            request,
            "scanner/history.html",
            {"scans": scans, "stats": get_global_stats()},
        )


class StatsAPIView(View):
    """Jonli statistika (JSON) — bosh sahifadagi raqamlarni yangilash uchun."""

    def get(self, request):
        return JsonResponse(get_global_stats())
