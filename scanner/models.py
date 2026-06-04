"""Skaner ma'lumotlar modellari."""
import hashlib

from django.conf import settings
from django.db import models
from django.utils import timezone


class ScanResult(models.Model):
    """Har bir fayl tekshiruvi natijasi."""

    STATUS_CHOICES = [
        ("pending", "Kutilmoqda"),
        ("scanning", "Tekshirilmoqda"),
        ("completed", "Yakunlandi"),
        ("error", "Xatolik"),
    ]

    VERDICT_CHOICES = [
        ("safe", "Xavfsiz"),
        ("suspicious", "Shubhali"),
        ("dangerous", "Xavfli"),
        ("unknown", "Noma'lum"),
    ]

    SOURCE_CHOICES = [
        ("web", "Web sayt"),
        ("telegram", "Telegram bot"),
        ("api", "API"),
    ]

    # --- Egasi (ro'yxatdan o'tgan foydalanuvchi; web orqali) ---
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="scans",
        verbose_name="Foydalanuvchi",
    )

    # --- Fayl ma'lumotlari ---
    file_name = models.CharField(max_length=255, verbose_name="Fayl nomi")
    file_size = models.BigIntegerField(default=0, verbose_name="Fayl hajmi (bayt)")
    file_type = models.CharField(max_length=120, blank=True, verbose_name="Fayl turi")
    file_md5 = models.CharField(max_length=32, db_index=True, verbose_name="MD5")
    file_sha1 = models.CharField(max_length=40, blank=True, verbose_name="SHA1")
    file_sha256 = models.CharField(max_length=64, db_index=True, verbose_name="SHA256")

    # --- Tekshiruv holati ---
    status = models.CharField(
        max_length=20, choices=STATUS_CHOICES, default="pending", verbose_name="Holat"
    )
    verdict = models.CharField(
        max_length=20, choices=VERDICT_CHOICES, default="unknown", verbose_name="Xulosa"
    )
    danger_score = models.PositiveSmallIntegerField(default=0, verbose_name="Xavf darajasi (0-100)")
    source = models.CharField(
        max_length=20, choices=SOURCE_CHOICES, default="web", verbose_name="Manba"
    )

    # --- Telegram ma'lumotlari ---
    telegram_user_id = models.BigIntegerField(null=True, blank=True)
    telegram_username = models.CharField(max_length=100, blank=True)

    # --- Vaqt ---
    created_at = models.DateTimeField(auto_now_add=True, verbose_name="Yaratildi")
    completed_at = models.DateTimeField(null=True, blank=True, verbose_name="Yakunlandi")

    # --- Manbalar natijalari (normallashtirilgan JSON) ---
    virustotal_result = models.JSONField(null=True, blank=True)
    hybrid_analysis_result = models.JSONField(null=True, blank=True)
    malwarebazaar_result = models.JSONField(null=True, blank=True)

    # --- Yakuniy xulosa ---
    summary_uz = models.TextField(blank=True, verbose_name="O'zbekcha xulosa")
    detections = models.JSONField(default=list, blank=True, verbose_name="Aniqlangan tahdidlar")
    error_message = models.TextField(blank=True)

    class Meta:
        ordering = ["-created_at"]
        verbose_name = "Skan natijasi"
        verbose_name_plural = "Skan natijalari"
        indexes = [
            models.Index(fields=["file_sha256", "status"]),
            models.Index(fields=["verdict"]),
            models.Index(fields=["user", "status"]),
        ]

    def __str__(self):
        return f"{self.file_name} — {self.get_verdict_display()}"

    # ----- Yordamchi xossalar (templatelar uchun) -----
    @property
    def verdict_emoji(self) -> str:
        return {
            "dangerous": "🔴",
            "suspicious": "🟡",
            "safe": "🟢",
            "unknown": "⚪",
        }.get(self.verdict, "⚪")

    @property
    def verdict_label(self) -> str:
        return self.get_verdict_display()

    @property
    def file_size_human(self) -> str:
        size = float(self.file_size or 0)
        for unit in ["B", "KB", "MB", "GB"]:
            if size < 1024 or unit == "GB":
                return f"{size:.1f} {unit}" if unit != "B" else f"{int(size)} {unit}"
            size /= 1024
        return f"{size:.1f} GB"

    @property
    def vt_stats(self) -> dict:
        """VirusTotal qisqacha statistikasi (template uchun xavfsiz)."""
        vt = self.virustotal_result or {}
        return {
            "found": vt.get("found", False),
            "malicious": vt.get("malicious_count", 0),
            "suspicious": vt.get("suspicious_count", 0),
            "harmless": vt.get("harmless_count", 0),
            "total": vt.get("total_engines", 0),
        }

    @staticmethod
    def compute_hashes(file_bytes: bytes) -> dict:
        return {
            "md5": hashlib.md5(file_bytes).hexdigest(),
            "sha1": hashlib.sha1(file_bytes).hexdigest(),
            "sha256": hashlib.sha256(file_bytes).hexdigest(),
        }

    def mark_completed(self):
        self.status = "completed"
        self.completed_at = timezone.now()


class ScanStatistics(models.Model):
    """Kunlik statistika (ixtiyoriy yig'ma jadval)."""

    date = models.DateField(unique=True, verbose_name="Sana")
    total_scans = models.IntegerField(default=0)
    dangerous_count = models.IntegerField(default=0)
    suspicious_count = models.IntegerField(default=0)
    safe_count = models.IntegerField(default=0)
    web_scans = models.IntegerField(default=0)
    telegram_scans = models.IntegerField(default=0)

    class Meta:
        ordering = ["-date"]
        verbose_name = "Kunlik statistika"
        verbose_name_plural = "Kunlik statistikalar"

    def __str__(self):
        return f"Statistika: {self.date}"
