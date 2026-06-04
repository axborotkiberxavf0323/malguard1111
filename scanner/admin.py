"""Admin panel sozlamalari."""
from django.contrib import admin
from django.utils.html import format_html

from .models import ScanResult, ScanStatistics


@admin.register(ScanResult)
class ScanResultAdmin(admin.ModelAdmin):
    list_display = (
        "file_name",
        "colored_verdict",
        "danger_score",
        "user",
        "source",
        "status",
        "created_at",
    )
    list_filter = ("verdict", "status", "source", "created_at")
    search_fields = ("file_name", "file_md5", "file_sha256", "telegram_username", "user__email")
    raw_id_fields = ("user",)
    readonly_fields = (
        "file_md5",
        "file_sha1",
        "file_sha256",
        "created_at",
        "completed_at",
        "virustotal_result",
        "hybrid_analysis_result",
        "malwarebazaar_result",
    )
    date_hierarchy = "created_at"
    list_per_page = 50

    @admin.display(description="Xulosa")
    def colored_verdict(self, obj):
        colors = {
            "dangerous": "#ff3b5c",
            "suspicious": "#f5c400",
            "safe": "#00b87a",
            "unknown": "#888",
        }
        return format_html(
            '<b style="color:{}">{} {}</b>',
            colors.get(obj.verdict, "#888"),
            obj.verdict_emoji,
            obj.get_verdict_display(),
        )


@admin.register(ScanStatistics)
class ScanStatisticsAdmin(admin.ModelAdmin):
    list_display = (
        "date",
        "total_scans",
        "dangerous_count",
        "suspicious_count",
        "safe_count",
        "web_scans",
        "telegram_scans",
    )
    list_filter = ("date",)
