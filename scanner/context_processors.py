"""Templatelar uchun umumiy kontekst (har bir sahifada mavjud)."""
from django.conf import settings


def site_context(request):
    return {
        "TELEGRAM_BOT_USERNAME": settings.TELEGRAM_BOT_USERNAME,
        "MAX_UPLOAD_SIZE_MB": settings.MAX_UPLOAD_SIZE_MB,
        "SITE_URL": settings.SITE_URL,
    }
