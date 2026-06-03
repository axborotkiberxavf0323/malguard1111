"""Telegram webhook (production uchun).

Eslatma: Lokal ishlab chiqishda polling osonroq — `python manage.py runbot`.
Webhook faqat HTTPS public domen bo'lganda kerak bo'ladi.
"""
import asyncio
import json
import logging
import threading

from django.conf import settings
from django.http import HttpResponseForbidden, JsonResponse
from django.utils.decorators import method_decorator
from django.views import View
from django.views.decorators.csrf import csrf_exempt
from telegram import Update

logger = logging.getLogger("bot")

# Doimiy event loop va bitta marta initsializatsiya qilinadigan ilova
_loop = None
_app = None
_lock = threading.Lock()


def _get_loop():
    global _loop
    if _loop is None:
        _loop = asyncio.new_event_loop()
    return _loop


async def _ensure_app():
    global _app
    if _app is None:
        from .bot import build_application

        _app = build_application()
        await _app.initialize()
        logger.info("Webhook: bot ilovasi initsializatsiya qilindi.")
    return _app


@method_decorator(csrf_exempt, name="dispatch")
class WebhookView(View):
    def post(self, request):
        # Maxfiy token tekshiruvi (agar o'rnatilgan bo'lsa)
        secret = settings.TELEGRAM_WEBHOOK_SECRET
        if secret:
            header = request.headers.get("X-Telegram-Bot-Api-Secret-Token", "")
            if header != secret:
                return HttpResponseForbidden("Noto'g'ri maxfiy token")

        if not settings.TELEGRAM_BOT_TOKEN:
            return JsonResponse({"error": "Bot tokeni sozlanmagan"}, status=500)

        try:
            data = json.loads(request.body.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            return JsonResponse({"error": "Noto'g'ri JSON"}, status=400)

        async def _process():
            app = await _ensure_app()
            update = Update.de_json(data, app.bot)
            await app.process_update(update)

        try:
            with _lock:
                _get_loop().run_until_complete(_process())
        except Exception as exc:  # noqa: BLE001
            logger.exception("Webhook xatolik: %s", exc)
            return JsonResponse({"error": "ichki xatolik"}, status=500)

        return JsonResponse({"ok": True})

    def get(self, request):
        return JsonResponse({"status": "Webhook ishlayapti ✅"})
