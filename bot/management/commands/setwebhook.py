"""Telegram webhook manzilini o'rnatadi yoki o'chiradi.

Foydalanish:
    python manage.py setwebhook                # .env dagi TELEGRAM_WEBHOOK_URL
    python manage.py setwebhook --url https://domen.uz/bot/webhook/
    python manage.py setwebhook --delete       # webhook'ni o'chirish (polling uchun)
"""
import asyncio

from django.conf import settings
from django.core.management.base import BaseCommand
from telegram import Bot


class Command(BaseCommand):
    help = "Telegram webhook manzilini o'rnatadi yoki o'chiradi"

    def add_arguments(self, parser):
        parser.add_argument("--url", type=str, default="", help="Webhook URL")
        parser.add_argument("--delete", action="store_true", help="Webhook'ni o'chirish")

    def handle(self, *args, **options):
        if not settings.TELEGRAM_BOT_TOKEN:
            self.stderr.write(self.style.ERROR("TELEGRAM_BOT_TOKEN sozlanmagan!"))
            return

        bot = Bot(token=settings.TELEGRAM_BOT_TOKEN)

        if options["delete"]:
            asyncio.run(bot.delete_webhook(drop_pending_updates=True))
            self.stdout.write(self.style.SUCCESS("✅ Webhook o'chirildi (endi polling ishlatsa bo'ladi)."))
            return

        url = options["url"] or settings.TELEGRAM_WEBHOOK_URL
        if not url:
            self.stderr.write(self.style.ERROR("URL berilmadi. --url yoki .env TELEGRAM_WEBHOOK_URL kerak."))
            return

        kwargs = {"url": url, "drop_pending_updates": True}
        if settings.TELEGRAM_WEBHOOK_SECRET:
            kwargs["secret_token"] = settings.TELEGRAM_WEBHOOK_SECRET

        asyncio.run(bot.set_webhook(**kwargs))
        self.stdout.write(self.style.SUCCESS(f"✅ Webhook o'rnatildi: {url}"))
