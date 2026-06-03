"""Telegram botni polling rejimida ishga tushiradi.

Foydalanish:
    python manage.py runbot
"""
from django.core.management.base import BaseCommand


class Command(BaseCommand):
    help = "Telegram botni polling rejimida ishga tushiradi"

    def handle(self, *args, **options):
        from bot.bot import run_polling

        self.stdout.write(self.style.SUCCESS("🤖 Bot ishga tushmoqda... (to'xtatish: Ctrl+C)"))
        try:
            run_polling()
        except KeyboardInterrupt:
            self.stdout.write(self.style.WARNING("\nBot to'xtatildi."))
