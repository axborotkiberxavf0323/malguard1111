"""
Telegram bot — python-telegram-bot v20+ (async).

Django ORM va skaner xizmati sinxron bo'lgani uchun ular `asyncio.to_thread`
ichida ishlatiladi — shunda bot bitta fayl tekshirilayotganda ham
boshqa foydalanuvchilarga javob bera oladi (event loop bloklanmaydi).
"""
import asyncio
import html
import logging

from telegram import InlineKeyboardButton, InlineKeyboardMarkup, Update
from telegram.constants import ParseMode
from telegram.ext import (
    Application,
    CallbackQueryHandler,
    CommandHandler,
    ContextTypes,
    MessageHandler,
    filters,
)

from django.conf import settings

logger = logging.getLogger("bot")

MAX_FILE_SIZE_MB = getattr(settings, "MAX_UPLOAD_SIZE_MB", 32)


# =========================================================
# YORDAMCHI FUNKSIYALAR
# =========================================================
def _progress_bar(score: int) -> str:
    filled = max(0, min(10, score // 10))
    return "█" * filled + "░" * (10 - filled)


def _result_url(scan_id: int) -> str:
    return f"{settings.SITE_URL}/result/{scan_id}/"


def _run_scan(file_bytes, file_name, user):
    """Sinxron skan (alohida thread'da chaqiriladi)."""
    from scanner.services.scanner_service import ScannerService

    service = ScannerService()
    return service.scan(
        file_bytes=file_bytes,
        file_name=file_name,
        source="telegram",
        telegram_user_id=user.id,
        telegram_username=user.username or "",
    )


def _fetch_stats():
    """Statistika (alohida thread'da chaqiriladi)."""
    from scanner.models import ScanResult

    return {
        "total": ScanResult.objects.count(),
        "dangerous": ScanResult.objects.filter(verdict="dangerous").count(),
        "suspicious": ScanResult.objects.filter(verdict="suspicious").count(),
        "safe": ScanResult.objects.filter(verdict="safe").count(),
    }


# =========================================================
# BUYRUQLAR
# =========================================================
async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    text = (
        "🛡️ <b>MalGuard — Fayl Skaner Bot</b>\n\n"
        "Menga istalgan faylni yuboring — men uni zararli dasturlarga tekshiraman.\n\n"
        "🔍 <b>VirusTotal</b> — 70+ antivirus\n"
        "🧬 <b>Hybrid Analysis</b> — sandbox tahlili\n"
        "🗃️ <b>MalwareBazaar</b> — zararli dasturlar bazasi\n\n"
        "🟢 Xavfsiz / 🟡 Shubhali / 🔴 Xavfli — aniq o'zbekcha xulosa olasiz.\n\n"
        f"📏 Maksimal fayl hajmi: <b>{MAX_FILE_SIZE_MB} MB</b>"
    )
    keyboard = [
        [
            InlineKeyboardButton("❓ Yordam", callback_data="help"),
            InlineKeyboardButton("📊 Statistika", callback_data="stats"),
        ],
        [InlineKeyboardButton("🌐 Veb-sayt", url=settings.SITE_URL)],
    ]
    await update.message.reply_text(
        text, parse_mode=ParseMode.HTML, reply_markup=InlineKeyboardMarkup(keyboard)
    )


async def help_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    text = (
        "📚 <b>Qanday foydalanish kerak?</b>\n\n"
        "1️⃣ Tekshirmoqchi bo'lgan faylni shu chatga yuboring.\n"
        "2️⃣ Bir necha soniya kuting.\n"
        "3️⃣ Natijani o'zbek tilida oling.\n\n"
        "<b>Qo'llab-quvvatlanadi:</b>\n"
        "EXE, DLL, MSI, APK, PDF, DOC(X), XLS(X), ZIP, RAR, JS, PS1, va boshqalar.\n\n"
        f"📏 Maksimal hajm: <b>{MAX_FILE_SIZE_MB} MB</b>\n\n"
        "⚠️ <b>Eslatma:</b> Bu vosita yordamchi xarakterga ega. Hech qachon "
        "noma'lum manbadan kelgan faylni ochmang."
    )
    msg = update.effective_message
    await msg.reply_text(text, parse_mode=ParseMode.HTML)


async def stats_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    stats = await asyncio.to_thread(_fetch_stats)
    text = (
        "📊 <b>Umumiy statistika</b>\n\n"
        f"📁 Jami tekshiruvlar: <b>{stats['total']}</b>\n"
        f"🔴 Xavfli: <b>{stats['dangerous']}</b>\n"
        f"🟡 Shubhali: <b>{stats['suspicious']}</b>\n"
        f"🟢 Xavfsiz: <b>{stats['safe']}</b>"
    )
    msg = update.effective_message
    await msg.reply_text(text, parse_mode=ParseMode.HTML)


# =========================================================
# FAYL ISHLOVCHISI
# =========================================================
async def handle_document(update: Update, context: ContextTypes.DEFAULT_TYPE):
    message = update.message
    document = message.document

    if document.file_size and document.file_size > MAX_FILE_SIZE_MB * 1024 * 1024:
        await message.reply_text(
            f"❌ Fayl juda katta. Maksimal hajm: {MAX_FILE_SIZE_MB} MB."
        )
        return

    status_msg = await message.reply_text("⏳ Fayl tekshirilmoqda, kuting...")

    try:
        tg_file = await context.bot.get_file(document.file_id)
        file_bytes = bytes(await tg_file.download_as_bytearray())
        user = update.effective_user

        # 🔑 Bloklovchi skan alohida thread'da — event loop band bo'lmaydi
        scan = await asyncio.to_thread(
            _run_scan, file_bytes, document.file_name or "file", user
        )
        await _send_result(status_msg, scan)

    except Exception as exc:  # noqa: BLE001
        logger.exception("Fayl tekshirishda xatolik: %s", exc)
        await status_msg.edit_text("❌ Xatolik yuz berdi. Birozdan keyin qayta urinib ko'ring.")


async def handle_photo(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Rasm sifatida yuborilgan fayllar uchun."""
    await update.message.reply_text(
        "ℹ️ Rasmni <b>fayl (document)</b> sifatida yuboring — shunda to'g'ri tekshira olaman.",
        parse_mode=ParseMode.HTML,
    )


async def handle_text(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text("📎 Iltimos, tekshirish uchun fayl yuboring.")


# =========================================================
# NATIJANI YUBORISH
# =========================================================
async def _send_result(status_msg, scan):
    emoji = scan.verdict_emoji
    score = scan.danger_score
    bar = _progress_bar(score)
    summary = (scan.summary_uz or "").strip()

    safe_name = html.escape(scan.file_name or "file")
    safe_summary = html.escape(summary[:2500])

    text = (
        f"{emoji} <b>Tekshiruv natijasi</b>\n\n"
        f"📄 Fayl: <code>{safe_name}</code>\n"
        f"⚖️ Xavf darajasi: [{bar}] {score}/100\n"
        f"🏷️ Xulosa: <b>{html.escape(scan.verdict_label)}</b>\n\n"
        f"{safe_summary}"
    )

    keyboard = [[InlineKeyboardButton("🌐 Batafsil hisobot", url=_result_url(scan.id))]]

    await status_msg.edit_text(
        text, parse_mode=ParseMode.HTML, reply_markup=InlineKeyboardMarkup(keyboard)
    )


# =========================================================
# CALLBACK TUGMALARI
# =========================================================
async def button_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()
    if query.data == "help":
        await help_command(update, context)
    elif query.data == "stats":
        await stats_command(update, context)


# =========================================================
# ILOVANI QURISH (poll va webhook uchun umumiy)
# =========================================================
def build_application() -> Application:
    token = settings.TELEGRAM_BOT_TOKEN
    if not token:
        raise ValueError(
            "TELEGRAM_BOT_TOKEN topilmadi! .env faylida tokenni o'rnating."
        )

    app = Application.builder().token(token).build()
    app.add_handler(CommandHandler("start", start))
    app.add_handler(CommandHandler("help", help_command))
    app.add_handler(CommandHandler("stats", stats_command))
    app.add_handler(MessageHandler(filters.Document.ALL, handle_document))
    app.add_handler(MessageHandler(filters.PHOTO, handle_photo))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_text))
    app.add_handler(CallbackQueryHandler(button_handler))
    return app


def run_polling():
    """Polling rejimida ishga tushirish (lokal/ishlab chiqish uchun qulay)."""
    app = build_application()
    logger.info("🤖 Bot polling rejimida ishga tushdi...")
    app.run_polling(drop_pending_updates=True, allowed_updates=Update.ALL_TYPES)
