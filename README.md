# 🛡️ MalGuard — Zararli fayllarni aniqlovchi tizim

Fayllarni **VirusTotal**, **Hybrid Analysis** va **MalwareBazaar** orqali bir vaqtda
(parallel) tekshirib, natijalarni birlashtiradi va **o'zbek tilida** aniq xulosa beradigan
Django sayti + Telegram bot.

> Diplom loyihasi uchun tayyor, optimallashtirilgan versiya.

---

## ✨ Imkoniyatlar

- 🌐 **Veb-sayt** — faylni drag & drop bilan yuklab tekshirish
- 🤖 **Telegram bot** — faylni botga yuborib, shu zahoti natija olish
- ⚡ **Parallel tahlil** — 3 ta API bir vaqtda chaqiriladi (ketma-ket emas → 3x tezroq)
- 💾 **Hash keshlash** — bir xil fayl (SHA-256) qayta yuborilsa, API chaqirilmaydi (kvota tejaladi)
- 🧠 **Aqlli xulosa** — 3 manba natijasidan yagona xavf darajasi (0–100) va o'zbekcha tavsiya
- 🔄 **Bloklamaydigan bot** — bir fayl tekshirilayotganda boshqa foydalanuvchilar kutmaydi
- 📊 **Statistika va tarix** — barcha tekshiruvlar bazada saqlanadi
- 🛠️ **Admin panel** — Django admin orqali boshqaruv

---

## 📦 Talablar

- Python **3.10+**
- (Ixtiyoriy) PostgreSQL — standart holatda SQLite ishlatiladi, hech narsa sozlash shart emas

---

## 🚀 Tezkor ishga tushirish (5 qadam)

### 1. Virtual muhit va kutubxonalar

```bash
# Loyiha papkasiga kiring
cd malware_scanner

# Virtual muhit yaratish
python -m venv venv

# Faollashtirish:
#   Windows:
venv\Scripts\activate
#   Linux / macOS:
source venv/bin/activate

# Kutubxonalarni o'rnatish
pip install -r requirements.txt
```

### 2. Sozlamalar (.env)

`.env.example` faylini `.env` nomi bilan nusxalang va to'ldiring:

```bash
cp .env.example .env       # Linux/macOS
copy .env.example .env     # Windows
```

`.env` ichida kamida quyidagilarni to'ldiring:

```env
SECRET_KEY=ixtiyoriy-uzun-maxfiy-kalit
VIRUSTOTAL_API_KEY=...
HYBRID_ANALYSIS_API_KEY=...
MALWAREBAZAAR_API_KEY=...
TELEGRAM_BOT_TOKEN=...
TELEGRAM_BOT_USERNAME=sizning_bot
```

> 💡 API kalitlarning **kamida bittasi** bo'lsa ham tizim ishlaydi.
> Kalit kiritilmagan xizmat avtomatik o'tkazib yuboriladi.

### 3. Ma'lumotlar bazasi

```bash
python manage.py migrate
python manage.py createsuperuser   # admin panel uchun (ixtiyoriy)
```

### 4. Saytni ishga tushirish

```bash
python manage.py runserver
```

Brauzerda oching: **http://localhost:8000**

### 5. Telegram botni ishga tushirish (alohida terminalda)

```bash
python manage.py runbot
```

Endi botingizga Telegram orqali fayl yuborib, sinab ko'ring! ✅

---

## 🔑 API kalitlarini qayerdan olish

| Xizmat | Manzil | Eslatma |
|--------|--------|---------|
| **VirusTotal** | https://www.virustotal.com/gui/my-apikey | Bepul: 4 so'rov/daqiqa, 500/kun |
| **Hybrid Analysis** | https://www.hybrid-analysis.com → My Account → API key | Bepul akkaunt yetarli |
| **MalwareBazaar** | https://auth.abuse.ch/ | Auth-Key oling |
| **Telegram bot** | https://t.me/BotFather → `/newbot` | Token va username |

---

## 🤖 Bot: Polling vs Webhook

- **Polling** (tavsiya, lokal uchun): `python manage.py runbot` — public domen shart emas.
- **Webhook** (production, HTTPS domen bo'lganda):
  ```bash
  # .env ga TELEGRAM_WEBHOOK_URL=https://domen.uz/bot/webhook/ yozing, so'ng:
  python manage.py setwebhook
  # Polingga qaytish uchun:
  python manage.py setwebhook --delete
  ```

---

## 🗂️ Loyiha tuzilishi

```
malware_scanner/
├── config/               # Django sozlamalari (settings, urls, wsgi/asgi)
├── scanner/              # Asosiy ilova
│   ├── models.py         # ScanResult, ScanStatistics
│   ├── views.py          # Sayt sahifalari + skan API
│   ├── admin.py          # Admin panel
│   └── services/         # 🔬 Tahlil yadrosi
│       ├── virustotal.py
│       ├── malwarebazaar.py
│       ├── hybrid_analysis.py
│       ├── aggregator.py        # Natijalarni birlashtirish + xulosa
│       └── scanner_service.py   # Orkestrator (parallel + kesh)
├── bot/                  # Telegram bot
│   ├── bot.py            # Handlerlar (async)
│   ├── views.py          # Webhook
│   └── management/commands/   # runbot, setwebhook
├── templates/            # HTML shablonlar
├── static/               # CSS / JS
├── .env.example
├── requirements.txt
└── manage.py
```

---

## ⚙️ Qanday ishlaydi (tahlil mantig'i)

1. Fayl qabul qilinadi → **MD5/SHA-256** hisoblanadi.
2. **Kesh tekshiruvi**: shu SHA-256 avval tekshirilgan bo'lsa — tayyor natija qaytariladi.
3. **Parallel so'rov** (`ThreadPoolExecutor`):
   - VirusTotal — hash bo'yicha, topilmasa fayl yuklab tahlil qilinadi;
   - MalwareBazaar — hash ma'lum zararli dasturlar bazasida bormi;
   - Hybrid Analysis — sandbox hisobotlari bormi.
4. **Birlashtirish** (`aggregator.py`): har bir manbadan xavf balli olinadi, eng yuqorisi yakuniy daraja bo'ladi.
5. **Xulosa**: `0–100` xavf darajasi + verdict (🟢/🟡/🔴) + o'zbekcha tavsiya.

| Xavf darajasi | Xulosa |
|---------------|--------|
| 70–100 | 🔴 Xavfli |
| 35–69 | 🟡 Shubhali |
| 0–34 | 🟢 Xavfsiz |

---

## 🛡️ Xavfsizlik eslatmalari

- `.env` faylini **hech qachon** Git'ga qo'shmang (`.gitignore` da bor).
- Agar kalit/token oshkor bo'lsa — darhol yangilang (BotFather: `/revoke`).
- Production'da `DEBUG=False` qiling va `ALLOWED_HOSTS` ni to'ldiring.

---

## 🧰 Production uchun

```bash
python manage.py collectstatic --noinput
gunicorn config.wsgi:application --bind 0.0.0.0:8000
```

Statik fayllar **WhiteNoise** orqali xizmat qilinadi (qo'shimcha sozlash shart emas).
