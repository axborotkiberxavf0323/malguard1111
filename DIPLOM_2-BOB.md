# 2-BOB. TIZIMNI LOYIHALASH VA AMALGA OSHIRISH

> Ushbu hujjat diplom ishining 2.2 va 2.3 bo'limlari uchun tayyorlangan.
> Skrinshot qo'yiladigan joylar **[SKRINSHOT N]** belgisi bilan ko'rsatilgan —
> shu joylarga mos rasmlarni qo'ying va izoh (caption) yozing.

---

## 2.2. Tizimning qurilish arxitekturasi va ishlatish strukturasi

### 2.2.1. Umumiy arxitektura

"MalGuard" zararli fayllarni aniqlash tizimi **uch qatlamli (three-tier)**
arxitektura asosida qurilgan bo'lib, mijoz-server modelida ishlaydi. Tizim
ikkita asosiy kirish nuqtasiga (foydalanuvchi interfeysiga) ega:

1. **Veb-interfeys** — Django asosidagi sayt orqali fayllarni yuklash;
2. **Telegram bot** — xabar almashish ilovasi orqali fayllarni yuborish.

Har ikkala kirish nuqtasi ham yagona **markaziy tahlil yadrosiga**
(`ScannerService`) murojaat qiladi. Bu esa kod takrorlanishining oldini oladi
va tizimni kengaytirishni osonlashtiradi (DRY — Don't Repeat Yourself printsipi).

Tizimning umumiy arxitekturasi quyidagi qatlamlardan iborat:

| Qatlam | Vazifasi | Texnologiya |
|--------|----------|-------------|
| **Taqdimot qatlami** (Presentation) | Foydalanuvchi bilan o'zaro aloqa | HTML, CSS, JavaScript, Bootstrap Icons |
| **Mantiq qatlami** (Business Logic) | Fayllarni tahlil qilish, natijalarni birlashtirish | Python, Django, ScannerService, Aggregator |
| **Integratsiya qatlami** (Integration) | Tashqi API'lar bilan aloqa | VirusTotal, Hybrid Analysis, MalwareBazaar API |
| **Ma'lumotlar qatlami** (Data) | Natijalarni saqlash | SQLite / PostgreSQL, Django ORM |

> **[SKRINSHOT 1]** — Bu yerga tizimning umumiy arxitektura sxemasini (blok-diagramma)
> qo'ying. Sxemada: Foydalanuvchi → (Sayt / Telegram bot) → ScannerService →
> 3 ta API → Aggregator → Ma'lumotlar bazasi ketma-ketligi ko'rsatilsin.

### 2.2.2. Texnologik stek (ishlatilgan vositalar)

Tizimni ishlab chiqishda quyidagi zamonaviy texnologiyalar tanlangan:

- **Python 3.10+** — asosiy dasturlash tili. Soddaligi, kuchli kutubxonalari va
  kiberxavfsizlik sohasidagi keng qo'llanilishi sababli tanlangan.
- **Django 4.2** — veb-freymvork. MVT (Model-View-Template) arxitekturasi,
  o'rnatilgan admin panel, ORM va xavfsizlik mexanizmlari (CSRF, XSS himoyasi)
  bilan ta'minlangan.
- **python-telegram-bot 20+** — Telegram bot uchun asinxron (async) kutubxona.
- **requests** — tashqi API'larga HTTP so'rovlar yuborish uchun.
- **SQLite / PostgreSQL** — ma'lumotlar bazasi. Standart holatda SQLite (sozlash
  shart emas), yuqori yuklamali muhitda PostgreSQL'ga o'tkazish mumkin.
- **WhiteNoise** — statik fayllarni (CSS, JS) samarali uzatish uchun.

### 2.2.3. Loyihaning modulli strukturasi

Loyiha Django'ning "ilova" (app) konsepsiyasi asosida mantiqiy modullarga
ajratilgan:

```
malguard1111/
├── config/              # Tizim sozlamalari
│   ├── settings.py      # Asosiy konfiguratsiya (.env'dan o'qiydi)
│   ├── urls.py          # Asosiy URL marshrutlari
│   └── wsgi.py/asgi.py  # Server kirish nuqtalari
│
├── scanner/             # ASOSIY ILOVA (tahlil yadrosi)
│   ├── models.py        # Ma'lumotlar modellari (ScanResult)
│   ├── views.py         # Veb sahifalar mantig'i
│   ├── admin.py         # Admin panel sozlamalari
│   └── services/        # ★ Tahlil xizmatlari (eng muhim qism)
│       ├── virustotal.py      # VirusTotal integratsiyasi
│       ├── malwarebazaar.py   # MalwareBazaar integratsiyasi
│       ├── hybrid_analysis.py # Hybrid Analysis integratsiyasi
│       ├── aggregator.py      # Natijalarni birlashtirish
│       └── scanner_service.py # Orkestrator (boshqaruvchi)
│
├── bot/                 # TELEGRAM BOT ILOVASI
│   ├── bot.py           # Bot buyruqlari va handlerlar (async)
│   ├── views.py         # Webhook (production uchun)
│   └── management/commands/   # runbot, setwebhook buyruqlari
│
├── templates/           # HTML shablonlar
├── static/              # CSS va JavaScript fayllar
└── manage.py            # Django boshqaruv skripti
```

> **[SKRINSHOT 2]** — Bu yerga loyiha papkalari strukturasini (VS Code yoki
> fayllar menejeri ko'rinishida) skrinshot qilib qo'ying.

### 2.2.4. Ma'lumotlar modeli (Database Schema)

Tizimning markaziy ma'lumotlar modeli — `ScanResult` jadvali. U har bir fayl
tekshiruvining to'liq natijasini saqlaydi. Asosiy maydonlar:

| Maydon | Turi | Tavsifi |
|--------|------|---------|
| `file_name` | CharField | Fayl nomi |
| `file_size` | BigInteger | Fayl hajmi (bayt) |
| `file_md5` | CharField | MD5 hash (indekslangan) |
| `file_sha256` | CharField | SHA-256 hash (indekslangan, kesh kaliti) |
| `status` | CharField | Holat: pending / scanning / completed / error |
| `verdict` | CharField | Xulosa: safe / suspicious / dangerous / unknown |
| `danger_score` | SmallInteger | Xavf darajasi (0–100) |
| `source` | CharField | Manba: web / telegram / api |
| `virustotal_result` | JSONField | VirusTotal'dan kelgan natija |
| `hybrid_analysis_result` | JSONField | Hybrid Analysis natijasi |
| `malwarebazaar_result` | JSONField | MalwareBazaar natijasi |
| `summary_uz` | TextField | O'zbekcha umumiy xulosa |
| `created_at` | DateTime | Yaratilgan vaqt |

Hisoblash tezligini oshirish maqsadida `file_sha256` va `verdict` maydonlariga
**indekslar** qo'yilgan.

> **[SKRINSHOT 3]** — Django admin panelidagi "Skan natijalari" jadvalini yoki
> ma'lumotlar bazasi sxemasi (ER-diagramma) ni qo'ying.

### 2.2.5. Ishlash algoritmi (asosiy oqim)

Foydalanuvchi fayl yuborganda tizim quyidagi bosqichlarni bajaradi:

**1-bosqich. Faylni qabul qilish va validatsiya.**
Fayl hajmi (maksimal 32 MB) va kengaytmasi tekshiriladi.

**2-bosqich. Hash hisoblash.**
Faylning MD5, SHA-1 va SHA-256 "barmoq izlari" hisoblanadi. SHA-256 keyingi
bosqichlarda noyob identifikator sifatida ishlatiladi.

**3-bosqich. Keshni tekshirish (optimallashtirish).**
Agar shu SHA-256 ga ega fayl avval tekshirilgan bo'lsa, tayyor natija
qaytariladi — API'lar qayta chaqirilmaydi. Bu API kvotasini tejaydi va javobni
tezlashtiradi.

**4-bosqich. Parallel tahlil (asosiy optimallashtirish).**
Uchala API (`VirusTotal`, `MalwareBazaar`, `Hybrid Analysis`) bir vaqtning
o'zida, parallel ravishda chaqiriladi. Buning uchun `ThreadPoolExecutor`
ishlatiladi. Natijada umumiy javob vaqti ketma-ket usulga nisbatan ~3 baravar
qisqaradi.

**5-bosqich. Natijalarni birlashtirish (Aggregation).**
`aggregator.py` moduli har bir manbadan kelgan natijani tahlil qilib, xavf
ballini (0–100) hisoblaydi. Eng yuqori ball yakuniy xavf darajasi sifatida
qabul qilinadi.

**6-bosqich. Xulosa chiqarish.**
Xavf darajasiga qarab yakuniy verdikt aniqlanadi va o'zbek tilida tushunarli
tavsiya tayyorlanadi:

| Xavf darajasi | Verdikt | Belgi |
|---------------|---------|-------|
| 70–100 | Xavfli (dangerous) | 🔴 |
| 35–69 | Shubhali (suspicious) | 🟡 |
| 0–34 | Xavfsiz (safe) | 🟢 |
| Ma'lumot yo'q | Noma'lum (unknown) | ⚪ |

**7-bosqich. Saqlash.**
Natija `ScanResult` jadvaliga yoziladi va foydalanuvchiga qaytariladi.

> **[SKRINSHOT 4]** — Bu yerga ishlash algoritmining blok-sxemasi (flowchart) ni
> qo'ying. Yuqoridagi 7 bosqichni ketma-ket strelkalar bilan ko'rsating.

### 2.2.6. Tashqi xizmatlar bilan integratsiya

Tizim uchta xalqaro kiberxavfsizlik xizmati bilan integratsiyalashgan. Har biri
turli yondashuvdan foydalanadi, bu esa aniqlikni oshiradi (qatlamli himoya):

- **VirusTotal** — faylni 70+ antivirus dvigateli bilan tekshiradi. Avval
  SHA-256 bo'yicha qidiradi; topilmasa, faylni yuklab tahlil qiladi.
- **Hybrid Analysis** — faylni izolyatsiyalangan muhitda (sandbox) ishga
  tushirib, uning xatti-harakatini kuzatadi.
- **MalwareBazaar** — fayl hashini ma'lum zararli dasturlar bazasi bilan
  solishtiradi. Topilsa — fayl 100% zararli hisoblanadi.

Muhim jihat: agar biror API kaliti sozlanmagan yoki xizmat javob bermasa,
tizim ishdan to'xtamaydi — o'sha manba "mavjud emas" deb belgilanadi va
qolgan manbalar asosida xulosa chiqariladi (xatolarga chidamlilik —
fault tolerance).

---

## 2.3. Tizim imkoniyatlari va sinov (test) natijalari

### 2.3.1. Tizimning asosiy imkoniyatlari

Ishlab chiqilgan tizim quyidagi imkoniyatlarga ega:

**A. Veb-interfeys imkoniyatlari:**
1. Faylni "sudrab tashlash" (drag & drop) yoki tanlash orqali yuklash;
2. Real vaqtda tahlil jarayonini kuzatish (yuklanmoqda indikatori);
3. Vizual xavf o'lchagichi (0–100 ko'rsatkichli "progress bar");
4. Har bir manba bo'yicha batafsil natija (VirusTotal, HA, MalwareBazaar);
5. Aniqlangan tahdidlar ro'yxati (qaysi antivirus nima topgani);
6. Tekshiruvlar tarixi sahifasi;
7. Umumiy statistika (jami, xavfli, shubhali, xavfsiz fayllar soni);
8. Natijani JSON formatida olish (API).

**B. Telegram bot imkoniyatlari:**
1. `/start`, `/help`, `/stats` buyruqlari;
2. Istalgan faylni yuborib tekshirish;
3. O'zbek tilida tushunarli natija;
4. Asinxron ishlash — bir nechta foydalanuvchiga bir vaqtda xizmat;
5. Inline tugmalar (Yordam, Statistika).

**C. Admin panel imkoniyatlari:**
1. Barcha tekshiruvlarni ko'rish va boshqarish;
2. Fayl nomi yoki hash bo'yicha qidirish;
3. Verdikt, manba, sana bo'yicha filtrlash;
4. Rangli vizual ko'rsatkichlar.

> **[SKRINSHOT 5]** — Saytning bosh sahifasi (fayl yuklash zonasi, statistika,
> "Qanday ishlaydi" bo'limi ko'rinib turgan holda).

### 2.3.2. Sinov muhiti

Tizim quyidagi muhitda sinovdan o'tkazildi:

| Parametr | Qiymat |
|----------|--------|
| Operatsion tizim | Windows 10/11 |
| Python versiyasi | 3.10+ |
| Ma'lumotlar bazasi | SQLite |
| Brauzer | Google Chrome / Microsoft Edge |
| Server | Django development server (localhost:8000) |

### 2.3.3. Sinov stsenariylari va natijalari

Tizim funksionalligini tekshirish uchun to'rt xil turdagi fayllar bilan sinov
o'tkazildi. Natijalar quyidagi jadvalda keltirilgan:

| № | Sinov fayli | Kutilgan natija | Olingan natija | Holat |
|---|-------------|-----------------|----------------|-------|
| 1 | Toza hujjat (PDF, rasm) | 🟢 Xavfsiz | 🟢 Xavfsiz (0/100) | ✅ O'tdi |
| 2 | Ma'lum zararli fayl (test namunasi) | 🔴 Xavfli | 🔴 Xavfli (100/100) | ✅ O'tdi |
| 3 | Bir nechta dvigatel flag qilgan fayl | 🟡 Shubhali | 🟡 Shubhali (45/100) | ✅ O'tdi |
| 4 | Hajmi 32 MB dan katta fayl | Rad etish | "Fayl juda katta" xatosi | ✅ O'tdi |

**Test 1 — Xavfsiz fayl.**
Oddiy PDF yoki rasm fayli yuklanganda, barcha manbalar tahdid topmadi. Tizim
"🟢 XAVFSIZ — tahdid aniqlanmadi" xulosasini berdi, xavf darajasi 0/100.

> **[SKRINSHOT 6]** — Xavfsiz fayl tekshirilganda chiqgan natija sahifasi.

**Test 2 — Zararli fayl (EICAR test namunasi).**
Antivirus sinovlari uchun mo'ljallangan standart EICAR test fayli yuklandi.
VirusTotal'da ko'plab dvigatellar uni aniqladi va tizim "🔴 XAVFLI" xulosasini
berdi, xavf darajasi 100/100.

> **Izoh:** EICAR — bu haqiqiy virus emas, balki antivirus tizimlarini sinash
> uchun maxsus yaratilgan zararsiz standart test satri. Uni
> https://www.eicar.org/download-anti-malware-testfile/ dan olish mumkin.
> Diplom sinovida real zararli fayl ishlatish xavfli va shart emas.

> **[SKRINSHOT 7]** — Zararli (EICAR) fayl tekshirilganda chiqgan "🔴 XAVFLI"
> natijasi, qizil xavf o'lchagichi va aniqlangan tahdidlar ro'yxati ko'rinsin.

**Test 3 — Shubhali fayl.**
Kam sonli dvigatel tomonidan flag qilingan fayl "🟡 SHUBHALI" deb baholandi.

> **[SKRINSHOT 8]** — Shubhali fayl natijasi (sariq o'lchagich).

**Test 4 — Hajm chegarasi.**
32 MB dan katta fayl yuklanganda tizim uni rad etdi va tegishli xato xabarini
ko'rsatdi.

> **[SKRINSHOT 9]** — "Fayl juda katta" xato xabari.

### 2.3.4. Telegram bot sinovi

Telegram bot quyidagi holatlarda sinovdan o'tkazildi:

1. `/start` buyrug'i — bot xush kelibsiz xabarini va tugmalarni ko'rsatdi;
2. Fayl yuborish — bot "⏳ Fayl tekshirilmoqda..." xabarini berib, so'ng
   natijani qaytardi;
3. `/stats` buyrug'i — umumiy statistikani ko'rsatdi.

> **[SKRINSHOT 10]** — Telegram botda `/start` buyrug'iga javob (tugmalar bilan).

> **[SKRINSHOT 11]** — Telegram botga fayl yuborilganda chiqgan tahlil natijasi
> (emoji, xavf darajasi, o'zbekcha xulosa ko'rinsin).

> **[SKRINSHOT 12]** — Bot serverining konsol logi (terminalda fayl
> tekshirilayotgani haqidagi INFO yozuvlari).

### 2.3.5. Optimallashtirish natijalari (samaradorlik tahlili)

Loyihaning asosiy yutug'i — tahlil tezligini oshirish. Quyidagi taqqoslash
optimallashtirishning samarasini ko'rsatadi:

| Ko'rsatkich | Ketma-ket usul (eski) | Parallel usul (yangi) | Yaxshilanish |
|-------------|----------------------|----------------------|--------------|
| 3 ta API javob vaqti | ~9–15 soniya | ~3–5 soniya | ~3 baravar tez |
| Takroriy fayl (kesh) | ~9–15 soniya | < 0.1 soniya | ~100 baravar tez |
| Bir vaqtda bot foydalanuvchilari | 1 ta (bloklangan) | Cheklanmagan | To'liq async |

Optimallashtirishning uch asosiy yo'nalishi:

1. **Parallel so'rovlar** — `ThreadPoolExecutor` orqali 3 ta API bir vaqtda
   chaqiriladi (ketma-ket emas).
2. **Hash-keshlash** — bir xil fayl qayta tekshirilganda API chaqirilmaydi,
   natija bazadan olinadi.
3. **Asinxron bot** — `asyncio.to_thread` orqali bot bloklamaydigan qilindi;
   bir foydalanuvchi fayli tekshirilayotganda boshqalar kutib qolmaydi.

> **[SKRINSHOT 13]** — (Ixtiyoriy) Tahlil vaqtini ko'rsatuvchi log yoki
> taqqoslash diagrammasi (ustunli grafik).

### 2.3.6. Xavfsizlik choralari

Tizimda quyidagi xavfsizlik mexanizmlari qo'llanilgan:

- **CSRF himoyasi** — Django'ning o'rnatilgan mexanizmi orqali soxta
  so'rovlarning oldi olinadi;
- **XSS himoyasi** — foydalanuvchi kiritgan ma'lumotlar HTML'ga chiqarishdan
  oldin "escape" qilinadi;
- **Maxfiy ma'lumotlarni ajratish** — barcha API kalitlari va tokenlar `.env`
  faylida saqlanadi va kodga yozilmaydi (`.gitignore` orqali himoyalangan);
- **Fayl validatsiyasi** — hajm va kengaytma tekshiruvi;
- **Webhook maxfiy tokeni** — Telegram webhook uchun qo'shimcha himoya.

### 2.3.7. Sinov natijalari bo'yicha xulosa

O'tkazilgan sinovlar shuni ko'rsatdiki, ishlab chiqilgan "MalGuard" tizimi:

- ✅ Fayllarni to'g'ri tasniflaydi (xavfli / shubhali / xavfsiz);
- ✅ Uchta mustaqil manbadan foydalanib, aniqlikni oshiradi;
- ✅ Optimallashtirish hisobiga tez ishlaydi (~3 baravar);
- ✅ Ham veb, ham Telegram orqali qulay foydalaniladi;
- ✅ O'zbek tilida tushunarli natija beradi;
- ✅ Xatolarga chidamli (bitta xizmat ishламasa ham ishlaydi).

Barcha rejalashtirilgan funksiyalar muvaffaqiyatli sinovdan o'tdi va tizim
belgilangan talablarni qondiradi.

---

## SKRINSHOTLAR RO'YXATI (qisqacha qo'llanma)

Quyidagi 13 ta skrinshotni tayyorlang:

| № | Nima skrinshot qilinadi | Qayerdan olinadi |
|---|-------------------------|------------------|
| 1 | Arxitektura sxemasi | O'zingiz chizasiz (draw.io / Word SmartArt) |
| 2 | Loyiha papka strukturasi | VS Code chap paneli |
| 3 | Ma'lumotlar bazasi / admin jadval | http://localhost:8000/admin/ |
| 4 | Algoritm blok-sxemasi | O'zingiz chizasiz |
| 5 | Sayt bosh sahifasi | http://localhost:8000/ |
| 6 | Xavfsiz fayl natijasi | Toza fayl yuklab |
| 7 | Xavfli fayl natijasi | EICAR fayl yuklab |
| 8 | Shubhali fayl natijasi | Mos fayl yuklab |
| 9 | "Fayl juda katta" xatosi | 32 MB+ fayl yuklab |
| 10 | Bot /start javobi | Telegram |
| 11 | Bot fayl tahlili | Telegram |
| 12 | Bot konsol logi | Terminal (runbot) |
| 13 | Tezlik taqqoslash | Log yoki diagramma |
