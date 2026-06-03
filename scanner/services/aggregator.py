"""Uchala manba natijasini birlashtirib yakuniy xulosa chiqaradi.

Chiqish: danger_score (0-100), verdict (safe/suspicious/dangerous/unknown),
aniqlangan tahdidlar ro'yxati va o'zbekcha matnli xulosa.
"""

DANGEROUS_THRESHOLD = 70
SUSPICIOUS_THRESHOLD = 35


def _vt_score(vt: dict) -> tuple[int, list[str]]:
    """VirusTotal natijasidan xavf balli va izohlar."""
    notes = []
    if not vt or not vt.get("available") or not vt.get("found"):
        return 0, notes

    mal = vt.get("malicious_count", 0)
    susp = vt.get("suspicious_count", 0)
    total = vt.get("total_engines", 0)

    # Aniqlovchilar soniga qarab ball
    if mal >= 10:
        score = 95
    elif mal >= 4:
        score = 80
    elif mal >= 1:
        score = 45
    elif susp >= 1:
        score = 30
    else:
        score = 0

    # Nisbat orqali nozik tuzatish
    if total > 0:
        ratio_score = min(100, round((mal + susp * 0.5) / total * 100) * 2)
        score = max(score, ratio_score)

    if mal or susp:
        notes.append(f"VirusTotal: {total} ta antivirusdan {mal} tasi xavfli, {susp} tasi shubhali deb topdi.")
    else:
        notes.append(f"VirusTotal: {total} ta antivirus hech qanday tahdid topmadi.")
    return min(score, 100), notes


def _mb_score(mb: dict) -> tuple[int, list[str]]:
    notes = []
    if not mb or not mb.get("available"):
        return 0, notes
    if mb.get("found"):
        sig = mb.get("signature") or "noma'lum oila"
        tags = ", ".join(mb.get("tags", [])[:6])
        msg = f"MalwareBazaar: fayl ma'lum zararli dasturlar bazasida topildi (oila: {sig})."
        if tags:
            msg += f" Teglar: {tags}."
        notes.append(msg)
        return 92, notes
    notes.append("MalwareBazaar: fayl ma'lum zararli dasturlar bazasida yo'q.")
    return 0, notes


def _ha_score(ha: dict) -> tuple[int, list[str]]:
    notes = []
    if not ha or not ha.get("available") or not ha.get("found"):
        return 0, notes

    verdict = ha.get("verdict")
    ts = int(ha.get("threat_score") or 0)
    family = ha.get("threat_family") or ""

    if verdict == "dangerous":
        score = max(80, ts)
        extra = f" (tahdid oilasi: {family})" if family else ""
        notes.append(f"Hybrid Analysis: sandbox tahlili faylni ZARARLI deb baholadi{extra}. Tahdid balli: {ts}/100.")
    elif verdict == "suspicious":
        score = max(50, ts)
        notes.append(f"Hybrid Analysis: sandbox tahlili faylni SHUBHALI deb baholadi. Tahdid balli: {ts}/100.")
    elif verdict == "safe":
        score = 0
        notes.append("Hybrid Analysis: sandbox tahlili tahdid topmadi.")
    else:
        score = 0
        notes.append("Hybrid Analysis: aniq xulosa berilmadi.")
    return min(score, 100), notes


def aggregate(vt: dict, mb: dict, ha: dict) -> dict:
    """Yakuniy natijani hisoblaydi."""
    vt = vt or {}
    mb = mb or {}
    ha = ha or {}

    vt_s, vt_notes = _vt_score(vt)
    mb_s, mb_notes = _mb_score(mb)
    ha_s, ha_notes = _ha_score(ha)

    # Eng yuqori ball yakuniy xavf darajasi bo'ladi
    danger_score = max(vt_s, mb_s, ha_s)

    any_available = any(s.get("available") for s in (vt, mb, ha))
    any_found = any(s.get("found") for s in (vt, mb, ha))

    if not any_available:
        verdict = "unknown"
    elif danger_score >= DANGEROUS_THRESHOLD:
        verdict = "dangerous"
    elif danger_score >= SUSPICIOUS_THRESHOLD:
        verdict = "suspicious"
    elif any_found:
        verdict = "safe"
    else:
        # Hech bir manbada topilmadi — to'liq ishonch yo'q
        verdict = "safe" if any_available else "unknown"

    detections = _collect_detections(vt, mb, ha)
    summary = _build_summary_uz(verdict, danger_score, vt_notes + mb_notes + ha_notes, vt, mb, ha)

    return {
        "verdict": verdict,
        "danger_score": int(danger_score),
        "detections": detections,
        "summary_uz": summary,
    }


def _collect_detections(vt: dict, mb: dict, ha: dict) -> list[dict]:
    out = []
    for d in (vt.get("detections") or [])[:15]:
        out.append({"source": "VirusTotal", "name": f"{d.get('engine')}: {d.get('result')}"})
    if mb.get("found"):
        out.append({"source": "MalwareBazaar", "name": mb.get("signature") or "Known malware"})
    if ha.get("found") and ha.get("threat_family"):
        out.append({"source": "Hybrid Analysis", "name": ha.get("threat_family")})
    return out


def _build_summary_uz(verdict, score, notes, vt, mb, ha) -> str:
    headers = {
        "dangerous": "🔴 XAVFLI FAYL — bu fayl zararli deb topildi!",
        "suspicious": "🟡 SHUBHALI FAYL — ehtiyot bo'ling.",
        "safe": "🟢 XAVFSIZ — tahdid aniqlanmadi.",
        "unknown": "⚪ NOMA'LUM — yetarli ma'lumot yo'q.",
    }
    advice = {
        "dangerous": "Bu faylni OCHMANG va o'chirib tashlang. U qurilmangizga zarar yetkazishi mumkin.",
        "suspicious": "Faylga ishonmaganingiz ma'qul. Manbasini tekshiring, kerak bo'lmasa ochmang.",
        "safe": "Hozircha tahdid topilmadi, lekin har doim faqat ishonchli manbalardan fayl oling.",
        "unknown": "Manbalardan natija olinmadi (kalit yo'q yoki fayl yangi). Ehtiyot choralarini ko'ring.",
    }

    lines = [headers.get(verdict, ""), "", f"Umumiy xavf darajasi: {score}/100", ""]
    lines.append("Manbalar bo'yicha tahlil:")
    for n in notes:
        if n:
            lines.append(f"  • {n}")
    lines.append("")
    lines.append(f"Tavsiya: {advice.get(verdict, '')}")
    return "\n".join(lines)
