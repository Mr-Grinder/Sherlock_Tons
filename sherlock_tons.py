import os
import asyncio
import json
import re

from aiogram import Bot, Dispatcher, types, F
from aiogram.types import ReplyKeyboardMarkup, KeyboardButton
from aiogram.fsm.state import State, StatesGroup
from aiogram.fsm.storage.memory import MemoryStorage
from aiogram.fsm.context import FSMContext
from aiogram.enums import ParseMode
from aiogram.client.default import DefaultBotProperties
from aiogram.filters import Command, StateFilter
from aiogram import Router
from dotenv import load_dotenv
from urllib.parse import urlparse, parse_qs

# Ваші модулі
from ton_wallet_checker import extract_address, normalize_address, get_transactions, assess_safety, has_exchange_interaction
from report_exporter import save_wallet_analysis
from vt_link_checker import prepare_url_for_checking, check_url_virustotal

load_dotenv()
BOT_TOKEN = os.getenv("TG_BOT_TOKEN")
assert BOT_TOKEN, "TG_BOT_TOKEN is missing in .env file"

bot = Bot(
    token=BOT_TOKEN,
    default=DefaultBotProperties(parse_mode=ParseMode.HTML)
)
dp = Dispatcher(storage=MemoryStorage())
router = Router()
dp.include_router(router)

# Завантажуємо список відомих біржевих адрес
with open("know_exchange_addresses.json") as f:
    known_exchange_addresses = set(json.load(f))

class Form(StatesGroup):
    waiting_for_wallet = State()
    waiting_for_link   = State()
    waiting_for_scam   = State()

# Головна клавіатура
keyboard = ReplyKeyboardMarkup(
    keyboard=[
        [KeyboardButton(text="🔎 Check TON Wallet")],
        [KeyboardButton(text="🔗 Check link")],
        [KeyboardButton(text="📨 Check message")]
    ],
    resize_keyboard=True
)

MENU_ACTIONS = {"🔎 Check TON Wallet", "🔗 Check link","📨 Check message"}

IP_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
TON_RE = re.compile(r"\b[UEk][A-Za-z0-9_-]{45,}\b")

# --- Helpers ---
def collect_urls(message: types.Message) -> list[str]:
    urls = []

    text = (message.text or message.caption or "")
    entities = (message.entities or []) + (message.caption_entities or [])

    # text_link / url з entities
    for ent in entities:
        if ent.type == "text_link" and ent.url:
            urls.append(ent.url)
        elif ent.type == "url":
            urls.append(text[ent.offset: ent.offset + ent.length])

    # з inline-кнопок
    if message.reply_markup and getattr(message.reply_markup, "inline_keyboard", None):
        for row in message.reply_markup.inline_keyboard:
            for btn in row:
                if getattr(btn, "url", None):
                    urls.append(btn.url)

    # унікалізація з збереженням порядку
    seen, clean = set(), []
    for u in urls:
        if u not in seen:
            seen.add(u)
            clean.append(u)
    return clean

def parse_tme(url: str) -> dict | None:
    try:
        p = urlparse(url)
        if p.netloc.lower() not in {"t.me", "telegram.me"}:
            return None
        path = (p.path or "").strip("/")
        if not path:
            return {"kind": "tme", "username": "", "note": "no username"}
        username = path.split("/")[0]
        qs = parse_qs(p.query or "")
        payload = qs.get("start", [""])[0] or ""
        startapp = qs.get("startapp", [""])[0] or ""

        return {
            "kind": "tme",
            "username": username,
            "looks_like_bot": username.lower().endswith("bot"),
            "has_start": bool(payload),
            "has_startapp": bool(startapp),
            "payload": payload or startapp,
            "raw_query": p.query
        }
    except Exception:
        return {"kind": "tme", "error": "parse-failed"}

TRUSTED_BOTS = {
    # якщо хочеш whitelist — додай тут офіційні боти (не плутати з fragment.com)
    # "fragment": "@fragment"  # приклад (за потреби)
}
TRUSTED_DOMAINS = {"fragment.com", "ton.org", "getgems.io"}

def classify_link(url: str) -> dict:
    p = urlparse(url)
    host = p.netloc.lower()

    if host in {"t.me", "telegram.me"}:
        info = parse_tme(url)
        risk, reasons = 0, []

        if info.get("error"):
            return {"url": url, "risk": 60, "reasons": ["t.me parse failed"], "tme": info}

        u = info["username"].lower()
        if not u:
            risk += 40; reasons.append("t.me without username")

        if info["looks_like_bot"]:
            if info["has_start"] or info["has_startapp"]:
                risk += 40
                reasons.append("Telegram bot deep-link (start/startapp). "
                               "Official services typically use a website URL (e.g., fragment.com), not a bot.")
        else:
            risk += 20
            reasons.append("t.me non-bot username used in transaction context")

        if any(x in (p.path or "") for x in ["fragment", "fragmnt", "fragnent"]):
            risk += 20; reasons.append("Fragment-like wording via Telegram bot")

        return {"url": url, "risk": min(risk, 100), "reasons": reasons, "tme": info}

    # не-t.me → домен
    risk, reasons = 10, []
    if host not in TRUSTED_DOMAINS:
        risk += 30
        reasons.append("Domain is not among known official services")
    if host.startswith("xn--") or ".xn--" in host:
        risk += 40; reasons.append("Punycode/homograph domain")
    return {"url": url, "risk": min(risk, 100), "reasons": reasons}

async def analyze_wallet_quick(addr_b64: str) -> dict:
    """
    Швидкий аналіз гаманця для вбудовування в репорти.
    Повертає dict із ключовими метриками та вердиктом.
    """
    txs = get_transactions(addr_b64, limit=100)
    rows = []
    for tx in txs:
        in_msg = tx.get("in_msg", {})
        rows.append({
            "timestamp":   tx.get("utime"),
            "source":      in_msg.get("source"),
            "destination": in_msg.get("destination"),
            "value_TON":   int(in_msg.get("value", 0)) / 1e9,
            "comment":     in_msg.get("decoded_body", {}).get("text","") or in_msg.get("message","")
        })

    score, verdict = assess_safety(rows)
    details = {
        "address":              addr_b64,
        "tx_count":             len(rows),
        "exchange_interaction": has_exchange_interaction(rows, known_exchange_addresses),
        "tiny_transfers":       sum(1 for tx in rows if tx["value_TON"] < 0.001),
        "unique_sources":       len({tx["source"]["address"]
                                     for tx in rows
                                     if tx.get("source") and isinstance(tx["source"], dict) and tx["source"].get("address")}),
        "score":                score,
        "verdict":              verdict
    }
    return details

def format_wallet_summary(w: dict) -> str:
    flag = "🟥" if w["score"] >= 2 else "🟧" if w["score"] == 1 else "🟩"
    ex  = "Yes" if w["exchange_interaction"] else "No"
    return (
        f"<b>Wallet:</b> <code>{w['address']}</code>\n"
        f"{flag} <b>{w['verdict']}</b>\n"
        f"• Tx count: {w['tx_count']}\n"
        f"• Exchange interaction: {ex}\n"
        f"• Tiny transfers (&lt;0.001): {w['tiny_transfers']}\n"
        f"• Unique sources: {w['unique_sources']}"
    )


def extract_ips_wallets_from_text(text: str):
    ips = IP_RE.findall(text)
    w  = TON_RE.findall(text)
    # унікальні:
    ips = list(dict.fromkeys(ips))
    w   = list(dict.fromkeys(w))
    return ips, w


@router.message(Command("start"))
async def cmd_start(message: types.Message):
    await message.answer(
        "Hello! I'm your Security Bot.\n"
        "I can check TON wallets and verify URLs for phishing threats.\n"
        "Choose an option:",
        reply_markup=keyboard
    )

@router.message(F.text == "🔎 Check TON Wallet")
async def wallet_choice(message: types.Message, state: FSMContext):
    await state.set_state(Form.waiting_for_wallet)
    await message.answer("📥 Please send the TON wallet address or a link to it:", reply_markup=types.ReplyKeyboardRemove())

@router.message(Form.waiting_for_wallet)
async def process_wallet(message: types.Message, state: FSMContext):
    await message.answer("⏳ Processing wallet, this may take a few seconds...")
    user_input = message.text.strip()
    try:
        raw  = extract_address(user_input)
        addr = normalize_address(raw)

        # Аналіз
        wr = await analyze_wallet_quick(addr)
        flag = "🟥" if wr["score"] >= 2 else "🟧" if wr["score"] == 1 else "🟩"

        # Збереження у файл (як і раніше)
        user = message.from_user
        save_wallet_analysis([{
            "user_id":              user.id,
            "username":             user.username or "N/A",
            "is_bot":               user.is_bot,
            "address":              wr["address"],
            "exchange_interaction": wr["exchange_interaction"],
            "tiny_transfers":       wr["tiny_transfers"],
            "unique_sources":       wr["unique_sources"],
            "score":                wr["score"],
            "verdict":              wr["verdict"]
        }])

        # Відповідь користувачу — “повний вердикт”
        reply = (
            f"{flag} <b>{wr['verdict']}</b>\n"
            f"<b>Address:</b> <code>{wr['address']}</code>\n"
            f"• Tx count: {wr['tx_count']}\n"
            f"• Exchange interaction: {'Yes' if wr['exchange_interaction'] else 'No'}\n"
            f"• Tiny transfers (&lt;0.001): {wr['tiny_transfers']}\n"
            f"• Unique sources: {wr['unique_sources']}"
        )
        await message.answer(reply)

    except Exception as e:
        await message.answer(f"❌ Error processing wallet: {e}")

    await state.clear()
    await message.answer("🔄 What next?", reply_markup=keyboard)

@router.message(F.text == "🔗 Check link")
async def link_choice(message: types.Message, state: FSMContext):
    await state.set_state(Form.waiting_for_link)
    await message.answer("📥 Please send the URL you want to check:", reply_markup=types.ReplyKeyboardRemove())

@router.message(Form.waiting_for_link)
async def process_link(message: types.Message, state: FSMContext):
    await message.answer("⏳ Processing URL, this may take a few seconds...")
    user_url = message.text.strip()
    try:
        clean_url = prepare_url_for_checking(user_url)
        status = check_url_virustotal(clean_url)

        if status == "dangerous":
            verdict = "🚨 The URL appears potentially dangerous!"
        elif status == "unknown":
            verdict = "🕵️ URL not recognized. It may be a new or fake domain ⚠️"
        elif status == "unresolved":
            verdict = "⁉️ No such domain found, suspected phishing attack!"    
        elif status == "invalid":
            verdict = "❌ This doesn't look like a valid link. Please check the format."    
        else:  # "safe"
            verdict = "✅ The URL appears safe."

        await message.answer(verdict)

    except Exception as e:
        await message.answer(f"❌ Error checking URL: {e}")

    await state.clear()
    await message.answer("🔄 What next?", reply_markup=keyboard)

@router.message(F.text == "📨 Check message")
async def check_message(message: types.Message, state: FSMContext):
    await state.set_state(Form.waiting_for_scam)
    await message.answer(
        "📥 Please forward the MESSAGE you want to check:",
        reply_markup=types.ReplyKeyboardRemove()
    )

@router.message(Form.waiting_for_scam)
async def process_scam_message(message: types.Message, state: FSMContext):
    await message.answer("⏳ Processing analyze, this may take a few seconds...")
    text   = (message.text or message.caption or "")
    urls   = collect_urls(message)
    links  = [classify_link(u) for u in urls]

    # VirusTotal тільки для не-t.me (опціонально: можеш вимкнути)
    enriched = []
    for l in links:
        host = urlparse(l["url"]).netloc.lower()
        vt = None
        if host not in {"t.me", "telegram.me"}:
            try:
                clean = prepare_url_for_checking(l["url"])
                vt = check_url_virustotal(clean)
                if vt == "dangerous":
                    l["risk"] = max(l["risk"], 80)
                    l["reasons"].append("VirusTotal flags: dangerous")
                elif vt == "unknown":
                    l["reasons"].append("VirusTotal: unknown")
                elif vt == "unresolved":
                    l["reasons"].append("Domain unresolved")
                elif vt == "invalid":
                    l["reasons"].append("Invalid URL")
            except Exception as e:
                l["reasons"].append(f"VT error: {e}")
        enriched.append(l)

    # IPs & wallets
    ips, wallet_candidates = extract_ips_wallets_from_text(text)

    # Аналіз знайдених гаманців
    wallet_reports = []
    for raw in wallet_candidates[:3]:  # не більше 3 на повідомлення
        try:
            addr = normalize_address(extract_address(raw))
            wr = await analyze_wallet_quick(addr)
            wallet_reports.append(wr)
        except Exception as e:
            wallet_reports.append({"address": raw, "score": -1, "verdict": f"Error: {e}", 
                                   "tx_count": 0, "exchange_interaction": False, 
                                   "tiny_transfers": 0, "unique_sources": 0})

    # Висновок
    max_link_risk = max([l["risk"] for l in enriched], default=0)
    max_wallet_risk = max([w["score"] for w in wallet_reports], default=0)
    overall = max(max_link_risk, 70 if max_wallet_risk >= 2 else 40 if max_wallet_risk == 1 else 0)

    verdict = "🚨 High risk" if overall >= 70 else "⚠️ Medium risk" if overall >= 40 else "✅ Low risk markers"

    # Analysis (пояснення, що не так)
    analysis_reasons = []
    if any("Telegram bot deep-link" in ",".join(l["reasons"]) for l in enriched):
        analysis_reasons.append("• Uses Telegram bot deep-link (start/startapp). Official services typically use a website URL (e.g., fragment.com).")
    if any("Domain is not among known official services" in ",".join(l["reasons"]) for l in enriched):
        analysis_reasons.append("• Link points to a domain that is not among known official services.")
    if any("Punycode" in ",".join(l["reasons"]) for l in enriched):
        analysis_reasons.append("• Domain looks like an IDN/homograph (punycode).")
    if any(r for r in enriched if any("VirusTotal flags: dangerous" in x for x in r["reasons"])):
        analysis_reasons.append("• VirusTotal reports malicious or suspicious indicators.")
    if any(w["score"] >= 2 for w in wallet_reports):
        analysis_reasons.append("• Related wallet shows multiple red flags (suspicious activity).")

    # РЕПОРТ
    out = [f"{verdict}", ""]
    if analysis_reasons:
        out.append("<b>Analysis — what looks wrong:</b>")
        out += analysis_reasons
        out.append("")

    # Links
    out.append("<b>Links:</b>")
    if enriched:
        for l in enriched:
            rbadge = "🟥" if l["risk"]>=70 else "🟧" if l["risk"]>=40 else "🟩"
            line = f"{rbadge} <code>{l['url']}</code>"
            if l.get("tme"):
                t = l["tme"]
                line += (f"\n    t.me → username=@{t.get('username','')}, "
                         f"bot={t.get('looks_like_bot')}, payload={bool(t.get('payload'))}")
            if l["reasons"]:
                line += f"\n    reasons: {', '.join(l['reasons'])}"
            out.append(line)
    else:
        out.append("none")
    out.append("")

    # IPs
    out.append("<b>IPs:</b>")
    out += [f"• <code>{ip}</code>" for ip in ips] if ips else ["none"]
    out.append("")

    # Wallets
    out.append("<b>TON wallet analysis:</b>")
    if wallet_reports:
        for w in wallet_reports:
            out.append(format_wallet_summary(w))
            out.append("")
    else:
        out.append("none")

    await message.answer("\n".join(out).strip())
    await state.clear()
    await message.answer("🔄 What next?", reply_markup=keyboard)


@router.message(StateFilter(None), F.text & ~F.text.in_(MENU_ACTIONS)) # Обробка текстових повідомлень, які не є командами меню
async def invalid_text_action(message: types.Message):
    await message.answer(
        "❌ This is not a valid action.\nPlease choose an option from the keyboard below.",
        reply_markup=keyboard
    )

@router.message(StateFilter(None), ~F.text) # Обробка не текстових повідомлень
async def invalid_non_text_action(message: types.Message):
    await message.answer(
        "❌ This is not a valid action.\nPlease choose an option from the keyboard below.",
        reply_markup=keyboard
    )

# Polling
async def main():
    await dp.start_polling(bot)

if __name__ == "__main__":
    print("✅ Running bot")
    asyncio.run(main())

        