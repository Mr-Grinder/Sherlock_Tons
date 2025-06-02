import os
import asyncio
import json

from aiogram import Bot, Dispatcher, types, F
from aiogram.types import ReplyKeyboardMarkup, KeyboardButton
from aiogram.fsm.state import State, StatesGroup
from aiogram.fsm.storage.memory import MemoryStorage
from aiogram.fsm.context import FSMContext
from aiogram.enums import ParseMode
from aiogram.client.default import DefaultBotProperties
from aiogram.filters import Command
from aiogram import Router
from dotenv import load_dotenv

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
storage = MemoryStorage()
dp = Dispatcher(storage=storage)
router = Router()
dp.include_router(router)

# Завантажуємо список відомих біржевих адрес
with open("know_exchange_address.json") as f:
    known_exchange_addresses = set(json.load(f))

class Form(StatesGroup):
    waiting_for_wallet = State()
    waiting_for_link   = State()

# Головна клавіатура
keyboard = ReplyKeyboardMarkup(
    keyboard=[
        [KeyboardButton(text="🔎 Check TON Wallet")],
        [KeyboardButton(text="🔗 Check link")]
    ],
    resize_keyboard=True
)

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
        raw   = extract_address(user_input)
        addr  = normalize_address(raw)
        txs   = get_transactions(addr, limit=100)

        if not txs:
            verdict = "⚠️ No transactions found for this wallet."
        else:
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
            
            user = message.from_user
            # Зберігаємо звіт у файл, але не повідомляємо про це користувача
            result = {                
                "user_id":              user.id,
                "username":   user.username or "N/A",
                "is_bot":     user.is_bot,
                "address":              addr,
                "exchange_interaction": has_exchange_interaction(rows, known_exchange_addresses),
                "tiny_transfers":       sum(1 for tx in rows if tx["value_TON"] < 0.001),
                "unique_sources":       len({tx["source"]["address"] for tx in rows if tx.get("source") and isinstance(tx["source"], dict)}),
                "score":                score,
                "verdict":              verdict              
            }
            save_wallet_analysis([result])

        # Відправляємо лише вердикт
        await message.answer(verdict)

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

