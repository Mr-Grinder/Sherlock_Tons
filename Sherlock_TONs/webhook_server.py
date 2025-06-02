import os
from aiogram import Bot, Dispatcher
from aiogram.enums import ParseMode
from aiogram.fsm.storage.memory import MemoryStorage
from aiogram.client.default import DefaultBotProperties
from dotenv import load_dotenv
from fastapi import FastAPI
from aiogram.webhook.aiohttp_server import SimpleRequestHandler, setup_application

# Імпортуємо router з твого коду (handlers і т.д.)
from sherlock_tons import router

# Завантажуємо токен і дані Webhook
load_dotenv()
BOT_TOKEN = os.getenv("TG_BOT_TOKEN")
WEBHOOK_PATH = "/webhook"
WEBHOOK_SECRET = "tralala"  # можеш змінити
WEBHOOK_BASE = os.getenv("WEBHOOK_BASE")  
WEBHOOK_URL = f"{WEBHOOK_BASE}{WEBHOOK_PATH}"

# Створення бота та диспетчера
bot = Bot(token=BOT_TOKEN, default=DefaultBotProperties(parse_mode=ParseMode.HTML))
dp = Dispatcher(storage=MemoryStorage())
dp.include_router(router)

# FastAPI сервер
app = FastAPI()

@app.on_event("startup")
async def on_startup():
    await bot.set_webhook(WEBHOOK_URL, secret_token=WEBHOOK_SECRET)

@app.on_event("shutdown")
async def on_shutdown():
    await bot.delete_webhook()

# Підключаємо SimpleRequestHandler для обробки запитів Telegram
SimpleRequestHandler(dispatcher=dp, bot=bot, secret_token=WEBHOOK_SECRET).register(app, path=WEBHOOK_PATH)
