import os
from dotenv import load_dotenv
from fastapi import FastAPI
from aiogram.webhook.aiohttp_server import SimpleRequestHandler, setup_application

# Імпортуємо router з основного коду 
from sherlock_tons import router, bot, dp

# Завантажуємо токен і дані Webhook
load_dotenv()
BOT_TOKEN = os.getenv("TG_BOT_TOKEN")
WEBHOOK_PATH = "/webhook"
WEBHOOK_SECRET = "tralala"  
WEBHOOK_BASE = os.getenv("WEBHOOK_BASE")  
WEBHOOK_URL = f"{WEBHOOK_BASE}{WEBHOOK_PATH}"

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
