import os
from dotenv import load_dotenv
from fastapi import FastAPI, Request, HTTPException
from aiogram.webhook import AiogramWebhookCallback
from sherlock_tons import bot, dp  # ← імпортуємо вже готові bot і dp
from aiogram import types
from aiogram.client.default import DefaultBotProperties

load_dotenv()

WEBHOOK_PATH   = "/webhook"
WEBHOOK_SECRET = os.getenv("WEBHOOK_SECRET", "some_super_secret_string")
WEBHOOK_BASE   = os.getenv("WEBHOOK_BASE")  
if not WEBHOOK_BASE:
    raise RuntimeError("❌ В .env має бути змінна WEBHOOK_BASE, наприклад: https://your-app.up.railway.app")
WEBHOOK_URL = f"{WEBHOOK_BASE}{WEBHOOK_PATH}"

app = FastAPI()

# Aiogram callback для обробки апдейтів від Telegram
webhook_callback = AiogramWebhookCallback(dispatcher=dp, bot=bot, secret_token=WEBHOOK_SECRET)

@app.on_event("startup")
async def on_startup():
    # Встановлюємо webhook на Telegram-сервері
    await bot.set_webhook(WEBHOOK_URL, secret_token=WEBHOOK_SECRET)
    print(f"✅ Webhook set to: {WEBHOOK_URL}")

@app.on_event("shutdown")
async def on_shutdown():
    # Видаляємо webhook під час завершення додатка
    await bot.delete_webhook()
    print("❌ Webhook deleted")

@app.post(WEBHOOK_PATH)
async def telegram_webhook(request: Request):
    """
    Цей ендпоінт приймає POST-запити від Telegram
    і передає їх у AiogramWebhookCallback.
    """
    # Переконаємося, що у заголовку є правильний секрет
    token = request.headers.get("X-Telegram-Bot-Api-Secret-Token")
    if token != WEBHOOK_SECRET:
        # Якщо секрет не співпав – не обробляємо запит
        raise HTTPException(status_code=403, detail="Forbidden")

    # Отримуємо json із запиту
    body = await request.json()
    update = types.Update.model_validate(body)
    # Передаємо апдейт до Aiogram
    await webhook_callback(request)
    return {"status": "ok"}
