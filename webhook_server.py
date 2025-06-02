import os
from dotenv import load_dotenv
from fastapi import FastAPI, Request, HTTPException
from aiogram import types
from sherlock_tons import bot, dp   # ← перевір, щоб назва файлу і папки точно співпадали
#   └── тут ми імпортуємо bot і dp з Sherlock_TONs/sherlock_tons.py

load_dotenv()

WEBHOOK_PATH   = "/webhook"
WEBHOOK_SECRET = os.getenv("WEBHOOK_SECRET", "some_super_secret_string")
WEBHOOK_BASE   = os.getenv("WEBHOOK_BASE")  
if not WEBHOOK_BASE:
    raise RuntimeError("У .env повинно бути: WEBHOOK_BASE=https://your-app.up.railway.app")
WEBHOOK_URL = f"{WEBHOOK_BASE}{WEBHOOK_PATH}"

app = FastAPI()

@app.on_event("startup")
async def on_startup():
    # встановлюємо вебхук у Telegram
    await bot.set_webhook(WEBHOOK_URL, secret_token=WEBHOOK_SECRET)
    print(f"✅ Webhook set to: {WEBHOOK_URL}")

@app.on_event("shutdown")
async def on_shutdown():
    # прибираємо вебхук при вимиканні
    await bot.delete_webhook()
    print("❌ Webhook deleted")

@app.post(WEBHOOK_PATH)
async def telegram_webhook(request: Request):
    # перевіряємо, що секретний токен у заголовку збігається
    token = request.headers.get("X-Telegram-Bot-Api-Secret-Token")
    if token != WEBHOOK_SECRET:
        raise HTTPException(status_code=403, detail="Forbidden")

    body = await request.json()
    update = types.Update.model_validate(body)
    # вручну передаємо Update у Dispatcher
    await dp.process_update(update)
    return {"status": "ok"}
