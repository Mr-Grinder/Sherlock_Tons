import os
from dotenv import load_dotenv
from fastapi import FastAPI, Request, HTTPException
from aiogram import types
from sherlock_tons import bot, dp   

load_dotenv()

WEBHOOK_PATH   = "/webhook"
WEBHOOK_SECRET = os.getenv("WEBHOOK_SECRET")
WEBHOOK_BASE   = os.getenv("WEBHOOK_BASE") 
if not WEBHOOK_BASE:
    raise RuntimeError("У .env повинна бути змінна WEBHOOK_BASE")
WEBHOOK_URL = f"{WEBHOOK_BASE}{WEBHOOK_PATH}"

app = FastAPI()

@app.on_event("startup")
async def on_startup():
    await bot.delete_webhook(drop_pending_updates=True)
    await bot.set_webhook(WEBHOOK_URL, secret_token=WEBHOOK_SECRET)
    print(f"✅ Webhook set to: {WEBHOOK_URL}  (old updates dropped)")

@app.on_event("shutdown")
async def on_shutdown():
    await bot.delete_webhook(drop_pending_updates=True)
    await bot.session.close()
    print("❌ Webhook deleted and bot session closed")


@app.post(WEBHOOK_PATH)
async def telegram_webhook(request: Request):
    token = request.headers.get("X-Telegram-Bot-Api-Secret-Token")
    if token != WEBHOOK_SECRET:
        raise HTTPException(status_code=403, detail="Forbidden")

    body = await request.json()
    update = types.Update.model_validate(body)

    await dp.feed_update(update=update, bot=bot)
    return {"status": "ok"}
