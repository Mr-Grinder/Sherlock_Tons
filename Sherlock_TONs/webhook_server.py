import os
from dotenv import load_dotenv
from fastapi import FastAPI, Request, HTTPException
from aiogram import types
from sherlock_tons import bot, dp   # <- переконайтеся, що тут правильно імпортовані bot і dp

load_dotenv()

WEBHOOK_PATH   = "/webhook"
WEBHOOK_SECRET = os.getenv("WEBHOOK_SECRET", "some_super_secret_string")
WEBHOOK_BASE   = os.getenv("WEBHOOK_BASE")  # наприклад: "https://your-app.up.railway.app"
if not WEBHOOK_BASE:
    raise RuntimeError("У .env повинна бути змінна WEBHOOK_BASE, наприклад: https://your-app.up.railway.app")
WEBHOOK_URL = f"{WEBHOOK_BASE}{WEBHOOK_PATH}"

app = FastAPI()

@app.on_event("startup")
async def on_startup():
    # Уточнюємо: видаляємо старий вебхук та скидaємо всі накопичені апдейти
    await bot.delete_webhook(drop_pending_updates=True)
    # Далі виставляємо новий вебхук із секретом
    await bot.set_webhook(WEBHOOK_URL, secret_token=WEBHOOK_SECRET)
    print(f"✅ Webhook set to: {WEBHOOK_URL}  (old updates dropped)")

@app.on_event("shutdown")
async def on_shutdown():
    # Перед завершенням роботи сервера видаляємо вебхук (та знищуємо можливі черги):
    await bot.delete_webhook(drop_pending_updates=True)
    # Імовірно, після цього слід також закрити асинхронну сесію бота
    await bot.session.close()
    print("❌ Webhook deleted and bot session closed")


@app.post(WEBHOOK_PATH)
async def telegram_webhook(request: Request):
    # Перевіряємо, що секретний токен у заголовку співпадає
    token = request.headers.get("X-Telegram-Bot-Api-Secret-Token")
    if token != WEBHOOK_SECRET:
        raise HTTPException(status_code=403, detail="Forbidden")

    # Парсимо JSON і створюємо Update
    body = await request.json()
    update = types.Update.model_validate(body)

    # Передаємо Update до диспетчера через feed_update
    await dp.feed_update(update=update, bot=bot)
    return {"status": "ok"}
