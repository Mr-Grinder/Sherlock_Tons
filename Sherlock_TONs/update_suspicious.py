import json
import requests
import os

# Шлях до JSON-файлу, в якому зберігаємо підозрілі адреси
SUSPICIOUS_FILE = "suspicious_addresses.json"

# Адреси, які хочемо перевірити
addresses_to_check = [
    "Uf_BbsF16B4aReCFhXIOLh7qgIdLTClPvKU29ZWwLShiscNK",
    # додай ще адреси вручну або з іншого джерела
]

# Завантажити вже збережені підозрілі адреси
if os.path.exists(SUSPICIOUS_FILE):
    with open(SUSPICIOUS_FILE, "r") as f:
        suspicious_data = json.load(f)
else:
    suspicious_data = {}

# Функція перевірки адреси через TONAPI
def check_address(address):
    url = f"https://tonapi.io/v2/blockchain/accounts/{address}"
    try:
        response = requests.get(url)
        if response.status_code == 200:
            data = response.json()
            if data.get("is_scam") or (data.get("label") and "scam" in data["label"].lower()):
                return {
                    "address": address,
                    "label": data.get("label", "unknown"),
                    "is_scam": data.get("is_scam", False)
                }
    except Exception as e:
        print(f"❌ Помилка при перевірці {address}: {e}")
    return None

# Перевірка та оновлення
for addr in addresses_to_check:
    if addr not in suspicious_data:
        print(f"🔍 Перевірка адреси: {addr}")
        result = check_address(addr)
        if result:
            print(f"⚠️  Додано як підозрілу: {addr}")
            suspicious_data[addr] = result

# Зберігаємо оновлений список
with open(SUSPICIOUS_FILE, "w") as f:
    json.dump(suspicious_data, f, indent=2)

print("✅ Перевірка завершена. Список оновлено.")
