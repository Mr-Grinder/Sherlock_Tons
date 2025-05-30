import re
import base64
import os
import requests
import pandas as pd
from dotenv import load_dotenv
import json
from report_exporter import save_wallet_analysis

# ---- Load API key from .env ----
load_dotenv()
TON_API_KEY = os.getenv("TON_API_KEY")
assert TON_API_KEY, "TON_API_KEY not found in .env"

# Load known exchange addresses
with open("know_exchange_address.json") as f:
    known_exchange_addresses = json.load(f)

# ---- Extract raw address from any input string ----
def extract_address(input_str: str) -> str:
    s = input_str.strip()

    # 1) URLs like https://tonviewer.com/<address> or https://tonscan.org/<address>
    m = re.search(r'https?://(?:tonviewer\.com|tonscan\.org)/([A-Za-z0-9_-]+)', s)
    if m:
        return m.group(1)

    # 2) Any URL – take the last segment
    m = re.search(r'https?://[^/]+/([^/]+)$', s)
    if m:
        return m.group(1)

    # 3) Otherwise assume it's already a raw address
    return s

# ---- Normalize to base64url format (48 characters) ----
def normalize_address(addr: str) -> str:
    addr = addr.strip()

    # Already in base64url format?
    if re.fullmatch(r'[A-Za-z0-9_-]{48}', addr):
        return addr

    # hex format “0:<hex>”
    if addr.startswith('0:'):
        hex_part = addr.split(':', 1)[1]
        hex_part = hex_part.zfill(64)
        data = bytes.fromhex(hex_part)
        b64 = base64.urlsafe_b64encode(data).decode('utf-8').rstrip('=')
        if re.fullmatch(r'[A-Za-z0-9_-]{48}', b64):
            return b64
        else:
            raise ValueError(f"Invalid base64url length after encoding: {len(b64)}")

    raise ValueError(f"Unknown address format: «{addr}»")

# ---- Get transactions from TonAPI V2 ----
def get_transactions(address_b64: str, limit: int = 50):
    url = f"https://tonapi.io/v2/blockchain/accounts/{address_b64}/transactions?limit={limit}"
    headers = {"Authorization": f"Bearer {TON_API_KEY}"}
    r = requests.get(url, headers=headers)

    print("→ URL:", url)
    print("→ Status:", r.status_code)
    print("→ Response (first 200 chars):", r.text[:200].replace('\n',' '), '…')

    r.raise_for_status()
    return r.json().get("transactions", [])

def has_exchange_interaction(transactions: list, known_addresses: dict) -> bool:
    """Check whether any transactions were sent to known exchange addresses."""
    for tx in transactions:
        for msg in tx.get("out_msgs", []):
            destination = msg.get("destination")
            if destination in known_addresses:
                print(f"⚠️ Found transaction to exchange: {destination}")
                return True
    return False

# ---- Safety assessment function ----
def assess_safety(transactions):
    score = 0

    if has_exchange_interaction(transactions, known_exchange_addresses):
        score += 2

    tiny_transfers = [tx for tx in transactions if tx["value_TON"] < 0.001]
    if len(tiny_transfers) > 5:
        score += 1

    sources = {
        tx["source"]["address"]
        for tx in transactions
        if tx.get("source") and isinstance(tx["source"], dict) and tx["source"].get("address")
    }

    destinations = {
        tx["destination"]["address"]
        for tx in transactions
        if tx.get("destination") and isinstance(tx["destination"], dict) and tx["destination"].get("address")
    }

    if sources and not destinations.intersection(sources):
        score += 1

    if len(sources) > 10:
        score += 1

    if score == 0:
        verdict = "✅ The wallet appears safe (no obvious red flags found)."
    elif score == 1:
        verdict = "⚠️ Minor suspicions (one or two anomalies). Further verification is recommended."
    else:
        verdict = "🚨 Suspicious! It is recommended to avoid interacting with this wallet."

    return score, verdict

# ---- Main logic ----
if __name__ == "__main__":
    all_results = []

    raw = input("Enter TON address or wallet URL: ")
    try:
        extracted = extract_address(raw)
        address = normalize_address(extracted)
        print("Normalized address:", address)

        transactions = get_transactions(address, limit=100)
        if not transactions:
            print("⚠️ No transactions found.")
            exit()

        parsed_rows = []
        for tx in transactions:
            in_msg = tx.get("in_msg", {})
            parsed_rows.append({
                "timestamp":    tx.get("utime"),
                "source":       in_msg.get("source"),
                "destination":  in_msg.get("destination"),
                "value_TON":    int(in_msg.get("value", 0)) / 1e9,
                "comment":      in_msg.get("decoded_body", {}).get("text","") or in_msg.get("message","")
            })

        score, verdict = assess_safety(parsed_rows)
        print(f"\n🔎 Safety score: {score}")
        print(verdict)

        result = {
            "address":               address,
            "exchange_interaction":  has_exchange_interaction(parsed_rows, known_exchange_addresses),
            "tiny_transfers":        sum(1 for tx in parsed_rows if tx["value_TON"] < 0.001),
            "unique_sources":        len({tx["source"]["address"]
                                        for tx in parsed_rows
                                        if tx.get("source") and isinstance(tx["source"], dict)}),
            "score":                 score,
            "verdict":               verdict
        }
        all_results.append(result)

        df = pd.DataFrame(parsed_rows)
        df.to_csv("ton_wallet_report.csv", index=False)
        print("\nTransaction details saved to ton_wallet_report.csv")

        save_wallet_analysis(all_results, filename="wallet_analysis.xlsx")

    except Exception as e:
        print("❌ Error:", e)
