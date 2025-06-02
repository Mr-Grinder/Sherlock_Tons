import pandas as pd
import os
from datetime import datetime

def save_wallet_analysis(results, filename: str = "wallet_analysis.csv"):
    """
    Зберігає аналіз гаманців у CSV-файл із датою й часом. Якщо файл існує — додає до нього.

    Параметри:
    - results: list[dict], де кожен dict містить:
        'address' (str),
        'exchange_interaction' (bool),
        'tiny_transfers' (int),
        'unique_sources' (int),
        'score' (int),
        'verdict' (str)
    - filename: назва вихідного CSV-файлу
    """
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    # Додаємо timestamp до кожного запису
    for item in results:
        item["timestamp"] = timestamp

    df = pd.DataFrame(results)
    file_exists = os.path.isfile(filename)
    df.to_csv(filename, mode='a', header=not file_exists, index=False)
    print(f"✅ Звіт збережено у файл: {filename}")
