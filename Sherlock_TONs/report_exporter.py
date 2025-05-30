import pandas as pd


def save_wallet_analysis(results, filename: str = "wallet_analysis.xlsx"):
    """
    Зберігає аналіз гаманців у файл Excel.

    Параметри:
    - results: list[dict], де кожен dict містить:
        'address' (str),
        'exchange_interaction' (bool),
        'tiny_transfers' (int),
        'unique_sources' (int),
        'score' (int),
        'verdict' (str)
    - filename: назва вихідного файлу (.xlsx)
    """
    # Створення DataFrame з результатами
    df = pd.DataFrame(results)

    # Запис у Excel
    df.to_excel(filename, index=False)
    print(f"✅ Звіт збережено у файл: {filename}")

