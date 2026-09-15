import pandas as pd

df = pd.read_csv("GUIDE_train_final.csv")

print("=== All Columns ===")
for col in df.columns:
    print(f"  {col}: {df[col].dtype} | nulls: {df[col].isna().sum()}")