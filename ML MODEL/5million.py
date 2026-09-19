import pandas as pd

print("Testing 5M rows...")
df = pd.read_csv(
    "D:\\AL_MASHROOOOOO3\\ML\\GUIDE_Train.csv",
    nrows=5000000
)
df = df.dropna(subset=["IncidentGrade"])
print(f"Rows: {len(df):,}")
print(f"Memory: {df.memory_usage(deep=True).sum() / 1e9:.2f} GB")
print(df["IncidentGrade"].value_counts())
