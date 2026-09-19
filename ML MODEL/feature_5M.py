import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder

print("Loading 5M rows...")
df = pd.read_csv(
    "D:\\AL_MASHROOOOOO3\\ML\\GUIDE_Train.csv",
    nrows=5000000
)
df = df.dropna(subset=["IncidentGrade"])
print(f"Rows: {len(df):,}")

# fill nulls
df["MitreTechniques"] = df["MitreTechniques"].fillna("Unknown")
df["SuspicionLevel"]  = df["SuspicionLevel"].fillna("Unknown")
df["LastVerdict"]     = df["LastVerdict"].fillna("Unknown")

# encode target
label_map = {"TruePositive": 1, "FalsePositive": 0, "BenignPositive": 2}
df["label"] = df["IncidentGrade"].map(label_map)

# encode categorical
categorical_cols = [
    "Category", "EntityType", "EvidenceRole",
    "MitreTechniques", "SuspicionLevel", "LastVerdict"
]
numeric_features = ["OSFamily", "OSVersion", "DetectorId", "OrgId"]

for col in categorical_cols:
    le = LabelEncoder()
    df[col + "_enc"] = le.fit_transform(df[col].astype(str))

print("✅ Encoding done")

all_features = numeric_features + [col+"_enc" for col in categorical_cols]
X = df[all_features]
y = df["label"]

# split 80/10/10
X_train, X_temp, y_train, y_temp = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)
X_val, X_test, y_val, y_test = train_test_split(
    X_temp, y_temp, test_size=0.5, random_state=42, stratify=y_temp
)

print(f"\nTrain: {len(X_train):,}")
print(f"Val  : {len(X_val):,}")
print(f"Test : {len(X_test):,}")

# save
X_train.to_csv("X_train_5M.csv", index=False)
y_train.to_csv("y_train_5M.csv", index=False)
X_val.to_csv("X_val_5M.csv", index=False)
y_val.to_csv("y_val_5M.csv", index=False)
X_test.to_csv("X_test_5M.csv", index=False)
y_test.to_csv("y_test_5M.csv", index=False)

print("\n✅ All splits saved!")