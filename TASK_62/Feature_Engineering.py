import pandas as pd
from sklearn.preprocessing import LabelEncoder
import numpy as np

print("Loading data...")
train = pd.read_csv("GUIDE_train_final.csv")
val   = pd.read_csv("GUIDE_val_final.csv")
test  = pd.read_csv("GUIDE_test_sample.csv")

print(f"Train: {len(train):,} | Val: {len(val):,} | Test: {len(test):,}")

# === Step 1: Select useful features ===
features = [
    "Category",
    "EntityType",
    "EvidenceRole",
    "OSFamily",
    "OSVersion",
    "DetectorId",
    "OrgId",
    "MitreTechniques",
    "SuspicionLevel",
    "LastVerdict",
]
target = "IncidentGrade"

# === Step 2: Fill nulls ===
for df in [train, val, test]:
    df["MitreTechniques"] = df["MitreTechniques"].fillna("Unknown")
    df["SuspicionLevel"]  = df["SuspicionLevel"].fillna("Unknown")
    df["LastVerdict"]     = df["LastVerdict"].fillna("Unknown")

# === Step 3: Encode target label ===
label_map = {
    "TruePositive":   1,
    "FalsePositive":  0,
    "BenignPositive": 2
}
for df in [train, val, test]:
    df["label"] = df[target].map(label_map)

# === Step 4: Encode categorical features ===
categorical_cols = [
    "Category", "EntityType", "EvidenceRole",
    "MitreTechniques", "SuspicionLevel", "LastVerdict"
]

for col in categorical_cols:
    le = LabelEncoder()
    # fit on train only
    le.fit(train[col].astype(str))

    # transform all splits
    train[col + "_enc"] = le.transform(train[col].astype(str))
    # handle unseen values in val/test
    val[col + "_enc"]  = val[col].astype(str).apply(
        lambda x: le.transform([x])[0] if x in le.classes_ else -1
    )
    test[col + "_enc"] = test[col].astype(str).apply(
        lambda x: le.transform([x])[0] if x in le.classes_ else -1
    )

print("✅ Encoding done")

# === Step 5: Build final feature sets ===
numeric_features = ["OSFamily", "OSVersion", "DetectorId", "OrgId"]
encoded_features = [col + "_enc" for col in categorical_cols]
all_features     = numeric_features + encoded_features

X_train = train[all_features]
y_train = train["label"]

X_val   = val[all_features]
y_val   = val["label"]

X_test  = test[all_features]
y_test  = test["label"]

print(f"\nFeature count: {len(all_features)}")
print(f"Features used: {all_features}")

print(f"\nX_train shape: {X_train.shape}")
print(f"X_val shape  : {X_val.shape}")
print(f"X_test shape : {X_test.shape}")

print(f"\ny_train distribution:\n{y_train.value_counts()}")

# === Step 6: Save ===
X_train.to_csv("X_train.csv", index=False)
y_train.to_csv("y_train.csv", index=False)

X_val.to_csv("X_val.csv", index=False)
y_val.to_csv("y_val.csv", index=False)

X_test.to_csv("X_test.csv", index=False)
y_test.to_csv("y_test.csv", index=False)

print("\n✅ Saved: X_train, y_train, X_val, y_val, X_test, y_test")
print("Task 62 Complete ✅")