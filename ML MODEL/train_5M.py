import pandas as pd
from xgboost import XGBClassifier
from sklearn.metrics import classification_report, accuracy_score
import time

print("Loading training data...")
X_train = pd.read_csv("X_train_5M.csv")
y_train = pd.read_csv("y_train_5M.csv").values.ravel()
X_val   = pd.read_csv("X_val_5M.csv")
y_val   = pd.read_csv("y_val_5M.csv").values.ravel()

print(f"X_train: {X_train.shape}")

print("Training XGBoost on 5M rows...")
start = time.time()

model = XGBClassifier(
    n_estimators  = 300,
    max_depth     = 6,
    learning_rate = 0.1,
    objective     = "multi:softprob",
    num_class     = 3,
    eval_metric   = "mlogloss",
    random_state  = 42,
    n_jobs        = -1,
)

model.fit(
    X_train, y_train,
    eval_set=[(X_val, y_val)],
    verbose=50,
)

elapsed = time.time() - start
print(f"Training time: {elapsed:.1f} seconds ({elapsed/60:.1f} minutes)")

print("\n=== Validation Results ===")
y_pred = model.predict(X_val)
print(f"Accuracy: {accuracy_score(y_val, y_pred):.4f}")
print(classification_report(
    y_val, y_pred,
    target_names=["FalsePositive", "TruePositive", "BenignPositive"]
))

model.save_model("xgboost_5M_model.json")
print("Model saved ✅")
print("Task 63 Complete ✅")