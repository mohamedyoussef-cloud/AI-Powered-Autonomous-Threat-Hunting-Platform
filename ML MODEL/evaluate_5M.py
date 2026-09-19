import pandas as pd
from xgboost import XGBClassifier
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
import json

print("Loading test data...")
X_test = pd.read_csv("X_test_5M.csv")
y_test = pd.read_csv("y_test_5M.csv").values.ravel()

model = XGBClassifier()
model.load_model("xgboost_5M_model.json")
print("Model loaded ✅")

print("\n=== Final Test Results (Task 64) ===")
y_pred = model.predict(X_test)

accuracy = accuracy_score(y_test, y_pred)
print(f"Accuracy: {accuracy:.4f}")

report = classification_report(
    y_test, y_pred,
    target_names=["FalsePositive", "TruePositive", "BenignPositive"],
    output_dict=True
)
print(classification_report(
    y_test, y_pred,
    target_names=["FalsePositive", "TruePositive", "BenignPositive"]
))

cm = confusion_matrix(y_test, y_pred)
print("Confusion Matrix:")
print(cm)

print("\n=== Feature Importance ===")
features = X_test.columns.tolist()
importance = model.feature_importances_
for feat, imp in sorted(zip(features, importance), key=lambda x: -x[1]):
    print(f"  {feat:<25} {imp:.4f}")

results = {
    "accuracy":      float(accuracy),
    "macro_f1":      float(report["macro avg"]["f1-score"]),
    "training_rows": 3977593,
    "test_rows":     len(X_test),
    "classification_report": report,
    "confusion_matrix": cm.tolist()
}
with open("task64_results.json", "w") as f:
    json.dump(results, f, indent=2)

print("\nSaved to task64_results.json ✅")
print("Task 64 Complete ✅")