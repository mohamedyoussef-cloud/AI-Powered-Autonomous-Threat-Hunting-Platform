import json, yaml
from collections import Counter

keep_products = {"windows", "linux", "none"}

kept    = []
removed = []

with open("train.jsonl", encoding="utf-8") as f:
    for line in f:
        item = json.loads(line)
        try:
            rule = yaml.safe_load(item["output"])
            prod = rule.get("logsource", {}).get("product", "none")
            if prod in keep_products:
                kept.append(item)
            else:
                removed.append(item)
        except:
            kept.append(item)

print(f"Kept   : {len(kept)}")
print(f"Removed: {len(removed)}")

with open("train_filtered.jsonl", "w", encoding="utf-8") as f:
    for item in kept:
        f.write(json.dumps(item) + "\n")

print("Saved train_filtered.jsonl ✅")

products = Counter()
for item in kept:
    try:
        rule = yaml.safe_load(item["output"])
        prod = rule.get("logsource", {}).get("product", "none")
        products[prod] += 1
    except:
        pass

print("\nNew distribution:")
for k, v in products.most_common():
    print(f"  {v:>5}  {k}")