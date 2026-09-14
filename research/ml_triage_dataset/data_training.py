import json, yaml
from collections import Counter

products = Counter()

with open("train.jsonl", encoding="utf-8") as f:
    for line in f:
        item = json.loads(line)
        try:
            rule = yaml.safe_load(item["output"])
            prod = rule.get("logsource", {}).get("product", "none")
            products[prod] += 1
        except:
            pass

print("Products in training data:")
for k, v in products.most_common():
    print(f"  {v:>5}  {k}")