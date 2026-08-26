import json, yaml
from collections import Counter

categories = Counter()

with open("train_filtered.jsonl", encoding="utf-8") as f:
    for line in f:
        item = json.loads(line)
        try:
            rule = yaml.safe_load(item["output"])
            ls   = rule.get("logsource", {})
            cat  = ls.get("category", "none")
            categories[cat] += 1
        except:
            pass

print("Categories in filtered training data:")
for k, v in categories.most_common():
    print(f"  {v:>5}  {k}")