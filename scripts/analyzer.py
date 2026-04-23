import json
import os
import csv

policies_dir = "/home/vboxuser/cloud-iam-capstone/policies"
results = []

vulnerable_count = 0
total_count = 0

for filename in os.listdir(policies_dir):
    if filename.endswith('.json'):
        total_count +=1
        filepath = os.path.join(policies_dir, filename)

        try:
            with open(filepath, 'r') as f:
                policy = json.load(f)

            has_wildcard = False

            for statement in policy.get('Statement', []):
                actions = statement.get('Action', [])
                resources = statement.get('Resource', [])

                if isinstance(actions, str):
                    actions = [actions]
                if isinstance(resources, str):
                    resources = [resources]

                if "*" in actions or "*" in resources:
                    has_wildcard = True
                    break

            if has_wildcard:
                vulnerable_count +=1

            results.append({
                'filename': filename,
                'vulnerable': has_wildcard
                })

        except:
            pass

print(f'Total policies: {total_count}')
print(f'Vulnerable count: {vulnerable_count}')
print(f'Percentage: {(vulnerable_count/total_count)*100:.1f}%')

with open('results.csv', 'w', newline='') as f:
    writer = csv.DictWriter(f, fieldnames=['filename', 'vulnerable'])
    writer.writeheader()
    writer.writerows(results)

print('Results saved to results.csv')
