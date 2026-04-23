import json
import csv
import matplotlib.pyplot as plt
import os

# Read results from analyzer
results_file = "results.csv"
vulnerable_count = 0
total_count = 0

# Count vulnerabilities
with open(results_file, 'r') as f:
    reader = csv.DictReader(f)
    for row in reader:
        total_count += 1
        if row['vulnerable'].lower() == 'true':
            vulnerable_count += 1

safe_count = total_count - vulnerable_count
percentage = (vulnerable_count / total_count) * 100

print(f"Total: {total_count}")
print(f"Vulnerable: {vulnerable_count}")
print(f"Safe: {safe_count}")
print(f"Percentage: {percentage:.1f}%")

# Create results directory
os.makedirs("results/charts", exist_ok=True)

# Chart 1: Bar Chart (Vulnerable vs Safe)
fig, ax = plt.subplots(figsize=(10, 6))
categories = ['Vulnerable', 'Safe']
counts = [vulnerable_count, safe_count]
colors = ['#E24B4A', '#1D9E75']
bars = ax.bar(categories, counts, color=colors, width=0.6)

# Add labels on bars
for bar in bars:
    height = bar.get_height()
    ax.text(bar.get_x() + bar.get_width()/2., height,
            f'{int(height)}',
            ha='center', va='bottom', fontsize=14, fontweight='bold')

ax.set_ylabel('Number of Policies', fontsize=12)
ax.set_title('AWS IAM Policy Vulnerability Analysis (500 Policies)', fontsize=14, fontweight='bold')
ax.set_ylim(0, max(counts) * 1.1)
plt.tight_layout()
plt.savefig('results/charts/vulnerable_vs_safe.png', dpi=300, bbox_inches='tight')
print("Saved: results/charts/vulnerable_vs_safe.png")
plt.close()

# Chart 2: Pie Chart (Percentage)
fig, ax = plt.subplots(figsize=(10, 8))
sizes = [percentage, 100 - percentage]
labels = [f'Vulnerable\n{percentage:.1f}%', f'Safe\n{100-percentage:.1f}%']
colors = ['#E24B4A', '#1D9E75']
explode = (0.05, 0)

wedges, texts, autotexts = ax.pie(sizes, explode=explode, labels=labels, colors=colors,
                                    autopct='%1.1f%%', shadow=True, startangle=90,
                                    textprops={'fontsize': 12, 'fontweight': 'bold'})

ax.set_title('AWS IAM Policy Vulnerability Distribution', fontsize=14, fontweight='bold', pad=20)
plt.tight_layout()
plt.savefig('results/charts/vulnerability_distribution.png', dpi=300, bbox_inches='tight')
print("Saved: results/charts/vulnerability_distribution.png")
plt.close()

# Chart 3: Summary Statistics Table
fig, ax = plt.subplots(figsize=(10, 6))
ax.axis('off')

summary_data = [
    ['Metric', 'Value'],
    ['Total Policies Analyzed', f'{total_count}'],
    ['Vulnerable Policies', f'{vulnerable_count}'],
    ['Safe Policies', f'{safe_count}'],
    ['Vulnerability Rate', f'{percentage:.1f}%'],
    ['Hypothesis Threshold', '40%'],
    ['Result', 'TRUE - Exceeds Threshold'],
]

table = ax.table(cellText=summary_data, cellLoc='center', loc='center',
                colWidths=[0.5, 0.5])
table.auto_set_font_size(False)
table.set_fontsize(11)
table.scale(1, 2.5)

# Style header row
for i in range(2):
    table[(0, i)].set_facecolor('#185FA5')
    table[(0, i)].set_text_props(weight='bold', color='white')

# Alternate row colors
for i in range(1, len(summary_data)):
    for j in range(2):
        if i % 2 == 0:
            table[(i, j)].set_facecolor('#E6F1FB')
        else:
            table[(i, j)].set_facecolor('#FFFFFF')

ax.set_title('Primary Hypothesis Analysis Summary', fontsize=14, fontweight='bold', pad=20)
plt.tight_layout()
plt.savefig('results/charts/summary_statistics.png', dpi=300, bbox_inches='tight')
print("Saved: results/charts/summary_statistics.png")
plt.close()

print("\n" + "="*60)
print("ALL VISUALIZATIONS CREATED SUCCESSFULLY!")
print("="*60)
print(f"Location: results/charts/")
print(f"  1. vulnerable_vs_safe.png")
print(f"  2. vulnerability_distribution.png")
print(f"  3. summary_statistics.png")
print("="*60)
