import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import os

os.makedirs("../charts", exist_ok=True)

print("Creating charts...")

# ============================================================
# CHART 1: Primary Hypothesis Bar Chart
# ============================================================
fig, ax = plt.subplots(figsize=(10, 6))

categories = ['Vulnerable\n(Wildcard)', 'Safe']
values = [314, 186]
colors = ['#E74C3C', '#2ECC71']

bars = ax.bar(categories, values, color=colors, width=0.5, edgecolor='black')

for bar in bars:
    height = bar.get_height()
    ax.text(bar.get_x() + bar.get_width()/2., height + 5,
            f'{int(height)} ({int(height)/500*100:.1f}%)',
            ha='center', va='bottom', fontsize=12, fontweight='bold')

ax.set_title('Primary Hypothesis: IAM Policy Vulnerability Analysis\n500 Real GitHub Policies',
             fontsize=14, fontweight='bold')
ax.set_ylabel('Number of Policies', fontsize=12)
ax.set_ylim(0, 420)
ax.axhline(y=200, color='orange', linestyle='--', linewidth=2, label='40% Threshold (200 policies)')
ax.legend(fontsize=10)
plt.tight_layout()
plt.savefig('../charts/primary_hypothesis.png', dpi=300, bbox_inches='tight')
print("Saved: primary_hypothesis.png")
plt.close()

# ============================================================
# CHART 2: Primary Hypothesis Pie Chart
# ============================================================
fig, ax = plt.subplots(figsize=(8, 8))

sizes = [62.8, 37.2]
labels = ['Vulnerable\n62.8%', 'Safe\n37.2%']
colors = ['#E74C3C', '#2ECC71']
explode = (0.05, 0)

ax.pie(sizes, explode=explode, labels=labels, colors=colors,
       autopct='%1.1f%%', shadow=True, startangle=90,
       textprops={'fontsize': 12, 'fontweight': 'bold'})

ax.set_title('Primary Hypothesis: Vulnerability Distribution\n500 Real GitHub Policies',
             fontsize=14, fontweight='bold', pad=20)
plt.tight_layout()
plt.savefig('../charts/primary_pie_chart.png', dpi=300, bbox_inches='tight')
print("Saved: primary_pie_chart.png")
plt.close()

# ============================================================
# CHART 3: Secondary Hypothesis Bar Chart
# ============================================================
fig, ax = plt.subplots(figsize=(10, 6))

categories = ['Exploitable\n(100% API Success)', 'Partial\nExploitation', 'Not\nExploitable']
values = [309, 0, 0]
colors = ['#E74C3C', '#F39C12', '#2ECC71']

bars = ax.bar(categories, values, color=colors, width=0.5, edgecolor='black')

for bar in bars:
    height = bar.get_height()
    if height > 0:
        ax.text(bar.get_x() + bar.get_width()/2., height + 2,
                f'{int(height)}',
                ha='center', va='bottom', fontsize=12, fontweight='bold')

ax.set_title('Secondary Hypothesis: Exploitation Results\n309 Wildcard Policies Tested',
             fontsize=14, fontweight='bold')
ax.set_ylabel('Number of Policies', fontsize=12)
ax.set_ylim(0, 350)
ax.axhline(y=262, color='orange', linestyle='--', linewidth=2, label='85% Threshold (262 policies)')
ax.legend(fontsize=10)
plt.tight_layout()
plt.savefig('../charts/secondary_hypothesis.png', dpi=300, bbox_inches='tight')
print("Saved: secondary_hypothesis.png")
plt.close()

# ============================================================
# CHART 4: API Success Rate by Service
# ============================================================
fig, ax = plt.subplots(figsize=(10, 6))

services = ['IAM\n(5 APIs)', 'S3\n(4 APIs)', 'EC2\n(4 APIs)', 'STS\n(2 APIs)']
success_rates = [100, 100, 100, 100]
colors = ['#3498DB', '#E74C3C', '#F39C12', '#9B59B6']

bars = ax.bar(services, success_rates, color=colors, width=0.5, edgecolor='black')

for bar in bars:
    height = bar.get_height()
    ax.text(bar.get_x() + bar.get_width()/2., height + 0.5,
            f'{int(height)}%',
            ha='center', va='bottom', fontsize=12, fontweight='bold')

ax.set_title('API Exploitation Success Rate by AWS Service\n15 Total API Calls Per Policy',
             fontsize=14, fontweight='bold')
ax.set_ylabel('Success Rate (%)', fontsize=12)
ax.set_ylim(0, 115)
ax.axhline(y=85, color='red', linestyle='--', linewidth=2, label='85% Threshold')
ax.legend(fontsize=10)
plt.tight_layout()
plt.savefig('../charts/api_success_by_service.png', dpi=300, bbox_inches='tight')
print("Saved: api_success_by_service.png")
plt.close()

# ============================================================
# CHART 5: Combined Research Summary
# ============================================================
fig, axes = plt.subplots(1, 2, figsize=(14, 6))

# Left: Primary Hypothesis
ax1 = axes[0]
categories1 = ['Vulnerable\n(62.8%)', 'Safe\n(37.2%)']
values1 = [314, 186]
colors1 = ['#E74C3C', '#2ECC71']
bars1 = ax1.bar(categories1, values1, color=colors1, width=0.5, edgecolor='black')
ax1.set_title('Primary Hypothesis\nVulnerability Rate: 62.8%', fontsize=13, fontweight='bold')
ax1.set_ylabel('Number of Policies', fontsize=11)
ax1.set_ylim(0, 420)
ax1.axhline(y=200, color='orange', linestyle='--', label='40% Threshold')
ax1.legend(fontsize=9)
for bar in bars1:
    height = bar.get_height()
    ax1.text(bar.get_x() + bar.get_width()/2., height + 3,
             f'{int(height)}', ha='center', va='bottom', fontsize=11, fontweight='bold')

# Right: Secondary Hypothesis
ax2 = axes[1]
categories2 = ['Exploitable\n(100%)', 'Partial\n(0%)', 'Safe\n(0%)']
values2 = [309, 0, 0]
colors2 = ['#E74C3C', '#F39C12', '#2ECC71']
bars2 = ax2.bar(categories2, values2, color=colors2, width=0.5, edgecolor='black')
ax2.set_title('Secondary Hypothesis\nExploitation Rate: 100%', fontsize=13, fontweight='bold')
ax2.set_ylabel('Number of Policies', fontsize=11)
ax2.set_ylim(0, 350)
ax2.axhline(y=262, color='orange', linestyle='--', label='85% Threshold')
ax2.legend(fontsize=9)
for bar in bars2:
    height = bar.get_height()
    if height > 0:
        ax2.text(bar.get_x() + bar.get_width()/2., height + 3,
                 f'{int(height)}', ha='center', va='bottom', fontsize=11, fontweight='bold')

fig.suptitle('Cloud IAM Privilege Escalation Research\nBimal Thanet | CSEC 395 | 2026',
             fontsize=14, fontweight='bold')
plt.tight_layout()
plt.savefig('../charts/combined_summary.png', dpi=300, bbox_inches='tight')
print("Saved: combined_summary.png")
plt.close()

print("\n" + "=" * 60)
print("ALL 5 CHARTS CREATED SUCCESSFULLY!")
print("=" * 60)
print("Location: Week4/charts/")
print("  1. primary_hypothesis.png")
print("  2. primary_pie_chart.png")
print("  3. secondary_hypothesis.png")
print("  4. api_success_by_service.png")
print("  5. combined_summary.png")
print("=" * 60)
