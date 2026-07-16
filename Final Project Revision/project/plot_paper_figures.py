#!/usr/bin/env python3
"""
Plot All Benchmark Figures from benchmark_paper_results.csv
IEEE-style publication-quality graphs for BVCRSA paper Section V.
"""
import csv, os
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import numpy as np

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CSV = os.path.join(BASE_DIR, "benchmark_paper_results.csv")
OUT = os.path.join(BASE_DIR, "paper_figures")
os.makedirs(OUT, exist_ok=True)

# ── Read CSV ──
rows = []
with open(CSV) as f:
    for r in csv.DictReader(f):
        rows.append(r)

# ── Style ──
plt.rcParams.update({
    'font.family': 'serif', 'font.size': 13, 'axes.linewidth': 1.2,
    'figure.facecolor': 'white', 'axes.facecolor': '#f9f9f9',
    'axes.grid': True, 'grid.alpha': 0.3, 'grid.linestyle': '--',
})
COLORS = {
    'BVCRSA': '#E53935', 'MHRQ': '#1E88E5', 'Trinity': '#43A047',
    'ABSE-Range': '#FB8C00', 'ECGRQ': '#8E24AA',
}
MARKERS = {
    'BVCRSA': 'o', 'MHRQ': 's', 'Trinity': '^',
    'ABSE-Range': 'D', 'ECGRQ': 'v',
}
ALGOS = ['BVCRSA', 'MHRQ', 'Trinity', 'ABSE-Range', 'ECGRQ']

def get(dim, xfield, metric):
    """Extract {algo: ([x], [y])} for given dimension."""
    data = {}
    for r in rows:
        if r['dim'] != dim:
            continue
        algo = r['algo']
        x = r.get(xfield, '')
        y = r.get(metric, '')
        if not x or not y:
            continue
        if algo not in data:
            data[algo] = ([], [])
        data[algo][0].append(float(x))
        data[algo][1].append(float(y))
    return data

def plot(dim, xfield, metric, xlabel, ylabel, title, fname, algos=None, logy=False):
    fig, ax = plt.subplots(figsize=(10, 6))
    data = get(dim, xfield, metric)
    for algo in (algos or ALGOS):
        if algo not in data:
            continue
        xs, ys = data[algo]
        ax.plot(xs, ys, color=COLORS[algo], marker=MARKERS[algo],
                label=algo, linewidth=2.5, markersize=10,
                markeredgecolor='white', markeredgewidth=1.5, linestyle='--')
    ax.set_xlabel(xlabel, fontsize=14, fontweight='bold')
    ax.set_ylabel(ylabel, fontsize=14, fontweight='bold')
    ax.set_title(title, fontsize=15, fontweight='bold')
    ax.legend(fontsize=11, framealpha=0.9, edgecolor='#ccc')
    if logy:
        ax.set_yscale('log')
    plt.tight_layout()
    path = os.path.join(OUT, fname)
    plt.savefig(path, dpi=200, bbox_inches='tight')
    plt.close()
    print(f"  ✓ {fname}")

print(f"\nGenerating figures → {OUT}/\n")

# ── Fig 1: Index Construction Time vs N ──
plot("vs_N", "N", "index_ms",
     "Number of Records (N)", "Index Construction Time (ms)",
     "Fig. 1: Index Construction Time vs Database Size",
     "fig1_index_vs_N.png", logy=True)

# ── Fig 2: Trapdoor Generation Time vs N ──
plot("vs_N", "N", "trap_ms",
     "Number of Records (N)", "Trapdoor Generation Time (ms)",
     "Fig. 2: Trapdoor Generation Time vs Database Size",
     "fig2_trap_vs_N.png", logy=True)

# ── Fig 3: Query Processing Time vs N ──
plot("vs_N", "N", "query_ms",
     "Number of Records (N)", "Query Processing Time (ms)",
     "Fig. 3: Query Processing Time vs Database Size",
     "fig3_query_vs_N.png", logy=True)

# ── Fig 4: Trapdoor Generation Time vs Range % ──
plot("vs_range", "range_pct", "trap_ms",
     "Range Size (% of domain)", "Trapdoor Generation Time (ms)",
     "Fig. 4: Trapdoor Generation Time vs Range Width",
     "fig4_trap_vs_range.png", logy=True)

# ── Fig 5: Query Processing Time vs Range % ──
plot("vs_range", "range_pct", "query_ms",
     "Range Size (% of domain)", "Query Processing Time (ms)",
     "Fig. 5: Query Processing Time vs Range Width",
     "fig5_query_vs_range.png", logy=True)

# ── Fig 6: Conjunctive Query Time vs d ──
plot("vs_d", "d", "query_ms",
     "Number of Conjunctive Dimensions (d)", "Query Processing Time (ms)",
     "Fig. 6: Conjunctive Query Time vs Dimensions",
     "fig6_conj_vs_d.png", algos=['BVCRSA', 'ECGRQ'])

# ── Fig 7: Aggregation Time vs |B_Q| ──
plot("vs_BQ", "BQ", "agg_ms",
     "Number of Matched Nodes |B_Q|", "Aggregation Time (ms)",
     "Fig. 7: EC-ElGamal Aggregation Time vs |B_Q|",
     "fig7_agg_vs_BQ.png", algos=['BVCRSA'])

# ── Fig 8: Verification Time vs |U*_Q| ──
plot("vs_UQ", "UQ", "verify_ms",
     "Number of Result Nodes |U*_Q|", "Verification Time (ms)",
     "Fig. 8: Merkle Verification Time vs |U*_Q|",
     "fig8_verify_vs_UQ.png", algos=['BVCRSA'])

# ── Fig 9: Skewed Distribution ──
# Compare skewed vs uniform for BVCRSA
fig, ax = plt.subplots(figsize=(10, 6))
# Uniform
uniform = get("vs_N", "N", "query_ms").get("BVCRSA", ([], []))
# Skewed
skewed = get("skewed", "N", "query_ms").get("BVCRSA", ([], []))
# Only plot matching N values
if uniform[0] and skewed[0]:
    ax.plot(uniform[0][:len(skewed[0])], uniform[1][:len(skewed[0])],
            color='#E53935', marker='o', label='BVCRSA (Uniform)',
            linewidth=2.5, markersize=10, markeredgecolor='white',
            markeredgewidth=1.5, linestyle='--')
    ax.plot(skewed[0], skewed[1],
            color='#1E88E5', marker='s', label='BVCRSA (Skewed N(70,10))',
            linewidth=2.5, markersize=10, markeredgecolor='white',
            markeredgewidth=1.5, linestyle='--')
ax.set_xlabel("Number of Records (N)", fontsize=14, fontweight='bold')
ax.set_ylabel("Query Processing Time (ms)", fontsize=14, fontweight='bold')
ax.set_title("Fig. 9: Robustness — Uniform vs Skewed N(70,10)", fontsize=15, fontweight='bold')
ax.legend(fontsize=12, framealpha=0.9, edgecolor='#ccc')
ax.grid(True, alpha=0.3, linestyle='--')
plt.tight_layout()
plt.savefig(os.path.join(OUT, "fig9_skewed_robustness.png"), dpi=200, bbox_inches='tight')
plt.close()
print("  ✓ fig9_skewed_robustness.png")

print(f"\n✅ All 9 figures saved to {OUT}/")
