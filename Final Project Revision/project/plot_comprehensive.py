#!/usr/bin/env python3
"""
Plot 6 IEEE-styled 2D graphs from the comprehensive benchmark CSVs.
"""
import csv
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import matplotlib.ticker as ticker
import numpy as np

plt.rcParams.update({
    'font.family': 'serif', 'font.size': 11,
    'axes.labelsize': 13, 'axes.titlesize': 14,
    'legend.fontsize': 9, 'xtick.labelsize': 10, 'ytick.labelsize': 10,
    'figure.dpi': 150, 'savefig.dpi': 300, 'savefig.bbox': 'tight',
    'axes.grid': True, 'grid.alpha': 0.3, 'grid.linestyle': '--',
})

ALGOS = {
    "AC-SCRAT":   {"color": "#E74C3C", "marker": "o", "ls": "-"},
    "EPBRQ":      {"color": "#3498DB", "marker": "s", "ls": "-"},
    "EPRQ+":      {"color": "#2ECC71", "marker": "^", "ls": "-"},
    "Trinity-I":  {"color": "#9B59B6", "marker": "D", "ls": "-"},
    "Trinity-II": {"color": "#F39C12", "marker": "v", "ls": "-"},
    "MHRQ":       {"color": "#1ABC9C", "marker": "P", "ls": "-"},
}
ALGO_ORDER = list(ALGOS.keys())


def load_csv(filename, x_key):
    """Load CSV → {algo: {x_vals, trap, query, total, index}}"""
    data = {a: {"x": [], "trap": [], "query": [], "total": [], "index": []} for a in ALGO_ORDER}
    with open(filename) as f:
        reader = csv.DictReader(f)
        for row in reader:
            x_val = float(row[x_key])
            for algo in ALGO_ORDER:
                data[algo]["x"].append(x_val)
                data[algo]["trap"].append(float(row.get(f"{algo}_trap_ms", 0) or 0))
                data[algo]["query"].append(float(row.get(f"{algo}_query_ms", 0) or 0))
                data[algo]["total"].append(float(row.get(f"{algo}_total_ms", 0) or 0))
                idx_key = f"{algo}_index_ms"
                data[algo]["index"].append(float(row.get(idx_key, 0) or 0))
    return data


def plot_2d(data, metric, xlabel, ylabel, title, filename, log_y=False):
    fig, ax = plt.subplots(figsize=(8, 5))
    for algo, cfg in ALGOS.items():
        x = data[algo]["x"]
        y = data[algo][metric]
        valid = [(xv, yv) for xv, yv in zip(x, y) if yv > 0]
        if valid:
            xs, ys = zip(*valid)
            ax.plot(xs, ys, color=cfg["color"], marker=cfg["marker"],
                    linestyle=cfg["ls"], linewidth=2.2, markersize=8,
                    label=algo, markeredgecolor='white', markeredgewidth=0.8)
    ax.set_xlabel(xlabel)
    ax.set_ylabel(ylabel)
    ax.set_title(title, fontweight='bold', pad=12)
    if log_y:
        ax.set_yscale('log')
    ax.legend(loc='best', framealpha=0.9, edgecolor='gray', fancybox=True)
    ax.set_facecolor('#FAFAFA')
    fig.patch.set_facecolor('white')
    if data[ALGO_ORDER[0]]["x"]:
        ax.set_xticks(data[ALGO_ORDER[0]]["x"])
    plt.tight_layout()
    plt.savefig(filename)
    plt.close()
    print(f"  ✓ {filename}")


def main():
    print("\n  Generating 6 comparison graphs...\n")

    # Load all 3 dimension CSVs
    d1 = load_csv("bench_dim1_vs_N.csv", "N")
    d2 = load_csv("bench_dim2_vs_range.csv", "range_pct")
    d3 = load_csv("bench_dim3_vs_keywords.csv", "keywords")

    # ── Graph 2: Trapdoor Gen vs N Records ───────────────────────────
    plot_2d(d1, "trap",
            "Number of Records (N)", "Trapdoor Generation Time (ms)",
            "Fig. 2: Trapdoor Generation Time vs Database Size",
            "fig2_trap_vs_N.png", log_y=True)

    # ── Graph 3: Trapdoor Gen vs Range Size (%) ──────────────────────
    plot_2d(d2, "trap",
            "Range Query Size (% of domain)", "Trapdoor Generation Time (ms)",
            "Fig. 3: Trapdoor Generation Time vs Range Size",
            "fig3_trap_vs_range.png", log_y=True)

    # ── Graph 4: Trapdoor Gen vs Number of Keywords ──────────────────
    plot_2d(d3, "trap",
            "Number of Keywords", "Trapdoor Generation Time (ms)",
            "Fig. 4: Trapdoor Generation Time vs Number of Keywords",
            "fig4_trap_vs_keywords.png", log_y=True)

    # ── Graph 5: Query Processing Time vs N Records ──────────────────
    plot_2d(d1, "query",
            "Number of Records (N)", "Query Processing Time (ms)",
            "Fig. 5: Query Processing Time vs Database Size",
            "fig5_query_vs_N.png", log_y=True)

    # ── Graph 6: Query Processing Time vs Range Size (%) ─────────────
    plot_2d(d2, "query",
            "Range Query Size (% of domain)", "Query Processing Time (ms)",
            "Fig. 6: Query Processing Time vs Range Size",
            "fig6_query_vs_range.png", log_y=True)

    # ── Graph 7: Index Generation Time vs N Records ──────────────────
    plot_2d(d1, "index",
            "Number of Records (N)", "Index Generation Time (ms)",
            "Fig. 7: Index Generation Time vs Database Size",
            "fig7_index_vs_N.png", log_y=True)

    print("\n  ✅ All 6 graphs generated!")


if __name__ == "__main__":
    main()
