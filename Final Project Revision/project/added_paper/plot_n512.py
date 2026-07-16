#!/usr/bin/env python3
"""
Plot n512 benchmark results — AC-SCRAT, ABSE-Range, IBE-Lattice
Reads: n512_bench_dim1_vs_N.csv, n512_bench_dim2_vs_range.csv, n512_bench_dim3_vs_keywords.csv
Produces 6 IEEE-styled graphs.
"""

import csv, os
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import numpy as np

plt.rcParams.update({
    'font.family': 'serif', 'font.size': 11,
    'axes.labelsize': 13, 'axes.titlesize': 14,
    'legend.fontsize': 9, 'xtick.labelsize': 10, 'ytick.labelsize': 10,
    'figure.dpi': 150, 'savefig.dpi': 300, 'savefig.bbox': 'tight',
    'axes.grid': True, 'grid.alpha': 0.3, 'grid.linestyle': '--',
})

ALGOS = {
    "AC-SCRAT":    {"color": "#E74C3C", "marker": "o", "ls": "-",  "lw": 2.8, "ms": 9},
    "ABSE-Range":  {"color": "#E67E22", "marker": "X", "ls": "--", "lw": 2.2, "ms": 8},
    "IBE-Lattice": {"color": "#8E44AD", "marker": "h", "ls": "--", "lw": 2.2, "ms": 8},
}
ALGO_ORDER = ["AC-SCRAT", "ABSE-Range", "IBE-Lattice"]

DIR = os.path.dirname(os.path.abspath(__file__))


def load_csv(filepath, x_key):
    data = {a: {"x": [], "trap": [], "query": [], "total": [], "index": []} for a in ALGO_ORDER}
    if not os.path.exists(filepath):
        print(f"  ⚠ Missing: {filepath}")
        return data
    with open(filepath) as f:
        reader = csv.DictReader(f)
        for row in reader:
            x_val = float(row[x_key])
            for algo in ALGO_ORDER:
                tk = f"{algo}_trap_ms"
                if tk not in row:
                    continue
                data[algo]["x"].append(x_val)
                data[algo]["trap"].append(float(row.get(f"{algo}_trap_ms", 0) or 0))
                data[algo]["query"].append(float(row.get(f"{algo}_query_ms", 0) or 0))
                data[algo]["total"].append(float(row.get(f"{algo}_total_ms", 0) or 0))
                data[algo]["index"].append(float(row.get(f"{algo}_index_ms", 0) or 0))
    return data


def plot_graph(data, metric, xlabel, ylabel, title, filename, log_y=True):
    fig, ax = plt.subplots(figsize=(9, 5.5))

    for algo in ALGO_ORDER:
        if not data[algo]["x"]:
            continue
        cfg = ALGOS[algo]
        x = data[algo]["x"]
        y = data[algo][metric]
        valid = [(xv, yv) for xv, yv in zip(x, y) if yv > 0]
        if valid:
            xs, ys = zip(*valid)
            ax.plot(xs, ys, color=cfg["color"], marker=cfg["marker"],
                    linestyle=cfg["ls"], linewidth=cfg["lw"],
                    markersize=cfg["ms"], label=algo,
                    markeredgecolor='white', markeredgewidth=0.8)

    ax.set_xlabel(xlabel)
    ax.set_ylabel(ylabel)
    ax.set_title(title, fontweight='bold', pad=12)
    if log_y:
        ax.set_yscale('log')
    ax.legend(loc='best', framealpha=0.9, edgecolor='gray', fancybox=True)
    ax.set_facecolor('#FAFAFA')
    fig.patch.set_facecolor('white')

    for algo in ALGO_ORDER:
        if data[algo]["x"]:
            ax.set_xticks(data[algo]["x"])
            break

    plt.tight_layout()
    outpath = os.path.join(DIR, filename)
    plt.savefig(outpath)
    plt.close()
    print(f"  ✓ Saved: {outpath}")


def main():
    print("\n  Plotting n512 benchmark results...\n")

    d1 = load_csv(os.path.join(DIR, "n512_bench_dim1_vs_N.csv"), "N")
    d2 = load_csv(os.path.join(DIR, "n512_bench_dim2_vs_range.csv"), "range_pct")
    d3 = load_csv(os.path.join(DIR, "n512_bench_dim3_vs_keywords.csv"), "keywords")

    # Fig 1: Trapdoor Gen vs N
    plot_graph(d1, "trap",
               "Number of Records (N)", "Trapdoor Generation Time (ms)",
               "Trapdoor Generation Time vs Database Size (n=512)",
               "n512_fig1_trap_vs_N.png")

    # Fig 2: Trapdoor Gen vs Range %
    plot_graph(d2, "trap",
               "Range Query Size (% of domain)", "Trapdoor Generation Time (ms)",
               "Trapdoor Generation Time vs Range Size (n=512)",
               "n512_fig2_trap_vs_range.png")

    # Fig 3: Trapdoor Gen vs Keywords
    plot_graph(d3, "trap",
               "Number of Keywords", "Trapdoor Generation Time (ms)",
               "Trapdoor Generation Time vs Number of Keywords (n=512)",
               "n512_fig3_trap_vs_keywords.png")

    # Fig 4: Query Time vs N
    plot_graph(d1, "query",
               "Number of Records (N)", "Query Processing Time (ms)",
               "Query Processing Time vs Database Size (n=512)",
               "n512_fig4_query_vs_N.png")

    # Fig 5: Query Time vs Range %
    plot_graph(d2, "query",
               "Range Query Size (% of domain)", "Query Processing Time (ms)",
               "Query Processing Time vs Range Size (n=512)",
               "n512_fig5_query_vs_range.png")

    # Fig 6: Index Gen vs N
    plot_graph(d1, "index",
               "Number of Records (N)", "Index Generation Time (ms)",
               "Index Generation Time vs Database Size (n=512)",
               "n512_fig6_index_vs_N.png")

    # Fig 7: Index Gen vs Keywords
    plot_graph(d3, "index",
               "Number of Keywords", "Index Generation Time (ms)",
               "Index Generation Time vs Number of Keywords (n=512)",
               "n512_fig7_index_vs_keywords.png")

    print("\n  ✅ All 7 n512 graphs generated!")


if __name__ == "__main__":
    main()
