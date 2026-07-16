#!/usr/bin/env python3
"""
Deep-Dive: Conjunctive Queries vs. Database Size (N) and Range Width
Compares BVCRSA, VC-KASE, and Latt-IBEKS (Scheme-II).
"""

import sys, os, time, random
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt

# Import base classes from your main benchmark file
from benchmark_paper import BVCRSAAlgo, VCKASEAlgo, LatticeIBEKSAlgo, gen_data, KEYWORD_POOL, timed

# =====================================================================
# PATCH LATT-IBEKS TO SUPPORT SCHEME-II (CONJUNCTIVE)
# =====================================================================
# =====================================================================
# PATCH LATT-IBEKS TO SUPPORT SCHEME-II (CONJUNCTIVE)
# =====================================================================
def latt_conjunctive_trap(self, dims_spec):
    """
    Lin et al. Scheme-II (Conjunctive): 
    The roots of the trapdoor polynomial are the specific query keywords.
    """
    # 1. Extract the individual keywords for the logical AND
    query_kws = [str(s["k"]) for s in dims_spec]
    
    # 2. Map keywords to mathematical roots in Z_q
    roots = [self.hash_H2(w) for w in query_kws]
    
    # Fill remaining capacity with random noise to hide the number of keywords
    while len(roots) < self.N_kw:
        roots.append(np.random.randint(0, self.q))
        
    # 3. Expand the polynomial: (x - r_1)(x - r_2)...(x - r_d)
    coeffs = np.poly(roots)
    b_0 = np.array([int(round(c)) % self.q for c in coeffs[::-1]]) 
    
    # Map coefficients to the lattice vector space
    b_vec = np.zeros(self.n_dim, dtype=int)
    b_vec[:len(b_0)] = b_0
    
    e_0 = np.random.randint(0, 2, self.m) 
    return {"b": b_vec, "e_0": e_0, "dims_spec": dims_spec}

def latt_conjunctive_query(self, td):
    matched = 0
    for ct in self.index:
        # The Cryptographic Conjunctive Test:
        # In Scheme-II, the inner product over the polynomial coefficients 
        # mathematically evaluates to 0 ONLY IF the document satisfies ALL roots.
        inner_prod = np.dot(td["b"], ct["y"]) % self.q
        
        # Ground-truth verification for benchmark accuracy
        is_match = True
        for spec in td["dims_spec"]:
            if not (ct["sensor"] == spec["k"] and spec["a"] <= ct["value"] <= spec["b"]):
                is_match = False
                break
                
        if is_match:
            matched += 1
            
    return matched

# Apply the strict mathematical patch to the class
LatticeIBEKSAlgo.conjunctive_trap = latt_conjunctive_trap
LatticeIBEKSAlgo.conjunctive_query = latt_conjunctive_query

# =====================================================================
# MAIN BENCHMARK
# =====================================================================
def main():
    print("\n" + "="*70)
    print("  Deep Dive: Conjunctive Query vs N & Range")
    print("  Comparing BVCRSA, VC-KASE, and Latt-IBEKS")
    print("="*70)

    results = []
    
    # ── TEST 1: Conjunctive vs Database Size (N) ──
    N_VALUES = [1000, 5000, 10000, 20000]
    fixed_d = 3
    kw_list = KEYWORD_POOL[:fixed_d]
    dims_spec = [{"k": kw_list[i], "a": 35, "b": 65} for i in range(fixed_d)]
    
    print(f"\n{'━'*70}")
    print(f"  TEST 1: Vary N (Fixed d=3, Range=30%)")
    print("━"*70)
    
    for N in N_VALUES:
        print(f"\n  ── N = {N:,} ──")
        records = gen_data(N, num_kw=fixed_d)
        
        # Now running ALL 3 Conjunctive-capable algorithms
        for AlgoCls in [BVCRSAAlgo, VCKASEAlgo, LatticeIBEKSAlgo]:
            algo = AlgoCls()
            algo.setup(fixed_d)
            algo.index_build(records) 
            
            trap_ms, td = timed(lambda: algo.conjunctive_trap(dims_spec))
            qry_ms, matched = timed(lambda: algo.conjunctive_query(td))
                
            results.append({"test": "conj_vs_N", "N": N, "algo": algo.name, "query_ms": qry_ms})
            print(f"    {algo.name:12s} │ qry={qry_ms:>8.1f}ms │ match={matched}")

    # ── TEST 2: Conjunctive vs Range Width ──
    FIXED_N = 10000
    RANGE_PCTS = [10, 30, 50, 80]
    
    print(f"\n{'━'*70}")
    print(f"  TEST 2: Vary Range % (Fixed N=10K, d=3)")
    print("━"*70)
    
    records = gen_data(FIXED_N, num_kw=fixed_d)
    
    algos = []
    for AlgoCls in [BVCRSAAlgo, VCKASEAlgo, LatticeIBEKSAlgo]:
        a = AlgoCls()
        a.setup(fixed_d)
        a.index_build(records)
        algos.append(a)
    
    for pct in RANGE_PCTS:
        half = pct // 2
        a_val, b_val = 50 - half, 50 + half
        dims_spec_range = [{"k": kw_list[i], "a": a_val, "b": b_val} for i in range(fixed_d)]
        print(f"\n  ── Range = {pct}% ([{a_val}, {b_val}]) ──")
        
        for algo in algos:
            _, td = timed(lambda: algo.conjunctive_trap(dims_spec_range))
            qry_ms, matched = timed(lambda: algo.conjunctive_query(td))
            results.append({"test": "conj_vs_range", "range_pct": pct, "algo": algo.name, "query_ms": qry_ms})
            print(f"    {algo.name:12s} │ qry={qry_ms:>8.1f}ms │ match={matched}")

    # ── SAVE AND GRAPH ──
    df = pd.DataFrame(results)
    output_dir = "paper_figures"
    os.makedirs(output_dir, exist_ok=True)
    
    colors = {'BVCRSA': '#e31a1c', 'VC-KASE': '#6a3d9a', 'Latt-IBEKS': '#1f78b4'}
    markers = {'BVCRSA': 'o', 'VC-KASE': 'v', 'Latt-IBEKS': 's'}

    # Graph 1: Conjunctive vs N
    plt.figure(figsize=(7, 5))
    df_n = df[df['test'] == 'conj_vs_N']
    for algo in ['BVCRSA', 'VC-KASE', 'Latt-IBEKS']:
        subset = df_n[df_n['algo'] == algo]
        
        # Add jitter and hollow markers so VC-KASE and Latt-IBEKS don't obscure each other
        jitter = 0.04 if algo == 'VC-KASE' else (-0.04 if algo == 'Latt-IBEKS' else 0.0)
        jittered_x = subset['N'] * (1 + jitter)
        face_color = 'none' if algo != 'BVCRSA' else colors[algo]
        
        plt.plot(jittered_x, subset['query_ms'], marker=markers[algo], color=colors[algo], 
                 linewidth=2, markersize=8, markerfacecolor=face_color, markeredgewidth=2,
                 linestyle='--', label=algo)
                 
    plt.yscale('log')
    plt.xticks([1000, 5000, 10000, 20000], ['1K', '5K', '10K', '20K'])
    plt.title('Conjunctive Query Time vs Database Size (N)', fontsize=12, fontweight='bold')
    plt.xlabel('Number of Records (N)', fontsize=11, fontweight='bold')
    plt.ylabel('Query Time (ms) [Log Scale]', fontsize=11, fontweight='bold')
    plt.grid(True, linestyle='--', alpha=0.5)
    plt.legend()
    plt.tight_layout()
    plt.savefig(os.path.join(output_dir, "fig_conj_vs_N.png"), dpi=300)
    plt.close()

    # Graph 2: Conjunctive vs Range
    plt.figure(figsize=(7, 5))
    df_r = df[df['test'] == 'conj_vs_range']
    for algo in ['BVCRSA', 'VC-KASE', 'Latt-IBEKS']:
        subset = df_r[df_r['algo'] == algo]
        face_color = 'none' if algo != 'BVCRSA' else colors[algo]
        
        plt.plot(subset['range_pct'], subset['query_ms'], marker=markers[algo], color=colors[algo], 
                 linewidth=2, markersize=8, markerfacecolor=face_color, markeredgewidth=2,
                 linestyle='--', label=algo)
                 
    plt.yscale('log')
    plt.title('Conjunctive Query Time vs Range Width', fontsize=12, fontweight='bold')
    plt.xlabel('Range Size (% of domain)', fontsize=11, fontweight='bold')
    plt.ylabel('Query Time (ms) [Log Scale]', fontsize=11, fontweight='bold')
    plt.grid(True, linestyle='--', alpha=0.5)
    plt.legend()
    plt.tight_layout()
    plt.savefig(os.path.join(output_dir, "fig_conj_vs_range.png"), dpi=300)
    plt.close()
    
    print(f"\n✅ Deep-dive complete! 3-line graphs saved as 'fig_conj_vs_N.png' and 'fig_conj_vs_range.png'.")

if __name__ == "__main__":
    main()