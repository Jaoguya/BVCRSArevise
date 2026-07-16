#!/usr/bin/env python3
import time
import random
import os
import matplotlib.pyplot as plt
from ec_elgamal import generate_ec_elgamal_keypair

def timed(fn, runs=3):
    results = []
    for _ in range(runs):
        t0 = time.perf_counter()
        fn()
        results.append((time.perf_counter() - t0) * 1000)
    return sum(results) / len(results)

def main():
    print("\n" + "="*70)
    print("  Ablation Study: Aggregate vs. Non-Aggregate BVCRSA")
    print("="*70)

    # 1. Setup EC-ElGamal keys
    print("  [Setting up Elliptic Curve keys...]")
    ec_pub, ec_priv = generate_ec_elgamal_keypair()
    
    BQ_VALUES = [10, 50, 100, 200, 500]
    
    agg_times = []
    non_agg_times = []

    for bq in BQ_VALUES:
        print(f"\n  ── |BQ| = {bq} ──")
        
        # Simulate BQ matching sensor readings
        plaintexts = [random.randint(0, 100) for _ in range(bq)]
        cts = [ec_pub.encrypt(pt) for pt in plaintexts]

        # ==========================================
        # METHOD 1: Aggregate BVCRSA (Cloud + User)
        # ==========================================
        def aggregate_method():
            # Server side: Homomorphic Addition
            agg_ct = cts[0]
            for ct in cts[1:]:
                agg_ct = agg_ct + ct
            
            # User side: Single Decryption
            _ = ec_priv.decrypt(agg_ct)

        time_agg = timed(aggregate_method)
        agg_times.append(time_agg)
        print(f"    Aggregate (Server Add + 1 Decrypt)  : {time_agg:>8.2f} ms")

        # ==========================================
        # METHOD 2: Non-Aggregate BVCRSA (User Only)
        # ==========================================
        def non_aggregate_method():
            # Server side does nothing. 
            # User side: BQ individual decryptions
            total = 0
            for ct in cts:
                total += ec_priv.decrypt(ct)

        time_non_agg = timed(non_aggregate_method)
        non_agg_times.append(time_non_agg)
        print(f"    Non-Aggregate (BQ Decrypts)         : {time_non_agg:>8.2f} ms")

    # ==========================================
    # Generate the Ablation Graph
    # ==========================================
    output_dir = "paper_figures"
    os.makedirs(output_dir, exist_ok=True)
    
    plt.figure(figsize=(7, 5))
    
    # Plot Non-Aggregate (The slow baseline)
    plt.plot(BQ_VALUES, non_agg_times, marker='s', color='#1f78b4', 
             linewidth=2, markersize=8, linestyle='--', label='Naive BVCRSA (No Aggregation)')
    
    # Plot Aggregate (Your fast framework)
    plt.plot(BQ_VALUES, agg_times, marker='o', color='#e31a1c', 
             linewidth=2, markersize=8, linestyle='-', label='BVCRSA (With Homomorphic Aggregation)')

    plt.title('Ablation Study: Impact of Homomorphic Aggregation', fontsize=12, fontweight='bold')
    plt.xlabel('Number of Matched Nodes |BQ|', fontsize=11, fontweight='bold')
    plt.ylabel('Total Processing Time (ms)', fontsize=11, fontweight='bold')
    plt.grid(True, linestyle='--', alpha=0.5)
    plt.legend()
    plt.tight_layout()
    
    save_path = os.path.join(output_dir, "fig_ablation_aggregation.png")
    plt.savefig(save_path, dpi=300, bbox_inches='tight')
    plt.close()
    
    print(f"\n✅ Ablation graph successfully saved to '{save_path}'!")

if __name__ == "__main__":
    main()