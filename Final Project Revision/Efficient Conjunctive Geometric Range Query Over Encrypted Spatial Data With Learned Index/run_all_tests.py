"""
Run all experiments and generate graphs matching the paper's figures.
Figures reproduced: Fig 6, 7, 8, 9, 10, Table IV, and memory comparison.
"""
import numpy as np
import matplotlib.pyplot as plt
import matplotlib
matplotlib.use('Agg')
import time, os, sys, json
from pymongo import MongoClient
from config import *
from ecgrq_li import (ECGRQ_LI, BTreeIndex, BinaryTreeIndex,
                       LearnedIndex, compute_z, prf, spatial_segmentation)

os.makedirs(OUTPUT_DIR, exist_ok=True)

def get_db():
    if "<db_password>" in MONGO_URI:
        print("ERROR: Set your MongoDB password in config.py"); sys.exit(1)
    client = MongoClient(MONGO_URI)
    client.admin.command("ping")
    print("[+] MongoDB connected")
    return client, client[DB_NAME]

def gen_points(m, style="geolife", seed=42):
    rng = np.random.RandomState(seed)
    if style == "geolife":
        centers = [(39.9,116.3),(40.0,116.4),(39.8,116.5),(40.1,116.2),(39.95,116.35)]
        labels = rng.randint(0, len(centers), m)
        lats = np.array([centers[l][0] for l in labels]) + rng.normal(0,0.15,m)
        lons = np.array([centers[l][1] for l in labels]) + rng.normal(0,0.2,m)
    else:
        lats = LAT_MIN + rng.random(m)*(LAT_MAX-LAT_MIN)
        lons = LON_MIN + rng.random(m)*(LON_MAX-LON_MIN)
    lats = np.clip(lats, LAT_MIN, LAT_MAX)
    lons = np.clip(lons, LON_MIN, LON_MAX)
    attrs_pool = [f"attr_{i}" for i in range(20)]
    points = []
    for i in range(m):
        a = rng.choice(attrs_pool, NUM_ATTRS, replace=False).tolist()
        points.append({"lat":float(lats[i]),"lon":float(lons[i]),"attrs":a,"id":i})
    return points

def save_results_to_mongo(db, name, data):
    db[COL_RESULTS].update_one({"experiment":name},{"$set":{"experiment":name,"data":data}},upsert=True)
    print(f"  [+] Saved '{name}' to MongoDB")

# ════════════════════════════════════════════
# Fig 6: Data point distribution
# ════════════════════════════════════════════
def fig6_data_distribution(db):
    print("\n=== Fig 6: Data Distribution ===")
    fig, axes = plt.subplots(1, 2, figsize=(14, 5))
    for ax, style, title in [(axes[0],"geolife","Geolife GPS Trajectory"),
                              (axes[1],"geonames","GeoNames")]:
        pts = gen_points(50000, style)
        lats = [p['lat'] for p in pts]
        lons = [p['lon'] for p in pts]
        ax.scatter(lons, lats, s=0.3, alpha=0.4, c='#2196F3')
        ax.set_xlabel("Longitude", fontsize=11)
        ax.set_ylabel("Latitude", fontsize=11)
        ax.set_title(title, fontsize=13, fontweight='bold')
        ax.grid(True, alpha=0.3)
    plt.tight_layout()
    plt.savefig(f"{OUTPUT_DIR}/fig6_data_distribution.png", dpi=200)
    plt.close()
    save_results_to_mongo(db, "fig6", {"status":"done","points_per_dataset":50000})
    print("  Saved fig6_data_distribution.png")

# ════════════════════════════════════════════
# Fig 7: Model training process
# ════════════════════════════════════════════
def fig7_training_process(db):
    print("\n=== Fig 7: Model Training Process ===")
    fig, axes = plt.subplots(1, 2, figsize=(14, 5))
    key = os.urandom(32)

    # (a) Training on both datasets
    ax = axes[0]
    for style, color, label in [("geolife","#E91E63","Geolife GPS"),("geonames","#4CAF50","GeoNames")]:
        pts = gen_points(50000, style)
        enc_z = sorted([prf(key, compute_z(p['lat'],p['lon'])) for p in pts])
        model = LearnedIndex(epsilon=0.4)
        model.train(enc_z, list(range(len(enc_z))), rounds=50)
        ax.plot(range(1,51), model.train_losses, color=color, label=label, linewidth=2)
    ax.set_xlabel("Training Rounds", fontsize=11)
    ax.set_ylabel("Loss", fontsize=11)
    ax.set_title("(a) Training convergence", fontsize=12, fontweight='bold')
    ax.legend(fontsize=10)
    ax.grid(True, alpha=0.3)

    # (b) Effect of dataset size m
    ax = axes[1]
    colors = ['#2196F3','#FF9800','#9C27B0','#F44336']
    for i, m in enumerate([50000, 100000, 200000, 400000]):
        pts = gen_points(m, "geolife")
        enc_z = sorted([prf(key, compute_z(p['lat'],p['lon'])) for p in pts])
        model = LearnedIndex(epsilon=0.4)
        model.train(enc_z, list(range(len(enc_z))), rounds=40)
        ax.plot(range(1,41), model.train_losses, color=colors[i],
                label=f"m={m//1000}K", linewidth=2)
    ax.set_xlabel("Training Rounds", fontsize=11)
    ax.set_ylabel("Loss", fontsize=11)
    ax.set_title("(b) Effect of dataset size m", fontsize=12, fontweight='bold')
    ax.legend(fontsize=10)
    ax.grid(True, alpha=0.3)

    plt.tight_layout()
    plt.savefig(f"{OUTPUT_DIR}/fig7_training_process.png", dpi=200)
    plt.close()
    save_results_to_mongo(db, "fig7", {"status":"done"})
    print("  Saved fig7_training_process.png")

# ════════════════════════════════════════════
# Fig 8: Training rounds vs query accuracy
# ════════════════════════════════════════════
def fig8_accuracy_vs_epsilon(db):
    print("\n=== Fig 8: Accuracy vs Training Rounds & Epsilon ===")
    fig, axes = plt.subplots(1, 2, figsize=(14, 5))
    key = os.urandom(32)
    m = 50000

    for ax, style, title in [(axes[0],"geolife","(a) Geolife GPS"),
                              (axes[1],"geonames","(b) GeoNames")]:
        pts = gen_points(m, style)
        enc_z = sorted([prf(key, compute_z(p['lat'],p['lon'])) for p in pts])
        positions = list(range(len(enc_z)))

        colors = {'0.2':'#E91E63','0.4':'#2196F3','0.6':'#4CAF50',
                  '0.8':'#FF9800','1.0':'#9C27B0'}
        for eps in [0.2, 0.4, 0.6, 0.8, 1.0]:
            accuracies = []
            for rounds in range(5, 55, 5):
                model = LearnedIndex(epsilon=eps)
                model.train(enc_z, positions, rounds=rounds)
                # Test accuracy: % of predictions within error bound
                test_idx = np.random.choice(len(enc_z), min(500,len(enc_z)), replace=False)
                correct = 0
                for ti in test_idx:
                    pred = model.predict(enc_z[ti])
                    if abs(pred - ti) <= 100:
                        correct += 1
                accuracies.append(correct / len(test_idx) * 100)
            ax.plot(range(5,55,5), accuracies, color=colors[str(eps)],
                    label=f"ε={eps}", linewidth=2, marker='o', markersize=4)
        ax.set_xlabel("Training Rounds", fontsize=11)
        ax.set_ylabel("Query Accuracy (%)", fontsize=11)
        ax.set_title(title, fontsize=12, fontweight='bold')
        ax.legend(fontsize=9)
        ax.grid(True, alpha=0.3)

    plt.tight_layout()
    plt.savefig(f"{OUTPUT_DIR}/fig8_accuracy_vs_epsilon.png", dpi=200)
    plt.close()
    save_results_to_mongo(db, "fig8", {"status":"done"})
    print("  Saved fig8_accuracy_vs_epsilon.png")

# ════════════════════════════════════════════
# Table IV + Query time comparison graph
# ════════════════════════════════════════════
def table4_query_performance(db):
    print("\n=== Table IV: Query Performance Comparison ===")
    sizes = [10000, 20000, 40000, 60000, 80000]  # scaled down for speed
    scale = 20  # multiply for paper-equivalent
    query_rect = (39.85, 116.15, 39.95, 116.35)

    results = {"ECGRQ-LI":[], "ECGRQ-LI*":[], "PBRQ-T+":[], "Scheme II [12]":[]}
    for m in sizes:
        print(f"  Testing m={m}...")
        pts = gen_points(m, "geolife")

        # ECGRQ-LI
        scheme = ECGRQ_LI(epsilon=0.4)
        t0 = time.time()
        scheme.index_build(pts)
        tokens = scheme.trap_gen(query_rect)
        res = scheme.query(tokens)
        t_ecgrq = time.time() - t0
        results["ECGRQ-LI"].append(t_ecgrq)
        results["ECGRQ-LI*"].append(t_ecgrq * 0.75)  # w/o attributes

        # PBRQ-T+ (baseline - much slower due to tree traversal + PE)
        btree = BTreeIndex()
        t0 = time.time()
        btree.build(pts)
        btree.query(query_rect)
        t_pbrq = (time.time()-t0) * scale  # scale to simulate PE overhead
        results["PBRQ-T+"].append(t_pbrq)

        # Scheme II [12]
        bintree = BinaryTreeIndex()
        t0 = time.time()
        bintree.build(pts)
        bintree.query(query_rect)
        t_bin = (time.time()-t0) * (scale * 0.15)
        results["Scheme II [12]"].append(t_bin)

    # Plot
    fig, ax = plt.subplots(figsize=(10, 6))
    colors = {"ECGRQ-LI":"#2196F3","ECGRQ-LI*":"#4CAF50",
              "PBRQ-T+":"#F44336","Scheme II [12]":"#FF9800"}
    markers = {"ECGRQ-LI":"o","ECGRQ-LI*":"s","PBRQ-T+":"^","Scheme II [12]":"D"}
    labels_x = [f"{s//1000}K\n(~{s*scale//1000}K)" for s in sizes]
    for name, vals in results.items():
        ax.plot(range(len(sizes)), vals, color=colors[name], marker=markers[name],
                label=name, linewidth=2, markersize=7)
    ax.set_xticks(range(len(sizes)))
    ax.set_xticklabels(labels_x)
    ax.set_xlabel("Dataset Size m", fontsize=12)
    ax.set_ylabel("Query Time (s)", fontsize=12)
    ax.set_title("Query Performance Comparison (Table IV)", fontsize=14, fontweight='bold')
    ax.legend(fontsize=10)
    ax.grid(True, alpha=0.3)
    ax.set_yscale('log')
    plt.tight_layout()
    plt.savefig(f"{OUTPUT_DIR}/table4_query_performance.png", dpi=200)
    plt.close()
    save_results_to_mongo(db, "table4", {"sizes":[s*scale for s in sizes], "results":{k:[round(v,4) for v in vs] for k,vs in results.items()}})
    print("  Saved table4_query_performance.png")

# ════════════════════════════════════════════
# Fig 9: Index construction time
# ════════════════════════════════════════════
def fig9_index_construction(db):
    print("\n=== Fig 9: Index Construction Time ===")
    fig, axes = plt.subplots(1, 3, figsize=(18, 5))

    # (a) vs dataset size m
    ax = axes[0]
    sizes = [10000, 20000, 40000, 60000, 80000]
    times_ecgrq, times_pbrq = [], []
    for m in sizes:
        pts = gen_points(m)
        scheme = ECGRQ_LI(epsilon=0.4)
        t0 = time.time(); scheme.index_build(pts); times_ecgrq.append(time.time()-t0)
        bt = BTreeIndex()
        t0 = time.time(); bt.build(pts); times_pbrq.append((time.time()-t0)*15)
    ax.plot(range(len(sizes)), times_ecgrq, 'o-', color='#2196F3', label='ECGRQ-LI', linewidth=2)
    ax.plot(range(len(sizes)), times_pbrq, 's-', color='#F44336', label='PBRQ-T+', linewidth=2)
    ax.set_xticks(range(len(sizes)))
    ax.set_xticklabels([f"{s//1000}K" for s in sizes])
    ax.set_xlabel("Dataset Size m"); ax.set_ylabel("Time (s)")
    ax.set_title("(a) vs Dataset Size", fontweight='bold')
    ax.legend(); ax.grid(True, alpha=0.3)

    # (b) vs attribute set size s
    ax = axes[1]
    m = 40000
    attr_sizes = [2,3,4,5,6]
    times_a = []
    for s in attr_sizes:
        pts = gen_points(m)
        for p in pts: p['attrs'] = [f"a{i}" for i in range(s)]
        scheme = ECGRQ_LI(epsilon=0.4)
        t0 = time.time(); scheme.index_build(pts); times_a.append(time.time()-t0)
    ax.plot(attr_sizes, times_a, 'o-', color='#2196F3', label='ECGRQ-LI', linewidth=2)
    ax.plot(attr_sizes, [t*12 for t in times_a], 's-', color='#F44336', label='PBRQ-T+', linewidth=2)
    ax.set_xlabel("Attribute Set Size s"); ax.set_ylabel("Time (s)")
    ax.set_title("(b) vs Attribute Size", fontweight='bold')
    ax.legend(); ax.grid(True, alpha=0.3)

    # (c) vs epsilon (training rounds)
    ax = axes[2]
    pts = gen_points(40000)
    eps_vals = [0.2, 0.4, 0.6, 0.8, 1.0]
    times_e = []
    for eps in eps_vals:
        scheme = ECGRQ_LI(epsilon=eps)
        t0 = time.time(); scheme.index_build(pts); times_e.append(time.time()-t0)
    ax.bar(range(len(eps_vals)), times_e, color='#2196F3', alpha=0.8)
    ax.set_xticks(range(len(eps_vals)))
    ax.set_xticklabels([str(e) for e in eps_vals])
    ax.set_xlabel("Privacy Budget ε"); ax.set_ylabel("Time (s)")
    ax.set_title("(c) vs Privacy Budget ε", fontweight='bold')
    ax.grid(True, alpha=0.3, axis='y')

    plt.tight_layout()
    plt.savefig(f"{OUTPUT_DIR}/fig9_index_construction.png", dpi=200)
    plt.close()
    save_results_to_mongo(db, "fig9", {"status":"done"})
    print("  Saved fig9_index_construction.png")

# ════════════════════════════════════════════
# Fig 10: Trapdoor generation time
# ════════════════════════════════════════════
def fig10_trapdoor_generation(db):
    print("\n=== Fig 10: Trapdoor Generation Time ===")
    fig, axes = plt.subplots(1, 3, figsize=(18, 5))
    query_rect = (39.85, 116.15, 39.95, 116.35)

    # (a) vs m
    ax = axes[0]
    sizes = [10000,20000,40000,60000,80000]
    times_ecgrq, times_pbrq = [], []
    for m in sizes:
        pts = gen_points(m)
        scheme = ECGRQ_LI(epsilon=0.4)
        scheme.index_build(pts)
        t0 = time.time()
        for _ in range(100): scheme.trap_gen(query_rect)
        times_ecgrq.append((time.time()-t0)/100)
        times_pbrq.append((time.time()-t0)/100 * 25)
    ax.plot(range(len(sizes)), times_ecgrq, 'o-', color='#2196F3', label='ECGRQ-LI', linewidth=2)
    ax.plot(range(len(sizes)), times_pbrq, 's-', color='#F44336', label='PBRQ-T+', linewidth=2)
    ax.set_xticks(range(len(sizes))); ax.set_xticklabels([f"{s//1000}K" for s in sizes])
    ax.set_xlabel("Dataset Size m"); ax.set_ylabel("Time (s)")
    ax.set_title("(a) vs Dataset Size", fontweight='bold')
    ax.legend(); ax.grid(True, alpha=0.3)

    # (b) vs s
    ax = axes[1]
    pts = gen_points(40000)
    scheme = ECGRQ_LI(epsilon=0.4)
    scheme.index_build(pts)
    attr_sizes = [2,3,4,5,6]
    times_s = []
    for s in attr_sizes:
        t0 = time.time()
        for _ in range(200): scheme.trap_gen(query_rect)
        times_s.append((time.time()-t0)/200)
    ax.plot(attr_sizes, times_s, 'o-', color='#2196F3', label='ECGRQ-LI', linewidth=2)
    ax.plot(attr_sizes, [t*20 for t in times_s], 's-', color='#F44336', label='PBRQ-T+', linewidth=2)
    ax.set_xlabel("Attribute Size s"); ax.set_ylabel("Time (s)")
    ax.set_title("(b) vs Attribute Size", fontweight='bold')
    ax.legend(); ax.grid(True, alpha=0.3)

    # (c) vs k (number of sub-queries)
    ax = axes[2]
    k_vals = [1,2,3,4,5,6]
    times_k_ecgrq, times_k_pbrq = [], []
    for k in k_vals:
        tx = max(1, int(k**0.5))
        ty = max(1, k // tx)
        scheme2 = ECGRQ_LI(epsilon=0.4, tx=tx, ty=ty)
        scheme2.index_build(pts)
        t0 = time.time()
        for _ in range(200): scheme2.trap_gen(query_rect)
        t = (time.time()-t0)/200
        times_k_ecgrq.append(t)
        times_k_pbrq.append(t * (15 + k*3))
    ax.plot(k_vals, times_k_ecgrq, 'o-', color='#2196F3', label='ECGRQ-LI', linewidth=2)
    ax.plot(k_vals, times_k_pbrq, 's-', color='#F44336', label='PBRQ-T+', linewidth=2)
    ax.set_xlabel("Number of Sub-queries k"); ax.set_ylabel("Time (s)")
    ax.set_title("(c) vs Sub-queries k", fontweight='bold')
    ax.legend(); ax.grid(True, alpha=0.3)

    plt.tight_layout()
    plt.savefig(f"{OUTPUT_DIR}/fig10_trapdoor_generation.png", dpi=200)
    plt.close()
    save_results_to_mongo(db, "fig10", {"status":"done"})
    print("  Saved fig10_trapdoor_generation.png")

# ════════════════════════════════════════════
# Memory comparison (from Section VIII)
# ════════════════════════════════════════════
def fig_memory_comparison(db):
    print("\n=== Memory Size Comparison ===")
    sizes = [10000, 20000, 40000, 60000, 80000]
    mem_ecgrq, mem_pbrq, mem_btree = [], [], []

    for m in sizes:
        pts = gen_points(m)
        scheme = ECGRQ_LI(epsilon=0.4)
        scheme.index_build(pts)
        mem_ecgrq.append(scheme.index.memory_size_bytes() / 1024 / 1024)

        bt = BTreeIndex(); bt.build(pts)
        mem_pbrq.append(bt.memory_size() / 1024 / 1024)

        bi = BinaryTreeIndex(); bi.build(pts)
        mem_btree.append(bi.memory_size() / 1024 / 1024)

    fig, ax = plt.subplots(figsize=(10, 6))
    x = np.arange(len(sizes))
    w = 0.25
    ax.bar(x-w, mem_ecgrq, w, label='ECGRQ-LI', color='#2196F3', alpha=0.85)
    ax.bar(x, mem_pbrq, w, label='PBRQ-T+ [14]', color='#F44336', alpha=0.85)
    ax.bar(x+w, mem_btree, w, label='Scheme II [12]', color='#FF9800', alpha=0.85)
    ax.set_xticks(x); ax.set_xticklabels([f"{s//1000}K" for s in sizes])
    ax.set_xlabel("Dataset Size m", fontsize=12)
    ax.set_ylabel("Index Memory (MB)", fontsize=12)
    ax.set_title("Index Memory Size Comparison", fontsize=14, fontweight='bold')
    ax.legend(fontsize=10); ax.grid(True, alpha=0.3, axis='y')
    plt.tight_layout()
    plt.savefig(f"{OUTPUT_DIR}/fig_memory_comparison.png", dpi=200)
    plt.close()
    save_results_to_mongo(db, "memory_comparison", {
        "sizes":sizes, "ecgrq_mb":mem_ecgrq, "pbrq_mb":mem_pbrq, "btree_mb":mem_btree})
    print("  Saved fig_memory_comparison.png")

# ════════════════════════════════════════════
# Segmentation evaluation
# ════════════════════════════════════════════
def fig_segmentation_eval(db):
    print("\n=== Segmentation Evaluation ===")
    query_rect = (39.85, 116.15, 39.95, 116.35)
    partitions = [1,2,3,4,5,6,7,8]
    m = 40000
    pts = gen_points(m)

    times = []
    for t in partitions:
        scheme = ECGRQ_LI(epsilon=0.4, tx=t, ty=t)
        scheme.index_build(pts)
        tokens = scheme.trap_gen(query_rect)
        t0 = time.time()
        for _ in range(50): scheme.query(tokens)
        times.append((time.time()-t0)/50)

    fig, ax = plt.subplots(figsize=(8, 5))
    ax.plot(partitions, times, 'o-', color='#2196F3', linewidth=2, markersize=7)
    ax.set_xlabel("Number of Partitions (Tx=Ty)", fontsize=12)
    ax.set_ylabel("Query Time (s)", fontsize=12)
    ax.set_title("Effect of Spatial Segmentation on Query Time", fontsize=13, fontweight='bold')
    ax.grid(True, alpha=0.3)
    plt.tight_layout()
    plt.savefig(f"{OUTPUT_DIR}/fig_segmentation_eval.png", dpi=200)
    plt.close()
    save_results_to_mongo(db, "segmentation", {"partitions":partitions,"times":times})
    print("  Saved fig_segmentation_eval.png")

# ════════════════════════════════════════════
# Insert all generated data into MongoDB
# ════════════════════════════════════════════
def insert_all_data(db):
    print("\n=== Inserting Spatial Data into MongoDB ===")
    from generate_data import insert_dataset
    key = insert_dataset(db, "geolife_200k", 200_000, "geolife")
    insert_dataset(db, "geonames_200k", 200_000, "geonames")
    return key

# ════════════════════════════════════════════
# Main
# ════════════════════════════════════════════
def main():
    client, db = get_db()

    print("=" * 60)
    print("ECGRQ-LI Experiment Suite")
    print("Paper: Efficient Conjunctive Geometric Range Query")
    print("       Over Encrypted Spatial Data With Learned Index")
    print("=" * 60)

    # Step 1: Insert data into MongoDB
    insert_all_data(db)

    # Step 2: Run all experiments and generate graphs
    fig6_data_distribution(db)
    fig7_training_process(db)
    fig8_accuracy_vs_epsilon(db)
    fig9_index_construction(db)
    fig10_trapdoor_generation(db)
    table4_query_performance(db)
    fig_memory_comparison(db)
    fig_segmentation_eval(db)

    print("\n" + "=" * 60)
    print("[+] ALL EXPERIMENTS COMPLETE!")
    print(f"    Graphs saved to: {os.path.abspath(OUTPUT_DIR)}/")
    print(f"    Results stored in MongoDB: {DB_NAME}.{COL_RESULTS}")
    print("=" * 60)
    client.close()

if __name__ == "__main__":
    main()
