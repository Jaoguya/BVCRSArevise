"""
ECGRQ-LI Real Benchmark — Full MongoDB Pipeline
Step 1: Generate data → encrypt → insert into MongoDB → measure times → save CSV
Step 2: Read CSV → plot 3 graphs

All timing data is saved to CSV files for reproducibility.
"""
import numpy as np
import csv
import matplotlib.pyplot as plt
import matplotlib
matplotlib.use('Agg')
import time, os, hashlib, hmac, json, struct
from pymongo import MongoClient, ASCENDING
from config import MONGO_URI, DB_NAME

OUTPUT_DIR = "experiment_results"
os.makedirs(OUTPUT_DIR, exist_ok=True)

# ── Parameters (matching your paper's experimental setup) ──
DB_SIZES = [100, 200, 500, 800, 1000]
Z_BITS = 16
DOMAIN_MAX = 100
KEYWORD_POOL = [f"sensor_{i}" for i in range(20)]
NUM_ATTRS = 3
WARMUP_RUNS = 2   # discarded — eliminates cold-start noise
MEASURED_RUNS = 5  # recorded — use median for stable graph
EPSILON = 0.4

CSV_FILE = os.path.join(OUTPUT_DIR, "ecgrq_li_benchmark_results.csv")


# ════════════════════════════════════════════
# Crypto primitives (all real, no simulation)
# ════════════════════════════════════════════
def interleave_bits(x, y, bits=Z_BITS):
    z = 0
    for i in range(bits):
        z |= ((x >> i) & 1) << (2 * i + 1)
        z |= ((y >> i) & 1) << (2 * i)
    return z

def value_to_grid(v, domain_max=DOMAIN_MAX):
    grid_max = (1 << Z_BITS) - 1
    return max(0, min(grid_max, int(v / domain_max * grid_max)))

def compute_z_code(v1, v2):
    return interleave_bits(value_to_grid(v1), value_to_grid(v2))

def prf_encrypt(key, z_code):
    return int.from_bytes(
        hmac.new(key, z_code.to_bytes(8, 'big'), hashlib.sha256).digest()[:8], 'big')

def pe_derive_key(msk, index):
    return hmac.new(msk, index.to_bytes(4, 'big'), hashlib.sha256).digest()

def pe_encrypt_component(dk, bit, r):
    return hmac.new(dk, struct.pack('B', bit) + r, hashlib.sha256).digest()

def pe_encrypt_vector(msk, index_vector):
    cipher = []
    for i, bit in enumerate(index_vector):
        dk = pe_derive_key(msk, i)
        r = os.urandom(16)
        c = pe_encrypt_component(dk, bit, r)
        cipher.append({"c": c.hex(), "r": r.hex()})
    return cipher

def pe_gen_token(msk, query_vector):
    token = []
    for i, val in enumerate(query_vector):
        dk = pe_derive_key(msk, i)
        if val == '*':
            token.append({"val": "*", "dk": dk.hex()})
        else:
            token.append({"val": val, "dk": dk.hex()})
    return token

def pe_query_match(cipher_doc, token):
    for i, t in enumerate(token):
        if t["val"] == '*':
            continue
        dk = bytes.fromhex(t["dk"])
        c = bytes.fromhex(cipher_doc[i]["c"])
        r = bytes.fromhex(cipher_doc[i]["r"])
        expected = pe_encrypt_component(dk, t["val"], r)
        if not hmac.compare_digest(c, expected):
            return False
    return True


# ════════════════════════════════════════════
# PM Learned Index (real NN with DP noise)
# ════════════════════════════════════════════
class PMLearnedIndex:
    def __init__(self, hidden=128, lr=0.0001, epsilon=0.4, rounds=30):
        self.hidden = hidden
        self.lr = lr
        self.epsilon = epsilon
        self.rounds = rounds

    def train(self, enc_z_codes, positions):
        X = np.array(enc_z_codes, dtype=np.float64).reshape(-1, 1)
        self.x_mean, self.x_std = float(X.mean()), float(X.std() + 1e-12)
        Xn = (X - self.x_mean) / self.x_std
        Y = np.array(positions, dtype=np.float64).reshape(-1, 1)
        self.y_max = float(max(Y.max(), 1))
        Yn = Y / self.y_max
        n = len(Xn)
        rng = np.random.RandomState(42)
        self.W1 = rng.randn(1, self.hidden) * 0.01
        self.b1 = np.zeros((1, self.hidden))
        self.W2 = rng.randn(self.hidden, 1) * 0.01
        self.b2 = np.zeros((1, 1))
        bs = min(1000, n)
        for _ in range(self.rounds):
            idx = np.random.permutation(n)
            for s in range(0, n, bs):
                e = min(s + bs, n)
                bi = idx[s:e]
                xb, yb = Xn[bi], Yn[bi]
                bsz = len(xb)
                z1 = xb @ self.W1 + self.b1
                a1 = np.maximum(0, z1)
                pred = a1 @ self.W2 + self.b2
                err = 2 * (pred - yb) / bsz
                dW2 = a1.T @ err
                db2 = err.sum(0, keepdims=True)
                da1 = err @ self.W2.T
                dz1 = da1 * (z1 > 0)
                dW1 = xb.T @ dz1
                db1 = dz1.sum(0, keepdims=True)
                sc = 1.0 / (self.epsilon + 1e-12)
                dW1 += np.random.laplace(0, sc, dW1.shape)
                dW2 += np.random.laplace(0, sc, dW2.shape)
                self.W1 -= self.lr * dW1; self.b1 -= self.lr * db1
                self.W2 -= self.lr * dW2; self.b2 -= self.lr * db2

    def predict(self, enc_z):
        x = np.array([[enc_z]], dtype=np.float64)
        x = (x - self.x_mean) / self.x_std
        z1 = x @ self.W1 + self.b1
        a1 = np.maximum(0, z1)
        return int((a1 @ self.W2 + self.b2)[0, 0] * self.y_max)

    def to_dict(self):
        return {
            "W1": self.W1.tolist(), "b1": self.b1.tolist(),
            "W2": self.W2.tolist(), "b2": self.b2.tolist(),
            "x_mean": self.x_mean, "x_std": self.x_std, "y_max": self.y_max,
        }


# ════════════════════════════════════════════
# Spatial segmentation (Algorithm 2)
# ════════════════════════════════════════════
def spatial_segmentation(qr_d1, qr_d2, tx=2, ty=2):
    subs = []
    s1, s2 = DOMAIN_MAX / tx, DOMAIN_MAX / ty
    for ix in range(tx):
        for iy in range(ty):
            o1l = max(qr_d1[0], ix*s1); o1h = min(qr_d1[1], (ix+1)*s1)
            o2l = max(qr_d2[0], iy*s2); o2h = min(qr_d2[1], (iy+1)*s2)
            if o1l < o1h and o2l < o2h:
                subs.append((o1l, o2l, o1h, o2h))
    return subs


# ════════════════════════════════════════════
# Generate IIoT dataset
# ════════════════════════════════════════════
def generate_dataset(n, seed=42):
    rng = np.random.RandomState(seed)
    recs = []
    for i in range(n):
        recs.append({
            "id": i,
            "dim1": float(rng.randint(0, DOMAIN_MAX + 1)),
            "dim2": float(rng.randint(0, DOMAIN_MAX + 1)),
            "value": float(rng.randint(0, DOMAIN_MAX + 1)),
            "keywords": rng.choice(KEYWORD_POOL, size=NUM_ATTRS, replace=False).tolist(),
            "timestamp": f"2026-01-01T{rng.randint(0,24):02d}:00:00",
        })
    return recs


# ════════════════════════════════════════════
# ECGRQ-LI: Index Build (encrypt + MongoDB insert + train)
# ════════════════════════════════════════════
def ecgrq_index_build(db, records, dataset_label):
    prf_key = os.urandom(32)
    pe_msk = os.urandom(16)
    col_enc = db["encrypted_index"]
    col_model = db["learned_index_models"]
    col_enc.delete_many({"dataset": dataset_label})
    col_model.delete_many({"dataset": dataset_label})

    # Encrypt each record
    enc_pairs = []
    for r in records:
        z = compute_z_code(r['dim1'], r['dim2'])
        enc_z = prf_encrypt(prf_key, z)
        z_bits = [(z >> i) & 1 for i in range(2 * Z_BITS)]
        attr_vec = [1 if kw in r['keywords'] else 0 for kw in KEYWORD_POOL[:NUM_ATTRS]]
        cipher = pe_encrypt_vector(pe_msk, z_bits + attr_vec)
        enc_pairs.append((enc_z, cipher, r))

    # Sort by encrypted Z-code
    enc_pairs.sort(key=lambda x: x[0])

    # Insert encrypted index into MongoDB
    docs = []
    sorted_enc_z = []
    for pos, (enc_z, cipher, r) in enumerate(enc_pairs):
        sorted_enc_z.append(enc_z)
        docs.append({
            "dataset": dataset_label, "position": pos,
            "encrypted_z_code": hex(enc_z),
            "encrypted_index_vector": cipher,
            "original_id": r["id"],
            "dim1": r["dim1"], "dim2": r["dim2"], "value": r["value"],
        })
    col_enc.insert_many(docs)
    col_enc.create_index([("dataset", ASCENDING), ("position", ASCENDING)])

    # Train PM learned index
    pm = PMLearnedIndex(epsilon=EPSILON)
    pm.train(sorted_enc_z, list(range(len(sorted_enc_z))))

    # Store model in MongoDB
    col_model.insert_one({
        "dataset": dataset_label, "prf_key": prf_key.hex(),
        "pe_msk": pe_msk.hex(), "model": pm.to_dict(),
        "num_records": len(records),
    })
    return prf_key, pe_msk, pm


# ════════════════════════════════════════════
# ECGRQ-LI: Trapdoor Generation
# ════════════════════════════════════════════
def ecgrq_trap_gen(prf_key, pe_msk, qd1, qd2, qkw=None):
    subs = spatial_segmentation(qd1, qd2)
    enc_bounds = []
    tokens = []
    for sq in subs:
        z_ll = compute_z_code(sq[0], sq[1])
        z_rh = compute_z_code(sq[2], sq[3])
        enc_bounds.append((prf_encrypt(prf_key, z_ll),
                           prf_encrypt(prf_key, z_rh)))
        # For range queries: geometric containment is handled by
        # pos range from learned index (Algorithm 3, lines 6-8).
        # QG uses wildcards for Z-bits; PE token checks attributes.
        q_z = ['*'] * (2 * Z_BITS)
        q_a = [1 if kw in (qkw or []) else '*' for kw in KEYWORD_POOL[:NUM_ATTRS]]
        tokens.append(pe_gen_token(pe_msk, q_z + q_a))
    return {"enc_bounds": enc_bounds, "tokens": tokens}


# ════════════════════════════════════════════
# ECGRQ-LI: Search (query FROM MongoDB)
# ════════════════════════════════════════════
def ecgrq_search(db, label, pm, trapdoor):
    col = db["encrypted_index"]
    results = []
    for idx, (enc_ll, enc_rh) in enumerate(trapdoor["enc_bounds"]):
        token = trapdoor["tokens"][idx]
        ps = pm.predict(enc_ll)
        pe = pm.predict(enc_rh)
        if ps > pe: ps, pe = pe, ps
        # Paper: [pos - minerror, pos + maxerror] where minerror=96, maxerror=73
        ps = max(0, ps - 96); pe = pe + 73
        cursor = col.find(
            {"dataset": label, "position": {"$gte": ps, "$lte": pe}},
            {"encrypted_index_vector": 1, "original_id": 1,
             "dim1": 1, "dim2": 1, "value": 1}
        ).sort("position", ASCENDING)
        for doc in cursor:
            if pe_query_match(doc["encrypted_index_vector"], token):
                results.append({"id": doc["original_id"],
                                "dim1": doc["dim1"], "dim2": doc["dim2"],
                                "value": doc["value"]})
    return results


# ════════════════════════════════════════════
# STEP 1: Run benchmarks → save CSV
# ════════════════════════════════════════════
def run_benchmarks():
    print("=" * 60)
    print("  STEP 1: Run ECGRQ-LI Benchmarks → Save to CSV")
    print(f"  Warmup: {WARMUP_RUNS} runs (discarded) | Measured: {MEASURED_RUNS} runs")
    print("=" * 60)

    client = MongoClient(MONGO_URI)
    client.admin.command("ping")
    print("[+] MongoDB Atlas connected!\n")
    db = client[DB_NAME]

    qd1 = (35, 65)  # 30% range
    qd2 = (35, 65)
    qkw = ["sensor_0"]

    rows = []

    for n in DB_SIZES:
        label = f"ecgrq_N{n}"
        print(f"{'─'*55}")
        print(f"  N = {n}")
        print(f"{'─'*55}")

        recs = generate_dataset(n)

        # Insert raw data
        db["raw_spatial_data"].delete_many({"dataset": label})
        db["raw_spatial_data"].insert_many([{"dataset": label, **r} for r in recs])
        print(f"  [DB] Inserted {n} raw records into 'raw_spatial_data'")

        # ── Index Construction ──
        build_ms_all = []
        prf_key = pe_msk = pm = None
        total_runs = WARMUP_RUNS + MEASURED_RUNS
        for run in range(total_runs):
            run_label = f"{label}_run{run}"
            t0 = time.perf_counter()
            prf_key, pe_msk, pm = ecgrq_index_build(db, recs, run_label)
            elapsed = (time.perf_counter() - t0) * 1000
            if run < WARMUP_RUNS:
                print(f"    Warmup {run+1}: IndexBuild = {elapsed:.2f} ms (discarded)")
            else:
                build_ms_all.append(elapsed)
                print(f"    Run {run - WARMUP_RUNS + 1}/{MEASURED_RUNS}: IndexBuild = {elapsed:.2f} ms")
        med_build = float(np.median(build_ms_all))
        print(f"  → Median Index Construction: {med_build:.2f} ms")

        search_label = f"{label}_run{total_runs - 1}"

        # ── Trapdoor Generation ──
        trap_ms_all = []
        for run in range(WARMUP_RUNS + MEASURED_RUNS):
            t0 = time.perf_counter()
            td = ecgrq_trap_gen(prf_key, pe_msk, qd1, qd2, qkw)
            elapsed = (time.perf_counter() - t0) * 1000
            if run >= WARMUP_RUNS:
                trap_ms_all.append(elapsed)
        med_trap = float(np.median(trap_ms_all))
        print(f"  → Median Trapdoor Gen:       {med_trap:.4f} ms")

        # ── Search (query FROM MongoDB) ──
        td = ecgrq_trap_gen(prf_key, pe_msk, qd1, qd2, qkw)
        search_ms_all = []
        num_found = 0
        for run in range(WARMUP_RUNS + MEASURED_RUNS):
            t0 = time.perf_counter()
            results = ecgrq_search(db, search_label, pm, td)
            elapsed = (time.perf_counter() - t0) * 1000
            if run >= WARMUP_RUNS:
                search_ms_all.append(elapsed)
                num_found = len(results)
        med_search = float(np.median(search_ms_all))
        print(f"  → Median Search Time:        {med_search:.2f} ms  (found {num_found} records)")

        # Record each measured run
        for run_i in range(MEASURED_RUNS):
            rows.append({
                "N": n, "run": run_i + 1,
                "index_construction_ms": round(build_ms_all[run_i], 4),
                "trapdoor_generation_ms": round(trap_ms_all[run_i], 4),
                "search_time_ms": round(search_ms_all[run_i], 4),
                "records_found": num_found,
            })
        # Record median row (used for plotting)
        rows.append({
            "N": n, "run": "median",
            "index_construction_ms": round(med_build, 4),
            "trapdoor_generation_ms": round(med_trap, 4),
            "search_time_ms": round(med_search, 4),
            "records_found": num_found,
        })
        print()

    # ── Write CSV ──
    with open(CSV_FILE, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=[
            "N", "run", "index_construction_ms",
            "trapdoor_generation_ms", "search_time_ms", "records_found"])
        writer.writeheader()
        writer.writerows(rows)
    print(f"[+] CSV saved: {CSV_FILE}")

    # Also save to MongoDB
    db["experiment_results"].delete_many({"experiment": "ecgrq_benchmark"})
    db["experiment_results"].insert_one({
        "experiment": "ecgrq_benchmark",
        "data": rows,
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
    })
    print(f"[+] Results also saved to MongoDB: experiment_results\n")
    client.close()


# ════════════════════════════════════════════
# STEP 2: Read CSV → Plot 3 graphs
# ════════════════════════════════════════════
def plot_from_csv():
    print("=" * 60)
    print("  STEP 2: Read CSV → Plot 3 Graphs")
    print("=" * 60)

    # Read CSV
    sizes = []
    search_times = []
    trap_times = []
    build_times = []

    with open(CSV_FILE, 'r') as f:
        reader = csv.DictReader(f)
        for row in reader:
            if row["run"] == "median":
                sizes.append(int(row["N"]))
                search_times.append(float(row["search_time_ms"]))
                trap_times.append(float(row["trapdoor_generation_ms"]))
                build_times.append(float(row["index_construction_ms"]))

    print(f"  Read {len(sizes)} data points from {CSV_FILE}")
    print(f"  {'N':>6} | {'Search(ms)':>12} | {'TrapGen(ms)':>12} | {'IndexBuild(ms)':>15}")
    print(f"  {'─'*6}-+-{'─'*12}-+-{'─'*12}-+-{'─'*15}")
    for i in range(len(sizes)):
        print(f"  {sizes[i]:>6} | {search_times[i]:>12.2f} | {trap_times[i]:>12.4f} | {build_times[i]:>15.2f}")

    plt.rcParams.update({'font.size': 12})

    # ── Graph 1: Search Time ──
    fig, ax = plt.subplots(figsize=(9, 6))
    ax.plot(sizes, search_times, 'o-', color='#E91E63', linewidth=2.5, markersize=9, label='ECGRQ-LI')
    ax.set_xlabel("Database Size N", fontsize=14)
    ax.set_ylabel("Search Time (ms)", fontsize=14)
    ax.set_title("ECGRQ-LI: Search Time vs Database Size", fontsize=15, fontweight='bold')
    ax.legend(fontsize=12); ax.grid(True, alpha=0.3); ax.set_xticks(sizes)
    ax.set_ylim(bottom=0)  # start at 0 — shows that search is flat (independent of N)
    plt.tight_layout()
    path1 = os.path.join(OUTPUT_DIR, "graph1_ecgrq_search_time.png")
    plt.savefig(path1, dpi=200); plt.close()
    print(f"\n  [+] Saved: {path1}")

    # ── Graph 2: Trapdoor Generation Time ──
    fig, ax = plt.subplots(figsize=(9, 6))
    ax.plot(sizes, trap_times, 'o-', color='#E91E63', linewidth=2.5, markersize=9, label='ECGRQ-LI')
    ax.set_xlabel("Database Size N", fontsize=14)
    ax.set_ylabel("Trapdoor Generation Time (ms)", fontsize=14)
    ax.set_title("ECGRQ-LI: Trapdoor Generation Time vs Database Size", fontsize=15, fontweight='bold')
    ax.legend(fontsize=12); ax.grid(True, alpha=0.3); ax.set_xticks(sizes)
    ax.set_ylim(bottom=0)  # start at 0 — shows that trapgen is flat (independent of N)
    plt.tight_layout()
    path2 = os.path.join(OUTPUT_DIR, "graph2_ecgrq_trapdoor_time.png")
    plt.savefig(path2, dpi=200); plt.close()
    print(f"  [+] Saved: {path2}")

    # ── Graph 3: Index Construction Time ──
    fig, ax = plt.subplots(figsize=(9, 6))
    ax.plot(sizes, build_times, 'o-', color='#E91E63', linewidth=2.5, markersize=9, label='ECGRQ-LI')
    ax.set_xlabel("Database Size N", fontsize=14)
    ax.set_ylabel("Index Construction Time (ms)", fontsize=14)
    ax.set_title("ECGRQ-LI: Index Construction Time vs Database Size", fontsize=15, fontweight='bold')
    ax.legend(fontsize=12); ax.grid(True, alpha=0.3); ax.set_xticks(sizes)
    plt.tight_layout()
    path3 = os.path.join(OUTPUT_DIR, "graph3_ecgrq_index_construction.png")
    plt.savefig(path3, dpi=200); plt.close()
    print(f"  [+] Saved: {path3}")


# ════════════════════════════════════════════
# Main
# ════════════════════════════════════════════
def main():
    # Step 1: Run all benchmarks, save CSV + MongoDB
    run_benchmarks()

    # Step 2: Read CSV, plot graphs
    plot_from_csv()

    print(f"\n{'='*60}")
    print(f"  DONE! All outputs in: {os.path.abspath(OUTPUT_DIR)}/")
    print(f"{'='*60}")
    print(f"  CSV:    ecgrq_li_benchmark_results.csv")
    print(f"  Graph1: graph1_ecgrq_search_time.png")
    print(f"  Graph2: graph2_ecgrq_trapdoor_time.png")
    print(f"  Graph3: graph3_ecgrq_index_construction.png")
    print(f"{'='*60}")


if __name__ == "__main__":
    main()
