#!/usr/bin/env python3
"""
ECGRQ vs BVCRSA — Full 7-Figure Benchmark
==========================================
Matches the same figure set as BVCRSA paper (fig1-fig7):
  Fig 1: Trapdoor Generation Time vs Database Size (N)
  Fig 2: Trapdoor Generation Time vs Range Size (%)
  Fig 3: Trapdoor Generation Time vs Number of Keywords
  Fig 4: Query Processing Time vs Database Size (N)
  Fig 5: Query Processing Time vs Range Size (%)
  Fig 6: Index Construction Time vs Database Size (N)
  Fig 7: Index Construction Time vs Number of Keywords

All crypto operations are REAL.
"""
import sys, os, time, csv, random, hashlib
import numpy as np

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BASE_DIR)
ECGRQ_DIR = os.path.join(os.path.dirname(BASE_DIR),
    "Efficient Conjunctive Geometric Range Query Over Encrypted Spatial Data With Learned Index")
sys.path.insert(0, ECGRQ_DIR)

from pymongo import MongoClient

MONGO_URI = "mongodb+srv://yewza232_db_user:5qCbuPzMrzPSpflq@projectsomchart.lkihxz4.mongodb.net/?appName=ProjectSomchart"
DB_NAME = "ECGRQ_BVCRSA_Full_DB"

# Test parameters matching the paper
N_VALUES       = [100, 500, 800, 1000]
RANGE_PCTS     = [10, 20, 30, 40, 50]     # Range as % of domain [20,95]
KEYWORD_COUNTS = [1, 2, 3, 4, 5]
DOMAIN_MIN, DOMAIN_MAX = 20, 95
FIXED_N        = 500       # Fixed N when varying range/keywords
FIXED_RANGE    = 30        # Fixed range% when varying N/keywords
FIXED_KEYWORDS = 1         # Fixed keywords when varying N/range

ALL_KEYWORDS = ["Temp", "Humidity", "Pressure", "Vibration", "Current",
                "Voltage", "Flow", "Speed", "Torque", "Power"]


# ═══════════════════════════════════════════════════════════════
#  DGHV Fully Homomorphic Encryption (SEaaS Paper)
# ═══════════════════════════════════════════════════════════════
class DGHV:
    def __init__(self, lam=42):
        self.lam = lam
        self.eta = lam
        self.rho = lam // 4
        self.gamma = lam * 5
        self.tau = lam + 1
        self.sk = None
        self.pk = None

    def keygen(self):
        p = random.getrandbits(self.eta) | 1
        while p < (1 << (self.eta - 1)):
            p = random.getrandbits(self.eta) | 1
        self.sk = p
        pk = []
        for _ in range(self.tau):
            q = random.getrandbits(self.gamma - self.eta)
            r = random.getrandbits(self.rho)
            x = p * q + 2 * r
            pk.append(x)
        pk.sort(reverse=True)
        if (pk[0] % p) % 2 != 0:
            pk[0] += p
        self.pk = pk
        return self.sk, self.pk

    def encrypt(self, m):
        if self.pk is None:
            self.keygen()
        r = random.getrandbits(self.rho)
        subset_sum = 0
        for i in range(1, len(self.pk)):
            if random.randint(0, 1):
                subset_sum += self.pk[i]
        return (m + 2 * r + 2 * subset_sum) % self.pk[0]

    def decrypt(self, c):
        return (c % self.sk) % 2

    def subtract(self, c1, c2):
        return (c1 - c2) % self.pk[0]

    def multiply(self, c1, c2):
        return (c1 * c2) % self.pk[0]


# ═══════════════════════════════════════════════════════════════
#  BVCRSA (SEaaS MKSE) — Bench functions per phase
# ═══════════════════════════════════════════════════════════════
class BVCRSABench:
    def __init__(self):
        self.dghv = DGHV(lam=42)
        self.dghv.keygen()
        self.kp = os.urandom(16)

    def index_build(self, records, keywords):
        """DWE: SHA-3 hash + DGHV encrypt each keyword bit per record."""
        enc_docs = []
        for rec in records:
            kw_entries = {}
            for kw in keywords:
                if kw in rec.get("sensors", []):
                    h = hashlib.sha3_256(kw.encode()).digest()
                    enc_bits = []
                    for bv in h[:4]:
                        for bp in range(8):
                            enc_bits.append(self.dghv.encrypt((bv >> bp) & 1))
                    kw_entries[kw] = enc_bits
            enc_docs.append({"id": rec["id"], "kw_enc": kw_entries,
                             "value": rec["value"]})
        return enc_docs

    def trap_gen(self, query_keywords):
        """TrapGen: DGHV encrypt each keyword bit in the query."""
        traps = []
        for kw in query_keywords:
            h = hashlib.sha3_256(kw.encode()).digest()
            enc_bits = []
            for bv in h[:4]:
                for bp in range(8):
                    enc_bits.append(self.dghv.encrypt((bv >> bp) & 1))
            traps.append(enc_bits)
        return traps

    def query(self, trapdoor, enc_docs, val_range):
        """MultiKS: Homomorphic subtract + multiply per document."""
        lo, hi = val_range
        results = []
        trap_bits = trapdoor[0]
        for doc in enc_docs:
            # Check first keyword match
            first_kw = list(doc["kw_enc"].keys())[0] if doc["kw_enc"] else None
            if first_kw is None:
                continue
            doc_bits = doc["kw_enc"][first_kw]
            flag = self.dghv.encrypt(1)
            for j in range(min(len(trap_bits), len(doc_bits))):
                diff = self.dghv.subtract(trap_bits[j], doc_bits[j])
                flag = self.dghv.multiply(flag, diff)
            dec = self.dghv.decrypt(flag)
            if dec == 0 and lo <= doc["value"] <= hi:
                results.append(doc)
        return results

    def aggregate(self, matched):
        """Decrypt flags + sum matched values."""
        return sum(m["value"] for m in matched)


# ═══════════════════════════════════════════════════════════════
#  ECGRQ — Bench functions per phase
# ═══════════════════════════════════════════════════════════════
class ECGRQBench:
    def __init__(self):
        from ecgrq_li import ECGRQ_LI
        self.scheme = ECGRQ_LI(epsilon=0.4, tx=2, ty=2)
        self.lon_map = {"A":116.0, "B":116.3, "C":116.6}

    def _to_points(self, records, keywords):
        pts = []
        for rec in records:
            lat = 39.5 + (rec["value"] - DOMAIN_MIN) / (DOMAIN_MAX - DOMAIN_MIN)
            lon = self.lon_map.get(rec["machine"], 116.3)
            kws = [kw for kw in keywords if kw in rec.get("sensors", [])]
            pts.append({"lat":lat, "lon":lon, "attrs":kws,
                        "id":rec["id"], "value":rec["value"]})
        return pts

    def index_build(self, records, keywords):
        pts = self._to_points(records, keywords)
        from ecgrq_li import ECGRQ_LI
        self.scheme = ECGRQ_LI(epsilon=0.4, tx=2, ty=2)
        self.scheme.index_build(pts)
        return pts

    def trap_gen(self, val_range, keywords):
        lo, hi = val_range
        lat_min = 39.5 + (lo - DOMAIN_MIN) / (DOMAIN_MAX - DOMAIN_MIN)
        lat_max = 39.5 + (hi - DOMAIN_MIN) / (DOMAIN_MAX - DOMAIN_MIN)
        query_rect = (lat_min, 115.5, lat_max, 117.0)
        return self.scheme.trap_gen(query_rect)

    def query(self, tokens):
        return self.scheme.query(tokens)

    def aggregate(self, matched):
        return sum(p.get("value", 0) for p in matched if "value" in p)


# ═══════════════════════════════════════════════════════════════
#  Record generator
# ═══════════════════════════════════════════════════════════════
def gen_records(n, keywords):
    random.seed(42)
    recs = []
    for i in range(n):
        assigned = random.sample(keywords, min(len(keywords),
                                 random.randint(1, len(keywords))))
        recs.append({
            "id": i, "machine": random.choice(["A","B","C"]),
            "sensors": assigned,
            "value": random.randint(DOMAIN_MIN, DOMAIN_MAX),
        })
    return recs


def get_range(pct):
    span = DOMAIN_MAX - DOMAIN_MIN
    width = int(span * pct / 100)
    lo = DOMAIN_MIN + (span - width) // 2
    hi = lo + width
    return (lo, hi)


# ═══════════════════════════════════════════════════════════════
#  Benchmark runner
# ═══════════════════════════════════════════════════════════════
def run_bench(algo_name, n, range_pct, num_kw):
    keywords = ALL_KEYWORDS[:num_kw]
    records = gen_records(n, keywords)
    val_range = get_range(range_pct)

    if algo_name == "BVCRSA":
        bench = BVCRSABench()

        t0 = time.perf_counter()
        enc = bench.index_build(records, keywords)
        index_ms = (time.perf_counter()-t0)*1000

        t0 = time.perf_counter()
        trap = bench.trap_gen(keywords)
        trap_ms = (time.perf_counter()-t0)*1000

        t0 = time.perf_counter()
        matched = bench.query(trap, enc, val_range)
        query_ms = (time.perf_counter()-t0)*1000

        return {"trap_ms":trap_ms, "query_ms":query_ms, "index_ms":index_ms,
                "total_ms":trap_ms+query_ms+index_ms, "matched":len(matched)}

    else:  # ECGRQ
        bench = ECGRQBench()

        t0 = time.perf_counter()
        bench.index_build(records, keywords)
        index_ms = (time.perf_counter()-t0)*1000

        t0 = time.perf_counter()
        tokens = bench.trap_gen(val_range, keywords)
        trap_ms = (time.perf_counter()-t0)*1000

        t0 = time.perf_counter()
        matched = bench.query(tokens)
        query_ms = (time.perf_counter()-t0)*1000

        return {"trap_ms":trap_ms, "query_ms":query_ms, "index_ms":index_ms,
                "total_ms":trap_ms+query_ms+index_ms, "matched":len(matched)}


# ═══════════════════════════════════════════════════════════════
#  MAIN
# ═══════════════════════════════════════════════════════════════
def main():
    print()
    print("╔══════════════════════════════════════════════════════════════╗")
    print("║  ECGRQ vs BVCRSA — Full 7-Figure Benchmark                ║")
    print("║  Trapdoor / Query / Index vs N, Range, Keywords            ║")
    print("╚══════════════════════════════════════════════════════════════╝")
    print()

    client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=30000)
    client.admin.command("ping")
    db = client[DB_NAME]
    print("  ✓ MongoDB connected\n")

    all_rows = []
    ALGOS = ["BVCRSA", "ECGRQ"]

    # ─── DIM 1: Vary N (fixed range=30%, keywords=1) ───
    print("━"*60)
    print("  DIM 1: Varying Database Size (N)")
    print("━"*60)
    for N in N_VALUES:
        for algo in ALGOS:
            print(f"  [{algo}] N={N} ...", end="", flush=True)
            r = run_bench(algo, N, FIXED_RANGE, FIXED_KEYWORDS)
            r.update({"dim":"vs_N","N":N,"range_pct":FIXED_RANGE,
                      "num_kw":FIXED_KEYWORDS,"algorithm":algo})
            all_rows.append(r)
            print(f"  trap={r['trap_ms']:.2f}  query={r['query_ms']:.2f}  "
                  f"index={r['index_ms']:.2f}  matched={r['matched']}")

    # ─── DIM 2: Vary Range% (fixed N=500, keywords=1) ───
    print(f"\n{'━'*60}")
    print("  DIM 2: Varying Range Size (%)")
    print("━"*60)
    for rp in RANGE_PCTS:
        for algo in ALGOS:
            print(f"  [{algo}] range={rp}% ...", end="", flush=True)
            r = run_bench(algo, FIXED_N, rp, FIXED_KEYWORDS)
            r.update({"dim":"vs_range","N":FIXED_N,"range_pct":rp,
                      "num_kw":FIXED_KEYWORDS,"algorithm":algo})
            all_rows.append(r)
            print(f"  trap={r['trap_ms']:.2f}  query={r['query_ms']:.2f}  "
                  f"index={r['index_ms']:.2f}  matched={r['matched']}")

    # ─── DIM 3: Vary Keywords (fixed N=500, range=30%) ───
    print(f"\n{'━'*60}")
    print("  DIM 3: Varying Number of Keywords")
    print("━"*60)
    for nk in KEYWORD_COUNTS:
        for algo in ALGOS:
            print(f"  [{algo}] kw={nk} ...", end="", flush=True)
            r = run_bench(algo, FIXED_N, FIXED_RANGE, nk)
            r.update({"dim":"vs_kw","N":FIXED_N,"range_pct":FIXED_RANGE,
                      "num_kw":nk,"algorithm":algo})
            all_rows.append(r)
            print(f"  trap={r['trap_ms']:.2f}  query={r['query_ms']:.2f}  "
                  f"index={r['index_ms']:.2f}  matched={r['matched']}")

    # ─── Save CSV ───
    csv_path = os.path.join(BASE_DIR, "ecgrq_bvcrsa_full_results.csv")
    fields = ["dim","N","range_pct","num_kw","algorithm",
              "trap_ms","query_ms","index_ms","total_ms","matched"]
    with open(csv_path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        for row in all_rows:
            w.writerow({k: row.get(k,0) for k in fields})
    print(f"\n  ✓ CSV saved: {csv_path}")

    # Store in MongoDB
    results_coll = db["full_benchmark"]
    results_coll.delete_many({})
    results_coll.insert_many([{k:v for k,v in r.items()} for r in all_rows])
    print(f"  ✓ Stored in MongoDB: {DB_NAME}.full_benchmark")

    # ─── Plot all 7 figures ───
    print("\n  Generating 7 figures...")
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt

    plt.rcParams.update({'font.family':'serif','font.size':12,'axes.linewidth':1.2,
        'figure.facecolor':'#f8f8f8','axes.facecolor':'#f0f0f0'})
    colors = {'BVCRSA':'#E53935','ECGRQ':'#1E88E5'}
    markers = {'BVCRSA':'o','ECGRQ':'s'}
    out = os.path.join(BASE_DIR, 'all_figures')

    def get_series(dim, xfield, metric, algo):
        subset = [r for r in all_rows if r["dim"]==dim and r["algorithm"]==algo]
        subset.sort(key=lambda r: r[xfield])
        xs = [r[xfield] for r in subset]
        ys = [r[metric] for r in subset]
        return xs, ys

    def plot_fig(dim, xfield, metric, xlabel, ylabel, title, fname):
        fig, ax = plt.subplots(figsize=(10, 6))
        for algo in ALGOS:
            xs, ys = get_series(dim, xfield, metric, algo)
            ax.plot(xs, ys, color=colors[algo], marker=markers[algo],
                    label=algo, linewidth=2.5, markersize=10,
                    markeredgecolor='white', markeredgewidth=1.5, linestyle='--')
        ax.set_xlabel(xlabel, fontsize=14, fontweight='bold')
        ax.set_ylabel(ylabel, fontsize=14, fontweight='bold')
        ax.set_title(title, fontsize=15, fontweight='bold')
        ax.legend(fontsize=12, framealpha=0.9, edgecolor='#ccc')
        ax.grid(True, alpha=0.3, linestyle='--')
        plt.tight_layout()
        path = os.path.join(out, fname)
        plt.savefig(path, dpi=150, bbox_inches='tight')
        plt.close()
        print(f"    ✓ {fname}")

    # Fig 1: Trapdoor vs N
    plot_fig("vs_N","N","trap_ms",
             "Number of Records (N)", "Trapdoor Generation Time (ms)",
             "Trapdoor Generation Time vs Database Size",
             "fig_ecgrq_1_trap_vs_N.png")

    # Fig 2: Trapdoor vs Range%
    plot_fig("vs_range","range_pct","trap_ms",
             "Range Size (%)", "Trapdoor Generation Time (ms)",
             "Trapdoor Generation Time vs Range Size",
             "fig_ecgrq_2_trap_vs_range.png")

    # Fig 3: Trapdoor vs Keywords
    plot_fig("vs_kw","num_kw","trap_ms",
             "Number of Keywords", "Trapdoor Generation Time (ms)",
             "Trapdoor Generation Time vs Keywords",
             "fig_ecgrq_3_trap_vs_keywords.png")

    # Fig 4: Query vs N
    plot_fig("vs_N","N","query_ms",
             "Number of Records (N)", "Query Processing Time (ms)",
             "Query Processing Time vs Database Size",
             "fig_ecgrq_4_query_vs_N.png")

    # Fig 5: Query vs Range%
    plot_fig("vs_range","range_pct","query_ms",
             "Range Size (%)", "Query Processing Time (ms)",
             "Query Processing Time vs Range Size",
             "fig_ecgrq_5_query_vs_range.png")

    # Fig 6: Index vs N
    plot_fig("vs_N","N","index_ms",
             "Number of Records (N)", "Index Construction Time (ms)",
             "Index Construction Time vs Database Size",
             "fig_ecgrq_6_index_vs_N.png")

    # Fig 7: Index vs Keywords
    plot_fig("vs_kw","num_kw","index_ms",
             "Number of Keywords", "Index Construction Time (ms)",
             "Index Construction Time vs Keywords",
             "fig_ecgrq_7_index_vs_keywords.png")

    print(f"\n✅ All 7 figures saved to {out}/")
    print(f"   CSV: {csv_path}\n")
    client.close()


if __name__ == "__main__":
    main()
