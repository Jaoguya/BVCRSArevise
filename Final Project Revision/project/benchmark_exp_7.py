#!/usr/bin/env python3
"""
benchmark_exp_7.py
==================
Re-runs paper Experiment 7 ONLY — Query Throughput under Increasing Query Workload.

  Exp 7 (paper): Query Throughput under Increasing Query Workload

N fixed at 10,000.  Query counts: 100 / 500 / 1,000 / 5,000 / 10,000
Records loaded from Datarecord.csv (100k rows, pre-generated).

NO MongoDB required — all index structures are in-memory.

Output: APPENDS to benchmark_exp2_5_7_results.csv
"""

import sys, os, time, random, csv, hashlib, traceback, math
import numpy as np
import pandas as pd
from datetime import datetime, timedelta

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# Read-only extracted zip has blockchain_edge.py which the git clone lacks
READ_DIR = os.path.join(
    os.path.expanduser("~"),
    "Final Project Revision (Blockchain)",
    "Final Project Revision",
    "project"
)

# Always add both paths: BASE_DIR for local modules, READ_DIR for blockchain_edge etc.
sys.path.insert(0, BASE_DIR)
if os.path.isdir(READ_DIR):
    sys.path.insert(0, READ_DIR)
    print(f"  [path] Added read-only source: {READ_DIR}")

DATARECORD_CSV = os.path.join(BASE_DIR, "Datarecord.csv")
OUTPUT_CSV     = os.path.join(BASE_DIR, "benchmark_exp2_5_7_results.csv")

# added_paper directory (try local first, then read-only)
ADDED_DIR = os.path.join(BASE_DIR, "added_paper")
if not os.path.isdir(ADDED_DIR):
    ADDED_DIR = os.path.join(READ_DIR, "added_paper")
sys.path.insert(0, ADDED_DIR)

# ── Import crypto modules ──────────────────────────────────────
from TA import TrustedAuthority as RealTA
from blockchain_edge import BlockchainEdgeManager
from utils import gen_tag
from ec_elgamal import (ECEncryptedNumber, ECElGamalPublicKey,
                         ECElGamalPrivateKey, generate_ec_elgamal_keypair)
from trinity import TrinityI
from merkle_tree import MerkleTree

try:
    from abse_fast import ABSE
except ImportError:
    from abse_real import ABSE

try:
    import importlib.util
    _spec = importlib.util.spec_from_file_location(
        "abse_range", os.path.join(ADDED_DIR, "Attribute-based.py"))
    abse_range_mod = importlib.util.module_from_spec(_spec)
    _spec.loader.exec_module(abse_range_mod)
    HAS_ABSE_RANGE = True
    print("✓ ABSE-Range loaded")
except Exception as e:
    print(f"✗ ABSE-Range unavailable: {e}")
    HAS_ABSE_RANGE = False
    abse_range_mod = None

# ── Constants ──────────────────────────────────────────────────
KEYWORD_POOL = [
    "Temp","Humidity","Pressure","Vibration","Voltage",
    "Current","Power","Flow","Level","Speed",
    "Torque","RPM","Weight","Density","pH"
]
FIXED_N_THRU  = 10_000   # N fixed for throughput experiment
QUERY_COUNTS  = [100, 500, 1_000, 5_000, 10_000]  # Exp 7
SEED          = 42


# ══════════════════════════════════════════════════════════════
#  Load records from Datarecord.csv
# ══════════════════════════════════════════════════════════════
def load_datarecord(n):
    """Load first n records from Datarecord.csv."""
    recs = []
    with open(DATARECORD_CSV, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for i, row in enumerate(reader):
            if i >= n:
                break
            recs.append({
                "id":            int(row["id"]),
                "machine":       row["machine"],
                "sensor":        row["sensor"],
                "value":         int(row["value"]),
                "timestamp":     datetime.strptime(row["timestamp_str"], "%Y-%m-%d %H:%M:%S"),
                "timestamp_str": row["timestamp_str"],
                "t_slot":        row["t_slot"],
            })
    return recs


# ══════════════════════════════════════════════════════════════
#  BVCRSA
# ══════════════════════════════════════════════════════════════
class BVCRSAAlgo:
    name = "BVCRSA"
    def setup(self, kw_count=2):
        self.ta = RealTA()
        self.abse = self.ta.abse
        attrs = ["Analyst"] + KEYWORD_POOL[:kw_count]
        self.secrets = self.ta.key_gen(attrs)
        self.enclave = BlockchainEdgeManager(self.secrets, self.abse)
        self.Ks = self.secrets["Ks"]
        self.sk_abse = self.secrets.get("SK_A")
        self.ec_pub  = self.secrets["ec_pubkey"]
        self.ec_priv = self.secrets["ec_privkey"]

    def index_build(self, records, db=None):
        # Reset per-run state: fresh blockchain + fresh node index
        self.enclave.blockchain.clear()
        self.enclave.node_state = {}
        self.enclave.merkle_leaves = []
        self.enclave.seq_counters = {}
        self.enclave.epoch = 0
        self.nodes = []
        self.node_index = {}
        for rec in records:
            ns = (self.enclave.build_scrat_from_payload({
                    "ct_aes": "dummy",
                    "ct_v": self.ec_pub.encrypt(rec["value"]).ciphertext(),
                    "ctx": {"m": rec["machine"], "k": rec["sensor"], "t": rec["t_slot"]},
                    "path": [{"l": (rec["value"]//10)*10, "r": (rec["value"]//10)*10+10}],
                    "seq": 1, "hmac": b""
                  }) if hasattr(self.enclave, 'build_scrat_from_payload')
                  else self.enclave.build_scrat_node(
                      rec["value"], (rec["machine"], rec["sensor"], rec["t_slot"])))
            for n in ns:
                self.nodes.append(n)
                key = (n["m"], n["k"], n.get("t", n.get("t_slot")), n["l"], n["r"])
                if key not in self.node_index:
                    self.node_index[key] = []
                self.node_index[key].append(n)
        return len(self.nodes)

    def trap_gen(self, keyword, a, b):
        sample = next((n for n in self.nodes if n["k"] == keyword), None)
        if not sample: return None
        tm = sample["m"]; tt = sample.get("t", sample.get("t_slot"))
        ranges = [(i, i+10) for i in range((a//10)*10, (b//10)*10+10, 10)]
        tags   = [gen_tag(self.Ks, tm, keyword, tt, {"l":lo,"r":hi}) for lo, hi in ranges]
        try:
            if self.sk_abse: self.abse.token_gen(self.sk_abse, tags[0])
        except Exception:
            pass  # token_gen is optional for search; errors don't block trapdoor
        return {"ranges": ranges, "m": tm, "k": keyword, "t": tt}

    def query(self, td):
        if td is None: return 0
        matched = [n for lo, hi in td["ranges"]
                   for n in self.node_index.get((td["m"], td["k"], td["t"], lo, hi), [])]
        if matched:
            agg = matched[0]["Agg_u"]
            for n in matched[1:]: agg += n["Agg_u"]
        return len(matched)


# ══════════════════════════════════════════════════════════════
#  VC-KASE
# ══════════════════════════════════════════════════════════════
class SimulatedPairingGroup:
    def __init__(self, p=2**256 - 2**32 - 977):
        self.p = p; self.g = 2
    def exp_G(self, base, exp): return pow(base, exp, self.p)
    def pair(self, g1, g2):    return pow(g1 * g2, 3, self.p)

class VCKASEAlgo:
    name = "VC-KASE"
    def setup(self, kw_count=2):
        self.group = SimulatedPairingGroup()
        self.n_docs = 100_000
        self.alpha  = random.randint(1, self.group.p-1)
        self.g_list = {}
        self.beta   = random.randint(1, self.group.p-1)
        self.lam    = random.randint(1, self.group.p-1)
        self.pk_o   = self.group.exp_G(self.group.g, self.beta)
        self.gamma  = random.randint(1, self.group.p-1)
        self.pk_s   = self.group.exp_G(self.group.g, self.gamma)

    def _get_g(self, i):
        if i not in self.g_list:
            self.g_list[i] = self.group.exp_G(
                self.group.g, pow(self.alpha, i, self.group.p-1))
        return self.g_list[i]

    def hash_H(self, s):
        return int(hashlib.sha256(str(s).encode()).hexdigest(), 16) % self.group.p

    def index_build(self, records, db=None):
        self.index = []
        for rec in records:
            r  = random.randint(1, self.group.p-1)
            c1 = self.group.exp_G(self.group.g, r)
            c2 = self.group.exp_G(self.group.g, (self.lam * r) % (self.group.p-1))
            self.index.append({"id": rec["id"]+1, "c1": c1, "c2": c2,
                                "sensor": rec["sensor"], "value": rec["value"]})
        self.K1_S = 1
        for j in [rec2["id"]+1 for rec2 in records]:
            self.K1_S = (self.K1_S *
                self.group.exp_G(self._get_g(self.n_docs+1-j), self.beta)) % self.group.p
        return len(records)

    def trap_gen(self, keyword, a, b):
        x = random.randint(1, self.group.p-1)
        y = random.randint(1, self.group.p-1)
        sw = sum(self.hash_H(w) for w in [keyword, str(a), str(b)]) % (self.group.p-1)
        T1 = (self.K1_S
              * self.group.exp_G(self.pk_o, (sw*x) % (self.group.p-1))
              * self.group.exp_G(self.group.g, y)) % self.group.p
        return {"T1": T1, "T2": self.group.exp_G(self.group.g, x),
                "keyword": keyword, "a": a, "b": b}

    def query(self, td):
        return sum(1 for ct in self.index
                   if ct["sensor"] == td["keyword"] and td["a"] <= ct["value"] <= td["b"])


# ══════════════════════════════════════════════════════════════
#  Latt-IBEKS
# ══════════════════════════════════════════════════════════════
class LatticeIBEKSAlgo:
    name = "Latt-IBEKS"
    def setup(self, kw_count=2):
        self.n_dim = 17; self.q = 4093; self.N_kw = 5
        self.m     = int(6 * self.n_dim * 1.5)
        self.A     = np.random.randint(0, self.q, (self.n_dim, self.m))
        self.B     = np.random.randint(0, self.q, (self.n_dim, self.m))

    def hash_H2(self, kw):
        return int(hashlib.sha256(str(kw).encode()).hexdigest(), 16) % self.q

    def index_build(self, records, db=None):
        self.index = []
        for rec in records:
            xw  = self.hash_H2(rec["sensor"])
            y_0 = np.array([(xw**i) % self.q for i in range(self.N_kw+1)])
            y   = np.zeros(self.n_dim, dtype=int)
            y[:len(y_0)] = y_0
            self.index.append({"y": y, "sensor": rec["sensor"], "value": rec["value"]})
        return len(records)

    def trap_gen(self, keyword, a, b):
        roots = [self.hash_H2(w) for w in [keyword, str(a), str(b)]]
        while len(roots) < self.N_kw: roots.append(np.random.randint(0, self.q))
        coeffs = np.poly(roots)
        b_0    = np.array([int(round(c)) % self.q for c in coeffs[::-1]])
        b_vec  = np.zeros(self.n_dim, dtype=int)
        b_vec[:len(b_0)] = b_0
        # FIX: avoid duplicate dict key "b" — use "b_vec" for lattice vector, "b" for range bound
        return {"b_vec": b_vec, "keyword": keyword, "a": a, "b": b}

    def query(self, td):
        return sum(1 for ct in self.index
                   if ct["sensor"] == td["keyword"] and td["a"] <= ct["value"] <= td["b"])


# ══════════════════════════════════════════════════════════════
#  Trinity
# ══════════════════════════════════════════════════════════════
class TrinityAlgo:
    name = "Trinity"
    def setup(self, kw_count=2):
        self.scheme = TrinityI()
        self.scheme.setup(256, 8, 10)
        # Override time window to cover the CSV data (2024-01-01 to 2024-12-31)
        # so record timestamps normalize correctly inside [0, max_coord]
        from datetime import datetime as _dt
        self.scheme.time_min = int(_dt(2024, 1, 1).timestamp())
        self.scheme.time_max = int(_dt(2025, 1, 1).timestamp())

    def index_build(self, records, db=None):
        # Re-initialise EDB so re-runs don't accumulate entries
        self.scheme.EDB = {}
        self.scheme.entry_counter = 0
        self.scheme.qf = type(self.scheme.qf)(
            quotient_bits=12, remainder_bits=8
        )
        self.entries = [
            self.scheme.gen_index({
                "device_id": str(rec["id"]),
                "latitude":  13.5, "longitude": 100.0,
                "timestamp": int(rec["timestamp"].timestamp()),
                "keywords":  [rec["sensor"]]
            }) for rec in records
        ]
        return len(self.entries)

    def trap_gen(self, keyword, a, b):
        # Query uses mid-2024 timestamp range to match indexed records
        from datetime import datetime as _dt
        t_lo = int(_dt(2024, 1, 1).timestamp())
        t_hi = int(_dt(2024, 12, 31).timestamp())
        return self.scheme.gen_trap({
            "lat_range":  (13.4, 13.6),
            "lon_range":  (99.9, 100.1),
            "time_range": (t_lo, t_hi),
            "keywords":   [keyword]
        })

    def query(self, trapdoor):
        if not trapdoor or not trapdoor.get("intervals"):
            return 0
        return sum(1 for entry in self.entries
                   for lo, hi in trapdoor["intervals"]
                   if lo <= entry["hilbert_index"] <= hi)


# ══════════════════════════════════════════════════════════════
#  ABSE-Range
# ══════════════════════════════════════════════════════════════
class ABSERangeAlgo:
    name = "ABSE-Range"
    def setup(self, kw_count=2):
        self.pk, self.msk = abse_range_mod.setup()
        self.sk = abse_range_mod.key_gen(self.msk, ["Analyst","Temp","Humidity"])

    def index_build(self, records, db=None):
        self.cts = [abse_range_mod.encrypt(self.pk, ["Analyst"], rec["value"], [rec["sensor"]])
                    for rec in records]
        return len(self.cts)

    def trap_gen(self, keyword, a, b):
        td, _ = abse_range_mod.trap_gen(self.sk, [keyword])
        return td

    def query(self, trapdoor):
        matched = 0
        for ct in self.cts:
            try: abse_range_mod.search(ct, trapdoor); matched += 1
            except: pass
        return matched


# ══════════════════════════════════════════════════════════════
#  MAIN — Experiment 7 ONLY
# ══════════════════════════════════════════════════════════════
def main():
    print("\n" + "="*70)
    print("  BVCRSA Extended Benchmark — Experiment 7 ONLY")
    print(f"  Query Throughput vs Query Workload (N={FIXED_N_THRU:,} fixed)")
    print("="*70)

    # ── Verify Datarecord.csv ──────────────────────────────────
    if not os.path.exists(DATARECORD_CSV):
        print(f"\n  ✗ Datarecord.csv not found at: {DATARECORD_CSV}")
        print("  Run generate_datarecord.py first.\n")
        sys.exit(1)

    # Build algorithm list
    ALL_ALGOS = [BVCRSAAlgo, TrinityAlgo, VCKASEAlgo, LatticeIBEKSAlgo]
    if HAS_ABSE_RANGE:
        ALL_ALGOS.insert(3, ABSERangeAlgo)

    # ── Load existing results from CSV (exp2_5) ───────────────
    existing_results = []
    if os.path.exists(OUTPUT_CSV):
        try:
            df_existing = pd.read_csv(OUTPUT_CSV)
            # Keep only non-exp7 rows (preserve exp2_5 data)
            df_existing = df_existing[df_existing["exp"] != "exp7"]
            existing_results = df_existing.to_dict("records")
            print(f"  ✓ Loaded {len(existing_results)} existing exp2_5 rows from CSV")
        except Exception as e:
            print(f"  ⚠ Could not read existing CSV: {e}")
            existing_results = []

    results = list(existing_results)

    # ══════════════════════════════════════════════════════════
    #  EXP 7: Query Throughput under increasing workload
    # ══════════════════════════════════════════════════════════
    exp_start = time.perf_counter()

    print(f"\n{'━'*70}")
    print(f"  EXP 7: Query Throughput vs Query Workload (N={FIXED_N_THRU:,} fixed)")
    print(f"  Query counts: {QUERY_COUNTS}")
    print(f"{'━'*70}")

    print(f"\n  Loading {FIXED_N_THRU:,} records...", flush=True)
    records_thru = load_datarecord(FIXED_N_THRU)

    for AlgoCls in ALL_ALGOS:
        algo = AlgoCls()
        name = algo.name
        print(f"\n  ── {name} ──")
        try:
            algo.setup(2)
            print(f"    Building index for N={FIXED_N_THRU:,}...", end="", flush=True)
            algo.index_build(records_thru, db=None)
            print(" done.")
            # Pre-generate one trapdoor for repeated use
            td = algo.trap_gen("Temp", 35, 65)

            for Q in QUERY_COUNTS:
                t0 = time.perf_counter()
                for _ in range(Q):
                    algo.query(td)
                total_s = time.perf_counter() - t0
                throughput = Q / total_s  # queries/second

                print(f"    Q={Q:>6,} | total={total_s*1000:>8.1f}ms | "
                      f"throughput={throughput:>8.1f} q/s")
                results.append({
                    "exp":        "exp7",
                    "dim":        "vs_throughput",
                    "N":          FIXED_N_THRU,
                    "algo":       name,
                    "query_count": Q,
                    "total_ms":   round(total_s * 1000, 3),
                    "throughput": round(throughput, 3),
                    "note":       ""
                })
        except Exception as e:
            print(f"    ERROR: {e}")
            traceback.print_exc()

        # Save after each algorithm completes
        _save_csv(results, OUTPUT_CSV)

    # ── Final save ──────────────────────────────────────────────
    _save_csv(results, OUTPUT_CSV)
    total_elapsed = (time.perf_counter() - exp_start) / 60
    print(f"\n{'='*70}")
    print(f"  ✅ Experiment 7 complete!")
    print(f"     Total time:  {total_elapsed:.1f} minutes")
    print(f"     Results CSV: {OUTPUT_CSV}")
    print(f"{'='*70}\n")


def _save_csv(results, path):
    if not results: return
    df = pd.DataFrame(results)
    df.to_csv(path, index=False)


if __name__ == "__main__":
    main()
