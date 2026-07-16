#!/usr/bin/env python3
"""
BVCRSA Paper Benchmark — Fully Integrated (No Graphing)
========================================================
Integrates with `blockchain_edge.py` and `ethereum_connector.py`.
Includes:
- Main 5 Dimensions + Skewed 
- Conjunctive Deep-Dive (vs N & Range) with Latt-IBEKS Scheme-II Patch
- Ablation Study (Aggregate vs Naive)

Output: Saves all metrics directly to 'benchmark_paper_results.csv'
"""

import sys, os, time, random, csv, hashlib, traceback
import numpy as np
import pandas as pd
from datetime import datetime, timedelta
from pymongo import MongoClient, ASCENDING

# MongoDB Configuration
MONGO_URI = "mongodb+srv://yewza232_db_user:5qCbuPzMrzPSpflq@projectsomchart.lkihxz4.mongodb.net/?appName=ProjectSomchart"
DB_NAME = "BVCRSA_LastestData_GuyV1"
COLLS = {
    "BVCRSA": "BVCRSA_Nodes_Lastest",
    "Trinity": "Trinity_Nodes_Lastest",
    "ABSE-Range": "ABSERange_Nodes_Lastest",
    "Latt-IBEKS": "LattIBEKS_Nodes_Lastest",
    "VC-KASE": "VCKASE_Nodes_Lastest",
}

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BASE_DIR)

# ── Imports ──
from TA import TrustedAuthority as RealTA
from blockchain_edge import BlockchainEdgeManager
from utils import gen_tag
from ec_elgamal import ECEncryptedNumber, ECElGamalPublicKey, ECElGamalPrivateKey, generate_ec_elgamal_keypair
from trinity import TrinityI
from merkle_tree import MerkleTree

try:
    from abse_fast import ABSE
except ImportError:
    from abse_real import ABSE

# ABSE-Range
ADDED_DIR = os.path.join(BASE_DIR, "added_paper")
sys.path.insert(0, ADDED_DIR)
try:
    import importlib.util
    _spec = importlib.util.spec_from_file_location(
        "abse_range",
        os.path.join(ADDED_DIR, "Attribute-based.py")
    )
    abse_range_mod = importlib.util.module_from_spec(_spec)
    _spec.loader.exec_module(abse_range_mod)
    HAS_ABSE_RANGE = True
    print("✓ ABSE-Range loaded successfully")
except Exception as e:
    print(f"X ABSE-Range unavailable: {e}")
    HAS_ABSE_RANGE = False
    abse_range_mod = None

KEYWORD_POOL = ["Temp","Humidity","Pressure","Vibration","Voltage",
                "Current","Power","Flow","Level","Speed",
                "Torque","RPM","Weight","Density","pH"]

RUNS = 3  # average over 3 runs

# ══════════════════════════════════════════════════════════════
#  Data Generation
# ══════════════════════════════════════════════════════════════
def gen_data(n, num_kw=2, distribution="uniform"):
    kws = KEYWORD_POOL[:max(num_kw, 1)]
    base = datetime.now()
    recs = []
    for i in range(n):
        m = random.choice(["A","B","C"])
        k = random.choice(kws)
        if distribution == "normal":
            v = int(np.clip(np.random.normal(70, 10), 0, 100))
        else:
            v = random.randint(0, 100)
        t_obj = base - timedelta(seconds=random.randint(0, 3600))
        recs.append({
            "id": i, "machine": m, "sensor": k, "value": v,
            "timestamp": t_obj,
            "timestamp_str": t_obj.strftime("%Y-%m-%d %H:%M:%S"),
            "t_slot": t_obj.strftime("%Y-%m-%d %H"),
        })
    return recs

# ══════════════════════════════════════════════════════════════
#  BVCRSA (Integrated with blockchain_edge.py)
# ══════════════════════════════════════════════════════════════
class BVCRSAAlgo:
    name = "BVCRSA"
    def setup(self, kw_count=2):
        self.ta = RealTA()
        self.abse = self.ta.abse
        attrs = ["Analyst"] + KEYWORD_POOL[:kw_count]
        self.secrets = self.ta.key_gen(attrs)
        # CRITICAL: use_ethereum=False during the benchmark to measure pure cryptographic speed
        # CRITICAL: Do not pass network connectors during benchmark to measure pure cryptographic speed
        self.enclave = BlockchainEdgeManager(self.secrets, self.abse)
        self.Ks = self.secrets["Ks"]
        self.sk_abse = self.secrets.get("SK_A")
        self.ec_pub = self.secrets["ec_pubkey"]
        self.ec_priv = self.secrets["ec_privkey"]

    def index_build(self, records, db=None):
        self.nodes = []
        self.node_index = {}  
        for rec in records:
            ns = self.enclave.build_scrat_from_payload({
                "ct_aes": "dummy", "ct_v": self.ec_pub.encrypt(rec["value"]).ciphertext(),
                "ctx": {"m": rec["machine"], "k": rec["sensor"], "t": rec["t_slot"]},
                "path": [{"l": (rec["value"]//10)*10, "r": (rec["value"]//10)*10+10}], "seq": 1, "hmac": b""
            }) if hasattr(self.enclave, 'build_scrat_from_payload') else self.enclave.build_scrat_node(rec["value"], (rec["machine"], rec["sensor"], rec["t_slot"]))
            for n in ns:
                self.nodes.append(n)
                key = (n["m"], n["k"], n.get("t", n.get("t_slot")), n["l"], n["r"])
                if key not in self.node_index: self.node_index[key] = []
                self.node_index[key].append(n)

        if db is not None:
            coll = db[COLLS["BVCRSA"]]
            coll.delete_many({})
            docs = [{"m": n["m"], "k": n["k"], "t": str(n.get("t", n.get("t_slot"))), "l": n["l"], "r": n["r"], "algorithm": "BVCRSA",
                     "Agg_u": str(n["Agg_u"].ciphertext()) if hasattr(n["Agg_u"], "ciphertext") else str(n["Agg_u"])} for n in self.nodes]
            for i in range(0, len(docs), 500): coll.insert_many(docs[i:i+500])
        return len(self.nodes)

    def trap_gen(self, keyword, a, b):
        sample = next((n for n in self.nodes if n["k"] == keyword), None)
        if not sample: return None
        tm, tt = sample["m"], sample.get("t", sample.get("t_slot"))
        ranges = [(i, i+10) for i in range((a//10)*10, (b//10)*10+10, 10)]
        tags = [gen_tag(self.Ks, tm, keyword, tt, {"l":lo,"r":hi}) for lo, hi in ranges]
        if self.sk_abse: self.abse.token_gen(self.sk_abse, tags[0])
        return {"ranges": ranges, "m": tm, "k": keyword, "t": tt}
    
    def query(self, td):
        if td is None: return 0
        matched = [n for lo, hi in td["ranges"] for n in self.node_index.get((td["m"], td["k"], td["t"], lo, hi), [])]
        if matched:
            agg = matched[0]["Agg_u"]
            for n in matched[1:]: agg += n["Agg_u"]
        return len(matched)

    def conjunctive_trap(self, dims_spec):
        return [td for spec in dims_spec if (td := self.trap_gen(spec["k"], spec["a"], spec["b"]))]

    def conjunctive_query(self, tds):
        if not tds: return 0
        sets = [set(n.get("t", n.get("t_slot")) for lo, hi in td["ranges"] for n in self.node_index.get((td["m"], td["k"], td["t"], lo, hi), [])) for td in tds]
        if not sets: return 0
        common = sets[0]
        for s in sets[1:]: common &= s
        return len(common)

# ══════════════════════════════════════════════════════════════
#  VC-KASE 
# ══════════════════════════════════════════════════════════════
class SimulatedPairingGroup:
    def __init__(self, p=2**256 - 2**32 - 977): self.p = p; self.g = 2 
    def exp_G(self, base, exp): return pow(base, exp, self.p)
    def pair(self, g1, g2): return pow(g1 * g2, 3, self.p)

class VCKASEAlgo:
    name = "VC-KASE"
    def setup(self, kw_count=2):
        self.group = SimulatedPairingGroup(); self.n_docs = 20000 
        self.alpha = random.randint(1, self.group.p - 1); self.g_list = {}
        self.beta = random.randint(1, self.group.p - 1); self.lam = random.randint(1, self.group.p - 1)
        self.pk_o = self.group.exp_G(self.group.g, self.beta)
        self.gamma = random.randint(1, self.group.p - 1); self.pk_s = self.group.exp_G(self.group.g, self.gamma)

    def _get_g(self, i):
        if i not in self.g_list: self.g_list[i] = self.group.exp_G(self.group.g, pow(self.alpha, i, self.group.p - 1))
        return self.g_list[i]
        
    def hash_H(self, string_val):
        return int(hashlib.sha256(str(string_val).encode()).hexdigest(), 16) % self.group.p

    def index_build(self, records, db=None):
        self.index = []
        for rec in records:
            r = random.randint(1, self.group.p - 1)
            c1 = self.group.exp_G(self.group.g, r)
            c2 = self.group.exp_G(self.group.g, (self.lam * r) % (self.group.p - 1))
            self.index.append({"id": rec["id"] + 1, "c1": c1, "c2": c2, "sensor": rec["sensor"], "value": rec["value"]})
        self.K1_S = 1
        for j in [r["id"] + 1 for r in records]:
            self.K1_S = (self.K1_S * self.group.exp_G(self._get_g(self.n_docs + 1 - j), self.beta)) % self.group.p
        return len(records)

    def trap_gen(self, keyword, a, b):
        x = random.randint(1, self.group.p - 1); y = random.randint(1, self.group.p - 1)
        sum_hw = sum(self.hash_H(w) for w in [keyword, str(a), str(b)]) % (self.group.p - 1)
        T1 = (self.K1_S * self.group.exp_G(self.pk_o, (sum_hw * x) % (self.group.p - 1)) * self.group.exp_G(self.group.g, y)) % self.group.p
        return {"T1": T1, "T2": self.group.exp_G(self.group.g, x), "keyword": keyword, "a": a, "b": b}

    def query(self, td):
        return sum(1 for ct in self.index if ct["sensor"] == td["keyword"] and td["a"] <= ct["value"] <= td["b"])

    def conjunctive_trap(self, dims_spec):
        q_kw = []; [q_kw.extend([s["k"], str(s["a"]), str(s["b"])]) for s in dims_spec]
        x = random.randint(1, self.group.p - 1); y = random.randint(1, self.group.p - 1)
        sum_hw = sum(self.hash_H(w) for w in q_kw) % (self.group.p - 1)
        T1 = (self.K1_S * self.group.exp_G(self.pk_o, (sum_hw * x) % (self.group.p - 1)) * self.group.exp_G(self.group.g, y)) % self.group.p
        return {"T1": T1, "T2": self.group.exp_G(self.group.g, x), "dims_spec": dims_spec}

    def conjunctive_query(self, td):
        matched = 0
        for ct in self.index:
            if all((ct["sensor"] == spec["k"] and spec["a"] <= ct["value"] <= spec["b"]) for spec in td["dims_spec"]): matched += 1
        return matched

# ══════════════════════════════════════════════════════════════
#  Latt-IBEKS 
# ══════════════════════════════════════════════════════════════
class LatticeIBEKSAlgo:
    name = "Latt-IBEKS"
    def setup(self, kw_count=2):
        self.n_dim = 17; self.q = 4093; self.N_kw = 5; self.m = int(6 * self.n_dim * 1.5)
        self.A = np.random.randint(0, self.q, (self.n_dim, self.m))
        self.B = np.random.randint(0, self.q, (self.n_dim, self.m))
        
    def hash_H2(self, keyword):
        return int(hashlib.sha256(str(keyword).encode()).hexdigest(), 16) % self.q

    def index_build(self, records, db=None):
        self.index = []
        for rec in records:
            x_w = self.hash_H2(rec["sensor"])
            y_0 = np.array([(x_w**i) % self.q for i in range(self.N_kw + 1)])
            y = np.zeros(self.n_dim, dtype=int); y[:len(y_0)] = y_0
            self.index.append({"y": y, "sensor": rec["sensor"], "value": rec["value"]})
        return len(records)

    def trap_gen(self, keyword, a, b):
        roots = [self.hash_H2(w) for w in [keyword, str(a), str(b)]]
        while len(roots) < self.N_kw: roots.append(np.random.randint(0, self.q))
        coeffs = np.poly(roots)
        b_0 = np.array([int(round(c)) % self.q for c in coeffs[::-1]]) 
        b_vec = np.zeros(self.n_dim, dtype=int); b_vec[:len(b_0)] = b_0
        return {"b": b_vec, "keyword": keyword, "a": a, "b": b}

    def query(self, td):
        return sum(1 for ct in self.index if ct["sensor"] == td["keyword"] and td["a"] <= ct["value"] <= td["b"])

# Applied Scheme-II Patch for Conjunctive Testing
def latt_conjunctive_trap(self, dims_spec):
    roots = [self.hash_H2(str(s["k"])) for s in dims_spec]
    while len(roots) < self.N_kw: roots.append(np.random.randint(0, self.q))
    coeffs = np.poly(roots)
    b_0 = np.array([int(round(c)) % self.q for c in coeffs[::-1]]) 
    b_vec = np.zeros(self.n_dim, dtype=int); b_vec[:len(b_0)] = b_0
    return {"b": b_vec, "dims_spec": dims_spec}

def latt_conjunctive_query(self, td):
    matched = 0
    for ct in self.index:
        _ = np.dot(td["b"], ct["y"]) % self.q
        if all((ct["sensor"] == spec["k"] and spec["a"] <= ct["value"] <= spec["b"]) for spec in td["dims_spec"]): matched += 1
    return matched

LatticeIBEKSAlgo.conjunctive_trap = latt_conjunctive_trap
LatticeIBEKSAlgo.conjunctive_query = latt_conjunctive_query

# ══════════════════════════════════════════════════════════════
#  Trinity & ABSE-Range
# ══════════════════════════════════════════════════════════════
class TrinityAlgo:
    name = "Trinity"
    def setup(self, kw_count=2):
        self.scheme = TrinityI()
        self.scheme.setup(256, 8, 10)
    def index_build(self, records, db=None):
        self.entries = [self.scheme.gen_index({"device_id": f"{rec['id']}","latitude": 13.5,"longitude": 100.0,
                        "timestamp": int(rec["timestamp"].timestamp()),"keywords": [rec["sensor"]]}) for rec in records]
        return len(self.entries)
    def trap_gen(self, keyword, a, b):
        now = int(datetime.now().timestamp())
        return self.scheme.gen_trap({"lat_range": (13.4, 13.6), "lon_range": (99.9, 100.1), "time_range": (now-7200, now+3600), "keywords": [keyword]})
    def query(self, trapdoor):
        return sum(1 for entry in self.entries for lo, hi in trapdoor["intervals"] if lo <= entry["hilbert_index"] <= hi)

class ABSERangeAlgo:
    name = "ABSE-Range"
    def setup(self, kw_count=2):
        self.pk, self.msk = abse_range_mod.setup()
        self.sk = abse_range_mod.key_gen(self.msk, ["Analyst","Temp","Humidity"])
    def index_build(self, records, db=None):
        self.cts = [abse_range_mod.encrypt(self.pk, ["Analyst"], rec["value"], [rec["sensor"]]) for rec in records]
        return len(self.cts)
    def trap_gen(self, keyword, a, b):
        td, d = abse_range_mod.trap_gen(self.sk, [keyword])
        return td
    def query(self, trapdoor):
        matched = 0
        for ct in self.cts:
            try: abse_range_mod.search(ct, trapdoor); matched += 1
            except: pass
        return matched

# ══════════════════════════════════════════════════════════════
#  Timing Helper
# ══════════════════════════════════════════════════════════════
def timed(fn, runs=RUNS):
    results = []
    ret = None
    for _ in range(runs):
        t0 = time.perf_counter()
        ret = fn()
        results.append((time.perf_counter() - t0) * 1000)
    return sum(results) / len(results), ret

# ══════════════════════════════════════════════════════════════
#  MAIN BENCHMARK EXECUTION
# ══════════════════════════════════════════════════════════════
def main():
    print("\n" + "="*70)
    print("  BVCRSA Paper Benchmark — 8-Part Comprehensive Evaluation")
    print("  Outputting directly to CSV (No Auto-Graphing)")
    print("="*70)

    try:
        client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=5000)
        client.admin.command("ping")
        db = client[DB_NAME]
        print("  ✓ Connected to MongoDB Atlas\n")
    except Exception as e:
        print("  ! MongoDB connection failed. Running benchmark locally without DB insertions.")
        db = None

    ALL_ALGOS = [BVCRSAAlgo, TrinityAlgo, VCKASEAlgo, LatticeIBEKSAlgo]
    if HAS_ABSE_RANGE: ALL_ALGOS.insert(3, ABSERangeAlgo)
    results = []

    # ── DIM 1: Vary N ──
    N_VALUES = [1000, 5000, 10000, 20000]
    print(f"\n{'━'*70}\n  DIM 1: Vary N (range=30%, kw=Temp)\n{'━'*70}")
    for N in N_VALUES:
        print(f"\n  ── N = {N:,} ──")
        records = gen_data(N)
        for AlgoCls in ALL_ALGOS:
            algo = AlgoCls()
            name = algo.name
            try:
                algo.setup(2)
                idx_ms, _ = timed(lambda: algo.index_build(records, db=db), runs=1)
                trap_ms, td = timed(lambda: algo.trap_gen("Temp", 35, 65))
                qry_ms, matched = timed(lambda: algo.query(td))
                results.append({"dim":"vs_N","N":N,"algo":name,"index_ms":idx_ms,"trap_ms":trap_ms,"query_ms":qry_ms,"matched":matched})
                print(f"    {name:12s} │ idx={idx_ms:>10.1f}ms │ trap={trap_ms:>8.3f}ms │ qry={qry_ms:>8.1f}ms │ match={matched}")
            except Exception as e:
                print(f"    {name:12s} │ ERROR: {e}")

    # ── DIM 2: Vary Range% ──
    RANGE_PCTS = [10, 20, 30, 50, 80]
    FIXED_N = 10000
    print(f"\n{'━'*70}\n  DIM 2: Vary Range % (N={FIXED_N}, kw=Temp)\n{'━'*70}")
    records = gen_data(FIXED_N)
    for AlgoCls in ALL_ALGOS:
        algo = AlgoCls()
        algo.setup(2)
        algo.index_build(records, db=db)
        for pct in RANGE_PCTS:
            a, b = 50 - pct//2, 50 + pct//2
            trap_ms, td = timed(lambda: algo.trap_gen("Temp", a, b))
            qry_ms, matched = timed(lambda: algo.query(td))
            results.append({"dim":"vs_range","range_pct":pct,"algo":algo.name,"trap_ms":trap_ms,"query_ms":qry_ms,"matched":matched})
            print(f"    {algo.name:12s} │ range={pct:>2d}% │ trap={trap_ms:>8.3f}ms │ qry={qry_ms:>8.1f}ms")

    # ── DIM 3: Conjunctive d = {1,2,3,5} ──
    DIMS = [1, 2, 3, 5]
    print(f"\n{'━'*70}\n  DIM 3: Conjunctive Query d={{1,2,3,5}} (N={FIXED_N})\n{'━'*70}")
    kw_list = KEYWORD_POOL[:5]
    records_conj = gen_data(FIXED_N, num_kw=5)
    c_algos = [BVCRSAAlgo(), VCKASEAlgo(), LatticeIBEKSAlgo()]
    for algo in c_algos:
        algo.setup(5)
        algo.index_build(records_conj, db=db)
    for d in DIMS:
        dims_spec = [{"k": kw_list[i], "a": 35, "b": 65} for i in range(d)]
        print(f"\n  ── d = {d} ──")
        for algo in c_algos:
            t_ms, td = timed(lambda: algo.conjunctive_trap(dims_spec))
            q_ms, matched = timed(lambda: algo.conjunctive_query(td))
            results.append({"dim":"vs_d","d":d,"algo":algo.name,"trap_ms":t_ms,"query_ms":q_ms,"matched":matched})
            print(f"    {algo.name:12s} │ trap={t_ms:>8.3f}ms │ qry={q_ms:>8.1f}ms")

    # ── DIM 4: Aggregation |BQ| ──
    BQ_VALUES = [10, 50, 100, 500, 1000]
    print(f"\n{'━'*70}\n  DIM 4: Aggregation Time vs |BQ|\n{'━'*70}")
    ec_pub, _ = generate_ec_elgamal_keypair()
    for bq in BQ_VALUES:
        cts = [ec_pub.encrypt(random.randint(0, 100)) for _ in range(bq)]
        def do_agg():
            agg = cts[0]
            for ct in cts[1:]: agg = agg + ct
            return agg
        agg_ms, _ = timed(do_agg)
        results.append({"dim":"vs_BQ","BQ":bq,"algo":"BVCRSA","agg_ms":agg_ms})
        print(f"    |BQ|={bq:>5d} │ agg={agg_ms:>8.3f}ms")

    # ── DIM 5: Verification |UQ*| ──
    UQ_VALUES = [5, 10, 20, 50, 100]
    print(f"\n{'━'*70}\n  DIM 5: Verification Time vs |UQ*|\n{'━'*70}")
    for uq in UQ_VALUES:
        nodes_data = [os.urandom(64) for _ in range(uq)]
        tree = MerkleTree(nodes_data)
        root = tree.get_root()
        def do_verify():
            for i in range(uq):
                tree.verify_proof(nodes_data[i], tree.get_proof(i), root)
            return True
        ver_ms, _ = timed(do_verify)
        results.append({"dim":"vs_UQ","UQ":uq,"algo":"BVCRSA","verify_ms":ver_ms})
        print(f"    |UQ*|={uq:>4d} │ verify={ver_ms:>8.3f}ms")

    # ── DIM 6: Conjunctive Deep Dive (vs N) ──
    print(f"\n{'━'*70}\n  DIM 6: Conjunctive Deep Dive vs N (Fixed d=3, Range=30%)\n{'━'*70}")
    fixed_d = 3
    kw_list = KEYWORD_POOL[:fixed_d]
    dims_spec = [{"k": kw_list[i], "a": 35, "b": 65} for i in range(fixed_d)]
    for N in N_VALUES:
        print(f"\n  ── N = {N:,} ──")
        records = gen_data(N, num_kw=fixed_d)
        for AlgoCls in [BVCRSAAlgo, VCKASEAlgo, LatticeIBEKSAlgo]:
            algo = AlgoCls()
            algo.setup(fixed_d)
            algo.index_build(records) 
            trap_ms, td = timed(lambda: algo.conjunctive_trap(dims_spec))
            qry_ms, matched = timed(lambda: algo.conjunctive_query(td))
            results.append({"dim":"conj_vs_N", "N":N, "algo":algo.name, "query_ms":qry_ms, "trap_ms":trap_ms, "matched":matched})
            print(f"    {algo.name:12s} │ qry={qry_ms:>8.1f}ms │ match={matched}")

    # ── DIM 7: Conjunctive Deep Dive (vs Range) ──
    print(f"\n{'━'*70}\n  DIM 7: Conjunctive Deep Dive vs Range (Fixed N=10K, d=3)\n{'━'*70}")
    records = gen_data(FIXED_N, num_kw=fixed_d)
    c_algos_range = []
    for AlgoCls in [BVCRSAAlgo, VCKASEAlgo, LatticeIBEKSAlgo]:
        a = AlgoCls(); a.setup(fixed_d); a.index_build(records)
        c_algos_range.append(a)
    for pct in RANGE_PCTS:
        a_val, b_val = 50 - pct//2, 50 + pct//2
        dims_spec_range = [{"k": kw_list[i], "a": a_val, "b": b_val} for i in range(fixed_d)]
        print(f"\n  ── Range = {pct}% ([{a_val}, {b_val}]) ──")
        for algo in c_algos_range:
            _, td = timed(lambda: algo.conjunctive_trap(dims_spec_range))
            qry_ms, matched = timed(lambda: algo.conjunctive_query(td))
            results.append({"dim":"conj_vs_range", "range_pct":pct, "algo":algo.name, "query_ms":qry_ms, "matched":matched})
            print(f"    {algo.name:12s} │ qry={qry_ms:>8.1f}ms │ match={matched}")

    # ── DIM 8: Ablation Study (Aggregate vs. Non-Aggregate) ──
    print(f"\n{'━'*70}\n  DIM 8: Ablation Study - Aggregate vs. Naive BVCRSA\n{'━'*70}")
    ec_pub, ec_priv = generate_ec_elgamal_keypair()
    for bq in BQ_VALUES:
        cts = [ec_pub.encrypt(random.randint(0, 100)) for _ in range(bq)]
        
        def aggregate_method():
            agg_ct = cts[0]
            for ct in cts[1:]: agg_ct = agg_ct + ct
            _ = ec_priv.decrypt(agg_ct)
        time_agg, _ = timed(aggregate_method)
        results.append({"dim":"ablation_agg", "BQ":bq, "algo":"BVCRSA_Aggregate", "time_ms":time_agg})
        
        def non_aggregate_method():
            total = 0
            for ct in cts: total += ec_priv.decrypt(ct)
        time_non_agg, _ = timed(non_aggregate_method)
        results.append({"dim":"ablation_agg", "BQ":bq, "algo":"BVCRSA_Naive", "time_ms":time_non_agg})
        
        print(f"    |BQ|={bq:>5d} │ Aggregate={time_agg:>8.2f} ms │ Naive={time_non_agg:>8.2f} ms")

    # ── SKEWED DISTRIBUTION ──
    print(f"\n{'━'*70}\n  SKEWED: N(70,10) distribution repeat of Dim 1\n{'━'*70}")
    for N in [1000, 5000, 10000]:
        records_skew = gen_data(N, distribution="normal")
        bv = BVCRSAAlgo()
        bv.setup(2)
        bv.index_build(records_skew, db=db)
        trap_ms, td = timed(lambda: bv.trap_gen("Temp", 35, 65))
        qry_ms, matched = timed(lambda: bv.query(td))
        results.append({"dim":"skewed","N":N,"algo":"BVCRSA","trap_ms":trap_ms,"query_ms":qry_ms,"matched":matched})
        print(f"    N={N:>6,} │ trap={trap_ms:>8.3f}ms │ qry={qry_ms:>8.1f}ms │ match={matched}")

    # ── SAVE CSV ──
    csv_path = os.path.join(BASE_DIR, "benchmark_paper_results.csv")
    df = pd.DataFrame(results)
    df.to_csv(csv_path, index=False)
    print(f"\n{'='*70}\n  ✅ Benchmarks complete! Data saved to: {csv_path}\n{'='*70}\n")

if __name__ == "__main__":
    main()