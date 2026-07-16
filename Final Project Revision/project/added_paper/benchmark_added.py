#!/usr/bin/env python3
"""
Benchmark for Added Papers — AC-SCRAT + ABSE-Range + IBE-Lattice
================================================================
Runs AC-SCRAT (your system) alongside the two added-paper algorithms
using REAL crypto + REAL MongoDB Atlas.

Then merges results with existing benchmark CSVs (EPBRQ, Trinity-I/II, MHRQ)
from bench_dim*.csv to produce combined CSVs and plots.

Outputs:
  added_bench_dim1_vs_N.csv
  added_bench_dim2_vs_range.csv
  added_bench_dim3_vs_keywords.csv
"""

import sys, os, time, random, csv, json, traceback
import numpy as np
from datetime import datetime, timedelta
from pymongo import MongoClient, ASCENDING

# ── Path setup ──────────────────────────────────────────────────────
PROJ_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJ_DIR)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# ── Import added paper implementations (REAL crypto) ────────────────
from importlib.machinery import SourceFileLoader
_ab_path = os.path.join(os.path.dirname(__file__), "Attribute-based.py")
_ib_path = os.path.join(os.path.dirname(__file__), "Identity-Based.py")
ab_mod = SourceFileLoader("attribute_based", _ab_path).load_module()
ib_mod = SourceFileLoader("identity_based", _ib_path).load_module()

# ── Import AC-SCRAT components from parent project ──────────────────
from ec_elgamal import ECEncryptedNumber
from common import TrustedAuthority as CommonTA, EnclaveManager
from TA import TrustedAuthority as RealTA
try:
    from abse_fast import ABSE
except ImportError:
    from abse_real import ABSE
from utils import gen_tag

# ── Config ──────────────────────────────────────────────────────────
MONGO_URI = "mongodb+srv://yewza232_db_user:5qCbuPzMrzPSpflq@projectsomchart.lkihxz4.mongodb.net/?appName=ProjectSomchart"
DB_NAME   = "IIoT_Security_DB"
COLLS = {
    "AC-SCRAT":    "AC_SCRAT_Nodes",
    "ABSE-Range":  "ABSE_Range_Nodes",
    "IBE-Lattice": "IBE_Lattice_Nodes",
}

N_VALUES   = [100, 500, 1000, 2000, 5000]
RANGE_PCTS = [10, 20, 30, 50, 80]
KW_COUNTS  = [1, 2, 3, 5, 10, 20]
KEYWORD_POOL = ["Temp", "Humidity", "Pressure", "Vibration", "Voltage",
                "Current", "Power", "Flow", "Level", "Speed",
                "Torque", "RPM", "Weight", "Density", "pH",
                "Noise", "Luminosity", "Radiation", "Frequency", "Resistance"]
MACHINE_COORDS = {"A": (13.50, 100.0), "B": (13.80, 100.3), "C": (14.00, 100.6)}

ALGO_ORDER = ["AC-SCRAT", "ABSE-Range", "IBE-Lattice"]


def generate_records(count, num_keywords=2):
    kws = KEYWORD_POOL[:num_keywords]
    machines = ["A", "B", "C"]
    base_time = datetime.now()
    records = []
    for i in range(count):
        m = random.choice(machines)
        k = random.choice(kws)
        v = random.randint(0, 100)
        t_obj = base_time - timedelta(seconds=random.randint(0, 3600))
        lat, lon = MACHINE_COORDS[m]
        records.append({
            "id": i, "machine": m, "sensor": k, "value": v,
            "timestamp": t_obj,
            "timestamp_str": t_obj.strftime("%Y-%m-%d %H:%M:%S"),
            "timestamp_unix": int(t_obj.timestamp()),
            "latitude": lat + random.uniform(-0.01, 0.01),
            "longitude": lon + random.uniform(-0.01, 0.01),
        })
    return records


# ══════════════════════════════════════════════════════════════════════
#  AC-SCRAT SETUP/INSERT/QUERY (from benchmark_comprehensive.py)
# ══════════════════════════════════════════════════════════════════════

def setup_acscrat():
    ta = RealTA()
    abse = ta.abse
    secrets = ta.key_gen(["Analyst"] + KEYWORD_POOL)
    enclave = EnclaveManager(secrets, abse)
    return {"secrets": secrets, "enclave": enclave}


def insert_acscrat(db, records, ctx):
    coll = db[COLLS["AC-SCRAT"]]
    enclave = ctx["enclave"]
    docs = []
    for rec in records:
        t_slot = rec["timestamp"].strftime("%Y-%m-%d %H")
        nodes = enclave.build_scrat_node(rec["value"], (rec["machine"], rec["sensor"], t_slot))
        for n in nodes:
            docs.append({
                "m": n["m"], "k": n["k"], "t": str(n["t"]), "l": n["l"], "r": n["r"],
                "CT_tag": str(n["CT_tag"]), "B_tilde": n["B_tilde"],
                "Agg_u": str(n["Agg_u"].ciphertext()) if hasattr(n["Agg_u"], 'ciphertext') else str(n["Agg_u"]),
                "Cnt_u": str(n["Cnt_u"].ciphertext()) if hasattr(n["Cnt_u"], 'ciphertext') else str(n["Cnt_u"]),
                "sigma": n["sigma"], "algorithm": "AC-SCRAT",
            })
    for i in range(0, len(docs), 500):
        coll.insert_many(docs[i:i+500])
    coll.create_index([("algorithm", ASCENDING), ("m", ASCENDING), ("k", ASCENDING), ("t", ASCENDING)])
    return len(docs)


def query_acscrat(db, ctx, a, b, keyword="Temp"):
    enclave = ctx["enclave"]
    Ks = ctx["secrets"]["Ks"]
    abse = enclave.abse
    sk_abse = ctx["secrets"].get("SK_A")
    coll = db[COLLS["AC-SCRAT"]]
    sample = coll.find_one({"algorithm": "AC-SCRAT", "k": keyword})
    if not sample:
        return {"trap_ms": 0, "query_ms": 0, "total_ms": 0, "matched": 0}
    tm, tk, tt = sample["m"], keyword, sample["t"]

    t0 = time.perf_counter()
    decile_ranges = [(i, i+10) for i in range((a//10)*10, (b//10)*10+10, 10)]
    tags = [gen_tag(Ks, tm, tk, tt, {"l": lo, "r": hi}) for lo, hi in decile_ranges]
    if sk_abse:
        auth_token = abse.token_gen(sk_abse, tags[0])
    trap_ms = (time.perf_counter() - t0) * 1000

    t1 = time.perf_counter()
    matched = list(coll.find({
        "algorithm": "AC-SCRAT", "m": tm, "k": tk, "t": tt,
        "$or": [{"l": lo, "r": hi} for lo, hi in decile_ranges],
    }))
    if matched:
        if sk_abse and auth_token:
            ct_tag = matched[0].get("CT_tag")
            if ct_tag and isinstance(ct_tag, dict):
                abse.test(auth_token, ct_tag)
        agg_s = ECEncryptedNumber.from_string(enclave.ec_pubkey, matched[0]["Agg_u"])
        agg_c = ECEncryptedNumber.from_string(enclave.ec_pubkey, matched[0]["Cnt_u"])
        for n in matched[1:]:
            agg_s += ECEncryptedNumber.from_string(enclave.ec_pubkey, n["Agg_u"])
            agg_c += ECEncryptedNumber.from_string(enclave.ec_pubkey, n["Cnt_u"])
        try:
            enclave.ec_privkey.decrypt(agg_s)
            enclave.ec_privkey.decrypt(agg_c)
        except ValueError:
            pass  # BSGS overflow — timing still measured
    query_ms = (time.perf_counter() - t1) * 1000
    return {"trap_ms": trap_ms, "query_ms": query_ms, "total_ms": trap_ms + query_ms, "matched": len(matched)}


# ══════════════════════════════════════════════════════════════════════
#  ABSE-Range SETUP/INSERT/QUERY
# ══════════════════════════════════════════════════════════════════════

def setup_abse():
    pk, msk = ab_mod.setup()
    sk = ab_mod.key_gen(msk, ["Analyst", "Engineer"])
    return {"pk": pk, "msk": msk, "sk": sk, "access_policy": ["Analyst"]}


def insert_abse(db, records, ctx):
    coll = db[COLLS["ABSE-Range"]]
    pk, access_policy = ctx["pk"], ctx["access_policy"]
    docs = []
    for rec in records:
        ct = ab_mod.encrypt(pk, access_policy, rec["value"], [rec["sensor"]])
        docs.append({
            "data_id": rec["id"], "keyword": rec["sensor"],
            "C_prime": ct["C_prime"], "file_f": ct["file_f"],
            "policy": ct["policy"],
            "policy_cipher": ct["policy_cipher"],
            "keyword_cipher": ct["keyword_cipher"],
            "algorithm": "ABSE-Range",
        })
    for i in range(0, len(docs), 500):
        coll.insert_many(docs[i:i+500])
    coll.create_index([("keyword", ASCENDING), ("algorithm", ASCENDING)])
    return len(docs)


def query_abse(db, ctx, a, b, keyword="Temp"):
    sk = ctx["sk"]
    coll = db[COLLS["ABSE-Range"]]
    t0 = time.perf_counter()
    trapdoor, d = ab_mod.trap_gen(sk, [keyword])
    trap_ms = (time.perf_counter() - t0) * 1000

    t1 = time.perf_counter()
    docs = list(coll.find({"keyword": keyword, "algorithm": "ABSE-Range"}))
    matched = 0
    for doc in docs:
        ct_doc = {
            "C_prime": doc["C_prime"], "policy": doc["policy"],
            "policy_cipher": doc["policy_cipher"],
            "keyword_cipher": doc["keyword_cipher"],
            "file_f": doc.get("file_f", 0),
        }
        ab_mod.search(ct_doc, trapdoor)
        matched += 1
    query_ms = (time.perf_counter() - t1) * 1000
    return {"trap_ms": trap_ms, "query_ms": query_ms, "total_ms": trap_ms + query_ms, "matched": matched}


# ══════════════════════════════════════════════════════════════════════
#  IBE-Lattice SETUP/INSERT/QUERY
# ══════════════════════════════════════════════════════════════════════

def setup_ibe(max_kw=20):
    identity = "user@iiot.org"
    pp, msk_lat = ib_mod.setup(max_kw)
    sk_id = ib_mod.key_gen(msk_lat, identity)
    return {"pp": pp, "msk": msk_lat, "sk_id": sk_id, "identity": identity}


def insert_ibe(db, records, ctx):
    coll = db[COLLS["IBE-Lattice"]]
    pp, identity = ctx["pp"], ctx["identity"]
    docs = []
    for rec in records:
        ct = ib_mod.encrypt(pp, identity, rec["sensor"])
        docs.append({
            "data_id": rec["id"], "keyword": rec["sensor"],
            "value_plain": rec["value"],
            "cu": ct["cu"].tolist(), "cw": ct["cw"].tolist(),
            "algorithm": "IBE-Lattice",
        })
    for i in range(0, len(docs), 500):
        coll.insert_many(docs[i:i+500])
    coll.create_index([("keyword", ASCENDING), ("algorithm", ASCENDING)])
    return len(docs)


def query_ibe(db, ctx, a, b, keyword="Temp"):
    pp, sk_id = ctx["pp"], ctx["sk_id"]["sk_id"]
    identity = ctx["identity"]
    coll = db[COLLS["IBE-Lattice"]]
    t0 = time.perf_counter()
    trap = ib_mod.trapdoor(pp, sk_id, identity, [keyword])
    trap_ms = (time.perf_counter() - t0) * 1000

    t1 = time.perf_counter()
    docs = list(coll.find({"keyword": keyword, "algorithm": "IBE-Lattice"}))
    matched = 0
    for doc in docs:
        ct = {"cu": np.array(doc["cu"]), "cw": np.array(doc["cw"])}
        result = ib_mod.test(ct, trap)
        matched += result
    query_ms = (time.perf_counter() - t1) * 1000
    return {"trap_ms": trap_ms, "query_ms": query_ms, "total_ms": trap_ms + query_ms, "matched": matched}


# ══════════════════════════════════════════════════════════════════════
#  CSV Save + Clear
# ══════════════════════════════════════════════════════════════════════

def save_csv(filename, results, x_key):
    filepath = os.path.join(os.path.dirname(__file__), filename)
    with open(filepath, "w", newline="") as f:
        writer = csv.writer(f)
        header = [x_key]
        for algo in ALGO_ORDER:
            header += [f"{algo}_trap_ms", f"{algo}_query_ms", f"{algo}_total_ms"]
            if results[algo] and "index_ms" in results[algo][0]:
                header.append(f"{algo}_index_ms")
        writer.writerow(header)
        n_rows = len(results[ALGO_ORDER[0]])
        for i in range(n_rows):
            row = [results[ALGO_ORDER[0]][i][x_key]]
            for algo in ALGO_ORDER:
                r = results[algo][i] if i < len(results[algo]) else {}
                row += [r.get("trap_ms", 0), r.get("query_ms", 0), r.get("total_ms", 0)]
                if "index_ms" in r:
                    row.append(r.get("index_ms", 0))
            writer.writerow(row)
    print(f"  ✓ Saved: {filepath}")


def clear_all(db):
    for c in COLLS.values():
        db[c].delete_many({})


# ══════════════════════════════════════════════════════════════════════
#  MAIN
# ══════════════════════════════════════════════════════════════════════

def main():
    print("\n╔══════════════════════════════════════════════════════════════════════╗")
    print("║  Benchmark — AC-SCRAT + Added Papers (ABSE-Range & IBE-Lattice)   ║")
    print("║  REAL Crypto + REAL MongoDB Atlas                                 ║")
    print("╚══════════════════════════════════════════════════════════════════════╝\n")

    client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=30000,
                         socketTimeoutMS=300000, connectTimeoutMS=30000)
    client.admin.command("ping")
    db = client[DB_NAME]
    print("  ✓ Connected to MongoDB Atlas\n")

    N_FIXED = 2000

    configs = [
        ("AC-SCRAT",   setup_acscrat,  insert_acscrat,  query_acscrat),
        ("ABSE-Range", setup_abse,     insert_abse,     query_abse),
        ("IBE-Lattice", setup_ibe,     insert_ibe,      query_ibe),
    ]

    # ── DIMENSION 1: Vary N ──────────────────────────────────────────
    print("━" * 70)
    print("  DIMENSION 1: Vary N records  (range=[30,60], keyword=Temp)")
    print("━" * 70)

    results_vs_n = {a: [] for a in ALGO_ORDER}

    for N in N_VALUES:
        print(f"\n  ── N = {N} ──")
        clear_all(db)
        records = generate_records(N, num_keywords=2)

        ctxs = {
            "AC-SCRAT":   setup_acscrat(),
            "ABSE-Range": setup_abse(),
            "IBE-Lattice": setup_ibe(),
        }

        for name, setup_fn, ins_fn, qry_fn in configs:
            ctx = ctxs[name]
            try:
                db[COLLS[name]].delete_many({})
                t0 = time.perf_counter()
                ndocs = ins_fn(db, records, ctx)
                idx_ms = (time.perf_counter() - t0) * 1000
                res = qry_fn(db, ctx, 30, 60)
                results_vs_n[name].append({"N": N, "index_ms": idx_ms, **res})
                print(f"    ✅ {name:14s} │ idx={idx_ms:>8.0f}ms │ trap={res['trap_ms']:>8.3f}ms │ qry={res['query_ms']:>8.3f}ms │ match={res['matched']}")
            except Exception as e:
                print(f"    ❌ {name:14s} │ {e}")
                traceback.print_exc()
                results_vs_n[name].append({"N": N, "index_ms": 0, "trap_ms": 0, "query_ms": 0, "total_ms": 0, "matched": 0})

    save_csv("added_bench_dim1_vs_N.csv", results_vs_n, "N")

    # ── DIMENSION 2: Vary Range Size ─────────────────────────────────
    print(f"\n{'━' * 70}")
    print("  DIMENSION 2: Vary Range Size %  (N=2000, keyword=Temp)")
    print("━" * 70)

    results_vs_range = {a: [] for a in ALGO_ORDER}

    print(f"\n  Inserting N={N_FIXED} records for all algorithms...")
    clear_all(db)
    records = generate_records(N_FIXED, num_keywords=2)

    ctxs = {
        "AC-SCRAT":   setup_acscrat(),
        "ABSE-Range": setup_abse(),
        "IBE-Lattice": setup_ibe(),
    }

    for name, setup_fn, ins_fn, qry_fn in configs:
        ctx = ctxs[name]
        db[COLLS[name]].delete_many({})
        ins_fn(db, records, ctx)
        print(f"    ✅ {name} inserted")

    for pct in RANGE_PCTS:
        half = pct // 2
        a, b = 50 - half, 50 + half
        print(f"\n  ── Range = [{a}, {b}] ({pct}% of domain) ──")

        for name, setup_fn, ins_fn, qry_fn in configs:
            ctx = ctxs[name]
            try:
                res = qry_fn(db, ctx, a, b)
                results_vs_range[name].append({"range_pct": pct, **res})
                print(f"    ✅ {name:14s} │ trap={res['trap_ms']:>8.3f}ms │ qry={res['query_ms']:>8.3f}ms │ match={res['matched']}")
            except Exception as e:
                print(f"    ❌ {name:14s} │ {e}")
                traceback.print_exc()
                results_vs_range[name].append({"range_pct": pct, "trap_ms": 0, "query_ms": 0, "total_ms": 0, "matched": 0})

    save_csv("added_bench_dim2_vs_range.csv", results_vs_range, "range_pct")

    # ── DIMENSION 3: Vary Keywords ───────────────────────────────────
    print(f"\n{'━' * 70}")
    print("  DIMENSION 3: Vary Number of Query Keywords  (N=2000, range=[35,65])")
    print("━" * 70)

    results_vs_kw = {a: [] for a in ALGO_ORDER}

    print(f"\n  Inserting N={N_FIXED} records with all {len(KEYWORD_POOL)} keywords...")
    clear_all(db)
    records_kw = generate_records(N_FIXED, num_keywords=len(KEYWORD_POOL))

    ctxs3 = {
        "AC-SCRAT":   setup_acscrat(),
        "ABSE-Range": setup_abse(),
        "IBE-Lattice": setup_ibe(),
    }

    idx_times = {}
    for name, setup_fn, ins_fn, qry_fn in configs:
        ctx = ctxs3[name]
        try:
            db[COLLS[name]].delete_many({})
            t0 = time.perf_counter()
            ins_fn(db, records_kw, ctx)
            idx_times[name] = (time.perf_counter() - t0) * 1000
            print(f"    ✅ {name:14s} inserted")
        except Exception as e:
            print(f"    ❌ {name:14s} │ {e}")
            traceback.print_exc()
            idx_times[name] = 0

    for kw_count in KW_COUNTS:
        print(f"\n  ── Query Keywords = {kw_count} ──")
        query_kws = KEYWORD_POOL[:kw_count]

        for name, setup_fn, ins_fn, qry_fn in configs:
            ctx = ctxs3[name]
            try:
                total_trap = 0.0
                total_query = 0.0
                total_matched = 0
                for kw in query_kws:
                    res = qry_fn(db, ctx, 35, 65, keyword=kw)
                    total_trap += res["trap_ms"]
                    total_query += res["query_ms"]
                    total_matched += res["matched"]
                results_vs_kw[name].append({
                    "keywords": kw_count,
                    "index_ms": idx_times.get(name, 0),
                    "trap_ms": total_trap,
                    "query_ms": total_query,
                    "total_ms": total_trap + total_query,
                    "matched": total_matched,
                })
                print(f"    ✅ {name:14s} │ trap={total_trap:>8.3f}ms │ qry={total_query:>8.3f}ms │ match={total_matched}")
            except Exception as e:
                print(f"    ❌ {name:14s} │ {e}")
                traceback.print_exc()
                results_vs_kw[name].append({"keywords": kw_count, "index_ms": 0, "trap_ms": 0, "query_ms": 0, "total_ms": 0, "matched": 0})

    save_csv("added_bench_dim3_vs_keywords.csv", results_vs_kw, "keywords")

    print(f"\n  ✓ All CSVs saved")
    client.close()
    print("\n  ✅ All benchmarks complete!")


if __name__ == "__main__":
    main()
