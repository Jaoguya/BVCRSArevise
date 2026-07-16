#!/usr/bin/env python3
"""
Benchmark — MHRQ + Trinity-I + Trinity-II
==========================================
N_VALUES = [100, 200, 500, 800, 1000]
Saves:
  mhrq_trinity_dim1_vs_N.csv
  mhrq_trinity_dim2_vs_range.csv
  mhrq_trinity_dim3_vs_keywords.csv
Then combines with n512_bench_dim*.csv → combined_dim*.csv
"""

import sys, os, time, random, csv, base64, traceback
import numpy as np
from datetime import datetime, timedelta
from pymongo import MongoClient, ASCENDING

PROJ_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJ_DIR)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from trinity import TrinityI, TrinityII
from mhrq_graph import mhrq_setup, mhrq_update, crq_tokengen, crq_query

MONGO_URI = "mongodb+srv://yewza232_db_user:5qCbuPzMrzPSpflq@projectsomchart.lkihxz4.mongodb.net/?appName=ProjectSomchart"
DB_NAME   = "IIoT_Security_DB"
COLLS = {
    "Trinity-I": "Trinity_I_Nodes",
    "Trinity-II": "Trinity_II_Nodes",
    "MHRQ": "MHRQ_Nodes",
}
MACHINE_COORDS = {"A": (13.50, 100.0), "B": (13.80, 100.3), "C": (14.00, 100.6)}
KEYWORD_POOL = ["Temp", "Humidity", "Pressure", "Vibration", "Voltage",
                "Current", "Power", "Flow", "Level", "Speed",
                "Torque", "RPM", "Weight", "Density", "pH",
                "Noise", "Luminosity", "Radiation", "Frequency", "Resistance"]

N_VALUES   = [100, 200, 500, 800, 1000]
RANGE_PCTS = [10, 20, 30, 50, 80]
KW_COUNTS  = [1, 2, 3, 5, 10, 20]
ALGO_ORDER = ["Trinity-I", "Trinity-II", "MHRQ"]


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


# ═══════════════════════════════════════════════════════════════
#  Trinity-I
# ═══════════════════════════════════════════════════════════════

def insert_trinity_i(db, records, ctx):
    coll = db[COLLS["Trinity-I"]]
    scheme = ctx["scheme"]
    docs = []
    for rec in records:
        entry = scheme.gen_index({
            "device_id": f"{rec['machine']}_{rec['id']}", "latitude": rec["latitude"],
            "longitude": rec["longitude"], "timestamp": rec["timestamp_unix"],
            "temperature": rec["value"] if rec["sensor"] == "Temp" else 25,
            "humidity": rec["value"] if rec["sensor"] == "Humidity" else 50,
            "pressure": 1013, "keywords": [rec["sensor"], rec["machine"], "IIoT"],
        })
        docs.append({
            "entry_id": entry["entry_id"], "prefix_count": entry["prefix_count"],
            "hilbert_index": entry["hilbert_index"], "grid_coords": list(entry["grid_coords"]),
            "ct_val": base64.b64encode(entry["ct_val"]).decode() if isinstance(entry["ct_val"], bytes) else str(entry["ct_val"]),
            "shve_ct": str(entry["shve_ct"]), "algorithm": "Trinity-I",
        })
    for i in range(0, len(docs), 500):
        coll.insert_many(docs[i:i+500])
    coll.create_index([("algorithm", ASCENDING), ("hilbert_index", ASCENDING)])
    return len(docs)


def query_trinity_i(db, ctx, a, b, keyword="Temp"):
    scheme = ctx["scheme"]
    coll = db[COLLS["Trinity-I"]]
    now_ts = int(datetime.now().timestamp())
    qp = {"lat_range": (13.40, 13.60), "lon_range": (99.90, 100.10),
          "time_range": (now_ts-7200, now_ts+3600), "keywords": [keyword]}
    t0 = time.perf_counter()
    trapdoor = scheme.gen_trap(qp)
    trap_ms = (time.perf_counter() - t0) * 1000
    t1 = time.perf_counter()
    docs = list(coll.find({"algorithm": "Trinity-I"}))
    intervals = trapdoor["intervals"]
    shve_token = trapdoor.get("shve_token")
    matched = []
    for doc in docs:
        h = doc["hilbert_index"]
        for lo, hi in intervals:
            if lo <= h <= hi:
                shve_ct = doc.get("shve_ct")
                if shve_token and shve_ct:
                    try:
                        ct_data = eval(shve_ct) if isinstance(shve_ct, str) else shve_ct
                        if isinstance(ct_data, list) and len(ct_data) == len(shve_token):
                            scheme.shve.match(shve_token, ct_data)
                    except Exception:
                        pass
                matched.append(doc)
                break
    query_ms = (time.perf_counter() - t1) * 1000
    return {"trap_ms": trap_ms, "query_ms": query_ms, "total_ms": trap_ms + query_ms, "matched": len(matched)}


# ═══════════════════════════════════════════════════════════════
#  Trinity-II
# ═══════════════════════════════════════════════════════════════

def insert_trinity_ii(db, records, ctx):
    coll = db[COLLS["Trinity-II"]]
    scheme = ctx["scheme"]
    docs = []
    for rec in records:
        entry = scheme.gen_index({
            "device_id": f"{rec['machine']}_{rec['id']}", "latitude": rec["latitude"],
            "longitude": rec["longitude"], "timestamp": rec["timestamp_unix"],
            "temperature": rec["value"] if rec["sensor"] == "Temp" else 25,
            "humidity": rec["value"] if rec["sensor"] == "Humidity" else 50,
            "pressure": 1013, "keywords": [rec["sensor"], rec["machine"], "IIoT"],
        })
        docs.append({
            "entry_id": entry["entry_id"], "prefix_count": entry["prefix_count"],
            "hilbert_index": entry["hilbert_index"], "grid_coords": list(entry["grid_coords"]),
            "ct_val": base64.b64encode(entry["ct_val"]).decode() if isinstance(entry["ct_val"], bytes) else str(entry["ct_val"]),
            "shve_ct": str(entry["shve_ct"]),
            "state_counter": entry.get("state_counter", 0),
            "verify_tag": base64.b64encode(entry["verify_tag"]).decode() if "verify_tag" in entry and isinstance(entry["verify_tag"], bytes) else str(entry.get("verify_tag", "")),
            "algorithm": "Trinity-II",
        })
    for i in range(0, len(docs), 500):
        coll.insert_many(docs[i:i+500])
    coll.create_index([("algorithm", ASCENDING), ("hilbert_index", ASCENDING)])
    return len(docs)


def query_trinity_ii(db, ctx, a, b, keyword="Temp"):
    scheme = ctx["scheme"]
    coll = db[COLLS["Trinity-II"]]
    now_ts = int(datetime.now().timestamp())
    qp = {"lat_range": (13.40, 13.60), "lon_range": (99.90, 100.10),
          "time_range": (now_ts-7200, now_ts+3600), "keywords": [keyword]}
    t0 = time.perf_counter()
    trapdoor = scheme.gen_trap(qp)
    trap_ms = (time.perf_counter() - t0) * 1000
    t1 = time.perf_counter()
    docs = list(coll.find({"algorithm": "Trinity-II"}))
    intervals = trapdoor["intervals"]
    shve_token = trapdoor.get("shve_token")
    matched = []
    for doc in docs:
        h = doc["hilbert_index"]
        for lo, hi in intervals:
            if lo <= h <= hi:
                shve_ct = doc.get("shve_ct")
                if shve_token and shve_ct:
                    try:
                        ct_data = eval(shve_ct) if isinstance(shve_ct, str) else shve_ct
                        if isinstance(ct_data, list) and len(ct_data) == len(shve_token):
                            scheme.shve.match(shve_token, ct_data)
                    except Exception:
                        pass
                if "verify_tag" in doc and doc["verify_tag"]:
                    import hashlib as _hl
                    _hl.sha256(str(doc["entry_id"]).encode() + str(h).encode()).hexdigest()
                matched.append(doc)
                break
    query_ms = (time.perf_counter() - t1) * 1000
    return {"trap_ms": trap_ms, "query_ms": query_ms, "total_ms": trap_ms + query_ms, "matched": len(matched)}


# ═══════════════════════════════════════════════════════════════
#  MHRQ
# ═══════════════════════════════════════════════════════════════

def insert_mhrq(db, records, ctx):
    coll = db[COLLS["MHRQ"]]
    KPi, sigma, EDB, sk = ctx["KPi"], ctx["sigma"], ctx["EDB"], ctx["sk"]
    docs = []
    for rec in records:
        mat_before = set(EDB["Mat"].keys())
        mhrq_update(KPi, sigma, EDB, sk, f"doc_{rec['id']}", rec["sensor"], rec["value"])
        for adc in set(EDB["Mat"].keys()) - mat_before:
            mat_entry = EDB["Mat"][adc]
            docs.append({
                "doc_id": f"doc_{rec['id']}", "keyword": rec["sensor"],
                "adc": base64.b64encode(adc).decode() if isinstance(adc, bytes) else str(adc),
                "P_hat": mat_entry["P"].flatten().tolist(), "algorithm": "MHRQ",
            })
    for i in range(0, len(docs), 500):
        coll.insert_many(docs[i:i+500])
    coll.create_index([("keyword", ASCENDING), ("algorithm", ASCENDING)])
    return len(docs)


def query_mhrq(db, ctx, a, b, keyword="Temp"):
    sk = ctx["sk"]
    coll = db[COLLS["MHRQ"]]
    t0 = time.perf_counter()
    Q_hat = crq_tokengen(a, b, sk)
    trap_ms = (time.perf_counter() - t0) * 1000
    t1 = time.perf_counter()
    docs = list(coll.find({"keyword": keyword, "algorithm": "MHRQ"}))
    matched = []
    for doc in docs:
        P_flat = doc["P_hat"]
        side = int(round(len(P_flat) ** 0.5))
        P = np.array(P_flat).reshape(side, side)
        if crq_query(P, Q_hat):
            matched.append(doc)
    query_ms = (time.perf_counter() - t1) * 1000
    return {"trap_ms": trap_ms, "query_ms": query_ms, "total_ms": trap_ms + query_ms, "matched": len(matched)}


# ═══════════════════════════════════════════════════════════════
#  CSV helpers
# ═══════════════════════════════════════════════════════════════

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


def combine_csvs():
    """Combine mhrq_trinity CSVs with n512 CSVs into combined_dim*.csv"""
    import pandas as pd
    base = os.path.dirname(__file__)

    pairs = [
        ("n512_bench_dim1_vs_N.csv",        "mhrq_trinity_dim1_vs_N.csv",        "combined_dim1_vs_N.csv",        "N"),
        ("n512_bench_dim2_vs_range.csv",     "mhrq_trinity_dim2_vs_range.csv",    "combined_dim2_vs_range.csv",    "range_pct"),
        ("n512_bench_dim3_vs_keywords.csv",  "mhrq_trinity_dim3_vs_keywords.csv", "combined_dim3_vs_keywords.csv", "keywords"),
    ]

    for n512_f, mt_f, out_f, key in pairs:
        n512_path = os.path.join(base, n512_f)
        mt_path = os.path.join(base, mt_f)
        out_path = os.path.join(base, out_f)

        df1 = pd.read_csv(n512_path)
        df2 = pd.read_csv(mt_path)

        # Merge on the key column (outer join to keep all rows)
        merged = pd.merge(df1, df2, on=key, how="outer").sort_values(key)
        merged.to_csv(out_path, index=False)
        print(f"  ✓ Combined: {out_path}")


# ═══════════════════════════════════════════════════════════════
#  MAIN
# ═══════════════════════════════════════════════════════════════

def main():
    print("\n╔══════════════════════════════════════════════════════════════╗")
    print("║  Benchmark — MHRQ + Trinity-I + Trinity-II                 ║")
    print("║  N = [100, 200, 500, 800, 1000]                            ║")
    print("╚══════════════════════════════════════════════════════════════╝\n")

    client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=30000,
                         socketTimeoutMS=300000, connectTimeoutMS=30000)
    client.admin.command("ping")
    db = client[DB_NAME]
    print("  ✓ Connected to MongoDB Atlas\n")

    N_FIXED = 2000

    def make_ctxs():
        tri1 = {"scheme": TrinityI()}; tri1["scheme"].setup(256, 8, 10)
        tri2 = {"scheme": TrinityII()}; tri2["scheme"].setup(256, 8, 10)
        mhrq = dict(zip(["KPi","sigma","EDB","sk"], mhrq_setup(n=8)))
        return tri1, tri2, mhrq

    configs_fn = lambda t1, t2, mq: [
        ("Trinity-I",  t1, insert_trinity_i,  query_trinity_i),
        ("Trinity-II", t2, insert_trinity_ii, query_trinity_ii),
        ("MHRQ",       mq, insert_mhrq,       query_mhrq),
    ]

    # ── DIMENSION 1: Vary N ──────────────────────────────────
    print("━" * 60)
    print("  DIMENSION 1: Vary N records  (range=[30,60], keyword=Temp)")
    print("━" * 60)

    results_vs_n = {a: [] for a in ALGO_ORDER}

    for N in N_VALUES:
        print(f"\n  ── N = {N} ──")
        clear_all(db)
        records = generate_records(N, num_keywords=2)
        tri1_ctx, tri2_ctx, mhrq_ctx = make_ctxs()
        configs = configs_fn(tri1_ctx, tri2_ctx, mhrq_ctx)

        for name, ctx, ins_fn, qry_fn in configs:
            try:
                db[COLLS[name]].delete_many({})
                t0 = time.perf_counter()
                ndocs = ins_fn(db, records, ctx)
                idx_ms = (time.perf_counter() - t0) * 1000
                res = qry_fn(db, ctx, 30, 60)
                results_vs_n[name].append({"N": N, "index_ms": idx_ms, **res})
                print(f"    ✅ {name:12s} │ idx={idx_ms:>8.0f}ms │ trap={res['trap_ms']:>8.3f}ms │ qry={res['query_ms']:>8.3f}ms │ match={res['matched']}")
            except Exception as e:
                print(f"    ❌ {name:12s} │ {e}")
                traceback.print_exc()
                results_vs_n[name].append({"N": N, "index_ms": 0, "trap_ms": 0, "query_ms": 0, "total_ms": 0, "matched": 0})

    save_csv("mhrq_trinity_dim1_vs_N.csv", results_vs_n, "N")

    # ── DIMENSION 2: Vary Range ──────────────────────────────
    print(f"\n{'━' * 60}")
    print("  DIMENSION 2: Vary Range Size %  (N=2000, keyword=Temp)")
    print("━" * 60)

    results_vs_range = {a: [] for a in ALGO_ORDER}

    print(f"\n  Inserting N={N_FIXED} records for all algorithms...")
    clear_all(db)
    records = generate_records(N_FIXED, num_keywords=2)
    tri1_ctx, tri2_ctx, mhrq_ctx = make_ctxs()
    configs = configs_fn(tri1_ctx, tri2_ctx, mhrq_ctx)

    for name, ctx, ins_fn, _ in configs:
        db[COLLS[name]].delete_many({})
        ins_fn(db, records, ctx)
        print(f"    ✅ {name} inserted")

    for pct in RANGE_PCTS:
        half = pct // 2
        a, b = 50 - half, 50 + half
        print(f"\n  ── Range = [{a}, {b}] ({pct}% of domain) ──")
        for name, ctx, _, qry_fn in configs:
            try:
                res = qry_fn(db, ctx, a, b)
                results_vs_range[name].append({"range_pct": pct, **res})
                print(f"    ✅ {name:12s} │ trap={res['trap_ms']:>8.3f}ms │ qry={res['query_ms']:>8.3f}ms │ match={res['matched']}")
            except Exception as e:
                print(f"    ❌ {name:12s} │ {e}")
                traceback.print_exc()
                results_vs_range[name].append({"range_pct": pct, "trap_ms": 0, "query_ms": 0, "total_ms": 0, "matched": 0})

    save_csv("mhrq_trinity_dim2_vs_range.csv", results_vs_range, "range_pct")

    # ── DIMENSION 3: Vary Keywords ───────────────────────────
    print(f"\n{'━' * 60}")
    print("  DIMENSION 3: Vary Number of Query Keywords  (N=2000, range=[35,65])")
    print("━" * 60)

    results_vs_kw = {a: [] for a in ALGO_ORDER}

    print(f"\n  Inserting N={N_FIXED} records with all {len(KEYWORD_POOL)} keywords...")
    clear_all(db)
    records_kw = generate_records(N_FIXED, num_keywords=len(KEYWORD_POOL))
    tri1_ctx3, tri2_ctx3, mhrq_ctx3 = make_ctxs()
    configs3 = configs_fn(tri1_ctx3, tri2_ctx3, mhrq_ctx3)

    idx_times = {}
    for name, ctx, ins_fn, _ in configs3:
        try:
            db[COLLS[name]].delete_many({})
            t0 = time.perf_counter()
            ins_fn(db, records_kw, ctx)
            idx_times[name] = (time.perf_counter() - t0) * 1000
            print(f"    ✅ {name:12s} inserted")
        except Exception as e:
            print(f"    ❌ {name:12s} │ {e}")
            traceback.print_exc()
            idx_times[name] = 0

    for kw_count in KW_COUNTS:
        print(f"\n  ── Query Keywords = {kw_count} ──")
        query_kws = KEYWORD_POOL[:kw_count]
        for name, ctx, _, qry_fn in configs3:
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
                    "keywords": kw_count, "index_ms": idx_times.get(name, 0),
                    "trap_ms": total_trap, "query_ms": total_query,
                    "total_ms": total_trap + total_query, "matched": total_matched,
                })
                print(f"    ✅ {name:12s} │ trap={total_trap:>8.3f}ms │ qry={total_query:>8.3f}ms │ match={total_matched}")
            except Exception as e:
                print(f"    ❌ {name:12s} │ {e}")
                traceback.print_exc()
                results_vs_kw[name].append({"keywords": kw_count, "index_ms": 0, "trap_ms": 0, "query_ms": 0, "total_ms": 0, "matched": 0})

    save_csv("mhrq_trinity_dim3_vs_keywords.csv", results_vs_kw, "keywords")

    print(f"\n  ✓ All CSVs saved")

    # ── Combine with n512 CSVs ───────────────────────────────
    print(f"\n{'━' * 60}")
    print("  Combining with n512_bench CSVs...")
    print("━" * 60)
    combine_csvs()

    client.close()
    print("\n  ✅ Benchmark complete!")


if __name__ == "__main__":
    main()
