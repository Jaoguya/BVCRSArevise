#!/usr/bin/env python3
"""
Re-run ONLY kw=20 for Trinity-II and MHRQ (the two with fake round numbers).
AC-SCRAT, EPBRQ, Trinity-I already have real data. EPRQ+ excluded (no keyword support).
"""
import sys, os, time, csv
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from benchmark_comprehensive import (
    MONGO_URI, DB_NAME, COLLS, KEYWORD_POOL,
    generate_plaintext,
    insert_trinity_ii, insert_mhrq,
    query_trinity_ii, query_mhrq,
)
from trinity import TrinityII
from mhrq_graph import mhrq_setup
from pymongo import MongoClient

N_FIXED = 2000
KW_TARGET = 20
REPEATS = 3

print(f"\n{'='*60}")
print(f"  Re-running kw={KW_TARGET} for Trinity-II & MHRQ ONLY")
print(f"  (these had fake round numbers)")
print(f"  N={N_FIXED}, range=[35,65], {REPEATS} repeats averaged")
print(f"{'='*60}\n")

client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=15000, socketTimeoutMS=120000)
client.admin.command('ping')
db = client[DB_NAME]
print("  ✓ MongoDB connected\n")

records = generate_plaintext(N_FIXED, num_keywords=len(KEYWORD_POOL))

# Setup ONLY Trinity-II and MHRQ
ctx_t2 = {"scheme": TrinityII()}; ctx_t2["scheme"].setup(256, 8, 10)
ctx_m = dict(zip(["KPi", "sigma", "EDB", "sk"], mhrq_setup(n=8)))

cfgs = [
    ("Trinity-II", ctx_t2, insert_trinity_ii, query_trinity_ii),
    ("MHRQ",       ctx_m,  insert_mhrq,       query_mhrq),
]

# Insert data for these two only
print("  Inserting data...")
for name, ctx, ins_fn, _ in cfgs:
    db[COLLS[name]].delete_many({})
    t0 = time.perf_counter()
    ins_fn(db, records, ctx)
    ms = (time.perf_counter() - t0) * 1000
    print(f"    {name:12s}: {ms:.0f}ms")

# Query kw=20, averaged over REPEATS
print(f"\n  Querying kw={KW_TARGET} ({REPEATS} repeats)...")
query_kws = KEYWORD_POOL[:KW_TARGET]

results = {}
for name, ctx, _, qry_fn in cfgs:
    all_trap = []
    all_query = []
    last_matched = 0
    
    for rep in range(REPEATS):
        total_trap = 0.0
        total_query = 0.0
        total_matched = 0
        
        for kw in query_kws:
            r = qry_fn(db, ctx, 35, 65, keyword=kw)
            total_trap += r["trap_ms"]
            total_query += r["query_ms"]
            total_matched += r["matched"]
        
        all_trap.append(total_trap)
        all_query.append(total_query)
        last_matched = total_matched
        print(f"    {name:12s} rep {rep+1}/{REPEATS}: trap={total_trap:.3f}ms qry={total_query:.3f}ms match={total_matched}")
    
    avg_trap = sum(all_trap) / len(all_trap)
    avg_query = sum(all_query) / len(all_query)
    results[name] = {
        "trap_ms": avg_trap,
        "query_ms": avg_query,
        "total_ms": avg_trap + avg_query,
        "matched": last_matched,
    }
    print(f"    → AVG: trap={avg_trap:.3f}ms qry={avg_query:.3f}ms\n")

# Patch the CSV
csv_file = "bench_dim3_vs_keywords.csv"
print(f"\n  Patching {csv_file}...")

rows = []
with open(csv_file) as f:
    reader = csv.reader(f)
    header = next(reader)
    for row in reader:
        rows.append(row)

col_map = {h: idx for idx, h in enumerate(header)}

# Find kw=20 row
kw20_row = None
for i, row in enumerate(rows):
    if float(row[0]) == 20:
        kw20_row = i
        break

if kw20_row is None:
    print("  ❌ kw=20 row not found!"); sys.exit(1)

for algo, r in results.items():
    trap_col = col_map.get(f"{algo}_trap_ms")
    query_col = col_map.get(f"{algo}_query_ms")
    total_col = col_map.get(f"{algo}_total_ms")
    
    if trap_col is not None:
        old_t = rows[kw20_row][trap_col]
        old_q = rows[kw20_row][query_col]
        rows[kw20_row][trap_col] = str(r["trap_ms"])
        rows[kw20_row][query_col] = str(r["query_ms"])
        rows[kw20_row][total_col] = str(r["total_ms"])
        print(f"    {algo:12s}: trap {old_t} → {r['trap_ms']:.3f}")
        print(f"    {'':12s}  qry  {old_q} → {r['query_ms']:.3f}")

with open(csv_file, "w", newline="") as f:
    writer = csv.writer(f)
    writer.writerow(header)
    for row in rows:
        writer.writerow(row)

print(f"\n  ✅ {csv_file} updated with REAL measurements!")
client.close()
print("  Done.")
