#!/usr/bin/env python3
"""Run Dimension 3 — skip EPRQ+ (no keyword support). Averaged over 3 runs."""
import sys, os, time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from benchmark_comprehensive import (
    MONGO_URI, DB_NAME, COLLS, ALGO_ORDER, KEYWORD_POOL, KW_COUNTS,
    generate_plaintext, clear_all, save_csv,
    setup_acscrat, setup_epbrq, insert_acscrat, insert_epbrq,
    insert_trinity_i, insert_trinity_ii, insert_mhrq,
    query_acscrat, query_epbrq, query_trinity_i, query_trinity_ii, query_mhrq,
)
from trinity import TrinityI, TrinityII
from mhrq_graph import mhrq_setup
from pymongo import MongoClient

client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=10000)
client.admin.command('ping')
db = client[DB_NAME]

N_FIXED = 2000
REPEATS = 3

print(f'Inserting N={N_FIXED} with {len(KEYWORD_POOL)} keywords...')
clear_all(db)
records = generate_plaintext(N_FIXED, num_keywords=len(KEYWORD_POOL))

ctx_a = setup_acscrat()
ctx_e = setup_epbrq()
ctx_t1 = {"scheme": TrinityI()}; ctx_t1["scheme"].setup(256, 8, 10)
ctx_t2 = {"scheme": TrinityII()}; ctx_t2["scheme"].setup(256, 8, 10)
ctx_m = dict(zip(["KPi", "sigma", "EDB", "sk"], mhrq_setup(n=8)))

# Skip EPRQ+ — it has no keyword support, unfair comparison
cfgs = [
    ("AC-SCRAT",   ctx_a,  insert_acscrat,    query_acscrat),
    ("EPBRQ",      ctx_e,  insert_epbrq,      query_epbrq),
    ("Trinity-I",  ctx_t1, insert_trinity_i,   query_trinity_i),
    ("Trinity-II", ctx_t2, insert_trinity_ii,  query_trinity_ii),
    ("MHRQ",       ctx_m,  insert_mhrq,        query_mhrq),
]

for n, c, ins, q in cfgs:
    db[COLLS[n]].delete_many({})
    t0 = time.perf_counter()
    ins(db, records, c)
    print(f"  {n}: {(time.perf_counter()-t0)*1000:.0f}ms")

# Query with averaging (EPRQ+ excluded)
DIM3_ALGOS = ["AC-SCRAT", "EPBRQ", "Trinity-I", "Trinity-II", "MHRQ"]
results = {a: [] for a in DIM3_ALGOS}
for kc in KW_COUNTS:
    print(f"\n--- kw={kc} (avg {REPEATS}) ---")
    kws = KEYWORD_POOL[:kc]
    for n, c, _, qf in cfgs:
        all_trap = []; all_query = []; last_m = 0
        for rep in range(REPEATS):
            tt = tq = tm = 0
            for kw in kws:
                r = qf(db, c, 35, 65, keyword=kw)
                tt += r["trap_ms"]; tq += r["query_ms"]; tm += r["matched"]
            all_trap.append(tt); all_query.append(tq); last_m = tm
        at = sum(all_trap) / len(all_trap)
        aq = sum(all_query) / len(all_query)
        results[n].append({
            "keywords": kc, "index_ms": 0,
            "trap_ms": at, "query_ms": aq,
            "total_ms": at + aq, "matched": last_m,
        })
        print(f"  {n:12s} trap={at:>10.3f}ms qry={aq:>10.3f}ms match={last_m}")

# Save CSV — EPRQ+ gets zeros
full_results = {a: [] for a in ALGO_ORDER}
for a in ALGO_ORDER:
    if a in results:
        full_results[a] = results[a]
    else:
        # EPRQ+ — fill with zeros (excluded from Dim3)
        for kc in KW_COUNTS:
            full_results[a].append({
                "keywords": kc, "index_ms": 0,
                "trap_ms": 0, "query_ms": 0,
                "total_ms": 0, "matched": 0,
            })

save_csv("bench_dim3_vs_keywords.csv", full_results, "keywords")
client.close()
print("\nALL DONE")
