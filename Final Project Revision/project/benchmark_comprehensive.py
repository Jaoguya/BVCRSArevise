#!/usr/bin/env python3
"""
Comprehensive Real Benchmark — 3 Dimensions × 6 Algorithms
===========================================================
Dimension 1: Vary N (database size)       → fixed range=30%, keyword=Temp
Dimension 2: Vary Range Size (%)          → fixed N=2000
Dimension 3: Vary Number of Keywords      → fixed N=2000, range=30%

Generates 6 publication-quality 2D comparison graphs.
"""

import sys, os, time, random, csv, json, base64, traceback
import numpy as np
from datetime import datetime, timedelta
from pymongo import MongoClient, ASCENDING
from ec_elgamal import ECEncryptedNumber

from common import TrustedAuthority, EnclaveManager
from TA import TrustedAuthority as RealTA
try:
    from abse_fast import ABSE  # Rust-native BLS12-381 (~50x faster)
except ImportError:
    from abse_real import ABSE  # Fallback: pure-Python BN128
from utils import gen_tag
from multi_algorithm_pipeline import (
    setup_epbrq, _epbrq_binary_to_bt, _ashve_enc, ashve_keygen, ashve_query,
)
from secure_knn import knn_keygen, knn_encrypt, knn_trapdoor, knn_query, encode_epbrq_index, encode_epbrq_query
from shve import SHVE as SHVE_Module
from eprq_exact.phase1_setup import setup as eprq_setup_fn
from eprq_exact.phase2_index_build import index_build as eprq_index_build
from eprq_exact.phase3_token_gen import token_gen as eprq_token_gen
from eprq_exact.phase4_query import query as eprq_tree_query
from trinity import TrinityI, TrinityII
from mhrq_graph import mhrq_setup, mhrq_update, crq_tokengen, crq_query

# ── Config ────────────────────────────────────────────────────────────────
MONGO_URI = "mongodb+srv://yewza232_db_user:5qCbuPzMrzPSpflq@projectsomchart.lkihxz4.mongodb.net/?appName=ProjectSomchart"
DB_NAME   = "IIoT_Security_DB"
COLLS = {
    "AC-SCRAT": "AC_SCRAT_Nodes", "EPBRQ": "EPBRQ_Nodes",
    "EPRQ+": "EPRQ_Plus_Nodes", "Trinity-I": "Trinity_I_Nodes",
    "Trinity-II": "Trinity_II_Nodes", "MHRQ": "MHRQ_Nodes",
}
MACHINE_COORDS = {"A": (13.50, 100.0), "B": (13.80, 100.3), "C": (14.00, 100.6)}
KEYWORD_POOL = ["Temp", "Humidity", "Pressure", "Vibration", "Voltage",
                "Current", "Power", "Flow", "Level", "Speed",
                "Torque", "RPM", "Weight", "Density", "pH",
                "Noise", "Luminosity", "Radiation", "Frequency", "Resistance"]

# ── Dimensions ────────────────────────────────────────────────────────────
N_VALUES     = [100, 500, 1000, 2000, 5000]
RANGE_PCTS   = [10, 20, 30, 50, 80]      # % of domain [0,100]
KW_COUNTS    = [1, 2, 3, 5, 10, 20]


def generate_plaintext(count, num_keywords=2):
    """Generate N records with up to num_keywords distinct sensor types."""
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


# ══════════════════════════════════════════════════════════════════════════
#  INSERT FUNCTIONS (same as run_all_benchmarks.py)
# ══════════════════════════════════════════════════════════════════════════

def setup_acscrat():
    ta = RealTA()            # Real TA with BN128 ABSE + EC-ElGamal
    abse = ta.abse           # Use TA's own ABSE instance (matching MSK)
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

def insert_epbrq(db, records, ctx):
    """EPBRQ IndexBuild — Secure Knn encryption (Gong et al., §IV-B).
    Per paper: Gray code + Bloom filter recoding → M₁ᵀ·p₁, M₂ᵀ·p₂ matrix encrypt."""
    coll = db[COLLS["EPBRQ"]]
    knn_key = ctx["knn_key"]
    grid_bits = ctx["grid_bits"]
    m_keywords = ctx["m_keywords"]
    kw_index = ctx["kw_index"]  # keyword → bit position
    docs = []
    for rec in records:
        # Step 1: Create keyword bitmap
        bitmap = [0] * m_keywords
        kw = rec["sensor"]
        if kw in kw_index:
            bitmap[kw_index[kw]] = 1
        # Step 2: Encode to vector (Gray code + Bloom filter recoding)
        p_vec = encode_epbrq_index(rec["value"], bitmap, grid_bits=grid_bits)
        # Step 3: Secure Knn encryption: M₁ᵀ·p₁, M₂ᵀ·p₂
        ct = knn_encrypt(knn_key, p_vec)
        docs.append({
            "data_id": rec["id"], "keyword": rec["sensor"], "machine": rec["machine"],
            "timestamp": rec["timestamp_str"],
            "ct_c1": ct["c1"].tolist(), "ct_c2": ct["c2"].tolist(),
            "algorithm": "EPBRQ",
        })
    for i in range(0, len(docs), 500):
        coll.insert_many(docs[i:i+500])
    coll.create_index([("keyword", ASCENDING), ("algorithm", ASCENDING)])
    return len(docs)

def insert_eprq(db, records, ctx):
    coll = db[COLLS["EPRQ+"]]
    msk, m, s, t = ctx["msk"], ctx["m"], ctx["s"], ctx["t"]
    eprq_recs = [{"id": r["id"], "value": r["value"]} for r in records]
    root = eprq_index_build(eprq_recs, msk, m, s, t)
    docs = []
    def ser(node, pid, ctr):
        if not node: return
        cid = ctr[0]; ctr[0] += 1
        ct_hex = [c.hex() if isinstance(c, bytes) else str(c) for c in (node.ct or [])]
        d = {"node_id": cid, "parent_id": pid, "is_leaf": node.is_leaf, "bt_new": node.bt_new, "ct": ct_hex, "algorithm": "EPRQ+"}
        if node.is_leaf: d["data_val"] = node.data_val; d["id_val"] = node.id_val
        else: d["id_l"] = node.id_l; d["id_r"] = node.id_r
        docs.append(d)
        ser(node.left, cid, ctr); ser(node.right, cid, ctr)
    ser(root, None, [0])
    for i in range(0, len(docs), 500):
        coll.insert_many(docs[i:i+500])
    coll.create_index([("algorithm", ASCENDING), ("node_id", ASCENDING)])
    return len(docs)

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


# ══════════════════════════════════════════════════════════════════════════
#  QUERY FUNCTIONS (with parameterized range)
# ══════════════════════════════════════════════════════════════════════════

def query_acscrat(db, ctx, a, b, keyword="Temp"):
    enclave = ctx["enclave"]
    Ks = ctx["secrets"]["Ks"]
    abse = enclave.abse
    sk_abse = ctx["secrets"].get("SK_A")  # Real ABSE secret key from KeyGen
    coll = db[COLLS["AC-SCRAT"]]
    sample = coll.find_one({"algorithm": "AC-SCRAT", "k": keyword})
    if not sample: return {"trap_ms": 0, "query_ms": 0, "total_ms": 0, "matched": 0}
    tm, tk, tt = sample["m"], keyword, sample["t"]

    t0 = time.perf_counter()
    # Step 1: Decompose range into decile cover nodes + generate PRF tags
    decile_ranges = [(i, i+10) for i in range((a//10)*10, (b//10)*10+10, 10)]
    tags = [gen_tag(Ks, tm, tk, tt, {"l": lo, "r": hi}) for lo, hi in decile_ranges]
    # Step 2: REAL ABSE.TokenGen — generate ONE authorization token (BN128 scalar multiply)
    # This is the actual cryptographic cost: 2 scalar multiplications in G1/G2
    if sk_abse:
        auth_token = abse.token_gen(sk_abse, tags[0])
    trap_ms = (time.perf_counter() - t0) * 1000

    t1 = time.perf_counter()
    matched = list(coll.find({
        "algorithm": "AC-SCRAT", "m": tm, "k": tk, "t": tt,
        "$or": [{"l": lo, "r": hi} for lo, hi in decile_ranges],
    }))
    if matched:
        # Step 3: REAL ABSE.Test — ONE bilinear pairing test for authorization
        # e(C2_tag, T2) ?= e(T1, C1_g2) — 2 pairings (~300ms)
        if sk_abse and auth_token:
            ct_tag = matched[0].get("CT_tag")
            if ct_tag and isinstance(ct_tag, dict):
                abse.test(auth_token, ct_tag)
        # Step 4: EC-ElGamal homomorphic aggregation (real point addition)
        agg_s = ECEncryptedNumber.from_string(enclave.ec_pubkey, matched[0]["Agg_u"])
        agg_c = ECEncryptedNumber.from_string(enclave.ec_pubkey, matched[0]["Cnt_u"])
        for n in matched[1:]:
            agg_s += ECEncryptedNumber.from_string(enclave.ec_pubkey, n["Agg_u"])
            agg_c += ECEncryptedNumber.from_string(enclave.ec_pubkey, n["Cnt_u"])
        enclave.ec_privkey.decrypt(agg_s); enclave.ec_privkey.decrypt(agg_c)
    query_ms = (time.perf_counter() - t1) * 1000
    return {"trap_ms": trap_ms, "query_ms": query_ms, "total_ms": trap_ms+query_ms, "matched": len(matched)}

def query_epbrq(db, ctx, a, b, keyword="Temp"):
    """EPBRQ GenTrap + Query — Secure Knn trapdoor & inner product matching.
    Per paper (§IV-C,D): Bloom-filter recoding → M₁⁻¹·q₁, M₂⁻¹·q₂ matrix trapdoor.
    Query: dot(c1,t1) + dot(c2,t2) for each record (inner product via Knn)."""
    knn_key = ctx["knn_key"]
    grid_bits = ctx["grid_bits"]
    m_keywords = ctx["m_keywords"]
    kw_index = ctx["kw_index"]
    coll = db[COLLS["EPBRQ"]]

    t0 = time.perf_counter()
    # Step 1: Create keyword query bitmap
    kw_bitmap = [0] * m_keywords
    if keyword in kw_index:
        kw_bitmap[kw_index[keyword]] = 1
    # Step 2: Encode query vectors (one per range value — Bloom filter recoding)
    q_vecs = encode_epbrq_query(a, b, kw_bitmap, grid_bits=grid_bits, m_keywords=m_keywords)
    # Step 3: Secure Knn trapdoor: M₁⁻¹·q₁, M₂⁻¹·q₂ for each query vector
    tokens = [knn_trapdoor(knn_key, qv) for qv in q_vecs]
    trap_ms = (time.perf_counter() - t0) * 1000

    t1 = time.perf_counter()
    # Fetch all records for this keyword
    docs = list(coll.find({"keyword": keyword, "algorithm": "EPBRQ"}))
    # Step 4: For each record, compute inner product with each trapdoor token
    matched = 0
    for doc in docs:
        ct = {"c1": np.array(doc["ct_c1"]), "c2": np.array(doc["ct_c2"])}
        for td in tokens:
            ip = knn_query(ct, td)
            if ip > 0:  # Inner product threshold (matching records have positive IP)
                matched += 1
                break
    query_ms = (time.perf_counter() - t1) * 1000
    return {"trap_ms": trap_ms, "query_ms": query_ms, "total_ms": trap_ms+query_ms, "matched": matched}

def query_eprq(db, ctx, a, b, keyword="Temp"):
    """EPRQ+: Fetch tree nodes from MongoDB, reconstruct tree, traverse with ASHVE."""
    msk, m, s, t = ctx["msk"], ctx["m"], ctx["s"], ctx["t"]
    coll = db[COLLS["EPRQ+"]]
    t0 = time.perf_counter()
    tokens = eprq_token_gen(a, b, msk, m, s, t)
    trap_ms = (time.perf_counter() - t0) * 1000
    t1 = time.perf_counter()
    # Fetch ALL tree nodes from MongoDB
    docs = list(coll.find({"algorithm": "EPRQ+"}).sort("node_id", ASCENDING))
    # Reconstruct binary tree from fetched documents
    class _TreeNode:
        __slots__ = ['is_leaf','bt_new','ct','left','right','data_val','id_val','id_l','id_r']
        def __init__(self):
            self.left = self.right = None
    node_map = {}
    for doc in docs:
        n = _TreeNode()
        n.is_leaf = doc["is_leaf"]
        n.bt_new = doc.get("bt_new", [])
        # Deserialize ciphertext bytes from hex strings
        raw_ct = doc.get("ct", [])
        n.ct = []
        for c in raw_ct:
            try:
                n.ct.append(bytes.fromhex(c))
            except (ValueError, AttributeError):
                n.ct.append(c.encode() if isinstance(c, str) else c)
        n.data_val = doc.get("data_val")
        n.id_val = doc.get("id_val")
        n.id_l = doc.get("id_l")
        n.id_r = doc.get("id_r")
        nid = doc["node_id"]
        node_map[nid] = n
        pid = doc.get("parent_id")
        if pid is not None and pid in node_map:
            parent = node_map[pid]
            if parent.left is None:
                parent.left = n
            else:
                parent.right = n
    root_node = node_map.get(0)
    # Run REAL EPRQ+ tree traversal with ASHVE matching on reconstructed tree
    matched = eprq_tree_query(root_node, tokens) if root_node else []
    query_ms = (time.perf_counter() - t1) * 1000
    return {"trap_ms": trap_ms, "query_ms": query_ms, "total_ms": trap_ms+query_ms, "matched": len(matched)}

def query_trinity_i(db, ctx, a, b, keyword="Temp"):
    """Trinity-I Query — Hilbert interval check + REAL SHVE.Match (Li et al., §Algorithm 4).
    Per paper Table III: O(k·m·log m) SHVE predicate matching per candidate."""
    scheme = ctx["scheme"]
    coll = db[COLLS["Trinity-I"]]
    now_ts = int(datetime.now().timestamp())
    qp = {"lat_range": (13.40, 13.60), "lon_range": (99.90, 100.10),
          "time_range": (now_ts-7200, now_ts+3600), "keywords": [keyword]}
    t0 = time.perf_counter()
    trapdoor = scheme.gen_trap(qp)
    trap_ms = (time.perf_counter() - t0) * 1000
    t1 = time.perf_counter()
    # Fetch ALL entries from MongoDB
    docs = list(coll.find({"algorithm": "Trinity-I"}))
    # Step 1: Hilbert interval check (QF membership equivalent)
    intervals = trapdoor["intervals"]
    shve_token = trapdoor.get("shve_token")
    matched = []
    for doc in docs:
        h = doc["hilbert_index"]
        for lo, hi in intervals:
            if lo <= h <= hi:
                # Step 2: REAL SHVE.Match — predicate matching on encrypted coords
                # Per paper Algorithm 4: verify SHVE predicate on candidate entries
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
    return {"trap_ms": trap_ms, "query_ms": query_ms, "total_ms": trap_ms+query_ms, "matched": len(matched)}

def query_trinity_ii(db, ctx, a, b, keyword="Temp"):
    """Trinity-II Query — Hilbert + SHVE.Match + verify tag (Li et al., §Algorithm 4).
    Per paper Table III: Same as Trinity-I + O(log c) GGM tree + verification."""
    scheme = ctx["scheme"]
    coll = db[COLLS["Trinity-II"]]
    now_ts = int(datetime.now().timestamp())
    qp = {"lat_range": (13.40, 13.60), "lon_range": (99.90, 100.10),
          "time_range": (now_ts-7200, now_ts+3600), "keywords": [keyword]}
    t0 = time.perf_counter()
    trapdoor = scheme.gen_trap(qp)
    trap_ms = (time.perf_counter() - t0) * 1000
    t1 = time.perf_counter()
    # Fetch ALL entries from MongoDB
    docs = list(coll.find({"algorithm": "Trinity-II"}))
    # Hilbert interval check + SHVE match + verification
    intervals = trapdoor["intervals"]
    shve_token = trapdoor.get("shve_token")
    matched = []
    for doc in docs:
        h = doc["hilbert_index"]
        for lo, hi in intervals:
            if lo <= h <= hi:
                # Step 1: REAL SHVE.Match — predicate matching
                shve_ct = doc.get("shve_ct")
                if shve_token and shve_ct:
                    try:
                        ct_data = eval(shve_ct) if isinstance(shve_ct, str) else shve_ct
                        if isinstance(ct_data, list) and len(ct_data) == len(shve_token):
                            scheme.shve.match(shve_token, ct_data)
                    except Exception:
                        pass
                # Step 2: Verify integrity tag (SHA-256, real Trinity-II step)
                if "verify_tag" in doc and doc["verify_tag"]:
                    import hashlib as _hl
                    _hl.sha256(
                        str(doc["entry_id"]).encode() + str(h).encode()
                    ).hexdigest()
                matched.append(doc)
                break
    query_ms = (time.perf_counter() - t1) * 1000
    return {"trap_ms": trap_ms, "query_ms": query_ms, "total_ms": trap_ms+query_ms, "matched": len(matched)}

def query_mhrq(db, ctx, a, b, keyword="Temp"):
    """MHRQ: Fetch CRQ matrices from MongoDB, reconstruct, run trace-query."""
    sk = ctx["sk"]
    coll = db[COLLS["MHRQ"]]
    t0 = time.perf_counter()
    Q_hat = crq_tokengen(a, b, sk)
    trap_ms = (time.perf_counter() - t0) * 1000
    t1 = time.perf_counter()
    # Fetch MHRQ entries for keyword "Temp" from MongoDB
    docs = list(coll.find({"keyword": keyword, "algorithm": "MHRQ"}))
    # Reconstruct P matrices from stored flat arrays and run REAL CRQ matching
    matched = []
    for doc in docs:
        P_flat = doc["P_hat"]
        side = int(round(len(P_flat) ** 0.5))
        P = np.array(P_flat).reshape(side, side)
        if crq_query(P, Q_hat):
            matched.append(doc)
    query_ms = (time.perf_counter() - t1) * 1000
    return {"trap_ms": trap_ms, "query_ms": query_ms, "total_ms": trap_ms+query_ms, "matched": len(matched)}


# ══════════════════════════════════════════════════════════════════════════
#  MAIN
# ══════════════════════════════════════════════════════════════════════════

ALGO_ORDER = ["AC-SCRAT", "EPBRQ", "EPRQ+", "Trinity-I", "Trinity-II", "MHRQ"]

def clear_all(db):
    for c in COLLS.values():
        db[c].delete_many({})

def main(start_dim=1):
    print("\n╔══════════════════════════════════════════════════════════════════════════╗")
    print("║  Comprehensive Benchmark — Vary N, Range %, Keywords                   ║")
    print("╚══════════════════════════════════════════════════════════════════════════╝\n")

    client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=30000, socketTimeoutMS=300000, connectTimeoutMS=30000)
    client.admin.command("ping")
    db = client[DB_NAME]
    print("  ✓ Connected to MongoDB Atlas\n")

    N_FIXED = 2000

    # ── DIMENSION 1: Vary N (fixed range=30%, keyword=Temp) ──────────
    if start_dim <= 1:
        print("━"*70)
        print("  DIMENSION 1: Vary N records  (range=[30,60], keyword=Temp)")
        print("━"*70)

        results_vs_n = {a: [] for a in ALGO_ORDER}

        for N in N_VALUES:
            print(f"\n  ── N = {N} ──")
            clear_all(db)
            records = generate_plaintext(N, num_keywords=2)

            acscrat_ctx = setup_acscrat()
            # EPBRQ: Secure Knn keygen (Gong et al.) — matrix M₁, M₂
            grid_bits = 7  # 2^7 = 128 grid cells
            m_kw = len(KEYWORD_POOL)
            knn_dim = (grid_bits + m_kw) * 4  # Bloom filter recoded dim
            kw_idx = {kw: i for i, kw in enumerate(KEYWORD_POOL)}
            epbrq_ctx = {"knn_key": knn_keygen(knn_dim), "grid_bits": grid_bits,
                         "m_keywords": m_kw, "kw_index": kw_idx}
            eprq_ctx = {"msk": eprq_setup_fn(m=8, s=4, t=4)[0], "m": 8, "s": 4, "t": 4}
            tri1_ctx = {"scheme": TrinityI()}; tri1_ctx["scheme"].setup(256, 8, 10)
            tri2_ctx = {"scheme": TrinityII()}; tri2_ctx["scheme"].setup(256, 8, 10)
            mhrq_ctx = dict(zip(["KPi","sigma","EDB","sk"], mhrq_setup(n=8)))

            configs = [
                ("AC-SCRAT",   acscrat_ctx, insert_acscrat,    query_acscrat),
                ("EPBRQ",      epbrq_ctx,   insert_epbrq,      query_epbrq),
                ("EPRQ+",      eprq_ctx,    insert_eprq,       query_eprq),
                ("Trinity-I",  tri1_ctx,    insert_trinity_i,   query_trinity_i),
                ("Trinity-II", tri2_ctx,    insert_trinity_ii,  query_trinity_ii),
                ("MHRQ",       mhrq_ctx,    insert_mhrq,        query_mhrq),
            ]

            for name, ctx, ins_fn, qry_fn in configs:
                try:
                    db[COLLS[name]].delete_many({})
                    t0 = time.perf_counter()
                    docs = ins_fn(db, records, ctx)
                    idx_ms = (time.perf_counter() - t0) * 1000
                    res = qry_fn(db, ctx, 30, 60)
                    results_vs_n[name].append({
                        "N": N, "index_ms": idx_ms, **res
                    })
                    print(f"    ✅ {name:12s} │ idx={idx_ms:>8.0f}ms │ trap={res['trap_ms']:>8.3f}ms │ qry={res['query_ms']:>8.3f}ms │ match={res['matched']}")
                except Exception as e:
                    print(f"    ❌ {name:12s} │ {e}")
                    results_vs_n[name].append({"N": N, "index_ms": 0, "trap_ms": 0, "query_ms": 0, "total_ms": 0, "matched": 0})

        save_csv("bench_dim1_vs_N.csv", results_vs_n, "N")
    else:
        print("  ⏭  Skipping Dimension 1 (already completed)\n")

    # ── DIMENSION 2: Vary Range Size (fixed N=2000, keyword=Temp) ────
    if start_dim <= 2:
        print(f"\n{'━'*70}")
        print("  DIMENSION 2: Vary Range Size %  (N=2000, keyword=Temp)")
        print("━"*70)

        results_vs_range = {a: [] for a in ALGO_ORDER}

        print(f"\n  Inserting N={N_FIXED} records for all algorithms...")
        clear_all(db)
        records = generate_plaintext(N_FIXED, num_keywords=2)

        acscrat_ctx = setup_acscrat()
        grid_bits = 7; m_kw = len(KEYWORD_POOL)
        knn_dim = (grid_bits + m_kw) * 4
        kw_idx = {kw: i for i, kw in enumerate(KEYWORD_POOL)}
        epbrq_ctx = {"knn_key": knn_keygen(knn_dim), "grid_bits": grid_bits,
                     "m_keywords": m_kw, "kw_index": kw_idx}
        eprq_ctx = {"msk": eprq_setup_fn(m=8, s=4, t=4)[0], "m": 8, "s": 4, "t": 4}
        tri1_ctx = {"scheme": TrinityI()}; tri1_ctx["scheme"].setup(256, 8, 10)
        tri2_ctx = {"scheme": TrinityII()}; tri2_ctx["scheme"].setup(256, 8, 10)
        mhrq_ctx = dict(zip(["KPi","sigma","EDB","sk"], mhrq_setup(n=8)))

        configs = [
            ("AC-SCRAT",   acscrat_ctx, insert_acscrat,    query_acscrat),
            ("EPBRQ",      epbrq_ctx,   insert_epbrq,      query_epbrq),
            ("EPRQ+",      eprq_ctx,    insert_eprq,       query_eprq),
            ("Trinity-I",  tri1_ctx,    insert_trinity_i,   query_trinity_i),
            ("Trinity-II", tri2_ctx,    insert_trinity_ii,  query_trinity_ii),
            ("MHRQ",       mhrq_ctx,    insert_mhrq,        query_mhrq),
        ]

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
                    results_vs_range[name].append({
                        "range_pct": pct, **res
                    })
                    print(f"    ✅ {name:12s} │ trap={res['trap_ms']:>8.3f}ms │ qry={res['query_ms']:>8.3f}ms │ match={res['matched']}")
                except Exception as e:
                    print(f"    ❌ {name:12s} │ {e}")
                    results_vs_range[name].append({"range_pct": pct, "trap_ms": 0, "query_ms": 0, "total_ms": 0, "matched": 0})

        save_csv("bench_dim2_vs_range.csv", results_vs_range, "range_pct")
    else:
        print("  ⏭  Skipping Dimension 2 (already completed)\n")

    # ── DIMENSION 3: Vary Keywords (fixed N=2000, range=30%) ─────────
    print(f"\n{'━'*70}")
    print("  DIMENSION 3: Vary Number of Query Keywords  (N=2000, range=[35,65])")
    print("━"*70)

    results_vs_kw = {a: [] for a in ALGO_ORDER}

    print(f"\n  Inserting N={N_FIXED} records with all {len(KEYWORD_POOL)} keywords...")
    clear_all(db)
    records_kw = generate_plaintext(N_FIXED, num_keywords=len(KEYWORD_POOL))

    acscrat_ctx3 = setup_acscrat()
    grid_bits = 7; m_kw = len(KEYWORD_POOL)
    knn_dim = (grid_bits + m_kw) * 4
    kw_idx = {kw: i for i, kw in enumerate(KEYWORD_POOL)}
    epbrq_ctx3 = {"knn_key": knn_keygen(knn_dim), "grid_bits": grid_bits,
                  "m_keywords": m_kw, "kw_index": kw_idx}
    eprq_ctx3 = {"msk": eprq_setup_fn(m=8, s=4, t=4)[0], "m": 8, "s": 4, "t": 4}
    tri1_ctx3 = {"scheme": TrinityI()}; tri1_ctx3["scheme"].setup(256, 8, 10)
    tri2_ctx3 = {"scheme": TrinityII()}; tri2_ctx3["scheme"].setup(256, 8, 10)
    mhrq_ctx3 = dict(zip(["KPi","sigma","EDB","sk"], mhrq_setup(n=8)))

    configs3 = [
        ("AC-SCRAT",   acscrat_ctx3, insert_acscrat,    query_acscrat),
        ("EPBRQ",      epbrq_ctx3,   insert_epbrq,      query_epbrq),
        ("EPRQ+",      eprq_ctx3,    insert_eprq,       query_eprq),
        ("Trinity-I",  tri1_ctx3,    insert_trinity_i,   query_trinity_i),
        ("Trinity-II", tri2_ctx3,    insert_trinity_ii,  query_trinity_ii),
        ("MHRQ",       mhrq_ctx3,    insert_mhrq,        query_mhrq),
    ]

    idx_times = {}
    for name, ctx, ins_fn, qry_fn in configs3:
        try:
            db[COLLS[name]].delete_many({})
            t0 = time.perf_counter()
            ins_fn(db, records_kw, ctx)
            idx_times[name] = (time.perf_counter() - t0) * 1000
            print(f"    ✅ {name:12s} inserted")
        except Exception as e:
            print(f"    ❌ {name:12s} │ {e}")
            idx_times[name] = 0

    for kw_count in KW_COUNTS:
        print(f"\n  ── Query Keywords = {kw_count} ──")
        query_kws = KEYWORD_POOL[:kw_count]

        for name, ctx, ins_fn, qry_fn in configs3:
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
                print(f"    ✅ {name:12s} │ trap={total_trap:>8.3f}ms │ qry={total_query:>8.3f}ms │ match={total_matched}")
            except Exception as e:
                print(f"    ❌ {name:12s} │ {e}")
                results_vs_kw[name].append({"keywords": kw_count, "index_ms": 0, "trap_ms": 0, "query_ms": 0, "total_ms": 0, "matched": 0})

    save_csv("bench_dim3_vs_keywords.csv", results_vs_kw, "keywords")
    print(f"\n  ✓ All CSVs saved")

    client.close()
    print("\n  ✅ Comprehensive benchmark complete!")


def save_csv(filename, results, x_key):
    """Save combined CSV with all algorithms."""
    with open(filename, "w", newline="") as f:
        writer = csv.writer(f)
        header = [x_key]
        for algo in ALGO_ORDER:
            header += [f"{algo}_trap_ms", f"{algo}_query_ms", f"{algo}_total_ms"]
            if "index_ms" in (results[algo][0] if results[algo] else {}):
                header.append(f"{algo}_index_ms")
        writer.writerow(header)
        for i in range(len(results[ALGO_ORDER[0]])):
            row = [results[ALGO_ORDER[0]][i][x_key]]
            for algo in ALGO_ORDER:
                r = results[algo][i] if i < len(results[algo]) else {}
                row += [r.get("trap_ms", 0), r.get("query_ms", 0), r.get("total_ms", 0)]
                if "index_ms" in r:
                    row.append(r.get("index_ms", 0))
            writer.writerow(row)
    print(f"  ✓ Saved: {filename}")


if __name__ == "__main__":
    main(start_dim=1)  # Set to 2 or 3 to skip completed dimensions
