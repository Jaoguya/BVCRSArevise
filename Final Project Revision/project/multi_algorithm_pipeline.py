#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════════════════╗
║  Multi-Algorithm IIoT Sensor Pipeline                                      ║
║  Generates plaintext → encrypts via 6 algorithms → stores in MongoDB       ║
╚══════════════════════════════════════════════════════════════════════════════╝

Algorithms:
  1. AC-SCRAT   — Paillier + ABSE + SCRAT tree
  2. EPBRQ      — Paillier + ABSE + SCRAT tree  (separate keys)
  3. EPRQ+      — ASHVE + Binary Tree + Segment Tree encoding
  4. Trinity-I  — SHVE + Hilbert Curve + Quotient Filter
  5. Trinity-II — SHVE + Hilbert + QF + GGM-CPRF  (forward-secure)
  6. MHRQ       — DPRF + CRQ Matrix encryption

Each algorithm's encrypted output is stored in a separate MongoDB collection
under the database: IIoT_Security_DB
"""

import sys
import os
import time
import random
import base64
import hashlib
import struct
import traceback
import numpy as np
from datetime import datetime, timedelta
from pymongo import MongoClient
import json
from phe import paillier

# ── Add algorithm directories to Python path ──────────────────────────────
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(BASE_DIR, "boolean"))
sys.path.insert(0, os.path.join(BASE_DIR, "trinity_algorithm"))
sys.path.insert(0, os.path.join(BASE_DIR, "Paper_35_fix", "Paper_35"))
sys.path.insert(0, os.path.join(BASE_DIR, "health"))

# ── MongoDB Atlas Connection ──────────────────────────────────────────────
MONGO_URI = "mongodb+srv://yewza232_db_user:5qCbuPzMrzPSpflq@projectsomchart.lkihxz4.mongodb.net/?appName=ProjectSomchart"
DB_NAME = "IIoT_Security_DB"

# ── Collection Names ──────────────────────────────────────────────────────
COLLECTIONS = {
    "AC-SCRAT":   "AC_SCRAT_Nodes",
    "EPBRQ":      "EPBRQ_Nodes",
    "EPRQ+":      "EPRQ_Plus_Nodes",
    "Trinity-I":  "Trinity_I_Nodes",
    "Trinity-II": "Trinity_II_Nodes",
    "MHRQ":       "MHRQ_Nodes",
}

# ── Machine → lat/lon mapping for Trinity (spatio-temporal) ──────────────
MACHINE_COORDS = {
    "A": (13.50, 100.0),   # Bangkok area
    "B": (13.80, 100.3),
    "C": (14.00, 100.6),
}


# ════════════════════════════════════════════════════════════════════════════
#  PLAINTEXT DATA GENERATOR
# ════════════════════════════════════════════════════════════════════════════

def generate_plaintext_records(count):
    """
    Generate IIoT sensor plaintext records.
    Fields: id, machine (A/B/C), sensor (Temp/Humidity), timestamp, value (20-95)
    """
    machines = ["A", "B", "C"]
    sensors = ["Temp", "Humidity"]
    records = []

    base_time = datetime.now()

    for i in range(count):
        m = random.choice(machines)
        k = random.choice(sensors)
        v = random.randint(20, 95)
        t = (base_time - timedelta(seconds=random.randint(0, 3600))).strftime(
            "%Y-%m-%d %H:%M:%S"
        )

        records.append({
            "id": i,
            "machine": m,
            "sensor": k,
            "timestamp": t,
            "value": v,
        })

    return records


# ════════════════════════════════════════════════════════════════════════════
#  ALGORITHM 1:  AC-SCRAT  (Paillier + ABSE + SCRAT Tree)
# ════════════════════════════════════════════════════════════════════════════

import json
import os
from phe import paillier

def setup_acscrat():
    """Initialize AC-SCRAT with persistent key storage to allow cross-session decryption."""
    from common import TrustedAuthority, ABSESim, EnclaveManager
    
    KEY_FILE = "acscrat_private_keys.json"
    abse = ABSESim()

    # Check if we have previously saved keys
    if os.path.exists(KEY_FILE):
        print(f"[*] Loading existing AC-SCRAT keys from {KEY_FILE}...")
        with open(KEY_FILE, "r") as f:
            key_data = json.load(f)
        
        # 1. Reconstruct Paillier Public and Private keys from saved components
        # We need p and q to rebuild the private key for decryption
        pub_key = paillier.PaillierPublicKey(n=int(key_data["pub_n"]))
        priv_key = paillier.PaillierPrivateKey(pub_key, int(key_data["p"]), int(key_data["q"]))
        
        # 2. Initialize TA (don't generate new keys) and Enclave
        ta = TrustedAuthority(generate_new=False) 
        secrets = ta.key_gen(["Analyst", "Temp", "Humidity"])
        enclave = EnclaveManager(secrets, abse)
        
        # 3. CRITICAL: Override the session keys with the persistent keys
        enclave.pubkey = pub_key
        enclave.privkey = priv_key
        
    else:
        print("[*] No key file found. Generating NEW AC-SCRAT keys...")
        # Standard initialization
        ta = TrustedAuthority(generate_new=True)
        secrets = ta.key_gen(["Analyst", "Temp", "Humidity"])
        enclave = EnclaveManager(secrets, abse)
        
        # Save these keys so we can use them later
        key_data = {
            "pub_n": enclave.pubkey.n,
            "p": enclave.privkey.p,
            "q": enclave.privkey.q
        }
        with open(KEY_FILE, "w") as f:
            json.dump(key_data, f)
        print(f"[+] Persistent keys saved to {KEY_FILE}")

    return {"ta": ta, "abse": abse, "secrets": secrets, "enclave": enclave}


def process_acscrat(record, ctx):
    """Encrypt one record via AC-SCRAT → 3-level SCRAT nodes (Root/Decile/Leaf)."""
    enclave = ctx["enclave"]
    t_obj = datetime.strptime(record["timestamp"], "%Y-%m-%d %H:%M:%S")
    t_slot = t_obj.strftime("%Y-%m-%d %H")

    nodes = enclave.build_scrat_node(
        record["value"],
        (record["machine"], record["sensor"], t_slot)
    )

    docs = []
    for n in nodes:
        doc = {
            "m": n["m"],
            "k": n["k"],
            "t": str(n["t"]),
            "l": n["l"],
            "r": n["r"],
            "CT_tag": str(n["CT_tag"]),
            "B_tilde": n["B_tilde"],
            "Agg_u": str(n["Agg_u"].ciphertext()),
            "Cnt_u": str(n["Cnt_u"].ciphertext()),
            "sigma": n["sigma"],
            "algorithm": "AC-SCRAT",
        }
        docs.append(doc)
    return docs


# ════════════════════════════════════════════════════════════════════════════
#  ALGORITHM 2:  EPBRQ  (REncoder → binary string → ASHVE)
# ════════════════════════════════════════════════════════════════════════════
 
def setup_epbrq():
    """
    Initialize basic EPBRQ.
 
    Paper §V-A (Liang et al., IEEE TIFS 2024):
      Setup(1^λ): sample msk ← {0,1}^λ, choose positive integer m,
      define hash H:{0,1}*→{0,1}, PRF F, symmetric scheme (Sym.Enc, Sym.Dec),
      additional integer t for ASHVE.  Outputs (msk, m, t).
    """
    from eprq_exact.phase1_setup import setup
    # m=8 gives 8-bit value domain (0-255); s=m means no split (basic EPRQ);
    # t=4 additional positions for ASHVE to hide index length (paper §V-A)
    msk, m, s, t = setup(m=8, s=8, t=4)
    return {"msk": msk, "m": m, "t": t}
 
 
def _epbrq_binary_to_bt(value, m):
    """
    IndexBuild conversion step — Algorithm 1, paper §V-A.
 
    For data d = (o1 o2 … om):
      1. Convert d to m-bit binary.
      2. Initialise a (2^(m+1) − 1)-bit binary string BT to all zeros,
         except BT[0] = 1 (root is always 1).
      3. Traverse an (m+1)-level binary tree top-down following each bit
         (0 → left child, 1 → right child); set every visited node to 1.
         Node numbering is breadth-first order: root = index 0,
         left child of node i = 2i+1, right child of node i = 2i+2.
    Returns BT as a Python list of ints (0/1), length = 2^(m+1) − 1.
    """
    bt_len = (2 ** (m + 1)) - 1
    BT = [0] * bt_len
    BT[0] = 1                            # root node always set to 1
 
    bits = [(value >> (m - 1 - i)) & 1 for i in range(m)]
    node = 0
    for bit in bits:
        child = 2 * node + 1 + bit       # left child = 2i+1, right = 2i+2
        if child < bt_len:
            BT[child] = 1
            node = child
 
    return BT
 
 
def _ashve_enc(msk, BT, t):
    """
    Corrected ASHVE.Enc supporting predicate queries.
    """

    import hashlib, os

    def H(j):
        return int(hashlib.sha256(f"H_{j}".encode()).hexdigest(), 16) & 1

    def F(key, data):
        return hashlib.blake2b(data.encode(), key=key[:32], digest_size=32).digest()

    # Extend vector
    x_prime = BT + [H(j) for j in range(1, t + 1)]

    # Per-record randomness (IMPORTANT)
    r = os.urandom(16).hex()

    ct = []
    for l, xl in enumerate(x_prime):
        # Bind value + position + randomness
        c_l = F(msk, f"{xl}|{l}|{r}")
        ct.append(c_l.hex())

    return {
        "ct": ct,
        "r": r,
        "n": len(x_prime)
    }
 
def ashve_keygen(msk, y_vec):
    """
    Generate query token (trapdoor)

    y_vec: list of {0,1,None}
           None = wildcard (*)
    """

    import hashlib

    def F(key, data):
        return hashlib.blake2b(data.encode(), key=key[:32], digest_size=32).digest()

    token = []

    for l, yl in enumerate(y_vec):
        if yl is None:
            token.append(None)
        else:
            token.append({
                "pos": l,
                "val": yl,
                "key": F(msk, f"{yl}|{l}")
            })

    return token 

def ashve_query(doc, token, msk):
    """
    Test if encrypted record matches query
    """

    import hashlib

    def F(key, data):
        return hashlib.blake2b(data.encode(), key=key[:32], digest_size=32).digest()

    ct = doc["ct"]["ct"]
    r  = doc["ct"]["r"]

    for tk in token:
        if tk is None:
            continue

        l = tk["pos"]
        yl = tk["val"]

        expected = F(msk, f"{yl}|{l}|{r}").hex()

        if ct[l] != expected:
            return False

    return True
def process_epbrq(record, ctx):
    """
    Encrypt one record via basic EPBRQ — Algorithm 1 (IndexBuild), paper §V-A.
 
    Steps (per the paper, §V-A, Algorithm 1):
      Line 3  : Convert value d_i to m-bit binary (o1 o2 … om).
      Lines 5-10: Map d_i to a (2^(m+1) − 1)-bit binary string BT by
                  traversing an (m+1)-level binary tree; set visited nodes
                  to 1, the rest remain 0.  Root node BT[0] is always 1.
      Line 14 : Call ASHVE.Enc(msk, 0, BT_i) to produce the encrypted
                index entry c_i = {c_j}_{j ∈ [2^(m+1)+t−1]}.
 
    The resulting MongoDB document stores:
      - data_id  : record identifier (plaintext, used for result retrieval)
      - keyword  : sensor type — the searchable keyword w
      - machine  : machine label (metadata)
      - timestamp: record timestamp (metadata)
      - value_enc: masked — plaintext value is NOT stored on the server
      - bt_len   : length of BT = 2^(m+1) − 1  (scheme parameter, not secret)
      - ct       : ASHVE ciphertext list of hex strings, length = bt_len + t
      - m, t     : public scheme parameters
      - algorithm: "EPBRQ"
    """
    msk = ctx["msk"]
    m   = ctx["m"]
    t   = ctx["t"]
 
    value = record["value"]               # integer sensor reading, e.g. 20–95
 
    # ── Algorithm 1 lines 2-10: Conversion ───────────────────────────────
    BT = _epbrq_binary_to_bt(value, m)
 
    # ── Algorithm 1 line 14: Encryption via ASHVE.Enc ────────────────────
    ct_obj = _ashve_enc(msk, BT, t)
 
    doc = {
        "data_id":   record["id"],
        "keyword":   record["sensor"],        # searchable keyword w
        "machine":   record["machine"],
        "timestamp": record["timestamp"],
        "value_enc": "***",                   # server never sees plaintext
        "bt_len":    len(BT),                 # = 2^(m+1) − 1
        "ct":        ct_obj,                      # ASHVE ciphertext, length bt_len+t
        "m":         m,
        "t":         t,
        "algorithm": "EPBRQ",
    }
    return [doc]

# ════════════════════════════════════════════════════════════════════════════
#  ALGORITHM 3:  EPRQ+  (ASHVE + Binary Tree + Segment Tree Encoding)
# ════════════════════════════════════════════════════════════════════════════

def setup_eprq():
    """Initialize EPRQ+: generate master secret key and domain params."""
    from eprq_exact.phase1_setup import setup
    msk, m, s, t = setup(m=8, s=4, t=4)
    return {"msk": msk, "m": m, "s": s, "t": t}


def process_eprq_batch(records, ctx):
    """
    Encrypt ALL records via EPRQ+ (batch operation).
    EPRQ+ builds a binary tree over sorted records, then encrypts each node
    with ASHVE. This requires all data up-front (unlike per-record schemes).
    """
    from eprq_exact.phase2_index_build import index_build

    eprq_records = [{"id": r["id"], "value": r["value"]} for r in records]

    root = index_build(eprq_records, ctx["msk"], ctx["m"], ctx["s"], ctx["t"])

    # Flatten tree to list of MongoDB documents
    docs = []
    counter = [0]
    _serialize_eprq_tree(root, docs, parent_id=None, counter=counter)
    return docs


def _serialize_eprq_tree(node, docs, parent_id, counter):
    """Recursively serialize EPRQ+ tree nodes for MongoDB storage."""
    if node is None:
        return

    current_id = counter[0]
    counter[0] += 1

    # Encode ciphertext bytes as hex strings
    ct_hex = []
    if node.ct:
        for c in node.ct:
            if isinstance(c, bytes):
                ct_hex.append(c.hex())
            else:
                ct_hex.append(str(c))

    doc = {
        "node_id": current_id,
        "parent_id": parent_id,
        "is_leaf": node.is_leaf,
        "bt_new": node.bt_new,
        "ct": ct_hex,
        "algorithm": "EPRQ+",
    }

    if node.is_leaf:
        doc["data_val"] = node.data_val
        doc["id_val"] = node.id_val
    else:
        doc["id_l"] = node.id_l
        doc["id_r"] = node.id_r

    docs.append(doc)

    if node.left:
        _serialize_eprq_tree(node.left, docs, current_id, counter)
    if node.right:
        _serialize_eprq_tree(node.right, docs, current_id, counter)


# ════════════════════════════════════════════════════════════════════════════
#  ALGORITHM 4:  Trinity-I  (SHVE + Hilbert Curve + Quotient Filter)
# ════════════════════════════════════════════════════════════════════════════

def setup_trinity_i():
    """Initialize Trinity-I scheme with 3D Hilbert curve mapping."""
    from trinity import TrinityI
    t1 = TrinityI()
    t1.setup(security_param=256, hilbert_order=8, num_keywords=10)
    return {"scheme": t1}


def process_trinity_i(record, ctx):
    """Encrypt one record via Trinity-I → Hilbert + SHVE + QF entry."""
    scheme = ctx["scheme"]
    lat, lon = MACHINE_COORDS[record["machine"]]
    lat += random.uniform(-0.01, 0.01)
    lon += random.uniform(-0.01, 0.01)

    t_obj = datetime.strptime(record["timestamp"], "%Y-%m-%d %H:%M:%S")
    ts = int(t_obj.timestamp())

    trinity_record = {
        "device_id": f"{record['machine']}_{record['id']}",
        "latitude": lat,
        "longitude": lon,
        "timestamp": ts,
        "temperature": record["value"] if record["sensor"] == "Temp" else 25,
        "humidity": record["value"] if record["sensor"] == "Humidity" else 50,
        "pressure": 1013,
        "keywords": [record["sensor"], record["machine"], "IIoT"],
    }

    entry = scheme.gen_index(trinity_record)

    doc = {
        "entry_id": entry["entry_id"],
        "prefix_count": entry["prefix_count"],
        "hilbert_index": entry["hilbert_index"],
        "grid_coords": list(entry["grid_coords"]),
        "ct_val": base64.b64encode(entry["ct_val"]).decode()
                  if isinstance(entry["ct_val"], bytes)
                  else str(entry["ct_val"]),
        "shve_ct": str(entry["shve_ct"]),
        "algorithm": "Trinity-I",
    }
    return [doc]


# ════════════════════════════════════════════════════════════════════════════
#  ALGORITHM 5:  Trinity-II  (Forward-Secure Extension with GGM-CPRF)
# ════════════════════════════════════════════════════════════════════════════

def setup_trinity_ii():
    """Initialize Trinity-II with forward-secure GGM-CPRF."""
    from trinity import TrinityII
    t2 = TrinityII()
    t2.setup(security_param=256, hilbert_order=8, num_keywords=10)
    return {"scheme": t2}


def process_trinity_ii(record, ctx):
    """Encrypt one record via Trinity-II → forward-secure index entry."""
    scheme = ctx["scheme"]
    lat, lon = MACHINE_COORDS[record["machine"]]
    lat += random.uniform(-0.01, 0.01)
    lon += random.uniform(-0.01, 0.01)

    t_obj = datetime.strptime(record["timestamp"], "%Y-%m-%d %H:%M:%S")
    ts = int(t_obj.timestamp())

    trinity_record = {
        "device_id": f"{record['machine']}_{record['id']}",
        "latitude": lat,
        "longitude": lon,
        "timestamp": ts,
        "temperature": record["value"] if record["sensor"] == "Temp" else 25,
        "humidity": record["value"] if record["sensor"] == "Humidity" else 50,
        "pressure": 1013,
        "keywords": [record["sensor"], record["machine"], "IIoT"],
    }

    entry = scheme.gen_index(trinity_record)

    doc = {
        "entry_id": entry["entry_id"],
        "prefix_count": entry["prefix_count"],
        "hilbert_index": entry["hilbert_index"],
        "grid_coords": list(entry["grid_coords"]),
        "ct_val": base64.b64encode(entry["ct_val"]).decode()
                  if isinstance(entry["ct_val"], bytes)
                  else str(entry["ct_val"]),
        "shve_ct": str(entry["shve_ct"]),
        "state_counter": entry.get("state_counter", 0),
        "forward_secure": entry.get("forward_secure", False),
        "verify_tag": base64.b64encode(entry["verify_tag"]).decode()
                      if "verify_tag" in entry and isinstance(entry["verify_tag"], bytes)
                      else str(entry.get("verify_tag", "")),
        "algorithm": "Trinity-II",
    }
    return [doc]


# ════════════════════════════════════════════════════════════════════════════
#  ALGORITHM 6:  MHRQ  (DPRF + CRQ Matrix Encryption)
# ════════════════════════════════════════════════════════════════════════════

def setup_mhrq():
    """Initialize MHRQ: key generation + CRQ matrix scheme."""
    from mhrq_graph import mhrq_setup
    KPi, sigma, EDB, sk = mhrq_setup(n=8)
    return {"KPi": KPi, "sigma": sigma, "EDB": EDB, "sk": sk}


def process_mhrq(record, ctx):
    """Encrypt one record via MHRQ → DPRF chain + CRQ encrypted matrix."""
    from mhrq_graph import mhrq_update

    doc_id = f"doc_{record['id']}"
    keyword = record["sensor"]
    value = record["value"]

    # Track keys before update to identify the newly added entry
    mat_keys_before = set(ctx["EDB"]["Mat"].keys())
    cdb_keys_before = set(ctx["EDB"]["CDB"].keys())

    mhrq_update(ctx["KPi"], ctx["sigma"], ctx["EDB"], ctx["sk"],
                doc_id, keyword, value)

    # Find newly added entries
    mat_keys_after = set(ctx["EDB"]["Mat"].keys())
    cdb_keys_after = set(ctx["EDB"]["CDB"].keys())
    new_mat_keys = mat_keys_after - mat_keys_before
    new_cdb_keys = cdb_keys_after - cdb_keys_before

    docs = []
    for adc in new_mat_keys:
        mat_entry = ctx["EDB"]["Mat"][adc]
        P_flat = mat_entry["P"].flatten().tolist()

        # Find corresponding CDB entry
        cdb_data = {}
        for lc in new_cdb_keys:
            cdb_entry = ctx["EDB"]["CDB"][lc]
            if cdb_entry["w"] == keyword:
                cdb_data = {
                    "Lc": base64.b64encode(lc).decode() if isinstance(lc, bytes) else str(lc),
                    "Dc": base64.b64encode(cdb_entry["Dc"]).decode()
                          if isinstance(cdb_entry["Dc"], bytes)
                          else str(cdb_entry["Dc"]),
                }
                break

        doc = {
            "doc_id": doc_id,
            "keyword": keyword,
            "adc": base64.b64encode(adc).decode() if isinstance(adc, bytes) else str(adc),
            "P_hat": P_flat,
            "P_shape": list(mat_entry["P"].shape),
            **cdb_data,
            "algorithm": "MHRQ",
        }
        docs.append(doc)

    return docs


# ════════════════════════════════════════════════════════════════════════════
#  MAIN PIPELINE
# ════════════════════════════════════════════════════════════════════════════

def run_pipeline(num_records):
    """Run the complete multi-algorithm IIoT encryption pipeline."""

    print()
    print("╔" + "═" * 68 + "╗")
    print("║   Multi-Algorithm IIoT Sensor Pipeline                             ║")
    print("║   Plaintext → 6 Encryption Algorithms → 6 MongoDB Collections     ║")
    print("╚" + "═" * 68 + "╝")

    # ── Step 1: Connect to MongoDB ───────────────────────────────────────
    print("\n[1/4] Connecting to MongoDB Atlas...")
    client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=10000)

    # Quick connection test
    try:
        client.admin.command('ping')
        print("  ✓ Connected to MongoDB Atlas")
    except Exception as e:
        print(f"  ✗ MongoDB connection failed: {e}")
        return

    db = client[DB_NAME]

    # Clear existing data in all target collections
    for name, coll_name in COLLECTIONS.items():
        db[coll_name].delete_many({})
        print(f"  ✓ Cleared: {coll_name}")

    # ── Step 2: Generate Plaintext ───────────────────────────────────────
    print(f"\n[2/4] Generating {num_records} plaintext IIoT sensor records...")
    records = generate_plaintext_records(num_records)
    print(f"  ✓ Generated {len(records)} records")
    print(f"  Sample: machine={records[0]['machine']}, "
          f"sensor={records[0]['sensor']}, "
          f"value={records[0]['value']}, "
          f"time={records[0]['timestamp']}")

    # ── Step 3: Initialize All Algorithms ────────────────────────────────
    print(f"\n[3/4] Initializing all 6 encryption algorithms...")

    algo_configs = [
        ("AC-SCRAT",   setup_acscrat,    process_acscrat,    False),
        ("EPBRQ",      setup_epbrq,      process_epbrq,      False),
        ("EPRQ+",      setup_eprq,       None,               True),
        ("Trinity-I",  setup_trinity_i,  process_trinity_i,  False),
        ("Trinity-II", setup_trinity_ii, process_trinity_ii, False),
        ("MHRQ",       setup_mhrq,       process_mhrq,       False),
    ]

    algorithms = {}
    for name, setup_fn, process_fn, is_batch in algo_configs:
        t0 = time.perf_counter()
        try:
            ctx = setup_fn()
            setup_ms = (time.perf_counter() - t0) * 1000
            algorithms[name] = {
                "ctx": ctx,
                "process_fn": process_fn,
                "is_batch": is_batch,
            }
            print(f"  ✓ {name:12s} initialized  ({setup_ms:>8.1f} ms)")
        except Exception as e:
            print(f"  ✗ {name:12s} FAILED: {e}")
            traceback.print_exc()

    # ── Step 4: Process Records Through Each Algorithm ───────────────────
    print(f"\n[4/4] Processing {num_records} records through each algorithm...")
    print("─" * 70)

    timings = {}

    for name, algo in algorithms.items():
        coll = db[COLLECTIONS[name]]
        t0 = time.perf_counter()
        total_docs = 0

        try:
            if algo["is_batch"]:
                # ── EPRQ+: batch processing (builds tree at once) ──
                print(f"  [{name}] Building encrypted binary tree (batch)...")
                docs = process_eprq_batch(records, algo["ctx"])
                if docs:
                    coll.insert_many(docs)
                    total_docs = len(docs)
            else:
                # ── Per-record processing ──
                all_docs = []
                for i, record in enumerate(records):
                    docs = algo["process_fn"](record, algo["ctx"])
                    all_docs.extend(docs)

                    if (i + 1) % max(1, num_records // 10) == 0 or i == len(records) - 1:
                        print(f"\r  [{name:12s}] {i+1:>5d}/{num_records} records...",
                              end="", flush=True)

                if all_docs:
                    coll.insert_many(all_docs)
                    total_docs = len(all_docs)
                print()   # newline after progress

            elapsed_ms = (time.perf_counter() - t0) * 1000
            timings[name] = {
                "total_ms": elapsed_ms,
                "per_record_ms": elapsed_ms / num_records,
                "total_docs": total_docs,
            }
            print(f"  ✅ {name:12s} → {total_docs:>5d} docs → "
                  f"{COLLECTIONS[name]:20s}  "
                  f"({elapsed_ms:.1f} ms, {elapsed_ms/num_records:.2f} ms/rec)")

        except Exception as e:
            print(f"\n  ❌ {name:12s} FAILED: {e}")
            traceback.print_exc()
            timings[name] = {
                "total_ms": 0, "per_record_ms": 0,
                "total_docs": 0, "error": str(e),
            }

    # ── Summary ──────────────────────────────────────────────────────────
    print()
    print("╔" + "═" * 68 + "╗")
    print("║  PIPELINE SUMMARY                                                  ║")
    print("╚" + "═" * 68 + "╝")
    print(f"  {'Algorithm':<14} {'Docs':>7} {'Total (ms)':>12} "
          f"{'Per-Rec (ms)':>14}  {'MongoDB Collection'}")
    print("  " + "─" * 66)
    for name in COLLECTIONS:
        if name in timings:
            t = timings[name]
            status = "✅" if t["total_docs"] > 0 else "❌"
            print(f"  {status} {name:<12} {t['total_docs']:>7,} "
                  f"{t['total_ms']:>12,.1f} {t['per_record_ms']:>14.2f}  "
                  f"{COLLECTIONS[name]}")
        else:
            print(f"  ❌ {name:<12} {'SKIPPED':>7}")
    print("  " + "─" * 66)
    print(f"  Database: {DB_NAME}")
    print(f"  Records:  {num_records}")
    print()

    # Verify counts in MongoDB
    print("  MongoDB Verification:")
    for name, coll_name in COLLECTIONS.items():
        count = db[coll_name].count_documents({})
        print(f"    {coll_name:25s} → {count:>6,} documents")

    client.close()
    print("\n✅ Pipeline complete. All encrypted data stored in MongoDB Atlas.")


# ════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    target = input("\n[?] จำนวนเรคคอร์ดที่ต้องการสร้าง (Number of records): ").strip()
    count = int(target) if target else 10
    run_pipeline(count)
