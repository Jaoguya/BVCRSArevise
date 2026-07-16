"""
BVCRSA (AC-SCRAT) Server — Flask API

Implements the full 5-phase pipeline from the paper:
  Phase 1: System initialization (TA.py)
  Phase 2: Sensor-side encryption + edge-side SCRAT construction
  Phase 3: Conjunctive range-query trapdoor generation
  Phase 4: Cloud-side query processing
  Phase 5: Verifiable aggregation and decryption

Architecture (per paper):
  Sensor → encrypts v with EC-ElGamal, computes canonical path, HMACs
  Edge   → verifies HMAC, builds SCRAT with OPAQUE ciphertexts (never sees v)
  Cloud  → ABSE bilinear pairing test + bitmap filtering
  User   → decrypts aggregate with sk_AHE
"""

import time
import sys
import hashlib
from datetime import datetime
from flask import Flask, request, jsonify
from pymongo import MongoClient, ReplaceOne
from blockchain_edge import BlockchainEdgeManager
from TA import TrustedAuthority
from cloud_server import CloudServer
from utils import gen_pi_agg
from ec_elgamal import ECEncryptedNumber

app = Flask(__name__)

# MongoDB Atlas connection
uri = "mongodb+srv://yewza232_db_user:5qCbuPzMrzPSpflq@projectsomchart.lkihxz4.mongodb.net/?appName=ProjectSomchart"
client = MongoClient(uri)
db = client["IIoT_Security_DB"]
collection = db["AC_SCRAT_Nodes"]

# ── Phase 1: System Initialization (Eq. 1-9) ────────────────────
ta = TrustedAuthority()
user_secrets = ta.key_gen(["Analyst", "Temp", "Humidity"])
edge_node = BlockchainEdgeManager(user_secrets, user_secrets["abse"])

# Sensor provisioning (Phase 1 Step 4)
rpi_aes_key = ta.get_sensor_key("RPI_01")
rpi_hmac_key = ta.get_sensor_hmac_key("RPI_01")


@app.route("/ingest", methods=["POST"])
def ingest():
    """Phase 2: Sensor-Side Encryption + Edge-Side SCRAT Construction.

    The sensor has ALREADY performed (Eq. 10-14):
      (a) AES-GCM encryption of full tuple
      (b) EC-ElGamal encryption of value v
      (c) Canonical path computation
      (d) HMAC tag construction

    The edge:
      Step 2: Verifies HMAC and sequence counter (Eq. 13)
      Step 3-8: Builds SCRAT nodes using OPAQUE ciphertexts

    The edge NEVER decrypts AES-GCM or EC-ElGamal.
    It NEVER sees the plaintext sensor value v.
    """
    data = request.json
    try:
        start_gen = time.perf_counter()

        # Check if payload is in new paper-aligned format (sensor.py)
        if "ct_v" in data and "ctx" in data:
            # ── PAPER-ALIGNED PATH: sensor pre-encrypted payload ──
            # Step 2: Verify HMAC and sequence counter (Eq. 13)
            valid, msg = edge_node.verify_sensor_payload(data, rpi_hmac_key)
            if not valid:
                return jsonify({"error": f"Payload rejected: {msg}"}), 403

            # Steps 3-8: Build SCRAT from opaque ciphertexts
            nodes = edge_node.build_scrat_from_payload(data)

        else:
            # ── LEGACY PATH: AES-only payload (backward compat) ──
            # For legacy callers that send AES-encrypted data without
            # pre-computed EC-ElGamal ciphertext and canonical path.
            # The edge decrypts AES to extract context, then re-encrypts.
            import base64
            from Crypto.Cipher import AES as AESCipher

            cipher = AESCipher.new(rpi_aes_key, AESCipher.MODE_GCM,
                                   base64.b64decode(data['iv']))
            decrypted = cipher.decrypt_and_verify(
                base64.b64decode(data['payload']),
                base64.b64decode(data['auth_tag'])
            ).decode('utf-8')

            m, k, t_str, v = decrypted.split('|')
            t_obj = datetime.strptime(t_str, "%Y-%m-%d %H:%M:%S")

            # Simulate sensor-side encryption for legacy path
            from sensor import sensor_encrypt
            seq = int(time.time() * 1000)
            payload = sensor_encrypt(
                "RPI_01", m, k, t_str, int(v),
                rpi_aes_key, rpi_hmac_key,
                ta.ec_pubkey, seq
            )
            valid, msg = edge_node.verify_sensor_payload(payload, rpi_hmac_key)
            if not valid:
                return jsonify({"error": f"Payload rejected: {msg}"}), 403
            nodes = edge_node.build_scrat_from_payload(payload)

        # Upsert SCRAT nodes to MongoDB (Phase 2 Step 9: Secure Outsourcing)
        bulk_ops = []
        for n in nodes:
            query = {"m_enc": n["m_enc"], "k_enc": n["k_enc"],
                     "l": n["l"], "r": n["r"], "t": n["t"]}
            bulk_ops.append(ReplaceOne(query, n, upsert=True))
        if bulk_ops:
            collection.bulk_write(bulk_ops)

        gen_time = (time.perf_counter() - start_gen) * 1000
        return jsonify({"status": "success", "gen_index_ms": gen_time}), 200

    except Exception as e:
        import traceback; traceback.print_exc()
        return jsonify({"error": str(e)}), 500


@app.route("/query", methods=["POST"])
def query():
    """Phase 4 & 5: Secure Range Query and Verifiable Aggregation.

    Phase 4 (Cloud-side):
      - ABSE bilinear pairing test for authorization (Eq. 34)
      - Bitmap-constrained filtering (Eq. 37)
    Phase 5 (User-side):
      - Homomorphic aggregation of matched ciphertexts (Eq. 38-39)
      - Aggregation commitment (Eq. 44)
      - Merkle proof verification
    """
    try:
        trapdoor = request.json
        cloud = CloudServer(collection)

        start_agg = time.perf_counter()

        # Phase 4: Cloud processes query with ABSE test + bitmap filter
        matched_docs = cloud.process_query(trapdoor)

        agg_sum_cipher, agg_cnt_cipher = None, None
        node_ids = []

        # Phase 5 Step 1: Homomorphic aggregation (Eq. 38-39)
        # CT_sum = Σ Agg_u for u ∈ U*_Q — EC-ElGamal ciphertext addition
        for d in matched_docs:
            ct_v = ECEncryptedNumber.from_string(edge_node.ec_pubkey, d["Agg_u"])
            ct_c = ECEncryptedNumber.from_string(edge_node.ec_pubkey, d["Cnt_u"])
            node_ids.append(str(d["_id"]))

            if agg_sum_cipher is None:
                agg_sum_cipher, agg_cnt_cipher = ct_v, ct_c
            else:
                agg_sum_cipher = agg_sum_cipher + ct_v   # EC point addition
                agg_cnt_cipher = agg_cnt_cipher + ct_c   # EC point addition

        ct_sum_str = agg_sum_cipher.ciphertext() if agg_sum_cipher else "0"
        ct_cnt_str = agg_cnt_cipher.ciphertext() if agg_cnt_cipher else "0"

        # Phase 5 Step 3: Aggregation commitment (Eq. 44)
        merkle_root = matched_docs[0]["root"] if matched_docs else "EMPTY"
        pi_agg = gen_pi_agg(merkle_root, ",".join(node_ids), ct_sum_str, ct_cnt_str)

        # Collect proofs for client-side verification
        node_proofs = [{
            "m": trapdoor["m"], "k": trapdoor["k"],
            "t": d["t"], "l": d["l"], "r": d["r"],
            "sigma": d["sigma"], "pi_u": d["pi_u"],
            "root": d["root"], "CT_v": d["CT_v"], "Cnt_u": d["Cnt_u"]
        } for d in matched_docs]

        agg_time = (time.perf_counter() - start_agg) * 1000
        return jsonify({
            "CT_sum": ct_sum_str, "CT_cnt": ct_cnt_str,
            "Pi_agg": pi_agg, "proofs": node_proofs,
            "agg_only_ms": agg_time, "matched_nodes": len(matched_docs)
        })
    except Exception as e:
        import traceback; traceback.print_exc()
        return jsonify({"error": str(e)}), 500


@app.route("/conjunctive_query", methods=["POST"])
def conjunctive_query():
    """Phase 4 & 5: Conjunctive Multi-Range Query (Eq. 27, Theorem 4).

    Q = Q_1 ∧ Q_2 ∧ ... ∧ Q_d,  Q_j = (D_j, [a_j, b_j])

    Example request body:
    {
        "m": "Machine_01",
        "t_slot": "2026-05-20 15",
        "type": "conjunctive",
        "d": 2,
        "dimensions": [
            {"m":"Machine_01", "k":"Temp", "t_slot":"2026-05-20 15",
             "range":[20,50], "tokens":[...], "search_tags":[...], "auth_token":{...}},
            {"m":"Machine_01", "k":"Humidity", "t_slot":"2026-05-20 15",
             "range":[60,80], "tokens":[...], "search_tags":[...], "auth_token":{...}}
        ]
    }

    Each dimension is queried independently via ABSE.Test + bitmap filter.
    Conjunction: only time slots matching ALL dimensions are kept.
    Aggregation: per-dimension EC-ElGamal ciphertext summation.
    """
    try:
        conj_trapdoor = request.json
        cloud = CloudServer(collection)
        start = time.perf_counter()

        result = cloud.process_conjunctive_query(conj_trapdoor)

        # Per-dimension homomorphic aggregation (Eq. 38-39)
        dim_aggregates = []
        for dim_result in result["dimensions"]:
            agg_sum, agg_cnt = None, None
            for doc in dim_result["matched_nodes"]:
                ct_v = ECEncryptedNumber.from_string(edge_node.ec_pubkey, doc["Agg_u"])
                ct_c = ECEncryptedNumber.from_string(edge_node.ec_pubkey, doc["Cnt_u"])
                if agg_sum is None:
                    agg_sum, agg_cnt = ct_v, ct_c
                else:
                    agg_sum = agg_sum + ct_v
                    agg_cnt = agg_cnt + ct_c

            dim_aggregates.append({
                "k": dim_result["k"],
                "range": dim_result["range"],
                "CT_sum": agg_sum.ciphertext() if agg_sum else "0",
                "CT_cnt": agg_cnt.ciphertext() if agg_cnt else "0",
                "matched_nodes": dim_result["node_count"],
            })

        elapsed = (time.perf_counter() - start) * 1000
        return jsonify({
            "type": "conjunctive",
            "d": result["d"],
            "common_timeslots": result["common_timeslots"],
            "matched_any": result["matched_any"],
            "dimensions": dim_aggregates,
            "total_ms": elapsed,
        })
    except Exception as e:
        import traceback; traceback.print_exc()
        return jsonify({"error": str(e)}), 500


if __name__ == "__main__":
    print("\n  AC-SCRAT Server — Blockchain Edge Node")
    app.run(host="0.0.0.0", port=5000)