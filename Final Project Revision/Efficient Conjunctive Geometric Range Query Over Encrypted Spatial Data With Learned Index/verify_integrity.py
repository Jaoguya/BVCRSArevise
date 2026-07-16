"""
ECGRQ-LI Verification Dashboard
Runs all verification tests, saves results as JSON, then opens a web dashboard.
"""
import os, json, hashlib, hmac, struct, time
from pymongo import MongoClient, ASCENDING
from config import MONGO_URI, DB_NAME
import http.server, threading, webbrowser

Z_BITS = 16
DOMAIN_MAX = 100
KEYWORD_POOL = [f"sensor_{i}" for i in range(20)]
NUM_ATTRS = 3
OUTPUT_DIR = "experiment_results"

def interleave_bits(x, y, bits=Z_BITS):
    z = 0
    for i in range(bits):
        z |= ((x >> i) & 1) << (2 * i + 1)
        z |= ((y >> i) & 1) << (2 * i)
    return z

def value_to_grid(v):
    return max(0, min((1 << Z_BITS) - 1, int(v / DOMAIN_MAX * ((1 << Z_BITS) - 1))))

def compute_z_code(v1, v2):
    return interleave_bits(value_to_grid(v1), value_to_grid(v2))

def prf_encrypt(key, z_code):
    return int.from_bytes(hmac.new(key, z_code.to_bytes(8, 'big'), hashlib.sha256).digest()[:8], 'big')

def pe_derive_key(msk, index):
    return hmac.new(msk, index.to_bytes(4, 'big'), hashlib.sha256).digest()

def pe_encrypt_component(dk, bit, r):
    return hmac.new(dk, struct.pack('B', bit) + r, hashlib.sha256).digest()


def run_verification():
    print("[*] Running verification tests...")
    client = MongoClient(MONGO_URI)
    db = client[DB_NAME]

    model = db["learned_index_models"].find_one(
        {"dataset": {"$regex": "^ecgrq_N1000"}}, sort=[("_id", -1)])
    pe_msk = bytes.fromhex(model["pe_msk"])
    prf_key = bytes.fromhex(model["prf_key"])
    label = model["dataset"]
    raw_label = label.rsplit("_run", 1)[0]

    enc_docs = list(db["encrypted_index"].find({"dataset": label}).sort("position", ASCENDING))
    raw_docs = list(db["raw_spatial_data"].find({"dataset": raw_label}))
    raw_by_id = {r["id"]: r for r in raw_docs}

    results = {"tests": [], "records": [], "tamper_demo": {}}

    # ── TEST 1: PRF Verification (check 30 records) ──
    prf_checks = []
    for doc in enc_docs[:30]:
        oid = doc["original_id"]
        if oid not in raw_by_id:
            continue
        raw = raw_by_id[oid]
        z = compute_z_code(raw["dim1"], raw["dim2"])
        expected = hex(prf_encrypt(prf_key, z))
        actual = doc["encrypted_z_code"]
        match = expected == actual
        prf_checks.append({
            "record_id": oid,
            "dim1": raw["dim1"], "dim2": raw["dim2"],
            "expected_enc_z": expected[:18] + "...",
            "actual_enc_z": actual[:18] + "...",
            "match": match
        })
    prf_pass = all(c["match"] for c in prf_checks)
    results["tests"].append({
        "name": "PRF Encryption Verification",
        "description": "Re-compute F(K, Z{p}) from raw data → compare to stored encrypted Z-code",
        "passed": prf_pass,
        "details": prf_checks
    })

    # ── TEST 2: PE Ciphertext Verification (check 10 records) ──
    pe_checks = []
    for doc in enc_docs[:10]:
        oid = doc["original_id"]
        if oid not in raw_by_id:
            continue
        raw = raw_by_id[oid]
        z = compute_z_code(raw["dim1"], raw["dim2"])
        z_bits = [(z >> i) & 1 for i in range(2 * Z_BITS)]
        attr_vec = [1 if kw in raw['keywords'] else 0 for kw in KEYWORD_POOL[:NUM_ATTRS]]
        index_vector = z_bits + attr_vec
        cipher = doc["encrypted_index_vector"]
        all_ok = True
        mismatch_pos = -1
        for i, bit in enumerate(index_vector):
            dk = pe_derive_key(pe_msk, i)
            r = bytes.fromhex(cipher[i]["r"])
            exp_c = pe_encrypt_component(dk, bit, r).hex()
            if exp_c != cipher[i]["c"]:
                all_ok = False
                mismatch_pos = i
                break
        pe_checks.append({
            "record_id": oid,
            "vector_length": len(index_vector),
            "all_components_match": all_ok,
            "mismatch_at": mismatch_pos
        })
    pe_pass = all(c["all_components_match"] for c in pe_checks)
    results["tests"].append({
        "name": "PE Ciphertext Verification",
        "description": "Re-derive keys, re-encrypt with stored nonce → compare ciphertext byte-by-byte",
        "passed": pe_pass,
        "details": pe_checks
    })

    # ── TEST 3: Query Correctness ──
    from comparison_test import pe_gen_token, pe_query_match
    q_z = ['*'] * (2 * Z_BITS)
    q_a = [1 if kw == "sensor_0" else '*' for kw in KEYWORD_POOL[:NUM_ATTRS]]
    token = pe_gen_token(pe_msk, q_z + q_a)
    pe_matched = sum(1 for d in enc_docs if pe_query_match(d["encrypted_index_vector"], token))
    expected_match = sum(1 for r in raw_docs if "sensor_0" in r.get("keywords", []))
    results["tests"].append({
        "name": "Query Correctness",
        "description": f"PE.Query with 'sensor_0' token: found {pe_matched} records, expected {expected_match} from plaintext",
        "passed": pe_matched == expected_match,
        "details": [{"pe_matched": pe_matched, "expected": expected_match}]
    })

    # ── TEST 4: Tamper Detection Demo ──
    raw_rec = db["raw_spatial_data"].find_one({"dataset": raw_label, "keywords": "sensor_0"})
    enc_doc = db["encrypted_index"].find_one({"dataset": label, "original_id": raw_rec["id"]})
    cipher = enc_doc["encrypted_index_vector"]
    attr_pos = 2 * Z_BITS
    stored_c = cipher[attr_pos]["c"]
    stored_r = cipher[attr_pos]["r"]
    dk = pe_derive_key(pe_msk, attr_pos)
    r_bytes = bytes.fromhex(stored_r)
    expected_c = pe_encrypt_component(dk, 1, r_bytes).hex()

    # Original
    orig_match = hmac.compare_digest(bytes.fromhex(expected_c), bytes.fromhex(stored_c))

    # Tamper ciphertext
    tb = bytearray(bytes.fromhex(stored_c))
    orig_byte = f"0x{tb[0]:02x}"
    tb[0] ^= 0xFF
    new_byte = f"0x{tb[0]:02x}"
    tampered_c = tb.hex()
    tamper_match = hmac.compare_digest(bytes.fromhex(expected_c), tb)

    # Tamper nonce
    tr = bytearray(r_bytes)
    tr[0] ^= 0xFF
    recomputed = pe_encrypt_component(dk, 1, bytes(tr)).hex()
    nonce_match = hmac.compare_digest(bytes.fromhex(stored_c), bytes.fromhex(recomputed))

    # Wrong key
    wrong_msk = os.urandom(16)
    wrong_dk = pe_derive_key(wrong_msk, attr_pos)
    wrong_c = pe_encrypt_component(wrong_dk, 1, r_bytes).hex()
    wrong_match = hmac.compare_digest(bytes.fromhex(stored_c), bytes.fromhex(wrong_c))

    results["tamper_demo"] = {
        "record_id": raw_rec["id"],
        "keywords": raw_rec["keywords"],
        "attr_position": attr_pos,
        "cases": [
            {"label": "Original Data", "stored_c": stored_c, "computed_c": expected_c,
             "match": orig_match, "icon": "✅", "status": "VALID"},
            {"label": "Tampered Ciphertext", "stored_c": tampered_c, "computed_c": expected_c,
             "match": tamper_match, "icon": "❌",
             "status": f"REJECTED (byte[0]: {orig_byte}→{new_byte})"},
            {"label": "Tampered Nonce", "stored_c": stored_c, "computed_c": recomputed,
             "match": nonce_match, "icon": "❌", "status": "REJECTED (nonce modified)"},
            {"label": "Wrong Key", "stored_c": stored_c, "computed_c": wrong_c,
             "match": wrong_match, "icon": "❌",
             "status": f"REJECTED (MSK: {wrong_msk.hex()[:16]}...)"}
        ]
    }
    results["tests"].append({
        "name": "Tamper Detection",
        "description": "Modify ciphertext/nonce/key → PE must reject",
        "passed": not tamper_match and not nonce_match and not wrong_match,
        "details": results["tamper_demo"]["cases"]
    })

    # ── TEST 5: Wrong Key ──
    wrong_token = pe_gen_token(wrong_msk, q_z + q_a)
    wrong_matches = sum(1 for d in enc_docs[:50] if pe_query_match(d["encrypted_index_vector"], wrong_token))
    results["tests"].append({
        "name": "Wrong Key Rejection",
        "description": f"Query with wrong MSK → {wrong_matches} matches out of 50 records",
        "passed": wrong_matches == 0,
        "details": [{"wrong_matches": wrong_matches, "tested": 50}]
    })

    # ── TEST 6: MongoDB Data Check ──
    counts = {}
    for c in ["raw_spatial_data", "encrypted_index", "learned_index_models", "experiment_results"]:
        counts[c] = db[c].count_documents({})
    results["tests"].append({
        "name": "MongoDB Data Reality",
        "description": "Verify encrypted data exists in MongoDB Atlas",
        "passed": counts["encrypted_index"] > 0,
        "details": [counts]
    })

    results["summary"] = {
        "total": len(results["tests"]),
        "passed": sum(1 for t in results["tests"] if t["passed"]),
        "failed": sum(1 for t in results["tests"] if not t["passed"]),
    }

    client.close()

    # Save JSON
    json_path = os.path.join(OUTPUT_DIR, "verification_results.json")
    with open(json_path, 'w') as f:
        json.dump(results, f, indent=2, default=str)
    print(f"[+] Results saved to {json_path}")
    return results


def build_dashboard(results):
    """Generate HTML dashboard."""
    tests_html = ""
    for t in results["tests"]:
        icon = "✅" if t["passed"] else "❌"
        status_class = "pass" if t["passed"] else "fail"
        details_items = ""
        for d in t["details"]:
            if isinstance(d, dict):
                for k, v in d.items():
                    if k in ("match", "all_components_match"):
                        val_class = "val-pass" if v else "val-fail"
                        details_items += f'<div class="detail-row"><span class="detail-key">{k}</span><span class="detail-val {val_class}">{v}</span></div>'
                    elif k == "icon":
                        continue
                    else:
                        details_items += f'<div class="detail-row"><span class="detail-key">{k}</span><span class="detail-val">{v}</span></div>'

        tests_html += f"""
        <div class="test-card {status_class}">
            <div class="test-header">
                <span class="test-icon">{icon}</span>
                <span class="test-name">{t['name']}</span>
                <span class="test-badge {'badge-pass' if t['passed'] else 'badge-fail'}">
                    {'PASSED' if t['passed'] else 'FAILED'}
                </span>
            </div>
            <div class="test-desc">{t['description']}</div>
            <div class="test-details">{details_items}</div>
        </div>"""

    # Tamper demo
    td = results["tamper_demo"]
    tamper_rows = ""
    for case in td["cases"]:
        row_class = "tamper-pass" if case["match"] else "tamper-fail"
        tamper_rows += f"""
        <tr class="{row_class}">
            <td><span class="tamper-icon">{case['icon']}</span> {case['label']}</td>
            <td class="mono">{case['stored_c'][:24]}...</td>
            <td class="mono">{case['computed_c'][:24]}...</td>
            <td class="{'val-pass' if case['match'] else 'val-fail'}">{case['match']}</td>
            <td>{case['status']}</td>
        </tr>"""

    s = results["summary"]
    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>ECGRQ-LI Verification Dashboard</title>
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap');
:root {{
    --bg: #0f1117; --card: #1a1d27; --border: #2a2d3a;
    --text: #e4e6eb; --muted: #8b8fa3; --green: #22c55e;
    --red: #ef4444; --blue: #3b82f6; --purple: #a855f7;
    --green-bg: rgba(34,197,94,0.08); --red-bg: rgba(239,68,68,0.08);
}}
* {{ margin:0; padding:0; box-sizing:border-box; }}
body {{ font-family:'Inter',sans-serif; background:var(--bg); color:var(--text); padding:24px; min-height:100vh; }}
.container {{ max-width:1100px; margin:0 auto; }}
h1 {{ font-size:28px; font-weight:700; margin-bottom:4px;
     background:linear-gradient(135deg,#3b82f6,#a855f7);
     -webkit-background-clip:text; -webkit-text-fill-color:transparent; }}
.subtitle {{ color:var(--muted); font-size:14px; margin-bottom:28px; }}

.summary {{ display:flex; gap:16px; margin-bottom:32px; }}
.stat-card {{ flex:1; background:var(--card); border:1px solid var(--border);
    border-radius:12px; padding:20px; text-align:center; }}
.stat-num {{ font-size:42px; font-weight:700; }}
.stat-num.green {{ color:var(--green); }}
.stat-num.red {{ color:var(--red); }}
.stat-num.blue {{ color:var(--blue); }}
.stat-label {{ color:var(--muted); font-size:13px; margin-top:4px; text-transform:uppercase; letter-spacing:1px; }}

.test-card {{ background:var(--card); border:1px solid var(--border);
    border-radius:12px; padding:20px; margin-bottom:16px;
    transition:border-color 0.2s; }}
.test-card:hover {{ border-color:#3b82f6; }}
.test-card.pass {{ border-left:4px solid var(--green); }}
.test-card.fail {{ border-left:4px solid var(--red); }}
.test-header {{ display:flex; align-items:center; gap:10px; margin-bottom:8px; }}
.test-icon {{ font-size:22px; }}
.test-name {{ font-size:17px; font-weight:600; flex:1; }}
.test-badge {{ font-size:11px; font-weight:600; padding:4px 10px; border-radius:20px; letter-spacing:0.5px; }}
.badge-pass {{ background:var(--green-bg); color:var(--green); }}
.badge-fail {{ background:var(--red-bg); color:var(--red); }}
.test-desc {{ color:var(--muted); font-size:13px; margin-bottom:12px; }}
.test-details {{ display:flex; flex-wrap:wrap; gap:6px 16px; }}
.detail-row {{ font-size:12px; display:flex; gap:6px; }}
.detail-key {{ color:var(--muted); font-family:'JetBrains Mono',monospace; }}
.detail-val {{ font-family:'JetBrains Mono',monospace; }}
.val-pass {{ color:var(--green); font-weight:600; }}
.val-fail {{ color:var(--red); font-weight:600; }}

.section-title {{ font-size:20px; font-weight:700; margin:32px 0 16px;
    display:flex; align-items:center; gap:8px; }}
.section-title::before {{ content:''; width:4px; height:24px; border-radius:2px;
    background:linear-gradient(180deg,#3b82f6,#a855f7); }}

table {{ width:100%; border-collapse:collapse; background:var(--card);
    border-radius:12px; overflow:hidden; border:1px solid var(--border); }}
th {{ background:#1e2130; text-align:left; padding:12px 16px; font-size:12px;
    text-transform:uppercase; letter-spacing:0.5px; color:var(--muted); font-weight:600; }}
td {{ padding:10px 16px; font-size:13px; border-top:1px solid var(--border); }}
.mono {{ font-family:'JetBrains Mono',monospace; font-size:11px; color:var(--muted); }}
tr.tamper-pass {{ background:var(--green-bg); }}
tr.tamper-fail {{ background:var(--red-bg); }}
.tamper-icon {{ font-size:16px; }}

.footer {{ text-align:center; color:var(--muted); font-size:12px; margin-top:40px; padding:20px 0; border-top:1px solid var(--border); }}
</style>
</head>
<body>
<div class="container">
    <h1>🔐 ECGRQ-LI Verification Dashboard</h1>
    <p class="subtitle">Real-time integrity verification of encrypted spatial data in MongoDB Atlas</p>

    <div class="summary">
        <div class="stat-card"><div class="stat-num blue">{s['total']}</div><div class="stat-label">Total Tests</div></div>
        <div class="stat-card"><div class="stat-num green">{s['passed']}</div><div class="stat-label">Passed</div></div>
        <div class="stat-card"><div class="stat-num red">{s['failed']}</div><div class="stat-label">Failed</div></div>
    </div>

    <div class="section-title">Test Results</div>
    {tests_html}

    <div class="section-title">Tamper Detection Demo</div>
    <p style="color:var(--muted);font-size:13px;margin-bottom:12px;">
        Record ID: {td['record_id']} &nbsp;|&nbsp; Keywords: {', '.join(td['keywords'])} &nbsp;|&nbsp;
        Testing attribute component at index {td['attr_position']}
    </p>
    <table>
        <thead><tr>
            <th>Scenario</th><th>Stored Ciphertext</th><th>Computed Ciphertext</th>
            <th>Match?</th><th>Result</th>
        </tr></thead>
        <tbody>{tamper_rows}</tbody>
    </table>

    <div class="footer">
        ECGRQ-LI &bull; PE: HMAC-SHA256 &bull; PRF: HMAC-SHA256 &bull; PM Learned Index (ε=0.4)
        &bull; Data stored in MongoDB Atlas
    </div>
</div>
</body>
</html>"""
    return html


def main():
    results = run_verification()
    html = build_dashboard(results)
    html_path = os.path.join(OUTPUT_DIR, "verification_dashboard.html")
    with open(html_path, 'w', encoding='utf-8') as f:
        f.write(html)
    abs_path = os.path.abspath(html_path)
    print(f"[+] Dashboard saved: {abs_path}")
    webbrowser.open(f"file:///{abs_path}")
    print("[+] Opened in browser!")


if __name__ == "__main__":
    main()
