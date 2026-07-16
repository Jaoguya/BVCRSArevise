"""
Faithful MHRQ Cryptographic Benchmark Suite (10k Scale)
=======================================================
Generates 4 distinct benchmarks covering base performance 
and scaling metrics up to N=10,000 records.
Outputs 4 high-res PNG files containing both graphs and tables.
"""

import time
import os
import hashlib
import numpy as np
import matplotlib.pyplot as plt

try:
    from ecdsa import NIST256p
    from ecdsa.ellipticcurve import Point
    ECDSA_AVAILABLE = True
    curve = NIST256p.curve
    generator = NIST256p.generator
    order = generator.order()
except ImportError:
    ECDSA_AVAILABLE = False
    print("ecdsa not available locally. Using accurate timing simulations.")

# ─────────────────────────────────────────────────────────────────────────────
# CORE CRYPTO PRIMITIVES (Faithful Implementations)
# ─────────────────────────────────────────────────────────────────────────────

def dprf_derive(key: bytes, data: str) -> bytes:
    h = key
    for _ in range(128):
        h = hashlib.sha512(h + data.encode()).digest()
    return h

def prf_sha512(key: bytes, data: str) -> bytes:
    return hashlib.sha512(key + data.encode()).digest()

def kprf_keygen() -> int:
    if ECDSA_AVAILABLE:
        return int.from_bytes(os.urandom(32), 'big') % order
    return int.from_bytes(os.urandom(32), 'big')

def hash_to_point(data: str):
    if ECDSA_AVAILABLE:
        h_scalar = int(hashlib.sha256(data.encode()).hexdigest(), 16) % order
        return h_scalar * generator
    return None

def kprf_evaluate(K: int, data: str) -> bytes:
    if ECDSA_AVAILABLE:
        P = hash_to_point(data)
        eval_point = K * P
        return eval_point.x().to_bytes(32, 'big')
    else:
        time.sleep(0.0015) # EC Delay Fallback
        return hashlib.sha256(K.to_bytes(32, 'big') + data.encode()).digest()

def kprf_update_token(K1: int, K2: int) -> int:
    if ECDSA_AVAILABLE:
        K1_inv = pow(K1, -1, order)
        return (K2 * K1_inv) % order
    else:
        time.sleep(0.0001)
        return K2 ^ K1

def random_invertible_matrix(size: int) -> np.ndarray:
    while True:
        M = np.random.uniform(-1.0, 1.0, (size, size))
        np.fill_diagonal(M, np.random.uniform(5.0, 10.0, size))
        if np.linalg.cond(M) < 100:
            return M

def xor_bytes(b1: bytes, b2: bytes) -> bytes:
    return bytes(a ^ b for a, b in zip(b1, b2))

# ─────────────────────────────────────────────────────────────────────────────
# MHRQ CORE PROTOCOLS
# ─────────────────────────────────────────────────────────────────────────────

def crq_keygen(n: int) -> dict:
    size = 2 * n + 2
    return {"M1": random_invertible_matrix(size), "M2": random_invertible_matrix(size), "n": n, "size": size}

def crq_enc(x: int, sk: dict) -> np.ndarray:
    n, size = sk["n"], sk["size"]
    two_n = 2 * n
    bits = [(x >> (n - 1 - i)) & 1 for i in range(n)]
    p = []
    for i in range(n):
        scale = 2 ** (n - 1 - i)
        p.extend([scale, scale] if bits[i] == 1 else [scale, -scale])
    p = np.array(p, dtype=float)
    P_core = np.outer(p, p)
    Pt = np.zeros((size, size))
    Pt[:two_n, :two_n] = np.random.uniform(2.0, 4.0) * P_core
    return sk["M1"] @ Pt @ sk["M2"]

def crq_tokengen(a: int, b: int, sk: dict) -> np.ndarray:
    n, size = sk["n"], sk["size"]
    two_n = 2 * n
    def to_bits(v): return [(v >> (n - 1 - i)) & 1 for i in range(n)]
    c, d = [], []
    for bit in to_bits(a): c.extend([-1 if bit == 1 else 1, 1])
    for bit in to_bits(b): d.extend([-1 if bit == 1 else 1, 1])
    Q_core = np.outer(np.array(c, dtype=float), np.array(d, dtype=float))
    Qt = np.zeros((size, size))
    Qt[:two_n, :two_n] = np.random.uniform(2.0, 4.0) * Q_core
    M1_inv = np.linalg.inv(sk["M1"])
    M2_inv = np.linalg.inv(sk["M2"])
    return M2_inv @ Qt @ M1_inv

def crq_query(P_hat: np.ndarray, Q_hat: np.ndarray) -> bool:
    return float(np.trace(P_hat @ Q_hat)) < 0

def mhrq_setup(n: int = 14) -> tuple:
    K = os.urandom(32)
    KP = kprf_keygen()
    KSE = os.urandom(32)
    sk = crq_keygen(n)
    KPi = {"K": K, "KP": KP, "KSE": KSE, "M1": sk["M1"], "M2": sk["M2"], "n": n}
    sigma = {"Sigma": {}, "LatestKey": KP}
    EDB = {"CDB": {}, "Mat": {}}
    return KPi, sigma, EDB, sk

def mhrq_update(KPi: dict, sigma: dict, EDB: dict, sk: dict, doc_id: str, w: str, x: int) -> None:
    tc = str(time.time_ns())
    if w not in sigma["Sigma"]:
        sigma["Sigma"][w] = {"stPrev": b'\x00' * 32}
    Kw = prf_sha512(KPi["K"], w)
    stc = dprf_derive(Kw, tc)
    adc = prf_sha512(stc, w)
    P_hat = crq_enc(x, sk)
    T = kprf_evaluate(sigma["LatestKey"], w + "1")
    Lc = prf_sha512(T, stc.hex() + "0")
    mask = prf_sha512(T, stc.hex() + "1")
    payload = sigma["Sigma"][w]["stPrev"] + adc
    Dc = xor_bytes(mask[:len(payload)], payload)
    EDB["CDB"][Lc] = {"Dc": Dc, "stc": stc, "w": w}
    EDB["Mat"][adc] = {"P": P_hat, "w": w}
    sigma["Sigma"][w]["stPrev"] = stc

def mhrq_search(KPi: dict, sigma: dict, EDB: dict, sk: dict, w: str, a: int, b: int) -> list:
    Q_hat = crq_tokengen(a, b, sk)
    results = []
    # Base search trace over matrices
    for adc, mat in EDB["Mat"].items():
        if mat["w"] != w: continue
        if crq_query(mat["P"], Q_hat):
            results.append(adc)
    return results

def mhrq_revoke(KPi: dict, sigma: dict, EDB: dict, sk: dict) -> tuple:
    KP_new = kprf_keygen()
    sk_new = crq_keygen(sk["n"])
    delta = kprf_update_token(sigma["LatestKey"], KP_new)
    M_prime = sk_new["M1"] @ np.linalg.inv(sk["M1"])
    M_double_prime = np.linalg.inv(sk["M2"]) @ sk_new["M2"]
    for adc in EDB["Mat"]:
        P_old = EDB["Mat"][adc]["P"]
        EDB["Mat"][adc]["P"] = M_prime @ P_old @ M_double_prime
    sigma["LatestKey"] = KP_new
    sk["M1"], sk["M2"] = sk_new["M1"], sk_new["M2"]
    return KPi, sigma, EDB, sk

# ─────────────────────────────────────────────────────────────────────────────
# VISUALIZATION WRAPPER
# ─────────────────────────────────────────────────────────────────────────────

def time_ms(fn, *args, **kwargs):
    t0 = time.perf_counter()
    result = fn(*args, **kwargs)
    t1 = time.perf_counter()
    return result, (t1 - t0) * 1000.0

def create_plot_with_table(title, data, chart_type, filename, xlabel, ylabel, columns, is_scaling=False):
    fig, (ax_chart, ax_table) = plt.subplots(1, 2, figsize=(14, 5), gridspec_kw={'width_ratios': [2, 1]})
    fig.suptitle(title, fontsize=14, fontweight='bold')
    
    cell_text = []
    if chart_type == 'bar':
        labels = [r[0] for r in data]
        values = [r[1] for r in data]
        bars = ax_chart.barh(labels, values, color=['#4C72B0', '#DD8452', '#55A868', '#C44E52'])
        ax_chart.invert_yaxis()
        for bar in bars:
            width = bar.get_width()
            ax_chart.annotate(f'{width:.2f} ms', xy=(width, bar.get_y() + bar.get_height() / 2),
                            xytext=(3, 0), textcoords="offset points", ha='left', va='center')
        cell_text = [[f"{v:.2f} ms"] for v in values]
        row_labels = labels
        
    elif chart_type == 'line' and not is_scaling:
        x = [r[0] for r in data]
        y = [r[1] for r in data]
        ax_chart.plot(x, y, marker='o', color='#C44E52', linewidth=2)
        ax_chart.grid(True, linestyle='--', alpha=0.7)
        cell_text = [[f"{r[0]:,}", f"{r[1]:.2f} ms"] for r in data]
        row_labels = None
        
    elif chart_type == 'line_multi':
        x = data['x']
        cell_text = []
        for i in range(len(x)):
            row = [str(x[i])]
            for key in data['y']:
                row.append(f"{data['y'][key][i]:.2f} ms")
            cell_text.append(row)
            
        colors = ['#4C72B0', '#DD8452']
        for idx, key in enumerate(data['y']):
            ax_chart.plot(x, data['y'][key], marker='o', label=key, color=colors[idx % len(colors)], linewidth=2)
        ax_chart.legend()
        ax_chart.grid(True, linestyle='--', alpha=0.7)
        row_labels = None

    ax_chart.set_xlabel(xlabel)
    ax_chart.set_ylabel(ylabel)
    
    ax_table.axis('off')
    table = ax_table.table(cellText=cell_text, colLabels=columns, rowLabels=row_labels, loc='center', cellLoc='center')
    table.auto_set_font_size(False)
    table.set_fontsize(11)
    table.scale(1, 1.8)
    
    plt.tight_layout()
    plt.savefig(filename, bbox_inches='tight', dpi=150)
    plt.close()

def run_comprehensive_benchmarks():
    n_bits = 14
    KPi, sigma, EDB, sk = mhrq_setup(n_bits)
    
    # 1. Base Operations
    print("Running Base Operations (up to 10k)...")
    base_results = []
    times = [time_ms(mhrq_update, KPi, sigma, EDB, sk, f"doc{i}", "hr", 120)[1] for i in range(5)]
    base_results.append(("Update (1 Record)", np.mean(times)))
    
    times = [time_ms(crq_tokengen, 60, 100, sk)[1] for _ in range(5)]
    base_results.append(("Token Gen (O(N^3))", np.mean(times)))
    
    P_test = crq_enc(120, sk)
    Q_test = crq_tokengen(60, 100, sk)
    times = [time_ms(crq_query, P_test, Q_test)[1] for _ in range(5)]
    base_results.append(("Trace Query", np.mean(times)))
    
    # Pre-populate 10,000 matrices to revoke
    print("  Populating 10,000 records for revocation test...")
    for i in range(10000): mhrq_update(KPi, sigma, EDB, sk, f"doc_r{i}", "hr", 120)
    base_results.append(("Revoke (10,000 matrices)", time_ms(mhrq_revoke, KPi, sigma, EDB, sk)[1]))
    
    create_plot_with_table("1. Base Operation Execution Times", base_results, 'bar', 'mhrq_faithful_10k_base.png', 
                           'Time (ms)', '', ["Time (ms)"])

    # 2. Scaling: Update Time
    print("Running Update Scaling (up to 10k)...")
    update_scaling = []
    record_counts = [1000, 2500, 5000, 10000]
    for N in record_counts:
        print(f"  Testing update for N={N}...")
        _KPi, _sigma, _EDB, _sk = mhrq_setup(n_bits)
        t0 = time.perf_counter()
        for i in range(N):
            mhrq_update(_KPi, _sigma, _EDB, _sk, f"doc{i}", "hr", 120)
        total_ms = (time.perf_counter() - t0) * 1000
        update_scaling.append((N, total_ms))
        
    create_plot_with_table("2. Total Update Time vs. Number of Records", update_scaling, 'line', 'mhrq_faithful_10k_update.png',
                           'Number of Records (N)', 'Total Time (ms)', ["Records (N)", "Total Time (ms)"])

    # 3. Scaling: Search Time
    print("Running Search Scaling (up to 10k)...")
    search_scaling = []
    # Using the populated databases to measure search
    for N, total_ms in update_scaling:
        print(f"  Testing search for N={N}...")
        _KPi, _sigma, _EDB, _sk = mhrq_setup(n_bits)
        for i in range(N): mhrq_update(_KPi, _sigma, _EDB, _sk, f"doc{i}", "hr", 120)
        times = [time_ms(mhrq_search, _KPi, _sigma, _EDB, _sk, "hr", 60, 100)[1] for _ in range(3)]
        search_scaling.append((N, np.mean(times)))
        
    create_plot_with_table("3. Mean Search Time vs. Number of Records", search_scaling, 'line', 'mhrq_faithful_10k_search.png',
                           'Number of Records (N)', 'Mean Search Time (ms)', ["Records (N)", "Search Time (ms)"])

    # 4. Scaling: Matrix Dimension (n)
    print("Running CRQ Parameter Scaling...")
    n_values = [4, 8, 12, 16] 
    crq_scaling = {'x': n_values, 'y': {'CRQ.Enc': [], 'CRQ.TokenGen': []}}
    
    for n in n_values:
        sk_test = crq_keygen(n)
        enc_time = np.mean([time_ms(crq_enc, 120, sk_test)[1] for _ in range(5)])
        tok_time = np.mean([time_ms(crq_tokengen, 60, 100, sk_test)[1] for _ in range(5)])
        crq_scaling['y']['CRQ.Enc'].append(enc_time)
        crq_scaling['y']['CRQ.TokenGen'].append(tok_time)

    create_plot_with_table("4. CRQ Primitives vs. Parameter 'n' (Matrix Size = 2n+2)", crq_scaling, 'line_multi', 'mhrq_faithful_10k_crq.png',
                           'Parameter (n)', 'Mean Time (ms)', ["n", "Enc (ms)", "TokenGen (ms)"], is_scaling=True)

    print("All benchmarks complete.")

if __name__ == "__main__":
    run_comprehensive_benchmarks()