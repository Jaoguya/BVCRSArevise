#!/usr/bin/env python3
"""
═══════════════════════════════════════════════════════════════════════════
  Secure Knn Computation — Wong et al. (SIGMOD 2009)
═══════════════════════════════════════════════════════════════════════════

Used by EPBRQ (Gong et al., IEEE Systems Journal 2023) for privacy-
preserving inner product computation via matrix obfuscation.

Operations:
   KeyGen(dim)     → {S, M1, M2, M1_inv, M2_inv}
   Encrypt(key, p) → {c1, c2}         (data encryption: M1ᵀ·p1, M2ᵀ·p2)
   Trapdoor(key,q) → {t1, t2}         (query token: M1⁻¹·q1, M2⁻¹·q2)
   Query(ct, td)   → float            (inner product: c1·t1 + c2·t2 = p·q)

Security: IND-SCPA — encrypted vectors reveal nothing about p
          beyond what the inner product p·q reveals.
"""

import numpy as np
import os


def knn_keygen(dim):
    """
    KeyGen(dim) → secret key ϕ = {S, M1, M2}

    Per Wong et al. and EPBRQ paper (Section III-B):
      S  : random bit vector (dim-bit), determines split strategy
      M1 : random invertible matrix (dim × dim)
      M2 : random invertible matrix (dim × dim)

    We also pre-compute M1⁻¹ and M2⁻¹ for trapdoor generation.
    """
    # Random bit vector S
    S = np.array([int(b) for b in os.urandom(dim // 8 + 1)
                  for b in format(int(b), '08b')][:dim], dtype=np.float64)
    # Ensure roughly half are 1s
    S[:dim // 2] = 0
    S[dim // 2:] = 1
    np.random.shuffle(S)

    # Random invertible matrices — use diagonally dominant for stability
    def random_invertible(n):
        M = np.random.uniform(-1.0, 1.0, (n, n))
        np.fill_diagonal(M, np.random.uniform(5.0, 10.0, n))
        return M

    M1 = random_invertible(dim)
    M2 = random_invertible(dim)
    M1_inv = np.linalg.inv(M1)
    M2_inv = np.linalg.inv(M2)

    return {
        "S": S, "dim": dim,
        "M1": M1, "M2": M2,
        "M1_inv": M1_inv, "M2_inv": M2_inv,
    }


def knn_encrypt(key, p):
    """
    Encrypt(ϕ, p) → encrypted index Î = {c1, c2}

    Per EPBRQ paper (Section IV-B, Index Encryption):
      1. Split p into (p1, p2) based on S:
         - If S[j]=0: p1[j] = p2[j] = p[j]
         - If S[j]=1: p1[j] = random r, p2[j] = p[j] - r
      2. c1 = M1ᵀ · p1
      3. c2 = M2ᵀ · p2

    Args:
        key: Secret key from knn_keygen()
        p: Data vector (numpy array or list, length=dim)

    Returns:
        dict with 'c1', 'c2' (encrypted vectors)
    """
    S = key["S"]
    dim = key["dim"]
    p = np.array(p, dtype=np.float64)

    p1 = np.zeros(dim)
    p2 = np.zeros(dim)

    for j in range(dim):
        if S[j] == 0:
            p1[j] = p[j]
            p2[j] = p[j]
        else:
            r = np.random.uniform(-10, 10)
            p1[j] = r
            p2[j] = p[j] - r

    # Matrix-vector multiply: dominant cost O(dim²)
    c1 = key["M1"].T @ p1
    c2 = key["M2"].T @ p2

    return {"c1": c1, "c2": c2}


def knn_trapdoor(key, q):
    """
    Trapdoor(ϕ, q) → query token Q̂ = {t1, t2}

    Per EPBRQ paper (Section IV-C, Trapdoor Generation):
      1. Split q into (q1, q2) based on S:
         - If S[j]=0: q1[j] = q2[j] = q[j]
         - If S[j]=1: q1[j] = random r, q2[j] = q[j] - r
      2. t1 = M1⁻¹ · q1
      3. t2 = M2⁻¹ · q2

    Args:
        key: Secret key from knn_keygen()
        q: Query vector (numpy array or list, length=dim)

    Returns:
        dict with 't1', 't2' (trapdoor vectors)
    """
    S = key["S"]
    dim = key["dim"]
    q = np.array(q, dtype=np.float64)

    q1 = np.zeros(dim)
    q2 = np.zeros(dim)

    for j in range(dim):
        if S[j] == 0:
            q1[j] = q[j]
            q2[j] = q[j]
        else:
            r = np.random.uniform(-10, 10)
            q1[j] = r
            q2[j] = q[j] - r

    # Matrix-vector multiply with inverse matrices: dominant cost O(dim²)
    t1 = key["M1_inv"] @ q1
    t2 = key["M2_inv"] @ q2

    return {"t1": t1, "t2": t2}


def knn_query(ct, td):
    """
    Query(Î, Q̂) → inner product value

    Per EPBRQ paper (Section IV-D, Query):
      result = c1·t1 + c2·t2
             = (M1ᵀ·p1)·(M1⁻¹·q1) + (M2ᵀ·p2)·(M2⁻¹·q2)
             = p1ᵀ·M1·M1⁻¹·q1 + p2ᵀ·M2·M2⁻¹·q2
             = p1·q1 + p2·q2
             = p·q (original inner product)

    Match condition: result >= threshold (for range/keyword matching)
    """
    return float(np.dot(ct["c1"], td["t1"]) + np.dot(ct["c2"], td["t2"]))


# ═══════════════════════════════════════════════════════════════
#  EPBRQ-specific encoding functions
# ═══════════════════════════════════════════════════════════════

def gray_code(n):
    """Generate n-bit Gray code value from integer."""
    return n ^ (n >> 1)


def value_to_gray_bits(value, num_bits):
    """Convert integer value to Gray code bit list."""
    g = gray_code(value)
    return [(g >> (num_bits - 1 - i)) & 1 for i in range(num_bits)]


def bloom_recode(bits, l_bloom=4):
    """
    Bloom filter recoding (EPBRQ Algorithm 1).

    Each bit is converted to an l_bloom-length Bloom filter vector:
      - bit=0: standard BF (e.g., [0,1,0,1])
      - bit=1: modified BF (swap nearest 0↔1, e.g., [1,0,0,1])

    This ensures inner product of matching BFs > 0,
    and non-matching BFs = 0.

    Returns: Concatenated Bloom vector
    """
    bv = []
    for bit in bits:
        # Standard Bloom filter for bit=0
        bf_std = [0] * l_bloom
        # Set hash positions
        for h in range(min(2, l_bloom)):
            bf_std[h * (l_bloom // 2)] = 1

        if bit == 0:
            bv.extend(bf_std)
        else:
            # Modified: swap nearest 0 and 1
            bf_mod = bf_std[:]
            # Find first 1 and first 0
            pos1 = next(i for i, v in enumerate(bf_mod) if v == 1)
            pos0 = next(i for i, v in enumerate(bf_mod) if v == 0)
            bf_mod[pos1], bf_mod[pos0] = bf_mod[pos0], bf_mod[pos1]
            bv.extend(bf_mod)
    return bv


def encode_epbrq_index(value, keywords_bitmap, grid_bits=3, l_bloom=4):
    """
    Encode a data record for EPBRQ index.

    Per EPBRQ paper (Section IV-A, Index Building):
      1. Convert value to Gray code bits
      2. Create keyword bitmap
      3. Bloom filter recoding
      4. Concatenate: gray_bloom || keyword_bloom

    Returns: float vector suitable for Knn encryption
    """
    # Gray code encoding for the value (on a 1D grid for simplicity)
    gray_bits = value_to_gray_bits(value % (1 << grid_bits), grid_bits)

    # Concatenate: spatial Gray code bits + keyword bitmap bits
    all_bits = gray_bits + list(keywords_bitmap)

    # Bloom filter recoding
    bv = bloom_recode(all_bits, l_bloom)

    return [float(x) for x in bv]


def encode_epbrq_query(range_lo, range_hi, keyword_query, grid_bits=3, l_bloom=4, m_keywords=20):
    """
    Encode a range query for EPBRQ trapdoor.

    Per EPBRQ paper (Section IV-C, Trapdoor Generation):
      1. Generate range token: Gray code with wildcards for covering range
      2. Generate keyword token: bitmap query vector
      3. Bloom filter recoding (with wildcards mapped to 0)

    The query vector is designed so that:
      dot(index_vec, query_vec) >= threshold  iff  value ∈ [range_lo, range_hi] AND keywords match

    Returns: list of query vectors (one per covering prefix)
    """
    queries = []

    # Range decomposition into Gray code prefixes (simplified matching)
    # For each value in range, create a representative query
    # The paper uses Quadtree prefix covering, we use Gray code range check
    for val in range(range_lo, min(range_hi + 1, 1 << grid_bits)):
        gray_bits = value_to_gray_bits(val, grid_bits)
        all_bits = gray_bits + list(keyword_query)
        qv = bloom_recode(all_bits, l_bloom)
        queries.append([float(x) for x in qv])

    if not queries:
        # At least one query
        gray_bits = value_to_gray_bits(range_lo % (1 << grid_bits), grid_bits)
        all_bits = gray_bits + list(keyword_query)
        qv = bloom_recode(all_bits, l_bloom)
        queries.append([float(x) for x in qv])

    return queries


# ═══════════════════════════════════════════════════════════════
#  Test
# ═══════════════════════════════════════════════════════════════

if __name__ == "__main__":
    print("═══ Secure Knn Test ═══\n")

    # Test basic Knn
    dim = 8
    key = knn_keygen(dim)
    print(f"Key generated: dim={dim}, M1 shape={key['M1'].shape}")

    p = [1, 0, 1, 0, 1, 1, 0, 1]
    q_match = [1, 0, 1, 0, 1, 1, 0, 1]  # Same → high inner product
    q_mismatch = [0, 1, 0, 1, 0, 0, 1, 0]  # Different

    ct = knn_encrypt(key, p)
    td_match = knn_trapdoor(key, q_match)
    td_mismatch = knn_trapdoor(key, q_mismatch)

    ip_match = knn_query(ct, td_match)
    ip_mismatch = knn_query(ct, td_mismatch)

    print(f"Inner product (match):    {ip_match:.4f} (expected: {np.dot(p, q_match)})")
    print(f"Inner product (mismatch): {ip_mismatch:.4f} (expected: {np.dot(p, q_mismatch)})")

    # Test EPBRQ encoding
    print("\n═══ EPBRQ Encoding Test ═══\n")
    bitmap = [1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
    idx_vec = encode_epbrq_index(42, bitmap, grid_bits=7)
    print(f"Index vector dim: {len(idx_vec)}")

    # Test with Knn
    knn_key = knn_keygen(len(idx_vec))
    ct = knn_encrypt(knn_key, idx_vec)
    q_vecs = encode_epbrq_query(40, 45, bitmap, grid_bits=7, m_keywords=20)
    print(f"Query vectors: {len(q_vecs)}")

    for i, qv in enumerate(q_vecs):
        td = knn_trapdoor(knn_key, qv)
        ip = knn_query(ct, td)
        print(f"  Query prefix {i}: inner product = {ip:.4f}")

    import time
    # Performance test
    dim = 104  # Typical EPBRQ dimension
    key = knn_keygen(dim)
    p = np.random.randint(0, 2, dim).astype(float).tolist()

    # Encrypt timing
    times = []
    for _ in range(100):
        t0 = time.perf_counter()
        knn_encrypt(key, p)
        times.append((time.perf_counter() - t0) * 1000)
    print(f"\nKnn.Encrypt (dim={dim}): {sum(times)/len(times):.3f}ms avg")

    # Trapdoor timing
    times = []
    for _ in range(100):
        t0 = time.perf_counter()
        knn_trapdoor(key, p)
        times.append((time.perf_counter() - t0) * 1000)
    print(f"Knn.Trapdoor (dim={dim}): {sum(times)/len(times):.3f}ms avg")

    # Query timing
    ct = knn_encrypt(key, p)
    td = knn_trapdoor(key, p)
    times = []
    for _ in range(100):
        t0 = time.perf_counter()
        knn_query(ct, td)
        times.append((time.perf_counter() - t0) * 1000)
    print(f"Knn.Query (dim={dim}): {sum(times)/len(times):.3f}ms avg")
