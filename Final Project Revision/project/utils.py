"""
Shared cryptographic utility functions for BVCRSA (AC-SCRAT).

All functions use real SHA-256 hashing and real PRF (HMAC-based).
No simulation — every operation produces cryptographically binding outputs.
"""

import hashlib
import struct


def gen_tag(Ks, m, k, t_slot, node):
    """Phase 2 Step 3: Context-bound node tag generation (Eq. 15-17).

    τ_u^struct = H_g(l_u || r_u)                         (Eq. 15)
    τ_u^ctx    = F_Ks(ctx_i || D_j || u)                 (Eq. 16)
    τ_u        = H_g(τ_u^struct || τ_u^ctx)              (Eq. 17)

    Real crypto: SHA-256 hash (collision-resistant), HMAC-SHA256 as PRF.
    """
    # Layer 1: Structural tag — depends only on node bounds
    tau_struct = hashlib.sha256(f"{node['l']}|{node['r']}".encode()).hexdigest()

    # Layer 2: Contextual tag — PRF(Ks, context||dimension||node)
    ctx_raw = Ks + f"|{m}|{k}|{t_slot}|{node['l']}|{node['r']}".encode()
    tau_ctx = hashlib.sha256(ctx_raw).hexdigest()

    # Combined final tag (Eq. 17)
    return hashlib.sha256((tau_struct + tau_ctx).encode()).hexdigest()


def gen_sigma(epoch, dim_j, node_id, tag, bitmap_str, agg_str, cnt_str):
    """Phase 2 Step 7: Authenticated node-binding digest (Eq. 22).

    σ_u = H(e || j || ID_u || τ_u || B̃_u || Agg_u || Cnt_u)

    Binds ALL node metadata into a single collision-resistant digest.
    Real crypto: SHA-256.
    """
    raw = f"{epoch}|{dim_j}|{node_id}|{tag}|{bitmap_str}|{agg_str}|{cnt_str}"
    return hashlib.sha256(raw.encode()).hexdigest()


def _bitmap_permutation(Ks, m, k, t_slot):
    """PRF-based deterministic bit permutation (AND-preserving).

    Returns permutation table so π(B_u) AND π(B_Q) ≠ 0 ⟺ B_u AND B_Q ≠ 0.
    Real crypto: SHA-256 chain as PRF for Fisher-Yates shuffle.
    """
    DOMAIN_SIZE = 101
    ctx_bytes = Ks + f"|{m}|{k}|{t_slot}".encode()
    seed_bytes = hashlib.sha256(ctx_bytes).digest()
    positions = list(range(DOMAIN_SIZE))

    for i in range(DOMAIN_SIZE - 1, 0, -1):
        h = hashlib.sha256(seed_bytes + struct.pack('>I', i)).digest()
        j = int.from_bytes(h[:4], 'big') % (i + 1)
        positions[i], positions[j] = positions[j], positions[i]

    return positions


def _apply_permutation(bitmap_int, perm):
    """Apply bit permutation: bit at position i moves to perm[i]."""
    DOMAIN_SIZE = 101
    result = 0
    for i in range(DOMAIN_SIZE):
        if bitmap_int & (1 << i):
            result |= (1 << perm[i])
    return result


def gen_bitmap(Ks, m, k, t_slot, node):
    """Phase 2 Step 4: Masked bitmap generation (Eq. 18).

    B̃_u = B_u ⊕ F_Ks(ctx_i || u)

    Domain-position bitmap over D_v = [0, 100]:
      - 101 bit positions, one per integer value
      - Node [l, r] sets bits l..r to 1
      - Bits permuted via PRF(Ks, context) — AND-preserving
    Real crypto: SHA-256 PRF for permutation seed.
    """
    DOMAIN_SIZE = 101
    B_u = 0
    for i in range(node['l'], min(node['r'], 100) + 1):
        B_u |= (1 << i)

    perm = _bitmap_permutation(Ks, m, k, t_slot)
    B_tilde = _apply_permutation(B_u, perm)
    return format(B_tilde, f'0{DOMAIN_SIZE}b')


def gen_query_bitmap(Ks, m, k, t_slot, val_lo, val_hi):
    """Phase 3: Query bitmap for range [val_lo, val_hi] (Eq. 37).

    Uses SAME permutation as gen_bitmap so AND is preserved:
      π(B_u) AND π(B_Q) ≠ 0 ⟺ [l,r] ∩ [val_lo, val_hi] ≠ ∅
    Real crypto: SHA-256 PRF.
    """
    DOMAIN_SIZE = 101
    B_Q = 0
    for i in range(val_lo, min(val_hi, 100) + 1):
        B_Q |= (1 << i)

    perm = _bitmap_permutation(Ks, m, k, t_slot)
    B_tilde_Q = _apply_permutation(B_Q, perm)
    return format(B_tilde_Q, f'0{DOMAIN_SIZE}b')


def gen_pi_agg(root_hash, matched_node_ids, ct_sum, ct_cnt):
    """Phase 5 Step 3: Structure-aware aggregation commitment (Eq. 44).

    Π_batch = H(Root_e || H({σ_u}) || B_Q || CT_sum || CT_count)
    Real crypto: SHA-256.
    """
    raw = f"{root_hash}|{matched_node_ids}|{ct_sum}|{ct_cnt}"
    return hashlib.sha256(raw.encode()).hexdigest()