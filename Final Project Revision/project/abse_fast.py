"""
Optimized ABSE using Rust-native BLS12-381 pairings (py_arkworks_bls12381).

Drop-in replacement for abse_real.py that uses compiled Rust/C pairing library
instead of pure-Python py_ecc. Same security level (128-bit) as BN128.

Performance comparison (per TokenGen call):
    py_ecc BN128:     ~43ms  (pure Python — 118K function calls per multiply)
    arkworks BLS12:   ~0.8ms (compiled Rust — native field arithmetic)
    Speedup:          ~50x faster TokenGen, ~140x faster pairing

The ABSE protocol is identical — only the underlying curve changes.
Access policy: AND-gate — user must possess ALL policy attributes.
"""

import hashlib
import os
from functools import lru_cache

from py_arkworks_bls12381 import G1Point, G2Point, Scalar, GT


# BLS12-381 scalar field order
_R = 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001


# ─── Utility Functions ───────────────────────────────────────────────

def _rand_zp() -> Scalar:
    """Sample a random non-zero scalar in Z_r."""
    val = int.from_bytes(os.urandom(32), "little") % _R
    if val == 0:
        val = 1
    return Scalar.from_le_bytes(val.to_bytes(32, "little"))


def _hash_to_scalar(data: bytes) -> Scalar:
    """Hash arbitrary bytes to a valid BLS12-381 scalar."""
    h = int.from_bytes(hashlib.sha256(data).digest(), "little") % _R
    if h == 0:
        h = 1
    return Scalar.from_le_bytes(h.to_bytes(32, "little"))


@lru_cache(maxsize=4096)
def _hash_to_g1(data: bytes) -> G1Point:
    """H_g: {0,1}* → G₁  [Paper Eq. 5]
    
    Hash-to-group via hash-and-multiply: H(data) mod r → scalar → scalar * G₁.
    LRU-cached to avoid recomputing for repeated tags.
    """
    return G1Point() * _hash_to_scalar(data)


def _g1_to_str(point: G1Point) -> str:
    """Serialize G₁ point to hex string for MongoDB storage."""
    return point.to_compressed_bytes().hex()


def _str_to_g1(s: str) -> G1Point:
    """Deserialize G₁ point from hex string."""
    return G1Point.from_compressed_bytes(bytes.fromhex(s))


def _g2_to_str(point: G2Point) -> str:
    """Serialize G₂ point to hex string for MongoDB storage."""
    return point.to_compressed_bytes().hex()


def _str_to_g2(s: str) -> G2Point:
    """Deserialize G₂ point from hex string."""
    return G2Point.from_compressed_bytes(bytes.fromhex(s))


# ─── ABSE Class ──────────────────────────────────────────────────────

class ABSE:
    """
    Optimized ABSE using Rust-native BLS12-381 bilinear pairings.
    
    Security: 128-bit (equivalent to BN128 at this security level).
    Backend:  py_arkworks_bls12381 (compiled Rust via PyO3).
    Speedup:  ~50-140x over pure-Python py_ecc BN128.
    """

    def setup(self):
        """
        Eq. 1: (PP, MSK) ← ABSE.Setup(1^λ)
        
        PP  = (r, G₁, G₂, G_T, e, g, g₂)  — public parameters (BLS12-381)
        MSK = α                              — master secret key (scalar)
        """
        alpha = _rand_zp()
        self.PP = {"g": G1Point(), "g2": G2Point(), "curve_order": _R}
        self.MSK = {"alpha": alpha}
        return self.PP, self.MSK

    def key_gen(self, msk: dict, attributes: list) -> dict:
        """
        Eq. 2: SK_A ← ABSE.KeyGen(MSK, A)
        
        Per-user random r for collusion resistance.
        """
        r = _rand_zp()
        attr_keys = {}
        for attr in attributes:
            h_attr = _hash_to_g1(attr.encode())
            D_i = h_attr * r
            attr_keys[attr] = _g1_to_str(D_i)

        return {
            "attrs": attributes,
            "attr_keys": attr_keys,
            "r": r,  # Scalar object
        }

    def encrypt(self, tag: str, policy: str) -> dict:
        """
        Eq. 18: CT_tag ← ABSE.Enc(PP, τ_u, P)
        """
        s = _rand_zp()
        C1     = G1Point() * s
        C2_tag = _hash_to_g1(tag.encode()) * s
        C1_g2  = G2Point() * s

        required = [a.strip() for a in policy.split("AND")]
        C_attrs = {}
        for attr in required:
            C_attrs[attr] = _g1_to_str(_hash_to_g1(attr.encode()) * s)

        return {
            "C1":      _g1_to_str(C1),
            "C2_tag":  _g1_to_str(C2_tag),
            "C1_g2":   _g2_to_str(C1_g2),
            "C_attrs": C_attrs,
            "policy":  policy,
        }

    def token_gen(self, sk: dict, tag: str) -> dict:
        """
        Eq. 29-30: Tok_i ← ABSE.TokenGen(SK_A, τ'_u)
        
        UNLINKABLE TRAPDOOR: fresh r_q per query for unlinkability.
        ~0.8ms per call (vs ~43ms with py_ecc BN128).
        """
        r = sk["r"]
        r_q = _rand_zp()
        r_combined = r * r_q  # Scalar * Scalar (Rust-native)

        T1 = _hash_to_g1(tag.encode()) * r_combined  # ~0.2ms
        T2 = G2Point() * r_combined                   # ~0.6ms

        return {
            "T1":    _g1_to_str(T1),
            "T2":    _g2_to_str(T2),
            "attrs": sk["attrs"],
        }

    def test(self, token: dict, ct: dict) -> bool:
        """
        Eq. 34: ABSE.Test(PP, Tok_i, CT_tag) → {0, 1}
        
        Pairing equality test: ~2ms (vs ~300ms with py_ecc BN128).
        """
        # Step 1: Attribute policy check
        required = [a.strip() for a in ct["policy"].split("AND")]
        if not all(attr in token["attrs"] for attr in required):
            return False

        # Step 2: Deserialize points
        C2_tag = _str_to_g1(ct["C2_tag"])
        C1_g2  = _str_to_g2(ct["C1_g2"])
        T1     = _str_to_g1(token["T1"])
        T2     = _str_to_g2(token["T2"])

        # Step 3: Bilinear pairing equality test (~2ms)
        lhs = GT.pairing(C2_tag, T2)
        rhs = GT.pairing(T1, C1_g2)
        return lhs == rhs
