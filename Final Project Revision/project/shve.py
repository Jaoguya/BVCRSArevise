#!/usr/bin/env python3
"""
═══════════════════════════════════════════════════════════════════════
  SHVE — Symmetric-key Hidden Vector Encryption
═══════════════════════════════════════════════════════════════════════

Paper Reference (Trinity, IEEE TIFS 2025):
  SHVE is used to encrypt index entries so that the server can
  perform predicate matching WITHOUT decrypting the data.

  A hidden vector x = (x₁, ..., x_ℓ) is encrypted under the secret key.
  A query predicate σ = (σ₁, ..., σ_ℓ) where σᵢ ∈ {0, 1, *} (* = wildcard)
  matches if σᵢ = xᵢ for all non-wildcard positions.

Algorithms:
  1. SHVE.KeyGen(1^λ) → K
     Generate master secret key K (random 256-bit key).

  2. SHVE.Enc(K, x) → CT
     Encrypt vector x = (x₁, ..., x_ℓ):
       For each dimension i:
         kᵢ = PRF(K, i)          — derive per-dimension key
         rᵢ ← random nonce
         cᵢ = H(kᵢ || xᵢ || rᵢ) — one-way commitment
       CT = (c₁, r₁, ..., c_ℓ, r_ℓ)

  3. SHVE.TokenGen(K, σ) → TK
     Generate search token for predicate σ:
       For each dimension i:
         If σᵢ ≠ *:
           tkᵢ = PRF(K, i)      — reveal per-dimension key
         Else:
           tkᵢ = ⊥              — wildcard, no key needed
       TK = (tk₁, σ₁, ..., tk_ℓ, σ_ℓ)

  4. SHVE.Match(TK, CT) → {0, 1}
     Test predicate match:
       For each non-wildcard dimension i:
         Recompute: c'ᵢ = H(tkᵢ || σᵢ || rᵢ)
         If c'ᵢ ≠ cᵢ → return 0   (mismatch)
       Return 1                     (match)

Security: IND-SCPA — ciphertexts reveal nothing about x
          beyond what the predicate match result reveals.
"""
import hashlib
import hmac
import os
import struct


class SHVE:
    """
    Symmetric-key Hidden Vector Encryption.

    Supports predicate evaluation over encrypted vectors
    with wildcard positions.
    """

    def __init__(self, vector_length):
        """
        Initialize SHVE scheme.

        Args:
            vector_length: Number of dimensions in the hidden vector (ℓ).
        """
        self.vector_length = vector_length

    # ───────────────────────────────────────────────────────────
    #  SHVE.KeyGen — Generate Master Key
    # ───────────────────────────────────────────────────────────
    def keygen(self, security_param=256):
        """
        SHVE.KeyGen(1^λ) → K

        Generate a master secret key of λ bits.

        Returns:
            bytes: Master key K.
        """
        key = os.urandom(security_param // 8)
        return key

    # ───────────────────────────────────────────────────────────
    #  SHVE.Enc — Encrypt a Hidden Vector
    # ───────────────────────────────────────────────────────────
    def encrypt(self, master_key, vector):
        """
        SHVE.Enc(K, x) → CT

        Encrypt vector x = (x₁, ..., x_ℓ).

        For each dimension i:
          1. Derive per-dimension key: kᵢ = HMAC(K, i)
          2. Sample random nonce: rᵢ ← {0,1}^128
          3. Compute commitment: cᵢ = SHA256(kᵢ || xᵢ || rᵢ)

        Args:
            master_key: Master secret key K.
            vector: List/tuple of integer values (x₁, ..., x_ℓ).

        Returns:
            List of (commitment, nonce) pairs — the ciphertext CT.
        """
        if len(vector) != self.vector_length:
            raise ValueError(
                f"Vector length {len(vector)} != expected {self.vector_length}"
            )

        ciphertext = []
        for i in range(self.vector_length):
            # Step 1: Derive per-dimension key
            ki = hmac.new(
                master_key,
                struct.pack('<I', i),
                hashlib.sha256
            ).digest()

            # Step 2: Random nonce
            ri = os.urandom(16)

            # Step 3: Commitment
            ci = hashlib.sha256(
                ki + struct.pack('<I', vector[i]) + ri
            ).digest()

            ciphertext.append((ci, ri))

        return ciphertext

    # ───────────────────────────────────────────────────────────
    #  SHVE.TokenGen — Generate Search Token
    # ───────────────────────────────────────────────────────────
    def token_gen(self, master_key, predicate):
        """
        SHVE.TokenGen(K, σ) → TK

        Generate search token for predicate σ = (σ₁, ..., σ_ℓ).
        σᵢ = None means wildcard (*).

        For each dimension i:
          If σᵢ ≠ *:  tkᵢ = HMAC(K, i)  — reveal dimension key
          If σᵢ = *:  tkᵢ = None         — no key needed

        Args:
            master_key: Master secret key K.
            predicate: List of (value or None). None = wildcard.

        Returns:
            List of (key_or_None, predicate_value_or_None) — the token TK.
        """
        if len(predicate) != self.vector_length:
            raise ValueError(
                f"Predicate length {len(predicate)} != expected {self.vector_length}"
            )

        token = []
        for i in range(self.vector_length):
            if predicate[i] is not None:
                # Non-wildcard: reveal per-dimension key
                ki = hmac.new(
                    master_key,
                    struct.pack('<I', i),
                    hashlib.sha256
                ).digest()
                token.append((ki, predicate[i]))
            else:
                # Wildcard: no key needed
                token.append((None, None))

        return token

    # ───────────────────────────────────────────────────────────
    #  SHVE.Match — Predicate Matching
    # ───────────────────────────────────────────────────────────
    def match(self, token, ciphertext):
        """
        SHVE.Match(TK, CT) → {True, False}

        Test if the encrypted vector satisfies the predicate.

        For each non-wildcard dimension i:
          Recompute: c'ᵢ = SHA256(tkᵢ || σᵢ || rᵢ)
          If c'ᵢ ≠ cᵢ → return False

        Args:
            token: Search token from token_gen().
            ciphertext: Encrypted vector from encrypt().

        Returns:
            True if predicate matches, False otherwise.
        """
        for i in range(self.vector_length):
            tk_key, tk_val = token[i]
            ct_commit, ct_nonce = ciphertext[i]

            if tk_key is None:
                # Wildcard — skip this dimension
                continue

            # Recompute commitment with token key and predicate value
            recomputed = hashlib.sha256(
                tk_key + struct.pack('<I', tk_val) + ct_nonce
            ).digest()

            if recomputed != ct_commit:
                return False  # Mismatch

        return True  # All non-wildcard dimensions match


# ═══════════════════════════════════════════════════════════════
#  Standalone test
# ═══════════════════════════════════════════════════════════════
if __name__ == '__main__':
    print("═══ SHVE Test ═══\n")

    shve = SHVE(vector_length=4)
    key = shve.keygen()
    print(f"Key: {key.hex()[:32]}...")

    # Encrypt vector
    vector = (10, 20, 30, 40)
    ct = shve.encrypt(key, vector)
    print(f"Encrypted vector {vector}: {len(ct)} components")

    # Exact match token
    tok_exact = shve.token_gen(key, (10, 20, 30, 40))
    print(f"Exact match: {shve.match(tok_exact, ct)}")  # True

    # Partial match (wildcards on dims 2,3)
    tok_partial = shve.token_gen(key, (10, 20, None, None))
    print(f"Partial match (10,20,*,*): {shve.match(tok_partial, ct)}")  # True

    # Mismatch
    tok_wrong = shve.token_gen(key, (99, 20, 30, 40))
    print(f"Mismatch (99,20,30,40): {shve.match(tok_wrong, ct)}")  # False

    # All wildcards — always matches
    tok_wild = shve.token_gen(key, (None, None, None, None))
    print(f"All wildcards: {shve.match(tok_wild, ct)}")  # True
