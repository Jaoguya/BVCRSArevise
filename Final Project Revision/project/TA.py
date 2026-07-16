"""
Phase 1: System Initialization — Trusted Authority (Eq. 1-9)

Generates and distributes:
  - ABSE parameters (PP, MSK) via BN128 bilinear pairings  (Eq. 1)
  - EC-ElGamal keypair (pk_AHE, sk_AHE) over NIST P-256    (Eq. 5-6)
  - PRF seed Ks for tag/bitmap construction                  (Eq. 7-8)
  - Per-sensor AES key K_AES^(i) = KDF(K_master, ID_i)      (Eq. 10)
  - Per-sensor HMAC key K_HMAC^(i) = KDF(K_master, ID_i||"hmac") (Eq. 13)

Real crypto: BN128 pairings (ABSE), NIST P-256 (EC-ElGamal), SHA-256 (KDF).
No Paillier — paper specifies lifted EC-ElGamal exclusively.
"""

import hashlib
import os
try:
    from abse_fast import ABSE  # Rust-native BLS12-381 (~50x faster)
except ImportError:
    from abse_real import ABSE  # Fallback: pure-Python BN128
from ec_elgamal import generate_ec_elgamal_keypair


class TrustedAuthority:
    def __init__(self):
        # Phase 1 Step 3: PRF seed Ks (Eq. 7-8)
        self.Ks = hashlib.sha256(b"PRF_SEED_K_S").digest()
        self.K_master = b"MASTER_AES_KEY_IIOT_2026"

        # Phase 1 Step 2: Lifted EC-ElGamal over NIST P-256 (Eq. 5-6)
        # KeyGen: x ← Z_p*, P = xG, keypair = (P, x)
        self.ec_pubkey, self.ec_privkey = generate_ec_elgamal_keypair(max_val=500000)

        # Phase 1 Step 1: ABSE Setup (Eq. 1)
        # (PP, MSK) ← ABSE.Setup(1^λ) using BN128 bilinear pairings
        self.abse = ABSE()
        self.abse.setup()

    def get_sensor_key(self, device_id):
        """Phase 1 Step 4: Sensor AES key (Eq. 10)
        K_AES^(i) = KDF(K_master, ID_i)
        """
        raw = self.K_master + device_id.encode()
        return hashlib.sha256(raw).digest()[:16]

    def get_sensor_hmac_key(self, device_id):
        """Phase 1 Step 4: Sensor HMAC key (Eq. 13)
        K_HMAC^(i) = KDF(K_master, ID_i || "hmac")
        """
        raw = self.K_master + device_id.encode() + b"hmac"
        return hashlib.sha256(raw).digest()

    def key_gen(self, attributes):
        """Phase 1 Step 3: Attribute-based key generation (Eq. 2)
        SK_A ← ABSE.KeyGen(MSK, A) using real BN128 bilinear pairings.
        Also distributes EC-ElGamal keys and PRF seed Ks.
        """
        # Real ABSE key generation with bilinear pairing secret keys
        abse_sk = self.abse.key_gen(self.abse.MSK, attributes)

        return {
            "SK_A": abse_sk,
            "Ks": self.Ks,
            "ec_pubkey": self.ec_pubkey,
            "ec_privkey": self.ec_privkey,
            "abse": self.abse,
        }