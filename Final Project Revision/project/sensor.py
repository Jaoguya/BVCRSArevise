"""
Phase 2 Step 1: Sensor-Side Encryption (Eq. 10-14)

Each sensor locally performs:
  (a) AES-GCM encryption of full tuple  (Eq. 10)
  (b) EC-ElGamal encryption of value v  (Eq. 11)
  (c) Canonical path computation         (Eq. 12)
  (d) HMAC tag construction              (Eq. 13)

The sensor NEVER sends plaintext values to the edge.
Real cryptographic operations: AES-GCM, EC-ElGamal (NIST P-256), HMAC-SHA256.
"""

import hashlib
import hmac
import base64
import json
from Crypto.Cipher import AES


def compute_canonical_path(v, domain_min=0, domain_max=100):
    """Eq. 12: Canonical path via O(log|D_j|) decomposition.

    For domain [0,100] with decile granularity (3-level SCRAT):
      Level 0 (Root):   [0, 100]
      Level 1 (Decile): [(v//10)*10, (v//10)*10+9]
      Level 2 (Leaf):   [v, v]
    """
    decile_l = (v // 10) * 10
    decile_r = min(decile_l + 9, domain_max)
    return [
        {"l": domain_min, "r": domain_max},
        {"l": decile_l, "r": decile_r},
        {"l": v, "r": v},
    ]


def sensor_encrypt(device_id, m, k, t_str, v, aes_key, hmac_key, ec_pubkey, seq_counter):
    """Phase 2 Step 1: Full sensor-side encryption pipeline.

    Returns payload R_i = (CT_AES, CT_v, ctx, P_v, seq, τ_hmac)  [Eq. 14]
    """
    # (a) AES-GCM encryption of the full tuple (Eq. 10)
    plaintext = f"{m}|{k}|{t_str}|{v}"
    cipher = AES.new(aes_key, AES.MODE_GCM)
    ct_bytes, auth_tag = cipher.encrypt_and_digest(plaintext.encode())
    ct_aes = {
        "iv": base64.b64encode(cipher.nonce).decode(),
        "payload": base64.b64encode(ct_bytes).decode(),
        "auth_tag": base64.b64encode(auth_tag).decode(),
    }

    # (b) EC-ElGamal encryption of the numerical value (Eq. 11)
    ct_v = ec_pubkey.encrypt(v)
    ct_v_str = ct_v.ciphertext()

    # (c) Canonical path computation (Eq. 12)
    path = compute_canonical_path(v)

    # (d) HMAC tag construction (Eq. 13)
    ctx = {"m": m, "k": k, "t": t_str}
    hmac_data = json.dumps({
        "ct_aes": ct_aes, "ct_v": ct_v_str,
        "ctx": ctx, "path": path, "seq": seq_counter,
    }, sort_keys=True).encode()
    tau_hmac = hmac.new(hmac_key, hmac_data, hashlib.sha256).hexdigest()

    return {
        "ct_aes": ct_aes,
        "ct_v": ct_v_str,
        "ctx": ctx,
        "path": path,
        "seq": seq_counter,
        "hmac": tau_hmac,
        "device_id": device_id,
    }
