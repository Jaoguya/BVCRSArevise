"""
Shared cryptographic components for the AC-SCRAT scheme.

Paper: "Efficient Privacy-Preserving Geographic Keyword Boolean Range Query
        Over Encrypted Spatial Data"

Components:
  - TrustedAuthority (TA): System setup & key management
  - ABSESim: Attribute-Based Searchable Encryption (simplified)
  - BlockchainEdgeManager: Blockchain-based Edge Node for SCRAT construction
  - UserClient: User-side trapdoor generation
"""

import hashlib
import random
import struct
import os
from ec_elgamal import generate_ec_elgamal_keypair, ECEncryptedNumber

BASE_DIR = os.path.dirname(os.path.abspath(__file__))


# ─────────────────────────────────────────────────────────
#  Utility Functions
# ─────────────────────────────────────────────────────────

def gen_tag(Ks, m, k, t_slot, node):
    """Dual-layer tag generation (Eq. 14-16).
    PRF-based deterministic tag from (Ks, machine, keyword, time_slot, range).
    Optimized: uses struct.pack for the integer range bounds to avoid
    repeated f-string formatting overhead.
    """
    h = hashlib.sha256()
    h.update(Ks if isinstance(Ks, bytes) else Ks.encode())
    h.update(f"{m}|{k}|{t_slot}".encode())
    h.update(struct.pack('>ii', node['l'], node['r']))
    return h.hexdigest()


def gen_sigma(tag, ct_v, parent_sigma):
    """Path-consistent binding (Eq. 21).
    Binds each SCRAT node to its parent for integrity verification.
    """
    raw = f"{tag}|{ct_v}|{parent_sigma}"
    return hashlib.sha256(raw.encode()).hexdigest()


def gen_bitmap(Ks, m, k, t_slot, node):
    """Masked bitmap generation (Eq. 17).
    
    Domain-position bitmap over D_v = [0, 100]:
      - 101 bit positions, one per integer value in the domain
      - Node covering [l, r] sets bits l..r to 1
      - Bits are permuted via PRF(Ks, m|k|t_slot) — AND-preserving
      - Stored as binary string "01101..." in MongoDB
    """
    import struct
    DOMAIN_SIZE = 101
    
    # Build raw membership bitmap B_u
    B_u = 0
    for i in range(node['l'], min(node['r'], 100) + 1):
        B_u |= (1 << i)
    
    # PRF-based permutation (same as utils.py)
    ctx_bytes = Ks + f"|{m}|{k}|{t_slot}".encode()
    seed_bytes = hashlib.sha256(ctx_bytes).digest()
    positions = list(range(DOMAIN_SIZE))
    for i in range(DOMAIN_SIZE - 1, 0, -1):
        h = hashlib.sha256(seed_bytes + struct.pack('>I', i)).digest()
        j = int.from_bytes(h[:4], 'big') % (i + 1)
        positions[i], positions[j] = positions[j], positions[i]
    
    # Apply permutation
    result = 0
    for i in range(DOMAIN_SIZE):
        if B_u & (1 << i):
            result |= (1 << positions[i])
    
    return format(result, f'0{DOMAIN_SIZE}b')


# ─────────────────────────────────────────────────────────
#  Trusted Authority (TA)
# ─────────────────────────────────────────────────────────

class TrustedAuthority:
    """Trusted Authority for system-wide key management.

    Generates and manages:
      - EC-ElGamal keypair (for homomorphic encryption)
      - Master secret key MSK
      - PRF seed Ks (for tag generation)
    """

    def __init__(self, generate_new=False):
        self.MSK = hashlib.sha256(b"SCRAT_MASTER_SECRET_2026").digest()
        self.Ks = hashlib.sha256(b"PRF_SEED_K_S").digest()

        # EC-ElGamal AHE (NIST P-256, ~20× faster than Paillier)
        self.ec_pubkey, self.ec_privkey = generate_ec_elgamal_keypair(max_val=500000)

    def key_gen(self, attributes):
        """Generate key material for a user with given attributes."""
        return {
            "SK_A": {"attrs": attributes},
            "Ks": self.Ks,
            "ec_pubkey": self.ec_pubkey,
            "ec_privkey": self.ec_privkey,
        }


# ─────────────────────────────────────────────────────────
#  ABSE (Attribute-Based Searchable Encryption) - Simulated
# ─────────────────────────────────────────────────────────

class ABSESim:
    """Simplified ABSE for tag encryption and access control.

    In production, this would use CP-ABE or KP-ABE.
    Here we simulate with hash-based tag matching + policy check.
    """

    def _hash(self, data):
        return hashlib.sha256(data.encode()).hexdigest()

    def encrypt(self, message, policy):
        """ABSE Index Encryption (Eq. 18)."""
        return {"cipher": self._hash(message), "policy": policy}

    def decrypt(self, sk, ct):
        """Access Control verification - checks attribute match."""
        required = [p.strip() for p in ct["policy"].split("AND")]
        if all(r in sk["attrs"] for r in required):
            return ct["cipher"]
        return None


# ─────────────────────────────────────────────────────────
#  Blockchain Edge Manager
# ─────────────────────────────────────────────────────────

class BlockchainEdgeManager:
    """Blockchain-based Edge Node for secure SCRAT construction.

    Responsible for:
      - Building SCRAT tree nodes from plaintext sensor values
      - EC-ElGamal-encrypting values for homomorphic aggregation
      - ABSE-encrypting tags for access-controlled search
      - Recording operations on an immutable blockchain ledger
    """

    def __init__(self, secrets, abse):
        self.Ks = secrets['Ks']
        self.abse = abse
        # EC-ElGamal AHE (NIST P-256)
        self.ec_pubkey = secrets['ec_pubkey']
        self.ec_privkey = secrets['ec_privkey']

    def build_scrat_node(self, v, ctx):
        """Algorithm 1: Secure SCRAT Node Construction.

        For each data value v with context (machine, keyword, time_slot),
        builds 3-level tree: Root [0-100], Decile, Leaf [v,v].
        Each node contains:
        - CT_tag: ABSE-encrypted searchable tag
        - B_tilde: masked bitmap
        - Agg_u: EC-ElGamal-encrypted value
        - Cnt_u: EC-ElGamal-encrypted count (=1)
        - sigma: path-consistent binding hash

        Note: ct_v and ct_count are fresh EncryptedNumber objects per record.
        They must NOT be shared across records — .ciphertext() applies
        obfuscation in place, so a shared object accumulates blinding factors
        on each serialization and decrypts to garbage.
        """
        m, k, t_slot = ctx

        # 3-level SCRAT path
        path = [
            {"l": 0, "r": 100},                                      # Root
            {"l": (v // 10) * 10, "r": (v // 10) * 10 + 10},        # Decile
            {"l": v, "r": v}                                          # Leaf
        ]

        # EC-ElGamal AHE encryption
        ct_v     = self.ec_pubkey.encrypt(v)
        ct_count = self.ec_pubkey.encrypt(1)

        nodes = []
        current_parent_sigma = "ROOT"

        for node_range in path:
            tag = gen_tag(self.Ks, m, k, t_slot, node_range)
            ct_tag = self.abse.encrypt(tag, f"Analyst AND {k}")

            sigma = gen_sigma(tag, ct_v.ciphertext(), current_parent_sigma)
            current_parent_sigma = sigma

            nodes.append({
                "m": m, "k": k, "t": t_slot,
                "l": node_range["l"], "r": node_range["r"],
                "CT_tag": ct_tag,
                "B_tilde": gen_bitmap(self.Ks, m, k, t_slot, node_range),
                "Agg_u": ct_v,
                "Cnt_u": ct_count,
                "sigma": sigma
            })

        return nodes

# ─────────────────────────────────────────────────────────
#  User Client
# ─────────────────────────────────────────────────────────

class UserClient:
    """User-side component for generating search trapdoors.

    The trapdoor contains cover tokens for the requested value range,
    decomposed at decile granularity to match SCRAT tree structure.
    """

    def __init__(self, secrets):
        self.Ks = secrets["Ks"]
        self.SK_A = secrets["SK_A"]

    def generate_trapdoor(self, m, k, t_slot, a, b):
        """Phase 3: Trapdoor Generation.

        Generates search tokens covering range [a, b] at decile granularity.
        Returns (list_of_tokens, token_count).
        """
        cover_nodes = [
            {"l": i, "r": i + 10}
            for i in range((a // 10) * 10, (b // 10) * 10 + 10, 10)
        ]
        tokens = [gen_tag(self.Ks, m, k, t_slot, node) for node in cover_nodes]
        return tokens, len(cover_nodes)
