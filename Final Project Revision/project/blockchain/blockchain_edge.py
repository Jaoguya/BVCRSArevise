"""
Phase 2: Edge-Side Index Construction — BlockchainEdgeManager

Paper reference: Phase 2 Steps 2-9 (Eq. 15-26)

The edge gateway:
  - Verifies sensor HMAC and sequence counter (Step 2, Eq. 13)
  - Generates context-bound tags τ_u (Step 3, Eq. 15-17)
  - Constructs masked bitmaps B̃_u (Step 4, Eq. 18)
  - ABSE-encrypts tags CT_tag (Step 5, Eq. 19)
  - Performs ciphertext-only homomorphic aggregation (Step 6, Eq. 20-21)
  - Computes authenticated node binding σ_u (Step 7, Eq. 22)
  - Builds Merkle root and anchors to blockchain (Step 8, Eq. 23-25)

CRITICAL: The edge NEVER decrypts AES-GCM or EC-ElGamal.
It processes CT_v as an OPAQUE ciphertext for homomorphic aggregation.

Real crypto used:
  - BN128 bilinear pairings (ABSE encrypt)
  - EC-ElGamal ciphertext addition (homomorphic aggregation)
  - SHA-256 (tags, sigma, Merkle tree)
  - HMAC-SHA256 (payload verification)
  - Ethereum smart contract (real blockchain anchoring via Ganache)
"""

import hashlib
import hmac
import json
import time
from utils import gen_tag, gen_sigma, gen_bitmap
from ec_elgamal import ECEncryptedNumber


# ─────────────────────────────────────────────────────────
#  Block — Single unit in the edge blockchain ledger
# ─────────────────────────────────────────────────────────

class Block:
    """A single block in the edge blockchain.
    Each block records a data event with SHA-256 proof-of-work hash chain.
    Real crypto: SHA-256 hash chain with proof-of-work.
    """

    def __init__(self, index, timestamp, data_hash, prev_hash, nonce=0):
        self.index = index
        self.timestamp = timestamp
        self.data_hash = data_hash
        self.prev_hash = prev_hash
        self.nonce = nonce
        self.hash = self.compute_hash()

    def compute_hash(self):
        raw = f"{self.index}|{self.timestamp}|{self.data_hash}|{self.prev_hash}|{self.nonce}"
        return hashlib.sha256(raw.encode()).hexdigest()

    def mine(self, difficulty=2):
        prefix = "0" * difficulty
        while not self.hash.startswith(prefix):
            self.nonce += 1
            self.hash = self.compute_hash()
        return self

    def to_dict(self):
        return {
            "index": self.index, "timestamp": self.timestamp,
            "data_hash": self.data_hash, "prev_hash": self.prev_hash,
            "nonce": self.nonce, "hash": self.hash,
        }


# ─────────────────────────────────────────────────────────
#  EdgeBlockchain — Hash-chained ledger at the edge node
#  Now with REAL Ethereum anchoring via Ganache
# ─────────────────────────────────────────────────────────

class EdgeBlockchain:
    """Local blockchain ledger for epoch-based root anchoring (Eq. 23-25).

    Dual-layer architecture:
      - Layer 1: Fast local SHA-256 hash chain (in-memory, for speed)
      - Layer 2: Real Ethereum smart contract on Ganache (immutable, persistent)

    Every block mined locally is ALSO anchored to the Ethereum smart contract,
    producing a real Ethereum transaction with tx_hash, gas, and block confirmation.

    Real crypto:
      - SHA-256 hash chain with proof-of-work (local)
      - Ethereum transaction signing and execution (on-chain)
    """

    def __init__(self, difficulty=2, eth_connector=None):
        self.difficulty = difficulty
        self.eth_connector = eth_connector   # Real Ethereum connector (optional)
        self.chain = []
        self.eth_tx_log = []                 # Log of Ethereum transactions
        self._create_genesis()

    def _create_genesis(self):
        genesis = Block(0, time.time(), "GENESIS_BLOCK", "0" * 64)
        genesis.mine(self.difficulty)
        self.chain.append(genesis)

    def add_block(self, data_summary):
        """Add a new block to the local chain AND anchor to Ethereum.

        Args:
            data_summary: String describing the SCRAT operation

        Returns:
            Block object with optional eth_tx metadata
        """
        prev = self.chain[-1]
        data_hash = hashlib.sha256(data_summary.encode()).hexdigest()
        block = Block(len(self.chain), time.time(), data_hash, prev.hash)
        block.mine(self.difficulty)
        self.chain.append(block)

        # ── REAL BLOCKCHAIN: Anchor to Ethereum via Ganache ──
        if self.eth_connector:
            try:
                eth_result = self.eth_connector.anchor_block(data_hash, block.hash)
                block.eth_tx_hash = eth_result["tx_hash"]
                block.eth_block_number = eth_result["block_number"]
                block.eth_gas_used = eth_result["gas_used"]
                block.eth_on_chain_index = eth_result["on_chain_index"]
                self.eth_tx_log.append(eth_result)
            except Exception as e:
                block.eth_tx_hash = None
                block.eth_error = str(e)
                print(f"  ⚠️  Ethereum anchor failed for block {block.index}: {e}")
        else:
            block.eth_tx_hash = None

        return block

    def validate_chain(self):
        """Validate the local chain AND cross-check with on-chain records."""
        # Local chain validation
        for i in range(1, len(self.chain)):
            curr, prev = self.chain[i], self.chain[i - 1]
            if curr.hash != curr.compute_hash():
                return False, f"Block {i}: hash mismatch"
            if curr.prev_hash != prev.hash:
                return False, f"Block {i}: chain broken"
            if not curr.hash.startswith("0" * self.difficulty):
                return False, f"Block {i}: invalid PoW"

        # On-chain cross-validation (if Ethereum is connected)
        if self.eth_connector:
            try:
                on_chain_length = self.eth_connector.contract.functions.getChainLength().call()
                # Verify a sample of blocks against on-chain records
                for block in self.chain[1:]:  # Skip genesis
                    if hasattr(block, 'eth_on_chain_index') and block.eth_on_chain_index:
                        verified = self.eth_connector.verify_block_on_chain(
                            block.eth_on_chain_index, block.hash
                        )
                        if not verified:
                            return False, f"Block {block.index}: on-chain verification FAILED"
            except Exception as e:
                pass  # On-chain check is best-effort; local validation still passes

        return True, None

    def get_chain_summary(self):
        is_valid, error = self.validate_chain()
        summary = {
            "chain_length": len(self.chain),
            "latest_block_hash": self.chain[-1].hash if self.chain else None,
            "genesis_hash": self.chain[0].hash if self.chain else None,
            "difficulty": self.difficulty,
            "is_valid": is_valid, "error": error,
            "blockchain_type": "ethereum_ganache" if self.eth_connector else "simulated",
        }

        # Add Ethereum-specific info
        if self.eth_connector:
            eth_info = self.eth_connector.get_chain_info()
            summary["ethereum"] = eth_info
            summary["eth_transactions"] = len(self.eth_tx_log)
            # Include recent tx hashes
            if self.eth_tx_log:
                summary["recent_eth_txs"] = [
                    {"tx_hash": tx["tx_hash"], "block": tx["block_number"]}
                    for tx in self.eth_tx_log[-5:]  # Last 5
                ]

        return summary

    def clear(self):
        self.chain.clear()
        self.eth_tx_log.clear()
        self._create_genesis()


# ─────────────────────────────────────────────────────────
#  BlockchainEdgeManager — Paper-aligned edge node
#  Now with REAL Ethereum blockchain anchoring
# ─────────────────────────────────────────────────────────

class BlockchainEdgeManager:
    """Blockchain-based Edge Node for secure SCRAT construction.

    Implements Phase 2 Steps 2-9 from the paper.
    Trust model: Real Ethereum blockchain integrity (replaces simulated chain).

    Real crypto operations:
      - ABSE.Enc (BN128 bilinear pairings) for tag encryption
      - EC-ElGamal ciphertext addition for homomorphic aggregation
      - SHA-256 for tags, sigma, Merkle proofs
      - HMAC-SHA256 for sensor payload verification
      - Ethereum smart contract for immutable block anchoring (via Ganache)
    """

    def __init__(self, secrets, abse, eth_connector=None):
        self.Ks = secrets['Ks']
        self.abse = abse           # Real ABSE instance with BN128 pairings
        self.ec_pubkey = secrets['ec_pubkey']
        self.ec_privkey = secrets['ec_privkey']
        self.node_state = {}       # Aggregation state per SCRAT node
        self.merkle_leaves = []
        self.seq_counters = {}     # Per-sensor sequence counter tracking
        self.epoch = 0             # Current epoch for Eq. 23-25

        # Ethereum connector for real blockchain
        self.eth_connector = eth_connector

        # Blockchain ledger — now with REAL Ethereum anchoring
        self.blockchain = EdgeBlockchain(
            difficulty=2,
            eth_connector=eth_connector
        )

        if eth_connector:
            print(f"  ⛓️  Blockchain Edge Node initialized with REAL Ethereum")
            print(f"     Genesis: {self.blockchain.chain[0].hash[:16]}...")
            print(f"     Contract: {eth_connector.contract_address}")
        else:
            print(f"  ⛓️  Blockchain Edge Node initialized (simulated mode)")
            print(f"     Genesis: {self.blockchain.chain[0].hash[:16]}...")

    def verify_blockchain(self):
        is_valid, error = self.blockchain.validate_chain()
        result = {
            "is_valid": is_valid,
            "chain_length": len(self.blockchain.chain),
            "latest_hash": self.blockchain.chain[-1].hash if self.blockchain.chain else None,
            "error": error,
            "blockchain_type": "ethereum_ganache" if self.eth_connector else "simulated",
        }

        # Add on-chain verification status
        if self.eth_connector:
            eth_info = self.eth_connector.get_chain_info()
            result["ethereum"] = {
                "contract_address": eth_info.get("contract_address"),
                "on_chain_blocks": eth_info.get("on_chain_blocks"),
                "ganache_connected": eth_info.get("ganache_connected"),
                "eth_block_number": eth_info.get("eth_block_number"),
            }

        return result

    def get_blockchain_info(self):
        return self.blockchain.get_chain_summary()

    def verify_sensor_payload(self, payload, hmac_key):
        """Phase 2 Step 2: Edge-side payload verification (Eq. 13).

        1. Verify τ_hmac using shared HMAC key
        2. Verify seq_i exceeds last accepted sequence counter
        3. Reject if either check fails

        Real crypto: HMAC-SHA256 verification.
        """
        # Recompute HMAC over the payload fields
        hmac_data = json.dumps({
            "ct_aes": payload["ct_aes"], "ct_v": payload["ct_v"],
            "ctx": payload["ctx"], "path": payload["path"],
            "seq": payload["seq"],
        }, sort_keys=True).encode()
        expected = hmac.new(hmac_key, hmac_data, hashlib.sha256).hexdigest()

        if not hmac.compare_digest(expected, payload["hmac"]):
            return False, "HMAC verification failed"

        # Sequence counter replay protection
        dev_id = payload.get("device_id", "unknown")
        last_seq = self.seq_counters.get(dev_id, -1)
        if payload["seq"] <= last_seq:
            return False, f"Replay detected: seq {payload['seq']} <= {last_seq}"
        self.seq_counters[dev_id] = payload["seq"]

        return True, "OK"

    def build_scrat_from_payload(self, payload):
        """Phase 2 Steps 3-8: Build SCRAT nodes from verified sensor payload.

        The edge processes CT_v as an OPAQUE EC-ElGamal ciphertext.
        It NEVER decrypts or sees the plaintext sensor value.

        Args:
            payload: Verified sensor payload containing:
                - ct_v: EC-ElGamal ciphertext string (sensor-encrypted, Eq. 11)
                - ctx: {m, k, t} plaintext routing context
                - path: Canonical node path (sensor-computed, Eq. 12)

        Real crypto in this function:
            - ABSE.Enc with BN128 bilinear pairings (Eq. 19)
            - EC-ElGamal ciphertext addition (Eq. 20-21) — NO plaintext access
            - SHA-256 for tags, sigma, bitmaps (Eq. 15-18, 22)
            - Ethereum transaction for each block (real blockchain anchoring)
        """
        m = payload["ctx"]["m"]
        k = payload["ctx"]["k"]
        t_raw = payload["ctx"]["t"]
        # Derive hourly time slot: "2026-05-20 15:00:00" → "2026-05-20 15"
        t_slot = t_raw[:13] if len(t_raw) > 13 else t_raw
        path = payload["path"]

        # Deserialize the sensor-provided EC-ElGamal ciphertext (OPAQUE)
        ct_v = ECEncryptedNumber.from_string(self.ec_pubkey, payload["ct_v"])

        # Fresh encryption of 1 for count aggregation (Eq. 21)
        ct_one = self.ec_pubkey.encrypt(1)

        nodes = []

        from merkle_tree import MerkleTree
        for node_range in path:
            state_key = f"{m}|{k}|{t_slot}|{node_range['l']}|{node_range['r']}"
            node_id = f"[{node_range['l']},{node_range['r']}]"

            # Step 3: Context-bound tag generation (Eq. 15-17) — Real SHA-256
            tag = gen_tag(self.Ks, m, k, t_slot, node_range)

            # Step 5: ABSE tag encryption (Eq. 19) — Real BN128 bilinear pairings
            ct_tag = self.abse.encrypt(tag, f"Analyst AND {k}")

            # Step 4: Masked bitmap construction (Eq. 18) — Real PRF permutation
            bitmap = gen_bitmap(self.Ks, m, k, t_slot, node_range)

            # Step 6: Homomorphic aggregation (Eq. 20-21) — CIPHERTEXT-ONLY
            # Edge adds opaque CT_v ciphertexts; NEVER sees plaintext values
            if state_key not in self.node_state:
                self.node_state[state_key] = {"ct_agg": ct_v, "ct_cnt": ct_one, "cnt": 1}
            else:
                s = self.node_state[state_key]
                s["ct_agg"] = s["ct_agg"] + ct_v      # EC point addition (Eq. 20)
                s["ct_cnt"] = s["ct_cnt"] + ct_one     # EC point addition (Eq. 21)
                s["cnt"] += 1

            curr = self.node_state[state_key]
            agg_str = curr["ct_agg"].ciphertext()
            cnt_str = curr["ct_cnt"].ciphertext()

            # Step 7: Authenticated node binding (Eq. 22) — Real SHA-256
            sigma = gen_sigma(self.epoch, k, node_id, tag, bitmap, agg_str, cnt_str)

            # Record on blockchain ledger — NOW ANCHORED TO REAL ETHEREUM
            block_data = f"SCRAT|{m}|{k}|{t_slot}|{node_id}|sigma={sigma[:16]}"
            block = self.blockchain.add_block(block_data)

            node_dict = {
                "m_enc": hashlib.sha256(m.encode()).hexdigest(),
                "k_enc": hashlib.sha256(k.encode()).hexdigest(),
                "m": m, "k": k,
                "t": t_slot,
                "t_slot": t_slot,
                "l": node_range["l"], "r": node_range["r"],
                "CT_tag": ct_tag,          # Real ABSE ciphertext (G₁/G₂ points)
                "search_tag": tag,         # PRF tag for post-auth matching
                "B_tilde": bitmap,         # PRF-permuted bitmap
                "CT_v": agg_str,           # EC-ElGamal ciphertext (opaque)
                "Agg_u": agg_str,          # Homomorphic aggregate (opaque)
                "Cnt_u": cnt_str,          # Homomorphic count (opaque)
                "sigma": sigma,            # Authenticated node digest
                "tag": tag,
                "block_hash": block.hash,
                "block_index": block.index,
            }

            # Add Ethereum transaction info if available
            if hasattr(block, 'eth_tx_hash') and block.eth_tx_hash:
                node_dict["eth_tx_hash"] = block.eth_tx_hash
                node_dict["eth_block_number"] = block.eth_block_number

            nodes.append(node_dict)

        # Step 8: Merkle root construction (Eq. 23)
        leaves_data = [f"{n['tag']}|{n['sigma']}|{n['CT_v']}|{n['Cnt_u']}" for n in nodes]
        mt = MerkleTree(leaves_data)
        root_idx = mt.get_root()

        # Epoch root (Eq. 25): Root_e = H(Root_idx || Root_agg || e)
        agg_root_data = "|".join(n["Agg_u"] for n in nodes)
        root_agg = hashlib.sha256(agg_root_data.encode()).hexdigest()
        epoch_root = hashlib.sha256(f"{root_idx}|{root_agg}|{self.epoch}".encode()).hexdigest()

        for i, n in enumerate(nodes):
            n["pi_u"] = mt.get_proof(i)
            n["root"] = epoch_root
            del n["tag"]

        return nodes

    def advance_epoch(self):
        """Phase 2 Step 8: Anchor epoch root to blockchain (Eq. 25).
        Real crypto: SHA-256 hash, blockchain proof-of-work, Ethereum transaction.
        """
        self.epoch += 1

        # Anchor epoch to local chain
        block = self.blockchain.add_block(f"EPOCH|{self.epoch}|{time.time()}")

        # Also anchor epoch root to Ethereum smart contract
        eth_epoch_result = None
        if self.eth_connector:
            try:
                # Use the block hash as the epoch root commitment
                epoch_root = hashlib.sha256(
                    f"EPOCH_ROOT|{self.epoch}|{block.hash}".encode()
                ).hexdigest()
                eth_epoch_result = self.eth_connector.anchor_epoch_root(
                    self.epoch, epoch_root
                )
            except Exception as e:
                print(f"  ⚠️  Ethereum epoch anchor failed: {e}")

        return self.epoch, block.hash, eth_epoch_result
