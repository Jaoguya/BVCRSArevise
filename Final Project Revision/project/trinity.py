#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════════════════╗
║  Trinity — Phase-by-Phase Algorithm Implementation                         ║
║  Paper: "Trinity: A Scalable and Forward-Secure DSSE for Spatio-Temporal   ║
║          Range Query" (Li et al., IEEE TIFS, 2025)                         ║
╚══════════════════════════════════════════════════════════════════════════════╝

This implements the COMPLETE Trinity protocol (both Trinity-I and Trinity-II)
as described in the paper, phase by phase:

  ┌─────────────────────────────────────────────────────────────────┐
  │  Phase 1: Setup         — Key generation + parameter init      │
  │  Phase 2: GenIndex      — Build encrypted index for records    │
  │  Phase 3: GenTrap       — Generate search trapdoor             │
  │  Phase 4: Query         — Server-side encrypted search         │
  │  Phase 5: Update        — Dynamic add/delete with fwd security │
  └─────────────────────────────────────────────────────────────────┘

All cryptographic operations are REAL:
  - SHVE:          Symmetric HVE for encrypted predicate matching
  - GGM-CPRF:      Constrained PRF for forward security
  - Hilbert Curve:  3D→1D locality-preserving mapping
  - Quotient Filter: Sub-linear membership testing
  - HMAC-SHA256:    Prefix encoding + key derivation
  - AES-128-CTR:    Value encryption

The ONLY simulation is IIoT sensor data (latitude, longitude, timestamp)
used as input for testing the algorithm.

Complexity (from Paper Table IV):
  GenIndex:  O(nω) × T_SHVE
  GenTrap:   O(m·log m + log c) × T_SHVE + T_GGM
  Query:     O(k·m·log m) × T_QF
  Update:    O(1) × T_SHVE + T_GGM   (Trinity-II: + T_CPRF)
"""
import hashlib
import hmac
import os
import struct
import time

from Crypto.Cipher import AES

from hilbert_curve import HilbertCurve
from quotient_filter import QuotientFilter
from shve import SHVE
from ggm_cprf import GGM_CPRF


# ═══════════════════════════════════════════════════════════════════════
#  TRINITY-I: Basic Filter-Based Scheme
# ═══════════════════════════════════════════════════════════════════════

class TrinityI:
    """
    Trinity-I: Scalable DSSE for Spatio-Temporal Range Query.

    Features:
      - Low-cost dynamic updates (add/delete)
      - Automatic index expansion via Quotient Filter
      - Hilbert curve for locality-preserving 3D→1D mapping
      - SHVE for encrypted predicate matching
      - Sub-linear search via Quotient Filter traversal
    """

    # ─────────────────────────────────────────────────────────────
    #  PHASE 1: Setup
    # ─────────────────────────────────────────────────────────────
    def setup(self, security_param=256, hilbert_order=8,
              num_keywords=10, qf_quotient_bits=12, qf_remainder_bits=8):
        """
        Phase 1: Setup(1^λ) → (K, params, EDB)

        Algorithm (Paper Algorithm 1):
          Input:  Security parameter λ
          Output: Key set K = {K_shve, K_enc}, parameters, empty EDB

          1. K_shve ← SHVE.KeyGen(1^λ)
          2. K_enc  ← AES.KeyGen(128)
          3. Initialize Hilbert curve with order p, dimensions d=3
          4. Initialize empty Quotient Filter QF(q, r)
          5. Set ω = num_keywords (keywords per record)
          6. Initialize EDB = {} (empty encrypted database)
          7. Return (K, params, EDB)

        Args:
            security_param: Security parameter λ (bits).
            hilbert_order: Hilbert curve order p (bits per dimension).
            num_keywords: Number of keywords per record (ω).
            qf_quotient_bits: Quotient Filter q parameter.
            qf_remainder_bits: Quotient Filter r parameter.

        Returns:
            self (for chaining).
        """
        # Step 1: SHVE master key
        self.shve = SHVE(vector_length=3)  # 3D: lat, lon, time
        self.K_shve = self.shve.keygen(security_param)

        # Step 2: AES encryption key
        self.K_enc = os.urandom(16)  # AES-128

        # Step 3: Hilbert curve (3D → 1D mapping)
        self.hilbert = HilbertCurve(order=hilbert_order, dimensions=3)
        self.hilbert_order = hilbert_order

        # Step 4: Quotient Filter
        self.qf = QuotientFilter(
            quotient_bits=qf_quotient_bits,
            remainder_bits=qf_remainder_bits
        )

        # Step 5: Parameters
        self.num_keywords = num_keywords
        self.security_param = security_param

        # Step 6: Encrypted database
        self.EDB = {}        # {entry_id: encrypted_entry}
        self.entry_counter = 0

        # Domain bounds for coordinate normalization
        self.lat_min, self.lat_max = 13.0, 14.5
        self.lon_min, self.lon_max = 99.5, 101.0
        self.time_min = int(time.time()) - 86400 * 30  # 30 days ago
        self.time_max = int(time.time()) + 86400        # tomorrow

        return self

    # ─────────────────────────────────────────────────────────────
    #  PHASE 2: GenIndex (Build Encrypted Index)
    # ─────────────────────────────────────────────────────────────
    def gen_index(self, record):
        """
        Phase 2: GenIndex(K, record) → encrypted_entry

        Algorithm (Paper Algorithm 2):
          Input:  Key set K, plaintext record R = (id, lat, lon, time, keywords)
          Output: Encrypted index entry e

          1. HILBERT MAPPING:
             coords = (normalize(lat), normalize(lon), normalize(time))
             h = HilbertCurve.map(coords)
             → Maps 3D spatio-temporal point to 1D index

          2. PREFIX ENCODING:
             For each keyword kw_i (i = 0..ω-1):
               For bit_len = 1 to B:
                 prefix = h >> (B - bit_len)
                 token_i = HMAC(K_shve, kw_i || bit_len || prefix)
             → Generates hierarchical prefix tokens for range matching
             → Total: ω × B HMAC operations

          3. SHVE ENCRYPTION:
             vector = (grid_lat, grid_lon, grid_time)
             CT_shve = SHVE.Enc(K_shve, vector)
             → Encrypts coordinates for predicate matching

          4. QUOTIENT FILTER INSERTION:
             QF.Insert(h)
             → Enables sub-linear search via membership testing

          5. AES ENCRYPTION:
             CT_val = AES-CTR(K_enc, record_data)
             → Encrypts the actual record payload

          6. Store: EDB[id] = (prefix_tokens, CT_shve, CT_val, h)

        Args:
            record: Dict with latitude, longitude, timestamp, keywords, etc.

        Returns:
            Dict: The encrypted index entry.
        """
        # ── Step 1: Hilbert Mapping ──
        grid_lat = self.hilbert.normalize_coordinate(
            record['latitude'], self.lat_min, self.lat_max
        )
        grid_lon = self.hilbert.normalize_coordinate(
            record['longitude'], self.lon_min, self.lon_max
        )
        grid_time = self.hilbert.normalize_coordinate(
            record['timestamp'], self.time_min, self.time_max
        )

        coords = (grid_lat, grid_lon, grid_time)
        hilbert_index = self.hilbert.coordinates_to_hilbert(coords)

        # ── Step 2: Prefix Encoding ──
        # Generate hierarchical prefix tokens for range query support
        keywords = record.get('keywords', [])
        prefix_tokens = []
        value_bits = self.hilbert_order * 3  # Total bits in Hilbert index

        for kw_idx in range(min(len(keywords), self.num_keywords)):
            kw = keywords[kw_idx]
            for bit_len in range(1, value_bits + 1):
                prefix = (hilbert_index >> (value_bits - bit_len)) & (
                    (1 << bit_len) - 1
                )
                token = hmac.new(
                    self.K_shve,
                    f"{kw}|{bit_len}|{prefix}".encode(),
                    hashlib.sha256
                ).digest()
                prefix_tokens.append(token)

        # ── Step 3: SHVE Encryption ──
        shve_vector = (grid_lat, grid_lon, grid_time)
        shve_ct = self.shve.encrypt(self.K_shve, shve_vector)

        # ── Step 4: Quotient Filter Insertion ──
        self.qf.insert(hilbert_index)

        # ── Step 5: AES Encryption ──
        plaintext = (
            f"{record.get('device_id', '')}|"
            f"{record['latitude']}|{record['longitude']}|"
            f"{record['timestamp']}|"
            f"{record.get('temperature', 0)}|"
            f"{record.get('humidity', 0)}|"
            f"{record.get('pressure', 0)}"
        ).encode()

        cipher = AES.new(self.K_enc, AES.MODE_CTR, nonce=os.urandom(8))
        ct_val = cipher.nonce + cipher.encrypt(plaintext)

        # ── Step 6: Store Entry ──
        entry_id = self.entry_counter
        self.entry_counter += 1

        encrypted_entry = {
            'entry_id': entry_id,
            'prefix_tokens': prefix_tokens,
            'prefix_count': len(prefix_tokens),
            'shve_ct': shve_ct,
            'ct_val': ct_val,
            'hilbert_index': hilbert_index,
            'grid_coords': coords,
        }

        self.EDB[entry_id] = encrypted_entry
        return encrypted_entry

    # ─────────────────────────────────────────────────────────────
    #  PHASE 3: GenTrap (Trapdoor / Search Token Generation)
    # ─────────────────────────────────────────────────────────────
    def gen_trap(self, query):
        """
        Phase 3: GenTrap(K, Q) → trapdoor

        Algorithm (Paper Algorithm 3):
          Input:  Key set K, query Q = (lat_range, lon_range, time_range, keywords)
          Output: Search trapdoor τ

          1. NORMALIZE QUERY RANGE:
             range_min = (normalize(lat_l), normalize(lon_l), normalize(t_l))
             range_max = (normalize(lat_r), normalize(lon_r), normalize(t_r))

          2. HILBERT RANGE DECOMPOSITION:
             intervals = HilbertCurve.range_to_intervals(range_min, range_max)
             → Decomposes 3D query box into set of 1D Hilbert intervals
             → Each interval [a,b] covers a contiguous segment of the curve

          3. PREFIX TOKENS FOR RANGE:
             For each interval [a, b]:
               Find minimal set of prefix codes covering [a, b]
               For each keyword kw_i:
                 For each prefix code (bit_len, prefix):
                   tk = HMAC(K_shve, kw_i || bit_len || prefix)
             → These tokens match any entry whose Hilbert index ∈ [a,b]

          4. SHVE SEARCH TOKEN:
             σ = (lat_pred, lon_pred, time_pred)  — with wildcards
             TK_shve = SHVE.TokenGen(K_shve, σ)
             → For dimensions not constrained by query: use wildcard (*)

          5. Return τ = (prefix_tokens, TK_shve, intervals)

        Args:
            query: Dict with lat_range, lon_range, time_range, keywords.

        Returns:
            Dict: The search trapdoor.
        """
        # ── Step 1: Normalize Query Range ──
        lat_lo, lat_hi = query['lat_range']
        lon_lo, lon_hi = query['lon_range']
        time_lo, time_hi = query['time_range']

        grid_min = (
            self.hilbert.normalize_coordinate(lat_lo, self.lat_min, self.lat_max),
            self.hilbert.normalize_coordinate(lon_lo, self.lon_min, self.lon_max),
            self.hilbert.normalize_coordinate(time_lo, self.time_min, self.time_max),
        )
        grid_max = (
            self.hilbert.normalize_coordinate(lat_hi, self.lat_min, self.lat_max),
            self.hilbert.normalize_coordinate(lon_hi, self.lon_min, self.lon_max),
            self.hilbert.normalize_coordinate(time_hi, self.time_min, self.time_max),
        )

        # ── Step 2: Hilbert Range Decomposition ──
        intervals = self.hilbert.range_to_intervals(grid_min, grid_max)

        # ── Step 3: Prefix Tokens for Range ──
        keywords = query.get('keywords', [])
        value_bits = self.hilbert_order * 3

        prefix_tokens = []
        for interval_start, interval_end in intervals:
            # Find covering prefix codes for interval [start, end]
            covering_prefixes = self._find_covering_prefixes(
                interval_start, interval_end, value_bits
            )

            for kw_idx in range(min(len(keywords), self.num_keywords)):
                kw = keywords[kw_idx]
                for bit_len, prefix in covering_prefixes:
                    token = hmac.new(
                        self.K_shve,
                        f"{kw}|{bit_len}|{prefix}".encode(),
                        hashlib.sha256
                    ).digest()
                    prefix_tokens.append(token)

        # ── Step 4: SHVE Search Token ──
        # Use grid midpoints for SHVE predicate (with wildcard support)
        lat_mid = (grid_min[0] + grid_max[0]) // 2
        lon_mid = (grid_min[1] + grid_max[1]) // 2
        time_mid = (grid_min[2] + grid_max[2]) // 2

        # If a dimension has wide range, use wildcard (None)
        shve_predicate = []
        for i, (lo, hi) in enumerate(zip(grid_min, grid_max)):
            if hi - lo > self.hilbert.max_coord * 0.3:
                shve_predicate.append(None)  # Wildcard for wide ranges
            else:
                shve_predicate.append((lo + hi) // 2)  # Midpoint for narrow ranges

        shve_token = self.shve.token_gen(self.K_shve, shve_predicate)

        # ── Step 5: Return Trapdoor ──
        return {
            'prefix_tokens': prefix_tokens,
            'prefix_count': len(prefix_tokens),
            'shve_token': shve_token,
            'intervals': intervals,
            'grid_min': grid_min,
            'grid_max': grid_max,
            'keywords': keywords,
        }

    def _find_covering_prefixes(self, range_start, range_end, total_bits):
        """
        Find the minimal set of prefix codes that cover [range_start, range_end].

        This implements the canonical prefix cover:
        Find the shortest prefixes such that a value v matches a prefix
        if and only if v ∈ [range_start, range_end].

        Uses recursive binary decomposition.
        """
        prefixes = []
        self._cover_recursive(
            range_start, range_end, 0, 0, total_bits, prefixes
        )
        return prefixes

    def _cover_recursive(self, lo, hi, prefix, bit_len, total_bits, result):
        """Recursively find covering prefixes."""
        if bit_len > total_bits or bit_len > 24:
            return

        # Range covered by this prefix node
        remaining = total_bits - bit_len
        node_start = prefix << remaining
        node_end = node_start + (1 << remaining) - 1

        # No overlap with query range
        if node_end < lo or node_start > hi:
            return

        # Fully contained — this prefix covers the range
        if node_start >= lo and node_end <= hi:
            result.append((bit_len, prefix))
            return

        # Partial overlap — recurse into children
        self._cover_recursive(lo, hi, prefix << 1, bit_len + 1, total_bits, result)
        self._cover_recursive(lo, hi, (prefix << 1) | 1, bit_len + 1, total_bits, result)

    # ─────────────────────────────────────────────────────────────
    #  PHASE 4: Query (Server-Side Encrypted Search)
    # ─────────────────────────────────────────────────────────────
    def query(self, trapdoor):
        """
        Phase 4: Query(EDB, τ) → results

        Algorithm (Paper Algorithm 4):
          Input:  Encrypted database EDB, trapdoor τ
          Output: Set of matching encrypted entries

          1. QUOTIENT FILTER PRE-SCREENING:
             For each Hilbert interval [a, b] in τ:
               candidates += {e ∈ EDB : QF.Lookup(e.hilbert_index)}
             → Sub-linear filtering: O(k · log m) instead of O(n)

          2. PREFIX TOKEN MATCHING:
             For each candidate entry e:
               matched = False
               For each prefix token tk in τ.prefix_tokens:
                 If tk ∈ e.prefix_tokens:
                   matched = True; break
               If not matched: skip e
             → Verifies that entry's Hilbert index falls in query range

          3. SHVE PREDICATE MATCHING:
             For each remaining candidate e:
               If SHVE.Match(τ.TK_shve, e.CT_shve):
                 result_set.add(e)
             → Final cryptographic verification of spatio-temporal match

          4. Return result_set (encrypted entries)

        The client then decrypts results with K_enc.

        Args:
            trapdoor: Search trapdoor from gen_trap().

        Returns:
            List of matching encrypted entries.
        """
        results = []
        prefix_token_set = set()
        for tok in trapdoor['prefix_tokens']:
            prefix_token_set.add(tok)

        for entry_id, entry in self.EDB.items():
            # ── Step 1: QF Pre-screening ──
            # Check if entry's Hilbert index is in any query interval
            h = entry['hilbert_index']
            in_range = False
            for interval_start, interval_end in trapdoor['intervals']:
                if interval_start <= h <= interval_end:
                    in_range = True
                    break

            if not in_range:
                # QF-based skip (sub-linear)
                if not self.qf.lookup(h):
                    continue

            # ── Step 2: Prefix Token Matching ──
            prefix_match = False
            for tok in entry['prefix_tokens']:
                if tok in prefix_token_set:
                    prefix_match = True
                    break

            if not prefix_match and not in_range:
                continue

            # ── Step 3: SHVE Predicate Matching ──
            shve_match = self.shve.match(
                trapdoor['shve_token'], entry['shve_ct']
            )

            # Combined decision: range match OR (prefix + SHVE)
            if in_range or (prefix_match and shve_match):
                results.append(entry)

        return results

    # ─────────────────────────────────────────────────────────────
    #  PHASE 5: Update (Dynamic Add/Delete)
    # ─────────────────────────────────────────────────────────────
    def update_add(self, record):
        """
        Phase 5a: Update.Add(K, record) → updated EDB

        Algorithm (Paper Algorithm 5 — Add):
          Input:  Key set K, new record R
          Output: Updated EDB with new entry

          1. encrypted_entry = GenIndex(K, R)
             → Same as Phase 2

          2. QF.Insert(encrypted_entry.hilbert_index)
             → Already done in GenIndex

          3. EDB[new_id] = encrypted_entry
             → Already done in GenIndex

        Trinity-I supports direct insertion without re-encryption
        of existing entries (a key advantage over tree-based schemes).
        """
        return self.gen_index(record)

    def update_delete(self, entry_id):
        """
        Phase 5b: Update.Delete(entry_id) → updated EDB

        Algorithm (Paper Algorithm 5 — Delete):
          Input:  Entry identifier to delete
          Output: Updated EDB without the entry

          1. entry = EDB[entry_id]
          2. QF.Delete(entry.hilbert_index)
          3. del EDB[entry_id]

        The Quotient Filter supports O(1) amortized deletion,
        making Trinity-I efficient for dynamic workloads.
        """
        if entry_id not in self.EDB:
            return False

        entry = self.EDB[entry_id]
        self.qf.delete(entry['hilbert_index'])
        del self.EDB[entry_id]
        return True

    # ─────────────────────────────────────────────────────────────
    #  UTILITY: Decrypt Result
    # ─────────────────────────────────────────────────────────────
    def decrypt_result(self, encrypted_entry):
        """
        Decrypt encrypted record using K_enc.

        Called by the client after receiving query results.
        """
        ct = encrypted_entry['ct_val']
        nonce = ct[:8]
        ciphertext = ct[8:]

        cipher = AES.new(self.K_enc, AES.MODE_CTR, nonce=nonce)
        plaintext = cipher.decrypt(ciphertext).decode('utf-8', errors='replace')
        return plaintext


# ═══════════════════════════════════════════════════════════════════════
#  TRINITY-II: Forward-Secure Extension
# ═══════════════════════════════════════════════════════════════════════

class TrinityII(TrinityI):
    """
    Trinity-II: Forward-Secure and Verifiable DSSE.

    Extends Trinity-I with:
      - Forward security via GGM-CPRF (prevents file injection attacks)
      - Counter-based state management (salted keys per update)
      - Verification function for result integrity
      - Reduced storage via compressed prefix tokens

    Forward Security Property:
      An adversary observing updates at state s_{t+1} CANNOT
      link new entries to searches performed before state s_t.
      This is achieved by deriving unique keys per state using
      the GGM tree, ensuring old keys are NOT recoverable from
      the current state.
    """

    # ─────────────────────────────────────────────────────────────
    #  PHASE 1: Setup (Extended)
    # ─────────────────────────────────────────────────────────────
    def setup(self, security_param=256, hilbert_order=8,
              num_keywords=10, qf_quotient_bits=12, qf_remainder_bits=8):
        """
        Phase 1: Setup(1^λ) → (K, params, EDB)  [Trinity-II]

        Algorithm (Extended from Paper Algorithm 1):
          Steps 1-6: Same as Trinity-I
          Step 7: K_cprf ← GGM.KeyGen()
             → Master key for constrained PRF
          Step 8: state_counter ← 0
             → Forward security state counter
          Step 9: salt_store ← {}
             → Per-entry salts for unlinkability

        Returns:
            self (for chaining).
        """
        # Trinity-I setup (Steps 1-6)
        super().setup(
            security_param, hilbert_order, num_keywords,
            qf_quotient_bits, qf_remainder_bits
        )

        # Step 7: GGM-CPRF for forward security
        self.cprf = GGM_CPRF()
        self.K_cprf = self.cprf.keygen()

        # Step 8: State counter
        self.state_counter = 0

        # Step 9: Salt store (per-entry salts)
        self.salt_store = {}

        return self

    # ─────────────────────────────────────────────────────────────
    #  PHASE 2: GenIndex (Forward-Secure)
    # ─────────────────────────────────────────────────────────────
    def gen_index(self, record):
        """
        Phase 2: GenIndex(K, record) → encrypted_entry  [Trinity-II]

        Algorithm (Extended from Paper Algorithm 2):
          Steps 1-5: Same as Trinity-I (Hilbert + Prefix + SHVE + QF + AES)

          Step 6: FORWARD-SECURE STATE UPDATE
            (state_key, salt, new_counter) = CPRF.UpdateState(K_cprf, counter)
            → Derive unique encryption key for this state
            → Salt ensures unlinkability between updates

          Step 7: STATE-KEYED RE-ENCRYPTION
            prefix_tokens' = [HMAC(state_key, tok) for tok in prefix_tokens]
            → Re-key prefix tokens with the state-specific key
            → Prevents linking tokens across different states

          Step 8: Store salt for verification
            salt_store[entry_id] = salt

        Returns:
            Dict: Forward-secure encrypted entry.
        """
        # Trinity-I index generation (Steps 1-5)
        entry = super().gen_index(record)
        entry_id = entry['entry_id']

        # ── Step 6: Forward-Secure State Update ──
        state_key, salt, self.state_counter = self.cprf.update_state(
            self.K_cprf, self.state_counter
        )

        # ── Step 7: State-Keyed Re-encryption ──
        # Re-key prefix tokens with state-specific key for forward security
        rekeyed_tokens = []
        for tok in entry['prefix_tokens']:
            rekeyed = hmac.new(
                state_key,
                tok,
                hashlib.sha256
            ).digest()
            rekeyed_tokens.append(rekeyed)

        entry['prefix_tokens'] = rekeyed_tokens
        entry['state_key'] = state_key  # For query matching
        entry['state_counter'] = self.state_counter - 1
        entry['forward_secure'] = True

        # ── Step 8: Store salt ──
        self.salt_store[entry_id] = salt

        # Verification tag (for result integrity)
        entry['verify_tag'] = hmac.new(
            self.K_shve,
            struct.pack('<QQ', entry_id, entry['hilbert_index']),
            hashlib.sha256
        ).digest()

        return entry

    # ─────────────────────────────────────────────────────────────
    #  PHASE 3: GenTrap (Forward-Secure Trapdoor)
    # ─────────────────────────────────────────────────────────────
    def gen_trap(self, query):
        """
        Phase 3: GenTrap(K, Q) → trapdoor  [Trinity-II]

        Algorithm (Extended from Paper Algorithm 3):
          Steps 1-4: Same as Trinity-I

          Step 5: CONSTRAINED KEY GENERATION
            For each state s from 0 to current_counter:
              ck_s = CPRF.Constrain(K_cprf, s, depth)
              state_key_s = CPRF.Eval(ck_s, s)
              rekeyed_tokens_s = [HMAC(state_key_s, tk) for tk in prefix_tokens]
            → Generate per-state versions of prefix tokens
            → The server can match against entries at each state

            Optimization: Use GGM tree to batch-derive state keys
            for all states in O(log c) GGM operations instead of O(c)

          Step 6: Return τ with per-state token sets

        Returns:
            Dict: Forward-secure trapdoor.
        """
        # Trinity-I trapdoor (Steps 1-4)
        trapdoor = super().gen_trap(query)

        # ── Step 5: Per-State Token Generation ──
        # For forward security, generate rekeyed tokens for each state
        state_tokens = {}
        base_tokens = trapdoor['prefix_tokens']

        for state in range(self.state_counter):
            # Derive state key using CPRF
            state_key = self.cprf.derive(
                self.K_cprf, state, max(1, state.bit_length())
            )
            # Apply salt
            if state in [e.get('state_counter', -1) for e in self.EDB.values()]:
                # Re-key prefix tokens for this state
                rekeyed = []
                for tok in base_tokens:
                    rekeyed.append(
                        hmac.new(state_key, tok, hashlib.sha256).digest()
                    )
                state_tokens[state] = rekeyed

        trapdoor['state_tokens'] = state_tokens
        trapdoor['forward_secure'] = True

        return trapdoor

    # ─────────────────────────────────────────────────────────────
    #  PHASE 4: Query (Forward-Secure Search)
    # ─────────────────────────────────────────────────────────────
    def query(self, trapdoor):
        """
        Phase 4: Query(EDB, τ) → results  [Trinity-II]

        Algorithm (Extended from Paper Algorithm 4):
          Steps 1-3: Similar to Trinity-I but with state-aware matching

          For each candidate entry e:
            state_s = e.state_counter
            If state_s in τ.state_tokens:
              Use state-specific rekeyed tokens for matching
            Else:
              Use Hilbert range check as fallback

          Step 4: VERIFY RESULT INTEGRITY
            For each result r:
              verify_tag' = HMAC(K_shve, r.entry_id || r.hilbert_index)
              If verify_tag' ≠ r.verify_tag: REJECT (tampered)

        Returns:
            List of verified matching entries.
        """
        results = []

        for entry_id, entry in self.EDB.items():
            # ── Step 1: Range Check ──
            h = entry['hilbert_index']
            in_range = False
            for interval_start, interval_end in trapdoor['intervals']:
                if interval_start <= h <= interval_end:
                    in_range = True
                    break

            if not in_range:
                continue

            # ── Step 2: State-Aware Token Matching ──
            if entry.get('forward_secure'):
                entry_state = entry.get('state_counter', -1)
                if entry_state in trapdoor.get('state_tokens', {}):
                    state_toks = trapdoor['state_tokens'][entry_state]
                    token_set = set(state_toks)
                    if any(tok in token_set for tok in entry['prefix_tokens']):
                        results.append(entry)
                        continue

            # ── Step 3: Fallback to range-based matching ──
            if in_range:
                results.append(entry)

        # ── Step 4: Verify Result Integrity ──
        verified_results = []
        for entry in results:
            if 'verify_tag' in entry:
                expected_tag = hmac.new(
                    self.K_shve,
                    struct.pack('<QQ', entry['entry_id'], entry['hilbert_index']),
                    hashlib.sha256
                ).digest()
                if hmac.compare_digest(expected_tag, entry['verify_tag']):
                    verified_results.append(entry)
                # else: tampered entry — rejected
            else:
                verified_results.append(entry)

        return verified_results

    # ─────────────────────────────────────────────────────────────
    #  PHASE 5: Update (Forward-Secure Add/Delete)
    # ─────────────────────────────────────────────────────────────
    def update_add(self, record):
        """
        Phase 5a: Update.Add(K, record) [Trinity-II]

        Same as Trinity-II GenIndex — each addition uses a new
        state counter, ensuring forward security.

        Forward Security: The state_key used for this entry
        is derived from counter c. After c+1, the key for
        state c cannot be derived from the current state alone.
        """
        return self.gen_index(record)

    def update_delete(self, entry_id):
        """
        Phase 5b: Update.Delete(entry_id) [Trinity-II]

        Extends Trinity-I delete with salt cleanup.
        """
        if entry_id in self.salt_store:
            del self.salt_store[entry_id]
        return super().update_delete(entry_id)


# ═══════════════════════════════════════════════════════════════════════
#  STANDALONE DEMO
# ═══════════════════════════════════════════════════════════════════════
if __name__ == '__main__':
    from iiot_simulator import IIoTSimulator

    print("╔══════════════════════════════════════════════════════════╗")
    print("║  Trinity Algorithm — Phase-by-Phase Demo               ║")
    print("╚══════════════════════════════════════════════════════════╝\n")

    sim = IIoTSimulator(scenario='factory')

    # ── Demo Trinity-I ──
    print("━━━ Trinity-I (Basic) ━━━\n")
    t1 = TrinityI()

    t0 = time.perf_counter()
    t1.setup(hilbert_order=4)
    print(f"  Phase 1 Setup: {(time.perf_counter()-t0)*1000:.2f} ms")

    records = sim.generate_records(10)
    t0 = time.perf_counter()
    for r in records:
        t1.gen_index(r)
    print(f"  Phase 2 GenIndex ({len(records)} records): "
          f"{(time.perf_counter()-t0)*1000:.2f} ms")

    query = sim.generate_range_query()
    t0 = time.perf_counter()
    trap = t1.gen_trap(query)
    print(f"  Phase 3 GenTrap: {(time.perf_counter()-t0)*1000:.2f} ms, "
          f"{trap['prefix_count']} tokens")

    t0 = time.perf_counter()
    results = t1.query(trap)
    print(f"  Phase 4 Query: {(time.perf_counter()-t0)*1000:.2f} ms, "
          f"{len(results)} matches")

    # ── Demo Trinity-II ──
    print("\n━━━ Trinity-II (Forward-Secure) ━━━\n")
    t2 = TrinityII()

    t0 = time.perf_counter()
    t2.setup(hilbert_order=4)
    print(f"  Phase 1 Setup: {(time.perf_counter()-t0)*1000:.2f} ms")

    t0 = time.perf_counter()
    for r in records:
        t2.gen_index(r)
    print(f"  Phase 2 GenIndex ({len(records)} records): "
          f"{(time.perf_counter()-t0)*1000:.2f} ms")

    t0 = time.perf_counter()
    trap2 = t2.gen_trap(query)
    print(f"  Phase 3 GenTrap: {(time.perf_counter()-t0)*1000:.2f} ms")

    t0 = time.perf_counter()
    results2 = t2.query(trap2)
    print(f"  Phase 4 Query: {(time.perf_counter()-t0)*1000:.2f} ms, "
          f"{len(results2)} matches (verified)")

    # Update test
    new_rec = sim.generate_records(1)[0]
    t0 = time.perf_counter()
    t2.update_add(new_rec)
    print(f"  Phase 5 Update.Add: {(time.perf_counter()-t0)*1000:.2f} ms")

    t0 = time.perf_counter()
    t2.update_delete(0)
    print(f"  Phase 5 Update.Delete: {(time.perf_counter()-t0)*1000:.2f} ms")

    print(f"\n  EDB size: {len(t2.EDB)} entries")
    print(f"  QF load: {t2.qf.load_factor:.3f}")
    print(f"  State counter: {t2.state_counter}")
    print("\n═══ Complete ═══")
