"""
Phase 4: Cloud-Side Secure Range Query Processing (Eq. 34-38)

The cloud server:
  1. Receives encrypted trapdoor from authorized user
  2. Performs ABSE bilinear pairing test for authorization (Eq. 34)
  3. Applies bitmap-constrained filtering (Eq. 37)
  4. Returns matched encrypted nodes (never sees plaintext)

Real crypto:
  - ABSE.Test: 2 BN128 bilinear pairings per authorization check
  - Bitmap AND: PRF-permuted bit intersection

The cloud NEVER holds MSK, SK_A, sk_AHE, or any secret key.
It operates solely on encrypted structures and public parameters.
"""

import hashlib
from abse_real import ABSE


class CloudServer:
    def __init__(self, collection):
        self.db = collection

    def process_query(self, trapdoor, abse_instance=None):
        """Phase 4: Conjunctive range query processing.

        Optimization #2: ABSE-once + PRF tag matching.
          1. ONE ABSE.Test to verify user authorization (2 pairings)
          2. PRF tag hash-set matching for remaining nodes (O(1) each)

        Falls back to per-node ABSE.Test if search_tags absent.
        """
        m_enc = hashlib.sha256(trapdoor["m"].encode()).hexdigest()
        k_enc = hashlib.sha256(trapdoor["k"].encode()).hexdigest()

        docs = list(self.db.find({"m_enc": m_enc, "k_enc": k_enc}))

        # ABSE instance — cloud only needs test() (stateless, no secrets)
        abse = abse_instance if abse_instance else ABSE()
        if not abse_instance:
            abse.setup()  # Only public params needed for test()

        if "search_tags" in trapdoor and trapdoor["search_tags"]:
            return self._query_fast(docs, trapdoor, abse)
        return self._query_legacy(docs, trapdoor, abse)

    def _query_fast(self, docs, trapdoor, abse):
        """Optimized: ONE ABSE.Test for auth, then PRF tag matching.

        Step 1: Authorization — ABSE.Test on ONE doc (2 BN128 pairings)
        Step 2: Matching — compare search_tag via O(1) hash set lookup
        """
        auth_token = trapdoor.get("auth_token")
        expected_tags = set(trapdoor["search_tags"])

        # Step 1: ONE ABSE.Test for authorization (Real BN128 pairings)
        authorized = False
        if auth_token and docs:
            for doc in docs:
                ct_tag = doc.get("CT_tag")
                if ct_tag:
                    token = {
                        "T1": auth_token["T1"],
                        "T2": auth_token["T2"],
                        "attrs": auth_token["attrs"],
                    }
                    if abse.test(token, ct_tag):
                        authorized = True
                        break

        if not authorized:
            return []

        # Step 2: PRF tag set matching + bitmap filter
        matched = []
        for doc in docs:
            if "tokens" in trapdoor:
                bitmap_pass = False
                for tok in trapdoor["tokens"]:
                    b_node = int(doc["B_tilde"], 2) if isinstance(doc["B_tilde"], str) and all(c in '01' for c in doc["B_tilde"]) else int(doc["B_tilde"])
                    b_query = int(tok["eBQ"], 2) if isinstance(tok["eBQ"], str) and all(c in '01' for c in tok["eBQ"]) else int(tok["eBQ"])
                    if b_node & b_query:
                        bitmap_pass = True
                        break
                if not bitmap_pass:
                    continue

            if doc.get("search_tag") in expected_tags:
                matched.append(doc)

        return matched

    def _query_legacy(self, docs, trapdoor, abse):
        """Legacy: per-node ABSE.Test (2 BN128 pairings per node)."""
        matched = []
        for doc in docs:
            for tok in trapdoor["tokens"]:
                # Step 1: Bitmap filter (Eq. 37)
                b_node = int(doc["B_tilde"], 2) if isinstance(doc["B_tilde"], str) and all(c in '01' for c in doc["B_tilde"]) else int(doc["B_tilde"])
                b_query = int(tok["eBQ"], 2) if isinstance(tok["eBQ"], str) and all(c in '01' for c in tok["eBQ"]) else int(tok["eBQ"])
                if not (b_node & b_query):
                    continue

                # Step 2: ABSE bilinear pairing test (Eq. 34)
                token = {"T1": tok["T1"], "T2": tok["T2"], "attrs": tok["attrs"]}
                if abse.test(token, doc["CT_tag"]):
                    matched.append(doc)
                    break
        return matched

    @staticmethod
    def _parse_bitmap(b):
        """Parse bitmap from stored format to integer."""
        if isinstance(b, str) and all(c in '01' for c in b):
            return int(b, 2)
        return int(b)

    def process_conjunctive_query(self, conj_trapdoor):
        """Phase 4: Conjunctive multi-range query (Eq. 27, Theorem 4).

        Q = Q_1 ∧ Q_2 ∧ ... ∧ Q_d

        For each dimension D_j:
          1. Run process_query to get matched nodes (ABSE.Test + bitmap)
          2. Collect time slots that have matches

        Conjunction: intersect time-slot sets across all dimensions.
        Only nodes from time slots matching ALL dimensions are returned.

        Real crypto: ABSE.Test (BN128 pairings) per dimension,
                     bitmap AND filtering per dimension.
        """
        dimensions = conj_trapdoor["dimensions"]

        # Step 1: Per-dimension matching
        dim_matched = []
        dim_slots = []

        for dim_td in dimensions:
            matched = self.process_query(dim_td)
            dim_matched.append(matched)
            slots = set()
            for doc in matched:
                slots.add(doc.get("t_slot", doc.get("t", "")))
            dim_slots.append(slots)

        # Step 2: Conjunctive intersection — time slots in ALL dimensions
        if dim_slots:
            common = dim_slots[0]
            for s in dim_slots[1:]:
                common &= s
        else:
            common = set()

        # Step 3: Filter each dimension to only common time slots
        filtered = []
        for i, dim_td in enumerate(dimensions):
            nodes = [d for d in dim_matched[i]
                     if d.get("t_slot", d.get("t", "")) in common]
            filtered.append({
                "k": dim_td["k"],
                "range": dim_td.get("range", []),
                "matched_nodes": nodes,
                "node_count": len(nodes),
            })

        return {
            "type": "conjunctive",
            "d": len(dimensions),
            "common_timeslots": sorted(common),
            "dimensions": filtered,
            "matched_any": len(common) > 0,
        }