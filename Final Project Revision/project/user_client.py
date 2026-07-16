"""
Phase 3: User-Side Trapdoor Generation (Eq. 27-30)

Supports:
  - Single-dimension: Q = (D, [a, b])
  - Conjunctive multi-range: Q = Q_1 ∧ Q_2 ∧ ... ∧ Q_d

Real crypto: ABSE.TokenGen with BN128 bilinear pairings (Eq. 30),
             PRF tags with SHA-256 (Eq. 15-17).
"""

from utils import gen_tag, gen_query_bitmap


class UserClient:
    def __init__(self, secrets):
        self.Ks = secrets["Ks"]
        self.SK_A = secrets["SK_A"]
        self.abse = secrets["abse"]
        self.ec_privkey = secrets.get("ec_privkey")

    def _canonical_cover(self, a, b):
        """Eq. 28: Minimal canonical range-cover set at decile granularity."""
        nodes = []
        for i in range((a // 10) * 10, (b // 10) * 10 + 10, 10):
            nodes.append({"l": i, "r": min(i + 9, 100)})
        return nodes

    def generate_trapdoor(self, m, k, t_slot, a, b):
        """Phase 3: Single-dimension trapdoor (Eq. 27-30).

        Real crypto: ABSE.TokenGen (BN128 pairings), SHA-256 PRF tags.
        """
        cover = self._canonical_cover(a, b)
        tokens, search_tags, auth_token = [], [], None

        for node in cover:
            tag = gen_tag(self.Ks, m, k, t_slot, node)
            search_tags.append(tag)
            tok = self.abse.token_gen(self.SK_A, tag)
            eBQ = gen_query_bitmap(self.Ks, m, k, t_slot, a, b)
            tokens.append({
                "T1": tok["T1"], "T2": tok["T2"],
                "attrs": tok["attrs"], "eBQ": eBQ,
                "l": node["l"], "r": node["r"],
            })
            if auth_token is None:
                auth_token = {"T1": tok["T1"], "T2": tok["T2"], "attrs": tok["attrs"]}

        return {
            "m": m, "k": k, "t_slot": t_slot,
            "range": [a, b], "tokens": tokens,
            "search_tags": search_tags, "auth_token": auth_token,
        }

    def generate_conjunctive_trapdoor(self, m, t_slot, dimensions):
        """Phase 3: Conjunctive multi-range trapdoor (Eq. 27).

        Q = Q_1 ∧ Q_2 ∧ ... ∧ Q_d,  Q_j = (D_j, [a_j, b_j])

        Args:
            m: Machine ID
            t_slot: Time slot
            dimensions: List of {"k": keyword, "a": lo, "b": hi}
                e.g. [{"k":"Temp","a":20,"b":50}, {"k":"Humidity","a":60,"b":80}]

        Returns:
            Conjunctive trapdoor with per-dimension tokens.
        """
        dim_trapdoors = []
        for dim in dimensions:
            td = self.generate_trapdoor(m, dim["k"], t_slot, dim["a"], dim["b"])
            dim_trapdoors.append(td)

        return {
            "m": m, "t_slot": t_slot,
            "type": "conjunctive",
            "d": len(dimensions),
            "dimensions": dim_trapdoors,
        }

    def decrypt_aggregate(self, ct_sum_str, ct_cnt_str):
        """Phase 5 Step 4: Decrypt aggregate with sk_AHE (EC-ElGamal BSGS)."""
        if not self.ec_privkey or ct_sum_str == "0":
            return None, None
        from ec_elgamal import ECEncryptedNumber
        ct_sum = ECEncryptedNumber.from_string(self.ec_privkey.public_key, ct_sum_str)
        ct_cnt = ECEncryptedNumber.from_string(self.ec_privkey.public_key, ct_cnt_str)
        return self.ec_privkey.decrypt(ct_sum), self.ec_privkey.decrypt(ct_cnt)
