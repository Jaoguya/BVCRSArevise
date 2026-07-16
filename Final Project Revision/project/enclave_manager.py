import hashlib
from phe import paillier
from utils import gen_tag, gen_sigma, gen_bitmap

class EnclaveManager:
    def __init__(self, secrets, abse):
        self.Ks = secrets['Ks']
        self.abse = abse           # Real ABSE instance with bilinear pairings
        self.pubkey = secrets['pubkey']
        self.privkey = secrets['privkey']
        # Opt #3: EC-ElGamal AHE (faster encrypt/decrypt)
        self.ec_pubkey = secrets.get('ec_pubkey')
        self.ec_privkey = secrets.get('ec_privkey')
        self.use_ec = self.ec_pubkey is not None
        self.node_state = {} 
        self.merkle_leaves = []

    def remote_attest(self):
        """ Item 12: TEE Manager Remote Attestation Simulation """
        return {
            "quote": hashlib.sha256(b"RUST_SGX_ENCLAVE_QUOTE_OK").hexdigest(), 
            "mrenclave": "verified",
            "leakage_param": "suppressed"
        }

    def _get_adaptive_path(self, v, l_bound=0, r_bound=100):
        """ Item 2: True Adaptive AC-SCRAT Segment Coverage """
        path = [{"l": l_bound, "r": r_bound}]
        
        size = r_bound - l_bound
        while size > 1:
            size = max(1, size // 10)
            node_l = (v // size) * size
            node_r = node_l + size
            if path[-1]["l"] != node_l or path[-1]["r"] != node_r:
                path.append({"l": node_l, "r": node_r})
                
        if path[-1]["l"] != v or path[-1]["r"] != v:
            path.append({"l": v, "r": v})
        return path

    def build_scrat_node(self, v, ctx, w_u=1):
        """ Algorithm 1: Secure SCRAT Construction [cite: 242]
        
        Now uses REAL ABSE.Enc with BN128 bilinear pairings (Eq. 18).

        Args:
            v: Sensor value (integer)
            ctx: Context tuple (m, k, t_obj)
            w_u: Context-dependent weighting factor (Eq. 20). Default=1.
        """
        m, k, t_obj = ctx 
        t_slot = t_obj.strftime("%Y-%m-%d %H")
        
        path = self._get_adaptive_path(v, 0, 100)
        nodes = []
        current_parent_sigma = "ROOT"

        from merkle_tree import MerkleTree
        for node in path:
            state_key = f"{m}|{k}|{t_slot}|{node['l']}|{node['r']}"
            
            tag = gen_tag(self.Ks, m, k, t_slot, node)
            
            # Eq. 18: CT_tag ← ABSE.Enc(PP, τ_u, P) — REAL bilinear pairing encryption
            ct_tag = self.abse.encrypt(tag, f"Analyst AND {k}")
            
            if state_key not in self.node_state:
                # Opt #3: Use EC-ElGamal if available, else Paillier
                _pub = self.ec_pubkey if self.use_ec else self.pubkey
                ct_v = _pub.encrypt(v * w_u)
                ct_count = _pub.encrypt(1)
                self.node_state[state_key] = {"w_u": v * w_u, "cnt": 1, "ct_v": ct_v, "ct_cnt": ct_count}
            else:
                s = self.node_state[state_key]
                s["w_u"] += v * w_u
                s["cnt"] += 1
                s["ct_v"] += v * w_u
                s["ct_cnt"] += 1
            
            curr_state = self.node_state[state_key]
            sigma = gen_sigma(tag, curr_state["ct_v"].ciphertext(), current_parent_sigma)

            nodes.append({
                "m_enc": hashlib.sha256(m.encode()).hexdigest(),
                "k_enc": hashlib.sha256(k.encode()).hexdigest(),
                "m": m,               # Plaintext for PRF tag recomputation
                "k": k,               # Plaintext for PRF tag recomputation
                "t": t_obj,
                "t_slot": t_slot,      # Timezone-safe string (Opt #2)
                "l": node["l"],
                "r": node["r"],
                "CT_tag": ct_tag,     # ABSE ciphertext (G₁/G₂ points) — for authorization
                "search_tag": tag,    # PRF tag for fast post-auth matching (Opt #2)
                "B_tilde": gen_bitmap(self.Ks, m, k, t_slot, node),
                "CT_v": str(curr_state["ct_v"].ciphertext()), 
                "Agg_u": str(curr_state["ct_v"].ciphertext()), 
                "Cnt_u": str(curr_state["ct_cnt"].ciphertext()), 
                "sigma": sigma,
                "parent_sigma": current_parent_sigma,
                "tag": tag
            })
            current_parent_sigma = sigma
            
        leaves_data = [f"{n['tag']}|{n['sigma']}|{n['CT_v']}|{n['Cnt_u']}" for n in nodes]
        mt = MerkleTree(leaves_data)
        root = mt.get_root()
        
        for i, n in enumerate(nodes):
            n["pi_u"] = mt.get_proof(i)
            n["root"] = root
            del n["tag"]  # Remove raw tag; search_tag remains for query

        return nodes