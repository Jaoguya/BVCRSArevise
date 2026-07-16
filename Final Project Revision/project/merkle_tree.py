import hashlib

def _hash(data):
    if isinstance(data, str): data = data.encode()
    return hashlib.sha256(data).hexdigest()

class MerkleTree:
    def __init__(self, leaves):
        # Allow leaves to be pre-hashed or strings
        self.leaves = [_hash(l) for l in leaves]
        self.tree = [self.leaves]
        if self.leaves:
            self._build()

    def _build(self):
        current_level = self.leaves
        while len(current_level) > 1:
            next_level = []
            for i in range(0, len(current_level), 2):
                h1 = current_level[i]
                if i + 1 < len(current_level):
                    h2 = current_level[i+1]
                    next_level.append(_hash(f"{h1}{h2}"))
                else:
                    next_level.append(h1)
            self.tree.append(next_level)
            current_level = next_level

    def get_root(self):
        return self.tree[-1][0] if self.tree else ""

    def get_proof(self, index):
        proof = []
        curr_idx = index
        for level in range(len(self.tree) - 1):
            is_right = curr_idx % 2 != 0
            sibling_idx = curr_idx - 1 if is_right else curr_idx + 1
            if sibling_idx < len(self.tree[level]):
                proof.append({"hash": self.tree[level][sibling_idx], "pos": "L" if is_right else "R"})
            curr_idx //= 2
        return proof

    @staticmethod
    def verify_proof(leaf_str, proof, root):
        curr_hash = _hash(leaf_str)
        for sib in proof:
            if sib["pos"] == "L":
                curr_hash = _hash(f"{sib['hash']}{curr_hash}")
            else:
                curr_hash = _hash(f"{curr_hash}{sib['hash']}")
        return curr_hash == root
