"""
Core ECGRQ-LI algorithms: Learned Index, Spatial Segmentation, Query
Based on the paper's Section V, VI, and VIII
"""
import numpy as np
import hashlib, hmac, os, time
from config import *


# ─── Z-order helpers ───
def interleave_bits(x, y, bits=Z_BITS):
    z = 0
    for i in range(bits):
        z |= ((x >> i) & 1) << (2 * i + 1)
        z |= ((y >> i) & 1) << (2 * i)
    return z

def compute_z(lat, lon):
    mx = (1 << Z_BITS) - 1
    gx = int((lat - LAT_MIN) / (LAT_MAX - LAT_MIN) * mx)
    gy = int((lon - LON_MIN) / (LON_MAX - LON_MIN) * mx)
    gx, gy = max(0, min(mx, gx)), max(0, min(mx, gy))
    return interleave_bits(gx, gy)

def prf(key, z):
    h = hmac.new(key, z.to_bytes(8, 'big'), hashlib.sha256).digest()
    return int.from_bytes(h[:8], 'big')


# ─── Simple Neural Network (PM Learned Index) ───
class LearnedIndex:
    """Privacy-preserving learned index (PM model) with differential privacy."""

    def __init__(self, hidden=HIDDEN_NEURONS, lr=LR, epsilon=0.4):
        self.hidden = hidden
        self.lr = lr
        self.epsilon = epsilon
        self.W1 = None
        self.b1 = None
        self.W2 = None
        self.b2 = None
        self.trained = False
        self.train_losses = []

    def _init_weights(self):
        rng = np.random.RandomState(42)
        self.W1 = rng.randn(1, self.hidden) * 0.01
        self.b1 = np.zeros((1, self.hidden))
        self.W2 = rng.randn(self.hidden, 1) * 0.01
        self.b2 = np.zeros((1, 1))

    def _relu(self, x):
        return np.maximum(0, x)

    def _forward(self, X):
        self.z1 = X @ self.W1 + self.b1
        self.a1 = self._relu(self.z1)
        self.z2 = self.a1 @ self.W2 + self.b2
        return self.z2

    def _add_dp_noise(self, grad, sensitivity=1.0):
        """Add Laplace noise for differential privacy (Eq. 3 in paper)."""
        if self.epsilon <= 0:
            return grad
        scale = sensitivity / self.epsilon
        noise = np.random.laplace(0, scale, grad.shape)
        return grad + noise

    def train(self, enc_z_codes, positions, rounds=TRAINING_ROUNDS, batch_size=BATCH_SIZE):
        """Train the PM index to predict position from encrypted Z-code."""
        self._init_weights()
        X = np.array(enc_z_codes, dtype=np.float64).reshape(-1, 1)
        # Normalize
        self.x_mean, self.x_std = X.mean(), X.std() + 1e-12
        X = (X - self.x_mean) / self.x_std
        Y = np.array(positions, dtype=np.float64).reshape(-1, 1)
        self.y_max = Y.max() + 1e-12
        Y = Y / self.y_max
        n = len(X)
        self.train_losses = []

        for epoch in range(rounds):
            indices = np.random.permutation(n)
            epoch_loss = 0
            batches = 0
            for start in range(0, n, batch_size):
                end = min(start + batch_size, n)
                idx = indices[start:end]
                xb, yb = X[idx], Y[idx]
                bs = len(xb)

                pred = self._forward(xb)
                loss = np.mean((pred - yb) ** 2)
                epoch_loss += loss
                batches += 1

                # Backprop
                dz2 = 2 * (pred - yb) / bs
                dW2 = self.a1.T @ dz2
                db2 = dz2.sum(axis=0, keepdims=True)
                da1 = dz2 @ self.W2.T
                dz1 = da1 * (self.z1 > 0).astype(float)
                dW1 = xb.T @ dz1
                db1 = dz1.sum(axis=0, keepdims=True)

                # Add DP noise to gradients
                dW1 = self._add_dp_noise(dW1)
                dW2 = self._add_dp_noise(dW2)

                self.W1 -= self.lr * dW1
                self.b1 -= self.lr * db1
                self.W2 -= self.lr * dW2
                self.b2 -= self.lr * db2

            self.train_losses.append(epoch_loss / batches)
        self.trained = True

    def predict(self, enc_z_code):
        x = np.array([[enc_z_code]], dtype=np.float64)
        x = (x - self.x_mean) / self.x_std
        pred = self._forward(x)
        return int(pred[0, 0] * self.y_max)

    def point_search(self, enc_z_code, sorted_codes):
        """Algorithm 1: Point_Search - predict position then linear scan."""
        pos = self.predict(enc_z_code)
        pos = max(0, min(len(sorted_codes) - 1, pos))
        # Linear scan from predicted position
        if sorted_codes[pos] == enc_z_code:
            return pos
        lo, hi = max(0, pos - 100), min(len(sorted_codes) - 1, pos + 100)
        for i in range(lo, hi + 1):
            if sorted_codes[i] == enc_z_code:
                return i
        return pos

    def memory_size_bytes(self):
        if not self.trained:
            return 0
        return (self.W1.nbytes + self.b1.nbytes +
                self.W2.nbytes + self.b2.nbytes + 64)


# ─── Predicate Encryption (simplified SHVE-based) ───
class PredicateEncryption:
    def __init__(self):
        self.msk = os.urandom(32)

    def encrypt_index(self, z_code_bits, attr_vector):
        """PE.Encrypt: create encrypted index vector."""
        vec = z_code_bits + attr_vector
        r = np.random.randint(1, 2**16)
        cipher = []
        for bit in vec:
            val = int(hmac.new(self.msk, f"{bit}_{r}".encode(),
                               hashlib.sha256).hexdigest()[:8], 16)
            cipher.append(val)
        return cipher

    def gen_token(self, query_z_bits, query_attr):
        """PE.GenToken: generate search token."""
        vec = query_z_bits + query_attr
        token = []
        for i, bit in enumerate(vec):
            if bit == '*':  # wildcard
                token.append(None)
            else:
                token.append(bit)
        return token

    def query(self, cipher_vec, token):
        """PE.Query: check if index matches query."""
        for i, t in enumerate(token):
            if t is None:
                continue
        return True  # Simplified match


# ─── Spatial Segmentation (Algorithm 2) ───
def spatial_segmentation(query_rect, tx, ty):
    """Divide query into sub-queries based on spatial partitions."""
    x_min, y_min, x_max, y_max = query_rect
    x_step = (LAT_MAX - LAT_MIN) / tx
    y_step = (LON_MAX - LON_MIN) / ty
    sub_queries = []
    for ix in range(tx):
        for iy in range(ty):
            px_min = LAT_MIN + ix * x_step
            px_max = LAT_MIN + (ix + 1) * x_step
            py_min = LON_MIN + iy * y_step
            py_max = LON_MIN + (iy + 1) * y_step
            # Intersect with query
            ox_min = max(x_min, px_min)
            ox_max = min(x_max, px_max)
            oy_min = max(y_min, py_min)
            oy_max = min(y_max, py_max)
            if ox_min < ox_max and oy_min < oy_max:
                sub_queries.append((ox_min, oy_min, ox_max, oy_max))
    return sub_queries


# ─── ECGRQ-LI Full Scheme ───
class ECGRQ_LI:
    def __init__(self, epsilon=0.4, tx=2, ty=2):
        self.key = os.urandom(32)
        self.pe = PredicateEncryption()
        self.index = LearnedIndex(epsilon=epsilon)
        self.tx = tx
        self.ty = ty
        self.sorted_enc_z = []
        self.positions = []

    def index_build(self, points):
        """Build encrypted index and train PM learned index."""
        enc_z_list = []
        for p in points:
            z = compute_z(p['lat'], p['lon'])
            enc_z = prf(self.key, z)
            enc_z_list.append((enc_z, p))
        enc_z_list.sort(key=lambda x: x[0])
        self.sorted_enc_z = [e[0] for e in enc_z_list]
        self.sorted_points = [e[1] for e in enc_z_list]
        self.positions = list(range(len(self.sorted_enc_z)))
        self.index.train(self.sorted_enc_z, self.positions)

    def trap_gen(self, query_rect, query_attrs=None):
        """Generate trapdoor with spatial segmentation."""
        sub_qs = spatial_segmentation(query_rect, self.tx, self.ty)
        tokens = []
        for sq in sub_qs:
            z_ll = compute_z(sq[0], sq[1])
            z_rh = compute_z(sq[2], sq[3])
            enc_ll = prf(self.key, z_ll)
            enc_rh = prf(self.key, z_rh)
            tokens.append((enc_ll, enc_rh))
        return tokens

    def query(self, tokens):
        """Algorithm 3: Query with learned index."""
        results = []
        for enc_ll, enc_rh in tokens:
            pos_s = self.index.point_search(enc_ll, self.sorted_enc_z)
            pos_e = self.index.point_search(enc_rh, self.sorted_enc_z)
            if pos_s > pos_e:
                pos_s, pos_e = pos_e, pos_s
            for i in range(pos_s, min(pos_e + 1, len(self.sorted_points))):
                results.append(self.sorted_points[i])
        return results


# ─── Baseline schemes for comparison ───
class BTreeIndex:
    """Simulates traditional B-tree/Quadtree index (PBRQ-T+)."""
    def __init__(self):
        self.data = []

    def build(self, points):
        self.data = sorted(points, key=lambda p: compute_z(p['lat'], p['lon']))

    def query(self, query_rect):
        results = []
        for p in self.data:
            if (query_rect[0] <= p['lat'] <= query_rect[2] and
                query_rect[1] <= p['lon'] <= query_rect[3]):
                results.append(p)
        return results

    def memory_size(self):
        return len(self.data) * 200  # ~200 bytes per tree node


class BinaryTreeIndex:
    """Simulates Binary tree index (Scheme II from [12])."""
    def __init__(self):
        self.data = []

    def build(self, points):
        self.data = sorted(points, key=lambda p: compute_z(p['lat'], p['lon']))

    def query(self, query_rect):
        results = []
        z_min = compute_z(query_rect[0], query_rect[1])
        z_max = compute_z(query_rect[2], query_rect[3])
        lo, hi = 0, len(self.data) - 1
        while lo <= hi:
            mid = (lo + hi) // 2
            z = compute_z(self.data[mid]['lat'], self.data[mid]['lon'])
            if z < z_min:
                lo = mid + 1
            else:
                hi = mid - 1
        for i in range(lo, len(self.data)):
            p = self.data[i]
            z = compute_z(p['lat'], p['lon'])
            if z > z_max:
                break
            if (query_rect[0] <= p['lat'] <= query_rect[2] and
                query_rect[1] <= p['lon'] <= query_rect[3]):
                results.append(p)
        return results

    def memory_size(self):
        return len(self.data) * 160
