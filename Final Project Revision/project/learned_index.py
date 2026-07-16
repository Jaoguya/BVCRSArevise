"""
Piecewise Linear Learned Index + Laplace Noise Privacy
=======================================================
Approximates the RMI (Recursive Model Index) from:
  "Efficient Conjunctive Geometric Range Query Over Encrypted
   Spatial Data With Learned Index" (Li et al., IEEE TC 2025)

Two-level architecture:
  Level 0: single linear model routes to segment
  Level 1: per-segment linear model predicts position

Query complexity: O(log S + |candidates|) where S = num segments
  - Binary search over segments: O(log S)
  - Linear scan over candidate window: O(|candidates|)
  - Total << O(N) for selective queries

Privacy: Laplace noise mechanism on query boundaries
  - Sensitivity = 2.0 (domain width change from shifting boundary by 1)
  - Epsilon = 0.5 (differential privacy budget)
"""

import numpy as np
import bisect


class PiecewiseLinearIndex:
    """Two-level Recursive Model Index (RMI) with piecewise linear segments.

    Train: O(N log N) one-time (sort + fit)
    Predict: O(log S) binary search over S segments + epsilon window
    """

    def __init__(self, num_segments=10):
        self.num_segments = num_segments
        self.segments = []        # [(slope, intercept, min_val, max_val)]
        self.sorted_vals = None   # sorted array of indexed values
        self.val_to_indices = {}  # value → list of original record indices
        self.trained = False

    def train(self, values_with_ids):
        """Train the learned index on (value, record_id) pairs.

        Args:
            values_with_ids: list of (value, record_id) tuples
        """
        if not values_with_ids:
            self.trained = False
            return

        # Sort by value
        sorted_pairs = sorted(values_with_ids, key=lambda x: x[0])
        self.sorted_vals = np.array([v for v, _ in sorted_pairs])
        self.sorted_ids = [rid for _, rid in sorted_pairs]
        n = len(self.sorted_vals)

        # Build value → position mapping
        self.val_to_indices = {}
        for pos, (v, rid) in enumerate(sorted_pairs):
            if v not in self.val_to_indices:
                self.val_to_indices[v] = []
            self.val_to_indices[v].append(pos)

        # Determine segment boundaries (equal-width over value domain)
        v_min = float(self.sorted_vals[0])
        v_max = float(self.sorted_vals[-1])
        if v_max == v_min:
            v_max = v_min + 1.0

        actual_segments = min(self.num_segments, n)
        seg_width = (v_max - v_min) / actual_segments

        self.segments = []
        self.seg_boundaries = []  # sorted list of segment start values

        for s in range(actual_segments):
            seg_lo = v_min + s * seg_width
            seg_hi = v_min + (s + 1) * seg_width if s < actual_segments - 1 else v_max + 1

            self.seg_boundaries.append(seg_lo)

            # Find positions in this segment
            lo_pos = bisect.bisect_left(self.sorted_vals, seg_lo)
            hi_pos = bisect.bisect_right(self.sorted_vals, seg_hi)

            if hi_pos - lo_pos < 2:
                # Degenerate segment: constant model
                slope = 0.0
                intercept = float(lo_pos)
            else:
                # Fit linear regression: position = slope * value + intercept
                seg_vals = self.sorted_vals[lo_pos:hi_pos].astype(float)
                seg_positions = np.arange(lo_pos, hi_pos, dtype=float)
                # Least squares: y = mx + b
                x_mean = seg_vals.mean()
                y_mean = seg_positions.mean()
                denom = ((seg_vals - x_mean) ** 2).sum()
                if denom < 1e-12:
                    slope = 0.0
                    intercept = y_mean
                else:
                    slope = ((seg_vals - x_mean) * (seg_positions - y_mean)).sum() / denom
                    intercept = y_mean - slope * x_mean

            self.segments.append({
                "slope": slope,
                "intercept": intercept,
                "lo_pos": lo_pos,
                "hi_pos": hi_pos,
                "v_lo": seg_lo,
                "v_hi": seg_hi,
            })

        self.seg_boundaries = np.array(self.seg_boundaries)
        self.trained = True

    def _find_segment(self, value):
        """Binary search for the segment containing value. O(log S)."""
        idx = bisect.bisect_right(self.seg_boundaries, value) - 1
        return max(0, min(idx, len(self.segments) - 1))

    def _predict_position(self, value):
        """Predict the sorted-array position for a given value. O(log S)."""
        seg_idx = self._find_segment(value)
        seg = self.segments[seg_idx]
        predicted = seg["slope"] * value + seg["intercept"]
        # Clamp to valid range
        return int(max(0, min(predicted, len(self.sorted_vals) - 1)))

    def predict_range(self, a, b, epsilon=5):
        """Predict the candidate window [lo_idx, hi_idx] in sorted array.

        Args:
            a: lower bound of range query
            b: upper bound of range query
            epsilon: error margin (expands window by ±epsilon positions)

        Returns:
            (lo_idx, hi_idx): indices into sorted_vals for candidate scan
            This is sublinear when (hi_idx - lo_idx) << N
        """
        if not self.trained or len(self.sorted_vals) == 0:
            return (0, 0)

        n = len(self.sorted_vals)

        # Predict positions for boundaries
        pred_lo = self._predict_position(a)
        pred_hi = self._predict_position(b)

        # Expand by epsilon to account for model error
        lo_idx = max(0, pred_lo - epsilon)
        hi_idx = min(n - 1, pred_hi + epsilon)

        # Refine using binary search on the candidate window
        # This corrects any model prediction error
        actual_lo = bisect.bisect_left(self.sorted_vals, a, lo_idx, min(hi_idx + 1, n))
        actual_hi = bisect.bisect_right(self.sorted_vals, b, max(actual_lo, lo_idx), min(hi_idx + epsilon + 1, n))

        return (actual_lo, actual_hi)

    def get_candidates(self, a, b, epsilon=5):
        """Return list of (position, record_id) for values in [a, b].

        This is the main query method — uses learned index for sublinear access.
        """
        lo, hi = self.predict_range(a, b, epsilon)
        results = []
        for pos in range(lo, hi):
            if pos < len(self.sorted_vals):
                v = self.sorted_vals[pos]
                if a <= v <= b:
                    results.append((pos, self.sorted_ids[pos]))
        return results


class NoiseDisturbedQuery:
    """Laplace noise mechanism for differential privacy on query boundaries.

    From ECGRQ paper: query boundaries are perturbed with calibrated
    Laplace noise before being sent to the cloud, preventing the server
    from learning exact query ranges.

    Privacy guarantee: (epsilon)-differential privacy per query.
    """

    def __init__(self, sensitivity=2.0, epsilon=0.5, domain_min=0, domain_max=100):
        """
        Args:
            sensitivity: L1 sensitivity of the range boundary function
            epsilon: privacy budget (smaller = more private, more noise)
            domain_min: minimum valid value in domain
            domain_max: maximum valid value in domain
        """
        self.sensitivity = sensitivity
        self.epsilon = epsilon
        self.scale = sensitivity / epsilon  # Laplace scale parameter b
        self.domain_min = domain_min
        self.domain_max = domain_max

    def disturb(self, a, b):
        """Add Laplace noise to query boundaries [a, b].

        Returns:
            (a_noisy, b_noisy): perturbed boundaries, clamped to domain
        """
        noise_a = np.random.laplace(0, self.scale)
        noise_b = np.random.laplace(0, self.scale)

        a_noisy = np.clip(a + noise_a, self.domain_min, self.domain_max)
        b_noisy = np.clip(b + noise_b, self.domain_min, self.domain_max)

        # Ensure a_noisy <= b_noisy
        if a_noisy > b_noisy:
            a_noisy, b_noisy = b_noisy, a_noisy

        return (float(a_noisy), float(b_noisy))
