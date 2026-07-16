#!/usr/bin/env python3
"""
═══════════════════════════════════════════════════════════════════════
  Hilbert Curve — 3D Spatio-Temporal to 1D Mapping
═══════════════════════════════════════════════════════════════════════

Paper Reference (Trinity, IEEE TIFS 2025):
  The Hilbert curve is used to transform multi-dimensional
  spatio-temporal data (latitude, longitude, timestamp) into a
  one-dimensional index while preserving locality — nearby points
  in 3D space map to nearby values on the 1D curve.

  This enables efficient range queries: a spatio-temporal range
  query Q = [lat_l, lat_r] × [lon_l, lon_r] × [t_l, t_r]
  maps to a set of 1D intervals on the Hilbert curve.

Properties:
  - Locality-preserving: nearby 3D points → nearby 1D indices
  - Bijective: each 3D coordinate maps to exactly one 1D index
  - Order: p (precision bits per dimension)
  - Total cells: 2^(d*p) where d=3 (dimensions)
"""


class HilbertCurve:
    """
    Hilbert curve mapping for d-dimensional data.

    Uses the iterative algorithm based on Gray code and
    bit-transposition for arbitrary dimensions.
    """

    def __init__(self, order, dimensions=3):
        """
        Initialize Hilbert curve.

        Args:
            order: Number of bits per dimension (precision).
                   Total cells = 2^(order * dimensions)
            dimensions: Number of spatial dimensions (default 3: lat, lon, time)
        """
        self.order = order
        self.dimensions = dimensions
        self.max_coord = (1 << order) - 1  # Maximum coordinate value
        self.max_hilbert = (1 << (order * dimensions)) - 1  # Maximum Hilbert index

    def coordinates_to_hilbert(self, coords):
        """
        Map d-dimensional coordinates to 1D Hilbert index.

        Algorithm (bit-transposition method):
          1. Interleave coordinate bits into transposed form
          2. Apply Gray code inverse at each level
          3. Combine into single Hilbert index

        Args:
            coords: Tuple of d integer coordinates, each in [0, 2^order - 1]

        Returns:
            Integer Hilbert index in [0, 2^(order*dimensions) - 1]
        """
        n = self.dimensions
        p = self.order

        # Validate
        if len(coords) != n:
            raise ValueError(f"Expected {n} coordinates, got {len(coords)}")

        # Work with mutable copy
        x = list(coords)

        # Clamp to valid range
        for i in range(n):
            x[i] = max(0, min(x[i], self.max_coord))

        # --- Inverse undo of Hilbert curve ---
        # Process from most-significant to least-significant bit
        m = 1 << (p - 1)

        # Apply the inverse Gray code transform level by level
        q = m
        while q > 1:
            p_val = q - 1
            for i in range(n):
                if x[i] & q:
                    x[0] ^= p_val  # Invert
                else:
                    # Swap
                    t = (x[0] ^ x[i]) & p_val
                    x[0] ^= t
                    x[i] ^= t
            q >>= 1

        # Gray encode
        for i in range(1, n):
            x[i] ^= x[i - 1]

        t = 0
        q = m
        while q > 1:
            if x[n - 1] & q:
                t ^= q - 1
            q >>= 1
        for i in range(n):
            x[i] ^= t

        # Transpose bits to get Hilbert index
        hilbert = self._transpose_to_hilbert(x)
        return hilbert

    def hilbert_to_coordinates(self, hilbert_index):
        """
        Map 1D Hilbert index back to d-dimensional coordinates.

        Args:
            hilbert_index: Integer Hilbert index

        Returns:
            Tuple of d integer coordinates
        """
        n = self.dimensions
        p = self.order

        hilbert_index = max(0, min(hilbert_index, self.max_hilbert))

        # Extract transposed representation
        x = self._hilbert_to_transpose(hilbert_index)

        # Undo Gray code
        q = 2
        t = 0
        m = 1 << (p - 1)

        n_val = 1 << p
        q = n_val >> 1
        while q > 1:
            if x[n - 1] & q:
                t ^= q - 1
            q >>= 1
        for i in range(n):
            x[i] ^= t

        for i in range(n - 1, 0, -1):
            x[i] ^= x[i - 1]

        # Undo inversions/swaps
        m_val = 2
        while m_val < n_val:
            p_val = m_val - 1
            for i in range(n - 1, -1, -1):
                if x[i] & m_val:
                    x[0] ^= p_val
                else:
                    t = (x[0] ^ x[i]) & p_val
                    x[0] ^= t
                    x[i] ^= t
            m_val <<= 1

        return tuple(x)

    def _transpose_to_hilbert(self, x):
        """Convert transposed form to Hilbert index by interleaving bits."""
        n = self.dimensions
        p = self.order
        hilbert = 0
        for bit in range(p - 1, -1, -1):
            for dim in range(n - 1, -1, -1):
                hilbert = (hilbert << 1) | ((x[dim] >> bit) & 1)
        return hilbert

    def _hilbert_to_transpose(self, hilbert_index):
        """Convert Hilbert index to transposed form by de-interleaving bits."""
        n = self.dimensions
        p = self.order
        x = [0] * n
        bit_pos = 0
        for bit in range(p):
            for dim in range(n):
                if hilbert_index & (1 << bit_pos):
                    x[dim] |= (1 << bit)
                bit_pos += 1
        return x

    def range_to_intervals(self, range_min, range_max):
        """
        Convert a d-dimensional range query to a set of 1D Hilbert intervals.

        Given a query box defined by range_min and range_max coordinates,
        enumerate all cells and find contiguous Hilbert intervals.

        This is the key operation for Trinity's spatio-temporal range queries.

        Args:
            range_min: Tuple of d minimum coordinates
            range_max: Tuple of d maximum coordinates

        Returns:
            List of (start, end) Hilbert index intervals
        """
        n = self.dimensions

        # Enumerate all grid cells in the query box
        hilbert_values = []
        self._enumerate_cells(range_min, range_max, 0, [0] * n, hilbert_values)

        if not hilbert_values:
            return []

        # Sort and merge into contiguous intervals
        hilbert_values.sort()
        intervals = []
        start = hilbert_values[0]
        end = hilbert_values[0]

        for h in hilbert_values[1:]:
            if h == end + 1:
                end = h
            else:
                intervals.append((start, end))
                start = h
                end = h
        intervals.append((start, end))

        return intervals

    def _enumerate_cells(self, range_min, range_max, dim, current, result):
        """Recursively enumerate all cells in the query box."""
        if dim == self.dimensions:
            result.append(self.coordinates_to_hilbert(tuple(current)))
            return

        lo = max(0, range_min[dim])
        hi = min(self.max_coord, range_max[dim])

        for val in range(lo, hi + 1):
            current[dim] = val
            self._enumerate_cells(range_min, range_max, dim + 1, current, result)

    def normalize_coordinate(self, value, value_min, value_max):
        """
        Normalize a real-world coordinate to grid coordinate [0, max_coord].

        Used to map real lat/lon/time values to Hilbert grid points.
        """
        if value_max == value_min:
            return 0
        normalized = (value - value_min) / (value_max - value_min)
        return int(normalized * self.max_coord)


# ═══════════════════════════════════════════════════════════════
#  Standalone test
# ═══════════════════════════════════════════════════════════════
if __name__ == '__main__':
    print("═══ Hilbert Curve Test ═══\n")

    hc = HilbertCurve(order=4, dimensions=3)
    print(f"Order: {hc.order}, Dims: {hc.dimensions}")
    print(f"Max coord: {hc.max_coord}, Max Hilbert: {hc.max_hilbert}\n")

    # Test round-trip
    test_coords = [(0, 0, 0), (1, 2, 3), (5, 7, 10), (15, 15, 15)]
    for coords in test_coords:
        h = hc.coordinates_to_hilbert(coords)
        back = hc.hilbert_to_coordinates(h)
        print(f"  {coords} → H={h} → {back}  {'✓' if back == coords else '✗'}")

    # Test range query
    intervals = hc.range_to_intervals((2, 2, 2), (4, 4, 4))
    print(f"\n  Range (2,2,2)→(4,4,4): {len(intervals)} intervals")
