#!/usr/bin/env python3
"""
═══════════════════════════════════════════════════════════════════════
  GGM-CPRF — GGM Tree-based Constrained Pseudorandom Function
═══════════════════════════════════════════════════════════════════════

Paper Reference (Trinity, IEEE TIFS 2025):
  The GGM construction (Goldreich-Goldwasser-Micali, 1986) provides
  a tree-based PRF used in Trinity-II for FORWARD SECURITY.

  Forward Security Property:
    After an update with state sₜ, the server cannot link
    new entries to previous search queries. This is achieved by
    deriving keys hierarchically — a key at level L can derive
    all keys below it but NOT keys at level L-1 or above.

GGM Tree Construction:
  - Root key: K_root (master PRF key)
  - Internal nodes: key_{level+1} = PRF(key_level, bit)
    where bit = 0 → left child, bit = 1 → right child
  - Leaf keys: Used to derive state-specific encryption keys

  Structure (depth=4 example):
              K_root
             /      \\
        K_0           K_1
       /   \\        /   \\
     K_00  K_01   K_10  K_11
     / \\   / \\   / \\   / \\
    ...  ...  ...  ...

CPRF (Constrained PRF):
  A constrained key K_S reveals ONLY the keys for a subset S
  of the domain, without revealing the master key.

  Constrain(K_root, prefix) → K_prefix
    Returns the key at the node identified by 'prefix'.
    This key can derive all leaf keys under that prefix
    but cannot derive sibling or ancestor keys.

Algorithms:
  1. PRF.KeyGen() → K_root
  2. PRF.Derive(K_root, x, depth) → key_x
  3. PRF.Constrain(K_root, prefix) → K_constrained
  4. PRF.Eval(K_constrained, x) → output
  5. PRF.UpdateState(K_root, counter) → (state_key, new_counter)
"""
import hashlib
import hmac
import os
import struct


class GGM_CPRF:
    """
    GGM Tree-based Constrained PRF for forward security.

    Used in Trinity-II to ensure that update operations
    do not leak information about previous queries.
    """

    # ───────────────────────────────────────────────────────────
    #  PRF.KeyGen — Generate Root Key
    # ───────────────────────────────────────────────────────────
    def keygen(self, key_size=16):
        """
        PRF.KeyGen() → K_root

        Generate the GGM tree root key.

        Args:
            key_size: Key size in bytes (default 16 = 128 bits).

        Returns:
            bytes: Root key K_root.
        """
        return os.urandom(key_size)

    # ───────────────────────────────────────────────────────────
    #  PRF.Derive — Derive Key at Path
    # ───────────────────────────────────────────────────────────
    def derive(self, root_key, value, depth):
        """
        PRF.Derive(K_root, x, depth) → key_x

        Derive the key at the node reached by following
        the bit-path of 'value' for 'depth' levels.

        Algorithm:
          key₀ = K_root
          For level = 0 to depth-1:
            bit = (value >> level) & 1
            key_{level+1} = HMAC(key_level, bit)[:key_size]

        The bit decomposition determines the path:
          bit=0 → go left, bit=1 → go right

        Args:
            root_key: Root key or any ancestor key.
            value: Integer whose bits define the path.
            depth: Number of levels to descend.

        Returns:
            bytes: Derived key at the specified depth.
        """
        key = root_key
        key_size = len(root_key)

        for level in range(depth):
            bit = (value >> level) & 1
            key = hmac.new(
                key,
                struct.pack('<BI', bit, level),
                hashlib.sha256
            ).digest()[:key_size]

        return key

    # ───────────────────────────────────────────────────────────
    #  PRF.Constrain — Generate Constrained Key
    # ───────────────────────────────────────────────────────────
    def constrain(self, root_key, prefix_value, prefix_depth):
        """
        PRF.Constrain(K_root, prefix, depth) → K_constrained

        Generate a constrained key that can evaluate the PRF
        ONLY for inputs sharing the given prefix.

        This is the key mechanism for forward security:
        - The constrained key K_prefix can derive all leaf keys
          under the subtree rooted at 'prefix'
        - But it CANNOT derive keys outside that subtree
        - Specifically, it cannot go UP the tree (no parent key)

        Args:
            root_key: Master root key.
            prefix_value: Bit prefix identifying the subtree.
            prefix_depth: Length of the prefix (tree depth).

        Returns:
            dict: Constrained key containing the subtree key
                  and metadata needed for evaluation.
        """
        # Derive the key at the prefix node
        subtree_key = self.derive(root_key, prefix_value, prefix_depth)

        return {
            'key': subtree_key,
            'prefix': prefix_value,
            'depth': prefix_depth,
        }

    # ───────────────────────────────────────────────────────────
    #  PRF.Eval — Evaluate PRF with Constrained Key
    # ───────────────────────────────────────────────────────────
    def eval_constrained(self, constrained_key, value, total_depth):
        """
        PRF.Eval(K_constrained, x) → output

        Evaluate the PRF at 'value' using a constrained key.
        Only succeeds if 'value' shares the constrained prefix.

        Args:
            constrained_key: Constrained key from constrain().
            value: Input value to evaluate.
            total_depth: Total tree depth for leaf-level evaluation.

        Returns:
            bytes: PRF output, or None if value is outside
                   the constrained domain.
        """
        prefix = constrained_key['prefix']
        prefix_depth = constrained_key['depth']
        subtree_key = constrained_key['key']

        # Verify value shares the prefix
        prefix_mask = (1 << prefix_depth) - 1
        if (value & prefix_mask) != (prefix & prefix_mask):
            return None  # Outside constrained domain

        # Continue derivation from prefix node to leaf
        remaining_depth = total_depth - prefix_depth
        return self.derive(subtree_key, value >> prefix_depth, remaining_depth)

    # ───────────────────────────────────────────────────────────
    #  PRF.UpdateState — Forward-Secure State Update
    # ───────────────────────────────────────────────────────────
    def update_state(self, root_key, counter):
        """
        PRF.UpdateState(K_root, c) → (state_key, c+1)

        Derive a state-specific key and increment the counter.
        This ensures each update uses a unique key derived from
        the counter position in the GGM tree.

        Forward Security:
          After state c+1, the key for state c is no longer
          derivable from the current state. An adversary observing
          updates at state c+1 cannot link them to searches
          performed before state c.

        Args:
            root_key: Master root key.
            counter: Current state counter.

        Returns:
            (state_key, new_counter): The derived key and incremented counter.
        """
        # Derive state-specific key at depth proportional to counter bits
        depth = max(1, counter.bit_length())
        state_key = self.derive(root_key, counter, depth)

        # Apply "salt" (additional randomization per Trinity-II)
        salt = os.urandom(8)
        salted_key = hmac.new(
            state_key,
            salt + struct.pack('<Q', counter),
            hashlib.sha256
        ).digest()[:len(root_key)]

        return salted_key, salt, counter + 1


# ═══════════════════════════════════════════════════════════════
#  Standalone test
# ═══════════════════════════════════════════════════════════════
if __name__ == '__main__':
    print("═══ GGM-CPRF Test ═══\n")

    prf = GGM_CPRF()
    root = prf.keygen()
    print(f"Root key: {root.hex()}")

    # Derive keys at different paths
    k0 = prf.derive(root, 0b0000, 4)
    k1 = prf.derive(root, 0b0001, 4)
    k2 = prf.derive(root, 0b0010, 4)
    print(f"\n  Path 0000: {k0.hex()}")
    print(f"  Path 0001: {k1.hex()}")
    print(f"  Path 0010: {k2.hex()}")

    # Deterministic check
    k0_again = prf.derive(root, 0b0000, 4)
    print(f"\n  Deterministic: {k0 == k0_again}")

    # Constrained key
    ck = prf.constrain(root, 0b00, 2)
    print(f"\n  Constrained to prefix 00, depth 2")
    print(f"  Subtree key: {ck['key'].hex()}")

    # Eval within constraint
    r1 = prf.eval_constrained(ck, 0b0000, 4)  # prefix 00 — OK
    r2 = prf.eval_constrained(ck, 0b0100, 4)  # prefix 01 — blocked
    print(f"  Eval 0000 (prefix 00): {r1.hex() if r1 else 'BLOCKED'}")
    print(f"  Eval 0100 (prefix 01): {r2.hex() if r2 else 'BLOCKED'}")

    # Forward-secure state updates
    print("\n  Forward-secure state updates:")
    counter = 0
    for i in range(5):
        state_key, salt, counter = prf.update_state(root, counter)
        print(f"    State {i}: key={state_key.hex()[:16]}..., counter={counter}")
