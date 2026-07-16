import hashlib
import hmac
import os
import struct

# ---------------------------------------------------------
# Cryptographic Primitives
# ---------------------------------------------------------

def H(data: bytes) -> bytes:
    """Secure hash function mapping to {0,1} used to derive the single bit, but we'll use it to return a uniform byte/bit."""
    return hashlib.sha256(data).digest()

def PRF_F(msk: bytes, data: bytes) -> bytes:
    """Pseudorandom Function F: {0,1}^lambda x {0,1}^* -> {0,1}^{lambda+log lambda}
       Implemented via HMAC-SHA256.
    """
    return hmac.new(msk, data, hashlib.sha256).digest()

def Sym_Enc(key: bytes, msg: bytes) -> bytes:
    """IND-CPA Symmetric Encryption (CTR mode-like using SHA256 as stream cipher)."""
    nonce = os.urandom(16)
    stream = hashlib.sha256(key + nonce).digest()
    
    # Extend stream if needed (for simplicity, assumed len(msg) <= 32)
    while len(stream) < len(msg):
        stream += hashlib.sha256(key + stream).digest()
        
    ct = bytes(a ^ b for a, b in zip(msg, stream[:len(msg)]))
    return nonce + ct

def Sym_Dec(key: bytes, ct: bytes) -> bytes:
    """Symmetric Decryption."""
    nonce = ct[:16]
    actual_ct = ct[16:]
    stream = hashlib.sha256(key + nonce).digest()
    
    while len(stream) < len(actual_ct):
        stream += hashlib.sha256(key + stream).digest()
        
    msg = bytes(a ^ b for a, b in zip(actual_ct, stream[:len(actual_ct)]))
    return msg

# ---------------------------------------------------------
# REncoder and Binary Splitting Utilities
# ---------------------------------------------------------

def to_binary(value: int, bits: int) -> str:
    """Convert integer to fixed-length binary string."""
    return format(value, f'0{bits}b')

def split_binary(binary_str: str, s: int) -> list:
    """Split an m-bit binary into x s-bit sub-binaries."""
    return [binary_str[i:i+s] for i in range(0, len(binary_str), s)]

def construct_segment_tree_array(sub_bin: str) -> list:
    """
    Constructs a (2^{s+1} - 1)-bit binary string (segment tree).
    The input is an s-bit binary string.
    Level 0 (root) has 1 node, Level 1 has 2, ..., Level s has 2^s.
    Returns a list of ints [0, 1] of size 2^{s+1}-1.
    """
    s = len(sub_bin)
    size = (1 << (s + 1)) - 1
    tree = [0] * size
    
    # The path represented by sub_bin has its nodes set to 1.
    curr_idx = 0
    tree[curr_idx] = 1 # Root is always 1 (traversed)
    
    for lvl in range(s):
        bit = int(sub_bin[lvl])
        # left child = 2*curr_idx + 1, right child = 2*curr_idx + 2
        if bit == 0:
            curr_idx = 2 * curr_idx + 1
        else:
            curr_idx = 2 * curr_idx + 2
        tree[curr_idx] = 1
        
    return tree

def get_canonical_prefixes(range_a: int, range_b: int, total_bits: int) -> list:
    """Decompose [range_a, range_b] into canonical prefix strings (e.g. 010*)."""
    # Simple algorithm: Check from left to right, form prefix.
    # Note: A real prefix decomposition is a standard segment tree decomposition algorithm.
    prefixes = []
    
    def decompose(l, r, current_l, current_r, prefix):
        if l <= current_l and current_r <= r:
            # Full coverage, append the prefix padded with '*'
            pads = total_bits - len(prefix)
            prefixes.append(prefix + "*" * pads)
            return
        
        # Disjoint
        if current_r < l or current_l > r:
            return
            
        # Overlap -> split
        mid = (current_l + current_r) // 2
        decompose(l, r, current_l, mid, prefix + "0")
        decompose(l, r, mid + 1, current_r, prefix + "1")
        
    decompose(range_a, range_b, 0, (1 << total_bits) - 1, "")
    return prefixes
