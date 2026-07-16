import struct
import random
import os
from eprq_exact.utils import get_canonical_prefixes, split_binary, PRF_F, H, Sym_Enc

def ashve_keygen(msk: bytes, v_array: list, t: int):
    """
    ASHVE.KeyGen execution on a query binary array with '*' wildcards.
    """
    L = len(v_array)
    
    S1 = []
    for idx, v in enumerate(v_array):
        if v != '*':
            S1.append(idx)
            
    S2 = []
    # Randomly select a subset of indices from 1 to t
    for k in range(1, t + 1):
        if random.choice([True, False]):
            S2.append(k)
            
    # Ensure total size |S1| + |S2| is even
    if (len(S1) + len(S2)) % 2 != 0:
        if len(S2) > 0:
            S2.pop()
        else:
            S2.append(1)
            
    # Generate random K (32 bytes)
    K = os.urandom(32)
    
    xor_acc = bytearray(32)
    
    # Process S1
    for idx in S1:
        bit = v_array[idx]
        payload = struct.pack('>BI', bit, idx)
        prf_out = PRF_F(msk, payload)
        for i in range(32):
            xor_acc[i] ^= prf_out[i]
            
    # Process S2
    for k in S2:
        bit = H(struct.pack('>I', k))[0] % 2
        idx = L + k - 1
        payload = struct.pack('>BI', bit, idx)
        prf_out = PRF_F(msk, payload)
        for i in range(32):
            xor_acc[i] ^= prf_out[i]
            
    # XOR K
    d0 = bytes(a ^ b for a, b in zip(xor_acc, K))
    
    # Encrypt zero message
    d1 = Sym_Enc(K, b'\x00' * 32)
    
    # S contains all the indices to be matched
    S = S1[:]
    for k in S2:
        S.append(L + k - 1)
        
    return {
        'd0': d0,
        'd1': d1,
        'S': S
    }

def convert_sub_range_to_btq(sub_range: str) -> list:
    """
    Converts an s-bit prefix string (e.g. '01*') to a (2^{s+1}-1) array
    where exactly the path up to the prefix is 1, and everything else is '*'.
    """
    s = len(sub_range)
    size = (1 << (s + 1)) - 1
    # Initialize with wildcards
    btq = ['*'] * size
    
    # Root is always 1
    curr_idx = 0
    btq[curr_idx] = 1
    
    for lvl in range(s):
        bit_char = sub_range[lvl]
        if bit_char == '*':
            break
            
        bit = int(bit_char)
        if bit == 0:
            curr_idx = 2 * curr_idx + 1
        else:
            curr_idx = 2 * curr_idx + 2
            
        btq[curr_idx] = 1
        
    return btq

def token_gen(range_a: int, range_b: int, mks: bytes, m: int, s: int, t: int):
    """
    EPRQ+ TokenGen logic.
    range_a, range_b: Integer bounds
    """
    # 1. Decompose range into canonical prefixes
    prefixes = get_canonical_prefixes(range_a, range_b, m)
    
    tokens = []
    
    # 2. Split + Conversion for each prefix
    for prefix in prefixes:
        # Split into x s-bit components
        sub_ranges = split_binary(prefix, s)
        
        btq_new = []
        for sr in sub_ranges:
            btq = convert_sub_range_to_btq(sr)
            btq_new.extend(btq)
            
        # 3. Encrypt the combined array to get the token
        tk = ashve_keygen(mks, btq_new, t)
        tokens.append(tk)
        
    return tokens
