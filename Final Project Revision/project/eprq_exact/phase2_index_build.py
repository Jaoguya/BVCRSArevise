import struct
from eprq_exact.utils import to_binary, split_binary, construct_segment_tree_array, PRF_F, H, Sym_Enc
import math

def ASHVE_Enc(msk: bytes, value_array: list, t: int, assoc_id_hashes: list):
    """
    Encrypts a binary array using ASHVE encoding logic.
    assoc_id_hashes is a list of byte strings.
    For leaf node: [F(msk, id_x)]
    For non-leaf node: [F(msk, id_l), F(msk, id_r)]
    """
    # 1. Extend the binary array with t additional values using H
    extended = value_array[:]
    for k in range(1, t + 1):
        bit = H(struct.pack('>I', k))[0] % 2
        extended.append(bit)
        
    c = []
    # XOR all associative ID hashes to cancel out in queries
    id_xor_term = bytearray(32) # PRF output is 32 bytes
    for id_hash in assoc_id_hashes:
        for i in range(32):
            id_xor_term[i] ^= id_hash[i]
    id_xor_term = bytes(id_xor_term)

    # 2. Encrypt each bit
    for l, bit in enumerate(extended):
        # x'[l] || l
        payload = struct.pack('>BI', bit, l)
        prf_out = PRF_F(msk, payload)
        
        c_l = bytes(a ^ b for a, b in zip(prf_out, id_xor_term))
        c.append(c_l)
        
    return c

def or_binary_arrays(arr1, arr2):
    return [a | b for a, b in zip(arr1, arr2)]

class TreeNode:
    def __init__(self, is_leaf, bt_new, id_val=None, id_l=None, id_r=None, left=None, right=None, data_val=None):
        self.is_leaf = is_leaf
        self.bt_new = bt_new # The combined bit array
        self.id_val = id_val # id_x if leaf
        self.id_l = id_l # id_l if non-leaf
        self.id_r = id_r # id_r if non-leaf
        self.left = left
        self.right = right
        self.data_val = data_val # Original scalar value
        self.ct = None # Ciphertext populated later

def build_tree_recursive(records, l, r):
    if l == r:
        rec = records[l]
        return TreeNode(is_leaf=True, bt_new=rec['bt_new'], id_val=rec['id'], data_val=rec['value'])
    mid = (l + r) // 2
    left_node = build_tree_recursive(records, l, mid)
    right_node = build_tree_recursive(records, mid + 1, r)
    
    # Non-leaf is OR of bit arrays to represent union of values for proper pruning
    bt_or = or_binary_arrays(left_node.bt_new, right_node.bt_new)
    
    # id_l is the id of the first data in left child
    id_l = records[l]['id']
    # id_r is the id of the last data in right child
    id_r = records[r]['id']
    
    return TreeNode(is_leaf=False, bt_new=bt_or, id_l=id_l, id_r=id_r, left=left_node, right=right_node)

def encrypt_tree(node, msk, t):
    if node.is_leaf:
        assoc = [PRF_F(msk, struct.pack('>I', node.id_val))]
    else:
        assoc = [PRF_F(msk, struct.pack('>I', node.id_l)), PRF_F(msk, struct.pack('>I', node.id_r))]
        
    node.ct = ASHVE_Enc(msk, node.bt_new, t, assoc)
    
    if node.left:
        encrypt_tree(node.left, msk, t)
    if node.right:
        encrypt_tree(node.right, msk, t)

def index_build(records, msk: bytes, m: int, s: int, t: int):
    """
    EPRQ+ IndexBuild logic.
    records: list of dicts with 'id' and 'value'.
    """
    processed_records = []
    
    # 1. Convert and Split for each record
    for rec in records:
        val = rec['value']
        bin_str = to_binary(val, m)
        sub_bins = split_binary(bin_str, s)
        
        bt_new = []
        for sub in sub_bins:
            seg_tree = construct_segment_tree_array(sub)
            bt_new.extend(seg_tree)
            
        processed_records.append({
            'id': rec['id'],
            'value': val,
            'bt_new': bt_new
        })
        
    # 2. Construct binary tree
    if not processed_records:
        return None
    root_node = build_tree_recursive(processed_records, 0, len(processed_records) - 1)
    
    # 3. Encryption
    encrypt_tree(root_node, msk, t)
    
    return root_node
