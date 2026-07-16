from eprq_exact.utils import Sym_Dec

def ashve_query(ct_array: list, tk: dict) -> bool:
    """
    Evaluates whether the ASHVE ciphertext matches the token.
    """
    d0 = tk['d0']
    d1 = tk['d1']
    S = tk['S']
    
    # 1. Compute K' = (XOR_{j \in S} c_{j}) \oplus d0
    k_prime_acc = bytearray(32)
    for idx in S:
        c_val = ct_array[idx]
        for i in range(32):
            k_prime_acc[i] ^= c_val[i]
            
    for i in range(32):
        k_prime_acc[i] ^= d0[i]
        
    K_prime = bytes(k_prime_acc)
    
    # 2. Decrypt message
    msg = Sym_Dec(K_prime, d1)
    
    # 3. Check if all zeros
    if msg == b'\x00' * 32:
        return True
    return False

def query(root_node, tokens: list):
    """
    Recursively search the EPRQ+ encrypted index tree using the tokens.
    """
    matched_ids = []
    
    if root_node is None:
        return matched_ids
        
    # Test if ANY token matches the current node
    node_matches = False
    for tk in tokens:
        if ashve_query(root_node.ct, tk):
            node_matches = True
            break
            
    if node_matches:
        if root_node.is_leaf:
            matched_ids.append(root_node.id_val)
        else:
            if root_node.left:
                matched_ids.extend(query(root_node.left, tokens))
            if root_node.right:
                matched_ids.extend(query(root_node.right, tokens))
                
    return matched_ids
