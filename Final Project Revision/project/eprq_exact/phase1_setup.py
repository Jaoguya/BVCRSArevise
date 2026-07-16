import os

def setup(m: int, s: int, t: int):
    """
    Setup Phase of EPRQ+.
    Generates master secret key and returns domain parameters.
    m: Total bit length of the domain.
    s: Split size (length of each sub-binary).
    t: Number of additional values.
    """
    assert m % s == 0, "m must be divisible by s"
    
    # Generate master secret key (lambda = 256 bits = 32 bytes)
    msk = os.urandom(32)
    
    return msk, m, s, t
