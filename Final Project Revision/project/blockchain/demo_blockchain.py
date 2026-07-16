"""
Demo: Insert sensor data and query with REAL Ethereum blockchain
"""
import requests
import json
import time
from TA import TrustedAuthority
from sensor import sensor_encrypt

ta = TrustedAuthority()
secrets = ta.key_gen(["Analyst", "Temp", "Humidity"])
aes_key = ta.get_sensor_key("RPI_01")
hmac_key = ta.get_sensor_hmac_key("RPI_01")

print("=" * 60)
print("  STEP 1: Inserting sensor data (Real Ethereum anchoring)")
print("=" * 60)

records = [
    ("Machine_01", "Temp", "2026-06-01 00:00:00", 45),
    ("Machine_01", "Temp", "2026-06-01 00:00:00", 52),
    ("Machine_01", "Humidity", "2026-06-01 00:00:00", 70),
]

for i, (m, k, t, v) in enumerate(records):
    seq = int(time.time() * 1000) + i
    payload = sensor_encrypt("RPI_01", m, k, t, v, aes_key, hmac_key, secrets["ec_pubkey"], seq)
    r = requests.post("http://localhost:5000/ingest", json=payload)
    resp = r.json()
    status = resp.get("status", "error")
    ms = resp.get("gen_index_ms", 0)
    print(f"\n  Record {i+1}: {m} | {k} = {v}")
    print(f"    Status:     {status}")
    print(f"    Index time: {ms:.0f} ms")
    if "ethereum" in resp:
        eth = resp["ethereum"]
        print(f"    Ethereum:   {eth['tx_count']} transactions anchored!")
        for tx in eth.get("tx_hashes", []):
            print(f"      tx_hash: {tx[:50]}...")

# ── Check blockchain status ──
print("\n" + "=" * 60)
print("  STEP 2: Blockchain Status (Real Ethereum)")
print("=" * 60)

r = requests.get("http://localhost:5000/api/blockchain")
bc = r.json()
print(f"\n  Blockchain Type:  {bc['blockchain_type']}")
print(f"  Local Chain:      {bc['local_chain']['length']} blocks, valid={bc['local_chain']['is_valid']}")

if "ethereum" in bc:
    eth = bc["ethereum"]
    print(f"  Contract:         {eth.get('contract_address', 'N/A')}")
    print(f"  On-chain Blocks:  {eth.get('on_chain_blocks', 'N/A')}")
    print(f"  Ganache Connected: {eth.get('ganache_connected', False)}")
    print(f"  Account Balance:  {eth.get('balance_eth', 'N/A'):.4f} ETH")
    print(f"  Eth Block Number: {eth.get('eth_block_number', 'N/A')}")

if "recent_transactions" in bc:
    print(f"\n  Recent Ethereum Transactions:")
    for tx in bc["recent_transactions"]:
        print(f"    Block #{tx['block']}: tx={tx['tx_hash'][:40]}...")

print(f"  Total Eth Txs:    {bc.get('total_eth_transactions', 0)}")

# ── Query ──
print("\n" + "=" * 60)
print("  STEP 3: Encrypted Range Query (Temp 20-60 on Machine_01)")
print("=" * 60)

from user_client import UserClient
uc = UserClient(secrets)
trapdoor = uc.gen_trapdoor("Machine_01", "Temp", "2026-06-01 00", [20, 60])

r = requests.post("http://localhost:5000/query", json=trapdoor)
qr = r.json()
print(f"\n  Matched Nodes:    {qr.get('matched_nodes', 0)}")
print(f"  Query Time:       {qr.get('agg_only_ms', 0):.1f} ms")
print(f"  CT_sum (encrypted): {qr.get('CT_sum', 'N/A')[:60]}...")
print(f"  CT_cnt (encrypted): {qr.get('CT_cnt', 'N/A')[:60]}...")
print(f"  Pi_agg (commitment): {qr.get('Pi_agg', 'N/A')[:40]}...")

# Decrypt the result
if qr.get("CT_sum") and qr["CT_sum"] != "0":
    from ec_elgamal import ECEncryptedNumber
    ct_sum = ECEncryptedNumber.from_string(secrets["ec_pubkey"], qr["CT_sum"])
    ct_cnt = ECEncryptedNumber.from_string(secrets["ec_pubkey"], qr["CT_cnt"])
    total = secrets["ec_privkey"].decrypt(ct_sum)
    count = secrets["ec_privkey"].decrypt(ct_cnt)
    avg = total / count if count > 0 else 0
    print(f"\n  --- DECRYPTED RESULT ---")
    print(f"  Sum:     {total}")
    print(f"  Count:   {count}")
    print(f"  Average: {avg:.1f}")
    print(f"\n  Expected: sum=97 (45+52), count=2, avg=48.5")

# ── Integrity check ──
print("\n" + "=" * 60)
print("  STEP 4: Real-Time Integrity Verification")
print("=" * 60)

r = requests.get("http://localhost:5000/api/blockchain")
bc = r.json()
v = bc["verification"]
print(f"\n  Chain Valid:           {v['is_valid']}")
print(f"  Chain Length:          {v['chain_length']} blocks")
print(f"  Latest Hash:          {v['latest_hash'][:40]}...")
print(f"  Blockchain Type:      {v['blockchain_type']}")
if "ethereum" in v:
    print(f"  On-chain Blocks:      {v['ethereum']['on_chain_blocks']}")
    print(f"  Ganache Connected:    {v['ethereum']['ganache_connected']}")
    print(f"  Cross-chain Match:    Local({v['chain_length']}) vs On-chain({v['ethereum']['on_chain_blocks']})")

print("\n  INTEGRITY = Every local block is verified against")
print("  the Ethereum smart contract in REAL TIME.")
print("  If anyone tampers with a block, the on-chain hash won't match!")

print("\n" + "=" * 60)
print("  DEMO COMPLETE!")
print("=" * 60)
