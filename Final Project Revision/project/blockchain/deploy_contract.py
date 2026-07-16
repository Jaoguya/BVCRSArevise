"""
Deploy BVCRSALedger Smart Contract to Ganache

One-click script to:
  1. Connect to Ganache (local Ethereum)
  2. Compile the Solidity smart contract
  3. Deploy it to the blockchain
  4. Save contract address + ABI for the main application

Usage:
  1. Start Ganache:  npx ganache --deterministic --port 8545
  2. Run this:       python deploy_contract.py

Prerequisites:
  pip install web3 py-solc-x
"""

import sys
import time


def main():
    print()
    print("═" * 60)
    print("  BVCRSALedger — Smart Contract Deployment")
    print("═" * 60)
    print()

    # ── Step 1: Connect to Ganache ───────────────────────────────
    print("  Step 1: Connecting to Ganache...")
    try:
        from ethereum_connector import EthereumConnector
        eth = EthereumConnector()
    except ConnectionError as e:
        print(str(e))
        print("  💡 Start Ganache first:")
        print("     npx ganache --deterministic --port 8545")
        sys.exit(1)
    except ImportError as e:
        print(str(e))
        sys.exit(1)

    print()

    # ── Step 2: Deploy contract ──────────────────────────────────
    print("  Step 2: Compiling & deploying smart contract...")
    try:
        contract = eth.deploy_or_load_contract()
    except Exception as e:
        print(f"\n  ❌ Deployment failed: {e}")
        import traceback; traceback.print_exc()
        sys.exit(1)

    print()

    # ── Step 3: Verify deployment ────────────────────────────────
    print("  Step 3: Verifying deployment...")
    info = eth.get_chain_info()
    print(f"     Contract Address: {info.get('contract_address', 'N/A')}")
    print(f"     On-chain Blocks:  {info.get('on_chain_blocks', 'N/A')}")
    print(f"     Ganache Block#:   {info.get('eth_block_number', 'N/A')}")
    print(f"     Account Balance:  {info.get('balance_eth', 'N/A')} ETH")
    print()

    # ── Step 4: Test anchoring ───────────────────────────────────
    print("  Step 4: Testing block anchoring...")
    import hashlib
    test_data = f"TEST|deployment_verification|{time.time()}"
    test_hash = hashlib.sha256(test_data.encode()).hexdigest()
    test_block_hash = hashlib.sha256(f"block|{test_hash}".encode()).hexdigest()

    result = eth.anchor_block(test_hash, test_block_hash)
    print(f"     ✅ Test block anchored!")
    print(f"     Tx Hash:    {result['tx_hash'][:40]}...")
    print(f"     Gas Used:   {result['gas_used']}")
    print(f"     Eth Block#: {result['block_number']}")
    print(f"     On-chain#:  {result['on_chain_index']}")
    print()

    # ── Step 5: Verify on-chain ──────────────────────────────────
    print("  Step 5: Verifying on-chain record...")
    verified = eth.verify_block_on_chain(result['on_chain_index'], test_block_hash)
    print(f"     On-chain verification: {'✅ PASSED' if verified else '❌ FAILED'}")
    print()

    # ── Done ─────────────────────────────────────────────────────
    print("═" * 60)
    print("  ✅ Deployment complete! Contract is live on Ganache.")
    print()
    print("  Next steps:")
    print("    1. Start the server:    python main.py")
    print("    2. Ingest data:         python iiot_simulator.py --records 5")
    print("    3. Check blockchain:    curl http://localhost:5000/api/blockchain")
    print("═" * 60)
    print()


if __name__ == "__main__":
    main()
