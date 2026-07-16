"""
Ethereum Connector — Web3.py interface to Ganache (Local Ethereum)

Connects the BVCRSA edge node to a real Ethereum blockchain via Ganache.
Handles contract compilation, deployment, and transaction management.

Real blockchain operations:
  - anchorBlock():     Sends an Ethereum transaction to record a block hash
  - anchorEpochRoot(): Sends an Ethereum transaction to anchor a Merkle epoch root
  - verifyOnChain():   Reads on-chain state to verify block integrity
  - getChainInfo():    Queries contract for full chain summary

Each operation produces a real Ethereum transaction with:
  - Transaction hash (tx_hash)
  - Gas used
  - Block number
  - Block confirmation
"""

import json
import os
import time
from pathlib import Path

# ── Web3 Import with Helpful Error ──────────────────────────────

try:
    from web3 import Web3
    from web3.middleware import ExtraDataToPOAMiddleware
except ImportError:
    raise ImportError(
        "\n\n  ❌  web3 not installed. Run:\n"
        "      pip install web3\n"
        "  Then start Ganache:\n"
        "      npx ganache --deterministic --port 8545\n"
    )

# ── Solidity Compiler Import ────────────────────────────────────

try:
    import solcx
    _HAS_SOLCX = True
except ImportError:
    _HAS_SOLCX = False


# ─────────────────────────────────────────────────────────────────
#  Configuration
# ─────────────────────────────────────────────────────────────────

GANACHE_URL = "http://127.0.0.1:8545"
CONTRACT_DIR = Path(__file__).parent / "contracts"
CONFIG_FILE = Path(__file__).parent / "contract_config.json"
SOL_FILE = CONTRACT_DIR / "BVCRSALedger.sol"


# ─────────────────────────────────────────────────────────────────
#  EthereumConnector
# ─────────────────────────────────────────────────────────────────

class EthereumConnector:
    """Web3.py connector to Ganache for real Ethereum blockchain anchoring.

    Usage:
        eth = EthereumConnector()          # Connects to Ganache
        eth.deploy_or_load_contract()      # Deploys contract (or loads existing)
        tx = eth.anchor_block(data_hash, block_hash)  # Real Ethereum tx
    """

    def __init__(self, ganache_url=GANACHE_URL):
        self.ganache_url = ganache_url
        self.w3 = Web3(Web3.HTTPProvider(ganache_url))

        # PoA middleware for Ganache
        try:
            self.w3.middleware_onion.inject(ExtraDataToPOAMiddleware, layer=0)
        except Exception:
            pass  # Not all versions need this

        if not self.w3.is_connected():
            raise ConnectionError(
                f"\n\n  ❌  Cannot connect to Ganache at {ganache_url}\n"
                f"  Make sure Ganache is running:\n"
                f"      npx ganache --deterministic --port 8545\n"
            )

        # Use the first Ganache account (pre-funded with 1000 ETH)
        self.account = self.w3.eth.accounts[0]
        self.contract = None
        self.contract_address = None

        balance_wei = self.w3.eth.get_balance(self.account)
        balance_eth = self.w3.from_wei(balance_wei, 'ether')
        print(f"  ⛓️  Connected to Ganache at {ganache_url}")
        print(f"  💰 Account: {self.account} (Balance: {balance_eth} ETH)")

    # ─── Contract Deployment ─────────────────────────────────────

    def deploy_or_load_contract(self):
        """Deploy a new contract or load an existing one from config."""

        # Try to load existing contract
        if CONFIG_FILE.exists():
            try:
                config = json.loads(CONFIG_FILE.read_text())
                address = config["contract_address"]
                abi = config["abi"]

                # Verify the contract still exists on Ganache
                code = self.w3.eth.get_code(address)
                if code and len(code) > 2:  # Not just "0x"
                    self.contract = self.w3.eth.contract(
                        address=address, abi=abi
                    )
                    self.contract_address = address
                    chain_len = self.contract.functions.getChainLength().call()
                    print(f"  📄 Loaded existing contract: {address[:20]}...")
                    print(f"  📊 On-chain blocks: {chain_len}")
                    return self.contract
            except Exception as e:
                print(f"  ⚠️  Could not load existing contract: {e}")
                print(f"  📄 Deploying new contract...")

        # Compile and deploy new contract
        return self._compile_and_deploy()

    def _compile_and_deploy(self):
        """Compile Solidity contract and deploy to Ganache."""

        if not SOL_FILE.exists():
            raise FileNotFoundError(
                f"Contract not found: {SOL_FILE}\n"
                f"Make sure contracts/BVCRSALedger.sol exists."
            )

        sol_source = SOL_FILE.read_text()

        # Method 1: Use py-solc-x if available
        if _HAS_SOLCX:
            abi, bytecode = self._compile_with_solcx(sol_source)
        else:
            # Method 2: Use pre-compiled ABI/bytecode
            abi, bytecode = self._compile_with_json_fallback()

        # Deploy the contract
        Contract = self.w3.eth.contract(abi=abi, bytecode=bytecode)

        print(f"  🚀 Deploying BVCRSALedger to Ganache...")
        tx_hash = Contract.constructor().transact({
            'from': self.account,
            'gas': 3000000,
        })
        tx_receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash)

        self.contract_address = tx_receipt.contractAddress
        self.contract = self.w3.eth.contract(
            address=self.contract_address, abi=abi
        )

        # Save config for persistence across restarts
        config = {
            "contract_address": self.contract_address,
            "abi": abi,
            "deployed_at": time.time(),
            "deployer": self.account,
            "tx_hash": tx_hash.hex(),
            "block_number": tx_receipt.blockNumber,
            "gas_used": tx_receipt.gasUsed,
        }
        CONFIG_FILE.write_text(json.dumps(config, indent=2))

        print(f"  ✅ Contract deployed!")
        print(f"     Address:  {self.contract_address}")
        print(f"     Tx Hash:  {tx_hash.hex()[:20]}...")
        print(f"     Gas Used: {tx_receipt.gasUsed}")
        print(f"     Block:    {tx_receipt.blockNumber}")

        return self.contract

    def _compile_with_solcx(self, sol_source):
        """Compile Solidity using py-solc-x."""
        # Install solc if not available
        installed = solcx.get_installed_solc_versions()
        if not installed:
            print(f"  📦 Installing Solidity compiler 0.8.19...")
            solcx.install_solc("0.8.19")
        solcx.set_solc_version("0.8.19")

        compiled = solcx.compile_source(
            sol_source,
            output_values=["abi", "bin"],
            solc_version="0.8.19"
        )

        # Get the contract interface
        contract_id = None
        for key in compiled:
            if "BVCRSALedger" in key:
                contract_id = key
                break
        if not contract_id:
            contract_id = list(compiled.keys())[0]

        interface = compiled[contract_id]
        return interface["abi"], interface["bin"]

    def _compile_with_json_fallback(self):
        """Fallback: use pre-compiled ABI/bytecode from JSON."""
        fallback_file = CONTRACT_DIR / "BVCRSALedger_compiled.json"
        if fallback_file.exists():
            compiled = json.loads(fallback_file.read_text())
            return compiled["abi"], compiled["bytecode"]
        raise ImportError(
            "\n\n  ❌  Cannot compile Solidity. Install py-solc-x:\n"
            "      pip install py-solc-x\n"
            "  Or provide pre-compiled contracts/BVCRSALedger_compiled.json\n"
        )

    # ─── Blockchain Operations ───────────────────────────────────

    def anchor_block(self, data_hash_hex, block_hash_hex):
        """Anchor a block record to the smart contract.

        Sends a real Ethereum transaction to Ganache.

        Args:
            data_hash_hex: SHA-256 hex string of the SCRAT operation data
            block_hash_hex: SHA-256 hex string of the PoW block hash

        Returns:
            dict with tx_hash, gas_used, block_number, on_chain_index
        """
        if not self.contract:
            raise RuntimeError("Contract not deployed. Call deploy_or_load_contract() first.")

        # Convert hex strings to bytes32
        data_hash = bytes.fromhex(data_hash_hex.replace("0x", "").ljust(64, '0')[:64])
        block_hash = bytes.fromhex(block_hash_hex.replace("0x", "").ljust(64, '0')[:64])

        tx_hash = self.contract.functions.anchorBlock(
            data_hash, block_hash
        ).transact({
            'from': self.account,
            'gas': 200000,
        })
        receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash)

        # Get the on-chain index from the event log
        on_chain_index = None
        try:
            logs = self.contract.events.BlockAnchored().process_receipt(receipt)
            if logs:
                on_chain_index = logs[0]['args']['index']
        except Exception:
            pass

        return {
            "tx_hash": tx_hash.hex(),
            "gas_used": receipt.gasUsed,
            "block_number": receipt.blockNumber,
            "on_chain_index": on_chain_index,
            "status": "success" if receipt.status == 1 else "failed",
        }

    def anchor_epoch_root(self, epoch, epoch_root_hex):
        """Anchor an epoch Merkle root to the smart contract.

        Args:
            epoch: Epoch number (integer)
            epoch_root_hex: SHA-256 hex string of the epoch root

        Returns:
            dict with tx_hash, gas_used, block_number
        """
        if not self.contract:
            raise RuntimeError("Contract not deployed. Call deploy_or_load_contract() first.")

        epoch_root = bytes.fromhex(epoch_root_hex.replace("0x", "").ljust(64, '0')[:64])

        tx_hash = self.contract.functions.anchorEpochRoot(
            epoch, epoch_root
        ).transact({
            'from': self.account,
            'gas': 200000,
        })
        receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash)

        return {
            "tx_hash": tx_hash.hex(),
            "gas_used": receipt.gasUsed,
            "block_number": receipt.blockNumber,
            "epoch": epoch,
            "status": "success" if receipt.status == 1 else "failed",
        }

    def verify_block_on_chain(self, index, expected_hash_hex):
        """Verify a block hash matches the on-chain record.

        This is a READ operation (no gas cost).

        Args:
            index: Block index to verify
            expected_hash_hex: Expected SHA-256 block hash

        Returns:
            bool: True if the on-chain hash matches
        """
        if not self.contract:
            return False

        expected = bytes.fromhex(expected_hash_hex.replace("0x", "").ljust(64, '0')[:64])
        try:
            return self.contract.functions.verifyBlockHash(index, expected).call()
        except Exception:
            return False

    def verify_epoch_on_chain(self, epoch, expected_root_hex):
        """Verify an epoch root matches the on-chain record."""
        if not self.contract:
            return False

        expected = bytes.fromhex(expected_root_hex.replace("0x", "").ljust(64, '0')[:64])
        try:
            return self.contract.functions.verifyEpochRoot(epoch, expected).call()
        except Exception:
            return False

    def get_chain_info(self):
        """Get comprehensive on-chain status.

        Returns:
            dict with chain stats, contract info, Ganache connection status
        """
        if not self.contract:
            return {"status": "not_deployed", "ganache_connected": self.w3.is_connected()}

        try:
            chain_len, epochs, latest_hash, genesis_hash, contract_owner = \
                self.contract.functions.getChainSummary().call()

            return {
                "status": "active",
                "ganache_connected": True,
                "ganache_url": self.ganache_url,
                "contract_address": self.contract_address,
                "account": self.account,
                "balance_eth": float(self.w3.from_wei(
                    self.w3.eth.get_balance(self.account), 'ether'
                )),
                "on_chain_blocks": chain_len,
                "on_chain_epochs": epochs,
                "latest_block_hash": "0x" + latest_hash.hex(),
                "genesis_data_hash": "0x" + genesis_hash.hex(),
                "contract_owner": contract_owner,
                "eth_block_number": self.w3.eth.block_number,
            }
        except Exception as e:
            return {
                "status": "error",
                "ganache_connected": self.w3.is_connected(),
                "error": str(e),
            }

    def get_block_on_chain(self, index):
        """Retrieve a specific block record from the smart contract."""
        if not self.contract:
            return None
        try:
            idx, timestamp, data_hash, block_hash, anchored_by = \
                self.contract.functions.getBlock(index).call()
            return {
                "index": idx,
                "timestamp": timestamp,
                "data_hash": "0x" + data_hash.hex(),
                "block_hash": "0x" + block_hash.hex(),
                "anchored_by": anchored_by,
            }
        except Exception:
            return None

    def get_recent_transactions(self, count=5):
        """Get the most recent Ethereum block info from Ganache."""
        try:
            latest_block_num = self.w3.eth.block_number
            txs = []
            for i in range(max(0, latest_block_num - count + 1), latest_block_num + 1):
                block = self.w3.eth.get_block(i, full_transactions=True)
                for tx in block.transactions:
                    txs.append({
                        "tx_hash": tx.hash.hex(),
                        "block_number": block.number,
                        "from": tx['from'],
                        "to": tx['to'],
                        "gas_used": tx['gas'],
                    })
            return txs[-count:]  # Return last N
        except Exception:
            return []
