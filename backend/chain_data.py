"""
ChainSentinel — Blockchain Data Service
Fetches on-chain data from Etherscan, BscScan, BaseScan, and Solana RPC.
"""

import os
import httpx
from typing import Optional


# Free API key tiers (rate-limited but sufficient for MVP)
ETHERSCAN_API_KEY = os.getenv("ETHERSCAN_API_KEY", "")
BSCSCAN_API_KEY = os.getenv("BSCSCAN_API_KEY", "")
BASESCAN_API_KEY = os.getenv("BASESCAN_API_KEY", "")

API_BASE_URLS = {
    "eth": "https://api.etherscan.io/api",
    "bsc": "https://api.bscscan.com/api",
    "base": "https://api.basescan.org/api",
    "sol": "https://api.mainnet-beta.solana.com",
}


class ChainDataService:
    """Fetch and aggregate on-chain data for risk analysis."""

    async def get_address_data(self, address: str, chain: str = "eth") -> dict:
        """Get comprehensive on-chain data for an address."""

        if chain == "sol":
            return await self._get_solana_data(address)

        return await self._get_evm_data(address, chain)

    async def _get_evm_data(self, address: str, chain: str) -> dict:
        """Fetch data for EVM-compatible chains (ETH, BSC, Base)."""

        base_url = API_BASE_URLS.get(chain, API_BASE_URLS["eth"])
        api_key = {
            "eth": ETHERSCAN_API_KEY,
            "bsc": BSCSCAN_API_KEY,
            "base": BASESCAN_API_KEY,
        }.get(chain, "")

        data = {
            "address": address,
            "chain": chain,
            "is_contract": False,
            "contract_verified": True,
            "balance_eth": "0",
            "token_holders": [],
            "top_holders_percentage": 0,
            "liquidity_locked": True,
            "suspicious_functions": [],
            "recent_transactions": [],
            "creation_tx": None,
        }

        async with httpx.AsyncClient(timeout=15.0) as client:
            try:
                # Check if contract
                params = {
                    "module": "proxy",
                    "action": "eth_getCode",
                    "address": address,
                    "apikey": api_key,
                }
                resp = await client.get(base_url, params=params)
                code = resp.json().get("result", "0x")
                data["is_contract"] = code != "0x" and code != "0x0"

                # Get balance
                params = {
                    "module": "account",
                    "action": "balance",
                    "address": address,
                    "tag": "latest",
                    "apikey": api_key,
                }
                resp = await client.get(base_url, params=params)
                balance_wei = resp.json().get("result", "0")
                if balance_wei and balance_wei != "0":
                    data["balance_eth"] = str(int(balance_wei) / 1e18)

                # Get recent transactions (normal txs)
                params = {
                    "module": "account",
                    "action": "txlist",
                    "address": address,
                    "startblock": 0,
                    "endblock": 99999999,
                    "page": 1,
                    "offset": 10,
                    "sort": "desc",
                    "apikey": api_key,
                }
                resp = await client.get(base_url, params=params)
                txs = resp.json().get("result", [])
                if isinstance(txs, list):
                    data["recent_transactions"] = [
                        {
                            "hash": tx.get("hash", ""),
                            "from": tx.get("from", ""),
                            "to": tx.get("to", ""),
                            "value": tx.get("value", "0"),
                            "timeStamp": tx.get("timeStamp", ""),
                        }
                        for tx in txs[:10]
                    ]

                # If it's a contract, check verification status
                if data["is_contract"] and api_key:
                    params = {
                        "module": "contract",
                        "action": "getabi",
                        "address": address,
                        "apikey": api_key,
                    }
                    resp = await client.get(base_url, params=params)
                    result = resp.json()
                    if result.get("status") == "0":
                        data["contract_verified"] = False
                    else:
                        # Parse ABI for suspicious functions
                        abi_text = result.get("result", "")
                        suspicious = self._check_suspicious_functions(abi_text)
                        data["suspicious_functions"] = suspicious

            except Exception as e:
                data["error"] = str(e)

        return data

    async def _get_solana_data(self, address: str) -> dict:
        """Fetch data for Solana addresses."""

        data = {
            "address": address,
            "chain": "sol",
            "is_contract": False,
            "balance_sol": "0",
            "token_accounts": [],
            "recent_transactions": [],
        }

        async with httpx.AsyncClient(timeout=15.0) as client:
            try:
                # Get account info
                payload = {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "getAccountInfo",
                    "params": [address, {"encoding": "jsonParsed"}],
                }
                resp = await client.post(API_BASE_URLS["sol"], json=payload)
                result = resp.json().get("result", {})
                if result and result.get("value"):
                    data["is_contract"] = result["value"].get("executable", False)

                # Get balance
                payload = {
                    "jsonrpc": "2.0",
                    "id": 2,
                    "method": "getBalance",
                    "params": [address],
                }
                resp = await client.post(API_BASE_URLS["sol"], json=payload)
                result = resp.json().get("result", {})
                if result:
                    lamports = result.get("value", 0)
                    data["balance_sol"] = str(lamports / 1e9)

            except Exception as e:
                data["error"] = str(e)

        return data

    def _check_suspicious_functions(self, abi_text: str) -> list:
        """Check contract ABI for suspicious function signatures."""
        suspicious = []
        red_flags = [
            "mint", "mintTo", "mintTokens",
            "blacklist", "blackList", "addToBlacklist",
            "setTax", "setMaxTax",
            "pauseTrading", "disableTrading",
            "withdrawAll", "sweepFunds",
            "setFee", "setFees",
        ]

        abi_lower = abi_text.lower()
        for flag in red_flags:
            if flag.lower() in abi_lower:
                suspicious.append(flag)

        return suspicious
