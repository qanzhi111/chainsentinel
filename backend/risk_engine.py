"""
ChainSentinel — AI Risk Engine
Uses Gemini to analyze on-chain data and produce risk scores + reports.
"""

import os
import json
from datetime import datetime, timezone


class RiskEngine:
    """AI-powered risk analysis engine using Google Gemini."""

    def __init__(self):
        self._model = None
        self._gemini_available = None

    def _init_gemini(self):
        """Lazy init Gemini only when needed and available."""
        if self._gemini_available is not None:
            return self._gemini_available
        
        api_key = os.getenv("GEMINI_API_KEY", "")
        if not api_key:
            self._gemini_available = False
            return False
        
        try:
            import google.generativeai as genai
            genai.configure(api_key=api_key)
            self._model = genai.GenerativeModel("gemini-2.0-flash")
            self._gemini_available = True
            return True
        except Exception:
            self._gemini_available = False
            return False

    async def analyze(self, address: str, chain: str, chain_data: dict) -> dict:
        """Analyze an address and return a risk report."""
        if self._init_gemini():
            return await self._gemini_analysis(address, chain, chain_data)
        return self._rule_based_analysis(address, chain, chain_data)

    async def _gemini_analysis(self, address: str, chain: str, chain_data: dict) -> dict:
        """Use Gemini AI for deep risk analysis."""
        try:
            prompt = f"""You are ChainSentinel, an expert on-chain security analyst. Analyze the following blockchain data for risk factors.

Address: {address}
Chain: {chain}

On-chain data:
{json.dumps(chain_data, indent=2)}

Provide a JSON response with exactly these fields:
- risk_score: integer 0-100 (0=safe, 100=certain scam)
- risk_level: one of "low", "medium", "high", "critical"
- findings: array of specific risk factors found (each with "type", "severity", "description")
- ai_analysis: 2-3 paragraph plain-English analysis explaining the risk assessment

Risk factors to check:
1. Is this a known rug pull / honeypot contract?
2. Does the contract have suspicious functions (mint, blacklist, pause)?
3. Is token concentration >80% in top wallets?
4. Are there wash trading patterns?
5. Is liquidity locked or unlocked?
6. Any recent large suspicious transfers?
7. Is the contract verified on Etherscan?
8. Developer wallet behavior (fund mixing, tornado cash)

Be conservative - only flag real risks, not normal DeFi activity."""

            response = self._model.generate_content(prompt)
            text = response.text

            if "```json" in text:
                text = text.split("```json")[1].split("```")[0]
            elif "```" in text:
                text = text.split("```")[1].split("```")[0]

            result = json.loads(text.strip())
            return {
                "address": address,
                "chain": chain,
                "risk_score": result.get("risk_score", 50),
                "risk_level": result.get("risk_level", "medium"),
                "findings": result.get("findings", []),
                "ai_analysis": result.get("ai_analysis", "Analysis unavailable."),
                "checked_at": datetime.now(timezone.utc).isoformat(),
            }
        except Exception:
            return self._rule_based_analysis(address, chain, chain_data)

    def _rule_based_analysis(self, address: str, chain: str, chain_data: dict) -> dict:
        """Fallback rule-based risk analysis."""
        risk_score = 30
        findings = []

        if not chain_data.get("contract_verified", True):
            risk_score += 20
            findings.append({
                "type": "unverified_contract",
                "severity": "high",
                "description": "Contract source code is not verified on block explorer.",
            })

        top_holders_pct = chain_data.get("top_holders_percentage", 0)
        if top_holders_pct > 80:
            risk_score += 25
            findings.append({
                "type": "concentration_risk",
                "severity": "critical",
                "description": f"Top holders control {top_holders_pct}% of token supply.",
            })
        elif top_holders_pct > 60:
            risk_score += 10
            findings.append({
                "type": "concentration_risk",
                "severity": "medium",
                "description": f"Top holders control {top_holders_pct}% of token supply.",
            })

        if not chain_data.get("liquidity_locked", True):
            risk_score += 15
            findings.append({
                "type": "liquidity_risk",
                "severity": "high",
                "description": "Liquidity is not locked — rug pull possible.",
            })

        suspicious_funcs = chain_data.get("suspicious_functions", [])
        for func in suspicious_funcs:
            risk_score += 10
            findings.append({
                "type": "suspicious_function",
                "severity": "high",
                "description": f"Contract contains suspicious function: {func}",
            })

        risk_score = min(risk_score, 100)

        if risk_score >= 80:
            risk_level = "critical"
        elif risk_score >= 60:
            risk_level = "high"
        elif risk_score >= 40:
            risk_level = "medium"
        else:
            risk_level = "low"

        return {
            "address": address,
            "chain": chain,
            "risk_score": risk_score,
            "risk_level": risk_level,
            "findings": findings,
            "ai_analysis": f"Rule-based analysis for {address[:8]}... on {chain}. "
                          f"Risk score: {risk_score}/100. "
                          f"Found {len(findings)} risk factor(s). "
                          f"Enable Gemini API for AI-powered deep analysis.",
            "checked_at": datetime.now(timezone.utc).isoformat(),
        }
