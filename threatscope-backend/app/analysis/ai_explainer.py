"""
AI-powered threat explanation generator using a local Ollama LLM.

Sends the structured scan analysis to Ollama (Mistral 7B by default)
and receives a plain-English threat assessment with MITRE ATT&CK
technique mapping and actionable recommendations.

This module is **optional** — if Ollama is not running the scan
still completes normally and ``ai_available`` is set to False.

All functions are async (called from RQ via ``_run_async``).
"""

import logging
import re
from typing import Any

import httpx

from app.core.config import settings

logger = logging.getLogger(__name__)

# ─────────────────────────────────────────────────────────────
# Configuration
# ─────────────────────────────────────────────────────────────

OLLAMA_URL = getattr(settings, "OLLAMA_URL", "http://ollama:11434/api/generate")
OLLAMA_MODEL = getattr(settings, "OLLAMA_MODEL", "mistral")
OLLAMA_TIMEOUT = 90.0  # seconds — LLM on CPU can be slow

# ─────────────────────────────────────────────────────────────
# MITRE ATT&CK technique lookup (common subset)
# ─────────────────────────────────────────────────────────────

MITRE_TECHNIQUES: dict[str, dict[str, str]] = {
    "T1059": {"name": "Command and Scripting Interpreter", "tactic": "Execution"},
    "T1059.001": {"name": "PowerShell", "tactic": "Execution"},
    "T1059.003": {"name": "Windows Command Shell", "tactic": "Execution"},
    "T1059.005": {"name": "Visual Basic", "tactic": "Execution"},
    "T1059.007": {"name": "JavaScript", "tactic": "Execution"},
    "T1547": {"name": "Boot or Logon Autostart Execution", "tactic": "Persistence"},
    "T1547.001": {"name": "Registry Run Keys / Startup Folder", "tactic": "Persistence"},
    "T1053": {"name": "Scheduled Task/Job", "tactic": "Persistence"},
    "T1053.005": {"name": "Scheduled Task", "tactic": "Persistence"},
    "T1055": {"name": "Process Injection", "tactic": "Defense Evasion"},
    "T1055.001": {"name": "DLL Injection", "tactic": "Defense Evasion"},
    "T1055.012": {"name": "Process Hollowing", "tactic": "Defense Evasion"},
    "T1027": {"name": "Obfuscated Files or Information", "tactic": "Defense Evasion"},
    "T1027.002": {"name": "Software Packing", "tactic": "Defense Evasion"},
    "T1140": {"name": "Deobfuscate/Decode Files", "tactic": "Defense Evasion"},
    "T1497": {"name": "Virtualization/Sandbox Evasion", "tactic": "Defense Evasion"},
    "T1497.001": {"name": "System Checks", "tactic": "Defense Evasion"},
    "T1082": {"name": "System Information Discovery", "tactic": "Discovery"},
    "T1083": {"name": "File and Directory Discovery", "tactic": "Discovery"},
    "T1071": {"name": "Application Layer Protocol", "tactic": "Command and Control"},
    "T1071.001": {"name": "Web Protocols", "tactic": "Command and Control"},
    "T1105": {"name": "Ingress Tool Transfer", "tactic": "Command and Control"},
    "T1486": {"name": "Data Encrypted for Impact", "tactic": "Impact"},
    "T1566": {"name": "Phishing", "tactic": "Initial Access"},
    "T1566.001": {"name": "Spearphishing Attachment", "tactic": "Initial Access"},
    "T1566.002": {"name": "Spearphishing Link", "tactic": "Initial Access"},
    "T1003": {"name": "OS Credential Dumping", "tactic": "Credential Access"},
    "T1003.001": {"name": "LSASS Memory", "tactic": "Credential Access"},
    "T1056": {"name": "Input Capture", "tactic": "Collection"},
    "T1056.001": {"name": "Keylogging", "tactic": "Collection"},
    "T1113": {"name": "Screen Capture", "tactic": "Collection"},
    "T1041": {"name": "Exfiltration Over C2 Channel", "tactic": "Exfiltration"},
}


# ─────────────────────────────────────────────────────────────
# Prompt builder
# ─────────────────────────────────────────────────────────────

def build_analysis_prompt(scan_result: dict[str, Any]) -> str:
    """
    Construct a detailed prompt for the LLM from scan results.

    Includes the target, scan type, threat score, verdict, ranked
    reasons, YARA matches, suspicious strings, PE imports, and
    extracted IOCs.
    """
    scan_type = scan_result.get("scan_type", "unknown")
    score = scan_result.get("score", 0)
    verdict = scan_result.get("verdict_label", "UNKNOWN")
    reasons = scan_result.get("reasons", [])
    top_threat = scan_result.get("top_threat", "None identified")
    breakdown = scan_result.get("breakdown", {})

    reasons_text = "\n".join(f"  - {r}" for r in reasons) if reasons else "  - None"

    breakdown_text = ""
    for signal, data in breakdown.items():
        breakdown_text += f"  - {signal}: {data.get('score', 0)}/{data.get('max', 0)} — {data.get('detail', '')}\n"

    prompt = f"""You are a senior cybersecurity threat analyst. Analyse the following automated scan results and provide a concise, expert-level threat assessment.

## Scan Details
- **Type**: {scan_type} scan
- **Threat Score**: {score}/100
- **Verdict**: {verdict}
- **Top Threat**: {top_threat}

## Scoring Breakdown
{breakdown_text}
## Key Findings
{reasons_text}

## Your Task
Provide your analysis in the following structure:

1. **Summary** (2-3 sentences): What was detected and why it matters.
2. **Threat Assessment**: Explain each suspicious indicator found and what it means.
3. **Likely Attacker Objective**: What is the probable goal of this threat? (if applicable)
4. **MITRE ATT&CK Techniques**: List relevant technique IDs (e.g., T1059.001) with their names.
5. **Recommended Actions**: 3-5 specific, actionable remediation or investigation steps.

Be specific — reference the actual indicators found. If the scan is clean, say so clearly and briefly. Do not invent indicators that were not reported above."""

    return prompt


# ─────────────────────────────────────────────────────────────
# Public API
# ─────────────────────────────────────────────────────────────

async def generate_explanation(scan_result: dict[str, Any]) -> dict[str, Any]:
    """
    Send scan results to the local Ollama LLM for a natural-language
    threat explanation.

    Args:
        scan_result: Output from ``threat_score.calculate_threat_score()``.

    Returns:
        Dictionary with the explanation text, extracted MITRE
        technique details, recommended actions, confidence level,
        and the model name used.

    Never raises — returns ``{"ai_available": False, ...}`` on any
    error so the scan can still complete.
    """
    prompt = build_analysis_prompt(scan_result)

    try:
        # Add 2s health check
        async with httpx.AsyncClient(timeout=2.0) as check_client:
            health = await check_client.get(OLLAMA_URL.replace("/api/generate", "/api/tags"))
            if health.status_code != 200:
                raise httpx.ConnectError("Health check failed")

        async with httpx.AsyncClient(timeout=OLLAMA_TIMEOUT) as client:
            response = await client.post(
                OLLAMA_URL,
                json={
                    "model": OLLAMA_MODEL,
                    "prompt": prompt,
                    "stream": False,
                    "options": {
                        "temperature": 0.3,
                        "num_predict": 1024,
                    },
                },
            )

        if response.status_code != 200:
            logger.warning(
                "Ollama returned HTTP %d: %s",
                response.status_code,
                response.text[:200],
            )
            return {
                "ai_available": False,
                "explanation": None,
                "error": f"Ollama returned HTTP {response.status_code}",
            }

        data = response.json()
        explanation = data.get("response", "").strip()

        if not explanation:
            return {
                "ai_available": False,
                "explanation": None,
                "error": "Ollama returned an empty response",
            }

        # ── Extract MITRE technique IDs from the explanation ──
        technique_ids = list(set(re.findall(r"\bT\d{4}(?:\.\d{3})?\b", explanation)))

        # Also include techniques from the scan result's IOC data
        ioc_techniques = scan_result.get("iocs", {}).get("mitre_techniques", []) if isinstance(scan_result.get("iocs"), dict) else []
        all_technique_ids = sorted(set(technique_ids + ioc_techniques))

        mitre_details: list[dict[str, str]] = []
        for tid in all_technique_ids:
            info = MITRE_TECHNIQUES.get(tid)
            if info:
                mitre_details.append({
                    "id": tid,
                    "name": info["name"],
                    "tactic": info["tactic"],
                })

        # ── Extract recommended actions ──────
        recommended_actions: list[str] = []
        action_section = False
        for line in explanation.split("\n"):
            stripped = line.strip()
            # Heuristic: look for numbered or bulleted items after
            # "Recommended Actions" heading
            if "recommended action" in stripped.lower():
                action_section = True
                continue
            if action_section and stripped:
                # Stop at the next heading
                if stripped.startswith("#") or stripped.startswith("**") and stripped.endswith("**"):
                    action_section = False
                    continue
                # Clean up markdown list markers
                cleaned = re.sub(r"^[\d]+[\.\)]\s*", "", stripped)
                cleaned = re.sub(r"^[-\*]\s*", "", cleaned)
                if len(cleaned) > 10:
                    recommended_actions.append(cleaned)

        # ── Confidence heuristic ─────────────
        score = scan_result.get("score", 0)
        if score >= 70:
            confidence = "high"
        elif score >= 40:
            confidence = "medium"
        else:
            confidence = "low"

        logger.info("AI explanation generated (%d chars, %d MITRE techniques)",
                     len(explanation), len(mitre_details))

        return {
            "ai_available": True,
            "explanation": explanation,
            "mitre_techniques": mitre_details,
            "recommended_actions": recommended_actions[:5],
            "confidence": confidence,
            "model_used": OLLAMA_MODEL,
            "error": None,
        }

    except (httpx.ConnectError, httpx.TimeoutException, Exception) as exc:
        logger.warning("AI generation failed (%s) - using rule-based fallback", str(exc))
        
        scan_type = scan_result.get("scan_type", "unknown")
        score = scan_result.get("score", 0)
        verdict = scan_result.get("verdict_label", "UNKNOWN")
        reasons = scan_result.get("reasons", [])
        
        fallback_exp = f"Based on automated analysis of the {scan_type}, the threat score is {score}/100 ({verdict}).\n\n"
        if reasons:
            fallback_exp += "Key findings:\n"
            for r in reasons:
                fallback_exp += f"- {r}\n"
        else:
            fallback_exp += "No significant suspicious activity was found."
            
        return {
            "ai_available": False,
            "explanation": fallback_exp,
            "mitre_techniques": [],
            "recommended_actions": ["Review scan results manually", "Isolate if suspicious"],
            "confidence": "low",
            "model_used": "rule-based-fallback",
            "error": str(exc),
        }
