"""
Yara Rules Manager.
Clones yara rules repositories, compiles rules, and provides matching.
"""

import os
import time
import json
import logging
try:
    import yara
    YARA_AVAILABLE = True
except ImportError:
    yara = None
    YARA_AVAILABLE = False

from git import Repo
from app.core.config import settings
from app.core.rq_setup import redis_conn

logger = logging.getLogger(__name__)

# Configurable paths with fallback for development and testing environments
YARA_BASE_DIR = settings.YARA_BASE_DIR
COMPILED_RULES_PATH = settings.COMPILED_RULES_PATH

if os.name == 'nt' or not os.path.exists('/app'):
    project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
    YARA_BASE_DIR = os.path.join(project_root, "yara_rules", "repos")
    COMPILED_RULES_PATH = os.path.join(project_root, "yara_rules", "compiled.yarc")

REPOS = {
    "yara-rules": settings.YARA_REPO_1_URL,
    "signature-base": settings.YARA_REPO_2_URL,
}

_compiled_rules = None

def update_rules():
    """Clone or pull latest rules and compile them."""
    global _compiled_rules
    if not YARA_AVAILABLE:
        logger.warning("YARA package not available. Skipping rule compilation.")
        return
    os.makedirs(YARA_BASE_DIR, exist_ok=True)
    
    filepaths = {}
    
    for name, url in REPOS.items():
        repo_dir = os.path.join(YARA_BASE_DIR, name)
        if os.path.exists(os.path.join(repo_dir, ".git")):
            logger.info(f"Pulling latest for {name}")
            try:
                repo = Repo(repo_dir)
                origin = repo.remotes.origin
                origin.pull()
            except Exception as e:
                logger.error(f"Failed to pull {name}: {e}")
        else:
            logger.info(f"Cloning {name}")
            try:
                Repo.clone_from(url, repo_dir)
            except Exception as e:
                logger.error(f"Failed to clone {name}: {e}")

        # Gather .yar and .yara files
        rule_index = 0
        for root, _, files in os.walk(repo_dir):
            for file in files:
                if file.endswith(".yar") or file.endswith(".yara"):
                    path = os.path.join(root, file)
                    # yara.compile(filepaths=...) expects a flat dict of
                    # {namespace: filepath} where both are plain strings.
                    # Use a unique namespace key per file to avoid collisions.
                    namespace = f"{name}_{rule_index}"
                    filepaths[namespace] = str(path)
                    rule_index += 1

    # Compile rules
    try:
        if not filepaths:
            logger.warning("No YARA rule files found to compile.")
            return

        rules = yara.compile(filepaths=filepaths)
        os.makedirs(os.path.dirname(COMPILED_RULES_PATH), exist_ok=True)
        rules.save(COMPILED_RULES_PATH)
        _compiled_rules = rules
        
        # Save stats to redis
        stats = {
            "last_updated": time.time(),
            "rule_count": sum(len(rules_dict) for rules_dict in filepaths.values())
        }
        redis_conn.set("yara_status", json.dumps(stats))
        logger.info("Yara rules updated and compiled successfully.")
    except yara.SyntaxError as e:
        logger.error(f"Failed to compile yara rules: {e}")
    except Exception as e:
        logger.error(f"Unexpected error compiling YARA rules: {e}")
        
def get_rules():
    global _compiled_rules
    if not YARA_AVAILABLE:
        return None
    if _compiled_rules is None:
        if os.path.exists(COMPILED_RULES_PATH):
            try:
                _compiled_rules = yara.load(COMPILED_RULES_PATH)
            except Exception as e:
                logger.error(f"Failed to load compiled rules from {COMPILED_RULES_PATH}: {e}")
                update_rules()
        else:
            update_rules()
    return _compiled_rules

_SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}

def _get_severity(meta: dict) -> str:
    """Extract severity from rule metadata, default 'medium'."""
    return str(meta.get("severity", "medium")).lower()

def scan_with_yara(file_path: str) -> dict:
    """
    Scan a file against all compiled YARA rules.
    
    Returns:
        Dictionary matching the standard YARA engine output schema.
    """
    if not YARA_AVAILABLE:
        return {
            "yara_available": False,
            "matches": [],
            "match_count": 0,
            "yara_score": 0,
            "malware_families": [],
            "highest_severity": "none",
            "error": "yara-python package not installed",
        }
    rules = get_rules()
    if not rules:
        return {
            "yara_available": False,
            "matches": [],
            "match_count": 0,
            "yara_score": 0,
            "malware_families": [],
            "highest_severity": "none",
            "error": "YARA rules not loaded",
        }

    try:
        raw_matches = rules.match(file_path, timeout=60)
    except Exception as exc:
        logger.error("YARA scan failed for %s: %s", file_path, str(exc))
        return {
            "yara_available": True,
            "matches": [],
            "match_count": 0,
            "yara_score": 0,
            "malware_families": [],
            "highest_severity": "none",
            "error": str(exc),
        }

    matches = []
    malware_families = []
    highest_severity = "none"
    highest_sev_val = -1

    for match in raw_matches:
        meta = dict(match.meta) if match.meta else {}
        tags = list(match.tags) if match.tags else []
        severity = _get_severity(meta)

        # Track highest severity
        sev_val = _SEVERITY_ORDER.get(severity, 0)
        if sev_val > highest_sev_val:
            highest_sev_val = sev_val
            highest_severity = severity

        # Extract matched string literals (first 10 per rule)
        strings_matched = []
        for string_match in match.strings[:10]:
            for instance in string_match.instances[:3]:
                try:
                    decoded = instance.matched_data.decode("utf-8", errors="replace")
                    if decoded and decoded not in strings_matched:
                        strings_matched.append(decoded)
                except Exception:
                    pass

        # Extract malware family from rule name heuristics
        rule_name = match.rule
        if any(
            kw in rule_name.lower()
            for kw in ("rat", "trojan", "ransom", "backdoor", "worm", "miner", "stealer")
        ):
            malware_families.append(rule_name)

        matches.append({
            "rule": rule_name,
            "namespace": match.namespace,
            "tags": tags,
            "meta": meta,
            "strings_matched": strings_matched[:10],
            "severity": severity,
        })

    match_count = len(matches)
    yara_score = min(25, match_count * 8)

    return {
        "yara_available": True,
        "matches": matches,
        "match_count": match_count,
        "yara_score": yara_score,
        "malware_families": sorted(set(malware_families)),
        "highest_severity": highest_severity,
    }

def get_status() -> dict:
    if not YARA_AVAILABLE:
        return {
            "loaded": False,
            "rule_count": 0,
            "last_updated": None,
            "error": "yara-python package not installed",
        }
    status_data = redis_conn.get("yara_status")
    if status_data:
        try:
            return json.loads(status_data)
        except Exception:
            pass
    return {"last_updated": None, "rule_count": 0, "loaded": True}
