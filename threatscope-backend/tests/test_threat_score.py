"""
Unit tests for app.analysis.threat_score.
"""

from app.analysis.threat_score import calculate_threat_score

def test_threat_score_clean():
    """Verify that a score <= 19 results in 'clean' verdict."""
    results = {
        "scan_type": "file"
    }
    score_res = calculate_threat_score(results)
    assert score_res["score"] == 0
    assert score_res["verdict"] == "clean"

def test_threat_score_low_risk():
    """Verify that a score between 20 and 39 results in 'low_risk' verdict."""
    results = {
        "scan_type": "file",
        "entropy": {
            "entropy_score": 12,
            "value": 7.2,
            "entropy_label": "high"
        },
        "strings": {
            "string_score": 10,
            "suspicious_count": 2
        }
    }
    score_res = calculate_threat_score(results)
    assert 20 <= score_res["score"] <= 39
    assert score_res["verdict"] == "low_risk"

def test_threat_score_suspicious():
    """Verify that a score between 40 and 69 results in 'suspicious' verdict."""
    results = {
        "scan_type": "file",
        "entropy": {
            "entropy_score": 20,
            "value": 7.7,
            "entropy_label": "very_high"
        },
        "strings": {
            "string_score": 15,
            "suspicious_count": 5
        },
        "pe_analysis": {
            "is_pe": True,
            "suspicious_imports": ["CreateRemoteThread", "VirtualAllocEx", "WriteProcessMemory"]
        }
    }
    score_res = calculate_threat_score(results)
    # 20 + 15 + 6 = 41
    assert 40 <= score_res["score"] <= 69
    assert score_res["verdict"] == "suspicious"

def test_threat_score_malicious():
    """Verify that a score >= 70 results in 'malicious' verdict."""
    results = {
        "scan_type": "file",
        "yara": {
            "yara_score": 25,
            "match_count": 4,
            "malware_families": ["Trojan.Generic"]
        },
        "entropy": {
            "entropy_score": 20,
            "value": 7.7,
            "entropy_label": "very_high"
        },
        "strings": {
            "string_score": 15,
            "suspicious_count": 5
        },
        "pe_analysis": {
            "is_pe": True,
            "suspicious_imports": ["CreateRemoteThread", "VirtualAllocEx", "WriteProcessMemory", "QueueUserAPC"]
        },
        "virustotal": {
            "vt_available": True,
            "vt_found": True,
            "vt_malicious_count": 10,
            "vt_suspicious_count": 5,
            "vt_total_engines": 50
        }
    }
    score_res = calculate_threat_score(results)
    # YARA (25) + Entropy (20) + Strings (15) + PE (8) + VT (ratio (15/50) * 15 = 4) = 72
    assert score_res["score"] >= 70
    assert score_res["verdict"] == "malicious"
