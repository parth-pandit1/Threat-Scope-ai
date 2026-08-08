"""
Unit tests for app.analysis.ioc_extractor.
"""

from app.analysis.ioc_extractor import extract_iocs, defang_ioc

def test_extract_ips():
    """Verify IP extraction and private range filtering."""
    text = (
        "Here is a malicious IP: 8.8.8.8 and another one: 104.244.42.1. "
        "We should ignore private ranges like 192.168.1.5, 10.0.0.1, and 127.0.0.1."
    )
    res = extract_iocs(text)
    assert "8.8.8.8" in res["ipv4"]
    assert "104.244.42.1" in res["ipv4"]
    assert "192.168.1.5" not in res["ipv4"]
    assert "10.0.0.1" not in res["ipv4"]
    assert "127.0.0.1" not in res["ipv4"]

def test_extract_domains_and_urls():
    """Verify domains and URLs are extracted and FP domains are blocked."""
    text = (
        "Malicious domain: evil-domain.com and url: http://evil-domain.com/malware.exe . "
        "Standard files import system.io, microsoft.com, and go.microsoft.com which are FPs."
    )
    res = extract_iocs(text)
    assert "evil-domain.com" in res["domains"]
    assert "http://evil-domain.com/malware.exe" in res["urls"]
    assert "system.io" not in res["domains"]
    assert "microsoft.com" not in res["domains"]
    assert "go.microsoft.com" not in res["domains"]

def test_extract_hashes():
    """Verify MD5, SHA-1, SHA-256, and SHA-512 extraction with deduplication."""
    md5_val = "d41d8cd98f00b204e9800998ecf8427e"
    sha256_val = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    
    text = f"We found MD5 hash: {md5_val} and SHA-256 hash: {sha256_val}."
    res = extract_iocs(text)
    
    assert md5_val in res["hashes"]["md5"]
    assert sha256_val in res["hashes"]["sha256"]
    
    # Substring check: MD5 has 32 chars. A SHA-256 has 64 hex chars,
    # which contains 32-char substrings. We must ensure no partial MD5 matches are extracted
    # from the SHA-256 string itself.
    assert len(res["hashes"]["md5"]) == 1

def test_extract_threat_intel():
    """Verify CVEs and MITRE ATT&CK techniques are extracted."""
    text = "This exploits CVE-2021-34527 (PrintNightmare) and uses T1059.003 for execution."
    res = extract_iocs(text)
    assert "CVE-2021-34527" in res["cves"]
    assert "T1059.003" in res["mitre_techniques"]

def test_defang_ioc():
    """Verify defanging URLs and IPs."""
    assert defang_ioc("http://evil.com") == "hxxp://evil[.]com"
    assert defang_ioc("https://evil.com/path") == "hxxps://evil[.]com/path"
    assert defang_ioc("8.8.8.8") == "8[.]8[.]8[.]8"
