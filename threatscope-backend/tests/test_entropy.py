"""
Unit tests for app.analysis.entropy.
"""

import os
import tempfile
import pytest
from app.analysis.entropy import (
    calculate_file_entropy,
    entropy_verdict,
)

@pytest.fixture
def temp_file_factory():
    files = []
    
    def _create_temp_file(content: bytes):
        temp = tempfile.NamedTemporaryFile(delete=False)
        temp.write(content)
        temp.close()
        files.append(temp.name)
        return temp.name

    yield _create_temp_file

    for path in files:
        if os.path.exists(path):
            os.unlink(path)

def test_entropy_low(temp_file_factory):
    """Identical bytes should yield close to 0 entropy."""
    file_path = temp_file_factory(b"A" * 1000)
    entropy = calculate_file_entropy(file_path)
    assert 0.0 <= entropy < 1.0

def test_entropy_high(temp_file_factory):
    """Random bytes should yield high entropy (close to 8)."""
    # Generate 1000 random bytes
    file_path = temp_file_factory(os.urandom(1000))
    entropy = calculate_file_entropy(file_path)
    assert 7.0 < entropy <= 8.0

def test_entropy_normal(temp_file_factory):
    """Typical text content should yield medium/normal entropy."""
    text_content = b"This is a normal text file with typical ASCII words. It is used to test normal entropy levels." * 10
    file_path = temp_file_factory(text_content)
    entropy = calculate_file_entropy(file_path)
    assert 3.5 <= entropy < 6.0

def test_entropy_verdicts():
    """Verify verdict thresholds mapping."""
    # normal range (< 6.5)
    v_normal = entropy_verdict(5.0)
    assert v_normal["entropy_score"] == 0
    assert v_normal["entropy_label"] == "normal"

    # elevated range (6.5 - 7.0)
    v_elevated = entropy_verdict(6.7)
    assert v_elevated["entropy_score"] == 5
    assert v_elevated["entropy_label"] == "elevated"

    # high range (7.0 - 7.5)
    v_high = entropy_verdict(7.2)
    assert v_high["entropy_score"] == 12
    assert v_high["entropy_label"] == "high"

    # very high range (> 7.5)
    v_very_high = entropy_verdict(7.8)
    assert v_very_high["entropy_score"] == 20
    assert v_very_high["entropy_label"] == "very_high"
