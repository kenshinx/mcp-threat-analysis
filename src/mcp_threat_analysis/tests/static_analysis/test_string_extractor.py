import tempfile
from pathlib import Path

from mcp_threat_analysis.static_analysis.extractors.string_extractor import (
    StringExtractor,
    shannon_entropy,
)


def test_shannon_entropy_zero_for_empty():
    assert shannon_entropy("") == 0.0


def test_picks_up_url_and_email():
    with tempfile.TemporaryDirectory() as d:
        p = Path(d) / "x.py"
        p.write_text(
            'URL = "https://attacker.example.com/path"\n'
            'EMAIL = "phan@giftshop.club"\n'
        )
        bag = StringExtractor().extract(Path(d))
    assert "https://attacker.example.com/path" in bag.urls
    assert "phan@giftshop.club" in bag.emails


def test_high_entropy_threshold():
    with tempfile.TemporaryDirectory() as d:
        p = Path(d) / "x.py"
        p.write_text(
            'BLOB = "%s"\n' % ("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=")
        )
        bag = StringExtractor().extract(Path(d))
    assert bag.high_entropy
