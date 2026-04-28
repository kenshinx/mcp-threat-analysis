"""Collect string literals + classify URLs / emails / paths / high-entropy."""
from __future__ import annotations

import math
import re
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

from ..target_loader import is_text_file

_URL_RE = re.compile(r"https?://[\w\-\.]+(?::\d+)?(?:/[\w\-\./?%&=]*)?")
_EMAIL_RE = re.compile(r"[\w\.\-]+@[\w\-]+\.[\w\.\-]+")
_PATH_RE = re.compile(r"(?:/[\w\-\.]+){2,}")
_LITERAL_RE = re.compile(r'"((?:[^"\\]|\\.){4,})"|\'((?:[^\'\\]|\\.){4,})\'')


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in Counter(s).values())


@dataclass(slots=True)
class StringBag:
    literals: list[str] = field(default_factory=list)
    urls: set[str] = field(default_factory=set)
    hosts: set[str] = field(default_factory=set)
    emails: set[str] = field(default_factory=set)
    paths: set[str] = field(default_factory=set)
    high_entropy: list[str] = field(default_factory=list)


class StringExtractor:
    def extract(self, root: Path, *, max_files: int = 5000) -> StringBag:
        bag = StringBag()
        seen = 0
        for p in root.rglob("*"):
            if not p.is_file() or not is_text_file(p):
                continue
            seen += 1
            if seen > max_files:
                break
            try:
                text = p.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            self._scan(text, bag)
        return bag

    def _scan(self, text: str, bag: StringBag) -> None:
        for m in _LITERAL_RE.finditer(text):
            lit = m.group(1) or m.group(2)
            if not lit:
                continue
            bag.literals.append(lit)
            for u in _URL_RE.findall(lit):
                bag.urls.add(u)
                bag.hosts.add(u.split("/")[2] if "://" in u else u)
            for e in _EMAIL_RE.findall(lit):
                bag.emails.add(e)
            for path in _PATH_RE.findall(lit):
                bag.paths.add(path)
            if len(lit) >= 50 and shannon_entropy(lit) >= 4.5:
                bag.high_entropy.append(lit)
