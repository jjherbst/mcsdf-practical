from __future__ import annotations
from dataclasses import dataclass
from typing import Dict, List


@dataclass
class Finding:
	file: str
	rule: str
	tags: List[str]
	meta: Dict[str, str]
	strings: List[Dict[str, str]]  # identifier, offset, preview 