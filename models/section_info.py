from __future__ import annotations
from dataclasses import dataclass


@dataclass
class SectionInfo:
	name: str
	virtual_address: str
	raw_size: int
	virtual_size: int
	entropy: float
	characteristics: str 