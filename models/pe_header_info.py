from __future__ import annotations
from dataclasses import dataclass
from typing import Dict, List
from .section_info import SectionInfo

@dataclass
class PEHeaderInfo:
	machine: str
	timestamp: int
	number_of_sections: int
	entry_point: str
	image_base: str
	subsystem: int
	dll_characteristics: str
	imports: Dict[str, List[str]]
	exports: List[str]
	sections: List[SectionInfo] 