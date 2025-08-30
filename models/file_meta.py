from __future__ import annotations
from dataclasses import dataclass
from typing import Optional
from .pe_header_info import PEHeaderInfo

@dataclass
class FileMeta:
	path: str
	file_type: str  # "py" (python source) or "pe" (exe)
	sha256: str
	entropy: float
	pe_header: Optional[PEHeaderInfo] = None  # only for PE binaries 