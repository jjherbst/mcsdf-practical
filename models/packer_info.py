from __future__ import annotations
from dataclasses import dataclass
from typing import List, Optional


@dataclass
class PackerInfo:
	packed: bool
	type: Optional[str]  # "upx" | "pyinstaller --onefile" | None
	evidence: List[str] 