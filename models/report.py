from __future__ import annotations
from dataclasses import asdict, is_dataclass
from typing import Dict, List, Optional, Any
from pathlib import Path


class Report:
	def __init__(self):
		self._data: Dict[str, Any] = {}
	
	@staticmethod
	def _normalize(value: Any) -> Any:
		if is_dataclass(value):
			return asdict(value)
		if isinstance(value, Path):
			return str(value)
		if isinstance(value, (list, tuple)):
			result = []
			for item in value:
				if is_dataclass(item):
					result.append(asdict(item))
				elif isinstance(item, Path):
					result.append(str(item))
				else:
					result.append(item)
			return result
		if isinstance(value, dict):
			return {k: Report._normalize(v) for k, v in value.items()}
		return value
	
	def add(self, key_or_items: Any, value: Any = None) -> None:
		if value is None and isinstance(key_or_items, dict):
			for k, v in key_or_items.items():
				self._data[k] = Report._normalize(v)
			return
		self._data[str(key_or_items)] = Report._normalize(value)
	
	def add_list(self, key: str, values: List[Any]) -> None:
		self._data[key] = Report._normalize(values)
	
	def add_multiple(self, items: Dict[str, Any]) -> None:
		for k, v in items.items():
			self._data[k] = Report._normalize(v)
	
	def get(self, key: str, default: Any = None) -> Any:
		return self._data.get(key, default)
	
	def get_all(self) -> Dict[str, Any]:
		return self._data.copy()
	
	def has_key(self, key: str) -> bool:
		return key in self._data
	
	def __str__(self) -> str:
		return f"Report({len(self._data)} items)"
	
	def __repr__(self) -> str:
		return f"Report({self._data})" 