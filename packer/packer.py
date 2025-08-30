from __future__ import annotations
import subprocess
import sys
from pathlib import Path
from typing import Optional, Dict, Any

def is_exe_packed(data: bytes) -> str:
	if b"UPX!" in data or b"UPX0" in data or b"UPX1" in data:
		return "UPX"
	if b"PyInstaller" in data or b"pyi-windows-manifest-filename" in data:
		return "PyInstaller"
	return "None"

def unpack_upx(exe_path: Path, output_dir: Path) -> Dict[str, Any]:
	info: Dict[str, Any] = {
		"upx_unpack_status": "failed",
		"unpacked_path": "not_unpacked",
	}
	file_path = output_dir / exe_path.name
	cmd = ["upx", "-d", "-o", str(file_path), str(exe_path)]
	try:
		proc = subprocess.run(cmd, capture_output=True, text=True)
		if proc.returncode != 0:
			stderr = (proc.stderr or '').strip()
			info["upx_unpack_error"] = f"rc={proc.returncode} {stderr}" if stderr else f"rc={proc.returncode}"
			return info
		if file_path.is_file():
			info["upx_unpack_status"] = "ok"
			info["unpacked_path"] = str(file_path)
			info["packed"] = "UPX"
		else:
			info["upx_unpack_warning"] = "output_missing_after_success"
	except FileNotFoundError:
		info["upx_unpack_error"] = "upx_not_found_in_path"
	except Exception as e:  # pragma: no cover
		info["upx_unpack_error"] = f"unexpected: {e}"
	return info


def decompile_exe_to_pyc(path: Path) -> Optional[Path]:
	try:
		result = subprocess.run([
			sys.executable,
			"pyinstxtractor.py",
			str(path)
		], capture_output=True, text=True)
		if result.returncode == 0:
			return path.with_suffix(".pyc")
		else:
			# Optionally, log or return error output for debugging
			print(f"pyinstxtractor.py failed: {result.stderr}")
			return None
	except FileNotFoundError as exception:
		print(f"Failed to ecompile {path.__str__} in decompile_exe_to_pyc with exception {exception}")
		return None