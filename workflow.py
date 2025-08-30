#!/usr/bin/env python3
from __future__ import annotations

from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Dict, Any
from virus_total.upload_exe import scan_and_upload_exe_files
from virus_total.pdf_report import create_vt_pdf_report
from entropy.entropy import calculate_entropy as calculate_shannon_entropy
from packer.packer import is_exe_packed, unpack_upx, decompile_exe_to_pyc    
from pe_header.pe_headers import parse_pe_headers         
from utilities import report
from yara_detector.yara_scanner import compile_rules, scan_yara_file
from hash.hash import calculate_sha256         
from typing import Optional

# Import utility functions
from utilities.command_line_arguments import parse_arguments
from reports.report import generate_pdf_report

def resolve_rule_path(candidate: Path | None) -> tuple[Path | None, str | None, list[str]]:
    """Attempt to resolve a possibly wrong relative YARA rule path.
    Returns (resolved_path_or_None, note_if_adjusted, attempted_paths)."""
    attempts: list[str] = []
    if candidate is None:
        return None, None, attempts
    if candidate.is_file():
        return candidate, None, [str(candidate)]
    # Try common subdirectories relative to CWD and script location
    base = Path.cwd()
    script_dir = Path(__file__).parent
    guess_objs = [
        base / candidate,
        base / "yara_detector" / candidate.name,
        base / "yara" / candidate.name,
        script_dir / candidate.name,
        script_dir / "yara_detector" / candidate.name,
    ]
    for g in guess_objs:
        attempts.append(str(g))
        if g.is_file():
            return g, f"auto-resolved from {candidate} -> {g}", attempts
    # Fallback: if original exists (maybe directory), return None for file
    note = "original path invalid and no alternative found"
    return None, note, attempts

def read_all_bytes(path: Path) -> bytes:
    """Read entire file into memory as bytes."""
    return Path(path).read_bytes()

def run_source_workflow(source: Path, input_path: Path, yara_rules_path: Path) -> Dict[str, Any]:
    report: Dict[str, Any] = {}
    report.update(yara_scan(input_path / source, yara_rules_path, "PY"))
    return report

def run_exe_workflow(exe: Path, input_dir: Path, working_dir: Path, output_dir: Path, yara_rules_path: Path) -> Dict[str, Any]:
    report: Dict[str, Any] = {}
    
    exe_path = input_dir / exe
    report.update(retrieve_file_metadata(exe_path))
    
    file_bytes = read_all_bytes(exe_path)
    
    report.update(calculate_sha256_hash(file_bytes))
    report.update(calculate_entropy(file_bytes))
    
    if is_exe_packed(file_bytes) == "UPX":
        # yara scan on upx packed and pyinstaller compiled binary
        report.update(yara_scan(exe_path, yara_rules_path, "PACKED"))
        # unpack binary to convert to pyinstaller binary
        report.update(unpack_upx(exe_path, working_dir))
        exe_path = report["unpacked_path"]
        
    # extract the pe header from a pyinstaller binary (.exe)
    report.update(extract_pe_header_from_exe(exe_path))#Path(report["Absolute Path"])))
    report.update(yara_scan(exe_path, yara_rules_path, "EXE"))
    
    # deconstruct a .exe inty .pyc file(s)
    pyc_path = deconstruct_exe_to_pyc(exe_path)
    # yara report on .pyc files
    report.update(yara_scan(pyc_path, yara_rules_path, "PYC"))
    
    # decompile .pyc files into .py source files
    py_path = decompile_pyc_to_py(pyc_path)
    if py_path is not None:
        # yara on python source files
        report.update(yara_scan(py_path, yara_rules_path, "DPYC"))
        
    return report

def extract_file_size(num: int) -> str:
    for unit in ["B", "KiB", "MiB", "GiB", "TiB"]:
        if num < 1024 or unit == "TiB":
            return f"{num:.2f} {unit}" if unit != "B" else f"{num} {unit}"
        num /= 1024
    return f"{num} B"

def retrieve_file_metadata(target_path: Path) -> Dict[str, Any]:
    try:
        st = target_path.stat()
    except Exception as e:
        return {"path": str(target_path), "final_scan_target": str(target_path), "stat_error": str(e)}
    size_bytes = st.st_size
    def iso(ts: float) -> str:
        try:
            return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()
        except Exception:
            return ""
    return {
        "Path": str(target_path),
        "Name": target_path.name,
        "Stem": target_path.stem,
        "Extension": target_path.suffix.lower(),
        "Parent Directory": str(target_path.parent),
        "Size": extract_file_size(size_bytes),
        "Modified Time": iso(st.st_mtime),
        "Created Time": iso(st.st_ctime),
        "Accessed Time": iso(st.st_atime),
        "Mode": oct(st.st_mode),
        "Symbolic Link": target_path.is_symlink(),
        "Absolute Path": str(target_path.resolve())
    }

def calculate_sha256_hash(file_bytes: bytes) -> Dict[str, Any]:
    return {"SHA-256": calculate_sha256(file_bytes)}

def calculate_entropy(file_bytes: bytes) -> Dict[str, Any]:
    return {"Entropy": calculate_shannon_entropy(file_bytes)}

def yara_scan(target: Path | str, rules_path: Path, category: str) -> Dict[str, Any]:
    """ run a YARA scan on a single target file. """
    result: Dict[str, Any] = {}
    rules, rule_status = load_yara_rules(rules_path)
    if isinstance(target, str):
        target = Path(target)
          
    matches = []
    if rules and target.is_file():
        matches = scan_yara_file(target, rules)
    result[f"YARA {category}"] = {
        "Findings": matches,
        "Status": rule_status.lower(),
        "Match Count": len(matches),
        "Rules": str(rules_path) if rules_path else "not provided",
        "Reason": (
            f"Rules Status: {rule_status}; Path={rules_path}"
            if not matches and rule_status.lower() != "ok"
            else ""
        ),
    }
    return result

def extract_pe_header_values(working_path: Path) -> Dict[str, Any]:
    try:
        pe_header = parse_pe_headers(working_path)
    except Exception as e:
        return {"PE Header Error": str(e), "PE Header": "not detected"}
    if pe_header is None:
        return {"PE Header": "not detected"}
    # pe_header is now a dict, so just return it
    return pe_header

def load_yara_rules(rule_path: Path | None):
    if rule_path and Path(rule_path).is_file():
        rules = compile_rules(rule_path)
        if rules is None:
            return None, "compile_failed"
        return rules, "ok"
    return None, "missing_rules_file"

def extract_pe_header_from_exe(exe_path: Path) -> Dict[str, Any]:
    """Wrapper to extract PE header information for a given executable path.
    Kept separate from extract_pe_header_values for clearer naming in workflow."""
    return extract_pe_header_values(exe_path)

def deconstruct_exe_to_pyc(exe_path: Path) -> Optional[Path]:
    try:
        return decompile_exe_to_pyc(Path(exe_path))
    except Exception as exception:
        print(f"Failed to deconstruct EXE to PYC (deconstruct_exe_to_pyc): {exception}")
        return None

def decompile_pyc_to_py(pyc_path: Optional[Path]) -> Optional[Path]:
    """Decompile a single .pyc file (specified directly by pyc_path) to .py using 'pycdc'.

    Expectations / Contract:
      - pyc_path must point to an existing .pyc file (NOT a directory)
      - On success returns the Path to the generated .py file
      - On failure returns None (and prints a diagnostic message)
    """
    if pyc_path is None:
        return None
    if not isinstance(pyc_path, Path):
        raise TypeError(f"pyc_path must be a Path, got {type(pyc_path)}")
#    if not pyc_path.exists():
#        print(f"PYC path does not exist: {pyc_path}")
#        return None
    if pyc_path.is_dir():
        print(f"Provided path is a directory, expected a single .pyc file: {pyc_path}")
        return None
    if pyc_path.suffix.lower() != '.pyc':
        print(f"Provided path is not a .pyc file: {pyc_path}")
        return None
    import subprocess
    out_py = pyc_path.with_suffix('.py')
    try:
        proc = subprocess.run(['pycdc', str(pyc_path)], capture_output=True, text=True, timeout=20)
    except FileNotFoundError:
        print("pycdc not found. Install with: pip install pycdc (or build from source).")
        return None
    except Exception as e:
        print(f"Error running pycdc on {pyc_path}: {e}")
        return None
    if proc.returncode != 0:
        err = (proc.stderr or '').strip()
        print(f"pycdc failed for {pyc_path}: {err}")
        return None
    try:
        with open(out_py, 'w', encoding='utf-8', errors='ignore') as fh:
            fh.write(proc.stdout)
        if out_py.stat().st_size == 0:
            out_py.unlink(missing_ok=True)
            print(f"Discarded empty decompile output for {pyc_path}")
            return None
    except Exception as e:
        print(f"Failed writing decompiled source for {pyc_path}: {e}")
        return None
    return out_py


# ───────────────────────────── CLI / Orchestration ─────────────────────────────
def main() -> None:
    args = parse_arguments()
    source = args.source if getattr(args, 'source', None) else Path('benign_malware.py')
    exe = args.exe if getattr(args, 'exe', None) else Path('benign_malware.exe')
    pdf = args.pdf if getattr(args, 'pdf', None) else Path('malware.pdf')
    input_dir = args.input if getattr(args, 'input', None) else Path('./dist/input')
    working_dir = args.working if getattr(args, 'working', None) else Path('./dist/working')
    output_dir = args.output if getattr(args, 'output', None) else Path('./dist/output')
    yara_rules = args.yara_rules if getattr(args, 'yara_rules', None) else Path('./yara_detector/yara_rules.yar')

    report: Dict[str, Any] = {}
    report.update(run_source_workflow(source, Path(input_dir), Path(yara_rules)))
    report.update(run_exe_workflow(exe, Path(input_dir), Path(working_dir), Path(output_dir), Path(yara_rules)))
    generate_pdf_report(report, output_dir / pdf)
    
def run_virustotal_workflow(scan_directory: str, api_key: str, pdf_output_path: str):
    """
    Scans a directory for .exe files, uploads them to VirusTotal, and generates a PDF report.
    """
    print(f"Scanning directory for .exe files: {scan_directory}")
    vt_results = scan_and_upload_exe_files(scan_directory, api_key)
    print(f"Scan and upload complete. Generating PDF report at: {pdf_output_path}")
    create_vt_pdf_report(vt_results, pdf_output_path)
    print("VirusTotal workflow complete.")
    
if __name__ == "__main__":
    #main()
    run_virustotal_workflow("./dist/rq1", "d663e661563ec1b91a40086b3506645fd6af544eecf25fe59027dd5940e20532", "./dist/output/vt_malware.pdf")