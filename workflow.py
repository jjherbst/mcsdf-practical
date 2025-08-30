#!/usr/bin/env python3
from __future__ import annotations

# ═══════════════════════════════════════════════════════════════════════════════
#                                   IMPORTS
# ═══════════════════════════════════════════════════════════════════════════════
#                                   IMPORTS
# ═══════════════════════════════════════════════════════════════════════════════
import subprocess

from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Dict, Any

# Import analysis modules
from virus_total.upload_exe import scan_and_upload_exe_files
from virus_total.pdf_report import create_vt_pdf_report
from entropy.entropy import calculate_entropy as calculate_shannon_entropy
from packer.packer import is_exe_packed, unpack_upx, decompile_exe_to_pyc    
from pe_header.pe_headers import parse_pe_headers         
from yara_detector.yara_scanner import compile_rules, scan_yara_file
from hash.hash import calculate_sha256         

# Import utility functions
from utilities.command_line_arguments import parse_arguments
from reports.report import generate_pdf_report


# ═══════════════════════════════════════════════════════════════════════════════
#                                UTILITY FUNCTIONS
# ═══════════════════════════════════════════════════════════════════════════════

def read_all_bytes(path: Path) -> bytes:
    """ read entire file into memory as bytes. """
    return Path(path).read_bytes()

def load_yara_rules(rule_path: Path | None):
    """Load and compile YARA rules from file."""
    if rule_path and Path(rule_path).is_file():
        rules = compile_rules(rule_path)
        if rules is None:
            return None, "compile_failed"
        return rules, "ok"
    return None, "missing_rules_file"

# ═══════════════════════════════════════════════════════════════════════════════
#                            FILE ANALYSIS FUNCTIONS
# ═══════════════════════════════════════════════════════════════════════════════
def extract_file_size(num: int) -> str:
    """ convert file size in bytes to human-readable format. """
    for unit in ["B", "KiB", "MiB", "GiB", "TiB"]:
        if num < 1024 or unit == "TiB":
            return f"{num:.2f} {unit}" if unit != "B" else f"{num} {unit}"
        num /= 1024
    return f"{num} B"

def extract_file_metadata(target_path: Path) -> Dict[str, Any]:
    """ extract comprehensive file metadata. """
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
    """ calculate SHA-256 hash of file bytes."""
    return {"SHA-256": calculate_sha256(file_bytes)}

def calculate_entropy(file_bytes: bytes) -> Dict[str, Any]:
    """ calculate Shannon entropy of file bytes. """
    return {"Entropy": calculate_shannon_entropy(file_bytes)}

def yara_scan(target: Path | str, rules_path: Path, category: str) -> Dict[str, Any]:
    """ run a YARA scan on a single target file. """
    result: Dict[str, Any] = {}
    rules, rule_status = load_yara_rules(rules_path)
    if isinstance(target, str):
        target = Path(target)
          
    matches = []
    if rules and target and target.is_file():
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

def extract_pe_header_from_exe(exe_path: Path) -> Dict[str, Any]:
    """ extract PE header information from executable. """
    try:
        pe_header = parse_pe_headers(exe_path)
    except Exception as e:
        return {"PE Header Error": str(e), "PE Header": "not detected"}
    if pe_header is None:
        return {"PE Header": "not detected"}
    # pe_header is now a dict, so just return it
    return pe_header

def deconstruct_exe_to_pyc(exe_path: Path) -> Optional[Path]:
    """ deconstruct executable to extract .pyc files. """
    try:
        return decompile_exe_to_pyc(Path(exe_path))
    except Exception as exception:
        print(f"Failed to deconstruct EXE to PYC (deconstruct_exe_to_pyc): {exception}")
        return None

def decompile_pyc_to_py(pyc_path: Optional[Path]) -> Optional[Path]:
    """ decompile a single .pyc file (specified directly by pyc_path) to .py using 'pycdc'. """
    if pyc_path is None:
        return None
        
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


# ═══════════════════════════════════════════════════════════════════════════════
#                            WORKFLOW ORCHESTRATION
# ═══════════════════════════════════════════════════════════════════════════════

def run_source_workflow(source_path: Path, input_path: Path, yara_rules_path: Path) -> Dict[str, Any]:
    """ run analysis workflow for Python source files only. """
    report: Dict[str, Any] = {}
    postfix = " "
    source_metadata = extract_file_metadata(source_path)
    for key, value in source_metadata.items():
        report[f"{key}{postfix}"] = value
    
    file_bytes = read_all_bytes(source_path)
    source_hash = calculate_sha256_hash(file_bytes)
    for key, value in source_hash.items():
        report[f"{key}{postfix}"] = value
    
    source_entropy = calculate_entropy(file_bytes)
    for key, value in source_entropy.items():
        report[f"{key}{postfix}"] = value
    
    report.update(yara_scan(source_path, yara_rules_path, "PY"))
    return report

def run_exe_workflow(exe_path: Path, input_dir: Path, working_dir: Path, output_dir: Path, yara_rules_path: Path) -> Dict[str, Any]:
    """ run comprehensive analysis workflow for executable files. """
    report: Dict[str, Any] = {}
    report.update(extract_file_metadata(exe_path))
    
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
    if pyc_path:
        report.update(yara_scan(pyc_path, yara_rules_path, "PYC"))
        
        # decompile .pyc files into .py source files
        py_path = decompile_pyc_to_py(pyc_path)
        if py_path is not None:
            # yara on python source files
            report.update(yara_scan(py_path, yara_rules_path, "DPYC"))
    else:
        report["YARA PYC"] = {"Status": "failed", "Reason": "Could not extract PYC files from executable"}
        report["YARA DPYC"] = {"Status": "failed", "Reason": "Could not extract PYC files from executable"}
        
    return report

def run_virustotal_workflow(scan_directory: str, api_key: str, pdf_output_path: str):
    """ scans a directory for .exe files, uploads them to VirusTotal, and generates a PDF report. """
    print(f"Scanning directory for .exe files: {scan_directory}")
    vt_results = scan_and_upload_exe_files(scan_directory, api_key)
    print(f"Scan and upload complete. Generating PDF report at: {pdf_output_path}")
    create_vt_pdf_report(vt_results, pdf_output_path)
    print("VirusTotal workflow complete.")


# ═══════════════════════════════════════════════════════════════════════════════
#                            HIGH-LEVEL WORKFLOW RUNNERS
# ═══════════════════════════════════════════════════════════════════════════════

def run_source_only_workflow(args):
    """Run static analysis on Python source file only."""
    source = args.source or Path('benign_malware.py')
    input_dir = args.input or Path('./dist/input')
    output_dir = args.output or Path('./dist/output')
    yara_rules = args.yara_rules or Path('./yara_detector/yara_rules.yar')
    pdf = args.pdf or Path('source_analysis.pdf')
    
    # If source is just a filename, look for it in input_dir
    if not source.is_absolute() and not source.parent.name:
        source_path = input_dir / source
    else:
        source_path = source
    
    print(f"Running source-only analysis on: {source.name}")
    
    report: Dict[str, Any] = {}
    report.update(run_source_workflow(source_path, input_dir, yara_rules))
    generate_pdf_report(report, output_dir / pdf)
    
    print(f"Source analysis complete. Report saved to: {output_dir / pdf}")

def run_full_static_workflow(args):
    """Run full static analysis (source + binary)."""
    source = args.source or Path('benign_malware.py')
    exe = args.exe or Path('benign_malware.exe')
    pdf = args.pdf or Path('full_analysis.pdf')
    input_dir = args.input or Path('./dist/input')
    working_dir = args.working or Path('./dist/working')
    output_dir = args.output or Path('./dist/output')
    yara_rules = args.yara_rules or Path('./yara_detector/yara_rules.yar')

    # If source/exe are just filenames, look for them in input_dir
    if not source.is_absolute() and not source.parent.name:
        source_path = input_dir / source
    else:
        source_path = source
        
    if not exe.is_absolute() and not exe.parent.name:
        exe_path = input_dir / exe
    else:
        exe_path = exe

    print(f"Running full static analysis on: {source.name} and {exe.name}")
    
    report: Dict[str, Any] = {}
    report.update(run_source_workflow(source_path, input_dir, yara_rules))
    report.update(run_exe_workflow(exe_path, input_dir, working_dir, output_dir, yara_rules))
    generate_pdf_report(report, output_dir / pdf)
    
    print(f"Full static analysis complete. Report saved to: {output_dir / pdf}")

def run_virustotal_analysis(args):
    """ run VirusTotal analysis workflow. """
    scan_directory = args.scan_directory or "./dist/rq1"
    api_key = args.vt_api_key or "d663e661563ec1b91a40086b3506645fd6af544eecf25fe59027dd5940e20532"
    output_dir = args.output or Path('./dist/output')
    pdf_output = output_dir / (args.pdf or Path('virustotal_analysis.pdf'))
    
    print(f"Running VirusTotal analysis on directory: {scan_directory}")
    run_virustotal_workflow(scan_directory, api_key, str(pdf_output))


# ═══════════════════════════════════════════════════════════════════════════════
#                            USER INTERFACE & MENU SYSTEM
# ═══════════════════════════════════════════════════════════════════════════════

def display_menu():
    """Display the analysis menu options."""
    print("\n" + "="*60)
    print("MALWARE ANALYSIS WORKFLOW")
    print("="*60)
    print("1. Static Analysis - Python Source File Only")
    print("2. Static Analysis - Python Source + Binary (.exe)")
    print("3. VirusTotal Analysis - Scan and Upload")
    print("="*60)

def get_user_choice():
    """Get user's menu choice."""
    while True:
        try:
            choice = int(input("Select analysis mode (1-3): "))
            if choice in [1, 2, 3]:
                return choice
            else:
                print("Please enter 1, 2, or 3")
        except ValueError:
            print("Please enter a valid number")


# ═══════════════════════════════════════════════════════════════════════════════
#                            MAIN ENTRY POINT
# ═══════════════════════════════════════════════════════════════════════════════

def main() -> None:
    """Main entry point for the malware analysis workflow."""
    try:
        args = parse_arguments().parse_args()
    except SystemExit:
        # If argument parsing fails, go to interactive mode with defaults
        args = parse_arguments().parse_args([])
    
    # If source is provided and pdf is default, update pdf name based on source
    if args.source and args.pdf == Path("default_report.pdf"):
        args.pdf = f"{Path(args.source).stem}.pdf"
    
    # If mode is specified via command line, use it directly
    if hasattr(args, 'mode') and args.mode:
        mode = args.mode
    else:
        # Interactive mode - show menu
        display_menu()
        mode = get_user_choice()
    
    # Execute based on selected mode
    if mode == 1:
        run_source_only_workflow(args)
    elif mode == 2:
        run_full_static_workflow(args)
    elif mode == 3:
        run_virustotal_analysis(args)
    else:
        print("Invalid mode selected")
        return

if __name__ == "__main__":
    main()
