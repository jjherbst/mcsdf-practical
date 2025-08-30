# ...existing code...
from pathlib import Path
import argparse

def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Static (.py, .pyc, .exe and upx packed .exe) analysis with YARA."
    )
    parser.add_argument("--source", dest="source", type=Path, help="Python source code file (.py).")
    parser.add_argument("--exe", dest="exe", type=Path, help="Executable (.exe) (possibly PyInstaller/UPX)")
    parser.add_argument("--pdf", dest="pdf", type=Path, help="PDF report name.")
    parser.add_argument("--input", dest="input", type=Path, help="Input directory", required="Input directory.")
    parser.add_argument("--output", dest="output", type=Path, help="Output directory", required="Results directory.")
    parser.add_argument("--working", dest="working", type=Path, help="Working directory", required="Processing directory.")
    parser.add_argument("--yara_rules", dest="yara_rules", type=Path, help="Path to YARA rules file", required=False)
    return parser
