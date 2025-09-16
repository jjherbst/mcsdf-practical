# ...existing code...
from pathlib import Path
import argparse

def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Static (.py, .pyc, .exe and upx packed .exe) analysis with YARA."
    )
    # Mode selection
    parser.add_argument("--mode", dest="mode", type=int, choices=[1, 2], 
                       help="Analysis mode: \n\t[1] Custom Static Analysis, \n\t[2] Custom Analysis with VirusTotal")
    
    # File arguments
    parser.add_argument("--source", dest="source", type=Path, help="Python source code file (.py)")
    parser.add_argument("--exe", dest="exe", type=Path, help="Executable (.exe) (PyInstaller/UPX)")
    parser.add_argument("--pdf", dest="pdf", type=Path, default="malware_analysis.pdf", help="PDF report name that contains analysis.")
    parser.add_argument("--csv", dest="csv", type=Path, default="malware_analysis.csv", help="CSV report name that contains analysis.")
    
    # Directory arguments
    parser.add_argument("--input", dest="input", type=Path, default=Path('./dist/input'), help="Input directory")
    parser.add_argument("--output", dest="output", type=Path, default=Path('./dist/output'), help="Output directory")
    parser.add_argument("--working", dest="working", type=Path, default=Path('./dist/working'), help="Working directory")
    
    # YARA rules
    parser.add_argument("--yara_rules", dest="yara_rules", type=Path, default=Path('./yara_detector/yara_rules.yar'), help="Path to YARA rules file", required=False)
    
    # VirusTotal specific arguments
    parser.add_argument("--vt_api_key", dest="vt_api_key", type=str, default="3e661563ec1b91a40086b3506645fd6af544eecf25fe59027dd5940e20", help="VirusTotal API key")
    parser.add_argument("--scan_directory", dest="scan_directory", type=Path, default=Path('./dist/input'), help="Directory to scan for VirusTotal upload")
    
    return parser
