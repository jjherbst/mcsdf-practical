from __future__ import annotations
from pathlib import Path
from typing import Union
from models.report import Report
from reports.pdf import create_pdf_report

def generate_pdf_report(report: Union[dict, Report, None], pdf_output_path: str) -> None:
	# Always emit PDF (now that we have a path)
	try:
		Path(pdf_output_path).parent.mkdir(parents=True, exist_ok=True)
		create_pdf_report(report, pdf_output_path)
	except Exception as e:
		print(f"[!] PDF generation failed: {e}")