from __future__ import annotations
import sys
from pathlib import Path
from typing import Optional, List, Dict
import pefile
from entropy.entropy import calculate_entropy
from models.pe_header_info import PEHeaderInfo, SectionInfo


def parse_pe_headers(file_path: Path) -> Optional[PEHeaderInfo]:
	"""Parse PE headers and return a dict with keys matching the PDF report format."""
	try:
		pe = pefile.PE(str(file_path))
		imports: Dict[str, List[str]] = (
			{
				(entry.dll.decode("utf-8") if entry.dll else "unknown"): [
					(imp.name.decode("utf-8") if imp.name else f"Ordinal_{imp.ordinal}")
					for imp in entry.imports
				]
				for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", [])
			}
		)
		exports: List[str] = (
			[
				(exp.name.decode("utf-8") if exp.name else f"Ordinal_{exp.ordinal}")
				for exp in getattr(getattr(pe, "DIRECTORY_ENTRY_EXPORT", None), "symbols", [])
			]
		)
		sections: List[SectionInfo] = [
			SectionInfo(
				name=section.Name.decode("utf-8").rstrip("\x00"),
				virtual_address=f"0x{section.VirtualAddress:x}",
				raw_size=section.SizeOfRawData,
				virtual_size=section.Misc_VirtualSize,
				entropy=(
					calculate_entropy(section.get_data())
					if section.get_data() else 0.0
				),
				characteristics=f"0x{section.Characteristics:x}",
			)
			for section in pe.sections
		]
		keys = [
			'Machine', 'Subsystem', 'Timestamp', 'Number of Sections', 'Entry Point', 'ImageBase',
			'Section Alignment', 'Size of Image', 'Size of Headers', 'Stack Reserve', 'Stack Commit',
			'Heap Reserve', 'Heap Commit', 'Relocation Info', 'ASLR', 'DEP', 'CFG', 'High Entropy VA',
			'SafeSEH', 'Force Integrity', 'AppContainer', 'Terminal Server Aware', 'Imports', 'Delay Imports',
			'Bound Imports', 'Exports', 'IAT', 'Version Info', 'Manifest', 'Icons', 'Certificate', 'Checksum',
			'CLR Header', 'Target Runtime', 'Strong Name', 'Debug Directory', 'Rich Header', 'Timestamp Consistency',
			'Security Cookie', 'SEH Table', 'CFG Flags', 'TLS Callbacks', 'Exception Directory', 'Section Names',
			'Section Characteristics', 'Section Entropy', 'Virtual vs Raw Size', 'Overlay Data', 'Invalid Timestamp',
			'Entry Point Outside .text', 'Suspicious Imports', 'Missing Sections', 'DLL Characteristics'
		]
		raw_dict = {
			'Machine': f"0x{pe.FILE_HEADER.Machine:x}",
			'Subsystem': getattr(pe.OPTIONAL_HEADER, 'Subsystem', None),
			'Timestamp': getattr(pe.FILE_HEADER, 'TimeDateStamp', None),
			'Number of Sections': getattr(pe.FILE_HEADER, 'NumberOfSections', None),
			'Entry Point': f"0x{getattr(pe.OPTIONAL_HEADER, 'AddressOfEntryPoint', 0):x}",
			'ImageBase': f"0x{getattr(pe.OPTIONAL_HEADER, 'ImageBase', 0):x}",
			'Section Alignment': getattr(pe.OPTIONAL_HEADER, 'SectionAlignment', None),
			'Size of Image': getattr(pe.OPTIONAL_HEADER, 'SizeOfImage', None),
			'Size of Headers': getattr(pe.OPTIONAL_HEADER, 'SizeOfHeaders', None),
			'Stack Reserve': getattr(pe.OPTIONAL_HEADER, 'SizeOfStackReserve', None),
			'Stack Commit': getattr(pe.OPTIONAL_HEADER, 'SizeOfStackCommit', None),
			'Heap Reserve': getattr(pe.OPTIONAL_HEADER, 'SizeOfHeapReserve', None),
			'Heap Commit': getattr(pe.OPTIONAL_HEADER, 'SizeOfHeapCommit', None),
			'Relocation Info': getattr(pe.OPTIONAL_HEADER, 'DataDirectory', [{}])[5] if hasattr(pe.OPTIONAL_HEADER, 'DataDirectory') and len(pe.OPTIONAL_HEADER.DataDirectory) > 5 else None,
			'ASLR': 'Enabled' if (getattr(pe.OPTIONAL_HEADER, 'DllCharacteristics', 0) & 0x40) else 'Disabled',
			'DEP': 'Enabled' if (getattr(pe.OPTIONAL_HEADER, 'DllCharacteristics', 0) & 0x100) else 'Disabled',
			'CFG': 'Enabled' if (getattr(pe.OPTIONAL_HEADER, 'DllCharacteristics', 0) & 0x4000) else 'Disabled',
			'High Entropy VA': 'Enabled' if (getattr(pe.OPTIONAL_HEADER, 'DllCharacteristics', 0) & 0x20) else 'Disabled',
			'Imports': imports,
			'Exports': exports,
			'Checksum': getattr(pe.OPTIONAL_HEADER, 'CheckSum', None),
			'Section Names': ', '.join([s.name for s in sections]) if sections else None,
			'Section Characteristics': ', '.join([s.characteristics for s in sections]) if sections else None,
			'Section Entropy': ', '.join([f"{s.entropy:.2f}" for s in sections]) if sections else None,
			'Virtual vs Raw Size': ', '.join([f"{s.virtual_size}/{s.raw_size}" for s in sections]) if sections else None,
			'DLL Characteristics': f"0x{getattr(pe.OPTIONAL_HEADER, 'DllCharacteristics', 0):x}",
		}
		pe_dict = {k: (raw_dict[k] if k in raw_dict and raw_dict[k] is not None else 'N/A') for k in keys}
		return pe_dict
	except Exception as e:
		print(f"[PEHeader] Error parsing {file_path}: {e}", file=sys.stderr)
		return None