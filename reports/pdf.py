from fpdf import FPDF
from typing import Dict, Any
from datetime import datetime as dt
from pathlib import Path

class malware_analysis_report(FPDF):
    def add_cover_page(self, file_name: str, analysis_date: str):
        self.add_page()
        self.set_font("Arial", "B", 24)
        self.set_text_color(0, 0, 0)
        self.ln(30)
        self.cell(0, 15, "Malware", new_x="LMARGIN", new_y="NEXT", align="C")
        self.cell(0, 15, "Analysis & Detection Report", new_x="LMARGIN", new_y="NEXT", align="C")
        self.ln(10)
        self.set_font("Arial", "", 14)
        self.set_text_color(60, 60, 60)
        self.cell(0, 10, "Custom Static Analysis & VirusTotal Intelligence", new_x="LMARGIN", new_y="NEXT", align="C")
        self.ln(20)
        self.set_font("Arial", "B", 12)
        self.set_text_color(0, 0, 0)
        self.cell(0, 8, "Analyzed Sample:", new_x="LMARGIN", new_y="NEXT", align="C")
        self.set_font("Arial", "", 12)
        self.cell(0, 8, file_name, new_x="LMARGIN", new_y="NEXT", align="C")
        self.ln(5)
        self.set_font("Arial", "B", 12)
        self.cell(0, 8, f"Analysis Date: {analysis_date}", new_x="LMARGIN", new_y="NEXT", align="C")
        self.ln(30)
        self.set_font("Arial", "B", 14)
        self.set_text_color(0, 0, 0)
        self.cell(0, 10, "Juan Herbst (13840146)", new_x="LMARGIN", new_y="NEXT", align="C")
        self.ln(10)
        self.set_font("Arial", "", 12)
        self.cell(0, 9, "Auckland University of Technology", new_x="LMARGIN", new_y="NEXT", align="C")
        self.ln(10)
        self.set_font("Arial", "", 12)
        self.cell(0, 8, "COMP997", new_x="LMARGIN", new_y="NEXT", align="C")
        self.cell(0, 8, "Master of Cyber Security and Digital Forensics", new_x="LMARGIN", new_y="NEXT", align="C")
        self.ln(30)
        self.set_font("Arial", "", 10)
        self.set_text_color(80, 80, 80)
        disclaimer_text = ("This report is generated for academic research purposes as part of the Master of Cyber Security and Digital Forensics "
                          "program. The analysis combines automated static analysis techniques with VirusTotal intelligence.")
        self.multi_cell(0, 6, disclaimer_text, align="C")
        self.set_text_color(0, 0, 0)
        
    def section_title(self, title, subtitle=None):
        self.ln(4)
        self.set_font("Arial", "B", 13)
        self.set_text_color(22, 37, 91)
        self.cell(0, 9, title, new_x="LMARGIN", new_y="NEXT")
        if subtitle:
            self.set_font("Arial", "", 10)
            self.set_text_color(95, 120, 160)
            self.cell(0, 7, subtitle, new_x="LMARGIN", new_y="NEXT")
        self.set_text_color(0, 0, 0)
        self.set_font("Arial", "", 10)

    def draw_table(self, report):
        self.set_text_color(0, 0, 0)
        self.set_font("Arial", "", 10)
        for key, value in report.items():
            self.set_font("Arial", "B", 10)
            self.set_text_color(50, 50, 50)
            self.cell(40, 7, f"{key}:", border=0)
            self.set_font("Arial", "", 10)
            self.set_text_color(0, 0, 0)
            value_str = str(value)
            if len(value_str) > 40 or '\n' in value_str:
                self.multi_cell(0, 7, value_str, new_x="LMARGIN", new_y="NEXT")
            else:
                self.cell(0, 7, value_str, new_x="LMARGIN", new_y="NEXT")
        self.set_font("Arial", "", 10)
        self.set_text_color(0, 0, 0)
        self.ln(2)

    def highlight_text(self, text, color=(240, 247, 255)):
        self.set_fill_color(*color)
        self.set_font("Arial", "I", 10)
        self.multi_cell(0, 7, text, fill=True)
        self.set_font("Arial", "", 10)
        self.set_text_color(0, 0, 0)
        self.ln(2)

    def section_file_metadata(self, report: Dict[str, Any]):
        self.section_title("File Metadata")
        if report:
            self.draw_table(report)
        else:
            self.highlight_text('No metadata available')

    def section_pe_header(self, report: Dict[str, Any]):
        self.section_title('PE Header Analysis')
        peh = report.get('pe_header') or report or {}
        self.set_draw_color(200, 200, 200)
        self.set_font('Arial','B',8)
        self.set_text_color(22,37,91)
        row_height = 8
        col1, col2, col3, col4 = 30, 40, 70, 40
        # Table header
        self.cell(col1,row_height,'Category',1,align='C')
        self.cell(col2,row_height,'Field',1,align='C')
        self.cell(col3,row_height,'Value',1,align='C')
        self.cell(col4,row_height,'Details',1,align='C',new_x='LMARGIN', new_y='NEXT')
        self.set_font('Arial','',8)
        self.set_text_color(0,0,0)
        def show_row(cat, field, value, details=''):
                val = value if value not in [None, '', [], {}] else 'N/A'
                if val == 'N/A':
                    return  # Skip rows with N/A value
                max_len = 40
                def trunc(s):
                    s = str(s)
                    return s if len(s) <= max_len else s[:max_len-3] + '...'
                # If value is a list, print each item in a separate row
                if isinstance(val, list):
                    for item in val:
                        self.cell(col1, row_height, cat, 1)
                        self.cell(col2, row_height, field, 1)
                        self.cell(col3, row_height, trunc(item), 1)
                        self.cell(col4, row_height, trunc(details), 1, new_x='LMARGIN', new_y='NEXT')
                    return
                # If value is a dict, print each key-value pair in a separate row
                if isinstance(val, dict):
                    for k, v in val.items():
                        self.cell(col1, row_height, cat, 1)
                        self.cell(col2, row_height, field, 1)
                        self.cell(col3, row_height, trunc(f'{k}: {v}'), 1)
                        self.cell(col4, row_height, trunc(details), 1, new_x='LMARGIN', new_y='NEXT')
                    return
                value_str = trunc(val)
                details_str = trunc(details)
                self.cell(col1, row_height, cat, 1)
                self.cell(col2, row_height, field, 1)
                self.cell(col3, row_height, value_str, 1)
                self.cell(col4, row_height, details_str, 1, new_x='LMARGIN', new_y='NEXT')
    # Identity & platform
        show_row('Identity','Machine Type',peh.get('Machine'),'x86/x64/ARM')
        show_row('Identity','Subsystem',peh.get('Subsystem'),'Console/GUI/Driver')
        show_row('Identity','PE Timestamp',peh.get('Timestamp'),'COFF TimeDateStamp')
        show_row('Identity','Number of Sections',peh.get('Number of Sections'),'')
        # Execution & memory layout
        show_row('Execution','Entry Point',peh.get('Entry Point'),'Execution start')
        show_row('Execution','ImageBase',peh.get('ImageBase'),'')
        show_row('Execution','Section Alignment',peh.get('Section Alignment',''),'File/Section')
        show_row('Execution','Size of Image',peh.get('Size of Image',''),'')
        show_row('Execution','Size of Headers',peh.get('Size of Headers',''),'')
        show_row('Execution','Stack Reserve',peh.get('Stack Reserve',''),'')
        show_row('Execution','Stack Commit',peh.get('Stack Commit',''),'')
        show_row('Execution','Heap Reserve',peh.get('Heap Reserve',''),'')
        show_row('Execution','Heap Commit',peh.get('Heap Commit',''),'')
        show_row('Execution','Relocation Info',peh.get('Relocation Info',''),'ASLR support')
        # Security hardening flags
        show_row('Security','ASLR',peh.get('ASLR',''),'DYNAMIC_BASE')
        show_row('Security','DEP / NX',peh.get('DEP',''),'NX_COMPAT')
        show_row('Security','Control Flow Guard',peh.get('CFG',''),'GUARD_CF')
        show_row('Security','High Entropy VA',peh.get('High Entropy VA',''),'x64 ASLR')
        show_row('Security','SafeSEH',peh.get('SafeSEH',''),'No SEH support')
        show_row('Security','Force Integrity',peh.get('Force Integrity',''),'')
        show_row('Security','AppContainer',peh.get('AppContainer',''),'')
        show_row('Security','Terminal Server Aware',peh.get('Terminal Server Aware',''),'')
        # Imports & exports
        show_row('Imports','Import Table',peh.get('Imports',''),'DLLs/APIs')
        show_row('Imports','Delay-load Imports',peh.get('Delay Imports',''),'')
        show_row('Imports','Bound Imports',peh.get('Bound Imports',''),'')
        show_row('Exports','Export Table',peh.get('Exports',''),'Functions provided')
        show_row('Imports','IAT Details',peh.get('IAT',''),'Import Address Table')
        # Resources & versioning
        show_row('Resources','Version Info',peh.get('Version Info',''),'Company/Product/Description')
        show_row('Resources','Manifest',peh.get('Manifest',''),'UAC/DPI/Virtualization')
        show_row('Resources','Icons/Strings',peh.get('Icons',''),'Localized resources')
        # Integrity & trust
        show_row('Integrity','Certificate Table',peh.get('Certificate',''),'Authenticode')
        show_row('Integrity','Checksum',peh.get('Checksum',''),'')
        # .NET / CLR specifics
        show_row('.NET','CLR Header',peh.get('CLR Header',''),'Managed code')
        show_row('.NET','Target Runtime',peh.get('Target Runtime',''),'')
        show_row('.NET','Strong Name',peh.get('Strong Name',''),'IL only')
        # Debug & build metadata
        show_row('Debug','Debug Directory',peh.get('Debug Directory',''),'PDB path/GUID/Age')
        show_row('Debug','Rich Header',peh.get('Rich Header',''),'Compiler/Linker')
        show_row('Debug','Timestamp Consistency',peh.get('Timestamp Consistency',''),'Headers/Debug/Resources')
        # Load Config / advanced structures
        show_row('Load Config','Security Cookie',peh.get('Security Cookie',''),'')
        show_row('Load Config','SEH Table',peh.get('SEH Table',''),'')
        show_row('Load Config','CFG/Exception Flags',peh.get('CFG Flags',''),'')
        show_row('Load Config','TLS Callbacks',peh.get('TLS Callbacks',''),'Pre-main code')
        show_row('Load Config','Exception Directory',peh.get('Exception Directory',''),'x64 unwind info')
        # Packing / obfuscation indicators
        show_row('Packing','Section Names',peh.get('Section Names',''),'.UPX/.aspack')
        show_row('Packing','Section Characteristics',peh.get('Section Characteristics',''),'Exec/Writable/RWX')
        show_row('Packing','Section Entropy',peh.get('Section Entropy',''),'High=packed/encrypted')
        show_row('Packing','Virtual vs Raw Size',peh.get('Virtual vs Raw Size',''),'')
        show_row('Packing','Overlay Data',peh.get('Overlay Data',''),'Appended after last section')
        # Anomalies / heuristics
        show_row('Anomaly','Invalid/Future Timestamp',peh.get('Invalid Timestamp',''),'')
        show_row('Anomaly','Entry Point Outside .text',peh.get('Entry Point Outside .text',''),'')
        show_row('Anomaly','Suspicious Imports',peh.get('Suspicious Imports',''),'NTDLL/Crypto/Networking')
        show_row('Anomaly','Missing/Strange Sections',peh.get('Missing Sections',''),'Alignment values')

    def section_yara(self, findings, title):
        self.section_title(title)
        self.set_draw_color(200, 200, 200)  # Light gray border
        self.set_font('Arial','B',8)
        self.set_text_color(22,37,91)
        row_height = 8
        self.cell(50,row_height,'Rule Matched',1,align='C')
        self.cell(40,row_height,'Filename',1,align='C')
        self.cell(20,row_height,'Matches',1,align='C')
        self.cell(20,row_height,'Offset',1,align='C')
        self.cell(70,row_height,'Meta',1,align='C',new_x='LMARGIN', new_y='NEXT')
        self.set_font('Arial','',8)
        self.set_text_color(0,0,0)
        if not findings:
            self.highlight_text('No findings. No YARA results found.')
            return
        # Group findings by rule name and filename
        grouped = {}
        for f in findings:
            rule = str(f.get('rule',''))[:48] or '\u00A0'
            filename = str(f.get('filename', f.get('file', '')))[:38] or '\u00A0'
            grouped.setdefault((rule, filename), []).append(f)
        for (rule, filename), rule_findings in grouped.items():
            first = True
            for f in rule_findings:
                meta_items = [(k, v) for k, v in f.get('meta',{}).items() if k not in ['category', 'author', 'purpose']]
                meta = ', '.join([f"{k}: {v}" for k, v in meta_items])[:68] or '\u00A0'
                strings = f.get('strings',[])
                offsets = f.get('offsets',[])
                self.set_draw_color(200, 200, 200)
                first_string = ''
                first_offset = ''
                if strings:
                    s = str(strings[0]).strip().replace('\n',' ').replace('\r',' ')
                    first_string = ''.join(c if 32 <= ord(c) <= 126 else '?' for c in s)
                    if offsets:
                        first_offset = str(offsets[0])
                meta_cell = first_string if first_string else meta
                self.cell(50,row_height,rule if first else '',1)
                self.cell(40,row_height,filename if first else '',1)
                self.cell(20,row_height,str(len(strings)),1)
                self.cell(20,row_height,first_offset,1)
                self.cell(70,row_height,meta_cell,1,new_x='LMARGIN', new_y='NEXT')
                first = False
                for idx, s in enumerate(strings[1:], start=1):
                    s = str(s).strip().replace('\n',' ').replace('\r',' ')
                    if not s:
                        continue
                    safe_s = ''.join(c if 32 <= ord(c) <= 126 else '?' for c in s)
                    offset_val = str(offsets[idx]) if idx < len(offsets) else ''
                    self.cell(50,row_height,'',1)
                    self.cell(40,row_height,'',1)
                    self.cell(20,row_height,'',1)
                    self.cell(20,row_height,offset_val,1)
                    self.cell(70,row_height,safe_s,1,new_x='LMARGIN', new_y='NEXT')

    def add_main_section_separator(self, title, subtitle=None):
        self.section_title(title, subtitle)
        self.ln(4)

    def add_simple_section_page(self, title: str, subtitle: str | None = None):
        self.add_page()
        line_color = (22, 37, 91)
        title_color = (22, 37, 91)
        subtitle_color = (95, 120, 160)
        left_x, right_x = 15, 195
        self.set_draw_color(*line_color)
        self.set_line_width(0.8)
        center_y = self.h / 2.0
        top_line_offset = -38  # distance from center to top line
        title_offset = -10      # distance from center to title baseline start
        subtitle_gap = 8
        bottom_line_offset = 40 # distance from center to bottom line
        y_top = max(25, center_y + top_line_offset)
        self.line(left_x, y_top, right_x, y_top)
        y_title = center_y + title_offset
        self.set_y(y_title)
        self.set_text_color(*title_color)
        self.set_font("Arial", "B", 22)
        self.cell(0, 16, title, align="C", new_x="LMARGIN", new_y="NEXT")
        if subtitle:
            self.set_font("Arial", "", 12)
            self.set_text_color(*subtitle_color)
            self.cell(0, 10, subtitle, align="C", new_x="LMARGIN", new_y="NEXT")
        current_y = self.get_y()
        y_bottom_candidate = center_y + bottom_line_offset
        y_bottom = min(self.h - 25, max(current_y + 6, y_bottom_candidate))
        self.set_draw_color(*line_color)
        self.line(left_x, y_bottom, right_x, y_bottom)
        self.set_text_color(0,0,0)
        self.set_font("Arial", "", 10)
        self.set_draw_color(0,0,0)
        self.set_line_width(0.2)

    def create_report(self, report: Dict[str, Any]):
        file_meta = report.get('file_metadata', {})
        pe_header = report.get('pe_header', {})
        sample_name = file_meta.get('file_name') or file_meta.get('path') or 'Sample'
        self.add_cover_page(str(sample_name), dt.utcnow().strftime('%Y-%m-%d %H:%M UTC'))
        self.add_simple_section_page("Static Analysis", "File & PE Characteristics")
        self.add_page()
        self.section_file_metadata(subset(report, "Path","Entropy"))
        self.add_page()
        self.section_pe_header(report)
        self.add_simple_section_page("YARA Analysis", "Unified YARA Rule Application")
        self.add_page()
        self.section_yara(report.get("YARA PY", {}).get("Findings", []), 'YARA Analysis of Original Python Source (.py).')
        self.add_page()
        self.section_yara(report.get("YARA PACKED", {}).get("Findings", []), 'YARA Analysis of UPX-Packed Executable (.exe).')
        self.add_page()
        self.section_yara(report.get("YARA EXE", {}).get("Findings", []), 'YARA Analysis of PyInstaller Executable (.exe).')
        self.add_page()
        self.section_yara(report.get("YARA PYC", {}).get("Findings", []), 'YARA Analysis of Python Bytecode (.pyc).')
        self.add_page()
        self.section_yara(report.get("YARA DPYC", {}).get("Findings", []), 'YARA Analysis of Decompiled Python Source (.py).')

def create_pdf_report(report: Dict[str, Any], output_path):
    try:
        pdf = malware_analysis_report()
        pdf.create_report(report)
        out = output_path
        pdf.output(str(out))
        print(f"PDF written to: {out}")
        try:
            size = Path(out).stat().st_size
            print(f"PDF file size: {size} bytes")
        except Exception as e:
            print(f"Could not get PDF file size: {e}")
        return out
    except Exception as e:
        print(f"Error generating PDF: {e}")
        raise

def subset(report, start_key, end_key):
    result = {}
    include = False
    for key, value in report.items():
        if key == start_key:
            include = True
        if include:
            result[key] = value
        if key == end_key:
            break
    return result