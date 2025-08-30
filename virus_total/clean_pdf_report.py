from fpdf import FPDF
from datetime import datetime as dt
from pathlib import Path
import os


class VTReportPDF(FPDF):
	def add_cover_page(self, file_name: str, analysis_date: str):
		self.add_page()
		self.set_font("Arial", "B", 24)
		self.set_text_color(0, 0, 0)
		self.ln(30)
		self.cell(0, 15, "Malware", new_x="LMARGIN", new_y="NEXT", align="C")
		self.cell(0, 15, "VirusTotal Scan Report", new_x="LMARGIN", new_y="NEXT", align="C")
		self.ln(10)
		self.set_font("Arial", "", 14)
		self.set_text_color(60, 60, 60)
		self.cell(0, 10, "Automated VirusTotal Intelligence", new_x="LMARGIN", new_y="NEXT", align="C")
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

	def add_file_section(self, file_path: str, vt_data: dict):
		"""Add a section for a single file's VirusTotal analysis."""
		self.add_page()
		
		# File header
		file_name = os.path.basename(file_path)
		self.set_font("Arial", "B", 16)
		self.set_text_color(0, 0, 0)
		self.cell(0, 10, f"File Analysis: {file_name}", new_x="LMARGIN", new_y="NEXT", align="L")
		self.ln(5)
		
		# Risk level box
		risk_level = vt_data.get("risk_level", "UNKNOWN")
		risk_score = vt_data.get("risk_score", 0)
		
		# Set color based on risk level
		if risk_level == "HIGH":
			self.set_fill_color(255, 200, 200)  # Light red
		elif risk_level == "MEDIUM":
			self.set_fill_color(255, 255, 200)  # Light yellow
		else:
			self.set_fill_color(200, 255, 200)  # Light green
		
		self.set_font("Arial", "B", 12)
		self.cell(0, 8, f"Risk Level: {risk_level} (Score: {risk_score}/100)", 
				 new_x="LMARGIN", new_y="NEXT", align="C", fill=True)
		self.ln(10)
		
		# Create key-value pairs table
		self.add_key_value_table(vt_data)

	def add_key_value_table(self, data: dict):
		"""Add a formatted table of key-value pairs."""
		self.set_font("Arial", "", 9)
		
		# Define sections and their display order
		sections = {
			"File Information": [
				("file_name", "File Name"),
				("file_path", "File Path"),
				("file_hash_sha256", "SHA256 Hash"),
				("md5", "MD5 Hash"),
				("sha1", "SHA1 Hash"),
				("file_size_bytes", "File Size (bytes)"),
				("file_type", "File Type"),
				("file_extension", "File Extension"),
				("magic_description", "Magic Description"),
			],
			"Detection Results": [
				("detection_percentage", "Detection Percentage"),
				("malicious_count", "Malicious Detections"),
				("suspicious_count", "Suspicious Detections"),
				("undetected_count", "Undetected"),
				("harmless_count", "Harmless"),
				("total_engines", "Total Engines"),
				("malicious_detections", "Malicious Detection Details"),
				("suspicious_detections", "Suspicious Detection Details"),
			],
			"Submission History": [
				("first_submission_date", "First Submission"),
				("last_submission_date", "Last Submission"),
				("last_analysis_date", "Last Analysis"),
				("times_submitted", "Times Submitted"),
				("reputation", "Reputation Score"),
			],
			"Community Intelligence": [
				("community_malicious_votes", "Community Malicious Votes"),
				("community_harmless_votes", "Community Harmless Votes"),
				("total_community_votes", "Total Community Votes"),
				("comments_count", "Comments Count"),
				("latest_comment", "Latest Comment"),
				("latest_comment_author", "Latest Comment Author"),
			],
			"Network Behavior": [
				("contacted_urls_count", "Contacted URLs Count"),
				("sample_contacted_urls", "Sample Contacted URLs"),
				("contacted_domains_count", "Contacted Domains Count"), 
				("sample_contacted_domains", "Sample Contacted Domains"),
				("contacted_ips_count", "Contacted IPs Count"),
				("sample_contacted_ips", "Sample Contacted IPs"),
			],
			"Behavioral Analysis": [
				("has_behavior_report", "Has Behavior Report"),
				("behavior_has_html_report", "Has HTML Report"),
				("behavior_has_pcap", "Has PCAP"),
				("behavior_has_evtx", "Has EVTX"),
			],
			"File Relations": [
				("similar_files_count", "Similar Files Count"),
				("execution_parents_count", "Execution Parents Count"),
				("downloaders_count", "Downloaders Count"),
				("has_bundle_info", "Has Bundle Info"),
				("bundle_type", "Bundle Type"),
			],
			"PE Information": [
				("pe_machine", "PE Machine Type"),
				("pe_timestamp", "PE Timestamp"),
				("pe_entry_point", "PE Entry Point"),
				("pe_imphash", "PE Import Hash"),
				("pe_sections_count", "PE Sections Count"),
				("pe_imports_count", "PE Imports Count"),
			],
			"Security Features": [
				("detected_packers", "Detected Packers"),
				("vt_tags", "VirusTotal Tags"),
				("known_file_names", "Known File Names"),
			]
		}
		
		for section_title, fields in sections.items():
			# Check if section has any data
			has_data = any(data.get(field[0]) not in [None, "", "N/A", 0, "False", False] for field in fields)
			if not has_data:
				continue
				
			# Section header
			self.set_font("Arial", "B", 11)
			self.set_fill_color(230, 230, 230)
			self.cell(0, 8, section_title, new_x="LMARGIN", new_y="NEXT", align="L", fill=True)
			self.ln(2)
			
			# Table rows
			self.set_font("Arial", "", 9)
			for field_key, field_label in fields:
				value = data.get(field_key, "N/A")
				if value in [None, "", "N/A", "False", False]:
					continue
					
				# Format value
				if isinstance(value, bool):
					value = "Yes" if value else "No"
				elif isinstance(value, (int, float)) and field_key.endswith("_count"):
					if value == 0:
						continue
				
				value_str = str(value)
				
				# Truncate long values
				if len(value_str) > 80:
					value_str = value_str[:77] + "..."
				
				# Field name (left column)
				self.set_font("Arial", "B", 9)
				self.cell(60, 6, field_label + ":", border=1, align="L")
				
				# Field value (right column)
				self.set_font("Arial", "", 9)
				self.cell(120, 6, value_str, border=1, new_x="LMARGIN", new_y="NEXT", align="L")
			
			self.ln(5)


def create_vt_pdf_report(vt_results: dict, output_path: str):
	"""Create a comprehensive PDF report from VirusTotal results."""
	pdf = VTReportPDF()
	
	# Cover page
	file_names = [os.path.basename(path) for path in vt_results.keys()]
	cover_name = f"{len(file_names)} Files Analyzed" if len(file_names) > 1 else file_names[0]
	analysis_date = dt.now().strftime("%Y-%m-%d %H:%M:%S")
	pdf.add_cover_page(cover_name, analysis_date)
	
	# Add each file
	for file_path, vt_data in vt_results.items():
		if "error" in vt_data:
			# Error page
			pdf.add_page()
			pdf.set_font("Arial", "B", 16)
			pdf.cell(0, 10, f"Error analyzing: {os.path.basename(file_path)}", 
					new_x="LMARGIN", new_y="NEXT", align="L")
			pdf.ln(5)
			pdf.set_font("Arial", "", 12)
			pdf.cell(0, 8, f"Error: {vt_data['error']}", new_x="LMARGIN", new_y="NEXT", align="L")
		else:
			pdf.add_file_section(file_path, vt_data)
	
	# Save
	pdf.output(output_path)
	print(f"VirusTotal report saved to: {output_path}")
	return output_path
