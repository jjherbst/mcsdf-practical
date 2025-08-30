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
				("detailed_submissions_count", "Detailed Submissions Count"),
				("submission_countries", "Submission Countries"),
				("submission_sources", "Submission Sources"),
				("known_names_count", "Known Names Count"),
				("all_known_names", "All Known Names"),
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
				("sandbox_reports_count", "Sandbox Reports Count"),
				("sandbox_environments", "Sandbox Environments"),
			],
			"File Relations": [
				("similar_files_count", "Similar Files Count"),
				("sample_similar_files", "Sample Similar Files"),
				("execution_parents_count", "Execution Parents Count"),
				("sample_execution_parents", "Sample Execution Parents"),
				("execution_children_count", "Execution Children Count"),
				("sample_execution_children", "Sample Execution Children"),
				("downloaders_count", "Downloaders Count"),
				("sample_downloaders", "Sample Downloaders"),
				("dropped_files_count", "Dropped Files Count"),
				("sample_dropped_files", "Sample Dropped Files"),
				("has_bundle_info", "Has Bundle Info"),
				("bundle_type", "Bundle Type"),
			],
			"Advanced Analysis": [
				("yara_rules_count", "YARA Rules Count"),
				("sample_yara_rules", "Sample YARA Rules"),
				("sigma_rules_count", "Sigma Rules Count"),
				("sample_sigma_rules", "Sample Sigma Rules"),
				("ids_rules_count", "IDS Rules Count"),
			],
			"File Structure Analysis": [
				("file_entropy", "Overall File Entropy"),
				("high_entropy_suspicious", "High Entropy Suspicious"),
				("pe_sections_count", "PE Sections Count"),
				("high_entropy_sections_count", "High Entropy Sections Count"),
				("high_entropy_sections", "High Entropy Sections"),
				("suspicious_sections_count", "Suspicious Sections Count"),
				("suspicious_sections", "Suspicious Sections"),
				("suspicious_imports_count", "Suspicious Imports Count"),
				("suspicious_imports", "Suspicious Imports"),
				("crypto_imports_count", "Cryptographic Imports Count"),
				("crypto_imports", "Cryptographic Imports"),
				("network_imports_count", "Network Imports Count"),
				("network_imports", "Network Imports"),
				("process_imports_count", "Process Manipulation Imports"),
				("process_imports", "Process Manipulation APIs"),
			],
			"String & Content Analysis": [
				("suspicious_string_count", "Suspicious String Count"),
				("suspicious_string_tags", "Suspicious String Tags"),
				("url_indicators", "URL Indicators"),
				("registry_indicators", "Registry Indicators"),
				("file_magic", "File Magic/Header"),
				("magic_suspicious", "Magic Header Suspicious"),
				("packer_type_tags_count", "Packer Type Tags Count"),
				("packer_type_tags", "Packer Type Tags"),
			],
			"Threat Intelligence": [
				("threat_categories_count", "Threat Categories Count"),
				("threat_categories", "Threat Categories"),
				("threat_collections_count", "Threat Collections Count"),
				("threat_collections", "Threat Collections"),
				("mitre_techniques_count", "MITRE Techniques Count"),
				("mitre_techniques", "MITRE ATT&CK Techniques"),
				("mitre_tactics_count", "MITRE Tactics Count"),
				("mitre_tactics", "MITRE ATT&CK Tactics"),
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
			],
			"Analysis Summary": [
				("threat_indicators_count", "Total Threat Indicators"),
				("threat_indicators_summary", "Threat Indicators Summary"),
				("detection_rate_percentage", "Detection Rate (%)"),
				("analysis_confidence", "Analysis Confidence"),
				("analysis_conclusion", "Analysis Conclusion"),
			]
		}
		
		for section_title, fields in sections.items():
			# Check if section has any meaningful data (be more inclusive)
			has_data = any(data.get(field[0]) not in [None, "", "N/A"] for field in fields)
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
				
				# Skip only truly empty values
				if value in [None, ""]:
					continue
					
				# Format value
				if isinstance(value, bool):
					value = "Yes" if value else "No"
				elif isinstance(value, (int, float)):
					# Show zero counts too - they're informative
					value = str(value)
				
				value_str = str(value)
				
				# Show "N/A" values too - they indicate what was checked
				if value_str == "N/A":
					value_str = "Not Available"
				
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
