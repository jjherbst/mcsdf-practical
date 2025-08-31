
import requests
import hashlib
import time
import os
from .scan_exe_directory import find_exe_files

def get_file_hash(file_path):
	"""Calculate SHA256 hash of file for VirusTotal lookup."""
	with open(file_path, 'rb') as f:
		return hashlib.sha256(f.read()).hexdigest()

def extract_basic_file_info(file_path, file_hash):
	"""Extract basic file information."""
	result = {
		"file_hash_sha256": file_hash,
		"file_path": file_path,
		"file_name": os.path.basename(file_path)
	}
	return result

def extract_file_data_from_vt(file_data):
	"""Extract comprehensive file information from VirusTotal file data."""
	result = {}
	
	# Basic file information
	result["md5"] = file_data.get("md5", "N/A")
	result["sha1"] = file_data.get("sha1", "N/A")
	result["file_size_bytes"] = file_data.get("size", "N/A")
	result["file_type"] = file_data.get("type_description", "N/A")
	result["file_extension"] = file_data.get("type_extension", "N/A")
	result["magic_description"] = file_data.get("magic", "N/A")
	result["first_submission_date"] = str(file_data.get("first_submission_date", "N/A"))
	result["last_submission_date"] = str(file_data.get("last_submission_date", "N/A"))
	result["last_analysis_date"] = str(file_data.get("last_analysis_date", "N/A"))
	result["times_submitted"] = file_data.get("times_submitted", 0)
	result["reputation"] = file_data.get("reputation", 0)
	
	# Detection statistics
	stats = file_data.get("last_analysis_stats", {})
	result["malicious_count"] = stats.get("malicious", 0)
	result["suspicious_count"] = stats.get("suspicious", 0)
	result["undetected_count"] = stats.get("undetected", 0)
	result["harmless_count"] = stats.get("harmless", 0)
	result["timeout_count"] = stats.get("timeout", 0)
	result["failure_count"] = stats.get("failure", 0)
	result["type_unsupported_count"] = stats.get("type-unsupported", 0)
	result["total_engines"] = sum(stats.values())
	
	# Calculate detection percentage
	if result["total_engines"] > 0:
		result["detection_percentage"] = round((result["malicious_count"] + result["suspicious_count"]) / result["total_engines"] * 100, 2)
	else:
		result["detection_percentage"] = 0
	
	# AV engine results - extract malicious and suspicious detections
	av_results = file_data.get("last_analysis_results", {})
	malicious_detections = []
	suspicious_detections = []
	for engine, details in av_results.items():
		if details.get("category") == "malicious" and details.get("result"):
			malicious_detections.append(f"{engine}: {details['result']}")
		elif details.get("category") == "suspicious" and details.get("result"):
			suspicious_detections.append(f"{engine}: {details['result']}")
	
	result["malicious_detections"] = "; ".join(malicious_detections[:10])
	result["suspicious_detections"] = "; ".join(suspicious_detections[:10])
	
	# File names and paths
	result["known_file_names"] = "; ".join(file_data.get("names", [])[:5])
	
	# PE information if available
	pe_info = file_data.get("pe_info", {})
	if pe_info:
		result["pe_machine"] = pe_info.get("machine", "N/A")
		result["pe_timestamp"] = str(pe_info.get("timestamp", "N/A"))
		result["pe_entry_point"] = pe_info.get("entry_point", "N/A")
		result["pe_imphash"] = pe_info.get("imphash", "N/A")
		result["pe_sections_count"] = len(pe_info.get("sections", []))
		result["pe_imports_count"] = len(pe_info.get("imports", []))
	
	# Packers
	packers = file_data.get("packers", {})
	if packers:
		result["detected_packers"] = "; ".join([f"{k}: {v}" for k, v in packers.items()])
	
	# Tags
	tags = file_data.get("tags", [])
	result["vt_tags"] = "; ".join(tags)
	
	return result

def upload_file_to_vt(file_path, headers):
	"""Upload a file to VirusTotal and wait for analysis."""
	result = {}
	
	upload_url = "https://www.virustotal.com/api/v3/files"
	with open(file_path, "rb") as f:
		files = {"file": f}
		upload_resp = requests.post(upload_url, headers=headers, files=files)
	
	if upload_resp.status_code != 200:
		result["error"] = f"Upload failed: {upload_resp.text}"
		return result
	
	upload_data = upload_resp.json()
	analysis_id = upload_data["data"]["id"]
	result["analysis_id"] = analysis_id
	
	# Wait for analysis to complete (with timeout)
	print("[DEBUG] Waiting for analysis...")
	max_wait = 180  # 3 minutes
	wait_interval = 15  # 15 seconds
	elapsed = 0
	
	analysis_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
	while elapsed < max_wait:
		analysis_resp = requests.get(analysis_url, headers=headers)
		if analysis_resp.status_code == 200:
			analysis_data = analysis_resp.json()["data"]["attributes"]
			status = analysis_data.get("status", "unknown")
			result["analysis_status"] = status
			result["analysis_date"] = str(analysis_data.get("date", "N/A"))
			
			if status == "completed":
				print("[DEBUG] Analysis completed")
				break
			else:
				print(f"[DEBUG] Analysis status: {status}, waiting...")
				time.sleep(wait_interval)
				elapsed += wait_interval
		else:
			break
	
	return result

def get_community_intelligence(file_hash, headers):
	"""Get community intelligence data (comments and votes)."""
	result = {}
	
	try:
		# Comments
		print("[DEBUG] Getting comments...")
		comments_url = f"https://www.virustotal.com/api/v3/files/{file_hash}/comments"
		comments_resp = requests.get(comments_url, headers=headers)
		if comments_resp.status_code == 200:
			comments_data = comments_resp.json()
			result["comments_count"] = len(comments_data.get("data", []))
			if comments_data.get("data"):
				first_comment = comments_data["data"][0]["attributes"]
				result["latest_comment"] = first_comment.get("text", "")[:200]
				result["latest_comment_author"] = first_comment.get("author", "")
				result["latest_comment_date"] = str(first_comment.get("date", ""))
		else:
			result["comments_count"] = 0
		
		time.sleep(1)  # Rate limiting
		
		# Votes
		print("[DEBUG] Getting votes...")
		votes_url = f"https://www.virustotal.com/api/v3/files/{file_hash}/votes"
		votes_resp = requests.get(votes_url, headers=headers)
		if votes_resp.status_code == 200:
			votes_data = votes_resp.json()
			votes = votes_data.get("data", [])
			malicious_votes = sum(1 for v in votes if v["attributes"]["verdict"] == "malicious")
			harmless_votes = sum(1 for v in votes if v["attributes"]["verdict"] == "harmless")
			result["community_malicious_votes"] = malicious_votes
			result["community_harmless_votes"] = harmless_votes
			result["total_community_votes"] = len(votes)
		else:
			result["community_malicious_votes"] = 0
			result["community_harmless_votes"] = 0
			result["total_community_votes"] = 0
		
		time.sleep(1)  # Rate limiting
		
	except Exception as e:
		result["community_error"] = f"Error getting community data: {str(e)}"
	
	return result

def get_behavioral_data(file_hash, headers):
	"""Get behavioral analysis data."""
	result = {}
	
	try:
		# Behavior analysis
		print("[DEBUG] Getting behavior analysis...")
		behavior_url = f"https://www.virustotal.com/api/v3/files/{file_hash}/behaviour_summary"
		behavior_resp = requests.get(behavior_url, headers=headers)
		if behavior_resp.status_code == 200:
			behavior_data = behavior_resp.json()
			result["has_behavior_report"] = True
			# Extract key behavior indicators
			attrs = behavior_data.get("data", {}).get("attributes", {})
			result["behavior_has_html_report"] = attrs.get("has_html_report", False)
			result["behavior_has_pcap"] = attrs.get("has_pcap", False)
			result["behavior_has_evtx"] = attrs.get("has_evtx", False)
		else:
			result["has_behavior_report"] = False
		
		time.sleep(1)  # Rate limiting
		
	except Exception as e:
		result["behavior_error"] = f"Error getting behavioral data: {str(e)}"
	
	return result

def get_network_data(file_hash, headers):
	"""Get network behavior data (contacted URLs, domains, IPs)."""
	result = {}
	
	try:
		# Contacted URLs
		print("[DEBUG] Getting contacted URLs...")
		urls_url = f"https://www.virustotal.com/api/v3/files/{file_hash}/contacted_urls"
		urls_resp = requests.get(urls_url, headers=headers)
		if urls_resp.status_code == 200:
			urls_data = urls_resp.json()
			contacted_urls = [item["id"] for item in urls_data.get("data", [])[:10]]
			result["contacted_urls_count"] = len(urls_data.get("data", []))
			result["sample_contacted_urls"] = "; ".join(contacted_urls)
		else:
			result["contacted_urls_count"] = 0
		
		time.sleep(1)  # Rate limiting
		
		# Contacted domains
		print("[DEBUG] Getting contacted domains...")
		domains_url = f"https://www.virustotal.com/api/v3/files/{file_hash}/contacted_domains"
		domains_resp = requests.get(domains_url, headers=headers)
		if domains_resp.status_code == 200:
			domains_data = domains_resp.json()
			contacted_domains = [item["id"] for item in domains_data.get("data", [])[:10]]
			result["contacted_domains_count"] = len(domains_data.get("data", []))
			result["sample_contacted_domains"] = "; ".join(contacted_domains)
		else:
			result["contacted_domains_count"] = 0
		
		time.sleep(1)  # Rate limiting
		
		# Contacted IPs
		print("[DEBUG] Getting contacted IPs...")
		ips_url = f"https://www.virustotal.com/api/v3/files/{file_hash}/contacted_ips"
		ips_resp = requests.get(ips_url, headers=headers)
		if ips_resp.status_code == 200:
			ips_data = ips_resp.json()
			contacted_ips = [item["id"] for item in ips_data.get("data", [])[:10]]
			result["contacted_ips_count"] = len(ips_data.get("data", []))
			result["sample_contacted_ips"] = "; ".join(contacted_ips)
		else:
			result["contacted_ips_count"] = 0
		
		time.sleep(1)  # Rate limiting
		
	except Exception as e:
		result["network_error"] = f"Error getting network data: {str(e)}"
	
	return result

def get_file_relationships(file_hash, headers):
	"""Get file relationship data (similar files, parents, etc.)."""
	result = {}
	
	try:
		# Similar files
		print("[DEBUG] Getting similar files...")
		similar_url = f"https://www.virustotal.com/api/v3/files/{file_hash}/similar"
		similar_resp = requests.get(similar_url, headers=headers)
		if similar_resp.status_code == 200:
			similar_data = similar_resp.json()
			result["similar_files_count"] = len(similar_data.get("data", []))
			# Get sample similar file hashes
			similar_hashes = [item["id"] for item in similar_data.get("data", [])[:5]]
			result["sample_similar_files"] = "; ".join(similar_hashes)
		else:
			result["similar_files_count"] = 0
		
		time.sleep(1)  # Rate limiting
		
		# Execution parents
		print("[DEBUG] Getting execution parents...")
		parents_url = f"https://www.virustotal.com/api/v3/files/{file_hash}/execution_parents"
		parents_resp = requests.get(parents_url, headers=headers)
		if parents_resp.status_code == 200:
			parents_data = parents_resp.json()
			result["execution_parents_count"] = len(parents_data.get("data", []))
			# Get sample parent hashes
			parent_hashes = [item["id"] for item in parents_data.get("data", [])[:3]]
			result["sample_execution_parents"] = "; ".join(parent_hashes)
		else:
			result["execution_parents_count"] = 0
		
		time.sleep(1)  # Rate limiting
		
		# Execution children
		print("[DEBUG] Getting execution children...")
		children_url = f"https://www.virustotal.com/api/v3/files/{file_hash}/execution_children"
		children_resp = requests.get(children_url, headers=headers)
		if children_resp.status_code == 200:
			children_data = children_resp.json()
			result["execution_children_count"] = len(children_data.get("data", []))
			child_hashes = [item["id"] for item in children_data.get("data", [])[:3]]
			result["sample_execution_children"] = "; ".join(child_hashes)
		else:
			result["execution_children_count"] = 0
		
		time.sleep(1)  # Rate limiting
		
		# Bundle info (for PE files)
		print("[DEBUG] Getting bundle info...")
		bundle_url = f"https://www.virustotal.com/api/v3/files/{file_hash}/bundle_info"
		bundle_resp = requests.get(bundle_url, headers=headers)
		if bundle_resp.status_code == 200:
			bundle_data = bundle_resp.json()
			result["has_bundle_info"] = True
			result["bundle_type"] = bundle_data.get("data", {}).get("type", "")
		else:
			result["has_bundle_info"] = False
		
		time.sleep(1)  # Rate limiting
		
		# Downloaders
		print("[DEBUG] Getting downloaders...")
		downloaders_url = f"https://www.virustotal.com/api/v3/files/{file_hash}/downloaders"
		downloaders_resp = requests.get(downloaders_url, headers=headers)
		if downloaders_resp.status_code == 200:
			downloaders_data = downloaders_resp.json()
			result["downloaders_count"] = len(downloaders_data.get("data", []))
			downloader_hashes = [item["id"] for item in downloaders_data.get("data", [])[:3]]
			result["sample_downloaders"] = "; ".join(downloader_hashes)
		else:
			result["downloaders_count"] = 0
		
		time.sleep(1)  # Rate limiting
		
		# Dropped files
		print("[DEBUG] Getting dropped files...")
		dropped_url = f"https://www.virustotal.com/api/v3/files/{file_hash}/dropped_files"
		dropped_resp = requests.get(dropped_url, headers=headers)
		if dropped_resp.status_code == 200:
			dropped_data = dropped_resp.json()
			result["dropped_files_count"] = len(dropped_data.get("data", []))
			dropped_hashes = [item["id"] for item in dropped_data.get("data", [])[:5]]
			result["sample_dropped_files"] = "; ".join(dropped_hashes)
		else:
			result["dropped_files_count"] = 0
		
		time.sleep(1)  # Rate limiting
		
	except Exception as e:
		result["relationships_error"] = f"Error getting file relationships: {str(e)}"
	
	return result

def get_advanced_analysis_data(file_hash, headers):
	"""Get advanced analysis data including YARA rules, signatures, etc."""
	result = {}
	
	try:
		# YARA rules
		print("[DEBUG] Getting YARA rules...")
		yara_url = f"https://www.virustotal.com/api/v3/files/{file_hash}/yara_rules"
		yara_resp = requests.get(yara_url, headers=headers)
		if yara_resp.status_code == 200:
			yara_data = yara_resp.json()
			yara_count = len(yara_data.get("data", []))
			result["yara_rules_count"] = yara_count
			if yara_count > 0:
				yara_rules = [item["attributes"]["rule_name"] for item in yara_data.get("data", [])[:10] if "attributes" in item]
				result["sample_yara_rules"] = "; ".join(yara_rules)
			else:
				result["sample_yara_rules"] = "No YARA rules matched (likely benign file)"
		elif yara_resp.status_code == 404:
			result["yara_rules_count"] = 0
			result["sample_yara_rules"] = "YARA analysis not available (404 - typically means benign file)"
		else:
			result["yara_rules_count"] = 0
			result["sample_yara_rules"] = f"YARA analysis failed (HTTP {yara_resp.status_code})"
		
		time.sleep(1)  # Rate limiting
		
		# Sigma rules
		print("[DEBUG] Getting Sigma rules...")
		sigma_url = f"https://www.virustotal.com/api/v3/files/{file_hash}/sigma_rules"
		sigma_resp = requests.get(sigma_url, headers=headers)
		if sigma_resp.status_code == 200:
			sigma_data = sigma_resp.json()
			sigma_count = len(sigma_data.get("data", []))
			result["sigma_rules_count"] = sigma_count
			if sigma_count > 0:
				sigma_rules = [item["attributes"]["title"] for item in sigma_data.get("data", [])[:5] if "attributes" in item]
				result["sample_sigma_rules"] = "; ".join(sigma_rules)
			else:
				result["sample_sigma_rules"] = "No Sigma rules matched (likely benign file)"
		elif sigma_resp.status_code == 404:
			result["sigma_rules_count"] = 0
			result["sample_sigma_rules"] = "Sigma analysis not available (404 - typically means benign file)"
		else:
			result["sigma_rules_count"] = 0
			result["sample_sigma_rules"] = f"Sigma analysis failed (HTTP {sigma_resp.status_code})"
		
		time.sleep(1)  # Rate limiting
		
		# Crowdsourced IDS rules
		print("[DEBUG] Getting IDS rules...")
		ids_url = f"https://www.virustotal.com/api/v3/files/{file_hash}/crowdsourced_ids_rules"
		ids_resp = requests.get(ids_url, headers=headers)
		if ids_resp.status_code == 200:
			ids_data = ids_resp.json()
			result["ids_rules_count"] = len(ids_data.get("data", []))
		else:
			result["ids_rules_count"] = 0
		
		time.sleep(1)  # Rate limiting
		
		# Sandbox reports
		print("[DEBUG] Getting sandbox reports...")
		sandbox_url = f"https://www.virustotal.com/api/v3/files/{file_hash}/sandbox_reports"
		sandbox_resp = requests.get(sandbox_url, headers=headers)
		if sandbox_resp.status_code == 200:
			sandbox_data = sandbox_resp.json()
			result["sandbox_reports_count"] = len(sandbox_data.get("data", []))
			# Extract sandbox names
			sandbox_names = list(set([item["attributes"]["sandbox_name"] for item in sandbox_data.get("data", []) if "attributes" in item]))
			result["sandbox_environments"] = "; ".join(sandbox_names[:5])
		else:
			result["sandbox_reports_count"] = 0
		
		time.sleep(1)  # Rate limiting
		
	except Exception as e:
		result["advanced_analysis_error"] = f"Error getting advanced analysis: {str(e)}"
	
	return result

def get_file_structure_analysis(file_hash, headers):
	"""Get detailed file structure analysis including entropy, strings, etc."""
	result = {}
	
	try:
		# PE structure and entropy analysis (from main file data)
		print("[DEBUG] Getting detailed file structure...")
		file_url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
		file_resp = requests.get(file_url, headers=headers)
		
		if file_resp.status_code == 200:
			file_data = file_resp.json()["data"]["attributes"]
			
			# Entropy analysis
			if "entropy" in file_data:
				result["file_entropy"] = file_data["entropy"]
				if file_data["entropy"] > 7.0:
					result["high_entropy_suspicious"] = True
				else:
					result["high_entropy_suspicious"] = False
			else:
				result["file_entropy"] = "Not available in VT"
				result["high_entropy_suspicious"] = False
			
			# PE section analysis
			pe_info = file_data.get("pe_info", {})
			if pe_info and "sections" in pe_info:
				sections = pe_info["sections"]
				result["pe_sections_count"] = len(sections)
				
				# Analyze section entropy
				high_entropy_sections = []
				suspicious_sections = []
				for section in sections:
					section_name = section.get("name", "unnamed")
					entropy = section.get("entropy", 0)
					raw_size = section.get("raw_size", 0)
					virtual_size = section.get("virtual_size", 0)
					
					if entropy > 7.0:
						high_entropy_sections.append(f"{section_name}({entropy:.2f})")
					
					# Check for suspicious characteristics
					if raw_size == 0 and virtual_size > 0:
						suspicious_sections.append(f"{section_name}(VirtualOnly)")
					elif raw_size > 0 and virtual_size == 0:
						suspicious_sections.append(f"{section_name}(RawOnly)")
					elif abs(raw_size - virtual_size) / max(raw_size, virtual_size, 1) > 0.9:
						suspicious_sections.append(f"{section_name}(SizeMismatch)")
				
				result["high_entropy_sections"] = "; ".join(high_entropy_sections[:5])
				result["high_entropy_sections_count"] = len(high_entropy_sections)
				result["suspicious_sections"] = "; ".join(suspicious_sections[:5])
				result["suspicious_sections_count"] = len(suspicious_sections)
			else:
				# Provide defaults for PE analysis
				result["pe_sections_count"] = 0
				result["high_entropy_sections"] = "No PE sections found"
				result["high_entropy_sections_count"] = 0
				result["suspicious_sections"] = "No PE sections found"
				result["suspicious_sections_count"] = 0
			
			# Import analysis
			imports = pe_info.get("imports", [])
			if imports:
				suspicious_imports = []
				crypto_imports = []
				network_imports = []
				process_imports = []
				
				for imp in imports:
					library = imp.get("library_name", "").lower()
					functions = [func.get("function_name", "") for func in imp.get("imported_functions", [])]
					
					# Check for suspicious API calls
					for func in functions:
						func_lower = func.lower()
						if any(sus in func_lower for sus in ["virtualalloc", "writeprocessmemory", "createremotethread", "setwindowshook"]):
							suspicious_imports.append(f"{library}:{func}")
						elif any(crypto in func_lower for crypto in ["crypt", "hash", "encrypt", "decrypt"]):
							crypto_imports.append(f"{library}:{func}")
						elif any(net in func_lower for net in ["socket", "connect", "send", "recv", "http", "download"]):
							network_imports.append(f"{library}:{func}")
						elif any(proc in func_lower for proc in ["createprocess", "shellexecute", "winexec"]):
							process_imports.append(f"{library}:{func}")
				
				result["suspicious_imports"] = "; ".join(suspicious_imports[:10])
				result["suspicious_imports_count"] = len(suspicious_imports)
				result["crypto_imports"] = "; ".join(crypto_imports[:5])
				result["crypto_imports_count"] = len(crypto_imports)
				result["network_imports"] = "; ".join(network_imports[:5])
				result["network_imports_count"] = len(network_imports)
				result["process_imports"] = "; ".join(process_imports[:5])
				result["process_imports_count"] = len(process_imports)
		
		time.sleep(1)  # Rate limiting
		
	except Exception as e:
		result["structure_analysis_error"] = f"Error analyzing file structure: {str(e)}"
	
	return result

def get_string_and_content_analysis(file_hash, headers):
	"""Get string analysis and content inspection."""
	result = {}
	
	try:
		# String analysis (if available in VT response)
		print("[DEBUG] Getting content analysis...")
		file_url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
		file_resp = requests.get(file_url, headers=headers)
		
		if file_resp.status_code == 200:
			file_data = file_resp.json()["data"]["attributes"]
			
			# Look for indicators in the raw data
			suspicious_strings = []
			base64_indicators = 0
			url_indicators = 0
			ip_indicators = 0
			registry_indicators = 0
			
			# Check if there are any string-based indicators in tags or other fields
			tags = file_data.get("tags", [])
			for tag in tags:
				tag_lower = tag.lower()
				if any(sus in tag_lower for sus in ["base64", "encoded", "obfuscat", "pack"]):
					suspicious_strings.append(tag)
				elif "url" in tag_lower or "http" in tag_lower:
					url_indicators += 1
				elif "registry" in tag_lower or "regkey" in tag_lower:
					registry_indicators += 1
			
			result["suspicious_string_tags"] = "; ".join(suspicious_strings[:10])
			result["suspicious_string_count"] = len(suspicious_strings)
			result["url_indicators"] = url_indicators
			result["registry_indicators"] = registry_indicators
			
			# Check magic bytes and file header
			magic = file_data.get("magic", "")
			if magic:
				result["file_magic"] = magic
				if any(sus in magic.lower() for sus in ["encrypted", "packed", "compressed", "obfuscated"]):
					result["magic_suspicious"] = True
				else:
					result["magic_suspicious"] = False
			
			# Check type tags for suspicious characteristics
			type_tags = file_data.get("type_tags", [])
			packer_tags = [tag for tag in type_tags if any(pack in tag.lower() for pack in ["pack", "compress", "crypt", "obfus"])]
			result["packer_type_tags"] = "; ".join(packer_tags[:5])
			result["packer_type_tags_count"] = len(packer_tags)
		
		time.sleep(1)  # Rate limiting
		
	except Exception as e:
		result["content_analysis_error"] = f"Error analyzing content: {str(e)}"
	
	return result

def generate_analysis_summary_and_conclusion(result):
	"""Generate comprehensive analysis summary and conclusion."""
	summary = {}
	
	# Risk scoring and categorization
	malicious_count = result.get("malicious_count", 0)
	suspicious_count = result.get("suspicious_count", 0)
	total_engines = result.get("total_engines", 1)
	detection_rate = (malicious_count + suspicious_count) / max(total_engines, 1) * 100
	
	# Threat indicators summary
	threat_indicators = []
	if result.get("high_entropy_sections_count", 0) > 0:
		threat_indicators.append(f"High entropy sections ({result['high_entropy_sections_count']})")
	if result.get("suspicious_imports_count", 0) > 0:
		threat_indicators.append(f"Suspicious imports ({result['suspicious_imports_count']})")
	if result.get("yara_rules_count", 0) > 0:
		threat_indicators.append(f"YARA detections ({result['yara_rules_count']})")
	if result.get("mitre_techniques_count", 0) > 0:
		threat_indicators.append(f"MITRE techniques ({result['mitre_techniques_count']})")
	if result.get("contacted_urls_count", 0) > 0:
		threat_indicators.append(f"Network contacts ({result['contacted_urls_count']})")
	
	summary["threat_indicators_summary"] = "; ".join(threat_indicators[:8])
	summary["threat_indicators_count"] = len(threat_indicators)
	
	# Analysis conclusion
	if detection_rate > 50:
		conclusion = "HIGH RISK: This file shows strong indicators of malicious behavior with significant AV detection rates."
	elif detection_rate > 20:
		conclusion = "MEDIUM RISK: This file shows some suspicious characteristics and moderate detection rates."
	elif result.get("high_entropy_sections_count", 0) > 0 or result.get("suspicious_imports_count", 0) > 2:
		conclusion = "LOW-MEDIUM RISK: While AV detection is low, structural analysis reveals potentially suspicious characteristics."
	elif result.get("yara_rules_count", 0) > 0 or result.get("mitre_techniques_count", 0) > 0:
		conclusion = "CAUTION: File matches threat intelligence signatures despite low AV detection."
	else:
		conclusion = "LOW RISK: File appears benign with minimal suspicious indicators."
	
	# Add specific findings
	specific_findings = []
	if result.get("detected_packers"):
		specific_findings.append(f"Packed with: {result['detected_packers']}")
	if result.get("magic_suspicious", False):
		specific_findings.append("Suspicious file header detected")
	if result.get("high_entropy_suspicious", False):
		specific_findings.append("Overall high entropy (possibly encrypted/packed)")
	if result.get("threat_categories"):
		specific_findings.append(f"Threat categories: {result['threat_categories']}")
	
	if specific_findings:
		conclusion += f" Specific findings: {'; '.join(specific_findings[:3])}"
	
	summary["analysis_conclusion"] = conclusion
	summary["detection_rate_percentage"] = round(detection_rate, 2)
	summary["analysis_confidence"] = "High" if total_engines > 50 else "Medium" if total_engines > 20 else "Low"
	
	return summary

def get_threat_intelligence_data(file_hash, headers):
	"""Get threat intelligence data including IOCs, TTPs, etc."""
	result = {}
	
	try:
		# Threat categories
		print("[DEBUG] Getting threat categories...")
		categories_url = f"https://www.virustotal.com/api/v3/files/{file_hash}/threat_categories"
		categories_resp = requests.get(categories_url, headers=headers)
		if categories_resp.status_code == 200:
			categories_data = categories_resp.json()
			threat_categories = [item["attributes"]["category"] for item in categories_data.get("data", []) if "attributes" in item]
			result["threat_categories"] = "; ".join(threat_categories)
			result["threat_categories_count"] = len(threat_categories)
		else:
			result["threat_categories_count"] = 0
		
		time.sleep(1)  # Rate limiting
		
		# Collections (threat actor groups, campaigns, etc.)
		print("[DEBUG] Getting collections...")
		collections_url = f"https://www.virustotal.com/api/v3/files/{file_hash}/collections"
		collections_resp = requests.get(collections_url, headers=headers)
		if collections_resp.status_code == 200:
			collections_data = collections_resp.json()
			collections = [item["attributes"]["name"] for item in collections_data.get("data", []) if "attributes" in item]
			result["threat_collections"] = "; ".join(collections[:5])
			result["threat_collections_count"] = len(collections)
		else:
			result["threat_collections_count"] = 0
		
		time.sleep(1)  # Rate limiting
		
		# MITRE ATT&CK tactics and techniques
		print("[DEBUG] Getting MITRE ATT&CK data...")
		attack_url = f"https://www.virustotal.com/api/v3/files/{file_hash}/attack_techniques"
		attack_resp = requests.get(attack_url, headers=headers)
		if attack_resp.status_code == 200:
			attack_data = attack_resp.json()
			techniques = []
			tactics = []
			for item in attack_data.get("data", []):
				if "attributes" in item:
					attrs = item["attributes"]
					if "technique_id" in attrs:
						techniques.append(f"{attrs['technique_id']}: {attrs.get('technique_name', '')}")
					if "tactic" in attrs:
						tactics.append(attrs["tactic"])
			
			result["mitre_techniques"] = "; ".join(techniques[:10])
			result["mitre_techniques_count"] = len(techniques)
			result["mitre_tactics"] = "; ".join(list(set(tactics))[:5])
			result["mitre_tactics_count"] = len(set(tactics))
		else:
			result["mitre_techniques_count"] = 0
			result["mitre_tactics_count"] = 0
		
		time.sleep(1)  # Rate limiting
		
	except Exception as e:
		result["threat_intel_error"] = f"Error getting threat intelligence: {str(e)}"
	
	return result

def get_metadata_and_submissions(file_hash, headers):
	"""Get detailed metadata and submission history."""
	result = {}
	
	try:
		# Detailed submissions history
		print("[DEBUG] Getting submissions history...")
		submissions_url = f"https://www.virustotal.com/api/v3/files/{file_hash}/submissions"
		submissions_resp = requests.get(submissions_url, headers=headers)
		if submissions_resp.status_code == 200:
			submissions_data = submissions_resp.json()
			submissions = submissions_data.get("data", [])
			result["detailed_submissions_count"] = len(submissions)
			
			# Extract submission countries and sources
			countries = [item["attributes"].get("country", "") for item in submissions if "attributes" in item]
			sources = [item["attributes"].get("source", "") for item in submissions if "attributes" in item]
			
			result["submission_countries"] = "; ".join(list(set([c for c in countries if c]))[:5])
			result["submission_sources"] = "; ".join(list(set([s for s in sources if s]))[:5])
		else:
			result["detailed_submissions_count"] = 0
		
		time.sleep(1)  # Rate limiting
		
		# Names and paths from submissions
		print("[DEBUG] Getting file names history...")
		names_url = f"https://www.virustotal.com/api/v3/files/{file_hash}/names"
		names_resp = requests.get(names_url, headers=headers)
		if names_resp.status_code == 200:
			names_data = names_resp.json()
			names = [item["attributes"]["name"] for item in names_data.get("data", []) if "attributes" in item]
			result["all_known_names"] = "; ".join(names[:10])
			result["known_names_count"] = len(names)
		else:
			result["known_names_count"] = 0
		
		time.sleep(1)  # Rate limiting
		
	except Exception as e:
		result["metadata_error"] = f"Error getting metadata: {str(e)}"
	
	return result

def calculate_risk_assessment(result):
	"""Calculate risk score and level based on analysis results."""
	risk_score = 0
	
	if result.get("malicious_count", 0) > 5:
		risk_score += 50
	elif result.get("malicious_count", 0) > 0:
		risk_score += 30
	if result.get("suspicious_count", 0) > 3:
		risk_score += 20
	if result.get("community_malicious_votes", 0) > result.get("community_harmless_votes", 0):
		risk_score += 15
	if result.get("contacted_urls_count", 0) > 0:
		risk_score += 10
	
	result["risk_score"] = min(risk_score, 100)
	if risk_score >= 70:
		result["risk_level"] = "HIGH"
	elif risk_score >= 40:
		result["risk_level"] = "MEDIUM"
	else:
		result["risk_level"] = "LOW"
	
	return result

def comprehensive_virustotal_analysis(file_path, api_key):
	"""
	Comprehensive VirusTotal analysis using multiple API endpoints.
	Returns a flattened dictionary with all available information.
	"""
	headers = {"x-apikey": api_key}
	
	# Step 1: Get basic file information
	file_hash = get_file_hash(file_path)
	result = extract_basic_file_info(file_path, file_hash)
	
	print(f"[DEBUG] Analyzing file: {file_path}")
	print(f"[DEBUG] File SHA256: {file_hash}")
	
	# Step 2: Check if file already exists in VirusTotal
	file_url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
	file_resp = requests.get(file_url, headers=headers)
	
	if file_resp.status_code == 200:
		print("[DEBUG] File already exists in VirusTotal")
		file_data = file_resp.json()["data"]["attributes"]
		
		# Extract comprehensive file information
		vt_data = extract_file_data_from_vt(file_data)
		result.update(vt_data)
		
	else:
		print("[DEBUG] File not found, uploading...")
		# Upload file if not exists
		upload_result = upload_file_to_vt(file_path, headers)
		
		if "error" in upload_result:
			result.update(upload_result)
			return result
		
		result.update(upload_result)
		
		# Get file report after upload
		file_resp = requests.get(file_url, headers=headers)
		if file_resp.status_code == 200:
			file_data = file_resp.json()["data"]["attributes"]
			vt_data = extract_file_data_from_vt(file_data)
			result.update(vt_data)
	
	# Step 3: Get comprehensive intelligence data
	print("[DEBUG] Gathering comprehensive intelligence...")
	
	community_data = get_community_intelligence(file_hash, headers)
	result.update(community_data)
	
	behavioral_data = get_behavioral_data(file_hash, headers)
	result.update(behavioral_data)
	
	network_data = get_network_data(file_hash, headers)
	result.update(network_data)
	
	relationships_data = get_file_relationships(file_hash, headers)
	result.update(relationships_data)
	
	advanced_data = get_advanced_analysis_data(file_hash, headers)
	result.update(advanced_data)
	
	# Get file structure analysis (entropy, sections, imports)
	structure_data = get_file_structure_analysis(file_hash, headers)
	result.update(structure_data)
	
	# Get string and content analysis
	content_data = get_string_and_content_analysis(file_hash, headers)
	result.update(content_data)
	
	threat_intel_data = get_threat_intelligence_data(file_hash, headers)
	result.update(threat_intel_data)
	
	metadata_data = get_metadata_and_submissions(file_hash, headers)
	result.update(metadata_data)
	
	# Generate comprehensive analysis summary and conclusion
	summary_data = generate_analysis_summary_and_conclusion(result)
	result.update(summary_data)
	
	# Step 4: Calculate risk assessment
	result = calculate_risk_assessment(result)
	
	print(f"[DEBUG] Analysis complete. Found {len(result)} data points")
	print(f"[DEBUG] Risk Assessment: {result.get('risk_level', 'UNKNOWN')} ({result.get('risk_score', 0)}/100)")
	return result

def scan_and_upload_exe_files(directory, api_key):
	"""
	Scans a directory for .exe files and uploads each to VirusTotal.
	Returns a dictionary mapping file paths to their VirusTotal analysis results.
	"""
	exe_files = find_exe_files(directory)
	results = {}
	
	print(f"Found {len(exe_files)} .exe files to analyze")
	
	for i, file_path in enumerate(exe_files, 1):
		print(f"\n[{i}/{len(exe_files)}] Analyzing {os.path.basename(file_path)}...")
		try:
			vt_result = comprehensive_virustotal_analysis(file_path, api_key)
			results[file_path] = vt_result
			print(f"Analysis complete. Risk level: {vt_result.get('risk_level', 'UNKNOWN')}")
		except Exception as e:
			print(f"Error analyzing {file_path}: {str(e)}")
			results[file_path] = {"error": str(e)}
		
		# Rate limiting between files
		if i < len(exe_files):
			print("Waiting 15 seconds before next file...")
			time.sleep(15)
	
	return results