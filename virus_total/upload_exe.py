
import requests
import hashlib
import time
import os
import functools
from typing import Callable, Dict, Any
from .scan_exe_directory import find_exe_files

def handle_vt_api_errors(func: Callable) -> Callable:
    """Decorator to handle VirusTotal API errors and standard response patterns."""
    @functools.wraps(func)
    def wrapper(*args, **kwargs) -> Dict[str, Any]:
        try:
            return func(*args, **kwargs)
        except requests.RequestException as e:
            return {"error": f"API request failed: {str(e)}"}
        except Exception as e:
            return {"error": f"Unexpected error in {func.__name__}: {str(e)}"}
    return wrapper

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

@handle_vt_api_errors
def _get_file_info(file_hash: str, file_path: str, headers: dict) -> dict:
	"""Check if file exists in VirusTotal and get its data."""
	file_url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
	file_resp = requests.get(file_url, headers=headers)
	result = {}
	
	if file_resp.status_code == 200:
		print("[-] File already exists in VirusTotal")
		file_data = file_resp.json()["data"]["attributes"]
		# Extract comprehensive file information
		result = extract_file_data_from_vt(file_data)
	else:
		print("[-] File not found, uploading...")
		# Upload file if not exists
		upload_result = upload_file_to_vt(file_path, headers)
		
		if "error" in upload_result:
			return upload_result
		
		result.update(upload_result)
		
		# Get file report after upload
		file_resp = requests.get(file_url, headers=headers)
		if file_resp.status_code == 200:
			file_data = file_resp.json()["data"]["attributes"]
			vt_data = extract_file_data_from_vt(file_data)
			result.update(vt_data)
	
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

def _post_file_upload(file_path: str, headers: dict) -> dict:
	"""Upload a file to VirusTotal API."""
	upload_url = "https://www.virustotal.com/api/v3/files"
	with open(file_path, "rb") as f:
		files = {"file": f}
		upload_resp = requests.post(upload_url, headers=headers, files=files)
	
	if upload_resp.status_code != 200:
		raise Exception(f"Upload failed: {upload_resp.text}")
	
	return upload_resp.json()

def _get_analysis_status(analysis_id: str, headers: dict) -> dict:
	"""Get analysis status from VirusTotal API."""
	analysis_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
	analysis_resp = requests.get(analysis_url, headers=headers)
	
	if analysis_resp.status_code != 200:
		raise Exception(f"Analysis status check failed: {analysis_resp.text}")
	
	return analysis_resp.json()["data"]["attributes"]

def upload_file_to_vt(file_path: str, headers: dict) -> dict:
	"""Upload a file to VirusTotal and wait for analysis."""
	result = {}
	
	# Upload file
	try:
		upload_data = _post_file_upload(file_path, headers)
		analysis_id = upload_data["data"]["id"]
		result["analysis_id"] = analysis_id
	except Exception as e:
		result["error"] = str(e)
		return result
	
	# Wait for analysis to complete (with timeout)
	print("[-] Waiting for analysis...")
	max_wait = 180  # 3 minutes
	wait_interval = 15  # 15 seconds
	elapsed = 0
	
	while elapsed < max_wait:
		try:
			analysis_data = _get_analysis_status(analysis_id, headers)
			status = analysis_data.get("status", "unknown")
			result["analysis_status"] = status
			result["analysis_date"] = str(analysis_data.get("date", "N/A"))
			
			if status == "completed":
				print("[-] Analysis completed")
				break
			else:
				print(f"[-] Analysis status: {status}, waiting...")
				time.sleep(wait_interval)
				elapsed += wait_interval
		except Exception:
			break
	
	return result

def _get_file_comments(file_hash: str, headers: dict) -> dict:
	"""Get file comments from VirusTotal API."""
	comments_url = f"https://www.virustotal.com/api/v3/files/{file_hash}/comments"
	comments_resp = requests.get(comments_url, headers=headers)
	if comments_resp.status_code != 200:
		raise Exception(f"Comments fetch failed: {comments_resp.text}")
	return comments_resp.json()

def _get_file_votes(file_hash: str, headers: dict) -> dict:
	"""Get file votes from VirusTotal API."""
	votes_url = f"https://www.virustotal.com/api/v3/files/{file_hash}/votes"
	votes_resp = requests.get(votes_url, headers=headers)
	if votes_resp.status_code != 200:
		raise Exception(f"Votes fetch failed: {votes_resp.text}")
	return votes_resp.json()

def get_community_intelligence(file_hash: str, headers: dict) -> dict:
	"""Get community intelligence data (comments and votes)."""
	result = {}
	
	try:
		# Get comments
		print("[-] Getting comments...")
		comments_data = _get_file_comments(file_hash, headers)
		result["comments_count"] = len(comments_data.get("data", []))
		if comments_data.get("data"):
			first_comment = comments_data["data"][0]["attributes"]
			result["latest_comment"] = first_comment.get("text", "")[:200]
			result["latest_comment_author"] = first_comment.get("author", "")
			result["latest_comment_date"] = str(first_comment.get("date", ""))
		else:
			result["comments_count"] = 0
		
		time.sleep(1)  # Rate limiting
		
		# Get votes
		print("[-] Getting votes...")
		votes_data = _get_file_votes(file_hash, headers)
		votes = votes_data.get("data", [])
		malicious_votes = sum(1 for v in votes if v["attributes"]["verdict"] == "malicious")
		harmless_votes = sum(1 for v in votes if v["attributes"]["verdict"] == "harmless")
		result["community_malicious_votes"] = malicious_votes
		result["community_harmless_votes"] = harmless_votes
		result["total_community_votes"] = len(votes)
		
		time.sleep(1)  # Rate limiting
		
	except Exception as e:
		result["community_error"] = f"Error getting community data: {str(e)}"
		result["comments_count"] = 0
		result["community_malicious_votes"] = 0
		result["community_harmless_votes"] = 0
		result["total_community_votes"] = 0
	
	return result

def _get_behavior_summary(file_hash: str, headers: dict) -> dict:
	"""Get behavior summary from VirusTotal API."""
	behavior_url = f"https://www.virustotal.com/api/v3/files/{file_hash}/behaviour_summary"
	behavior_resp = requests.get(behavior_url, headers=headers)
	if behavior_resp.status_code != 200:
		raise Exception(f"Behavior summary fetch failed: {behavior_resp.text}")
	return behavior_resp.json()

def get_behavioral_data(file_hash: str, headers: dict) -> dict:
	"""Get behavioral analysis data."""
	result = {}
	
	try:
		print("[-] Getting behavior analysis...")
		behavior_data = _get_behavior_summary(file_hash, headers)
		result["has_behavior_report"] = True
		# Extract key behavior indicators
		attrs = behavior_data.get("data", {}).get("attributes", {})
		result["behavior_has_html_report"] = attrs.get("has_html_report", False)
		result["behavior_has_pcap"] = attrs.get("has_pcap", False)
		result["behavior_has_evtx"] = attrs.get("has_evtx", False)
		
		time.sleep(1)  # Rate limiting
		
	except Exception as e:
		result["behavior_error"] = f"Error getting behavioral data: {str(e)}"
		result["has_behavior_report"] = False
	
	return result

def _get_contacted_urls(file_hash: str, headers: dict) -> dict:
	"""Get contacted URLs from VirusTotal API."""
	urls_url = f"https://www.virustotal.com/api/v3/files/{file_hash}/contacted_urls"
	urls_resp = requests.get(urls_url, headers=headers)
	if urls_resp.status_code != 200:
		raise Exception(f"Contacted URLs fetch failed: {urls_resp.text}")
	return urls_resp.json()

def _get_contacted_domains(file_hash: str, headers: dict) -> dict:
	"""Get contacted domains from VirusTotal API."""
	domains_url = f"https://www.virustotal.com/api/v3/files/{file_hash}/contacted_domains"
	domains_resp = requests.get(domains_url, headers=headers)
	if domains_resp.status_code != 200:
		raise Exception(f"Contacted domains fetch failed: {domains_resp.text}")
	return domains_resp.json()

def _get_contacted_ips(file_hash: str, headers: dict) -> dict:
	"""Get contacted IPs from VirusTotal API."""
	ips_url = f"https://www.virustotal.com/api/v3/files/{file_hash}/contacted_ips"
	ips_resp = requests.get(ips_url, headers=headers)
	if ips_resp.status_code != 200:
		raise Exception(f"Contacted IPs fetch failed: {ips_resp.text}")
	return ips_resp.json()

def get_network_data(file_hash: str, headers: dict) -> dict:
	"""Get network behavior data (contacted URLs, domains, IPs)."""
	result = {}
	
	try:
		# Get contacted URLs
		print("[-] Getting contacted URLs...")
		urls_data = _get_contacted_urls(file_hash, headers)
		contacted_urls = [item["id"] for item in urls_data.get("data", [])[:10]]
		result["contacted_urls_count"] = len(urls_data.get("data", []))
		result["sample_contacted_urls"] = "; ".join(contacted_urls)
		time.sleep(1)  # Rate limiting
		
		# Get contacted domains
		print("[-] Getting contacted domains...")
		domains_data = _get_contacted_domains(file_hash, headers)
		contacted_domains = [item["id"] for item in domains_data.get("data", [])[:10]]
		result["contacted_domains_count"] = len(domains_data.get("data", []))
		result["sample_contacted_domains"] = "; ".join(contacted_domains)
		time.sleep(1)  # Rate limiting
		
		# Get contacted IPs
		print("[-] Getting contacted IPs...")
		ips_data = _get_contacted_ips(file_hash, headers)
		contacted_ips = [item["id"] for item in ips_data.get("data", [])[:10]]
		result["contacted_ips_count"] = len(ips_data.get("data", []))
		result["sample_contacted_ips"] = "; ".join(contacted_ips)
		time.sleep(1)  # Rate limiting
		
	except Exception as e:
		result["network_error"] = f"Error getting network data: {str(e)}"
		result["contacted_urls_count"] = 0
		result["contacted_domains_count"] = 0
		result["contacted_ips_count"] = 0
	
	return result

def _get_similar_files(file_hash: str, headers: dict) -> dict:
	"""Get similar files from VirusTotal API."""
	similar_url = f"https://www.virustotal.com/api/v3/files/{file_hash}/similar"
	similar_resp = requests.get(similar_url, headers=headers)
	result = {}
	
	if similar_resp.status_code == 200:
		result = similar_resp.json()
	elif similar_resp.status_code == 404:
		# Not found is normal for new or unique files
		result["data"] = []
	else:
		raise Exception(f"Similar files fetch failed: {similar_resp.text}")
	
	return result

def _get_execution_parents(file_hash: str, headers: dict) -> dict:
	"""Get execution parents from VirusTotal API."""
	parents_url = f"https://www.virustotal.com/api/v3/files/{file_hash}/execution_parents"
	parents_resp = requests.get(parents_url, headers=headers)
	if parents_resp.status_code == 200:
		return parents_resp.json()
	elif parents_resp.status_code == 404:
		# Not found is normal for files without parents
		return {"data": []}
	else:
		raise Exception(f"Execution parents fetch failed: {parents_resp.text}")

def _get_execution_children(file_hash: str, headers: dict) -> dict:
	"""Get execution children from VirusTotal API."""
	children_url = f"https://www.virustotal.com/api/v3/files/{file_hash}/execution_children"
	children_resp = requests.get(children_url, headers=headers)
	if children_resp.status_code == 200:
		return children_resp.json()
	elif children_resp.status_code == 404:
		# Not found is normal for files without children
		return {"data": []}
	else:
		raise Exception(f"Execution children fetch failed: {children_resp.text}")

def get_file_relationships(file_hash: str, headers: dict) -> dict:
	"""Get file relationship data (similar files, parents, etc.)."""
	result = {}
	
	# Get similar files
	print("[-] Getting similar files...")
	try:
		similar_data = _get_similar_files(file_hash, headers)
		similar_hashes = [item["id"] for item in similar_data.get("data", [])[:5]]
		result["similar_files_count"] = len(similar_data.get("data", []))
		result["sample_similar_files"] = "; ".join(similar_hashes) if similar_hashes else "None found"
	except Exception as e:
		result["similar_files_count"] = 0
		result["sample_similar_files"] = "Error fetching similar files"
		result["similar_files_error"] = str(e)
	time.sleep(1)  # Rate limiting
	
	# Get execution parents
	print("[-] Getting execution parents...")
	try:
		parents_data = _get_execution_parents(file_hash, headers)
		parent_hashes = [item["id"] for item in parents_data.get("data", [])[:3]]
		result["execution_parents_count"] = len(parents_data.get("data", []))
		result["sample_execution_parents"] = "; ".join(parent_hashes) if parent_hashes else "None found"
	except Exception as e:
		result["execution_parents_count"] = 0
		result["sample_execution_parents"] = "Error fetching execution parents"
		result["execution_parents_error"] = str(e)
	time.sleep(1)  # Rate limiting
	
	# Get execution children
	print("[-] Getting execution children...")
	try:
		children_data = _get_execution_children(file_hash, headers)
		child_hashes = [item["id"] for item in children_data.get("data", [])[:3]]
		result["execution_children_count"] = len(children_data.get("data", []))
		result["sample_execution_children"] = "; ".join(child_hashes) if child_hashes else "None found"
	except Exception as e:
		result["execution_children_count"] = 0
		result["sample_execution_children"] = "Error fetching execution children"
		result["execution_children_error"] = str(e)
	time.sleep(1)  # Rate limiting
	
	# Get bundle info (for PE files)
	print("[-] Getting bundle info...")
	try:
		bundle_url = f"https://www.virustotal.com/api/v3/files/{file_hash}/bundle_info"
		bundle_resp = requests.get(bundle_url, headers=headers)
		if bundle_resp.status_code == 200:
			bundle_data = bundle_resp.json()
			result["has_bundle_info"] = True
			result["bundle_type"] = bundle_data.get("data", {}).get("type", "")
		else:
			result["has_bundle_info"] = False
	except Exception as e:
		result["has_bundle_info"] = False
		result["bundle_info_error"] = str(e)
	time.sleep(1)  # Rate limiting
	
	# Get downloaders
	print("[-] Getting downloaders...")
	try:
		downloaders_url = f"https://www.virustotal.com/api/v3/files/{file_hash}/downloaders"
		downloaders_resp = requests.get(downloaders_url, headers=headers)
		if downloaders_resp.status_code == 200:
			downloaders_data = downloaders_resp.json()
			result["downloaders_count"] = len(downloaders_data.get("data", []))
			downloader_hashes = [item["id"] for item in downloaders_data.get("data", [])[:3]]
			result["sample_downloaders"] = "; ".join(downloader_hashes) if downloader_hashes else "None found"
		else:
			result["downloaders_count"] = 0
			result["sample_downloaders"] = "No downloaders found"
	except Exception as e:
		result["downloaders_count"] = 0
		result["sample_downloaders"] = "Error fetching downloaders"
		result["downloaders_error"] = str(e)
	time.sleep(1)  # Rate limiting
	
	# Get dropped files
	print("[-] Getting dropped files...")
	try:
		dropped_url = f"https://www.virustotal.com/api/v3/files/{file_hash}/dropped_files"
		dropped_resp = requests.get(dropped_url, headers=headers)
		if dropped_resp.status_code == 200:
			dropped_data = dropped_resp.json()
			result["dropped_files_count"] = len(dropped_data.get("data", []))
			dropped_hashes = [item["id"] for item in dropped_data.get("data", [])[:5]]
			result["sample_dropped_files"] = "; ".join(dropped_hashes) if dropped_hashes else "None found"
		else:
			result["dropped_files_count"] = 0
			result["sample_dropped_files"] = "No dropped files found"
	except Exception as e:
		result["dropped_files_count"] = 0
		result["sample_dropped_files"] = "Error fetching dropped files"
		result["dropped_files_error"] = str(e)
	time.sleep(1)  # Rate limiting
	
	return result

@handle_vt_api_errors
def _get_yara_rules(file_hash: str, headers: dict) -> dict:
	"""Get YARA rules from VirusTotal API."""
	yara_url = f"https://www.virustotal.com/api/v3/files/{file_hash}/yara_rules"
	yara_resp = requests.get(yara_url, headers=headers)
	result = {}
	
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
	
	return result

def _get_sigma_rules(file_hash: str, headers: dict) -> dict:
	"""Get Sigma rules from VirusTotal API."""
	sigma_url = f"https://www.virustotal.com/api/v3/files/{file_hash}/sigma_rules"
	sigma_resp = requests.get(sigma_url, headers=headers)
	result = {}
	
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
	
	return result

def _get_ids_rules(file_hash: str, headers: dict) -> dict:
	"""Get crowdsourced IDS rules from VirusTotal API."""
	ids_url = f"https://www.virustotal.com/api/v3/files/{file_hash}/crowdsourced_ids_rules"
	ids_resp = requests.get(ids_url, headers=headers)
	result = {}
	
	if ids_resp.status_code == 200:
		ids_data = ids_resp.json()
		result["ids_rules_count"] = len(ids_data.get("data", []))
	else:
		result["ids_rules_count"] = 0
	
	return result

def _get_sandbox_reports(file_hash: str, headers: dict) -> dict:
	"""Get sandbox reports from VirusTotal API."""
	sandbox_url = f"https://www.virustotal.com/api/v3/files/{file_hash}/sandbox_reports"
	sandbox_resp = requests.get(sandbox_url, headers=headers)
	result = {}
	
	if sandbox_resp.status_code == 200:
		sandbox_data = sandbox_resp.json()
		result["sandbox_reports_count"] = len(sandbox_data.get("data", []))
		# Extract sandbox names
		sandbox_names = list(set([item["attributes"]["sandbox_name"] for item in sandbox_data.get("data", []) if "attributes" in item]))
		result["sandbox_environments"] = "; ".join(sandbox_names[:5])
	else:
		result["sandbox_reports_count"] = 0
		result["sandbox_environments"] = ""
	
	return result

def get_advanced_analysis_data(file_hash: str, headers: dict) -> dict:
	"""Get advanced analysis data including YARA rules, signatures, etc."""
	result = {}
	
	try:
		# Get YARA rules
		print("[-] Getting YARA rules...")
		result.update(_get_yara_rules(file_hash, headers))
		time.sleep(1)  # Rate limiting
		
		# Get Sigma rules
		print("[-] Getting Sigma rules...")
		result.update(_get_sigma_rules(file_hash, headers))
		time.sleep(1)  # Rate limiting
		
		# Get IDS rules
		print("[-] Getting IDS rules...")
		result.update(_get_ids_rules(file_hash, headers))
		time.sleep(1)  # Rate limiting
		
		# Get sandbox reports
		print("[-] Getting sandbox reports...")
		result.update(_get_sandbox_reports(file_hash, headers))
		time.sleep(1)  # Rate limiting
		
	except Exception as e:
		result["advanced_analysis_error"] = f"Error getting advanced analysis: {str(e)}"
	
	return result

def _get_file_details(file_hash: str, headers: dict) -> dict:
	"""Get detailed file information from VirusTotal API."""
	file_url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
	file_resp = requests.get(file_url, headers=headers)
	if file_resp.status_code != 200:
		raise Exception(f"File details fetch failed: {file_resp.text}")
	return file_resp.json()["data"]["attributes"]

def _analyze_entropy(file_data: dict) -> dict:
	"""Analyze file entropy from VirusTotal data."""
	result = {}
	
	if "entropy" in file_data:
		result["file_entropy"] = file_data["entropy"]
		result["high_entropy_suspicious"] = file_data["entropy"] > 7.0
	else:
		result["file_entropy"] = "Not available in VT"
		result["high_entropy_suspicious"] = False
	
	return result

def _analyze_pe_sections(pe_info: dict) -> dict:
	"""Analyze PE sections from VirusTotal data."""
	result = {}
	
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
		result["pe_sections_count"] = 0
		result["high_entropy_sections"] = "No PE sections found"
		result["high_entropy_sections_count"] = 0
		result["suspicious_sections"] = "No PE sections found"
		result["suspicious_sections_count"] = 0
	
	return result

def _get_import_functions(pe_info: dict) -> list:
	"""Extract all imported functions from PE info."""
	imports = []
	for imp in pe_info.get("imports", []):
		library = imp.get("library_name", "").lower()
		functions = [func.get("function_name", "") for func in imp.get("imported_functions", [])]
		imports.extend((library, func) for func in functions)
	return imports

def _find_suspicious_imports(imports: list) -> list:
	"""Find suspicious imports like memory manipulation functions."""
	suspicious_patterns = ["virtualalloc", "writeprocessmemory", "createremotethread", "setwindowshook"]
	return [f"{lib}:{func}" for lib, func in imports 
			if any(sus in func.lower() for sus in suspicious_patterns)]

def _find_crypto_imports(imports: list) -> list:
	"""Find cryptography-related imports."""
	crypto_patterns = ["crypt", "hash", "encrypt", "decrypt"]
	return [f"{lib}:{func}" for lib, func in imports 
			if any(crypto in func.lower() for crypto in crypto_patterns)]

def _find_network_imports(imports: list) -> list:
	"""Find network-related imports."""
	network_patterns = ["socket", "connect", "send", "recv", "http", "download"]
	return [f"{lib}:{func}" for lib, func in imports 
			if any(net in func.lower() for net in network_patterns)]

def _find_process_imports(imports: list) -> list:
	"""Find process manipulation imports."""
	process_patterns = ["createprocess", "shellexecute", "winexec"]
	return [f"{lib}:{func}" for lib, func in imports 
			if any(proc in func.lower() for proc in process_patterns)]

def _analyze_imports(pe_info: dict) -> dict:
	"""Analyze PE imports from VirusTotal data."""
	result = {}
	
	if imports := _get_import_functions(pe_info):
		suspicious_imports = _find_suspicious_imports(imports)
		crypto_imports = _find_crypto_imports(imports)
		network_imports = _find_network_imports(imports)
		process_imports = _find_process_imports(imports)
		
		result["suspicious_imports"] = "; ".join(suspicious_imports[:10])
		result["suspicious_imports_count"] = len(suspicious_imports)
		result["crypto_imports"] = "; ".join(crypto_imports[:5])
		result["crypto_imports_count"] = len(crypto_imports)
		result["network_imports"] = "; ".join(network_imports[:5])
		result["network_imports_count"] = len(network_imports)
		result["process_imports"] = "; ".join(process_imports[:5])
		result["process_imports_count"] = len(process_imports)
	else:
		result["suspicious_imports_count"] = 0
		result["crypto_imports_count"] = 0
		result["network_imports_count"] = 0
		result["process_imports_count"] = 0
	
	return result

def get_file_structure_analysis(file_hash: str, headers: dict) -> dict:
	"""Get detailed file structure analysis including entropy, strings, etc."""
	result = {}
	
	try:
		# Get file details and PE structure
		print("[-] Getting detailed file structure...")
		file_data = _get_file_details(file_hash, headers)
		
		# Analyze file details
		result.update(_analyze_entropy(file_data))
		
		# Analyze PE sections and imports if available
		pe_info = file_data.get("pe_info", {})
		result.update(_analyze_pe_sections(pe_info))
		result.update(_analyze_imports(pe_info))
		
		time.sleep(1)  # Rate limiting
		
	except Exception as e:
		result["structure_analysis_error"] = f"Error analyzing file structure: {str(e)}"
	
	return result

def _analyze_tags_and_indicators(file_data: dict) -> dict:
	"""Analyze tags and indicators from file data."""
	result = {}
	suspicious_strings = []
	url_indicators = 0
	registry_indicators = 0
	
	# Check tags for indicators
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
	
	return result

def _analyze_magic_and_type(file_data: dict) -> dict:
	"""Analyze file magic and type information."""
	result = {}
	
	# Check magic bytes and file header
	magic = file_data.get("magic", "")
	if magic:
		result["file_magic"] = magic
		result["magic_suspicious"] = any(sus in magic.lower() for sus in ["encrypted", "packed", "compressed", "obfuscated"])
	
	# Check type tags for suspicious characteristics
	type_tags = file_data.get("type_tags", [])
	packer_tags = [tag for tag in type_tags if any(pack in tag.lower() for pack in ["pack", "compress", "crypt", "obfus"])]
	result["packer_type_tags"] = "; ".join(packer_tags[:5])
	result["packer_type_tags_count"] = len(packer_tags)
	
	return result

def get_string_and_content_analysis(file_hash: str, headers: dict) -> dict:
	"""Get string analysis and content inspection."""
	result = {}
	
	try:
		# Get file details and analyze content
		print("[-] Getting content analysis...")
		file_data = _get_file_details(file_hash, headers)
		
		# Analyze tags and indicators
		result.update(_analyze_tags_and_indicators(file_data))
		
		# Analyze magic bytes and file types
		result.update(_analyze_magic_and_type(file_data))
			
			# Look for indicators in the raw data
		time.sleep(1)  # Rate limiting
		
	except Exception as e:
		result["content_analysis_error"] = f"Error analyzing content: {str(e)}"
	
	return result

def _calculate_risk_metrics(result: dict) -> dict:
	"""Calculate risk metrics from analysis results."""
	summary = {}
	
	# Calculate detection rate
	malicious_count = result.get("malicious_count", 0)
	suspicious_count = result.get("suspicious_count", 0)
	total_engines = result.get("total_engines", 1)
	detection_rate = (malicious_count + suspicious_count) / max(total_engines, 1) * 100
	summary["detection_rate"] = detection_rate
	
	# Count threat indicators
	threat_indicators = []
	if result.get("high_entropy_sections_count", 0) > 0:
		threat_indicators.append(f"High entropy sections ({result['high_entropy_sections_count']})")
	if result.get("suspicious_imports_count", 0) > 0:
		threat_indicators.append(f"Suspicious imports ({result['suspicious_imports_count']})")
	if result.get("yara_rules_count", 0) > 0:
		threat_indicators.append(f"YARA detections ({result['yara_rules_count']})")
	if result.get("mitre_techniques_count", 0) > 0:
		threat_indicators.append(f"MITRE techniques ({result['mitre_techniques_count']})")
	summary["threat_indicators"] = threat_indicators
	
	return summary

def _generate_threat_indicators(result: dict) -> list:
	"""Generate list of threat indicators from analysis results."""
	threat_indicators = []
	
	# Core threat indicators
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
	
	return threat_indicators

def _determine_risk_level(result: dict, detection_rate: float) -> str:
	"""Determine risk level based on analysis results."""
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
	return conclusion

def _collect_specific_findings(result: dict) -> list:
	"""Collect specific findings from analysis results."""
	specific_findings = []
	if result.get("detected_packers"):
		specific_findings.append(f"Packed with: {result['detected_packers']}")
	if result.get("magic_suspicious", False):
		specific_findings.append("Suspicious file header detected")
	if result.get("high_entropy_suspicious", False):
		specific_findings.append("Overall high entropy (possibly encrypted/packed)")
	if result.get("threat_categories"):
		specific_findings.append(f"Threat categories: {result['threat_categories']}")
	return specific_findings

def generate_analysis_summary_and_conclusion(result: dict) -> dict:
	"""Generate comprehensive analysis summary and conclusion."""
	# Get base risk metrics
	summary = _calculate_risk_metrics(result)
	detection_rate = summary["detection_rate"]
	total_engines = result.get("total_engines", 1)
	
	# Get threat indicators
	threat_indicators = _generate_threat_indicators(result)
	summary["threat_indicators_summary"] = "; ".join(threat_indicators[:8])
	summary["threat_indicators_count"] = len(threat_indicators)
	
	# Get risk level and specific findings
	conclusion = _determine_risk_level(result, detection_rate)
	specific_findings = _collect_specific_findings(result)
	if specific_findings:
		conclusion += f" Specific findings: {'; '.join(specific_findings[:3])}"
	
	summary["analysis_conclusion"] = conclusion
	summary["detection_rate_percentage"] = round(detection_rate, 2)
	summary["analysis_confidence"] = "High" if total_engines > 50 else "Medium" if total_engines > 20 else "Low"
	
	return summary

def _get_threat_categories(file_hash: str, headers: dict) -> dict:
	"""Get threat categories from VirusTotal API."""
	categories_url = f"https://www.virustotal.com/api/v3/files/{file_hash}/threat_categories"
	categories_resp = requests.get(categories_url, headers=headers)
	result = {}
	
	if categories_resp.status_code == 200:
		categories_data = categories_resp.json()
		threat_categories = [item["attributes"]["category"] for item in categories_data.get("data", []) if "attributes" in item]
		result["threat_categories"] = "; ".join(threat_categories)
		result["threat_categories_count"] = len(threat_categories)
	else:
		result["threat_categories_count"] = 0
	
	return result

def _get_threat_collections(file_hash: str, headers: dict) -> dict:
	"""Get threat collections from VirusTotal API."""
	collections_url = f"https://www.virustotal.com/api/v3/files/{file_hash}/collections"
	collections_resp = requests.get(collections_url, headers=headers)
	result = {}
	
	try:
		if collections_resp.status_code == 200:
			collections_data = collections_resp.json()
			collections = [item["attributes"]["name"] for item in collections_data.get("data", []) if "attributes" in item]
			result["threat_collections"] = "; ".join(collections[:5])
			result["threat_collections_count"] = len(collections)
		else:
			result["threat_collections_count"] = 0
	except Exception:
		result["threat_collections_count"] = 0
	
	return result

def _get_mitre_attack_data(file_hash: str, headers: dict) -> dict:
	"""Get MITRE ATT&CK techniques and tactics from VirusTotal."""
	result = {}
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
	
	return result

@handle_vt_api_errors
def get_threat_intelligence_data(file_hash: str, headers: dict) -> dict:
	"""Get threat intelligence data including IOCs, TTPs, etc."""
	result = {}
	
	# Get threat categories
	print("[-] Getting threat categories...")
	result.update(_get_threat_categories(file_hash, headers))
	time.sleep(1)  # Rate limiting
	
	# Get collections (threat actor groups, campaigns, etc.)
	print("[-] Getting collections...")
	result.update(_get_threat_collections(file_hash, headers))
	time.sleep(1)  # Rate limiting
	
	# Get MITRE ATT&CK data
	print("[-] Getting MITRE ATT&CK data...")
	result.update(_get_mitre_attack_data(file_hash, headers))
	time.sleep(1)  # Rate limiting
	
	return result

def _get_file_names_history(file_hash: str, headers: dict) -> dict:
	"""Get known file names history from VirusTotal."""
	result = {}
	names_url = f"https://www.virustotal.com/api/v3/files/{file_hash}/names"
	names_resp = requests.get(names_url, headers=headers)
	
	if names_resp.status_code == 200:
		names_data = names_resp.json()
		names = [item["attributes"]["name"] for item in names_data.get("data", []) if "attributes" in item]
		result["all_known_names"] = "; ".join(names[:10])
		result["known_names_count"] = len(names)
	else:
		result["known_names_count"] = 0
	
	return result

def _get_submissions_history(file_hash: str, headers: dict) -> dict:
	"""Get detailed submissions history from VirusTotal."""
	result = {}
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
	
	return result

def get_metadata_and_submissions(file_hash, headers):
	"""Get detailed metadata and submission history."""
	result = {}
	
	try:
		# Get detailed submissions history
		print("[-] Getting submissions history...")
		result.update(_get_submissions_history(file_hash, headers))
		time.sleep(1)  # Rate limiting
		
		# Get names and paths from submissions
		print("[-] Getting file names history...")
		result.update(_get_file_names_history(file_hash, headers))
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
    Comprehensive VirusTotal analysis showing direct API call sequence.
    Returns a flattened dictionary with all available information.
    """
    headers = {"x-apikey": api_key}
    result = {}

    # Step 1: Basic File Analysis
    print("[-] Starting file analysis...")
    file_hash = get_file_hash(file_path)
    result.update(extract_basic_file_info(file_path, file_hash))
    print(f"[-] File SHA256: {file_hash}")

    # Step 2: File Upload/Check
    print("[-] Checking if file exists in VirusTotal...")
    result.update(_get_file_info(file_hash, file_path, headers))
    time.sleep(1)

    # Step 3: Community Intelligence
    print("[-] Getting community feedback...")
    result.update(_get_file_comments(file_hash, headers))
    time.sleep(1)
    result.update(_get_file_votes(file_hash, headers))
    time.sleep(1)

    # Step 4: Behavioral Analysis
    print("[-] Analyzing behavior patterns...")
    result.update(_get_behavior_summary(file_hash, headers))
    time.sleep(1)

    # Step 5: Network Activity
    print("[-] Checking network connections...")
    result.update(_get_contacted_urls(file_hash, headers))
    time.sleep(1)
    result.update(_get_contacted_domains(file_hash, headers))
    time.sleep(1)
    result.update(_get_contacted_ips(file_hash, headers))
    time.sleep(1)

    # Step 6: File Relationships
    print("[-] Analyzing file relationships...")
    try:
        similar = _get_similar_files(file_hash, headers)
        if "error" not in similar:
            result.update(similar)
        time.sleep(1)

        parents = _get_execution_parents(file_hash, headers)
        if "error" not in parents:
            result.update(parents)
        time.sleep(1)

        children = _get_execution_children(file_hash, headers)
        if "error" not in children:
            result.update(children)
        time.sleep(1)
    except Exception as e:
        print(f"[-] Warning: Some relationship data unavailable: {str(e)}")
        # Set default values to indicate data was not available
        result.update({
            "similar_files_count": 0,
            "execution_parents_count": 0,
            "execution_children_count": 0
        })

    # Step 7: Detection Rules
    print("[-] Checking detection rules...")
    result.update(_get_yara_rules(file_hash, headers))
    time.sleep(1)
    result.update(_get_sigma_rules(file_hash, headers))
    time.sleep(1)
    result.update(_get_ids_rules(file_hash, headers))
    time.sleep(1)
    result.update(_get_sandbox_reports(file_hash, headers))
    time.sleep(1)

    # Step 8: File Structure
    print("[-] Analyzing file structure...")
    file_data = _get_file_details(file_hash, headers)
    result.update(_analyze_entropy(file_data))
    pe_info = file_data.get("pe_info", {})
    result.update(_analyze_pe_sections(pe_info))
    result.update(_analyze_imports(pe_info))
    time.sleep(1)

    # Step 9: Threat Intelligence
    print("[-] Gathering threat intelligence...")
    result.update(_get_threat_categories(file_hash, headers))
    time.sleep(1)
    result.update(_get_threat_collections(file_hash, headers))
    time.sleep(1)
    result.update(_get_mitre_attack_data(file_hash, headers))
    time.sleep(1)

    # Step 10: Historical Data
    print("[-] Getting submission history...")
    result.update(_get_submissions_history(file_hash, headers))
    time.sleep(1)
    result.update(_get_file_names_history(file_hash, headers))
    time.sleep(1)

    # Step 11: Risk Assessment
    print("[-] Calculating final risk assessment...")
    result = calculate_risk_assessment(result)
    result.update(_collect_specific_findings(result))

    print(f"[-] Analysis complete. Found {len(result)} data points")
    print(f"[-] Risk Assessment: {result.get('risk_level', 'UNKNOWN')} ({result.get('risk_score', 0)}/100)")
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