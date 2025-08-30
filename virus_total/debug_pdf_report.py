#!/usr/bin/env python3
"""
Debug script to show what data is being included in PDF reports
"""

from virus_total.upload_exe import comprehensive_virustotal_analysis
from virus_total.pdf_report import create_vt_pdf_report

def debug_pdf_data(file_path, api_key):
    """Debug function to show what data will be included in PDF"""
    print(f"Analyzing {file_path}...")
    result = comprehensive_virustotal_analysis(file_path, api_key)
    
    print(f"\nTotal data points: {len(result)}")
    
    # Define the sections as they appear in PDF
    sections = {
        "Basic Information": [
            ("file_path", "File Path"),
            ("file_size_bytes", "File Size (bytes)"),
            ("file_type", "File Type"),
            ("file_hash_sha256", "SHA256 Hash"),
            ("file_hash_md5", "MD5 Hash"),
            ("file_hash_sha1", "SHA1 Hash"),
        ],
        "Detection Results": [
            ("malicious_count", "Malicious Detections"),
            ("suspicious_count", "Suspicious Detections"),
            ("harmless_count", "Harmless Detections"),
            ("undetected_count", "Undetected"),
            ("total_engines", "Total Engines"),
            ("detection_percentage", "Detection Percentage"),
            ("failure_count", "Failure Count"),
            ("risk_level", "Risk Level"),
            ("risk_score", "Risk Score"),
        ],
        "Community Intelligence": [
            ("comments_count", "Comments Count"),
            ("community_malicious_votes", "Community Malicious Votes"),
            ("community_harmless_votes", "Community Harmless Votes"),
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
        ],
        "Analysis Summary": [
            ("threat_indicators_count", "Total Threat Indicators"),
            ("threat_indicators_summary", "Threat Indicators Summary"),
            ("detection_rate_percentage", "Detection Rate (%)"),
            ("analysis_confidence", "Analysis Confidence"),
            ("analysis_conclusion", "Analysis Conclusion"),
        ]
    }
    
    print("\n=== PDF SECTION ANALYSIS ===")
    for section_title, fields in sections.items():
        print(f"\n--- {section_title} ---")
        
        # Check if section has any meaningful data
        has_data = any(result.get(field[0]) not in [None, "", "N/A"] for field in fields)
        print(f"Section has data: {has_data}")
        
        for field_key, field_label in fields:
            value = result.get(field_key, "N/A")
            
            # Show what would be included/excluded
            will_include = value not in [None, ""]
            print(f"  {field_label}: {value} -> {'INCLUDE' if will_include else 'SKIP'}")
    
    # Generate the actual PDF
    results = {file_path: result}
    pdf_filename = f"debug_{file_path.replace('.', '_').replace('/', '_')}_report.pdf"
    create_vt_pdf_report(results, pdf_filename)
    print(f"\nPDF generated: {pdf_filename}")

if __name__ == "__main__":
    api_key = "d663e661563ec1b91a40086b3506645fd6af544eecf25fe59027dd5940e20532"
    debug_pdf_data("upx.exe", api_key)
