import csv
from datetime import datetime as dt
from pathlib import Path
import os

class VTReportCSV:
    def __init__(self, output_path: str):
        self.output_path = output_path
        self.rows = []
        self.headers = set()
        
    def add_file_data(self, file_path: str, vt_data: dict):
        """Add data for a single file's VirusTotal analysis."""
        file_name = os.path.basename(file_path)
        
        # Create a row dictionary with basic file info
        row = {
            'file_name': file_name,
            'file_path': file_path,
            'analysis_date': dt.now().strftime('%Y-%m-%d %H:%M:%S'),
            'risk_level': vt_data.get('risk_level', 'UNKNOWN'),
            'risk_score': vt_data.get('risk_score', 0)
        }
        
        # Add all data from vt_data to the row
        self._add_nested_dict_to_row('', vt_data, row)
        
        # Update headers with any new columns
        self.headers.update(row.keys())
        
        # Add the row to our data
        self.rows.append(row)

    def _add_nested_dict_to_row(self, prefix: str, data: dict, row: dict):
        """Recursively flatten nested dictionary into CSV columns."""
        for key, value in data.items():
            column_name = f"{prefix}_{key}" if prefix else key
            
            # Handle different types of values
            if isinstance(value, dict):
                self._add_nested_dict_to_row(column_name, value, row)
            elif isinstance(value, (list, set)):
                row[column_name] = '|'.join(str(x) for x in value)
            else:
                row[column_name] = value

    def save_report(self):
        """Save all data to a CSV file."""
        if not self.rows:
            print("No data to write to CSV.")
            return

        # Sort headers for consistent column order
        headers = sorted(list(self.headers))
        
        with open(self.output_path, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=headers)
            writer.writeheader()
            
            # Write all rows
            for row in self.rows:
                # Ensure all headers exist in each row
                for header in headers:
                    if header not in row:
                        row[header] = ''
                writer.writerow(row)
                
        print(f"CSV report saved to: {self.output_path}")

def create_vt_csv_report(vt_results: dict, output_path: str):
    """Create a CSV report from VirusTotal scan results."""
    report = VTReportCSV(output_path)
    
    for file_path, scan_data in vt_results.items():
        report.add_file_data(file_path, scan_data)
    
    report.save_report()