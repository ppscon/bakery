#!/usr/bin/env python3
import json
import sys
import os
import argparse
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# List of CVEs that are marked as ignored in Aqua UI
IGNORED_CVES = [
    "CVE-2025-27789"  # This CVE has been marked as ignored in Aqua UI
]

def filter_ignored_vulnerabilities(input_file, output_file, ignored_cves=None):
    """
    Filter out ignored vulnerabilities from Aqua security scan reports.
    
    Args:
        input_file (str): Path to the original Aqua scan JSON report
        output_file (str): Path where the filtered report will be saved
        ignored_cves (list): List of CVE IDs that should be filtered out
    """
    if ignored_cves is None:
        ignored_cves = IGNORED_CVES
    
    try:
        with open(input_file, 'r') as f:
            scan_data = json.load(f)
        
        logging.info(f"Loaded scan report from {input_file}")
        
        # Track removed vulnerabilities
        removed_count = 0
        total_vulnerabilities = 0
        
        # Process resources with vulnerabilities
        if 'resources' in scan_data:
            for resource in scan_data['resources']:
                if 'vulnerabilities' in resource:
                    original_count = len(resource['vulnerabilities'])
                    total_vulnerabilities += original_count
                    
                    # Filter out ignored vulnerabilities
                    resource['vulnerabilities'] = [
                        vuln for vuln in resource['vulnerabilities']
                        if vuln.get('name') not in ignored_cves
                    ]
                    
                    removed_count += original_count - len(resource['vulnerabilities'])
        
        # Process direct vulnerabilities array if present
        if 'vulnerabilities' in scan_data:
            original_count = len(scan_data['vulnerabilities'])
            total_vulnerabilities += original_count
            
            scan_data['vulnerabilities'] = [
                vuln for vuln in scan_data['vulnerabilities']
                if vuln.get('name') not in ignored_cves
            ]
            
            removed_count += original_count - len(scan_data['vulnerabilities'])
        
        # Update summary counts if they exist
        if 'vulnerability_summary' in scan_data:
            # This would need to be adjusted based on actual structure
            pass
        
        # Write the filtered report
        with open(output_file, 'w') as f:
            json.dump(scan_data, f, indent=2)
        
        logging.info(f"Filtered out {removed_count} ignored vulnerabilities from a total of {total_vulnerabilities}")
        logging.info(f"Filtered report saved to {output_file}")
        
        return True
    
    except Exception as e:
        logging.error(f"Error processing report: {str(e)}")
        return False

def main():
    parser = argparse.ArgumentParser(description='Filter ignored vulnerabilities from Aqua security scan reports')
    parser.add_argument('input_file', help='Path to the original Aqua scan JSON report')
    parser.add_argument('output_file', help='Path where the filtered report will be saved')
    parser.add_argument('--ignored-cves', nargs='+', help='List of CVE IDs to filter out')
    
    args = parser.parse_args()
    
    ignored_cves = args.ignored_cves or IGNORED_CVES
    success = filter_ignored_vulnerabilities(args.input_file, args.output_file, ignored_cves)
    
    sys.exit(0 if success else 1)

if __name__ == "__main__":
    main() 