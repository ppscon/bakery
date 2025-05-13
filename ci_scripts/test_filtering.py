#!/usr/bin/env python3
import json
import os
import logging
import sys
import re

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Test filtering logic
def test_filtering():
    # Sample vulnerability data
    sample_data = {
        "resources": [
            {
                "vulnerabilities": [
                    {"name": "CVE-2025-27789", "description": "This is an ignored CVE"},
                    {"name": "CVE-2023-12345", "description": "This should be kept"},
                    {"name": "CVE-2024-45590", "description": "Another ignored CVE"}
                ]
            }
        ],
        "vulnerabilities": [
            {"name": "CVE-2025-27789", "description": "This is an ignored CVE"},
            {"name": "CVE-2022-56789", "description": "This should be kept"},
            {"name": "CVE-2024-45590", "description": "Another ignored CVE"}
        ]
    }
    
    # List of CVEs to ignore
    ignored_cves = ["CVE-2025-27789", "CVE-2024-45590"]
    
    logging.info(f"Starting test with {len(ignored_cves)} ignored CVEs: {', '.join(ignored_cves)}")
    logging.info(f"Initial sample data contains {len(sample_data['resources'][0]['vulnerabilities'])} resource vulnerabilities and {len(sample_data['vulnerabilities'])} direct vulnerabilities")
    
    # Track removed vulnerabilities
    removed_count = 0
    
    # Process resources section
    if 'resources' in sample_data:
        for resource in sample_data['resources']:
            if 'vulnerabilities' in resource:
                # Store original count
                original_count = len(resource['vulnerabilities'])
                
                # Filter out ignored vulnerabilities
                filtered_vulns = []
                for vuln in resource['vulnerabilities']:
                    if 'name' in vuln and any(re.match(f"{cve}", vuln['name'], re.IGNORECASE) for cve in ignored_cves):
                        removed_count += 1
                        logging.info(f"Filtering out resource vuln: {vuln['name']}")
                    else:
                        filtered_vulns.append(vuln)
                        logging.info(f"Keeping resource vuln: {vuln['name']}")
                
                # Replace with filtered list
                resource['vulnerabilities'] = filtered_vulns
                logging.info(f"After filtering: Resource has {len(resource['vulnerabilities'])} vulnerabilities (removed {original_count - len(resource['vulnerabilities'])})")
    
    # Process direct vulnerabilities array
    if 'vulnerabilities' in sample_data:
        original_count = len(sample_data['vulnerabilities'])
        
        filtered_vulns = []
        for vuln in sample_data['vulnerabilities']:
            if 'name' in vuln and any(re.match(f"{cve}", vuln['name'], re.IGNORECASE) for cve in ignored_cves):
                removed_count += 1
                logging.info(f"Filtering out direct vuln: {vuln['name']}")
            else:
                filtered_vulns.append(vuln)
                logging.info(f"Keeping direct vuln: {vuln['name']}")
        
        # Replace with filtered list
        sample_data['vulnerabilities'] = filtered_vulns
        logging.info(f"After filtering: Direct vulnerabilities: {len(sample_data['vulnerabilities'])} (removed {original_count - len(sample_data['vulnerabilities'])})")
    
    # Print the final filtered data
    logging.info(f"Total removed: {removed_count}")
    logging.info("Final filtered data:")
    logging.info(f"Resources vulnerabilities: {[v['name'] for r in sample_data['resources'] for v in r['vulnerabilities']]}")
    logging.info(f"Direct vulnerabilities: {[v['name'] for v in sample_data['vulnerabilities']]}")

    # Verify filtering worked correctly
    all_remaining_vulns = [v['name'] for r in sample_data['resources'] for v in r['vulnerabilities']] + [v['name'] for v in sample_data['vulnerabilities']]
    for cve in ignored_cves:
        if any(cve.lower() in vuln.lower() for vuln in all_remaining_vulns):
            logging.error(f"FAILED: {cve} was found in filtered results")
            return False
    
    for cve in ["CVE-2023-12345", "CVE-2022-56789"]:
        if not any(cve.lower() in vuln.lower() for vuln in all_remaining_vulns):
            logging.error(f"FAILED: {cve} was incorrectly removed")
            return False
            
    logging.info("SUCCESS: Filtering logic worked correctly!")
    return True

if __name__ == "__main__":
    successful = test_filtering()
    sys.exit(0 if successful else 1) 