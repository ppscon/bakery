#!/usr/bin/env python3
import argparse
import logging
import os
import re
import sys
from bs4 import BeautifulSoup

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# List of CVEs that are marked as ignored in Aqua UI
IGNORED_CVES = [
    "CVE-2025-27789"  # This CVE has been marked as ignored in Aqua UI
]

def filter_html_report(input_file, output_file, ignored_cves=None):
    """
    Filter out ignored vulnerabilities from Aqua security HTML report.
    
    Args:
        input_file (str): Path to the original Aqua scan HTML report
        output_file (str): Path where the filtered report will be saved
        ignored_cves (list): List of CVE IDs that should be filtered out
    """
    if ignored_cves is None:
        ignored_cves = IGNORED_CVES
    
    try:
        with open(input_file, 'r', encoding='utf-8') as f:
            html_content = f.read()
        
        logging.info(f"Loaded HTML report from {input_file}")
        
        # Parse HTML
        soup = BeautifulSoup(html_content, 'html.parser')
        
        # Find vulnerability sections
        removed_count = 0
        for cve_id in ignored_cves:
            # Look for elements containing the CVE ID
            vulnerabilities = soup.find_all(string=re.compile(cve_id))
            
            for vuln in vulnerabilities:
                # Find the closest container element (likely a div or tr)
                container = vuln.find_parent(['div', 'tr', 'section', 'table'])
                if container:
                    container.decompose()  # Remove the element and its contents
                    removed_count += 1
        
        # Update any summary statistics if they exist
        summary_elements = soup.find_all(class_=re.compile("summary|total|count"))
        # This is a placeholder - actual implementation would depend on HTML structure
        
        # Write the filtered report
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(str(soup))
        
        # Copy CSS file if it exists
        css_file = os.path.join(os.path.dirname(input_file), 'styles.css')
        if os.path.exists(css_file):
            output_css = os.path.join(os.path.dirname(output_file), 'styles.css')
            with open(css_file, 'r', encoding='utf-8') as src, open(output_css, 'w', encoding='utf-8') as dst:
                dst.write(src.read())
        
        logging.info(f"Filtered out {removed_count} entries related to ignored vulnerabilities")
        logging.info(f"Filtered HTML report saved to {output_file}")
        
        return True
    
    except Exception as e:
        logging.error(f"Error processing HTML report: {str(e)}")
        return False

def main():
    parser = argparse.ArgumentParser(description='Filter ignored vulnerabilities from Aqua security HTML reports')
    parser.add_argument('input_file', help='Path to the original Aqua scan HTML report')
    parser.add_argument('output_file', help='Path where the filtered report will be saved')
    parser.add_argument('--ignored-cves', nargs='+', help='List of CVE IDs to filter out')
    
    args = parser.parse_args()
    
    ignored_cves = args.ignored_cves or IGNORED_CVES
    success = filter_html_report(args.input_file, args.output_file, ignored_cves)
    
    sys.exit(0 if success else 1)

if __name__ == "__main__":
    main() 