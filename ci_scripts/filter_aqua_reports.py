#!/usr/bin/env python3
import argparse
import logging
import os
import sys
import subprocess
import shutil

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

def filter_reports(input_dir, output_dir, ignored_cves=None):
    """
    Filter both JSON and HTML Aqua security reports to remove ignored vulnerabilities.
    
    Args:
        input_dir (str): Directory containing the original Aqua scan reports
        output_dir (str): Directory where filtered reports will be saved
        ignored_cves (list): List of CVE IDs to filter out
    """
    # Create output directory if it doesn't exist
    os.makedirs(output_dir, exist_ok=True)
    
    # Path to the input files
    json_input = os.path.join(input_dir, 'aqua-scan.json')
    html_input = os.path.join(input_dir, 'aqua-scan.html')
    
    # Path to the output files
    json_output = os.path.join(output_dir, 'aqua-scan-filtered.json')
    html_output = os.path.join(output_dir, 'aqua-scan-filtered.html')
    
    # Check if BeautifulSoup is installed for HTML filtering
    try:
        import importlib
        importlib.import_module('bs4')
        html_support = True
    except ImportError:
        logging.warning("BeautifulSoup not installed. HTML filtering will be skipped.")
        logging.warning("Install with: pip install beautifulsoup4")
        html_support = False
    
    # Filter JSON report
    try:
        # Import the filter_ignored_vulnerabilities function
        from filter_ignored_vulnerabilities import filter_ignored_vulnerabilities
        
        if os.path.exists(json_input):
            logging.info(f"Filtering JSON report from {json_input}")
            result = filter_ignored_vulnerabilities(json_input, json_output, ignored_cves)
            if result:
                logging.info(f"Successfully filtered JSON report to {json_output}")
            else:
                logging.error("Failed to filter JSON report")
        else:
            logging.warning(f"JSON report not found at {json_input}")
    except ImportError:
        logging.error("Could not import filter_ignored_vulnerabilities module")
        return False
    
    # Filter HTML report
    if html_support:
        try:
            # Import the filter_html_report function
            from filter_html_report import filter_html_report
            
            if os.path.exists(html_input):
                logging.info(f"Filtering HTML report from {html_input}")
                result = filter_html_report(html_input, html_output, ignored_cves)
                if result:
                    logging.info(f"Successfully filtered HTML report to {html_output}")
                else:
                    logging.error("Failed to filter HTML report")
            else:
                logging.warning(f"HTML report not found at {html_input}")
        except ImportError:
            logging.error("Could not import filter_html_report module")
            return False
    
    # Copy any other files (e.g., styles.css)
    css_input = os.path.join(input_dir, 'styles.css')
    css_output = os.path.join(output_dir, 'styles.css')
    if os.path.exists(css_input) and not os.path.exists(css_output):
        shutil.copy2(css_input, css_output)
        logging.info(f"Copied styles.css to {css_output}")
    
    return True

def main():
    parser = argparse.ArgumentParser(description='Filter Aqua security reports to remove ignored vulnerabilities')
    parser.add_argument('--input-dir', default='artifacts', help='Directory containing the original Aqua scan reports')
    parser.add_argument('--output-dir', default='filtered-artifacts', help='Directory where filtered reports will be saved')
    parser.add_argument('--ignored-cves', nargs='+', help='List of CVE IDs to filter out')
    
    args = parser.parse_args()
    
    success = filter_reports(args.input_dir, args.output_dir, args.ignored_cves)
    
    sys.exit(0 if success else 1)

if __name__ == "__main__":
    main() 