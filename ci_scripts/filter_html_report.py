#!/usr/bin/env python3
import argparse
import logging
import os
import re
import sys
import json
from bs4 import BeautifulSoup

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Example CVEs for testing - this should not be used in production
# Instead, we'll use the same dynamic approach as in filter_ignored_vulnerabilities.py
EXAMPLE_IGNORED_CVES = [
    "CVE-2025-27789"
]

def filter_html_report(input_file, output_file, ignored_cves=None):
    """
    Filter out ignored vulnerabilities from Aqua security HTML report.
    
    Args:
        input_file (str): Path to the original Aqua scan HTML report
        output_file (str): Path where the filtered report will be saved
        ignored_cves (list): List of CVE IDs that should be filtered out
    """
    try:
        with open(input_file, 'r', encoding='utf-8') as f:
            html_content = f.read()
        
        logging.info(f"Loaded HTML report from {input_file}")
        
        # If ignored_cves not provided, try to get them from environment or JSON report
        if ignored_cves is None or len(ignored_cves) == 0:
            # First try environment variables
            env_ignored = os.environ.get('AQUA_IGNORED_CVES', '')
            if env_ignored:
                ignored_cves = [cve.strip() for cve in env_ignored.split(',')]
                logging.info(f"Using {len(ignored_cves)} ignored CVEs from environment variable")
            else:
                # Try to find corresponding JSON report to extract ignored CVEs
                json_report_path = os.path.join(os.path.dirname(input_file), 
                                               os.path.basename(input_file).replace('.html', '.json'))
                
                if os.path.exists(json_report_path):
                    try:
                        # Import the function to avoid code duplication
                        sys.path.append(os.path.dirname(os.path.abspath(__file__)))
                        from filter_ignored_vulnerabilities import find_ignored_vulnerabilities_in_report
                        
                        with open(json_report_path, 'r') as f:
                            scan_data = json.load(f)
                        
                        ignored_cves = find_ignored_vulnerabilities_in_report(scan_data)
                        logging.info(f"Extracted {len(ignored_cves)} ignored CVEs from JSON report")
                    except Exception as e:
                        logging.warning(f"Could not extract ignored CVEs from JSON report: {str(e)}")
        
        # Fallback to example CVEs if we still have none
        if ignored_cves is None or len(ignored_cves) == 0:
            ignored_cves = []
            logging.warning("No ignored CVEs found from any source. Report will remain unchanged.")
            
        # Parse HTML
        soup = BeautifulSoup(html_content, 'html.parser')
        
        # Find vulnerability sections - more targeted approach
        removed_count = 0
        for cve_id in ignored_cves:
            # Look for table rows containing the CVE ID
            vuln_rows = soup.find_all('tr', string=lambda text: text and cve_id in text)
            
            # If no rows found, look for any elements containing the CVE ID
            if not vuln_rows:
                # First try to find td elements containing the CVE
                vuln_cells = soup.find_all('td', string=lambda text: text and cve_id in text)
                for cell in vuln_cells:
                    row = cell.find_parent('tr')
                    if row:
                        row.decompose()
                        removed_count += 1
                
                # Then look for any text containing the CVE
                vuln_elements = soup.find_all(string=lambda text: text and cve_id in text)
                for element in vuln_elements:
                    # Try to find the closest parent element that would represent a whole vulnerability entry
                    container = element.find_parent(['div', 'tr', 'section', 'table', 'li'])
                    if container:
                        container.decompose()
                        removed_count += 1
        
        # Update summary statistics if they exist
        # Look for elements with numeric content that might be counts
        count_elements = soup.find_all(string=re.compile(r'\b\d+\b'))
        for element in count_elements:
            # Only modify elements that look like they contain just a number
            if re.match(r'^\s*\d+\s*$', element.strip()):
                parent = element.parent
                if parent and ('total' in str(parent).lower() or 'count' in str(parent).lower() or 'summary' in str(parent).lower()):
                    # This is likely a count element - we could update it, but we'll leave it for now
                    pass
                
        # Add a "Filtered Report" notice to the report
        if soup.head:
            # Add custom styling
            style_tag = soup.new_tag('style')
            style_tag.string = """
            .filtered-notice {
                background-color: #f8f9fa;
                border-left: 4px solid #28a745;
                padding: 10px 15px;
                margin: 20px 0;
                border-radius: 3px;
                font-family: Arial, sans-serif;
            }
            .filtered-badge {
                display: inline-block;
                background-color: #28a745;
                color: white;
                padding: 3px 8px;
                border-radius: 3px;
                font-size: 0.8em;
                margin-right: 8px;
            }
            """
            soup.head.append(style_tag)
        
        # Add a notice at the top of the body that this is a filtered report
        if soup.body:
            notice_div = soup.new_tag('div')
            notice_div['class'] = 'filtered-notice'
            
            badge_span = soup.new_tag('span')
            badge_span['class'] = 'filtered-badge'
            badge_span.string = 'FILTERED'
            
            notice_div.append(badge_span)
            notice_div.append(' This report has been filtered to exclude ignored vulnerabilities')
            
            # Add details of removed CVEs
            if removed_count > 0:
                cve_list = soup.new_tag('p')
                cve_list.string = f"Removed {removed_count} entries related to ignored vulnerabilities: {', '.join(ignored_cves)}"
                notice_div.append(cve_list)
            
            # Insert at the beginning of the body
            soup.body.insert(0, notice_div)
        
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
    parser.add_argument('--config-file', help='Path to a configuration file containing ignored CVEs')
    
    args = parser.parse_args()
    
    ignored_cves = []
    
    # If config file is provided, read ignored CVEs from it
    if args.config_file and os.path.exists(args.config_file):
        try:
            with open(args.config_file, 'r') as f:
                config = json.load(f)
                if 'ignored_cves' in config:
                    ignored_cves = config['ignored_cves']
                    logging.info(f"Loaded {len(ignored_cves)} ignored CVEs from config file")
        except Exception as e:
            logging.error(f"Error loading config file: {str(e)}")
    
    # Command-line arguments take precedence
    if args.ignored_cves:
        ignored_cves = args.ignored_cves
        logging.info(f"Using {len(ignored_cves)} ignored CVEs from command line arguments")
    
    success = filter_html_report(args.input_file, args.output_file, ignored_cves)
    
    sys.exit(0 if success else 1)

if __name__ == "__main__":
    main() 