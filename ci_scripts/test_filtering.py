#!/usr/bin/env python3
import json
import os
import logging
import sys
import re
import subprocess

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
                    if 'name' in vuln and any(re.match(f"^{re.escape(cve)}$", vuln['name'], re.IGNORECASE) for cve in ignored_cves):
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
            if 'name' in vuln and any(re.match(f"^{re.escape(cve)}$", vuln['name'], re.IGNORECASE) for cve in ignored_cves):
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

def create_test_html():
    """Create a test HTML file with known vulnerability data for testing."""
    html = """
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Elegant Security Report</title>
        <style>
            body {
                font-family: 'Segoe UI', Arial, sans-serif;
                line-height: 1.6;
                color: #333;
                background-color: #f8f9fa;
                margin: 0;
                padding: 20px;
            }
            .container {
                max-width: 1200px;
                margin: 0 auto;
                background: white;
                padding: 20px;
                box-shadow: 0 0 10px rgba(0,0,0,0.1);
                border-radius: 5px;
            }
            h1, h2, h3 {
                color: #2c3e50;
            }
            h1 {
                border-bottom: 2px solid #3498db;
                padding-bottom: 10px;
            }
            .summary {
                display: flex;
                flex-wrap: wrap;
                gap: 15px;
                margin: 20px 0;
            }
            .summary-card {
                flex: 1;
                min-width: 180px;
                background: #f1f8ff;
                border-left: 4px solid #3498db;
                padding: 15px;
                border-radius: 3px;
            }
            .severity-chart {
                display: flex;
                height: 30px;
                border-radius: 4px;
                overflow: hidden;
                margin: 20px 0;
            }
            .severity-critical {
                background-color: #d9534f;
                color: white;
                text-align: center;
            }
            .severity-high {
                background-color: #f0ad4e;
                color: white;
                text-align: center;
            }
            .severity-medium {
                background-color: #5bc0de;
                color: white;
                text-align: center;
            }
            .severity-low {
                background-color: #5cb85c;
                color: white;
                text-align: center;
            }
            .severity-negligible {
                background-color: #777;
                color: white;
                text-align: center;
            }
            table {
                width: 100%;
                border-collapse: collapse;
                margin: 20px 0;
            }
            th, td {
                padding: 12px 15px;
                text-align: left;
                border-bottom: 1px solid #ddd;
            }
            th {
                background-color: #f2f2f2;
                font-weight: bold;
            }
            tr:hover {
                background-color: #f5f5f5;
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
            .cve-id {
                font-family: monospace;
                padding: 2px 4px;
                background: #eee;
                border-radius: 3px;
            }
            .severity-badge {
                display: inline-block;
                padding: 3px 8px;
                border-radius: 3px;
                font-size: 0.8em;
                color: white;
            }
            .severity-badge.critical {
                background-color: #d9534f;
            }
            .severity-badge.high {
                background-color: #f0ad4e;
            }
            .severity-badge.medium {
                background-color: #5bc0de;
            }
            .severity-badge.low {
                background-color: #5cb85c;
            }
            .severity-badge.negligible {
                background-color: #777;
            }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>
                <span class="filtered-badge">Filtered</span>
                Elegant Security Report
            </h1>
            
            <div class="summary">
                <div class="summary-card">
                    <h3>Scan Overview</h3>
                    <p><strong>Scan Date:</strong> ${GITHUB_SHA}</p>
                    <p><strong>Total Vulnerabilities:</strong> 10</p>
                    <p><strong>Unique CVEs:</strong> 10</p>
                </div>
                
                <div class="summary-card">
                    <h3>Severity Distribution</h3>
                    <p><strong>Critical:</strong> 0</p>
                    <p><strong>High:</strong> 0</p>
                    <p><strong>Medium:</strong> 0</p>
                    <p><strong>Low:</strong> 0</p>
                    <p><strong>Negligible:</strong> 0</p>
                </div>
            </div>
            
            <div class="severity-chart">
                <div class="severity-critical" style="width: 1%;">
                    0
                </div>
                <div class="severity-high" style="width: 1%;">
                    0
                </div>
                <div class="severity-medium" style="width: 1%;">
                    0
                </div>
                <div class="severity-low" style="width: 1%;">
                    0
                </div>
                <div class="severity-negligible" style="width: 1%;">
                    0
                </div>
            </div>
            
            <h2>Package Vulnerabilities</h2>
            <table>
                <thead>
                    <tr>
                        <th>Package</th>
                        <th>Path</th>
                        <th>Version</th>
                        <th>CVE / Vulnerability</th>
                        <th>Severity</th>
                        <th>Score</th>
                        <th>Fix Version</th>
                    </tr>
                </thead>
                <tbody>
                    <tr>
                        <td>package1</td>
                        <td>/path/to/package1</td>
                        <td>1.0.0</td>
                        <td>
                            <span class="cve-id">CVE-2023-1234</span>
                            <div style="font-size: 0.9em; color: #666;">Critical vulnerability in package1</div>
                        </td>
                        <td><span class="severity-badge unknown">Unknown</span></td>
                        <td>9.8</td>
                        <td>1.0.1</td>
                    </tr>
                    <tr>
                        <td>package2</td>
                        <td>/path/to/package2</td>
                        <td>2.0.0</td>
                        <td>
                            <span class="cve-id">CVE-2023-5678</span>
                            <div style="font-size: 0.9em; color: #666;">High severity vulnerability</div>
                        </td>
                        <td><span class="severity-badge unknown">Unknown</span></td>
                        <td>8.2</td>
                        <td>2.0.1</td>
                    </tr>
                    <tr>
                        <td>package3</td>
                        <td>/path/to/package3</td>
                        <td>3.0.0</td>
                        <td>
                            <span class="cve-id">CVE-2023-9012</span>
                            <div style="font-size: 0.9em; color: #666;">Medium severity vulnerability</div>
                        </td>
                        <td><span class="severity-badge unknown">Unknown</span></td>
                        <td>6.5</td>
                        <td>3.0.1</td>
                    </tr>
                    <tr>
                        <td>package4</td>
                        <td>/path/to/package4</td>
                        <td>4.0.0</td>
                        <td>
                            <span class="cve-id">CVE-2023-3456</span>
                            <div style="font-size: 0.9em; color: #666;">Low severity vulnerability</div>
                        </td>
                        <td><span class="severity-badge unknown">Unknown</span></td>
                        <td>3.2</td>
                        <td>4.0.1</td>
                    </tr>
                    <tr>
                        <td>package5</td>
                        <td>/path/to/package5</td>
                        <td>5.0.0</td>
                        <td>
                            <span class="cve-id">CVE-2023-7890</span>
                            <div style="font-size: 0.9em; color: #666;">Negligible severity vulnerability</div>
                        </td>
                        <td><span class="severity-badge unknown">Unknown</span></td>
                        <td>0.1</td>
                        <td>5.0.1</td>
                    </tr>
                    <tr>
                        <td>package6</td>
                        <td>/path/to/package6</td>
                        <td>6.0.0</td>
                        <td>
                            <span class="cve-id">CVE-2023-9999</span>
                            <div style="font-size: 0.9em; color: #666;">Critical vulnerability in package6</div>
                        </td>
                        <td><span class="severity-badge unknown">Unknown</span></td>
                        <td>9.1</td>
                        <td>6.0.1</td>
                    </tr>
                    <tr>
                        <td>package7</td>
                        <td>/path/to/package7</td>
                        <td>7.0.0</td>
                        <td>
                            <span class="cve-id">CVE-2023-8888</span>
                            <div style="font-size: 0.9em; color: #666;">High severity vulnerability</div>
                        </td>
                        <td><span class="severity-badge unknown">Unknown</span></td>
                        <td>7.2</td>
                        <td>7.0.1</td>
                    </tr>
                    <tr>
                        <td>package8</td>
                        <td>/path/to/package8</td>
                        <td>8.0.0</td>
                        <td>
                            <span class="cve-id">CVE-2023-7777</span>
                            <div style="font-size: 0.9em; color: #666;">Medium severity vulnerability</div>
                        </td>
                        <td><span class="severity-badge unknown">Unknown</span></td>
                        <td>5.5</td>
                        <td>8.0.1</td>
                    </tr>
                    <tr>
                        <td>package9</td>
                        <td>/path/to/package9</td>
                        <td>9.0.0</td>
                        <td>
                            <span class="cve-id">CVE-2023-6666</span>
                            <div style="font-size: 0.9em; color: #666;">Low severity vulnerability</div>
                        </td>
                        <td><span class="severity-badge unknown">Unknown</span></td>
                        <td>2.9</td>
                        <td>9.0.1</td>
                    </tr>
                    <tr>
                        <td>package10</td>
                        <td>/path/to/package10</td>
                        <td>10.0.0</td>
                        <td>
                            <span class="cve-id">CVE-2023-5555</span>
                            <div style="font-size: 0.9em; color: #666;">Unknown severity vulnerability</div>
                        </td>
                        <td><span class="severity-badge unknown">Unknown</span></td>
                        <td>0</td>
                        <td>10.0.1</td>
                    </tr>
                </tbody>
            </table>
        </div>
    </body>
    </html>
    """
    
    test_dir = "test-filtering"
    os.makedirs(test_dir, exist_ok=True)
    
    test_html_path = os.path.join(test_dir, "test_report.html")
    with open(test_html_path, "w", encoding="utf-8") as f:
        f.write(html)
    
    logging.info(f"Created test HTML file at {test_html_path}")
    return test_html_path

def run_test():
    """Run tests on the process_index_page.py script."""
    test_html_path = create_test_html()
    output_html_path = os.path.join("test-filtering", "processed_report.html")
    
    # Run the processing script
    script_path = os.path.join("ci_scripts", "process_index_page.py")
    cmd = [sys.executable, script_path, test_html_path, output_html_path]
    
    logging.info(f"Running command: {' '.join(cmd)}")
    process = subprocess.run(cmd, capture_output=True, text=True)
    
    if process.returncode != 0:
        logging.error(f"Error running process_index_page.py: {process.stderr}")
        return False
    
    logging.info(f"Script output:\n{process.stdout}")
    
    # Parse the summary output to verify metrics
    metrics = {}
    if "REPORT PROCESSING SUMMARY" in process.stdout:
        logging.info("Found processing summary in output")
        for line in process.stdout.split('\n'):
            if ':' in line:
                key, value = line.split(':', 1)
                metrics[key.strip()] = value.strip()
    
    if metrics:
        logging.info(f"Extracted metrics from output: {metrics}")
    
    # Verify the results
    with open(output_html_path, "r", encoding="utf-8") as f:
        processed_html = f.read()
    
    # Check if severity values were updated
    expected_mappings = {
        "CVE-2023-1234": "Critical",  # 9.8
        "CVE-2023-5678": "High",      # 8.2
        "CVE-2023-9012": "Medium",    # 6.5
        "CVE-2023-3456": "Low",       # 3.2
        "CVE-2023-7890": "Low",       # 0.1
        "CVE-2023-9999": "Critical",  # 9.1
        "CVE-2023-8888": "High",      # 7.2
        "CVE-2023-7777": "Medium",    # 5.5
        "CVE-2023-6666": "Low",       # 2.9
        "CVE-2023-5555": "Medium",    # 0 (should use default)
    }
    
    success = True
    
    # Check if variables were replaced
    if "${GITHUB_SHA}" in processed_html:
        logging.error("Variable ${GITHUB_SHA} was not replaced")
        success = False
    
    # Check if title was updated
    if "Elegant Security Report" in processed_html and "Curated Vulnerability Report" not in processed_html:
        logging.error("Title was not updated to 'Curated Vulnerability Report'")
        success = False
    
    # Write a summary file
    summary_path = os.path.join("test-filtering", "test_summary.txt")
    with open(summary_path, "w", encoding="utf-8") as f:
        f.write("SEVERITY MAPPING TEST RESULTS\n")
        f.write("===========================\n\n")
        
        for cve, expected_severity in expected_mappings.items():
            if f'<span class="cve-id">{cve}</span>' in processed_html:
                if f'<span class="severity-badge {expected_severity.lower()}">{expected_severity}</span>' in processed_html:
                    f.write(f"✅ {cve}: Correctly mapped to {expected_severity}\n")
                else:
                    f.write(f"❌ {cve}: Not correctly mapped to {expected_severity}\n")
                    success = False
            else:
                f.write(f"❓ {cve}: Not found in processed HTML\n")
                success = False
        
        # Check summary metrics
        expected_counts = {
            "Critical": 2,
            "High": 2,
            "Medium": 3,  # Including the one with score 0 that defaults to Medium
            "Low": 3,
            "Negligible": 0  # Our implementation maps 0.1 to Low, not Negligible
        }
        
        f.write("\nSUMMARY METRICS\n")
        f.write("===============\n\n")
        
        for severity, count in expected_counts.items():
            pattern = f'<strong>{severity}:</strong> {count}'
            if pattern in processed_html:
                f.write(f"✅ {severity} count correctly updated to {count}\n")
            else:
                f.write(f"❌ {severity} count not updated correctly\n")
                success = False
        
        f.write("\nPROCESSING SUMMARY\n")
        f.write("=================\n\n")
        if metrics:
            # Check metrics from script output
            f.write("Script output metrics:\n")
            for key, value in metrics.items():
                f.write(f"- {key}: {value}\n")
            
            if "Variables replaced" in metrics and int(metrics.get("Variables replaced", "0")) > 0:
                f.write("✅ Variables were successfully replaced\n")
            else:
                f.write("❌ Variables replacement tracking failed\n")
                
            if "Total vulnerabilities" in metrics and int(metrics.get("Total vulnerabilities", "0")) == sum(expected_counts.values()):
                f.write(f"✅ Total vulnerability count matches expected: {sum(expected_counts.values())}\n")
            else:
                f.write(f"❌ Total vulnerability count mismatch. Expected: {sum(expected_counts.values())}, Got: {metrics.get('Total vulnerabilities', 'N/A')}\n")
        else:
            f.write("❌ No processing metrics found in script output\n")
            
        f.write("\nOVERALL RESULT\n")
        f.write("=============\n\n")
        f.write("✅ Test passed\n" if success else "❌ Test failed\n")
    
    logging.info(f"Test {'passed' if success else 'failed'}. See {summary_path} for details.")
    return success

if __name__ == "__main__":
    success = run_test()
    sys.exit(0 if success else 1) 