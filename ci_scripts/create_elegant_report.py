#!/usr/bin/env python3
import json
import os
import sys
import argparse
import logging
from datetime import datetime

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def create_elegant_report(json_report_path, output_path):
    """
    Create an elegant HTML report from the filtered Aqua JSON report.
    
    Args:
        json_report_path (str): Path to the filtered JSON report
        output_path (str): Path where to save the elegant HTML report
    """
    try:
        with open(json_report_path, 'r') as f:
            report_data = json.load(f)
        
        logging.info(f"Loaded filtered JSON report from {json_report_path}")
        
        # Extract vulnerabilities for summary
        all_vulnerabilities = []
        total_critical = 0
        total_high = 0
        total_medium = 0
        total_low = 0
        
        # Process resources
        resources_with_vulnerabilities = []
        
        if 'resources' in report_data:
            for resource in report_data['resources']:
                if 'vulnerabilities' in resource and resource['vulnerabilities']:
                    # Count severities
                    for vuln in resource['vulnerabilities']:
                        all_vulnerabilities.append(vuln)
                        severity = vuln.get('aqua_severity', '').lower()
                        if severity == 'critical':
                            total_critical += 1
                        elif severity == 'high':
                            total_high += 1
                        elif severity == 'medium':
                            total_medium += 1
                        elif severity == 'low':
                            total_low += 1
                    
                    # Add to resources with vulnerabilities
                    resources_with_vulnerabilities.append(resource)
        
        # Process direct vulnerabilities if present
        if 'vulnerabilities' in report_data:
            for vuln in report_data['vulnerabilities']:
                all_vulnerabilities.append(vuln)
                severity = vuln.get('aqua_severity', '').lower()
                if severity == 'critical':
                    total_critical += 1
                elif severity == 'high':
                    total_high += 1
                elif severity == 'medium':
                    total_medium += 1
                elif severity == 'low':
                    total_low += 1
        
        # Generate HTML
        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Elegant Security Report - Filtered</title>
    <style>
        :root {{
            --primary-color: #2c3e50;
            --secondary-color: #3498db;
            --background-color: #f8f9fa;
            --card-background: white;
            --text-color: #333;
            --border-color: #e1e4e8;
            --critical-color: #e74c3c;
            --high-color: #e67e22;
            --medium-color: #f1c40f;
            --low-color: #2ecc71;
        }}
        
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            color: var(--text-color);
            background-color: var(--background-color);
            margin: 0;
            padding: 0;
        }}
        
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }}
        
        header {{
            background-color: var(--primary-color);
            color: white;
            padding: 20px 0;
            margin-bottom: 30px;
        }}
        
        header .container {{
            display: flex;
            justify-content: space-between;
            align-items: center;
        }}
        
        h1, h2, h3, h4 {{
            color: var(--primary-color);
            margin-top: 0;
        }}
        
        header h1 {{
            margin: 0;
            color: white;
        }}
        
        .summary-cards {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }}
        
        .card {{
            background-color: var(--card-background);
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1);
            padding: 20px;
            transition: transform 0.3s ease;
        }}
        
        .card:hover {{
            transform: translateY(-5px);
        }}
        
        .summary-card {{
            text-align: center;
            border-top: 4px solid var(--secondary-color);
        }}
        
        .summary-card.critical {{
            border-top-color: var(--critical-color);
        }}
        
        .summary-card.high {{
            border-top-color: var(--high-color);
        }}
        
        .summary-card.medium {{
            border-top-color: var(--medium-color);
        }}
        
        .summary-card.low {{
            border-top-color: var(--low-color);
        }}
        
        .summary-number {{
            font-size: 2.5rem;
            font-weight: bold;
            margin: 10px 0;
        }}
        
        .summary-card.critical .summary-number {{
            color: var(--critical-color);
        }}
        
        .summary-card.high .summary-number {{
            color: var(--high-color);
        }}
        
        .summary-card.medium .summary-number {{
            color: var(--medium-color);
        }}
        
        .summary-card.low .summary-number {{
            color: var(--low-color);
        }}
        
        .resource-section {{
            margin-bottom: 40px;
        }}
        
        table {{
            width: 100%;
            border-collapse: collapse;
            margin-bottom: 20px;
        }}
        
        th, td {{
            padding: 12px 15px;
            text-align: left;
            border-bottom: 1px solid var(--border-color);
        }}
        
        th {{
            background-color: var(--primary-color);
            color: white;
        }}
        
        tr:nth-child(even) {{
            background-color: rgba(0, 0, 0, 0.02);
        }}
        
        tr:hover {{
            background-color: rgba(0, 0, 0, 0.05);
        }}
        
        .badge {{
            display: inline-block;
            padding: 5px 10px;
            border-radius: 4px;
            color: white;
            font-size: 0.8rem;
            font-weight: bold;
        }}
        
        .badge-critical {{
            background-color: var(--critical-color);
        }}
        
        .badge-high {{
            background-color: var(--high-color);
        }}
        
        .badge-medium {{
            background-color: var(--medium-color);
        }}
        
        .badge-low {{
            background-color: var(--low-color);
        }}
        
        .badge-filtered {{
            background-color: #27ae60;
        }}
        
        .timestamp {{
            font-size: 0.9rem;
            color: #6c757d;
            margin-bottom: 30px;
        }}
        
        .filter-notice {{
            background-color: #e8f4f8;
            border-left: 4px solid #27ae60;
            padding: 15px;
            margin-bottom: 30px;
            border-radius: 4px;
        }}
        
        @media (max-width: 768px) {{
            .summary-cards {{
                grid-template-columns: 1fr 1fr;
            }}
        }}
        
        @media (max-width: 480px) {{
            .summary-cards {{
                grid-template-columns: 1fr;
            }}
        }}
    </style>
</head>
<body>
    <header>
        <div class="container">
            <h1>Aqua Security Scan Report</h1>
            <span class="badge badge-filtered">FILTERED</span>
        </div>
    </header>
    
    <div class="container">
        <div class="timestamp">
            Report generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
        </div>
        
        <div class="filter-notice">
            <strong>Filtered Report:</strong> This security report has been filtered to exclude CVEs that are marked as ignored.
        </div>
        
        <h2>Vulnerability Summary</h2>
        <div class="summary-cards">
            <div class="card summary-card critical">
                <h3>Critical</h3>
                <div class="summary-number">{total_critical}</div>
            </div>
            <div class="card summary-card high">
                <h3>High</h3>
                <div class="summary-number">{total_high}</div>
            </div>
            <div class="card summary-card medium">
                <h3>Medium</h3>
                <div class="summary-number">{total_medium}</div>
            </div>
            <div class="card summary-card low">
                <h3>Low</h3>
                <div class="summary-number">{total_low}</div>
            </div>
            <div class="card summary-card">
                <h3>Total</h3>
                <div class="summary-number">{len(all_vulnerabilities)}</div>
            </div>
        </div>
        
        <h2>Vulnerabilities by Resource</h2>
"""
        
        # Add vulnerabilities by resource
        for resource in resources_with_vulnerabilities:
            resource_name = resource.get('resource', {}).get('name', 'Unknown')
            resource_version = resource.get('resource', {}).get('version', 'N/A')
            
            html += f"""
        <div class="card resource-section">
            <h3>{resource_name} ({resource_version})</h3>
            <table>
                <thead>
                    <tr>
                        <th>CVE</th>
                        <th>Severity</th>
                        <th>CVSS Score</th>
                        <th>Affected Version</th>
                        <th>Fixed Version</th>
                    </tr>
                </thead>
                <tbody>
"""
            
            for vuln in resource.get('vulnerabilities', []):
                cve_id = vuln.get('name', 'N/A')
                severity = vuln.get('aqua_severity', 'N/A').lower()
                cvss_score = vuln.get('aqua_score', 'N/A')
                version = resource_version
                fix_version = vuln.get('fix_version', 'N/A')
                
                severity_class = f"badge-{severity}" if severity in ['critical', 'high', 'medium', 'low'] else ""
                
                html += f"""
                    <tr>
                        <td>{cve_id}</td>
                        <td><span class="badge {severity_class}">{severity.upper()}</span></td>
                        <td>{cvss_score}</td>
                        <td>{version}</td>
                        <td>{fix_version}</td>
                    </tr>
"""
            
            html += """
                </tbody>
            </table>
        </div>
"""
        
        # Close the HTML
        html += """
    </div>
</body>
</html>
"""
        
        # Write the elegant report
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html)
        
        logging.info(f"Created elegant HTML report at {output_path}")
        return True
        
    except Exception as e:
        logging.error(f"Error creating elegant report: {str(e)}")
        return False

def main():
    parser = argparse.ArgumentParser(description='Create an elegant HTML report from filtered Aqua scan data')
    parser.add_argument('json_report', help='Path to the filtered JSON report')
    parser.add_argument('output_path', help='Path where to save the elegant HTML report')
    
    args = parser.parse_args()
    success = create_elegant_report(args.json_report, args.output_path)
    
    sys.exit(0 if success else 1)

if __name__ == "__main__":
    main() 