# Technical Implementation Guide: Aqua Security Report Filtering

This document provides technical details for developers and DevOps engineers who need to maintain or extend the Aqua Security report filtering solution.

## Architecture Overview

The solution consists of several Python scripts that form a processing pipeline:

```
Aqua Scan Reports → filter_aqua_reports.py → process_index_page.py → create_elegant_report.py → GitHub Pages
```

## Script Descriptions

### 1. `filter_aqua_reports.py` (Orchestration)

This script coordinates the filtering of Aqua Security reports.

**Key Components:**
- Command-line argument parsing
- Configuration management
- Ignored CVE detection and handling
- Coordinating the execution of other scripts

**Dependencies:**
- Standard Python libraries: `json`, `sys`, `os`, `argparse`, `logging`, `re`

**Extension Points:**
- Additional configuration sources can be added
- Pre/post processing steps can be integrated
- More extensive CVE management can be implemented

### 2. `process_index_page.py` (HTML Processing)

This script processes HTML reports to fix severity values and replace variables.

**Key Components:**
- HTML parsing with BeautifulSoup
- Variable substitution for ${GITHUB_SHA} and $(date)
- Severity mapping from CVE scores
- Severity badge updating
- Summary metrics recalculation
- Chart visualization improvement
- Title and header updating
- Detailed logging and metrics collection

**Dependencies:**
- BeautifulSoup4 (`bs4`) - External dependency
- Standard Python libraries: `re`, `os`, `sys`, `argparse`, `logging`, `json`

**Extension Points:**
- Support for additional variable substitutions
- Custom severity mapping rules
- Enhanced visualization components
- Support for different report formats

**Severity Mapping:**
```python
def map_severity_from_score(score_str):
    try:
        score = float(score_str)
        if score >= 9.0:
            return "Critical"
        elif score >= 7.0:
            return "High"
        elif score >= 4.0:
            return "Medium"
        elif score > 0.0:
            return "Low"
        else:
            return "Negligible"
    except (ValueError, TypeError):
        # If score can't be converted to float, return Medium as default
        return "Medium"
```

### 3. `create_elegant_report.py` (Enhanced Report Generation)

This script generates a modern, responsive HTML dashboard from filtered vulnerability data.

**Key Components:**
- Data aggregation for summary statistics
- HTML generation with embedded CSS
- Responsive design elements
- Severity-based color coding and visualization

**Dependencies:**
- Standard Python libraries: `json`, `os`, `sys`, `argparse`, `logging`, `datetime`

**Extension Points:**
- Dashboard components can be extended or customized
- Additional visualizations can be added
- The styling can be modified to match corporate design guidelines

### 4. `test_filtering.py` (Testing Module)

This script provides automated testing of the filtering and processing pipeline.

**Key Components:**
- Sample vulnerability data for filtering tests
- Test HTML generation
- Processing script execution and validation
- Severity mapping verification
- Variable substitution testing
- Output metrics validation

**Dependencies:**
- All dependencies from the other scripts
- Standard Python libraries: `subprocess`, `json`, `re`, `os`, `sys`, `logging`

**Extension Points:**
- Additional test cases can be added
- Performance testing can be integrated
- Coverage metrics can be implemented

## GitHub Actions Integration

The solution is integrated into the GitHub Actions workflow in `.github/workflows/main.yml`:

```yaml
filter_aqua_reports:
  runs-on: ubuntu-latest
  needs: aqua_scan
  if: always()  # This ensures the job runs even if aqua_scan fails
  steps:
    - name: Checkout code
      uses: actions/checkout@v4
    - name: Setup Python
      uses: actions/setup-python@v5
      with:
        python-version: '3.9'
    - name: Install dependencies
      run: pip install beautifulsoup4
    - name: Download Aqua Reports
      uses: actions/download-artifact@v4
      with:
        name: aqua-reports
        path: artifacts/
    - name: Filter ignored vulnerabilities
      run: |
        # Create a copy of the config file for reference
        cat > ci_scripts/ignored_cves_config.json << 'EOL'
        {
          "ignored_cves": [
            "CVE-2025-27789",
            "CVE-2024-45590"
          ],
          "comment": "These CVEs have been marked as ignored in the Aqua UI"
        }
        EOL
        
        # Use explicit CVE list to avoid any configuration issues
        python ci_scripts/filter_aqua_reports.py --input-dir artifacts --output-dir filtered-artifacts --ignored-cves CVE-2025-27789 CVE-2024-45590
    - name: Create elegant report
      run: python ci_scripts/create_elegant_report.py filtered-artifacts/aqua-scan-filtered.json filtered-artifacts/elegant-report.html
    - name: Upload Filtered Aqua Reports as Artifacts
      uses: actions/upload-artifact@v4
      with:
        name: aqua-filtered-reports
        path: filtered-artifacts/
```

```yaml
publish_to_gh_pages:
  runs-on: ubuntu-latest
  needs: record_metadata
  steps:
    # ... other steps ...
    - name: Create index page for reports
      run: |
        mkdir -p ./security-reports
        cat > ./security-reports/index.html << 'EOL'
        # HTML content for the index page
        EOL
        
        # Install required dependencies
        pip install beautifulsoup4 
        
        # Process the index.html file to replace variables
        python3 ci_scripts/process_index_page.py ./security-reports/index.html ./security-reports/index.html
    - name: Deploy to GitHub Pages
      uses: peaceiris/actions-gh-pages@v4
      with:
        github_token: ${{ secrets.CI_TOKEN }}
        publish_dir: ./security-reports
        publish_branch: gh-pages
        force_orphan: true
        commit_message: "Deploy security reports from ${{ github.sha }}"
```

## Dynamic Detection of Ignored Vulnerabilities

The solution automatically detects and filters out vulnerabilities that have been marked as ignored in the Aqua UI:

1. **Automatic Detection**: The system examines the JSON report to identify vulnerabilities with "ignored" status
2. **Environment Variables**: You can specify CVEs to ignore via the `AQUA_IGNORED_CVES` environment variable 
3. **Configuration File**: Support for a JSON configuration file with a list of ignored CVEs
4. **Command-line Arguments**: Direct specification of CVEs to ignore via command line

### Detection Methods

The system looks for several indicators in the JSON data to identify ignored vulnerabilities:

```python
# Look for standard Aqua indicators of ignored status
if (vuln.get('status') == 'ignored' or 
    vuln.get('compliance_status') == 'ignored' or
    vuln.get('is_ignored', False) == True or
    'ignored' in vuln.get('status_label', '').lower() or
    'ignored' in vuln.get('audit_status', '').lower()):
    
    if 'name' in vuln and vuln['name'].startswith('CVE-'):
        ignored_cves.append(vuln['name'])
```

## HTML Report Processing

The system processes HTML reports to fix severity values and replace variables:

### Variable Substitution

The `process_index_page.py` script replaces shell-style variables in the HTML report:

```python
# Replace shell-style variables
github_sha = os.environ.get('GITHUB_SHA', 'latest')
current_date = os.environ.get('BUILD_DATE', 
                             os.popen('date "+%Y-%m-%d %H:%M:%S"').read().strip())

vars_replaced = 0
html_content_new = re.sub(r'\${GITHUB_SHA}', github_sha, html_content)
if html_content_new != html_content:
    vars_replaced += 1
    html_content = html_content_new
    
html_content_new = re.sub(r'\$\(date\)', current_date, html_content)
if html_content_new != html_content:
    vars_replaced += 1
    html_content = html_content_new
```

### Severity Mapping

The script maps CVE scores to severity levels:

```python
# For table cells with severity "Unknown"
if severity_text == "Unknown":
    # For score 0 or non-numeric scores, default to Medium
    if not score_text or score_text == "0":
        new_severity = "Medium"
    else:
        new_severity = map_severity_from_score(score_text)
    
    # Update the text and class in the severity cell
    severity_span = severity_cell.find('span', class_='severity-badge')
    if severity_span:
        # Remove old class
        for cls in list(severity_span.get('class', [])):
            if cls != 'severity-badge':
                severity_span['class'].remove(cls)
        
        # Add new class and text
        severity_span['class'].append(new_severity.lower())
        severity_span.string = new_severity
```

### Summary Statistics

The script updates summary cards with accurate severity counts:

```python
# Update the summary card with our counts
paragraphs = card.find_all('p')
for p in paragraphs:
    text = p.get_text()
    if 'Critical:' in text:
        p.clear()
        p.append(soup.new_tag('strong'))
        p.strong.string = 'Critical:'
        p.append(f" {severity_counts['Critical']}")
```

### Chart Visualization

The script updates the severity chart with proper proportional widths:

```python
# Update the severity chart
chart_updated = False
total = sum(severity_counts.values())
chart = soup.find('div', class_='severity-chart')
if chart:
    critical_bar = chart.find('div', class_='severity-critical')
    high_bar = chart.find('div', class_='severity-high')
    # ...
    
    if critical_bar:
        critical_width = max(1, (severity_counts['Critical'] / max(1, total) * 100))
        critical_bar['style'] = f'width: {critical_width}%;'
        critical_bar.string = str(severity_counts['Critical'])
```

## Testing and Verification

The solution includes automated testing through `test_filtering.py`:

### Test Case Generation

```python
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
            /* ... */
        </style>
    </head>
    <body>
        <!-- Test HTML content with vulnerabilities -->
    </body>
    </html>
    """
    
    test_dir = "test-filtering"
    os.makedirs(test_dir, exist_ok=True)
    
    test_html_path = os.path.join(test_dir, "test_report.html")
    with open(test_html_path, "w", encoding="utf-8") as f:
        f.write(html)
    
    return test_html_path
```

### Process Execution

```python
def run_test():
    """Run tests on the process_index_page.py script."""
    test_html_path = create_test_html()
    output_html_path = os.path.join("test-filtering", "processed_report.html")
    
    # Run the processing script
    script_path = os.path.join("ci_scripts", "process_index_page.py")
    cmd = [sys.executable, script_path, test_html_path, output_html_path]
    
    process = subprocess.run(cmd, capture_output=True, text=True)
    
    # Check output and verify results
    # ...
```

### Verification

```python
# Check if severity values were updated
expected_mappings = {
    "CVE-2023-1234": "Critical",  # 9.8
    "CVE-2023-5678": "High",      # 8.2
    # ...
}

# Check if variables were replaced
if "${GITHUB_SHA}" in processed_html:
    logging.error("Variable ${GITHUB_SHA} was not replaced")
    success = False

# Check if title was updated
if "Elegant Security Report" in processed_html and "Curated Vulnerability Report" not in processed_html:
    logging.error("Title was not updated to 'Curated Vulnerability Report'")
    success = False
```

## Recent Improvements

The solution has received several recent improvements:

1. **Fixed Filtering Logic**: Corrected issues where ignored CVEs were being shown instead of removed
2. **Variable Substitution**: Added detection and replacement of shell variables in HTML reports
3. **Severity Mapping**: Implemented proper mapping from CVE scores to severity levels
4. **Metrics Calculation**: Fixed severity metrics to display actual counts instead of zeroes
5. **Chart Enhancements**: Updated severity chart to display proper proportional widths
6. **Title Update**: Changed title from "Elegant Security Report" to "Curated Vulnerability Report"
7. **Enhanced Logging**: Added detailed logging and metrics about changes made during processing
8. **Automated Testing**: Implemented comprehensive testing via test_filtering.py
9. **Process Metrics**: Added summary statistics about processing operations for debugging

## Deployment Requirements

- Python 3.9 or later
- BeautifulSoup4 library
- GitHub repository with Actions and Pages enabled
- Appropriate permissions for GitHub Pages publishing

## Local Testing

1. Generate Aqua Security scan reports
   ```bash
   mkdir -p test_artifacts
   cp path/to/aqua-scan.json test_artifacts/
   cp path/to/aqua-scan.html test_artifacts/
   ```

2. Run the filtering pipeline
   ```bash
   python ci_scripts/filter_aqua_reports.py --input-dir test_artifacts --output-dir filtered_test --ignored-cves CVE-2025-27789 CVE-2024-45590
   ```

3. Generate the elegant report
   ```bash
   python ci_scripts/create_elegant_report.py filtered_test/aqua-scan-filtered.json filtered_test/elegant-report.html
   ```

4. Process HTML reports
   ```bash
   python ci_scripts/process_index_page.py filtered_test/elegant-report.html filtered_test/processed-report.html
   ```

5. Run the automated tests
   ```bash
   python ci_scripts/test_filtering.py
   ```

## Troubleshooting

### Common Issues

**Issue**: HTML Parsing Failures
- **Symptom**: Error in BeautifulSoup processing
- **Solution**: Install the required dependencies: `pip install beautifulsoup4`

**Issue**: Variable Substitution Not Working
- **Symptom**: ${GITHUB_SHA} still appears in the processed report
- **Solution**: Ensure the GITHUB_SHA environment variable is set, or use the --set-vars flag

**Issue**: Incorrect Severity Counts
- **Symptom**: The severity counts still show 0 despite vulnerabilities being present
- **Solution**: Check that the severity mapping logic is working and that the HTML structure matches what's expected

**Issue**: Missing Filtered CVEs
- **Symptom**: Ignored CVEs still appear in the report
- **Solution**: Verify the ignored CVEs list is correct and the filtering script is being run with proper parameters

### Debugging

The `process_index_page.py` script provides a detailed processing summary:

```
==================================================
REPORT PROCESSING SUMMARY
==================================================
Variables replaced: 2
Severity values updated: 10
Summary metrics updated: 5
Chart updated: Yes
Title updated: Yes
Total vulnerabilities: 10
Severity distribution: Critical=2, High=2, Medium=3, Low=3, Negligible=0
==================================================
```

This summary helps identify whether each component of the processing pipeline is working as expected.

## Future Enhancements

Planned future enhancements for the solution include:

1. Support for additional Aqua Security report formats
2. Integration with other security scanning tools
3. More customizable reporting options
4. Enhanced severity mapping with configurable thresholds
5. API-based reporting for integration with other systems 