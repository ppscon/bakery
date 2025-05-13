# Technical Implementation Guide: Aqua Security Report Filtering

This document provides technical details for developers and DevOps engineers who need to maintain or extend the Aqua Security report filtering solution.

## Architecture Overview

The solution consists of three Python scripts that form a processing pipeline:

```
Aqua Scan Reports → filter_ignored_vulnerabilities.py → filter_html_report.py → create_elegant_report.py → GitHub Pages
```

## Script Descriptions

### 1. `filter_ignored_vulnerabilities.py` (JSON Processing)

This script processes the JSON report from Aqua Security to remove ignored vulnerabilities.

**Key Components:**
- JSON parsing and manipulation
- Dynamic detection of ignored vulnerabilities from report metadata
- List-based filtering of vulnerability objects
- Command-line argument parsing
- Logging for operational visibility

**Dependencies:**
- Standard Python libraries: `json`, `sys`, `os`, `argparse`, `logging`, `re`

**Extension Points:**
- The vulnerability detection logic can be enhanced to handle different Aqua Security report formats
- The filtering logic can be enhanced to use other attributes (beyond name/CVE ID)
- Summary statistics recalculation can be implemented based on report structure

### 2. `filter_html_report.py` (HTML Processing)

This script processes the HTML report to remove ignored vulnerabilities and enhance presentation.

**Key Components:**
- HTML parsing with BeautifulSoup
- DOM manipulation to remove elements
- Integration with JSON filtering to ensure consistent handling of ignored CVEs
- CSS styling additions for visual indicators
- Regex-based element selection

**Dependencies:**
- BeautifulSoup4 (`bs4`) - External dependency
- Standard Python libraries: `re`, `os`, `sys`, `argparse`, `logging`, `json`

**Extension Points:**
- The element selection strategy can be refined based on HTML structure
- The styling and notification elements can be customized
- Additional summary statistics can be updated

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

### 4. `filter_aqua_reports.py` (Wrapper Script)

This script provides a unified interface for the filtering pipeline.

**Key Components:**
- Process coordination
- Input/output path management
- Automatic ignored CVE detection coordination
- Dependency checking
- Single-command operation for the entire pipeline

**Dependencies:**
- All dependencies from the individual scripts
- Imports the other scripts as modules

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
      run: python ci_scripts/filter_aqua_reports.py --input-dir artifacts --output-dir filtered-artifacts
    - name: Create elegant report
      run: python ci_scripts/create_elegant_report.py filtered-artifacts/aqua-scan-filtered.json filtered-artifacts/elegant-report.html
    - name: Upload Filtered Aqua Reports as Artifacts
      uses: actions/upload-artifact@v4
      with:
        name: aqua-filtered-reports
        path: filtered-artifacts/
```

## Dynamic Detection of Ignored Vulnerabilities

The solution now automatically detects and filters out vulnerabilities that have been marked as ignored in the Aqua UI:

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

### Using a Configuration File

You can create a JSON configuration file to specify CVEs to ignore:

```json
{
  "ignored_cves": [
    "CVE-2025-27789",
    "CVE-2023-12345",
    "CVE-2024-56789"
  ]
}
```

Then run the filtering with:

```bash
python ci_scripts/filter_aqua_reports.py --input-dir artifacts --output-dir filtered-artifacts --config-file ignored_cves_config.json
```

### Using Environment Variables

You can also set CVEs to ignore using environment variables:

```bash
export AQUA_IGNORED_CVES="CVE-2025-27789,CVE-2023-12345,CVE-2024-56789"
python ci_scripts/filter_aqua_reports.py --input-dir artifacts --output-dir filtered-artifacts
```

## GitHub Pages Publishing

The filtered reports are published to GitHub Pages through the `publish_to_gh_pages` job:

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
    - name: Deploy to GitHub Pages
      uses: peaceiris/actions-gh-pages@v4
      with:
        github_token: ${{ secrets.CI_TOKEN }}
        publish_dir: ./
        keep_files: true
        publish_branch: gh-pages
```

## Deployment Requirements

- Python 3.9 or later
- BeautifulSoup4 library
- GitHub repository with Actions and Pages enabled
- Appropriate permissions for GitHub Pages publishing

## Testing and Verification

### Local Testing

1. Generate Aqua Security scan reports
   ```bash
   mkdir -p test_artifacts
   cp path/to/aqua-scan.json test_artifacts/
   cp path/to/aqua-scan.html test_artifacts/
   ```

2. Run the filtering pipeline
   ```bash
   python ci_scripts/filter_aqua_reports.py --input-dir test_artifacts --output-dir filtered_test
   ```

3. Generate the elegant report
   ```bash
   python ci_scripts/create_elegant_report.py filtered_test/aqua-scan-filtered.json filtered_test/elegant-report.html
   ```

4. Verify results
   ```bash
   # Check for presence of filtered CVEs
   grep "CVE-2025-27789" filtered_test/aqua-scan-filtered.json
   # Should return no results
   
   # Open reports in browser
   open filtered_test/elegant-report.html
   ```

### CI/CD Verification

1. Check GitHub Actions workflow run
2. Verify artifacts were created
3. Confirm GitHub Pages deployment
4. Access reports at `https://[username].github.io/[repo]/security-reports/`

## Troubleshooting

### Common Issues

**Issue**: HTML Parsing Failures
- **Symptom**: Error in `filter_html_report.py`
- **Cause**: HTML structure changes in Aqua reports
- **Solution**: Update the element selection logic

**Issue**: Missing Dependencies
- **Symptom**: ImportError for BeautifulSoup
- **Cause**: Missing Python package
- **Solution**: Ensure `pip install beautifulsoup4` runs in the workflow

**Issue**: GitHub Pages Not Updating
- **Symptom**: Old or missing reports on GitHub Pages
- **Cause**: Publishing or permission issues
- **Solution**: Check CI_TOKEN permissions and workflow logs

**Issue**: No CVEs Detected as Ignored
- **Symptom**: Reports show no filtering occurring
- **Cause**: Automatic detection couldn't find ignored vulnerabilities
- **Solution**: Use a configuration file or environment variable to specify CVEs

## Maintenance

### Manually Specifying Ignored CVEs

If the automatic detection is not finding all ignored vulnerabilities, you can:

1. Create a configuration file:
   ```json
   {
     "ignored_cves": [
       "CVE-2025-27789",
       "CVE-YYYY-NNNNN"
     ]
   }
   ```

2. Update the CI workflow to use it:
   ```yaml
   - name: Filter ignored vulnerabilities
     run: python ci_scripts/filter_aqua_reports.py --input-dir artifacts --output-dir filtered-artifacts --config-file ignored_cves_config.json
   ```

### Modifying Report Appearance

1. Edit the HTML and CSS in `create_elegant_report.py`
2. For major styling changes, consider extracting CSS to an external file

### Updating GitHub Pages Layout

1. Modify the HTML content in the `Create index page for reports` step in `main.yml`

## Future Enhancements

1. ✅ Dynamic CVE Filtering
   - ✅ Read ignored CVEs from a configuration file
   - ✅ Dynamically detect ignored status from Aqua reports
   - Add API integration to query Aqua directly

2. Enhanced Visualization
   - Add trend analysis over time
   - Include resource-based aggregations and filtering

3. Automated Testing
   - Add unit tests for filtering logic
   - Create reference fixtures for verification

## Support

For issues or enhancements, please contact the DevOps team or submit a GitHub issue. 