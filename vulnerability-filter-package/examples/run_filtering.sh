#!/bin/bash
# Example script to demonstrate vulnerability filtering workflow

# Create directories
mkdir -p input output

# Sample report paths (replace with your actual report paths)
INPUT_JSON="input/aqua-scan.json"
INPUT_HTML="input/aqua-scan.html"
OUTPUT_DIR="output"

# Install dependencies if needed
pip install -r ../requirements.txt

# Run filtering scripts
echo "Step 1: Filtering ignored vulnerabilities from reports..."
python ../scripts/filter_aqua_reports.py --input-dir input --output-dir output --config-file ../config/ignored_cves_config.json

# Create elegant report from filtered data
echo "Step 2: Creating elegant report from filtered data..."
python ../scripts/create_elegant_report.py output/aqua-scan-filtered.json output/elegant-report.html

# Process HTML reports to fix severity values and replace variables
echo "Step 3: Processing HTML reports for improved presentation..."
python ../scripts/process_index_page.py output/elegant-report.html output/processed-report.html

echo "Filtering complete! Results are in the output directory:"
ls -la output/

echo "Open output/processed-report.html in your browser to view the results." 