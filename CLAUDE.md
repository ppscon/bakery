# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

# Container Bakery Demo Project - Build & Development Guide

## Project Architecture

This is a CI/CD security pipeline demonstration project built around the "Container Bakery" concept - producing high-quality, standardized Docker containers (Golden Images) with comprehensive security scanning and vulnerability management.

### Core Components

1. **Node.js Web Application** (`/app/`)
   - Express.js server with basic web interface  
   - Located in `app/server.js` with static assets in `app/`
   - Uses Jest for testing

2. **Vulnerability Filter Package** (`/vulnerability-filter-package/`)
   - Standalone Python package for Aqua Security report processing
   - Filters ignored CVEs, processes HTML reports, creates elegant dashboards
   - Includes Splunk integration and delta reporting capabilities
   - Entry points defined in `setup.py` for console scripts

3. **CI Scripts** (`/ci_scripts/`)
   - Python scripts for report processing and task assignment
   - Core processing pipeline: filter → process → create reports
   - Automated testing via `test_filtering.py`

4. **Kubernetes Manifests** (`/kubernetes/`)
   - Pod Security Standards compliant deployments
   - Standard and compliant deployment configurations

## Build Commands

### Node.js Application
- **Install Dependencies**: `npm install` (Run in both root and `/app/` directories)
- **Start Application**: `npm start` (Runs `node server.js` from `/app/` directory)
- **Run Tests**: `npm test` (Runs Jest tests with CI reporters)
- **Run Single Test**: `npm test -- -t "test name"`

### Python Components
- **Install Vulnerability Filter Package**: `pip install -e vulnerability-filter-package/` 
- **Install Dependencies**: `pip install -r vulnerability-filter-package/requirements.txt`
- **Run Vulnerability Filter**: `python ci_scripts/filter_aqua_reports.py --input-dir <input> --output-dir <output>`
- **Create Elegant Report**: `python ci_scripts/create_elegant_report.py <input.json> <output.html>`
- **Process HTML Reports**: `python ci_scripts/process_index_page.py <input.html> <output.html>`
- **Run Tests**: `python ci_scripts/test_filtering.py`

### Vulnerability Filter Package Commands (if installed)
- `filter-aqua-reports` - Main filtering script
- `filter-html-report` - HTML report processing  
- `create-elegant-report` - Dashboard generation
- `process-index-page` - Variable substitution and severity fixing
- `filter-for-splunk` - Splunk-optimized filtering
- `send-to-splunk` - HEC integration

## Security Scanning Pipeline

The project implements a comprehensive security pipeline using Aqua Security:

1. **Scan** → Generate JSON/HTML reports from Aqua scanner
2. **Filter** → Remove ignored CVEs and process data (`filter_aqua_reports.py`)
3. **Process** → Fix severity values and replace variables (`process_index_page.py`) 
4. **Enhance** → Create modern dashboard (`create_elegant_report.py`)
5. **Deploy** → Publish to GitHub Pages for stakeholder access

Key scripts work in sequence:
- `filter_aqua_reports.py` → orchestrates filtering and calls other scripts
- `process_index_page.py` → fixes HTML severity mappings and variable substitution
- `create_elegant_report.py` → generates responsive dashboard from filtered JSON

## Code Style Guidelines
- **JavaScript**: ES6+ features, Express.js patterns, proper error handling
- **Python**: Python 3.9+ compatible, try/except blocks, BeautifulSoup4 for HTML
- **Naming**: snake_case for Python, camelCase for JavaScript
- **Dependencies**: BeautifulSoup4 and requests are core Python dependencies
- **Testing**: Jest for JavaScript, custom test runner for Python components
- **Logging**: Structured logging with detailed processing metrics