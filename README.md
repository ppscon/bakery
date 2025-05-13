# Container Bakery Demo Project - for Zero Trust Workloads

### CI/CD Pipeline with Aqua acting as the validation 

This repository contains a CI/CD pipeline configured with GitHub Actions. It covers the following stages:

- Running Unit Tests.
- Building and Pushing Docker Images
- Security Scanning with Aqua Enterprise Scanner (Trivy)
    - Scan Results are uploaded as artifacts
    - Image is scanned against Aqua's Golden Image Policy
    - Failed scans will fail the build
    - Passed scans will continue the build
    - **NEW**: Ignored CVEs are filtered out of reports
    - **NEW**: Reports include accurate severity metrics and proper variable substitution
    - notification is sent to Teams, see next steps:
- Assigning Tasks
    - Assigning tasks to product teams based on scan results
- Notifying Teams.
   - Notify Teams with scan results
- Generating SBOM with Aqua Supply Chain Security
    - SBOM is uploaded as an artifact
    - SBOM is uploaded to GitHub Pages
    - SBOM is uploaded to Aqua Supply Chain Security
- Signing and Verifying Docker Images
- Recording Metadata
    - Publishing Metadata to GitHub Pages
- Deploying to GitHub Pages
    - Publishing Security Reports to GitHub Pages 
- Promoting Docker Images to AWS ECR
    - image-bakery is immutable 

## Workflow File

The main workflow is defined in: `.github/workflows/main.yml`.

## Jobs

### Run Unit Tests

- Checkout code
- Setup Node.js environment
- Install dependencies and run tests

### Build Image

- Checkout code
- Docker login to GitHub Container Registry
- Build and push Docker image

### Aqua Scan

- Pull Aqua Scanner
- Run Aqua Security scan against the Docker image
- Upload Aqua scan reports as artifacts

### Filter Aqua Reports

- Download Aqua scan reports
- Filter out ignored vulnerabilities
- Process HTML reports to fix severity metrics and replace variables
- Create an elegant, curated vulnerability report
- Upload filtered reports as artifacts

### Assign Task

- Setup Python environment
- Run script to assign tasks

### Notify Teams

- Download filtered Aqua scan reports
- Notify Teams with curated scan results

### Generate SBOM

- Generate Software Bill of Materials (SBOM) using Aqua

### Sign Image

- Sign the Docker image using Cosign

### Verify Image

- Verify the signed Docker image using Cosign

### Record Metadata

- Generate and upload metadata artifacts

### Publish to GitHub Pages

- Download filtered security reports
- Create index page for reports
- Process index page to replace variables
- Deploy security reports and metadata to GitHub Pages
- Access reports at: https://ppscon.github.io/bakery/security-reports/

### Promote to AWS ECR

- Pull the image from GitHub Container Registry
- Tag and push the image to AWS ECR

## Recent Improvements

### Vulnerability Filtering and Reporting Enhancements (May 2025)

We've implemented significant improvements to the Aqua vulnerability reporting system:

1. **Filtered Vulnerability Reports**: Ignored CVEs are completely removed from reports, aligning with our previous PA Prisma workflow
2. **Fixed Severity Metrics**: Accurate counts of Critical, High, Medium, Low, and Negligible vulnerabilities
3. **Variable Substitution**: Shell variables like ${GITHUB_SHA} are properly replaced in HTML reports
4. **Enhanced Visualization**: Severity charts show proportional representation of vulnerabilities
5. **Improved Readability**: Report title changed from "Elegant Security Report" to "Curated Vulnerability Report"
6. **Detailed Metrics**: Process logs include comprehensive statistics about all changes made
7. **Automated Testing**: Test suite validates all filtering and processing logic

For more detailed information, see:
- [Technical Implementation Details](./Technical_Implementation_Details.md)
- [Vulnerability Filter Solution Guide](./Vulnerability_Filter_Solution_Guide.md)

## Secrets

The following secrets need to be configured in GitHub:

- `CI_TOKEN`: GitHub Container Registry token
- `AWS_ACCESS_KEY_ID`: AWS Access Key ID
- `AWS_SECRET_ACCESS_KEY`: AWS Secret Access Key
- `AWS_SESSION_TOKEN`: AWS Session Token
- `TEAMS_WEBHOOK_URL`: Microsoft Teams Webhook URL
- `AQUA_SERVER`: Aqua Server URL
- `AQUA_TOKEN`: Aqua Token
- `COSIGN_PRIVATE_KEY`: Cosign Private Key
- `COSIGN_PUBLIC_KEY`: Cosign Public Key

## Usage

To run this pipeline, make a push to the `main` branch.

## Accessing Reports

Security reports are available at:
- https://ppscon.github.io/bakery/security-reports/

The page provides access to:
- **Elegant Report**: Modern dashboard view of filtered vulnerabilities
- **HTML Report**: Standard format with ignored vulnerabilities removed
- **JSON Data**: Filtered data for integration with other tools

## Golden Image

Our Golden Image is the high-quality, standardized output - like a bakery's signature bread. It ensures that our final Docker container maintains the same level of quality, performance, and security every time.

## Aqua Integration

Aqua's scanner is integrated throughout the pipeline to ensure the code's security. By catching vulnerabilities early, we maintain the high standards of our Golden Image.

This template encapsulates the information you provided and the Container Bakery/Golden Image process. You may need to adjust based on your specific application or setup.




