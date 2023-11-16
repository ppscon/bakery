# Container Bakery Demo Project - for Zero Trust Workloads

### CI/CD Pipeline with Aqua acting as the validation

This repository contains a CI/CD pipeline configured with GitHub Actions. It covers the following stages:

- Running Unit Tests.
- Building and Pushing Docker Images.
- Security Scanning with Aqua Enterprise Scanner. (Trivy)
    - Scan Results are uploaded as artifacts.
    - Image is scanned against Aqua's Golden Image Policy.
    - Failed scans will fail the build.
    - Passed scans will continue the build.
    - notification is sent to Teams, see next steps:
- Assigning Tasks:
    - Assigning tasks to product teams based on scan results.
- Notifying Teams:
    - Notify Teams with scan results.
- Generating SBOM with Aqua Supply Chain Security:
    - SBOM is uploaded as an artifact.
    - SBOM is uploaded to GitHub Pages.
    - SBOM is uploaded to Aqua Supply Chain Security.
- Signing and Verifying Docker Images.
- Recording Metadata:
    - Publishing Metadata to GitHub Pages.
    - Deploying to GitHub Pages:
        - Publishing Metadata to GitHub Pages.
    - Promoting Docker Images to AWS ECR:
        - image-bakery is immutable.

## Workflow File

The main workflow is defined in `.github/workflows/main.yml`.

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

### Assign Task

- Setup Python environment
- Run script to assign tasks

### Notify Teams

- Download Aqua scan reports
- Notify Teams with scan results

### Generate SBOM

- Generate Software Bill of Materials (SBOM) using Aqua

### Sign Image

- Sign the Docker image using Cosign

### Verify Image

- Verify the signed Docker image using Cosign

### Record Metadata

- Generate and upload metadata artifacts

### Publish to GitHub Pages

- Deploy metadata to GitHub Pages

### Promote to AWS ECR

- Pull the image from GitHub Container Registry
- Tag and push the image to AWS ECR

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



## Golden Image

Our Golden Image is the high-quality, standardized output - like a bakery's signature bread. It ensures that our final Docker container maintains the same level of quality, performance, and security every time.

## Aqua Integration

Aqua's scanner is integrated throughout the pipeline to ensure the code's security. By catching vulnerabilities early, we maintain the high standards of our Golden Image.

This template encapsulates the information you provided and the Container Bakery/Golden Image process. You may need to adjust based on your specific application or setup.




