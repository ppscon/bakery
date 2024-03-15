### GitHub Actions Workflow: Aqua Scan Pre-commit Hook yaml

Code example 
```yaml!
name: Aqua Pre-commit Hook

on:
  pull_request:
    branches:
      - main

jobs:
  aqua_scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2

      - name: Set up Docker Environment
        run: |
          echo "${{ secrets.DOCKER_AUTH_CONFIG }}" > ~/.docker/config.json

      - name: Pull Aqua Security Scanner
        run: docker pull registry.aquasec.com/scanner:2022.4

      - name: Run Aqua Security Scan
        run: |
          IMAGE_NAME="your-image-name-here"
          IMAGE_TAG="your-image-tag-here" # This could be dynamic based on the PR
          docker run --rm -v $(pwd)/artifacts:/artifacts --entrypoint="" registry.aquasec.com/scanner:2022.4 /opt/aquasec/scannercli scan -H ${{ secrets.AQUA_SERVER }} --token ${{ secrets.AQUA_TOKEN }} --registry "GitHub" $IMAGE_NAME:$IMAGE_TAG --show-negligible --register-compliant --htmlfile /artifacts/aqua-scan.html --jsonfile /artifacts/aqua-scan.json

      - name: Upload Aqua Reports as Artifacts
        uses: actions/upload-artifact@v2
        with:
          name: aqua-reports
          path: artifacts/

```

### Key Components:
**Trigger:** This workflow is triggered on pull requests to the main branch, ensuring that every change is scanned before merge.

**Docker Environment Setup:** Since Aqua's scanner runs within a Docker container, this step sets up Docker authentication to pull the scanner image.

**Aqua Security Scan:** This step pulls the Aqua scanner image and runs the scan against your application's Docker image. You'll need to adjust the IMAGE_NAME and IMAGE_TAG to match the Docker image you wish to scan.

**Artifact Upload:** After the scan, the generated reports are uploaded as workflow artifacts, which can be reviewed for any vulnerabilities.

**Integration with Development Workflow:**
By integrating this workflow into your development process, you're adopting a preventive approach to security, enabling early detection of vulnerabilities. This aligns with the shift-left security concept, embedding security into the early stages of the software development lifecycle (SDLC).

### Enforcing Workflow Results:
To enforce that code changes only merge after passing the Aqua security scan, you can use GitHub's branch protection rules to require status checks to pass before merging. This can be configured in the repository settings under the "Branches" section by adding a branch protection rule for the main branch and selecting this workflow as a required status check.

This setup ensures a robust, security-focused CI/CD pipeline that leverages Aqua Security's scanning capabilities to maintain high standards of security and compliance, particularly important in environments with stringent regulatory requirements like financial services.



---

### Required Environment Variables
For the Aqua pre-commit hook workflow in GitHub Actions, you will need to define several environment variables to ensure the scanner can authenticate and perform scans correctly. Here’s a summary of the essential environment variables and how to set them up in your GitHub repository:

- **Required Environment Variables:** DOCKER_AUTH_CONFIG: This variable stores your Docker registry's authentication configuration in JSON format. It's required if your Aqua Security scanner image is stored in a private registry that requires authentication.

- **Example format:** {"auths":{"registry.aquasec.com":{"username":"YOUR_USERNAME","password":"YOUR_PASSWORD"}}}

- **AQUA_SERVER:** The URL of your Aqua Security server. This variable is crucial for the scanner to know which Aqua server to communicate with during the scanning process.

- **AQUA_TOKEN:** A token used for authenticating with the Aqua Security server. This token provides the necessary permissions for the scanner to perform scans and retrieve results.

### How to Set Environment Variables in GitHub Actions
To securely store and use these environment variables in your GitHub Actions workflow, you should use GitHub's encrypted secrets feature, which allows you to store sensitive information in your GitHub repository settings.

**Here’s how to add these secrets to your repository:**

1. Navigate to your GitHub repository on the GitHub website.
1. Click on "Settings" > "Secrets" > "Actions".
1. Click on "New repository secret".
1. Enter the name of the secret (e.g., DOCKER_AUTH_CONFIG, AQUA_SERVER, AQUA_TOKEN) in the "Name" field.
1. Paste the value of your secret in the "Value" field.
1. Click "Add secret".
1. Repeat these steps for each of the environment variables mentioned above.

### Using Secrets in Your Workflow
After you've set up your secrets, you can reference them in your workflow file using the secrets context. Here's an example snippet showing how to use these secrets in your workflow:

---
### Best Practice Developer Workflow
It would be best practice to make this Aqua scan workflow a separate pipeline within your GitHub Actions setup. Designing it as a standalone workflow offers several benefits, particularly in aligning with the "shift-left" security approach and ensuring early detection of vulnerabilities. Here's why a separate pipeline is advantageous:

### Isolation of Security Scans
Creating a dedicated pipeline for Aqua Security scans isolates these security checks from other CI/CD processes. This isolation helps in managing and maintaining the security aspects of your development workflow more effectively. It allows for specific focus on security-related tasks without mixing them with unit tests, build processes, or deployment steps.

### Flexibility in Triggering
A separate security scanning pipeline can be configured to trigger under specific conditions that are most relevant for security assessments, such as on pull requests to critical branches (e.g., main or develop) or when specific files that could affect security posture are modified. This granularity in triggering ensures that scans are performed when most needed, optimizing resource usage and developer time.

### Simplified Management and Maintenance
With security scans in a standalone workflow, it's easier to update, modify, or enhance the security processes without impacting the rest of the CI/CD pipeline. For example, if you need to update the Aqua scanner version, adjust scanning parameters, or integrate additional security tools, you can do so within this dedicated pipeline, minimizing the risk of disrupting other CI/CD operations.

### Enhanced Security Focus
A dedicated pipeline for Aqua Security scans emphasizes the importance of security within your development process. It serves as a constant reminder of the need to maintain and improve security practices, encouraging developers to prioritize addressing identified vulnerabilities.

### Easier Integration with Security Policies and Compliance
Separating security scans into their own pipeline facilitates compliance with organizational security policies and regulatory requirements. It makes it easier to audit security practices, review scan results, and demonstrate compliance with security standards.

### Example Configuration
Considering these benefits, here's how you might define this separate pipeline in your .github/workflows/aqua_scan.yml file, focusing exclusively on security scanning:

```yaml!
name: Aqua Security Pre-commit Hook

on:
  pull_request:
    branches:
      - main

jobs:
  aqua_scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - name: Set up Docker Environment
        run: |
          echo "${{ secrets.DOCKER_AUTH_CONFIG }}" > ~/.docker/config.json
      - name: Pull Aqua Security Scanner
        run: docker pull registry.aquasec.com/scanner:2022.4
      - name: Run Aqua Security Scan
        run: |
          docker run --rm -v $(pwd)/artifacts:/artifacts --entrypoint="" registry.aquasec.com/scanner:2022.4 /opt/aquasec/scannercli scan -H ${{ secrets.AQUA_SERVER }} --token ${{ secrets.AQUA_TOKEN }} --registry "GitHub" $IMAGE_NAME:$IMAGE_TAG --show-negligible --register-compliant --htmlfile /artifacts/aqua-scan.html --jsonfile /artifacts/aqua-scan.json
      - name: Upload Aqua Reports as Artifacts
        uses: actions/upload-artifact@v2
        with:
          name: aqua-reports
          path: artifacts/

```

This separate workflow ensures that your security scanning process is efficient, focused, and aligned with best practices in DevSecOps.

Incorporating Aqua scans into the pre-commit process within a GitHub Actions workflow is slightly different from traditional local pre-commit hooks managed by Git. GitHub Actions doesn't directly interact with the Git pre-commit hooks in your local development environment. Instead, it operates on events triggered by actions such as push or pull_request. However, developers can still utilize this setup to ensure security checks are performed early in the development lifecycle, effectively implementing a "shift-left" approach to security.

Here's how developers can use this setup as part of their pre-commit process:

1. **Local Development Best Practices**
Pre-commit Hooks Locally: For immediate feedback, developers can set up local pre-commit hooks that run lightweight checks or even containerized scans if feasible. While local hooks won't directly use the GitHub Actions workflow, they can run similar commands or scripts to ensure code quality and security before pushing. Tools like pre-commit can manage these hooks, including running linters or static analysis tools.

- **Manual Triggers:** Developers can manually trigger the GitHub Actions workflow with the Aqua Security scan before creating a pull request by using the workflow_dispatch event. This approach allows for running the scans on demand, providing flexibility in the development process.

**2. Pull Request Integration**
The primary method to leverage GitHub Actions for Aqua Security scanning as a pre-commit mechanism is through pull request workflows:

- **Automated Scans on Pull Requests:** The GitHub Actions workflow is configured to automatically run Aqua Security scans when a pull request is created or updated. This setup ensures that code is scanned before it's merged into the main branch, aligning with the pre-commit intent.

- **Review and Fix:** Developers review the scan results directly in the GitHub Actions logs or through the artifacts uploaded by the workflow. If vulnerabilities or issues are identified, developers can make the necessary code changes and push updates to the pull request, triggering another scan.

- **Branch Protection Rules:** To enforce the security scan as a mandatory check, configure branch protection rules in the GitHub repository settings. Require the Aqua Security scan job to pass before allowing merges into the protected branch (e.g., main). This ensures no code is merged without passing the security checks, effectively acting as a gatekeeper.

**3. Educate and Document**
Documentation: Provide clear documentation on the security scanning process, how to interpret scan results, and remediation steps for common vulnerabilities. This helps developers understand the importance of security scans and how to address issues.

- **Training:** Offer training sessions or resources on secure coding practices and how to use the tools integrated into the CI/CD pipeline, including the Aqua Security scanner.

**4. Continuous Improvement**
- **Feedback Loop:** Establish a feedback loop where developers can suggest improvements to the scanning process, share challenges they encounter, and contribute to refining security policies.

- **Security Champions:** Designate or encourage the role of security champions within development teams who can provide guidance on security-related matters and act as liaisons to the security team.

By integrating Aqua scans into the GitHub Actions workflow and aligning it with the development process, you create a robust mechanism for ensuring code security early in the development lifecycle. This approach promotes a security-first mindset among developers and helps in mitigating risks before they become more significant issues in later stages of development or deployment.



