# Container Bakery/Golden Image Demo Project

This project demonstrates the workings of a "Container Bakery" following a basic framework. It involves an end-to-end CI/CD pipeline that not only builds Docker images from source code but also tests and scans them before deploying. Our goal is to produce a "Golden Image", our high-quality standard, much like a bakery aims to recreate their signature bread consistently.

## Testing:

The project uses the Jest library for tests (see the "test" script in `package.json`). We perform both unit and integration tests to ensure the integrity and functionality of our code.

### Unit Tests:

Our unit tests check if essential files (like `index.html`, `Dockerfile`, and `.gitignore`) exist in our project.

### Integration Tests:

Integration tests simulate real-world interactions with our server and endpoints, verifying the correct responses and behaviors.
To run the tests

```bash
npm install
npm run test
```

## CI/CD Pipeline and Container Bakery

Our CI/CD pipeline simulates a bakery's process.

1. Developer Pushes Code: The developer merges code to a branch triggering the CI/CD pipeline.
2. Code Scanning: CI/CD pipeline triggers an Aqua Security scan to ensure there are no vulnerabilities in the code.
3. Unit Testing: Unit tests are executed to verify code functionality.
4. Test Environment Deployment: Code is deployed to a test environment for further testing.
5. Approval Gates: After every significant step, there's an approval gate to review the process's output.
6. Integration and Functional Testing: Additional integration and functional tests are performed in the test environment.
7. Staging Environment Deployment: Post-approval, the code is deployed to the staging environment for a final round of testing.
8. Production Environment Deployment: Finally, the code is deployed to the production environment.

## Golden Image

Our Golden Image is the high-quality, standardized output - like a bakery's signature bread. It ensures that our final Docker container maintains the same level of quality, performance, and security every time.

## Aqua Integration

Aqua's scanner is integrated throughout the pipeline to ensure the code's security. By catching vulnerabilities early, we maintain the high standards of our Golden Image.

This template encapsulates the information you provided and the Container Bakery/Golden Image process. You may need to adjust based on your specific application or setup.




