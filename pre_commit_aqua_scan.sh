#!/bin/bash

# Configuration
IMAGE_NAME="local/bakery-app" # Change to your local image name
AQUA_SERVER="aqua-server-url" # Your Aqua server URL
AQUA_TOKEN="aqua-token"       # Your Aqua token

# Build the Docker image (optional, based on your workflow)
docker build -t $IMAGE_NAME .

# Run Aqua Security Scan
docker run --rm -v $(pwd)/artifacts:/artifacts --entrypoint="" \
    registry.aquasec.com/scanner:2022.4 \
    /opt/aquasec/scannercli scan -H $AQUA_SERVER --token $AQUA_TOKEN \
    --registry "Local" $IMAGE_NAME --show-negligible --register-compliant \
    --htmlfile /artifacts/aqua-scan.html --jsonfile /artifacts/aqua-scan.json

# Check for scan result and exit accordingly
# This part is pseudo-code and needs to be adapted based on how you want to handle scan results.
if [ scan detects high severity vulnerabilities ]; then
    echo "High severity vulnerabilities found, commit blocked."
    exit 1
else
    echo "No high severity vulnerabilities found, proceed with commit."
fi