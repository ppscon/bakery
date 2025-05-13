#!/bin/bash

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color
DIVIDER="━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

print_header() {
    echo -e "\n${BLUE}$DIVIDER"
    echo -e "📋 $1"
    echo -e "$DIVIDER${NC}\n"
}

print_step() {
    echo -e "${BLUE}▶ $1${NC}"
}

print_action_result() {
    local action_output=$1
    local action_type=$2
    local user=$3

    echo -e "${BLUE}Action performed by: ${GREEN}$user${NC}"
    echo -e "${BLUE}Action type: ${GREEN}$action_type${NC}"
    echo -e "${BLUE}Result:${NC}"
    echo "$action_output"
    echo "----------------------------------------"
}

# Cleanup previous run
print_header "Cleaning up previous demo resources"
kubectl delete namespace operator-test --ignore-not-found
kubectl delete clusterrolebinding test-operator-admin --ignore-not-found
echo "Waiting for full cleanup..."
sleep 10

# Verify cleanup
while kubectl get namespace operator-test >/dev/null 2>&1; do
    echo "Waiting for namespace cleanup to complete..."
    sleep 2
done

# Setup Test Environment
print_header "Setting up test environment"
print_step "Creating operator test namespace..."
kubectl create namespace operator-test

print_step "Creating operator service account with cluster-admin..."
cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: ServiceAccount
metadata:
  name: test-operator
  namespace: operator-test
  labels:
    audit.aquasec.com/type: "test-setup"
    audit.aquasec.com/component: "operator-identity"
  annotations:
    audit.aquasec.com/description: "Service account for testing operator controls"
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: test-operator-admin
  labels:
    audit.aquasec.com/type: "test-setup"
    audit.aquasec.com/component: "operator-rbac"
  annotations:
    audit.aquasec.com/description: "Cluster admin binding for test operator"
subjects:
- kind: ServiceAccount
  name: test-operator
  namespace: operator-test
roleRef:
  kind: ClusterRole
  name: cluster-admin
  apiGroup: rbac.authorization.k8s.io
EOF

# Test Case 1 - Malicious Configuration
print_header "Test Case 1: Attempting to create pod with host access (should be blocked)"
print_step "Creating pod with host access..."
ACTION_OUTPUT=$(kubectl --as=system:serviceaccount:operator-test:test-operator apply -f - 2>&1 <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: malicious-pod
  namespace: operator-test
  labels:
    audit.aquasec.com/type: "security-test"
    audit.aquasec.com/component: "malicious-attempt"
  annotations:
    audit.aquasec.com/action: "create-privileged-pod"
    audit.aquasec.com/description: "Attempt to create pod with host access"
spec:
  hostIPC: true
  hostNetwork: true
  hostPID: true
  containers:
  - name: nginx
    image: nginx
EOF
)
print_action_result "$ACTION_OUTPUT" "Create Pod with Host Access" "system:serviceaccount:operator-test:test-operator"

 Test Case 2 - Sensitive Data in ConfigMap
print_header "Test Case 2: Attempting to store secrets in ConfigMap (should be blocked)"
print_step "Creating ConfigMap with secrets..."
ACTION_OUTPUT=$(kubectl --as=system:serviceaccount:operator-test:test-operator apply -f - 2>&1 <<EOF
apiVersion: v1
kind: ConfigMap
metadata:
  name: operator-config-with-secret
  namespace: operator-test
  labels:
    audit.aquasec.com/type: "security-test"
    audit.aquasec.com/component: "secrets-attempt"
  annotations:
    audit.aquasec.com/action: "create-sensitive-configmap"
    audit.aquasec.com/description: "Attempt to store secrets in ConfigMap"
data:
  config.yaml: |
    apiKey: "SECRET123"
    password: "test123"
EOF
)
print_action_result "$ACTION_OUTPUT" "Create ConfigMap with Secrets" "system:serviceaccount:operator-test:test-operator"

# Verify if ConfigMap was created (shouldn't be)
kubectl get configmap operator-config-with-secret -n operator-test

# Test Case 3 - Legitimate Operation
print_header "Test Case 3: Creating legitimate ConfigMap (should be allowed)"
print_step "Creating legitimate ConfigMap..."
ACTION_OUTPUT=$(kubectl --as=system:serviceaccount:operator-test:test-operator apply -f - 2>&1 <<EOF
apiVersion: v1
kind: ConfigMap
metadata:
  name: operator-config-legitimate
  namespace: operator-test
  labels:
    audit.aquasec.com/type: "legitimate-operation"
    audit.aquasec.com/component: "operator-config"
  annotations:
    audit.aquasec.com/action: "create-legitimate-config"
    audit.aquasec.com/description: "Creating legitimate operator configuration"
data:
  config.yaml: |
    feature.enabled: true
    logging.level: debug
EOF
)
print_action_result "$ACTION_OUTPUT" "Create Legitimate ConfigMap" "system:serviceaccount:operator-test:test-operator"
#
## Verify in Kubernetes
#print_step "Verifying in Kubernetes... kubectl get configmap operator-config-legitimate -n operator-test -o yaml"
#kubectl get configmap operator-config-legitimate -n operator-test -o yaml

# Show Aqua Console Instructions
print_header "View Results in Aqua Console"
echo -e "${BLUE}To view the audit trail:${NC}"
echo "1. Open Aqua Console"
echo "2. Navigate to Security Reports → Audit"
echo "3. Filter for namespace: operator-test"
echo "4. Look for actions by: system:serviceaccount:operator-test:test-operator"
echo "5. Check the enhanced audit labels and annotations"

print_header "Demo Complete"