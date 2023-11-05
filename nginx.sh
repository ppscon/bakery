#!/bin/bash

# Step 1: Start a pod running the nginx image
kubectl run nginx --image=nginx --restart=Never

# Step 2: Wait until the pod is running
while [[ $(kubectl get pods nginx -o 'jsonpath={..status.conditions[?(@.type=="Ready")].status}') != "True" ]]; do echo "waiting for pod" && sleep 1; done

# Step 3: Install curl in the nginx pod
kubectl exec -it nginx -- /bin/sh -c "apt-get update; apt-get install curl -y"

echo "Curl is ready in the nginx pod"