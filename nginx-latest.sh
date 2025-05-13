#!/bin/bash

# Step 1: Start a pod running the nginx image
kubectl run nginx --image=nginx --restart=Never

# Step 2: Wait until the pod is running
while [[ $(kubectl get pods nginx -o 'jsonpath={..status.conditions[?(@.type=="Ready")].status}') != "True" ]]; do
  echo "waiting for pod"
  sleep 1
done

# Step 3: Install curl in the nginx pod (Debian-based image)
kubectl exec -it nginx -- /bin/sh -c "apt-get update && apt-get install curl -y"

# Step 4: Download the EICAR test file using curl
kubectl exec -it nginx -- /bin/sh -c "curl -o /tmp/eicar.com https://secure.eicar.org/eicar.com"


# Step 5: Attempt to execute or access the file (to trigger runtime detection)
kubectl exec -it nginx -- /bin/sh -c "cat /tmp/eicar.com"

echo "⚠️ MALWARE test file dropped and accessed. Check Aqua incidents screen for detection."
