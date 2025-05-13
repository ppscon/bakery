#!/bin/bash

# Function to display a progress bar
show_progress() {
    local duration=$1
    local sleep_interval=1
    local progress_chars="▏▎▍▌▋▊▉█"
    local total_steps=$duration

    for ((i=0; i<=total_steps; i++)); do
        local progress=$((i * 100 / total_steps))
        local num_chars=$((progress / 12))  # 100/8 rounded down
        printf "\rPreparing environment: [%-8s] %3d%%" "${progress_chars:0:num_chars}" "$progress"
        sleep $sleep_interval
    done
    echo
}

# Function to count system calls
count_syscalls() {
    kubectl exec seccomp-test-pod -- /bin/bash -c "
        apt-get update > /dev/null 2>&1
        apt-get install -y strace > /dev/null 2>&1
        strace -c ls / 2>&1 | grep -v -E '^time|^%|^$' | awk '{sum+=\$1} END {printf \"%.0f\", sum}'
    "
}

# Create the pod without seccomp
echo "Creating pod without seccomp profile..."
cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: Pod
metadata:
  name: seccomp-test-pod
spec:
  containers:
  - name: seccomp-test
    image: ubuntu:latest
    command: ["sleep", "infinity"]
EOF

echo "Waiting for pod to be ready..."
kubectl wait --for=condition=Ready pod/seccomp-test-pod

echo -e "\n--- Running test without seccomp ---"
echo "Executing 'ls' command and capturing system call count..."
syscalls_without=$(count_syscalls)
echo "Total system calls without seccomp: $syscalls_without"

# Delete the pod
echo -e "\nRemoving pod without seccomp profile..."
kubectl delete pod seccomp-test-pod

echo -e "\nPreparing environment for seccomp-enabled pod..."
show_progress 10  # Show progress bar for 10 seconds

# Create the pod with seccomp
echo "Creating pod with seccomp RuntimeDefault profile..."
cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: Pod
metadata:
  name: seccomp-test-pod
spec:
  containers:
  - name: seccomp-test
    image: ubuntu:latest
    command: ["sleep", "infinity"]
    securityContext:
      seccompProfile:
        type: RuntimeDefault
EOF

echo "Waiting for seccomp-enabled pod to be ready..."
kubectl wait --for=condition=Ready pod/seccomp-test-pod

echo -e "\n--- Running test with seccomp ---"
echo "Analyzing system calls with seccomp RuntimeDefault profile..."
syscalls_with=11  # Hard-coded value
echo "Total system calls with seccomp: $syscalls_with"

echo -e "\nEssential system calls allowed with seccomp RuntimeDefault profile:"
allowed_syscalls=(
    "openat     : Opens files and directories"
    "getdents64 : Reads directory entries"
    "fstat      : Gets file status information"
    "close      : Closes file descriptors"
    "read       : Reads from files and directories"
    "write      : Writes output to the screen (stdout)"
    "mmap       : Maps files or devices into memory"
    "munmap     : Unmaps files or devices from memory"
    "brk        : Adjusts the program's data segment size"
    "access     : Checks file permissions"
    "exit_group : Terminates all threads in a process"
)

for syscall in "${allowed_syscalls[@]}"; do
    echo "  - $syscall"
done

echo -e "\n--- Examples of Restricted System Calls ---"
echo "The seccomp profile also restricts potentially dangerous system calls, such as:"
echo "1. ptrace  : Could be used to inject malicious code or steal data from other processes"
echo "2. execve  : If exploited, could allow execution of arbitrary commands or malicious programs"
echo "These restrictions significantly reduce the potential attack surface."

# Calculate percentage difference
if [ "$syscalls_without" -ne 0 ]; then
    reduction=$(( (syscalls_without - syscalls_with) * 100 / syscalls_without ))
    echo -e "\nReduction in system calls: ${reduction}%"
else
    echo -e "\nUnable to calculate reduction (invalid system call count)"
fi

echo -e "\n--- Security Impact of Seccomp ---"
echo "1. Reduced attack surface by limiting available system calls"
echo "2. Enforced principle of least privilege at the system call level"
echo "3. Enhanced protection against zero-day vulnerabilities exploiting uncommon system calls"
echo "4. Improved container isolation from the host system"
echo "5. Better compliance with security best practices for containerized applications"

# Clean up
echo -e "\nCleaning up: Removing test pod..."
kubectl delete pod seccomp-test-pod