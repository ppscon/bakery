import json
import sys

def generate_metadata_artifact(signature_file, timestamp_file, artifact_file):
    with open(signature_file, 'r') as f:
        signature = f.read().strip()

    with open(timestamp_file, 'r') as f:
        timestamp = f.read().strip()

    artifact = {
        'signature': signature,
        'timestamp': timestamp,
    }

    with open(artifact_file, 'w') as f:
        json.dump(artifact, f)

if __name__ == "__main__":
    signature_file = sys.argv[1]
    timestamp_file = sys.argv[2]
    artifact_file = sys.argv[3]
    generate_metadata_artifact(signature_file, timestamp_file, artifact_file)
