import json
import sys

def verify_image_immutable(artifact_file):
    with open(artifact_file, 'r') as f:
        artifact = json.load(f)

    # Add your verification logic here
    return bool(artifact.get('timestamp'))

if __name__ == "__main__":
    artifact_file = sys.argv[1]
    if not verify_image_immutable(artifact_file):
        exit(1)
