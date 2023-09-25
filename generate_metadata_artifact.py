import json
import sys
from datetime import datetime

def generate_metadata_artifact(signature_file, timestamp_file, artifact_file):
    with open(signature_file, 'r') as f:
        signature = f.read().strip()

    with open(timestamp_file, 'r') as f:
        timestamp = f.read().strip()

    # Convert UNIX timestamp to human-readable date-time
    human_readable_date = datetime.utcfromtimestamp(int(timestamp)).strftime('%Y-%m-%d %H:%M:%S UTC')

    artifact = {
        'signature': signature,
        'timestamp': timestamp,
        'human_readable_date': human_readable_date
    }

    with open(artifact_file, 'w') as f:
        json.dump(artifact, f)

if __name__ == "__main__":
    signature_file = sys.argv[1]
    timestamp_file = sys.argv[2]
    artifact_file = "metadata.json"  # Directly specifying the file name here
    generate_metadata_artifact(signature_file, timestamp_file, artifact_file)
