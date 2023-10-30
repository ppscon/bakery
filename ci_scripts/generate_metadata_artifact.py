import json
import sys
from datetime import datetime

def generate_metadata_artifact(signature_file, timestamp_file, acceptance_criteria_file, actual_signature_file, artifact_file):
    with open(signature_file, 'r') as f:
        signature = f.read().strip()

    with open(timestamp_file, 'r') as f:
        timestamp = f.read().strip()

    with open(acceptance_criteria_file, 'r') as f:
        acceptance_criteria = f.read().strip()

    # Convert UNIX timestamp to human-readable date-time
    human_readable_date = datetime.utcfromtimestamp(int(timestamp)).strftime('%Y-%m-%d %H:%M:%S UTC')

    artifact = {
        'signature': signature,
        'timestamp': timestamp,
        'human_readable_date': human_readable_date,
        'acceptance_criteria': acceptance_criteria
    }

    with open(f"{artifact_file}.json", 'w') as f:
        json.dump(artifact, f)

    # Generate HTML content
    html_content = f'''
    <html>
    <head><title>Metadata Artifact</title></head>
    <body>
    <h1>Metadata Artifact</h1>
    <table border="1">
        <tr>
            <th>Attribute</th>
            <th>Value</th>
        </tr>
        <tr>
            <td>Signature</td>
            <td>{signature}</td>
        </tr>
        <tr>
            <td>Timestamp</td>
            <td>{timestamp} ({human_readable_date})</td>
        </tr>
        <tr>
            <td>Acceptance Criteria</td>
            <td>{acceptance_criteria}</td>
        </tr>
    </table>
    </body>
    </html>
    '''

    # Save as HTML
    with open(f"{artifact_file}.html", 'w') as f:
        f.write(html_content)

if __name__ == "__main__":
    signature_file = sys.argv[1]
    timestamp_file = sys.argv[2]
    acceptance_criteria_file = sys.argv[3]
    actual_signature_file = sys.argv[4]
    artifact_file = sys.argv[5]

    # Ensure '.txt' is not in the artifact_file name
    artifact_file = artifact_file.replace('.txt', '')

    generate_metadata_artifact(signature_file, timestamp_file, acceptance_criteria_file, actual_signature_file, artifact_file)

