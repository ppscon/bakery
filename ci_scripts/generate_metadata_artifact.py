import json
import sys
from datetime import datetime

def read_file_content(file_path):
    try:
        with open(file_path, 'r') as f:
            return f.read().strip()
    except FileNotFoundError:
        return ''

def generate_metadata_artifact(signature_file_path, timestamp_file_path, acceptance_criteria_path, actual_signature_path, artifact_file_prefix):
    signature = read_file_content(signature_file_path)
    timestamp = read_file_content(timestamp_file_path)
    acceptance_criteria = read_file_content(acceptance_criteria_path)
    actual_signature = read_file_content(actual_signature_path)

    metadata = {
        'Signature': signature,
        'Timestamp': timestamp,
        'Acceptance Criteria': acceptance_criteria,
        'Actual Signature': actual_signature
    }

    # Generate JSON artifact
    with open(f"{artifact_file_prefix}.json", 'w') as json_file:
        json.dump(metadata, json_file, indent=4)

    # Generate HTML artifact
    with open(f"{artifact_file_prefix}.html", 'w') as html_file:
        html_file.write('<html>\n')
        html_file.write('<head><title>Metadata Artifact</title></head>\n')
        html_file.write('<body>\n')
        html_file.write('<h1>Metadata Artifact</h1>\n')
        html_file.write('<table border="1">\n')
        html_file.write('<tr><th>Attribute</th><th>Value</th></tr>\n')

        for key, value in metadata.items():
            html_file.write(f'<tr><td>{key}</td><td>{value}</td></tr>\n')

        html_file.write('</table>\n')
        html_file.write('</body>\n')
        html_file.write('</html>\n')

if __name__ == '__main__':
    if len(sys.argv) != 6:
        print("Usage: python3 generate_metadata_artifact.py <signature_file> <timestamp_file> <acceptance_criteria_file> <actual_signature_file> <artifact_file_prefix>")
        sys.exit(1)

    signature_file = sys.argv[1]
    timestamp_file = sys.argv[2]
    acceptance_criteria_file = sys.argv[3]
    actual_signature_file = sys.argv[4]
    artifact_file = sys.argv[5]

    generate_metadata_artifact(signature_file, timestamp_file, acceptance_criteria_file, actual_signature_file, artifact_file)
