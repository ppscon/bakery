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

    with open(f"{artifact_file}.json", 'w') as f:
        json.dump(artifact, f)

    # Generate HTML content
    html_content = f"""
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
    </table>
    </body>
    </html>
    """

    # Save as HTML
    with open(f"{artifact_file}.html", 'w') as f:
        f.write(html_content)

if __name__ == "__main__":
    signature_file = sys.argv[1]
    timestamp_file = sys.argv[2]
    artifact_file = sys.argv[3]
    generate_metadata_artifact(signature_file, timestamp_file, artifact_file)






# import json
# import sys
# from datetime import datetime
#
# def generate_metadata_artifact(signature_file, timestamp_file, artifact_file):
#     with open(signature_file, 'r') as f:
#         signature = f.read().strip()
#
#     with open(timestamp_file, 'r') as f:
#         timestamp = f.read().strip()
#
#     # Convert UNIX timestamp to human-readable date-time
#     human_readable_date = datetime.utcfromtimestamp(int(timestamp)).strftime('%Y-%m-%d %H:%M:%S UTC')
#
#     artifact = {
#         'signature': signature,
#         'timestamp': timestamp,
#         'human_readable_date': human_readable_date
#     }
#
#     with open(artifact_file, 'w') as f:
#         json.dump(artifact, f)
#
# if __name__ == "__main__":
#     signature_file = sys.argv[1]
#     timestamp_file = sys.argv[2]
#     artifact_file = "metadata.json"  # Directly specifying the file name here
#     generate_metadata_artifact(signature_file, timestamp_file, artifact_file)

