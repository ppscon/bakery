import json
import requests
import os


def read_aqua_scan_json(file_path):
    try:
        with open(file_path, 'r') as f:
            data = json.load(f)
        return data
    except FileNotFoundError:
        print("Aqua scan JSON file not found.")
        return None
    except json.JSONDecodeError:
        print("Error decoding Aqua scan JSON file.")
        return None


def send_teams_notification(assignee, aqua_data):
    webhook_url = os.environ.get("TEAMS_WEBHOOK_URL", "default_value_if_not_found")

    # Extract relevant details from Aqua scan data
    vulnerabilities = aqua_data.get("vulnerabilities", [])
    cve_ids = [v.get("name") for v in vulnerabilities]
    severities = [v.get("severity") for v in vulnerabilities]

    adaptive_card_content = {
        "type": "AdaptiveCard",
        "version": "1.0",
        "body": [
            {
                "type": "TextBlock",
                "size": "Medium",
                "weight": "Bolder",
                "text": f"New vulnerability task assigned to {assignee}"
            },
            {
                "type": "TextBlock",
                "text": f"Found {len(cve_ids)} vulnerabilities. CVE IDs: {', '.join(cve_ids)}. Severities: {', '.join(severities)}"
            }
        ]
    }

    headers = {"Content-Type": "application/json"}
    payload = json.dumps({"type": "message", "attachments": [{"contentType": "application/vnd.microsoft.card.adaptive", "content": adaptive_card_content}]})

    try:
        response = requests.post(webhook_url, headers=headers, data=payload)
        response.raise_for_status()
        return response.status_code
    except requests.RequestException as e:
        print(f"Failed to send Teams notification: {e}")
        return None


if __name__ == "__main__":
    assignee = 'Philip'
    aqua_scan_data = read_aqua_scan_json('artifacts/aqua-scan.json')

    if aqua_scan_data:
        send_teams_notification(assignee, aqua_scan_data)
