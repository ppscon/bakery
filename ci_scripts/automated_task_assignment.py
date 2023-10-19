import json
import requests
import os


def send_teams_notification(assignee, task_details):
    webhook_url = "https://aquasecurity.webhook.office.com/webhookb2/75c4ed95-5e41-41a4-904c-687824986e78@bc034cf3-566b-41ca-9f24-5dc49474b05e/IncomingWebhook/dd5ae390abf74796b79987fc65336627/0aa89312-1741-4438-bd46-3254fabb5c0d"
    message = f"New vulnerability task assigned to {assignee}. Details: {task_details}"
    headers = {"Content-Type": "application/json"}
    payload = json.dumps({"text": message})
    try:
        response = requests.post(webhook_url, headers=headers, data=payload)
        response.raise_for_status()  # Raise HTTPError for bad responses
        return response.status_code
    except requests.RequestException as e:
        print(f"Failed to send Teams notification: {e}")
        return None


# Example use-case
assignee = 'Philip'
task_details = {'CVE': 'CVE-2021-4500', 'Severity': 'High', 'Fix Version': '1.2.3'}
send_teams_notification(assignee, task_details)
