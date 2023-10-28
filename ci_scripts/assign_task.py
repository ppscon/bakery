import json
import requests
import os


def send_teams_notification(assignee, task_details):
    webhook_url = os.environ.get("TEAMS_WEBHOOK_URL", "default_value_if_not_found")

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


def write_task_to_file(assignee, task_details):
    task = {
        'assignee': assignee,
        'task_details': task_details
    }
    with open('assigned_task.json', 'w') as f:
        json.dump(task, f)


# Example use-case
assignee = 'Philip'
task_details = {'CVE': 'CVE-2021-4500', 'Severity': 'High', 'Fix Version': '1.2.3'}
write_task_to_file(assignee, task_details)  # Write the task details to a JSON file
send_teams_notification(assignee, task_details)  # Send Teams notification