import requests
import json
import time
import csv
import urllib3
from typing import Tuple, List, Optional

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Set up Prisma Cloud API credentials
PRISMA_API_URL = "https://api2.prismacloud.io"
INSTANCE = "customer"

# User Roles for saved access keys files
ORIGINAL_ROLE = "admin"
NEW_ROLE = "user"

# Compliance Standard IDs
OLD_COMPLIANCE_STANDARD_ID = "e05537c5-1b30-4159-9fd4-1004e12a1926"
NEW_COMPLIANCE_STANDARD_ID = "c04d9661-1ff8-4142-80ce-35d03792bcb3"

# Read access keys from CSV
def read_access_keys(file_path: str) -> dict:
    with open(file_path, mode='r') as file:
        reader = csv.reader(file)
        keys = {rows[0]: rows[1] for rows in reader}
    return keys

# Get authentication token
def get_token(instance_url: str, role: str) -> Tuple[Optional[str], Optional[float]]:
    file_path = f"access_key-{INSTANCE}-{role}.csv"
    keys = read_access_keys(file_path)

    prisma_user = keys.get('Access Key ID')
    api_key = keys.get('Secret Key')

    login_url = f"{instance_url}/login"
    headers = {"Content-Type": "application/json"}
    data = {"username": prisma_user, "password": api_key}

    try:
        response = requests.post(login_url, headers=headers, json=data, verify=False)
        response.raise_for_status()
        return response.json().get('token'), time.time()
    except requests.exceptions.RequestException as e:
        print(f"Error during API call: {e}")
        return None, None

# Fetch reports for a given compliance standard
def get_reports_by_compliance_standard(compliance_standard_id: str, headers: dict) -> List[dict]:
    url = f"{PRISMA_API_URL}/report"
    try:
        response = requests.get(url, headers=headers, verify=False)
        response.raise_for_status()
        reports = response.json()
        return [report for report in reports if report.get('complianceStandardId') == compliance_standard_id and report.get('target', {}).get('scheduleEnabled') == True]
    except requests.exceptions.RequestException as e:
        print(f"Failed to fetch reports: {e}")
        return []

# Fetch compliance standard details
def get_compliance_standard_details(compliance_standard_id: str, headers: dict) -> Optional[dict]:
    url = f"{PRISMA_API_URL}/compliance/{compliance_standard_id}"
    try:
        response = requests.get(url, headers=headers, verify=False)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        print(f"Failed to fetch compliance standard details: {e}")
        return None

# Create a new report from an existing one
def create_new_report_from_old(old_report: dict, new_compliance_standard_name: str, headers: dict) -> Optional[dict]:
    url = f"{PRISMA_API_URL}/v2/report"
    new_name = f"{old_report.get('name', '')}_{new_compliance_standard_name}"

    new_report_data = {
        "cloudType": old_report.get("cloudType", ""),
        "complianceStandardId": NEW_COMPLIANCE_STANDARD_ID,
        "name": new_name,
        "status": "completed",
        "target": {
            "accountGroups": old_report.get("target", {}).get("accountGroups", [""]),
            "accounts": old_report.get("target", {}).get("accounts", []),
            "complianceStandardIds": old_report.get("target", {}).get("complianceStandardIds", []),
            "notifyTo": old_report.get("target", {}).get("notifyTo", [""]),
            "compressionEnabled": old_report.get("target", {}).get("compressionEnabled", False),
            "downloadNow": old_report.get("target", {}).get("downloadNow", False),
            "regions": old_report.get("target", {}).get("regions", []),
            "schedule": old_report.get("target", {}).get("schedule", ""),
            "scheduleEnabled": old_report.get("target", {}).get("scheduleEnabled", False),
            "notificationTemplateId": old_report.get("target", {}).get("notificationTemplateId", ""),
            "timeRange": {"type": "to_now", "value": "epoch"}
        },
        "type": new_compliance_standard_name
    }

    try:
        response = requests.post(url, headers=headers, json=new_report_data, verify=False)
        response.raise_for_status()
        print(f"Successfully created report: {new_name}")
        return response.json()
    except requests.exceptions.RequestException as e:
        print(f"Failed to create report: {e} Payload: {json.dumps(new_report_data, indent=2)}")
        return None

# Main function to execute report migration
def main():
    # Authenticate with original role
    token, _ = get_token(PRISMA_API_URL, ORIGINAL_ROLE)
    if not token:
        print("Failed to authenticate with original role.")
        return

    headers = {
        "Content-Type": "application/json",
        "x-redlock-auth": token
    }

    # Retrieve old reports
    old_reports = get_reports_by_compliance_standard(OLD_COMPLIANCE_STANDARD_ID, headers)
    if not old_reports:
        print("No reports found for the old compliance standard.")
        return

    # Get new compliance standard details
    new_compliance_standard = get_compliance_standard_details(NEW_COMPLIANCE_STANDARD_ID, headers)
    if not new_compliance_standard:
        print("Failed to retrieve new compliance standard details.")
        return

    new_compliance_standard_name = new_compliance_standard.get('name', 'New Compliance Standard')

    # Authenticate with new role
    token, _ = get_token(PRISMA_API_URL, NEW_ROLE)
    if not token:
        print("Failed to authenticate with new role.")
        return

    headers["x-redlock-auth"] = token

    # Create new reports
    for old_report in old_reports:
        create_new_report_from_old(old_report, new_compliance_standard_name, headers)

if __name__ == "__main__":
    main()
