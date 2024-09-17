import requests
import json
import time
import csv
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Set up your Prisma Cloud API credentials
PRISMA_API_URL = "https://api2.prismacloud.io"
instance = "pso"

# Compliance Standard IDs
OLD_COMPLIANCE_STANDARD_ID = "e05537c5-1b30-4159-9fd4-1004e12a1926"
NEW_COMPLIANCE_STANDARD_ID = "c04d9661-1ff8-4142-80ce-35d03792bcb3"

# Read the access keys from CSV
def read_access_keys(file_path):
    with open(file_path, mode='r') as file:
        reader = csv.reader(file)
        keys = {rows[0]: rows[1] for rows in reader}
    return keys

# Get authentication token
def get_token_one(instance_url):
    global instance
    # Path to your CSV file
    file_path = f"access_key-{instance}.csv"
    keys = read_access_keys(file_path)

    # Extract the specific keys
    prisma_user = keys.get('Access Key ID')
    api_key = keys.get('Secret Key')

    # auth_one
    login1_url = f"{instance_url}/login"
    headers1 = {
        "Content-Type": "application/json",
    }
    data_post = {
        "username": prisma_user,
        "password": api_key,
    }
    try:
        response_post = requests.post(login1_url, headers=headers1, json=data_post, verify=False)
        response_post.raise_for_status()
        post_response_data = response_post.json()
        token_one = post_response_data.get('token')
        return token_one, time.time()  # Return both the token and the current timestamp
    except requests.exceptions.RequestException as e:
        print("Error during API call:", e)
        return None, None

# Fetch reports for the given complianceStandardId
def get_reports_by_compliance_standard(compliance_standard_id, API_HEADERS):
    url = f"{PRISMA_API_URL}/report"
    response = requests.get(url, headers=API_HEADERS, verify=False)

    if response.status_code != 200:
        print(f"Failed to fetch reports: {response.text}")
        return []

    reports = response.json()

    # Filter reports by checking the complianceStandardId field
    filtered_reports = [
        report for report in reports if 'complianceStandardId' in report and report['complianceStandardId'] == compliance_standard_id
    ]

    return filtered_reports

# Fetch compliance standard details
def get_compliance_standard_details(compliance_standard_id, API_HEADERS):
    url = f"{PRISMA_API_URL}/compliance/{compliance_standard_id}"
    response = requests.get(url, headers=API_HEADERS, verify=False)

    if response.status_code != 200:
        print(f"Failed to fetch compliance standard details: {response.text}")
        return None

    return response.json()

# Create a new report by copying an existing one and only including specific fields
def create_new_report_from_old(old_report, new_compliance_standard_name, API_HEADERS):
    url = f"{PRISMA_API_URL}/v2/report"
    old_name = old_report.get("name", "")
    # print (f"Old name: {old_name}")
    new_name = f"{old_name}_{new_compliance_standard_name}"
    # print (f"New name: {new_name}")

    # Create a new report payload with only the specified fields
    new_report_data = {
        "cloudType": old_report.get("cloudType", ""),
        "complianceStandardId": NEW_COMPLIANCE_STANDARD_ID,
        "id": '',
        "name": new_name,
        "status": "completed",
        "target": {
            "accountGroups": old_report.get("target", {}).get("accountGroups", [""]),
            # "resourceGroups": old_report.get("target", {}).get("resourceGroups", []),
            "accounts": old_report.get("target", {}).get("accounts", []),
            "complianceStandardIds": old_report.get("target", {}).get("complianceStandardIds", []),
            "notifyTo": old_report.get("target", {}).get("notifyTo", [""]),
            "compressionEnabled": old_report.get("target", {}).get("compressionEnabled", False),
            "downloadNow": old_report.get("target", {}).get("downloadNow", False),
            "regions": old_report.get("target", {}).get("regions", []),
            "schedule": old_report.get("target", {}).get("schedule", ""),
            "scheduleEnabled": old_report.get("target", {}).get("scheduleEnabled", False),
            "notificationTemplateId": old_report.get("target", {}).get("notificationTemplateId", ""),
            "timeRange": {
                "type": "to_now",  # You specified the type as "to_now"
                "value": "epoch"  # Using "epoch" as the value for the time range
            }
        },
        "type": new_compliance_standard_name
    }

    # Send the POST request to create the new report
    # response = requests.post(url, headers=API_HEADERS, data=json.dumps(new_report_data), verify=False)
    try:
        response = requests.post(url, headers=API_HEADERS, data=json.dumps(new_report_data), verify=False)
        response.raise_for_status()  # Raise exception for 4xx/5xx responses
        print(f"Successfully created report: {new_name}")

        return response.json()
    except requests.exceptions.ConnectionError as e:
        print(f"Connection error: Failed to fetch data {response.status_code}: {e} {url} {json.dumps(new_report_data)} {response.text}")
        return None
    except requests.exceptions.HTTPError as e:
        print(f"HTTP error occurred: Failed to fetch data {response.status_code}:{e}  {url} {json.dumps(new_report_data)} {response.text}")
        return None
    except requests.exceptions.Timeout:
        print(f"Request timed out after {timeout} seconds. Failed to fetch data{response.status_code}: {url} {json.dumps(new_report_data)} {response.text}")
        return None
    except ConnectionResetError as e:
        print( f"Connection reset by peer: {e} Failed to fetch data: {response.status_code}: {url} {json.dumps(new_report_data)} {response.text}")
        return None
    if response.status_code == 200:
        print(f"Successfully created report: {new_compliance_standard_name}")

    else:
        print(f"Failed to create report: {response.text}")
        print(f"URL: {url} - {json.dumps(new_report_data)}")

def main():
    last_token, last_token_time = get_token_one(PRISMA_API_URL)
    if not last_token:
        print("Failed to authenticate.")
        return

    API_HEADERS = {
        "Content-Type": "application/json",
        "x-redlock-auth": last_token  # Use the authentication token
    }

    # Step 1: Retrieve the reports with the old complianceStandardId
    old_reports = get_reports_by_compliance_standard(OLD_COMPLIANCE_STANDARD_ID, API_HEADERS)

    if not old_reports:
        print("No reports found for the old compliance standard.")
        return

    # Step 2: Get the details of the new compliance standard
    new_compliance_standard = get_compliance_standard_details(NEW_COMPLIANCE_STANDARD_ID, API_HEADERS)

    if not new_compliance_standard:
        print("Failed to retrieve new compliance standard details.")
        return

    new_compliance_standard_name = new_compliance_standard.get('name', 'New Compliance Standard')

    # Step 3: Create new copies of the old reports with the new compliance standard
    for old_report in old_reports:
        # Fetch the old name
        old_name = old_report.get("name", "")
        print(f"Old name: {old_name}")

        # Generate the new name for the report
        new_name = f"{old_name}_{new_compliance_standard_name}"
        print(f"New name: {new_name}")

        # Call the function to create a new report
        create_new_report_from_old(old_report, new_compliance_standard_name, API_HEADERS)

        # To avoid making duplicate requests, ensure the function is only called once
        print(f"Report creation completed for: {new_name}")

if __name__ == "__main__":
    main()
