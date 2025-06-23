import requests
import logging
import os
import json

def update_cloud_accounts(cloud_type, hub_account, regions):
    limit = 50
    offset = 0
    response = True

    while response:

        payload = {
            'limit': limit,
            'offset': offset,
            'cloudProviders': cloud_type
        }

        try:
            r = requests.get(console_url + "/api/v1/cloud-scan-rules", headers=pccHeaders, params=payload)
            r.raise_for_status()
        except requests.exceptions.HTTPError as e:
            raise SystemExit(e)

        offset = offset + limit

        response = r.json()
        if response:
            for i in response:
                # Check for the specific agentlessScanSpec configuration:
                # enabled: true and hubCredentialID is missing
                if (
                        "agentlessScanSpec" in i and
                        i["agentlessScanSpec"].get("enabled") is True and
                        "hubCredentialID" not in i["agentlessScanSpec"]
                ):
                    if i["agentlessScanSpec"]["hubAccount"]:
                        continue

                    if i["deleted"]:
                        continue

                    del i["modified"]
                    del i["credential"]
                    del i["agentlessAccountState"]
                    del i["deleted"]
                    del i["organizationName"]
                    del i["agentlessScanSpec"]["scanners"]

                    i["agentlessScanSpec"]["hubCredentialID"] = hub_account
                    i["agentlessScanSpec"]["regions"] = regions
                    i["agentlessScanSpec"]["skipPermissionsCheck"] = True
                    i["agentlessScanSpec"]["scanNonRunning"] = True

                    data = []
                    data.append(i)
                    try:
                        update = requests.put(console_url+"/api/v1/cloud-scan-rules", headers=pccHeaders, json=data)
                        update.raise_for_status()
                    except requests.exceptions.HTTPError as e:
                        if e.response.status_code == 400:
                            logging.error(f"Skipping update for Cloud Account \"{cloud_type.upper()} :{i['credentialId']}\" due to HTTP 400 error: {e}")
                            continue  # Continue to the next account
                        else:
                            raise SystemExit(e)

                    if update.status_code == 200:  # Changed from r.status_code to update.status_code
                        logging.info(f"Cloud Account \"{cloud_type.upper()} : {i['credentialId']}\" sucessfully updated.")
                    else:
                        # This else block might be redundant with raise_for_status() but kept for explicit logging
                        logging.error(f"Failed to update Cloud Account \"{cloud_type.upper()} :{i['credentialId']}\". HTTP Error: {update.status_code}")
                        # If a non-400 error makes it here, we still want to exit.
                        exit(1)

def trigger_agentless_scan():
    try:
            r = requests.post(console_url+"/api/v1/agentless/scan", headers=pccHeaders)
            r.raise_for_status()
    except requests.exceptions.HTTPError as e:
        raise SystemExit(e)
    
    if r.status_code == 200:
        logging.info(f"Agentless scan triggered")
    else:
        logging.error(f"Failed to trigger Agentless scan!")
        exit(1)

if __name__ == "__main__":

    logging.basicConfig(level=logging.INFO,
                        format='%(asctime)s.%(msecs)03d %(levelname)s:%(message)s',
                        datefmt='%Y-%m-%d %H:%M:%S')

    console_url = os.getenv('PRISMA_CLOUD_COMPUTE_CONSOLE')
    access_key = os.getenv('PRISMA_CLOUD_ACCESS_KEY')
    secret_key = os.getenv('PRISMA_CLOUD_SECRET_KEY')
    gcp_hub_account = os.getenv('GCP_HUB_ACCOUNT')
    gcp_regions = json.loads(os.getenv('GCP_REGIONS'))
    azure_hub_account = os.getenv('AZURE_HUB_ACCOUNT')
    azure_regions = json.loads(os.getenv('AZURE_REGIONS'))

    payload = {
        'username': access_key,
        'password': secret_key
    }

    # Generate auth token for Prisma Cloud Compute. 
    try:
            r = requests.post(console_url+"/api/v1/authenticate", json=payload)
            r.raise_for_status()
    except requests.exceptions.HTTPError as e:
        raise SystemExit(e)

    TOKEN = r.json()['token']

    # Set Prisma Cloud Headers for Login with token
    pccHeaders = {
        'Authorization': 'Bearer '+TOKEN,
        'Accept': 'application/json'
    }

    update_cloud_accounts("gcp", gcp_hub_account, gcp_regions)
    update_cloud_accounts("azure", azure_hub_account, azure_regions)

    trigger_agentless_scan()
