import asyncio
import aiohttp
import csv
import configparser
import datetime
import json
import json5
import logging
import orjson  # Faster JSON parsing
import os
import random
import re
import sys
import time
import traceback
import uvloop  # Not supported on windows, comment this line
from aiohttp import ClientResponseError
from collections import defaultdict
from colorama import Fore, Style, init
from datetime import datetime, timedelta, timezone
from io import StringIO
from tenacity import retry, retry_if_exception_type, stop_after_attempt, wait_exponential

# Global request timestamps for rate limiting
global_request_timestamps = []
semaphore = asyncio.Semaphore(64)  # Limit concurrency to 256

class ColorFormatter(logging.Formatter):
    """Custom formatter to add colors to log levels."""
    COLORS = {
        logging.DEBUG: Fore.CYAN,
        logging.INFO: Fore.GREEN,
        logging.WARNING: Fore.YELLOW,
        logging.ERROR: Fore.RED,
        logging.CRITICAL: Fore.MAGENTA,
    }

    def format(self, record):
        """Format log messages with colors and timestamps."""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")  # Manual timestamp
        log_color = self.COLORS.get(record.levelno, Fore.WHITE)
        message = super().format(record)  # Get the formatted log message
        return f"{log_color}{timestamp} - {record.levelname} - {record.funcName} - {record.lineno} - {message}{Style.RESET_ALL}"

# Initialize colorama
init(autoreset=True)

# Create a handler with the custom formatter
handler = logging.StreamHandler()
formatter = ColorFormatter("%(message)s")  # Keep format string minimal
handler.setFormatter(formatter)

# Configure logging correctly
logger = logging.getLogger()  # Get the root logger
logger.setLevel(logging.DEBUG)
logger.addHandler(handler)  # Add the custom handler
# logging.basicConfig(
#     # level=logging.INFO,
#     level=logging.DEBUG,
#     handlers=[handler],
# )
# Adjust the log level for httpx and httpcore to suppress their DEBUG logs.
logging.getLogger("httpx").setLevel(logging.WARNING)
logging.getLogger("httpcore").setLevel(logging.WARNING)


global random_number
CONFIG_FILE = "config.jsonc"

def load_config():
    """Load configuration from JSON file."""
    try:
        with open(CONFIG_FILE, "r") as f:
            return json.load(f)
    except FileNotFoundError:
        print(f"Warning: {CONFIG_FILE} not found. Using defaults.")
        return {}
    except json.JSONDecodeError:
        print(f"Error: {CONFIG_FILE} is invalid JSON. Using defaults.")
        return {}

try:
    with open("config.jsonc", "r") as f:
        config = json5.load(f)
except FileNotFoundError:
    logging.error("config.jsonc not found. Exiting...")
    sys.exit(1)



# Load configuration parameters efficiently
SSL_VERIFY = config.get("SSL_VERIFY", "False")
COMPANY = config.get("COMPANY", "pcs")
# COMPUTE_CACHE_REFRESH = config.get("COMPUTE_CACHE_REFRESH", "24")
FILENAME_PREFIX = config.get("FILENAME_PREFIX")  # Get value from config
if FILENAME_PREFIX == "os.path.basename(__file__)":  # Check if it was stored as a string
    FILENAME_PREFIX = os.path.basename(__file__)  # Dynamically evaluate it
RUN_ON_WINDOWS = config.get("RUN_ON_WINDOWS", "False")
VULN_TYPE_STAGE = config.get("VULN_TYPE_STAGE", [])
VULN_TAG = config.get("VULN_TAG", [])
VULN_TAG_DESCRIPTION = config.get("VULN_TAG_DESCRIPTION", [])
VULN_TAG_COLOR = config.get("VULN_TAG_COLOR", [])
VULNERABILITY_QUERY = config.get("VULNERABILITY_QUERY", [])
vuln_query = f"{VULNERABILITY_QUERY}'{VULN_TYPE_STAGE}'"
VULN_HOST_FILTER = config.get("VULN_HOST_FILTER", [])
VULN_IMAGE_FILTER = config.get("VULN_IMAGE_FILTER", [])
PACKAGE_NAME_FILTER = config.get("PACKAGE_NAME_FILTER", [])

# Path to the API config file
# API_CONFIG_PATH = 'API_config.ini'
API_CONFIG_PATH = f'API_config-{COMPANY}.ini'

# Enable uvloop as the default event loop policy
if RUN_ON_WINDOWS:
    logging.info("Running python on windows")
    # uvloop.install()  # Not supported on windows, comment this line
else:
    uvloop.install()  # Not supported on windows, comment this line
    # Increase the field size limit to process runtime compliance data
    csv.field_size_limit(sys.maxsize) # Not supported on windows, comment this line
# Track the last printed percentage globally
last_printed_percentage = [0]  # Use a list to mutate the value inside the function
# Shared timestamp for global rate limiting
global_request_timestamps = []
random_number = random.randint(1000, 9999)  # used for debugging
# Use script name in results output filename, can change if required
py_filename = FILENAME_PREFIX

start_time = time.time()


def read_api_config():
    config = configparser.ConfigParser()
    config.read(API_CONFIG_PATH)
    baseurl = config.get('URL', 'BaseURL')
    computeurl = config.get('URL', 'twistlockBaseURL')
    access_key_id = config.get('AUTHENTICATION', 'ACCESS_KEY_ID')
    secret_key = config.get('AUTHENTICATION', 'SECRET_KEY')
    # print(f"{baseurl} {access_key_id} {secret_key}")
    return baseurl, computeurl, access_key_id, secret_key


class TokenManager:
    def __init__(self, baseurl, access_key_id, secret_key):
        self.baseurl = baseurl
        self.access_key_id = access_key_id
        self.secret_key = secret_key
        self.token = None
        self.token_expiry_time = 0
        self.lock = asyncio.Lock()

    async def get_token(self):
        async with self.lock:
            if not self.token or time.time() >= self.token_expiry_time:
                # logging.debug(f'Renewing token at {datetime.now(timezone.utc)}')
                await self._refresh_token()
            return self.token

    async def _refresh_token(self):
        url = f'{self.baseurl}/login'
        headers = {'Content-Type': 'application/json'}
        data = {'username': self.access_key_id, 'password': self.secret_key}
        async with aiohttp.ClientSession() as session:
            # logging.debug(f'Refreshing token at {datetime.now(timezone.utc)}')
            async with session.post(url, headers=headers, json=data, ssl=SSL_VERIFY) as response:
                if response.status == 200:
                    response_data = await response.json()
                    self.token = response_data.get('token', None)
                    if not self.token:
                        raise Exception('Token not found in response.')
                    self.token_expiry_time = time.time() + 480  # Token valid for 8 minutes

                else:
                    raise Exception(f'Failed to get access token: {await response.text()}')


# TokenManager for computeurl requests
class ComputeTokenManager:
    def __init__(self, computeurl, access_key_id, secret_key):
        self.computeurl = computeurl
        self.access_key_id = access_key_id
        self.secret_key = secret_key
        self.token = None
        self.token_expiry_time = 0
        self.lock = asyncio.Lock()

    async def get_token(self):
        async with self.lock:
            if not self.token or time.time() >= self.token_expiry_time:
                # logging.debug(f'Renewing compute token at {datetime.now(timezone.utc)}')
                await self._refresh_token()
            return self.token

    async def _refresh_token(self):
        url = f'{self.computeurl}/api/v1/authenticate'
        headers = {'Content-Type': 'application/json'}
        data = {'username': self.access_key_id, 'password': self.secret_key}
        async with aiohttp.ClientSession() as session:
            # logging.debug(f'Refreshing compute token at {datetime.now(timezone.utc)}')
            async with session.post(url, headers=headers, json=data, ssl=SSL_VERIFY) as response:
                if response.status == 200:
                    response_data = await response.json()
                    self.token = response_data.get('token', None)
                    if not self.token:
                        raise Exception('Token not found in response.')
                    self.token_expiry_time = time.time() + 480  # Token valid for 8 minutes

                else:
                    raise Exception(f'Failed to get access token: {await response.text()}')


def write_data_to_csv(data, file_name, data_type):
    if data.empty:
        logging.error(f'No {data_type} data to write for {file_name}')
        return
    # Save the DataFrame to a CSV file
    data.to_csv(file_name, index=False)
    logging.info(f'{data_type.capitalize()} results data written to {file_name}')


def write_data_to_json(data, file_name, data_type):
    if data.empty:
        logging.error(f'No {data_type} data to write for {file_name}')
        return
    # Save the DataFrame to a JSON file
    data.to_json(file_name, orient='records')
    logging.info(f'{data_type.capitalize()} results data written to {file_name}')

@retry(stop=stop_after_attempt(5), wait=wait_exponential(multiplier=3, min=1, max=30))
async def make_request(method, url, token_manager, session, semaphore, payload=None, max_retries=5, backoff_factor=3):
    """Generic async request function with retry logic for GET, POST, PUT."""
    status_forcelist = {429, 500, 502, 503, 504}  # Retry on these status codes
    method = method.upper()  # Ensure method is uppercase

    async with semaphore:
        for attempt in range(1, max_retries + 1):
            try:
                token = await token_manager.get_token()
                if 'twistlock' in url:
                    headers = {'Authorization': f'Bearer {token}', 'Content-Type': 'application/json', 'Accept': 'application/json'}
                else:
                    headers = {"X-Redlock-Auth": token, "Content-Type": "application/json", "Accept": "application/json"}
                request_kwargs = {"headers": headers, "ssl": SSL_VERIFY}

                if method == "GET":
                    request_method = session.get
                elif method == "POST":
                    request_method = session.post
                    request_kwargs["json"] = payload
                elif method == "PUT":
                    request_method = session.put
                    request_kwargs["json"] = payload
                else:
                    logging.error(f"Unsupported HTTP method: {method}")
                    return None, 405  # 405 Method Not Allowed

                logging.debug(f"DEBUG: Attempt {attempt}/{max_retries}, Method={method}, URL={url}")

                async with request_method(url, **request_kwargs) as response:
                    status_code = response.status
                    content_type = response.headers.get("Content-Type", "")
                    # Handle successful response
                    if status_code == 200:
                        if "application/json" in content_type:
                            return await response.json(), status_code
                        logging.warning(f"Expected JSON but got {content_type}. Response: {await response.text()}")
                        return None, status_code  # Return None if non-JSON response
                    # Handle authentication errors
                    elif status_code == 401:
                        logging.error(f'401 Unauthorized on attempt {attempt}: Renewing token and retrying.')
                        await token_manager._renew_token()
                    # Handle retryable errors
                    elif status_code in status_forcelist:
                        logging.error(f'Retryable error {status_code} on attempt {attempt}/{max_retries}: {url}')
                        if attempt == max_retries:
                            logging.error(f'Max retries reached. Failed to process request: {url}')
                            return None, status_code
                        await asyncio.sleep(backoff_factor ** (attempt - 1))
                    # Handle non-retryable errors
                    else:
                        logging.error(f'Non-retryable error {status_code}, message={response.reason}, url={url}')
                        return None, status_code
            except ClientResponseError as e:
                if e.status in status_forcelist:
                    logging.error(f'Retryable HTTP error {e.status} on attempt {attempt}/{max_retries}: {url}')
                    if attempt == max_retries:
                        logging.error(f'Max retries reached. Failed to process request: {url}')
                        return None, e.status
                    await asyncio.sleep(backoff_factor ** (attempt - 1))
                else:
                    logging.error(f'Non-retryable HTTP error {e.status}, message={e.message}, url={url}')
                    return None, e.status
            except Exception as e:
                logging.error(f'Unexpected error: {e}. Attempt {attempt}/{max_retries}. URL: {url}')
                if attempt == max_retries:
                    logging.error('Max retries reached. Aborting.')
                    return None, None
                await asyncio.sleep(backoff_factor ** (attempt - 1))


async def get_vulnerability_tags(computeurl, ctoken_manager, session, semaphore):
    """Fetch vulnerability tags from Twistlock API using `make_get_request()`."""
    get_tags_url = f'{computeurl}/api/v1/tags'
    # Use make_get_request for better error handling and retries
    response_data, status_code = await make_request("GET", get_tags_url, ctoken_manager, session, semaphore)
    if response_data is None or status_code != 200:
        logging.warning(f"Failed to fetch tags. Status Code: {status_code}")
        return []
    # Extract tag names if valid JSON response
    return [item["name"] for item in response_data if "name" in item]


async def create_vulnerability_tags(computeurl, ctoken_manager, tag_name, tag_description, tag_color, session, semaphore):
    """Creates a vulnerability tag if it does not exist."""
    payload = {
        "name": tag_name,
        "color": tag_color,
        "description": tag_description
    }
    logging.debug(f"Tag '{tag_name}' {payload}")

    create_tags_url = f"{computeurl}/api/v1/tags"
    response_data, status_code = await make_request("POST", create_tags_url, ctoken_manager, session, semaphore, payload=payload)
    if status_code == 200:
        logging.info(f"Tag '{tag_name}' created successfully.")
    else:
        logging.error(f"Failed to create tag '{tag_name}'. Status code: {status_code}")
    return status_code


async def get_vulnerabilities(baseurl, token_manager, asset_type, session, semaphore):
    """Fetch EPSS scores for vulnerabilities based on asset type and vulnerability stage."""
    global VULN_TYPE_STAGE
    payload = {"query": vuln_query}
    # if (VULN_TYPE_STAGE == 'run'and asset_type == 'host'): payload = {"query": "vulnerability where asset.type = 'Host' AND epss.score > 0"}
    # elif VULN_TYPE_STAGE == 'run' and asset_type == 'image': payload = {"query": "vulnerability where asset.type = 'Deployed Image' AND epss.score > 0"}
    # elif VULN_TYPE_STAGE == 'build' and asset_type == 'image': payload = {"query": "vulnerability where asset.type = 'Container Registry Image' AND epss.score > 0"}
    # else: payload = {"query": "vulnerability where epss.score > 0"}
    # else: payload = {"query": "vulnerability where severity = 'critical' AND risk.factors IN ( 'Exploit Exists - Poc', 'Exploit Exists - In The Wild' )"}
    # else: payload = {"query": "vulnerability where severity IN ('critical', 'high') AND risk.factors IN ( 'Exploit Exists - Poc', 'Exploit Exists - In The Wild' )"}
    logging.debug(f"Query: {payload}")

    vulnerabilities_search_url = f"{baseurl}/uve/api/v1/vulnerabilities/search"
    vulnerabilities_list = []
    total_vulnerabilities = 0
    total_assets = 0
    while True:
        response, status_code = await make_request("POST", vulnerabilities_search_url, token_manager, session, semaphore, payload)
        if response is None or status_code != 200:
            logging.error(f"Failed to fetch vulnerabilities data: Status Code: {status_code}")
            break
        data_items = response.get('data', {})
        total_assets = data_items.get('totalAssets')
        total_vulnerabilities = data_items.get('totalVulnerabilities')
        for item in data_items.get('items', []):
            cve_id = item.get('cveId', '').strip()
            severity = item.get('severity', '')
            cvss = item.get('cvssScore')
            epss = item.get('epssScore')
            exploitable = item.get('exploitable', False)
            patchable = item.get('patchable', False)
            # Ensure 'run' section is always a dictionary
            run_section = item.get('run') or {}
            # Ensure 'hosts' and 'deployedImages' are always dictionaries
            hosts_data = run_section.get("hosts") or {}
            images_data = run_section.get("deployedImages") or {}
            hosts_count = hosts_data.get("hostsCount")
            deployed_images_count = images_data.get("deployedImagesCount")
            if not cve_id:
                logging.debug(f"Skipping invalid CVE ID: {item}")
                continue
            # Append full data including run section
            vulnerabilities_list.append((cve_id, severity, cvss, epss, exploitable, patchable, hosts_count, deployed_images_count))
        # Check for next page
        nextpagetoken = data_items.get("nextPageToken")
        if not nextpagetoken:
            break
        vulnerabilities_search_url = f"{baseurl}/uve/api/v1/vulnerabilities/search?page_token={nextpagetoken}"
    logging.info(Fore.LIGHTGREEN_EX + f"TOTAL Vulnerabilities CVEs: {total_vulnerabilities} - Retrieved: {len(vulnerabilities_list)}  Total assets: {total_assets}")
    return vulnerabilities_list, total_vulnerabilities


async def process_vulnerabilities(vulnerabilities_list, vuln_tag, cve_tags_dict):
    """Processes vulnerabilities and adds them to cve_tags_dict for hosts and images if applicable."""
    global PACKAGE_NAME_FILTER, VULN_HOST_FILTER, VULN_IMAGE_FILTER
    total_added = 0  # Track the number of entries added
    for cve_id, severity, cvss, epss, exploitable, patchable, hosts_count, deployed_images_count in vulnerabilities_list:
        cve_id = cve_id.strip()
        if not cve_id:
            logging.debug(f"Skipping invalid CVE ID: {cve_id}")
            continue
        added_host = added_image = False  # Track if both are added
        # Process as "host" if hostsCount is present
        if hosts_count and hosts_count > 0:
            logging.debug(f"Adding CVE: {cve_id} with asset_type: host under tag: {vuln_tag} (hostsCount={hosts_count})")
            cve_tags_dict = add_to_cve_tags_dict(cve_tags_dict, vuln_tag, cve_id, package_name=PACKAGE_NAME_FILTER, asset_type="host", name=VULN_HOST_FILTER)
            added_host = True
        # Process as "image" if deployedImagesCount is present
        if deployed_images_count and deployed_images_count > 0:
            logging.debug(f"Adding CVE: {cve_id} with asset_type: image under tag: {vuln_tag} (deployedImagesCount={deployed_images_count})")
            cve_tags_dict = add_to_cve_tags_dict(cve_tags_dict, vuln_tag, cve_id, package_name=PACKAGE_NAME_FILTER, asset_type="image", name=VULN_IMAGE_FILTER)
            added_image = True
        # Track how many entries were added
        if added_host and added_image:
            total_added += 2
        elif added_host or added_image:
            total_added += 1
    logging.info(f"Total vulnerabilities processed: {total_added}")
    return cve_tags_dict


async def update_vulnerability_tags(computeurl, ctoken_manager, vulntags, cve_tags_assign_data, session, semaphore):
    """Updates vulnerability tags using a PUT request."""
    update_tags_url = f'{computeurl}/api/v1/tags/{vulntags}'
    # Parse cve_tags_assign_data if it's a JSON string
    if isinstance(cve_tags_assign_data, str):
        try:
            cve_tags_assign_data = json.loads(cve_tags_assign_data)
        except json.JSONDecodeError as e:
            logging.error(f"Error parsing JSON data: {e}")
            return None
    # Prepare the full payload
    full_payload = {"name": vulntags, "vulns": cve_tags_assign_data['vulns']}
    logging.debug(f"Payload: {full_payload}")

    response_data, status_code = await make_request("PUT", update_tags_url, ctoken_manager, session, semaphore, full_payload)
    if status_code == 200:
        logging.info(f"Tag '{vulntags}' updated successfully for {len(full_payload['vulns'])} vulnerabilities.")
    else:
        logging.error(f"Failed to update tag '{vulntags}'. Status code: {status_code}")
    return status_code


async def process_tags(computeurl, ctoken_manager, cve_tags_dict, session, semaphore):
    total_vulnerabilities_tags_processed = 0
    collected_entries = defaultdict(lambda: {
        'comment': 'Updated with API',
        'id': None,
        'packageName': '',
        'resourceType': '',
        'resources': []
    })
    for cve_id, tag_dict in cve_tags_dict.items():
        for vulntags, asset_types in tag_dict.items():  # Ensure multiple asset types per CVE
            for asset_type, details in asset_types.items():
                # Ensure 'resources' exists and is a list
                details['resources'] = list(details.get('resources', []))
                package_name = details.get('packageName', '')
                resource_type = details.get('resourceType', '')

                key = (vulntags, cve_id, package_name, resource_type)
                collected_entries[key]['id'] = cve_id
                collected_entries[key]['packageName'] = package_name
                collected_entries[key]['resourceType'] = resource_type
                collected_entries[key]['resources'].extend(details['resources'])

    logging.info("Updating Tags")
    vuln_tags_payloads = defaultdict(list)
    for key, entry_data in collected_entries.items():
        vulntags, cve_id, package_name, resource_type = key
        entry = {
            "comment": "Updated with API",
            "id": entry_data['id'],
            "packageName": package_name,
            "resourceType": resource_type,
            "resources": entry_data['resources']
        }
        vuln_tags_payloads[vulntags].append(entry)
    for vulntags, vulns_list in vuln_tags_payloads.items():
        if not vulns_list:
            continue
        # logging.debug(f"Payload for {vulntags}: {json.dumps({'name': vulntags, 'vulns': vulns_list}, indent=2)}")
        response_status = await update_vulnerability_tags(
            computeurl, ctoken_manager, vulntags, {"name": vulntags, "vulns": vulns_list}, session, semaphore
        )
        if response_status == 200:
            num_vulns = len(vulns_list)
            total_vulnerabilities_tags_processed += num_vulns
            logging.info(f"{vulntags} Tag updated successfully for {num_vulns} vulnerabilities.")
            # await asyncio.sleep(20)  # Adjust sleep duration as needed
    print(Fore.CYAN + f"Total vulnerabilities processed across all tags: {total_vulnerabilities_tags_processed}")


def add_to_cve_tags_dict(cve_tags_dict, vulntags, cve_id, package_name, asset_type, name):
    if cve_id not in cve_tags_dict:
        cve_tags_dict[cve_id] = {}
    if vulntags not in cve_tags_dict[cve_id]:
        cve_tags_dict[cve_id][vulntags] = {}
    # Make sure we allow both `host` and `image` for the same CVE ID
    if asset_type not in cve_tags_dict[cve_id][vulntags]:
        cve_tags_dict[cve_id][vulntags][asset_type] = {
            'vulntags': vulntags,
            'packageName': package_name,
            'resourceType': asset_type,
            'resources': []
        }
    cve_tags_dict[cve_id][vulntags][asset_type]['resources'].append(name)
    return cve_tags_dict


async def get_twistlockUrl(baseurl, token_manager, session):
    """Fetches the twistlockUrl from the meta_info endpoint."""
    token = await token_manager.get_token()
    headers = {"X-Redlock-Auth": token, "Content-Type": "application/json", "Accept": "application/json"}
    meta_url = f"{baseurl}/meta_info"
    try:
        async with session.get(meta_url, headers=headers, ssl=SSL_VERIFY, timeout=10) as response:
            response.raise_for_status()
            data = await response.json()
            twistlockUrl = data.get('twistlockUrl')
            return twistlockUrl
    except aiohttp.ClientResponseError as e:
        logging.error(f"Failed to get twistlockUrl URL: {e}")
        return None
    except aiohttp.ClientConnectionError as e:
        logging.error(f"Failed to connect to {meta_url}: {e}")
        return None
    except Exception as e:
        logging.error(f"An unexpected error occured when getting twistlockUrl: {e}")
        return None


async def main():
    try:
        baseurl, computeurl, access_key_id, secret_key = read_api_config()
    except Exception as e:
        logging.error(f'Error reading API configuration {API_CONFIG_PATH}: {e}')
        return
    async with aiohttp.ClientSession() as session:
        token_manager = TokenManager(baseurl, access_key_id, secret_key)
        computeurl = await get_twistlockUrl(baseurl, token_manager, session)
        if not computeurl:
            logging.error("Failed to get Compute URL")
            return
        ctoken_manager = ComputeTokenManager(computeurl, access_key_id, secret_key)
        semaphore = asyncio.Semaphore(64)  # Limit concurrency
        # Get existing tags
        existing_tags = await get_vulnerability_tags(computeurl, ctoken_manager, session, semaphore)
        # Create tag if it does not exist
        if VULN_TAG not in existing_tags:
            created_status = await create_vulnerability_tags(
                computeurl, ctoken_manager, VULN_TAG, VULN_TAG_DESCRIPTION, VULN_TAG_COLOR, session, semaphore
            )
            if created_status != 200:
                logging.error(f"Failed to create tag {VULN_TAG}")
                return
        # Retrieve vulnerabilities
        package_name, asset_type, name = '*', '', '*'
        # if asset_type == 'host':
        #     package_name, asset_type, name = 'PACKAGE_NAME_FILTER', 'host', 'VULN_HOST_FILTER'
        # elif asset_type == 'image':
        #     package_name, asset_type, name = 'PACKAGE_NAME_FILTER', 'image', 'VULN_IMAGE_FILTER'

        vulnerabilities_list, total_vulnerabilities = await get_vulnerabilities(baseurl, token_manager, asset_type, session, semaphore)
        cve_tags_dict = {}
        cve_tags_dict = await process_vulnerabilities(vulnerabilities_list, VULN_TAG, cve_tags_dict)
        await process_tags(computeurl, ctoken_manager, cve_tags_dict, session, semaphore)
    logging.info(Fore.LIGHTGREEN_EX + f'Time taken: {(time.time() - start_time) / 60:.2f} minutes')


# Run the async main function
if __name__ == '__main__':
    asyncio.run(main())
