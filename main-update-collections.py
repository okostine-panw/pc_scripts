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
CONFIG_FILE = "config-collections.jsonc"

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
    with open(CONFIG_FILE, "r") as f:
        config = json5.load(f)
except FileNotFoundError:
    logging.error(f"{CONFIG_FILE} not found. Exiting...")
    sys.exit(1)



# Load configuration parameters efficiently
SSL_VERIFY = config.get("SSL_VERIFY", "False")
COMPANY = config.get("COMPANY", "pcs")
# COMPUTE_CACHE_REFRESH = config.get("COMPUTE_CACHE_REFRESH", "24")
FILENAME_PREFIX = config.get("FILENAME_PREFIX")  # Get value from config
if FILENAME_PREFIX == "os.path.basename(__file__)":  # Check if it was stored as a string
    FILENAME_PREFIX = os.path.basename(__file__)  # Dynamically evaluate it
RUN_ON_WINDOWS = config.get("RUN_ON_WINDOWS", "False")
COLLECTION_NAME = config.get("COLLECTION_NAME", [])
HOSTNAME_FILTER = config.get("HOSTNAME_FILTER", [])
HOST_TYPE = config.get("HOST_TYPE", [])

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


@retry(stop=stop_after_attempt(5), wait=wait_exponential(multiplier=3, min=1, max=30))
async def make_request(method, url, token_manager, session, semaphore, payload=None, max_retries=5, backoff_factor=3):
    """Generic async request function with retry logic for GET, POST, PUT."""
    status_forcelist = {429, 500, 502, 503, 504}  # Retry on these status codes

    async with semaphore:
        for attempt in range(1, max_retries + 1):
            try:
                token = await token_manager.get_token()
                headers = {
                    'Authorization': f'Bearer {token}',
                    'Content-Type': 'application/json',
                    'Accept': 'application/json'
                }
                # Determine the request type dynamically
                async with session.request(method, url, headers=headers, json=payload, ssl=SSL_VERIFY) as response:
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


async def get_collection(computeurl, ctoken_manager, COLLECTION_NAME, session, semaphore):
    """Fetch host data from Twistlock API using `make_request()` and filter by COLLECTION_NAME."""
    collections_url = f'{computeurl}/api/v1/collections'
    # Use make_request to handle retries and errors
    response_data, status_code = await make_request("GET", collections_url, ctoken_manager, session, semaphore)
    if response_data is None or status_code != 200:
        logging.warning(f"Failed to fetch collections. Status Code: {status_code}")
        return [], None  # Return empty hosts list and None for collection data
    # Extract and return hosts only from the specified collection
    collection_hosts = set()
    matched_collection = None
    for collection in response_data:
        if collection.get("name") == COLLECTION_NAME:
            hosts = collection.get("hosts", [])
            collection_hosts.update(hosts)
            matched_collection = collection
            break  # Stop iterating once the correct collection is found
    if not matched_collection:
        logging.warning(f"Collection '{COLLECTION_NAME}' not found in the response.")
    return list(collection_hosts), matched_collection  # Return hosts list and full matched collection data


async def update_collection_hosts(computeurl, ctoken_manager, collection_name, hostname_filter, matched_collection, host_type, session, semaphore):
    """Update collection via PUT with the `hosts` field updated based on `hostname_filter`."""
    collections_update_url = f'{computeurl}/api/v1/collections/{collection_name}'
    if not matched_collection:
        logging.error(f"Collection '{collection_name}' not found. Skipping update.")
        return None, None
    # Fetch all available hosts from API
    if host_type == 'defender':
        hosts_url = f"{computeurl}/api/v33.03/defenders"
        hosts_data, status = await make_request("GET", hosts_url, ctoken_manager, session, semaphore)
        if hosts_data is None or status != 200:
            logging.warning(f"Failed to fetch hosts. Status Code: {status}")
            return None, status
        # Filter hosts based on `hostname_filter` (exact match or partial match)
        filtered_hosts = {host["hostname"] for host in hosts_data if hostname_filter in host.get("hostname", "")}
    else:
        hosts_url = f"{computeurl}/api/v1/hosts/info"
        hosts_data, status = await make_request("GET", hosts_url, ctoken_manager, session, semaphore)
        if hosts_data is None or status != 200:
            logging.warning(f"Failed to fetch hosts. Status Code: {status}")
            return None, status
        # Filter hosts based on `hostname_filter` (exact match or partial match)
        filtered_hosts = {host["hostname"] for host in hosts_data if hostname_filter in host.get("hostname", "")}
        logging.debug(f"Collection '{collection_name}' {len(filtered_hosts)} hosts matching filter: {hostname_filter}\n added hosts: {filtered_hosts}")

    if not filtered_hosts:
        logging.warning(f"No hosts matched the filter: {hostname_filter}")
        return None, 404  # Return 404 if no matching hosts
    else:
        logging.info(f"Collection '{collection_name}' updated with {len(filtered_hosts)} new hosts")

    # Extract existing hosts from the collection and update them
    existing_hosts = set(matched_collection.get("hosts", []))
    updated_hosts = existing_hosts.union(filtered_hosts)  # Merge existing and new hosts
    # Update the matched collection data with the new hosts list
    matched_collection["hosts"] = list(updated_hosts)
    # Send updated collection data via PUT request
    response_data, status = await make_request("PUT", collections_update_url, ctoken_manager, session, semaphore, payload=matched_collection)
    if status == 200:
        logging.info(f"Collection '{collection_name}' updated successfully with {len(updated_hosts)} hosts.")
    else:
        logging.warning(f"Collection '{collection_name}' update failed. Status: {status}")
        return status
    return updated_hosts, status



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
        semaphore = asyncio.Semaphore(64)  # Limit concurrency
        # hostname_filter = input(f"Cluster node hostname - e.g., 'prod-01' (exact match)").strip() or ''
        # if collection_name or hostname_filter == '': print("Invalid input. Please provide valid values")
        logging.info(f'Processing Collection: {COLLECTION_NAME}\nCluster node hostname match: {HOSTNAME_FILTER}')
        ctoken_manager = ComputeTokenManager(computeurl, access_key_id, secret_key)
        try:
            if COLLECTION_NAME and HOSTNAME_FILTER:
                logging.info(f"Updating Collection: {COLLECTION_NAME} with host {HOSTNAME_FILTER}")
                collection_existing_hosts, matched_collection = await get_collection(computeurl, ctoken_manager, COLLECTION_NAME, session, semaphore)
                logging.debug(f"Existing {COLLECTION_NAME} \nCollection hosts:  {collection_existing_hosts}")
                collection_updated_hosts, status = await update_collection_hosts(computeurl, ctoken_manager, COLLECTION_NAME, HOSTNAME_FILTER, matched_collection, HOST_TYPE, session, semaphore)
                logging.info(f"Updated Collection: {COLLECTION_NAME}. New hosts in collection:\n {collection_updated_hosts}")
            else:
                logging.info(f"Collection {COLLECTION_NAME} not updated")
        except Exception as e:
            logging.error(f"Collection {COLLECTION_NAME} not updated: {e}"); return


logging.info(Fore.LIGHTGREEN_EX + f'Time taken: {(time.time() - start_time) / 60:.2f} minutes')


# Run the async main function
if __name__ == '__main__':
    asyncio.run(main())
