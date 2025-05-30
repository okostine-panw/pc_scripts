import aiohttp
import asyncio
import configparser
import json
import os
import sys
import csv
import time
from datetime import datetime
from colorama import Fore, Style, init
import difflib # For fuzzy matching
# Initialize Colorama
init(autoreset=True)
# Global semaphore to limit concurrent requests
semaphore = asyncio.Semaphore(5) # Adjust as needed
# Configuration Constants (replace with your actual paths/values or environment variables)
API_CONFIG_PATH = 'API_config.ini' # Path to your API configuration file
POLICIES_OUTPUT_CSV_FILE = 'bridgecrew_policies.csv'
REPOS_OUTPUT_CSV_FILE = 'bridgecrew_repositories.csv'
SSL_VERIFY = False # Set to False to disable SSL verification (use with caution)
CATEGORY_SUFFIX_MARKER = "_BC_CATEGORIES" # Marker for policy category naming convention
REPO_SELECTION_MARKER = "_BC_REPOS" # New marker for repo selection naming convention
DYNAMIC_REPO_LABELS = ["ALL_REPOS", "ALL_PRIVATE_REPOS", "ALL_PUBLIC_REPOS"]
start_script_time = time.time()
class TokenManager:
    """Manages acquisition and refreshing of authentication tokens."""
    def __init__(self, baseurl, access_key_id, secret_key, session):
        self.baseurl = baseurl
        self.access_key_id = access_key_id
        self.secret_key = secret_key
        self.token = None
        self.token_expiry_time = 0
        self.lock = asyncio.Lock()
        self.session = session


    async def get_token(self):
        """Retrieves or refreshes the authentication token."""
        async with self.lock:
            # Check if token is invalid or expired (giving a 30-second buffer)
            if not self.token or time.time() >= self.token_expiry_time - 30:
                print(f"{Fore.YELLOW}Token expired or not available, refreshing...{Fore.RESET}")
                await self._refresh_token()
            return self.token


    async def _refresh_token(self):
        """Internal method to refresh the authentication token."""
        url = f'{self.baseurl}/login'
        headers = {'Content-Type': 'application/json'}
        data = {'username': self.access_key_id, 'password': self.secret_key}
        async with self.session.post(url, headers=headers, json=data, ssl=SSL_VERIFY) as response:  # Use self.session
            if response.status == 200:
                response_data = await response.json()
                self.token = response_data.get('token')
                self.token_expiry_time = time.time() + 480
            else:
                raise Exception(f'Failed to get access token: {await response.text()}')


def read_api_config():
    """Reads API configuration from API_config-pso.ini."""
    config = configparser.ConfigParser()
    if not os.path.exists(API_CONFIG_PATH):
        raise FileNotFoundError(f"Configuration file not found: {API_CONFIG_PATH}. Please create it with [URL] and [AUTHENTICATION] sections.")
    config.read(API_CONFIG_PATH)
    try:
        baseurl = config.get('URL', 'BaseURL')
        access_key_id = config.get('AUTHENTICATION', 'ACCESS_KEY_ID')
        secret_key = config.get('AUTHENTICATION', 'SECRET_KEY')
        return baseurl, access_key_id, secret_key
    except configparser.NoSectionError as e:
        raise ValueError(f"Missing section in config file: {e}. Ensure [URL] and [AUTHENTICATION] exist in {API_CONFIG_PATH}.")
    except configparser.NoOptionError as e:
        raise ValueError(f"Missing option in config file: {e}. Ensure BaseURL in [URL] and ACCESS_KEY_ID, SECRET_KEY in [AUTHENTICATION] exist in {API_CONFIG_PATH}.")


async def get_bridgecrew_policies(baseurl, token_manager, session, retries=3):
    """
    Fetches all policy data from the Bridgecrew API.
    Args:
        baseurl (str): The base URL of the Bridgecrew API.
        token_manager (TokenManager): An instance of the TokenManager.
        session (aiohttp.ClientSession): The aiohttp client session.
        retries (int): Number of retries for the API call.
    Returns:
        list: A list of policy dictionaries, or an empty list if an error occurs.
    """
    token = await token_manager.get_token()
    policies_url = f"{baseurl}/bridgecrew/api/v2/policies"
    headers = {
        'Authorization': f"Bearer {token}",
        'Content-Type': 'application/json'
    }
    print(f"{Fore.YELLOW}Fetching policies from {policies_url}...{Fore.RESET}")
    for attempt in range(retries):
        try:
            async with semaphore:  # Acquire semaphore before making the request
                async with session.get(policies_url, headers=headers, ssl=SSL_VERIFY, timeout=30) as response:
                    if response.status == 404:
                        print(f"{Fore.YELLOW}Policies endpoint not found (404) at {policies_url}. Attempt {attempt + 1}/{retries}.{Fore.RESET}")
                        return []  # Return empty list if the endpoint itself is not found
                    response.raise_for_status()  # Raise an exception for other bad status codes (4xx, 5xx)
                    policies_data = await response.json()
                    print(f"{Fore.GREEN}Successfully fetched policies from the API.{Fore.RESET}")
                    return policies_data
        except aiohttp.ClientError as e:
            print(f"{Fore.RED}API request failed (attempt {attempt + 1}/{retries}): {e}. Retrying...{Fore.RESET}")
            await asyncio.sleep(2 ** attempt)  # Exponential backoff
        except Exception as e:
            print(f"{Fore.RED}An unexpected error occurred during policy fetch (attempt {attempt + 1}/{retries}): {e}. Retrying...{Fore.RESET}")
            await asyncio.sleep(2 ** attempt)
    print(f"{Fore.RED}Failed to fetch policies after {retries} attempts.{Fore.RESET}")
    return []


async def get_repositories(baseurl, token_manager, session, retries=3):
    """
    Fetches all repository data from the Prisma Cloud API.
    Args:
        baseurl (str): The base URL of the Prisma Cloud API.
        token_manager (TokenManager): An instance of the TokenManager.
        session (aiohttp.ClientSession): The aiohttp client session.
        retries (int): Number of retries for the API call.
    Returns:
        list: A list of all repository dictionaries, or an empty list if an error occurs.
    """
    token = await token_manager.get_token()
    repos_url = f"{baseurl}/code/api/v1/repositories"
    headers = {
        'Authorization': f"Bearer {token}",
        'Content-Type': 'application/json'
    }
    print(f"{Fore.YELLOW}Fetching repositories from {repos_url}...{Fore.RESET}")
    for attempt in range(retries):
        try:
            async with semaphore:  # Acquire semaphore before making the request
                async with session.get(repos_url, headers=headers, ssl=SSL_VERIFY, timeout=30) as response:
                    if response.status == 404:
                        print(f"{Fore.YELLOW}Repositories endpoint not found (404) at {repos_url}. Attempt {attempt + 1}/{retries}.{Fore.RESET}")
                        return []
                    response.raise_for_status()
                    repos_data = await response.json()
                    print(f"{Fore.GREEN}Successfully fetched repositories from the API.{Fore.RESET}")
                    return repos_data  # Assuming all repos are returned in one go, no pagination
        except aiohttp.ClientError as e:
            print(f"{Fore.RED}API request failed (attempt {attempt + 1}/{retries}): {e}. Retrying...{Fore.RESET}")
            await asyncio.sleep(2 ** attempt)
        except Exception as e:
            print(f"{Fore.RED}An unexpected error occurred during repository fetch (attempt {attempt + 1}/{retries}): {e}. Retrying...{Fore.RESET}")
            await asyncio.sleep(2 ** attempt)
    print(f"{Fore.RED}Failed to fetch repositories after {retries} attempts.{Fore.RESET}")
    return []


def save_data_to_csv(data_list, output_file, fieldnames, aggregated_ids_list=None, aggregated_column_name=None, json_payload_key=None):
    """
    Saves a list of dictionaries to a CSV file.
    Args:
        data_list (list): A list of dictionaries to save.
        output_file (str): The name of the CSV file to save the data to.
        fieldnames (list): A list of strings representing the CSV header.
        aggregated_ids_list (list, optional): A list of IDs/names to be aggregated into a single cell
                                              in the last row. Defaults to None.
        aggregated_column_name (str, optional): The name of the column in the last row where
                                                the JSON-formatted aggregated IDs will be placed.
                                                Required if aggregated_ids_list is provided.
        json_payload_key (str, optional): The key to use within the JSON object (e.g., "excludePolicies", "repos").
                                          Required if aggregated_ids_list is provided.
    """
    if not data_list and not aggregated_ids_list:
        print(f"{Fore.YELLOW}No data to save to {output_file}.{Fore.RESET}")
        return
    # Prepare data to only include specified fieldnames
    prepared_data = []
    for item in data_list:
        row = {}
        for field in fieldnames:
            if field == "frameworks":
                # Convert the list of frameworks to a comma-separated string
                frameworks_list = item.get(field, [])
                row[field] = ", ".join(frameworks_list) if frameworks_list else "N/A"
            else:
                row[field] = item.get(field, "N/A")  # Get value, or "N/A" if key is missing
        prepared_data.append(row)
    # --- Add the extra row for aggregated data in valid JSON format ---
    # Need to handle current_fieldnames correctly if it's modified in the block
    current_fieldnames = list(fieldnames)  # Start with a mutable copy
    if aggregated_ids_list and aggregated_column_name and json_payload_key:
        # Create a dictionary for the specified payload key and convert to valid JSON string
        exclude_payload = {json_payload_key: aggregated_ids_list}
        json_string = json.dumps(exclude_payload)
        # Create the final row, initially with empty strings for all current_fieldnames
        final_row = {field: "" for field in current_fieldnames}
        # Place the JSON string into the specified aggregated_column_name
        final_row[aggregated_column_name] = json_string
        # If the aggregated_column_name is not in the original fieldnames, add it
        if aggregated_column_name not in current_fieldnames:
            current_fieldnames.append(aggregated_column_name)
            # If a new column was added, and it wasn't already in final_row, add it
            if aggregated_column_name not in final_row:
                final_row[aggregated_column_name] = json_string
        # Add a generic label if there's a first column and it's not the aggregated column
        if current_fieldnames and current_fieldnames[0] != aggregated_column_name:
            final_row[current_fieldnames[0]] = "Aggregated Data"
        prepared_data.append(final_row)
    try:
        with open(output_file, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=current_fieldnames)  # Use the potentially updated fieldnames
            writer.writeheader()  # Write the header row
            writer.writerows(prepared_data)  # Write the prepared data rows
        print(f"{Fore.GREEN}Successfully saved data to {output_file}{Fore.RESET}")
    except IOError as e:
        print(f"{Fore.RED}Error writing to CSV file {output_file}: {e}{Fore.RESET}")
    except Exception as e:
        print(f"{Fore.RED}An unexpected error occurred while writing CSV: {e}{Fore.RESET}")


# --- Functions for Notifications ---

async def get_notification_schemes(baseurl, token_manager, session, retries=3):
    """
    Fetches notification scheme data from the Bridgecrew API.
    Args:
        baseurl (str): The base URL of the Bridgecrew API.
        token_manager (TokenManager): An instance of the TokenManager.
        session (aiohttp.ClientSession): The aiohttp client session.
        retries (int): Number of retries for the API call.
    Returns:
        dict: The full response dictionary containing all notification types, or None if an error occurs.
    """
    token = await token_manager.get_token()
    notifications_url = f"{baseurl}/bridgecrew/api/v1/vcs/settings/scheme"
    headers = {
        'Authorization': f"Bearer {token}",
        'Content-Type': 'application/json'
    }
    print(f"{Fore.YELLOW}Fetching notification schemes from {notifications_url}...{Fore.RESET}")
    for attempt in range(retries):
        try:
            async with semaphore:
                async with session.get(notifications_url, headers=headers, ssl=SSL_VERIFY, timeout=30) as response:
                    response.raise_for_status()
                    response_data = await response.json()
                    print(f"{Fore.GREEN}Successfully fetched notification schemes.{Fore.RESET}")
                    return response_data  # Return the full response data
        except aiohttp.ClientError as e:
            print(f"{Fore.RED}API request failed (attempt {attempt + 1}/{retries}): {e}. Retrying...{Fore.RESET}")
            await asyncio.sleep(2 ** attempt)
        except Exception as e:
            print(f"{Fore.RED}An unexpected error occurred during notification scheme fetch (attempt {attempt + 1}/{retries}): {e}. Retrying...{Fore.RESET}")
            await asyncio.sleep(2 ** attempt)
    print(f"{Fore.RED}Failed to fetch notification schemes after {retries} attempts.{Fore.RESET}")
    return None


def get_integration_id_by_section_name(all_schemes_data, section_name):
    """
    Helper function to find integrationId based on section name from the original data.
    This is important because `unique_notification_sections` might lose the exact
    section object if there were duplicates. We need the original section to
    find its integrationId if it existed.
    """
    if all_schemes_data and 'pcNotifications' in all_schemes_data:
        for section in all_schemes_data['pcNotifications'].get('sections', []):
            if section.get('name') == section_name:
                integrations = section.get('rule', {}).get('pcNotificationIntegrations', [])
                if integrations and integrations[0].get('integrationId'):
                    return integrations[0]['integrationId']
    return None


async def update_notification_scheme(baseurl, token_manager, session, updated_payload, retries=3):
    """
    Updates notification scheme data via the Bridgecrew API.
    Args:
        baseurl (str): The base URL of the Bridgecrew API.
        token_manager (TokenManager): An instance of the TokenManager.
        session (aiohttp.ClientSession): The aiohttp client client_session.
        updated_payload (dict): The full payload for the POST request.
        retries (int): Number of retries for the API call.
    Returns:
        bool: True if the update was successful, False otherwise.
    """
    token = await token_manager.get_token()
    notifications_url = f"{baseurl}/bridgecrew/api/v1/vcs/settings/scheme"
    headers = {
        'Authorization': f"Bearer {token}",
        'Content-Type': 'application/json'
    }
    print(f"{Fore.YELLOW}Attempting to update notification scheme...{Fore.RESET}")
    for attempt in range(retries):
        try:
            async with semaphore: # Ensure semaphore is defined globally
                async with session.post(notifications_url, headers=headers, json=updated_payload, ssl=SSL_VERIFY, timeout=30) as response:
                    response.raise_for_status()
                    print(f"{Fore.GREEN}Notification scheme updated successfully!{Fore.RESET}")
                    return True
        except aiohttp.ClientResponseError as e:
            print(f"{Fore.RED}API response error (attempt {attempt + 1}/{retries}): {e.status} - {e.message}. Retrying...{Fore.RESET}")
            await asyncio.sleep(2 ** attempt)
        except aiohttp.ClientError as e:
            print(f"{Fore.RED}API request failed (attempt {attempt + 1}/{retries}): {e}. Retrying...{Fore.RESET}")
            await asyncio.sleep(2 ** attempt)
        except Exception as e:
            print(f"{Fore.RED}An unexpected error occurred during notification scheme update (attempt {attempt + 1}/{retries}): {e}. Retrying...{Fore.RESET}")
            await asyncio.sleep(2 ** attempt)
    print(f"{Fore.RED}Failed to update notification scheme after {retries} attempts.{Fore.RESET}")
    return False


# --- New helper function for searching repositories ---
def fuzzy_search_repos(all_available_repos, search_query, similarity_threshold=0.4):
    """
    Performs a fuzzy search on repository names and returns matching repos.
    Uses difflib.SequenceMatcher for a basic similarity score.
    """
    matched_repos = []
    # Print the raw data being searched
    print(f"{Fore.MAGENTA}DEBUG: Total repos available for search: {len(all_available_repos)}{Fore.RESET}")
    # print(f"{Fore.MAGENTA}DEBUG: First 5 raw repos: {all_available_repos[:5]}{Fore.RESET}") # Uncomment for more detail
    repo_name_map = {}
    for repo in all_available_repos:
        owner = repo.get('owner')
        repo_name = repo.get('repository')
        if owner and repo_name:
            full_repo_name = f"{owner}/{repo_name}"
            repo_name_map[full_repo_name] = repo
        else:
            print(f"{Fore.YELLOW}WARNING: Repository entry missing 'owner' or 'repository' key: {repo}{Fore.RESET}")
    repo_names = list(repo_name_map.keys())
    print(f"{Fore.MAGENTA}DEBUG: Repository names extracted for search ({len(repo_names)}): {repo_names[:10]}... (showing first 10){Fore.RESET}") # Show a sample
    # Get close matches using difflib
    matches = difflib.get_close_matches(
        search_query.lower(),
        [name.lower() for name in repo_names],
        n=len(repo_names),
        cutoff=similarity_threshold,
    )
    print(f"{Fore.MAGENTA}DEBUG: difflib.get_close_matches results for '{search_query}' (cutoff={similarity_threshold}): {matches}{Fore.RESET}")
    # Reconstruct the original repo objects from the matched names
    for match_name_lower in matches:
        # Find the original case name to get the original repo object
        original_repo_name = next(
            (name for name in repo_names if name.lower() == match_name_lower),
            None,
        )
        if original_repo_name:
            matched_repos.append(repo_name_map[original_repo_name])
    return matched_repos


async def main():
    """Main asynchronous function to orchestrate the policy and repository fetching and saving."""
    try:
        baseurl, access_key_id, secret_key = read_api_config()
    except (FileNotFoundError, ValueError) as e:
        print(f"{Fore.RED}Configuration error: {e}{Fore.RESET}")
        sys.exit(1)  # Exit if configuration cannot be loaded
    async with aiohttp.ClientSession() as session:
        token_manager = TokenManager(baseurl, access_key_id, secret_key, session)
        # --- Fetch and Save Policies ---
        policies = await get_bridgecrew_policies(baseurl, token_manager, session)
        # Populate all_policy_categories including "Secrets"
        all_policy_categories = sorted(list(set(p.get("category") for p in policies if p.get("category"))))
        excluded_incident_ids = []
        if policies:
            print(f"\n{Fore.CYAN}Available policy categories:{Fore.RESET}")
            for i, category in enumerate(all_policy_categories):
                print(f"  {i + 1}. {category}")
            print(f"  0. Select all (do not exclude any categories by category)")
            selected_category_names_for_inclusion = []
            while True:
                category_choices_input = input(
                    f"{Fore.CYAN}Enter numbers of categories to INCLUDE, separated by commas (e.g., 1,3,5), or 0 for all: {Fore.RESET}"
                ).strip()
                if category_choices_input == '0':
                    print(f"{Fore.YELLOW}All categories will be implicitly included (no policies excluded by category).{Fore.RESET}")
                    selected_category_names_for_inclusion = all_policy_categories  # Include all so none are excluded
                    break
                try:
                    chosen_indices = [int(c.strip()) for c in category_choices_input.split(',')]
                    valid_choices = True
                    for idx in chosen_indices:
                        if not (1 <= idx <= len(all_policy_categories)):
                            print(f"{Fore.RED}Invalid category number: {idx}. Please try again.{Fore.RESET}")
                            valid_choices = False
                            break
                    if valid_choices:
                        selected_category_names_for_inclusion = [all_policy_categories[i - 1] for i in chosen_indices]
                        print(f"{Fore.GREEN}Selected categories for inclusion: {', '.join(selected_category_names_for_inclusion)}{Fore.RESET}")
                        break
                except ValueError:
                    print(f"{Fore.RED}Invalid input. Please enter numbers separated by commas, or 0.{Fore.RESET}")
            # Now, populate excluded_incident_ids: include policies whose categories are NOT in selected_category_names_for_inclusion
            for policy in policies:
                if policy.get("category") not in selected_category_names_for_inclusion:
                    incident_id = policy.get("incidentId")
                    if incident_id:
                        excluded_incident_ids.append(incident_id)
            # Define policy fieldnames
            policy_fieldnames = [
                "incidentId", "checkovCheckId", "category", "pcSeverity",
                "provider", "frameworks", "descriptiveTitle", "pcPolicyId",
            ]
            save_data_to_csv(policies, POLICIES_OUTPUT_CSV_FILE, policy_fieldnames,
                             aggregated_ids_list=excluded_incident_ids,
                             aggregated_column_name="Exclude Policies JSON",
                             json_payload_key="excludePolicies")
        else:
            print(f"{Fore.YELLOW}No policies retrieved to save to CSV.{Fore.RESET}")
        print("\n" + "=" * 50 + "\n")  # Separator for better readability
        # --- Repository Visibility and Search Selection ---
        print(f"{Fore.CYAN}Fetching all repositories from API for selection...{Fore.RESET}")
        all_repos_from_api = await get_repositories(baseurl, token_manager, session)
        # DEBUG: Print the raw fetched repos to check if data is present and structured as expected
        if not all_repos_from_api:
            print(f"{Fore.RED}ERROR: No repositories were fetched from the API. Please check your API configuration and Prisma Cloud permissions.{Fore.RESET}")
            # Consider exiting or skipping repo-related operations if no repos are found
            # sys.exit(1) # Uncomment if you want to exit if no repos
        else:
            print(f"{Fore.GREEN}Successfully fetched {len(all_repos_from_api)} repositories from the API.{Fore.RESET}")
            # print(f"{Fore.MAGENTA}DEBUG: Sample of fetched repositories: {all_repos_from_api[:2]}{Fore.RESET}") # Uncomment to see first 2 repo objects
        all_repo_owner_names = []
        repo_selection_label = ""
        selected_repos = []
        search_string_for_notification = "" # Initialize variable to hold the search string if applicable
        while True:
            print(f"""
---
## Repository Selection Options
How would you like to select repositories?
1. Public Repositories Only
2. Private Repositories Only
3. All Repositories (Public and Private)
4. Search Repositories by Name
""")
            repo_choice = input(f"{Fore.CYAN}Please enter the number corresponding to your choice (1, 2, 3, or 4): {Fore.RESET}").strip()
            if repo_choice == '1':
                print(f"{Fore.CYAN}Selecting public repositories...{Fore.RESET}")
                selected_repos = [repo for repo in all_repos_from_api if repo.get("isPublic") is True]
                repo_selection_label = "ALL_PUBLIC_REPOS"
                break
            elif repo_choice == '2':
                print(f"{Fore.CYAN}Selecting private repositories...{Fore.RESET}")
                selected_repos = [repo for repo in all_repos_from_api if repo.get("isPublic") is False]
                repo_selection_label = "ALL_PRIVATE_REPOS"
                break
            elif repo_choice == '3':
                print(f"{Fore.CYAN}Selecting all repositories (public and private)...{Fore.RESET}")
                selected_repos = all_repos_from_api
                repo_selection_label = "ALL_REPOS"
                break
            elif repo_choice == '4':
                search_query = input(f"{Fore.CYAN}Enter a search term for repository names (e.g., 'backend', 'my-app'): {Fore.RESET}").strip()
                if not search_query:
                    print(f"{Fore.RED}Search query cannot be empty. Please try again.{Fore.RESET}")
                    continue
                search_string_for_notification = search_query # Store the search query
                # Pass all fetched repos to the fuzzy search
                search_results = fuzzy_search_repos(all_repos_from_api, search_query)
                if not search_results:
                    print(f"{Fore.YELLOW}No repositories found matching '{search_query}'. Please try a different search term or selection method.{Fore.RESET}")
                    continue
                print(f"\n{Fore.CYAN}Found {len(search_results)} matching repositories:{Fore.RESET}")
                for i, repo in enumerate(search_results):
                    print(f"  {i + 1}. {repo.get('owner', '')}/{repo.get('repository', '')} (Public: {repo.get('isPublic', 'N/A')})")
                print(f"  0. Select none / Go back to previous menu")
                print(f"  Enter 'all' to select all {len(search_results)} found repos.") # New option
                while True:
                    repo_indices_input = input(
                        f"{Fore.CYAN}Enter numbers of repositories to INCLUDE, separated by commas (e.g., 1,3,5), or 'all', or 0 to go back: {Fore.RESET}"
                    ).strip().lower() # .lower() for 'all' check
                    if repo_indices_input == '0':
                        selected_repos = []
                        break
                    elif repo_indices_input == 'all': # New condition for 'all'
                        selected_repos = search_results
                        print(f"{Fore.GREEN}All {len(selected_repos)} repositories from search results selected.{Fore.RESET}")
                        # Update repo_selection_label for naming convention
                        repo_selection_label = search_string_for_notification.replace(" ", "_") + "_REPOS" # Removed .upper() here
                        break
                    try:
                        chosen_indices = [int(i.strip()) for i in repo_indices_input.split(',')]
                        valid_choices = True
                        temp_selected_repos = []
                        for idx in chosen_indices:
                            if not (1 <= idx <= len(search_results)):
                                print(f"{Fore.RED}Invalid repository number: {idx}. Please try again.{Fore.RESET}")
                                valid_choices = False
                                break
                            temp_selected_repos.append(search_results[idx - 1])
                        if valid_choices:
                            selected_repos = temp_selected_repos
                            # If only one repo is selected via search, use its name
                            if len(selected_repos) == 1:
                                repo_selection_label = f"{selected_repos[0].get('owner', '').replace('/', '_')}_{selected_repos[0].get('repository', '').replace('/', '_')}_REPOS"
                            else:
                                # For multiple selected via search, use a generic "CUSTOM_SEARCH_REPOS" or similar
                                repo_selection_label = search_string_for_notification.replace(" ", "_") + "_REPOS" # Removed .upper() here
                            print(f"{Fore.GREEN}Selected {len(selected_repos)} repositories from search results.{Fore.RESET}")
                            break
                    except ValueError:
                        print(f"{Fore.RED}Invalid input. Please enter numbers separated by commas, or 'all', or 0.{Fore.RESET}")
                if selected_repos:
                    break
            else:
                print(f"{Fore.RED}Invalid choice. Please enter 1, 2, 3, or 4.{Fore.RESET}")
        if selected_repos:
            for repo in selected_repos:
                owner = repo.get("owner")
                repo_name = repo.get("repository")
                if owner and repo_name:
                    all_repo_owner_names.append(f"{owner}/{repo_name}")
            repo_fieldnames = ["id", "repository", "source", "owner", "isPublic"]
            save_data_to_csv(selected_repos, REPOS_OUTPUT_CSV_FILE, repo_fieldnames,
                             aggregated_ids_list=all_repo_owner_names,
                             aggregated_column_name="Selected Repos JSON",
                             json_payload_key="repos")
        else:
            print(f"{Fore.YELLOW}No repositories selected based on your choices.{Fore.RESET}")
        print("\n" + "=" * 50 + "\n")
        # --- Update pcNotifications Scheme ---
        print(f"{Fore.CYAN}Starting pcNotifications update process...{Fore.RESET}")
        all_schemes_data = await get_notification_schemes(baseurl, token_manager, session)
        if all_schemes_data and 'pcNotifications' in all_schemes_data:
            pc_notifications_scheme_data = all_schemes_data['pcNotifications']
            notification_sections = pc_notifications_scheme_data.get('sections', [])
            # --- Deduplicate notification sections based on their 'name' ---
            # Using a dictionary to store unique sections by name, keeping the last one encountered.
            unique_sections_dict = {}
            for section in notification_sections:
                section_name = section.get('name')
                if section_name:
                    unique_sections_dict[section_name] = section
            # Convert back to a list, these are the unique sections we will work with
            unique_notification_sections = list(unique_sections_dict.values())
            if not unique_notification_sections:
                print(f"{Fore.YELLOW}No unique pcNotifications sections found to update.{Fore.RESET}")
            else:
                print(f"{Fore.YELLOW}Available pcNotifications schemes (deduplicated):{Fore.RESET}")
                for i, section in enumerate(unique_notification_sections):
                    print(f"  {i + 1}. Name: {section.get('name', 'N/A')}")
                while True:
                    try:
                        choice = input(f"{Fore.CYAN}Enter the number of the pcNotifications scheme to update (or 'q' to skip): {Fore.RESET}").strip()
                        if choice.lower() == 'q':
                            print(f"{Fore.YELLOW}Skipping pcNotifications update.{Fore.RESET}")
                            break
                        idx = int(choice) - 1
                        if 0 <= idx < len(unique_notification_sections):
                            # Get the original data for the selected section from the deduplicated list
                            selected_section_original_data = unique_notification_sections[idx]
                            original_name_of_selected_section = selected_section_original_data.get('name', '')
                            # Create the new list of sections to send to the API.
                            # Start by copying all unique sections.
                            sections_to_send_final = [s.copy() for s in unique_notification_sections]
                            # Get the specific section to modify from this new list
                            # This is the section we will actively update
                            section_to_modify_in_payload = sections_to_send_final[idx]

                            # --- Apply conditional cleaning for templateId to ALL sections in the final payload ---
                            for section_to_process in sections_to_send_final:
                                if section_to_process.get('rule') and section_to_process['rule'].get('pcNotificationIntegrations'):
                                    for integration_dict in section_to_process['rule']['pcNotificationIntegrations']:
                                        if 'templateId' in integration_dict and (integration_dict['templateId'] is None or integration_dict['templateId'] == ""):
                                            integration_dict.pop('templateId', None)
                            # --- Naming convention logic for the selected section ---
                            # Extract base name from the original name
                            base_name = original_name_of_selected_section
                            dynamic_start_index = len(base_name) # Initialize to end of string
                            # Check for CATEGORY_SUFFIX_MARKER
                            if CATEGORY_SUFFIX_MARKER in base_name:
                                dynamic_start_index = min(dynamic_start_index, base_name.find(CATEGORY_SUFFIX_MARKER))
                            # Check for REPO_SELECTION_MARKER
                            if REPO_SELECTION_MARKER in base_name:
                                dynamic_start_index = min(dynamic_start_index, base_name.find(REPO_SELECTION_MARKER))
                            # Check for any of the DYNAMIC_REPO_LABELS
                            for label in DYNAMIC_REPO_LABELS:
                                if label in base_name:
                                    dynamic_start_index = min(dynamic_start_index, base_name.find(label))
                            # Extract the base name up to the found dynamic start index
                            base_name = base_name[:dynamic_start_index].strip('_')
                            # If the base name is empty after stripping, prompt for one
                            if not base_name:
                                print(f"{Fore.YELLOW}Selected section has no identifiable base name for naming convention. This usually happens if the original name doesn't contain a clear base part before dynamic suffixes.{Fore.RESET}")
                                temp_base_name = input(f"{Fore.CYAN}Please enter a base name for this notification scheme (e.g., 'MyAlerts'): {Fore.RESET}").strip()
                                if not temp_base_name:
                                    print(f"{Fore.RED}A base name is required. Skipping section update.{Fore.RESET}")
                                    continue # Go back to the choice prompt for the scheme
                                base_name = temp_base_name
                            # Determine new category string
                            new_categories_string = ""
                            if selected_category_names_for_inclusion and len(selected_category_names_for_inclusion) < len(all_policy_categories):
                                new_categories_string = "_".join(sorted(selected_category_names_for_inclusion))
                            else:
                                new_categories_string = "ALL_CATEGORIES"
                            # Construct the final new name for the selected section
                            final_repo_part = ""
                            if search_string_for_notification:
                                final_repo_part = search_string_for_notification.replace(" ", "_") # Use the actual search query, without .upper()
                            elif selected_repos and len(selected_repos) == 1:
                                # For a single selected repo (not from search or if search led to one), use its full name
                                final_repo_part = f"{selected_repos[0].get('owner', '')}_{selected_repos[0].get('repository', '')}".replace("/", "_")
                            else:
                                # Fallback to the generic labels for public/private/all repos
                                final_repo_part = repo_selection_label

                            final_new_section_name = (
                                f"{base_name}_"
                                f"{final_repo_part}{REPO_SELECTION_MARKER}_"
                                f"{new_categories_string}{CATEGORY_SUFFIX_MARKER}"
                            )
                            # Apply the new name to the section destined for the payload
                            section_to_modify_in_payload['name'] = final_new_section_name
                            print(f"{Fore.GREEN}Selected for update: {section_to_modify_in_payload['name']}{Fore.RESET}")
                            # Update the 'repos' and policy exclusion fields
                            section_to_modify_in_payload['repos'] = all_repo_owner_names
                            section_to_modify_in_payload['rule']['excludePolicies'] = excluded_incident_ids
                            section_to_modify_in_payload['rule']['securityCategories'] = []
                            # Get/Prompt for integrationId
                            existing_integration_id = get_integration_id_by_section_name(all_schemes_data, original_name_of_selected_section)
                            if existing_integration_id:
                                print(f"{Fore.MAGENTA}Retrieved existing integrationId for '{original_name_of_selected_section}': {existing_integration_id}{Fore.RESET}")
                                integration_id_input = existing_integration_id
                            else:
                                print(f"{Fore.YELLOW}Warning: Could not find existing integrationId for '{original_name_of_selected_section}'. You will be prompted to enter one manually.{Fore.RESET}")
                                integration_id_input = input(f"{Fore.CYAN}Enter the integrationId (e.g., '31207bd8-dd46-4154-8ce6-5d69fad628b2'): {Fore.RESET}").strip()
                                if not integration_id_input:
                                    print(f"{Fore.RED}No integrationId provided. Skipping update for this section.{Fore.RESET}")
                                    continue # Go back to the choice prompt for the scheme

                            # Prompt for severityLevel using numbers
                            severity_levels = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']
                            severity_level_input = ""
                            while True:
                                print(f"\n{Fore.CYAN}Select severity level:{Fore.RESET}")
                                for i, level in enumerate(severity_levels):
                                    print(f"  {i + 1}. {level}")
                                severity_choice = input(f"{Fore.CYAN}Enter the number corresponding to the severity level: {Fore.RESET}").strip()
                                try:
                                    severity_idx = int(severity_choice) - 1
                                    if 0 <= severity_idx < len(severity_levels):
                                        severity_level_input = severity_levels[severity_idx]
                                        print(f"{Fore.GREEN}Selected severity level: {severity_level_input}{Fore.RESET}")
                                        break
                                    else:
                                        print(f"{Fore.RED}Invalid number. Please enter a number between 1 and {len(severity_levels)}.{Fore.RESET}")
                                except ValueError:
                                    print(f"{Fore.RED}Invalid input. Please enter a number.{Fore.RESET}")

                            # Apply severity and integrationId
                            section_to_modify_in_payload['rule']['severityLevel'] = severity_level_input
                            if not section_to_modify_in_payload['rule'].get('pcNotificationIntegrations'):
                                section_to_modify_in_payload['rule']['pcNotificationIntegrations'] = [{}]
                            section_to_modify_in_payload['rule']['pcNotificationIntegrations'][0]['integrationId'] = integration_id_input
                            # --- Construct payload with the FINAL sections list ---
                            updated_payload_for_post = {
                                "scheme": {
                                    "pcNotifications": {
                                        "sections": sections_to_send_final,
                                        "enabled": pc_notifications_scheme_data.get('enabled', True)
                                    }
                                },
                                "type": "pcNotifications"
                            }
                            # print(f"{Fore.YELLOW}Sending payload: {json.dumps(updated_payload_for_post, indent=2)}{Fore.RESET}")
                            success = await update_notification_scheme(baseurl, token_manager, session, updated_payload_for_post)
                            if success:
                                print(f"{Fore.GREEN}Notification scheme '{final_new_section_name}' successfully updated.{Fore.RESET}")
                            else:
                                print(f"{Fore.RED}Failed to update notification scheme '{final_new_section_name}'.{Fore.RESET}")
                            break # Exit the loop after successful update
                        else:
                            print(f"{Fore.RED}Invalid number. Please enter a number between 1 and {len(unique_notification_sections)}.{Fore.RESET}")
                    except ValueError:
                        print(f"{Fore.RED}Invalid input. Please enter a number or 'q'.{Fore.RESET}")
        else:
            print(f"{Fore.YELLOW}Could not retrieve pcNotifications schemes or 'pcNotifications' key is missing. Check API response structure.{Fore.RESET}")
    # Calculate and print elapsed time
    end_script_time = time.time()
    elapsed_time_seconds = end_script_time - start_script_time
    elapsed_time_minutes = elapsed_time_seconds / 60
    print(f"\n{Fore.CYAN}Script finished in: {elapsed_time_minutes:.2f} minutes.{Fore.RESET}")

if __name__ == "__main__":
    # Ensure colorama initializes on Windows
    if sys.platform == "win32":
        os.system('color')
    asyncio.run(main())