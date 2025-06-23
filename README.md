# pc_scripts

<img src="https://github.com/okostine-panw/VortexCloud/blob/main/og-image.png" width="400">

## Requirements

To run this code, you will need:

- Python 3.10 or later (tested with 3.12)
- see pyproject.toml for Python libraries dependencies


## Installation
UV is the easiest and fastest Python virtual environment tool and is used here, but you can use any venv of your choice
1. Setup **uv** on your local machine - https://github.com/astral-sh/uv:
   Optional, install python within the uv project
```bash
   uv python install python3.12
```
2. Clone this repository to your local machine:
```
   git clone https://github.com/okostine-panw/pc_scripts.git
```
3. Install dependencies from the pyproject.toml (windows does not support uvloop uvtool, please see the comments in the script)
  ```
    cd pc_scripts
    uv run
  ```
Optional manual dependencies install:
    uv add aiohttp asyncio configparser colorama tenacity json5 orjson uvloop

## Configuration

### API Configuration
config.jsonc is used for configuration options
The parameters to configure are:
```
    // used for API_config-COMPANY.ini and filenames
    "COMPANY": "yourcompany",
    // Used for results and API Config filenames
    "FILENAME_PREFIX": "os.path.basename(__file__)",
    // disable SSL cert verification for proxies that don't support it
    //or if CA cert chain is not possible to generate for this script
    // see here on how to generate one for your proxy if required: https://github.com/PaloAltoNetworks/prismacloud-api-python/blob/main/scripts/pcs_ssl_configure.py
    "SSL_VERIFY": false,
    "RUN_ON_WINDOWS": false, // disable uvloop, also need to remove it from import statement and pyproject.toml
```
Please see other available parameters in config.jsonc file

### API Configuration
The script uses a local `.ini` configuration file (`API_config-COMPANY.ini`) to manage credentials securely. Make sure to update the file appended with your COMPANY name variable with your Prisma Cloud API details.
Optional AWS Secret code is included in the comments.

**Example `API_config-<COMPANY>.ini`**:
```ini
[URL]
BaseURL = https://api<your_stack>.prismacloud.api
twistlockBaseURL =

[AUTHENTICATION]
ACCESS_KEY_ID = your_access_key_id
SECRET_KEY = your_secret_key
```
twistlockBaseURL - not required, will be retrieved automatically

## Usage
  ```
uv run main-vulntags-baseline.py
  ```

## Scripts

### delete_stale_users.py
delete_stale_users.py - delete inactive users that have not logged in after a pre-defined time period (not_active_days) or users that have never logged and have not been modified/created for a given time period (never_login_after_days).

### copy_compliance_report.py
copy_compliance_report.py - generates new copies of existing reports for new compliance standard by cloning existing reports for a given "old" compliance standard, need to provide Old and New Compliance Standard IDs

### main-vulntags-baseline.py
main-vulntags-baseline.py - creates Vulnerability Tag to use for exceptions, retrieves vulnerabilities based on vulnerability search criteria and assigns CVEs for each resource type to this tag.
See config.jsonc for more options

### main-update-collections.py
main-update-collections.py - update collections for hosts dynamically matching host filter, works for two types: hosts for clusters, etc. and for defenders based collections (registry scanning)
See config-collections.jsonc for more options

### pc_update_code_notifications_search.py
pc_update_code_notifications_search.py - update an existing AppSec Code notifications for the repository  and Error categories selection. Allows selection of all Public, all private, all repos and search for repositories names to be included, selection of error categories policies to include and severity level. Works with existing notification rules, the integration must be already configured via UI to be able to use the script to update the existing notification rules config. Saves csv file for the processed notification rule repos and policies for debugging.
Requires Prisma Cloud AppSec Admin role to modify notification rules config.
Search is performed with fuzzy logic, current similarity_threshold=0.4, increase the threshold value to get more granular results.

### pc_update_agentless_hub_mode.py
pc_update_agentless_hub_mode.py - update onboarded accounts/subscriptions from default same-account scan mode to hub scan mode. This script will discover any accounts that are onboarded and set to the default scan mode to hub-scan mode with your desired hub mode and regions instead.

## Usage
#### ### main-vulntags-baseline.py Usage
  ```
% uv run main-vulntags-baseline.py
2025-03-14 12:02:57 - DEBUG - get_vulnerabilities - 423 - Query: {'query': "vulnerability where risk.factors IN ( 'Exploit Exists - In The Wild', 'Exploit Exists - Poc' ) AND severity = 'Critical' AND asset.lifecycle = 'run'"}
2025-03-14 12:02:58 - INFO - get_vulnerabilities - 461 - TOTAL Vulnerabilities CVEs: 146 - Retrieved: 30  Total assets: 77
2025-03-14 12:02:58 - DEBUG - process_vulnerabilities - 489 - Added CVE: CVE-2016-2148 with asset_type: image under tag: Ignore-Baseline-310325
2025-03-14 12:02:58 - DEBUG - process_vulnerabilities - 489 - Added CVE: CVE-2016-5018 with asset_type: image under tag: Ignore-Baseline-310325
2025-03-14 12:02:58 - DEBUG - process_vulnerabilities - 489 - Added CVE: CVE-2016-8735 with asset_type: image under tag: Ignore-Baseline-310325
2025-03-14 12:02:58 - DEBUG - process_vulnerabilities - 489 - Added CVE: CVE-2017-12629 with asset_type: host under tag: Ignore-Baseline-310325
2025-03-14 12:02:58 - DEBUG - process_vulnerabilities - 489 - Added CVE: CVE-2017-8046 with asset_type: image under tag: Ignore-Baseline-310325
2025-03-14 12:02:58 - DEBUG - process_vulnerabilities - 489 - Added CVE: CVE-2018-1270 with asset_type: image under tag: Ignore-Baseline-310325
2025-03-14 12:02:58 - DEBUG - process_vulnerabilities - 489 - Added CVE: CVE-2018-16492 with asset_type: image under tag: Ignore-Baseline-310325
2025-03-14 12:02:58 - DEBUG - process_vulnerabilities - 489 - Added CVE: CVE-2018-3739 with asset_type: image under tag: Ignore-Baseline-310325
2025-03-14 12:02:58 - DEBUG - process_vulnerabilities - 489 - Added CVE: CVE-2018-3750 with asset_type: image under tag: Ignore-Baseline-310325
2025-03-14 12:02:58 - DEBUG - process_vulnerabilities - 489 - Added CVE: CVE-2019-5413 with asset_type: image under tag: Ignore-Baseline-310325
2025-03-14 12:02:58 - DEBUG - process_vulnerabilities - 489 - Added CVE: CVE-2020-15999 with asset_type: image under tag: Ignore-Baseline-310325
2025-03-14 12:02:58 - DEBUG - process_vulnerabilities - 489 - Added CVE: CVE-2020-1938 with asset_type: image under tag: Ignore-Baseline-310325
2025-03-14 12:02:58 - DEBUG - process_vulnerabilities - 489 - Added CVE: CVE-2020-8178 with asset_type: image under tag: Ignore-Baseline-310325
2025-03-14 12:02:58 - DEBUG - process_vulnerabilities - 489 - Added CVE: CVE-2021-31535 with asset_type: image under tag: Ignore-Baseline-310325
2025-03-14 12:02:58 - DEBUG - process_vulnerabilities - 489 - Added CVE: CVE-2021-3918 with asset_type: image under tag: Ignore-Baseline-310325
2025-03-14 12:02:58 - DEBUG - process_vulnerabilities - 489 - Added CVE: CVE-2021-44228 with asset_type: image under tag: Ignore-Baseline-310325
2025-03-14 12:02:58 - DEBUG - process_vulnerabilities - 489 - Added CVE: CVE-2021-45046 with asset_type: image under tag: Ignore-Baseline-310325
2025-03-14 12:02:58 - DEBUG - process_vulnerabilities - 489 - Added CVE: CVE-2022-1471 with asset_type: host under tag: Ignore-Baseline-310325
2025-03-14 12:02:58 - DEBUG - process_vulnerabilities - 489 - Added CVE: CVE-2022-1471 with asset_type: image under tag: Ignore-Baseline-310325
2025-03-14 12:02:58 - DEBUG - process_vulnerabilities - 489 - Added CVE: CVE-2022-1996 with asset_type: host under tag: Ignore-Baseline-310325
2025-03-14 12:02:58 - DEBUG - process_vulnerabilities - 489 - Added CVE: CVE-2022-1996 with asset_type: image under tag: Ignore-Baseline-310325
2025-03-14 12:02:58 - DEBUG - process_vulnerabilities - 489 - Added CVE: CVE-2022-22965 with asset_type: image under tag: Ignore-Baseline-310325
2025-03-14 12:02:58 - DEBUG - process_vulnerabilities - 489 - Added CVE: CVE-2022-23221 with asset_type: host under tag: Ignore-Baseline-310325
2025-03-14 12:02:58 - DEBUG - process_vulnerabilities - 489 - Added CVE: CVE-2022-32207 with asset_type: image under tag: Ignore-Baseline-310325
2025-03-14 12:02:58 - DEBUG - process_vulnerabilities - 489 - Added CVE: CVE-2022-32221 with asset_type: image under tag: Ignore-Baseline-310325
2025-03-14 12:02:58 - DEBUG - process_vulnerabilities - 489 - Added CVE: CVE-2023-23914 with asset_type: host under tag: Ignore-Baseline-310325
2025-03-14 12:02:58 - DEBUG - process_vulnerabilities - 489 - Added CVE: CVE-2023-23914 with asset_type: image under tag: Ignore-Baseline-310325
2025-03-14 12:02:58 - DEBUG - process_vulnerabilities - 489 - Added CVE: CVE-2023-30547 with asset_type: image under tag: Ignore-Baseline-310325
2025-03-14 12:02:58 - DEBUG - process_vulnerabilities - 489 - Added CVE: CVE-2023-32314 with asset_type: image under tag: Ignore-Baseline-310325
2025-03-14 12:02:58 - DEBUG - process_vulnerabilities - 489 - Added CVE: CVE-2023-38408 with asset_type: image under tag: Ignore-Baseline-310325
2025-03-14 12:02:58 - DEBUG - process_vulnerabilities - 489 - Added CVE: CVE-2024-23897 with asset_type: host under tag: Ignore-Baseline-310325
2025-03-14 12:02:58 - DEBUG - process_vulnerabilities - 489 - Added CVE: CVE-2024-4577 with asset_type: image under tag: Ignore-Baseline-310325
2025-03-14 12:02:58 - INFO - process_tags - 532 - Updating Tags
2025-03-14 12:02:58 - INFO - process_tags - 547 - Updating Ignore-Baseline-310325 tag
2025-03-14 12:02:58 - INFO - update_vulnerability_tags - 507 - Tag 'Ignore-Baseline-310325' updated successfully for 29 vulnerabilities.
2025-03-14 12:02:58 - INFO - process_tags - 552 - Ignore-Baseline-310325 Tag updated successfully for 29 vulnerabilities.
Total vulnerabilities processed across all tags: 29
2025-03-14 12:02:58 - INFO - main - 616 - Time taken: 0.05 minutes
  ```
### pc_update_code_notifications_search.py usage
  ```
cloudskates % uv run pc_update_code_notifications_search.py
Token expired or not available, refreshing...
Fetching policies from https://api2.prismacloud.io/bridgecrew/api/v2/policies...
Successfully fetched policies from the API.

Available policy categories:
  1. Compute
  2. Drift
  3. General
  4. IAM
  5. Kubernetes
  6. Licenses
  7. Logging
  8. Monitoring
  9. Networking
  10. Public
  11. Sast
  12. Secrets
  13. Storage
  14. Vulnerabilities
  0. Select all (do not exclude any categories by category)
Enter numbers of categories to INCLUDE, separated by commas (e.g., 1,3,5), or 0 for all: 1,5,9,8
Selected categories for inclusion: Compute, Kubernetes, Networking, Monitoring
Successfully saved data to bridgecrew_policies.csv

==================================================

Fetching all repositories from API for selection...
Fetching repositories from https://api2.prismacloud.io/code/api/v1/repositories...
Successfully fetched repositories from the API.
Successfully fetched 143 repositories from the API.

---
## Repository Selection Options
How would you like to select repositories?
1. Public Repositories Only
2. Private Repositories Only
3. All Repositories (Public and Private)
4. Search Repositories by Name

Please enter the number corresponding to your choice (1, 2, 3, or 4): 4
Enter a search term for repository names (e.g., 'backend', 'my-app'): okostine-panw
DEBUG: Total repos available for search: 143
DEBUG: Repository names extracted for search (143): ['PCS-LAB-ORG/c2c-sample-repo', '']... (showing first 10)
DEBUG: difflib.get_close_matches results for 'okostine-panw' (cutoff=0.4): ['okostine-panw/crapi', 'okostine-panw/pygoat', 'okostine-panw/aigoat', 'okostine-panw/badcode', 'okostine-panw/juice-shop', 'okostine-panw/terraform-goof', 'okostine-panw/kubernetes-goof', '806775482162247680_okostine-panw/cspm', 'okostine-panw/infrastructure-as-code-goof', '806775482162247680_okostine-panw/sastrules_workshop']

Found 10 matching repositories:
  1. okostine-panw/crAPI (Public: True)
  2. okostine-panw/pygoat (Public: True)
  3. okostine-panw/AIGoat (Public: True)
  4. okostine-panw/badCode (Public: True)
  5. okostine-panw/juice-shop (Public: True)
  6. okostine-panw/terraform-goof (Public: True)
  7. okostine-panw/kubernetes-goof (Public: True)
  8. 806775482162247680_okostine-panw/cspm (Public: False)
  9. okostine-panw/infrastructure-as-code-goof (Public: True)
  10. 806775482162247680_okostine-panw/sastrules_workshop (Public: False)
  0. Select none / Go back to previous menu
  Enter 'all' to select all 10 found repos.
Enter numbers of repositories to INCLUDE, separated by commas (e.g., 1,3,5), or 'all', or 0 to go back: all
All 10 repositories from search results selected.
Successfully saved data to bridgecrew_repositories.csv

==================================================

Starting pcNotifications update process...
Fetching notification schemes from https://api2.prismacloud.io/bridgecrew/api/v1/vcs/settings/scheme...
Successfully fetched notification schemes.
Available pcNotifications schemes (deduplicated):
  1. Name: OK-Others-Test_okostine-panw_okostine-panw_BC_REPOS_Compute_Drift_General_BC_CATEGORIES
  2. Name: OK-Secrets-Test_ALL_PUBLIC_REPOS_BC_REPOS_Secrets_BC_CATEGORIES
  3. Name: OK-Vulnerabilities-Test_ALL_REPOS_BC_REPOS_Vulnerabilities_BC_CATEGORIES
Enter the number of the pcNotifications scheme to update (or 'q' to skip): 1
Selected for update: OK-Others-Test_okostine-panw_okostine-panw_okostine-panw_BC_REPOS_Compute_Kubernetes_Monitoring_Networking_BC_CATEGORIES
Retrieved existing integrationId for 'OK-Others-Test_okostine-panw_okostine-panw_BC_REPOS_Compute_Drift_General_BC_CATEGORIES': c71c9a24-0d59-4198-929e-35678e63fb9b

Select severity level:
  1. LOW
  2. MEDIUM
  3. HIGH
  4. CRITICAL
Enter the number corresponding to the severity level: 4
Selected severity level: CRITICAL
Attempting to update notification scheme...
Notification scheme updated successfully!
Notification scheme 'OK-Others-Test_okostine-panw_okostine-panw_okostine-panw_BC_REPOS_Compute_Kubernetes_Monitoring_Networking_BC_CATEGORIES' successfully updated.

Script finished in: 1.15 minutes.
  ```
