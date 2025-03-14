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
    uv add aiohttp asyncio configparser colorama tenacity json5 orjson uvloop
    uv run
  ```
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
#### Usage
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
