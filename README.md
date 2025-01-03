# Wordpress Plugin Downloader and Auditor

Script to filter, download and audit Wordpress plugins using the official WP's API and run Semgrep over them while storing output in a SQLite database.

Full write-up: https://projectblack.io/blog/cve-hunting-at-scale/
Original GitHub repo: https://github.com/prjblk/wordpress-audit-automation

# Getting Started

## Set up

1. Clone this repo and install the dependencies + semgrep
```sh
git clone https://github.com/0xb120/wp-plugin-downlauditor
pip install -r requirements.txt
```
2. Login again to ensure Semgrep is available via path
3. Login and enable semgrep scan for better results
```sh
semgrep login
```
4. Run the script
5. Triage output

## Description

The script works in three different modes:
- **download**: Download worpress plugins using the [official WP APIs and specific filters](https://developer.wordpress.org/reference/functions/plugins_api/). Plugins are stored inside the `plugins` folder (`download-dir/plugins/plugin-name/version/`). Plugin information are stored inside a SQLite database.
- **audit**: Audit the `plugins` folder using `semgrep` and specific rules provided to the script. Audit results are stored inside a SQLite database.
- **both**: Run the script in download mode and then in audit mode.

Information stored inside the `Plugins` db table:
```sql
slug VARCHAR(255)
version VARCHAR(255)
author VARCHAR(255)
active_installs INT
downloaded INT
last_updated DATETIME
added_date DATE
download_link TEXT
```

Audit information stored inside the `Audit` db table:
```sql
slug VARCHAR(255)
version VARCHAR(255)
file_path VARCHAR(255)
check_id VARCHAR(255)
start_line INT
end_line INT
vuln_lines TEXT
message TEXT
triaged BOOLEAN
```

## Example Usage

```sh
$ python3 wp-plugin-downlauditor.py -h
usage: wp-plugin-downlauditor.py [-h] [-m {download,audit,both}] [-d DOWNLOAD_DIR] [-o OUTPUT_DB] [--clear-results] [--last-updated LAST_UPDATED] [--active-installs ACTIVE_INSTALLS] [--author AUTHOR]
                                 [--tag TAG] [--search SEARCH] [--config CONFIG] [--verbose]

Wordpress Plugin Downloader and Auditor

options:
  -h, --help            show this help message and exit
  -m {download,audit,both}, --mode {download,audit,both}
                        Select the operative mode: 
                        download = Download every available wordpress plugin using the official WP APIs. 
                        audit = Audit the plugins folder using semgrep and specific rules. 
                        both = run the script in download mode and then in audit mode.
  -d DOWNLOAD_DIR, --download-dir DOWNLOAD_DIR
                        Directory containing the plugins folder (default: current directory)
  -o OUTPUT_DB, --output-db OUTPUT_DB
                        Store plugins and audits data inside the specified SQLite database
  --clear-results       Clear the audit database before running
  --last-updated LAST_UPDATED
                        Max number of months passed from the last_update (default: 24 months)
  --active-installs ACTIVE_INSTALLS
                        Min number of active_installs (default: 50)
  --author AUTHOR       Author's username to filter plugins
  --tag TAG             Tag to filter plugins
  --search SEARCH       Search term to filter plugins
  --config CONFIG       Semgrep config/rules to run (default: p/php) [audit mode only]
  --verbose             Print detailed messages
```

