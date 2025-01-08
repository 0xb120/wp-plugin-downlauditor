# Wordpress Plugin Downloader and Auditor

Script to filter, download and audit Wordpress plugins using the official WP's API and run Semgrep over them while storing output in a SQLite database.

Full write-up: https://projectblack.io/blog/cve-hunting-at-scale/

Original GitHub repo: https://github.com/prjblk/wordpress-audit-automation

Useful forked repo: https://github.com/m3ssap0/wordpress-audit-automation

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
6. Start a ready-to-go wordpress instance with `docker compose` and test the plugin dinamically

## Description

The script works in three different modes:
- **download**: Download worpress plugins using the [official WP APIs and specific filters](https://developer.wordpress.org/reference/functions/plugins_api/). Plugins are stored inside the `plugins` folder (`download-dir/plugins/plugin-name/version/`). Plugin information are stored inside a SQLite database.
- **audit**: Audit the `plugins` folder using `semgrep` and specific rules provided to the script. Audit results are stored inside a SQLite database. Semgrep "raw" results are stored for the latest version of every plugin inside a `semgrep-scan` directory.
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
last_time_scanned DATE
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
date_discovered DATE
triaged BOOLEAN
```

## Example Usage

```
$ python3 wp-plugin-downlauditor.py -h
usage: wp-plugin-downlauditor.py [-h] [-m {download,audit,both}] [-d DOWNLOAD_DIR] [--db SQLITE_DB] [--clear-results] [--last-updated LAST_UPDATED] [--active-installs ACTIVE_INSTALLS] [--author AUTHOR]
                                 [--tag TAG] [--search SEARCH] [--config CONFIG] [--verbose]

Wordpress Plugin Downloader and Auditor

options:
  -h, --help            show this help message and exit
  -m {download,audit,both}, --mode {download,audit,both}
                        Select the operative mode: download = Download every available wordpress plugin using the official WP APIs. audit = Audit the plugins folder using semgrep and specific rules. both = run
                        the script in download mode and then in audit mode.
  -d DOWNLOAD_DIR, --download-dir DOWNLOAD_DIR
                        Directory containing the plugins folder (default: current directory)
  --db SQLITE_DB        Store plugins and audits data inside the specified SQLite database
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

# Download binarymoon's plugins updated in the last 12 months, having at least 1 active install, and store the results inside test.db
$ python3 wp-plugin-downlauditor.py -m download --db test.db --author binarymoon --last-updated 12 --active-installs 1          
2025-01-08 13:23:42,466 - INFO - Started downloading.
2025-01-08 13:23:42,467 - INFO - Querying https://api.wordpress.org/plugins/info/1.2/?action=query_plugins&request[page]=1&request[per_page]=25&request[search]=&request[author]=binarymoon&request[tag]=
2025-01-08 13:23:42,905 - INFO - Total plugins: 8
2025-01-08 13:23:42,925 - INFO - Querying https://api.wordpress.org/plugins/info/1.2/?action=query_plugins&request[page]=1&request[per_page]=25&request[search]=&request[author]=binarymoon&request[tag]=
2025-01-08 13:23:44,502 - INFO - Updated data inside the DB for browser-shots 1.7.7
2025-01-08 13:23:45,311 - INFO - Updated data inside the DB for bm-custom-login 2.4.0
2025-01-08 13:23:45,984 - INFO - Updated data inside the DB for front-page-category 3.3.5
2025-01-08 13:23:48,002 - INFO - Updated data inside the DB for styleguide 1.8.1
2025-01-08 13:23:48,738 - INFO - Updated data inside the DB for tada 1.2
2025-01-08 13:23:50,052 - INFO - Updated data inside the DB for wp-toolbelt 3.6
2025-01-08 13:23:50,741 - INFO - Updated data inside the DB for translate-words 1.2.6

# Download boldgrid's plugins updated in the last 8 months, having at least 500 active installs, and store the results inside test.db
$ python3 wp-plugin-downlauditor.py -m download --db test.db --author boldgrid --last-updated 8 --active-installs 500 --verbose
2025-01-08 14:48:40,348 - INFO - Started downloading.
2025-01-08 14:48:40,348 - INFO - Querying https://api.wordpress.org/plugins/info/1.2/?action=query_plugins&request[page]=1&request[per_page]=25&request[search]=&request[author]=boldgrid&request[tag]=
2025-01-08 14:48:41,038 - INFO - Total plugins: 7
2025-01-08 14:48:41,040 - INFO - Page 1/1.
2025-01-08 14:48:41,040 - INFO - Querying https://api.wordpress.org/plugins/info/1.2/?action=query_plugins&request[page]=1&request[per_page]=25&request[search]=&request[author]=boldgrid&request[tag]=
2025-01-08 14:48:42,958 - INFO - Downloaded and extracted plugin: boldgrid-easy-seo 1.6.16
2025-01-08 14:48:42,972 - INFO - Updated data inside the DB for boldgrid-easy-seo 1.6.16
2025-01-08 14:48:43,684 - INFO - Downloaded and extracted plugin: easy-maps-block 1.0.1
2025-01-08 14:48:43,698 - INFO - Updated data inside the DB for easy-maps-block 1.0.1
2025-01-08 14:48:46,241 - INFO - Downloaded and extracted plugin: post-and-page-builder 1.27.4
2025-01-08 14:48:46,256 - INFO - Updated data inside the DB for post-and-page-builder 1.27.4
2025-01-08 14:48:46,256 - INFO - Skipping theme-grep-by-boldgrid: not enaught active installs: 30/500
2025-01-08 14:48:47,826 - INFO - Downloaded and extracted plugin: boldgrid-backup 1.16.7
2025-01-08 14:48:47,840 - INFO - Updated data inside the DB for boldgrid-backup 1.16.7
2025-01-08 14:48:50,659 - INFO - Downloaded and extracted plugin: w3-total-cache 2.8.2
2025-01-08 14:48:50,683 - INFO - Updated data inside the DB for w3-total-cache 2.8.2
2025-01-08 14:48:52,327 - INFO - Downloaded and extracted plugin: weforms 1.6.25
2025-01-08 14:48:52,341 - INFO - Updated data inside the DB for weforms 1.6.25

# Running the script again, existing data are updated and newer data are downloaded and stored
$ python3 wp-plugin-downlauditor.py -m download --db test.db --author boldgrid --last-updated 10 --active-installs 22 --verbose
2025-01-08 15:28:02,820 - INFO - Started downloading.
2025-01-08 15:28:02,820 - INFO - Querying https://api.wordpress.org/plugins/info/1.2/?action=query_plugins&request[page]=1&request[per_page]=25&request[search]=&request[author]=boldgrid&request[tag]=
2025-01-08 15:28:03,633 - INFO - Total plugins: 7
2025-01-08 15:28:03,634 - INFO - Page 1/1.
2025-01-08 15:28:03,634 - INFO - Querying https://api.wordpress.org/plugins/info/1.2/?action=query_plugins&request[page]=1&request[per_page]=25&request[search]=&request[author]=boldgrid&request[tag]=
2025-01-08 15:28:04,458 - WARNING - Plugin folder already exists, skipping folder creation: ./plugins/boldgrid-easy-seo/1.6.16
2025-01-08 15:28:04,475 - INFO - Updated data inside the DB for boldgrid-easy-seo 1.6.16
2025-01-08 15:28:04,475 - WARNING - Plugin folder already exists, skipping folder creation: ./plugins/easy-maps-block/1.0.1
2025-01-08 15:28:04,482 - INFO - Updated data inside the DB for easy-maps-block 1.0.1
2025-01-08 15:28:04,483 - WARNING - Plugin folder already exists, skipping folder creation: ./plugins/post-and-page-builder/1.27.4
2025-01-08 15:28:04,491 - INFO - Updated data inside the DB for post-and-page-builder 1.27.4
2025-01-08 15:28:05,425 - INFO - Downloaded and extracted plugin: theme-grep-by-boldgrid 1.0.0
2025-01-08 15:28:05,438 - INFO - Updated data inside the DB for theme-grep-by-boldgrid 1.0.0
2025-01-08 15:28:05,439 - WARNING - Plugin folder already exists, skipping folder creation: ./plugins/boldgrid-backup/1.16.7
2025-01-08 15:28:05,445 - INFO - Updated data inside the DB for boldgrid-backup 1.16.7
2025-01-08 15:28:05,445 - WARNING - Plugin folder already exists, skipping folder creation: ./plugins/w3-total-cache/2.8.2
2025-01-08 15:28:05,451 - INFO - Updated data inside the DB for w3-total-cache 2.8.2
2025-01-08 15:28:05,452 - WARNING - Plugin folder already exists, skipping folder creation: ./plugins/weforms/1.6.25
2025-01-08 15:28:05,458 - INFO - Updated data inside the DB for weforms 1.6.25

# Audit the entire plugins folder and store results inside test.db
$ python3 wp-plugin-downlauditor.py -m audit --db test.db --verbose
2025-01-03 12:30:45,844 - INFO - Started auditing.
2025-01-03 12:30:45,845 - INFO - Found plugin boldgrid-easy-seo
2025-01-03 12:30:45,845 - INFO - Latest version found: 1.6.16
...
2025-01-03 12:32:12,265 - INFO - Semgrep analysis completed for translate-words 1.2.6.

# Clear old results, apply filters on existing plugins stored inside test.db, audit them, and store results inside the SQLite db
$ python3 wp-plugin-downlauditor.py -m audit --db test.db --author boldgrid --clear-results --verbose
2025-01-08 15:34:15,414 - INFO - Started auditing.
2025-01-08 15:34:15,415 - INFO - Found plugin easy-maps-block
2025-01-08 15:34:15,415 - INFO - Latest version found: 1.0.1
┌──── ○○○ ────┐
│ Semgrep CLI │
└─────────────┘     
2025-01-08 15:34:19,233 - INFO - Semgrep analysis completed for easy-maps-block 1.0.1.       
2025-01-08 15:34:19,234 - INFO - Querying https://api.wordpress.org/plugins/info/1.2/?action=plugin_information&request[slug]=easy-maps-block&request[fields][downloaded]=1                                        
2025-01-08 15:34:19,779 - INFO - Updated data inside the DB for easy-maps-block 1.0.1
...
2025-01-08 15:37:02,796 - INFO - Found plugin tada
2025-01-08 15:37:02,796 - INFO - Latest version found: 1.1                                     
┌──── ○○○ ────┐
│ Semgrep CLI │
└─────────────┘     
2025-01-08 15:37:06,784 - INFO - Semgrep analysis completed for tada 1.1.               
2025-01-08 15:37:06,784 - INFO - Querying https://api.wordpress.org/plugins/info/1.2/?action=plugin_information&request[slug]=tada&request[fields][downloaded]=1
2025-01-08 15:37:07,384 - WARNING - Scanned tada version 1.1 but new version 1.2 found on WP
2025-01-08 15:37:07,390 - INFO - Updated data inside the DB for tada 1.2
2025-01-08 15:37:07,396 - INFO - Updated data inside the DB for tada 1.1
```

