import requests
import argparse
import logging
import os
import subprocess
import zipfile
import json
import urllib.parse
import sqlite3
import time
from io import BytesIO
from datetime import datetime
from dateutil.relativedelta import relativedelta

'''
TODO:
    - Investigate why after page 999 records start to duplicates
    - Implement in the audit mode the possibility to audit only plugins from filters (using the Plugin table as a starting point)
    - Implement the creation of the Plugin table when auditing plugins that do not have a Plugin record (pull data from WP API)
    - Implement a recovery mechanism 
'''

logger = logging.getLogger(__name__)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

timeout = 10
#output_db = "wp-plugin-audit.db"
db_plugin_table = "Plugins"
db_result_table = "Audit"

def parse_arguments():
    parser = argparse.ArgumentParser(description="Wordpress Plugin Downloader and Auditor")
    parser.add_argument(
        "-m",
        "--mode",
        default="download",
        choices=("download","audit","both"),
        help="""Select the operative mode: 
        download = Download every available wordpress plugin using the official WP APIs.
        audit = Audit the plugins folder using semgrep and specific rules.
        both = run the script in download mode and then in audit mode."""
    )
    parser.add_argument(
        "-d",
        "--download-dir",
        type=str,
        default=".",
        help="Directory containing the plugins folder (default: current directory)",
    )
    parser.add_argument(
        "-o",
        "--output-db",
        default=False,
        help="Store plugins and audits data inside the specified SQLite database"
    )
    parser.add_argument(
        "--clear-results",
        action="store_true", 
        default=False,
        help="Clear the audit database before running"
    )   
    parser.add_argument(
        "--last-updated",
        type=int,
        default=24,
        help="Max number of months passed from the last_update (default: 24 months)",
    )
    parser.add_argument(
        "--active-installs",
        type=int,
        default=50,
        help="Min number of active_installs (default: 50)",
    )
    parser.add_argument(
        "--author",
        type=str,
        default="",
        help="Author's username to filter plugins",
    )
    parser.add_argument(
        "--tag",
        type=str,
        default="",
        help="Tag to filter plugins",
    )
    parser.add_argument(
        "--search",
        type=str,
        default="",
        help="Search term to filter plugins",
    )
    parser.add_argument(
        "--config",
        type=str,
        default="p/php",
        help="Semgrep config/rules to run (default: p/php) [audit mode only]",
    )
    
    parser.add_argument(
        "--verbose",
        action="store_true", 
        default=False,
        help="Print detailed messages"
    )

    
    return parser.parse_args()

def download_plugins(search="", author="", tag="", download_dir=".", last_updated=24, active_installs=5000, output_db=False, verbose=False):

    # Get the first page to find out the total number of pages
    data = query_wp_api(page=1, search=search, author=author, tag=tag)

    if not data or "info" not in data:
        logger.error("Failed to retrieve plugins information.")
        return

    total_pages = data["info"]["pages"]
    total_plugins = data["info"]["results"]

    if total_plugins == 0:
        logger.info("No plugins found.")
        return
    
    logger.info("Total plugins: "+str(total_plugins))

    # Create the plugins directory
    os.makedirs(os.path.join(download_dir, "plugins"), exist_ok=True)

    # If DB write is requested, connect to the DB and create the table
    if output_db:
        con = sqlite3.connect(f"{output_db}")
        cur = con.cursor()
        try:
            cur.execute(f"""
            CREATE TABLE IF NOT EXISTS {db_plugin_table} (
                slug VARCHAR(255),
                version VARCHAR(255),
                author VARCHAR(255),
                active_installs INT,
                downloaded INT,
                last_updated DATETIME,
                added_date DATE,
                download_link TEXT,
                PRIMARY KEY(slug, version)
            )
            """
            )
        except Exception as e:
            logger.error(f"Can't create the table. {e}")

    # Iterate through the pages
    for page in range(1, total_pages + 1):
        if verbose:
            logger.info(f"Page {page}/{total_pages}.")

        data = query_wp_api(page=page, search=search, author=author, tag=tag)

        if not data or "plugins" not in data:
            break
        
        for plugin in data["plugins"]:
            # Check if the plugin was last updated in the last_update range
            try:
                # Parse the date format 'YYYY-MM-DD HH:MMpm GMT'
                last_updated_datetime = datetime.strptime(plugin["last_updated"], "%Y-%m-%d %I:%M%p %Z")
                today = datetime.now()

                delta = today - last_updated_datetime

                if delta.days > (last_updated*30):
                    if verbose==True:
                        logger.info(f"Skipping {plugin["slug"]}: updated last time on {plugin["last_updated"]}, delta from now is {int(delta.days/30)}")
                    continue
            except ValueError:
                logger.error(f"Invalid date format for plugin {plugin["slug"]}: {plugin["last_updated"]}")
                continue
            
            # Check if the plugin has the minimum number of active installions
            try:
                if int(plugin['active_installs']) < active_installs:
                    # Plugins from WP API are sorted by active_installs. I can exit the loop after finding the first plugin without enaught active installs. 
                    if verbose==True:
                            logger.info(f"Skipping {plugin["slug"]}: not enaught active installs: {plugin["active_installs"]}/{active_installs}")
                    break
                    #continue
            except:
                logger.error(f"Invalid active installs format for plugin {plugin["slug"]}: {plugin["active_installs"]}")
                continue
            
            # Download and extract the plugin
            error_saving = save_plugin(plugin, download_dir, verbose)
            if error_saving:
                continue

            if output_db:
                sql = f"""
                        INSERT OR REPLACE INTO {db_plugin_table} (slug, version, author, active_installs, downloaded, last_updated, added_date, download_link)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?);
                        """

                # Prepare data for database insertion
                plug_last_updated = plugin.get("last_updated", None)
                plug_added_date = plugin.get("added", None)

                if plug_last_updated:
                    plug_last_updated = datetime.strptime(plug_last_updated, "%Y-%m-%d %I:%M%p %Z").strftime(
                        "%Y-%m-%d %H:%M:%S"
                    )
                if plug_added_date:
                    plug_added_date = datetime.strptime(plug_added_date, "%Y-%m-%d").strftime("%Y-%m-%d")

                data = (
                    plugin['slug'],
                    plugin.get("version", "NA"),
                    plugin['author'],
                    int(plugin.get("active_installs", 0)),
                    int(plugin.get("downloaded", 0)),
                    plug_last_updated,
                    plug_added_date,
                    plugin['download_link']
                )

                try:
                    cur.execute(sql, data)
                    con.commit()
                    logger.info(f"Updated data inside the DB for {plugin['slug']} {plugin['version']}")
                except Exception as e:
                    logger.error(f"Can't write the record. {e}")

    if output_db:
        con.close()    

def save_plugin(plugin, download_dir, verbose=False):
    slug = plugin['slug']
    version = plugin['version']
    download_link = plugin['download_link']

    # Download and extract the plugin in versions folders
    plugin_path = os.path.join(download_dir, "plugins", slug)
    version_path = os.path.join(download_dir, "plugins", slug, version)

    # Skip the version if the directory exists
    if os.path.exists(version_path):
        if verbose:
            logger.warning(f"Plugin folder already exists, skipping folder creation: {version_path}")
        return 0

    try:
        response = requests.get(download_link, timeout=timeout)
        response.raise_for_status()  # Raises an HTTPError for bad responses

        with zipfile.ZipFile(BytesIO(response.content)) as zip:
            zip.extractall(os.path.join(plugin_path))
        # Rename the folder from plugin name to version
        os.rename(os.path.join(plugin_path,slug), version_path)
        if verbose:
            logger.info(f"Downloaded and extracted plugin: {slug} {version}")
        return 0
    
    except requests.RequestException as e:
        logger.error(f"Failed to download {slug}: {e}")
        return 1
    except zipfile.BadZipFile:
        logger.error(f"Failed to unzip {slug}: Not a zip file or corrupt zip file")
        return 1

def query_wp_api(page=1, per_page=25, search="", author="", tag=""):
    '''
    API documentation: https://developer.wordpress.org/reference/functions/plugins_api/
    Note: Plugins are ordered by install DESC
    '''
    url = f"https://api.wordpress.org/plugins/info/1.2/?action=query_plugins&request[page]={page}&request[per_page]={per_page}&request[search]={urllib.parse.quote_plus(search)}&request[author]={urllib.parse.quote_plus(author)}&request[tag]={urllib.parse.quote_plus(tag)}"
    logger.info(f"Querying {url}")

    exception_occured = True

    while exception_occured:
        try:
            if exception_occured == True:
                exception_occured == False

            response = requests.get(url, timeout=timeout)

            if response.status_code == 200:
                return response.json()
            else:
                logger.error(f"Failed to retrieve page {page}: {response.status_code}")
                return None
        except requests.RequestException as e:
            logger.error(f"Failed to send request: {e}. Retrying...")
            exception_occured = True
            time.sleep(3)


def audit_plugins(download_dir, config, output_db=False, verbose=False):
    
    plugins = os.scandir(os.path.join(download_dir, "plugins"))

    # If DB update is requested, connect to the DB and create the table if it is missing
    if output_db:
        con = sqlite3.connect(f"{output_db}")
        cur = con.cursor()
        try:
            cur.execute(f"""
            CREATE TABLE IF NOT EXISTS {db_result_table} (
                slug VARCHAR(255),
                version VARCHAR(255),
                file_path VARCHAR(255),
                check_id VARCHAR(255),
                start_line INT,
                end_line INT,
                vuln_lines TEXT,
                message TEXT,
                triaged BOOLEAN,
                PRIMARY KEY(slug, version, file_path, check_id, start_line, end_line)
                FOREIGN KEY (slug,version) REFERENCES {db_plugin_table}(slug,version)
            )
            """
            )
        except Exception as e:
            logger.error(f"Can't create the table. {e}")

    for plugin in plugins:
        versions = []

        # skip files
        if plugin.is_file():
            continue

        if verbose==True:
            logger.info(f"Found plugin {plugin.name}")
        contents = os.scandir(plugin.path)
        for content in contents:
            # Skip files
            if content.is_file():
                continue
            versions.append(content.name)
        
        versions.sort(reverse=True)
        last_version = versions[0]
        if verbose==True:
            logger.info(f"Latest version found: {last_version}")
        
        scan_path = os.path.join(plugin.path, last_version)
        scan_result_folder = os.path.join(plugin.path, last_version, "semgrep-scan")
        scan_result_file = os.path.join(plugin.path, last_version, "semgrep-scan", plugin.name+"."+last_version)

        # Make sure semgrep-scan folder exists
        os.makedirs(scan_result_folder, exist_ok=True)

        command = [
            "semgrep",
            "scan",
            "--config",
            "{}".format(config),
            "--json-output",
            "{}".format(scan_result_file+".json"),
            "--text-output",
            "{}".format(scan_result_file+".txt"),
            "--sarif-output",
            "{}".format(scan_result_file+".sarif"),
            "--no-git-ignore",
            "--quiet",  # Suppress non-essential output
            scan_path
        ]
        
        # Execute semgrep
        try:
            subprocess.run(command, check=True)
            if verbose==True:
                logger.info(f"Semgrep analysis completed for {plugin.name} {last_version}.")

            # Read the output file and update the auditor DB
            if output_db:
                with open(scan_result_file+".json", "r") as file:
                    json_content = json.load(file)
                    for item in json_content["results"]:
                        sql = f"""
                        INSERT OR IGNORE INTO {db_result_table} (slug, version, file_path, check_id, start_line, end_line, vuln_lines, message, triaged)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);
                        """

                        data = (
                            plugin.name,
                            last_version,
                            item['path'],
                            item['check_id'],
                            item['start']['line'],
                            item['end']['line'],
                            item['extra']['lines'],
                            item['extra']['message'],
                            False
                        )

                        try:
                            cur.execute(sql, data)
                            con.commit()
                            if verbose==True:
                                logger.info(f"Updated data inside the DB for {plugin.name} {last_version}.")
                        except Exception as e:
                            logger.error(f"Can't write the record. {e}")

        except subprocess.CalledProcessError as e:
            logger.error(f"Semgrep failed for {plugin.name} {last_version}: {e}")
        except json.JSONDecodeError as e:
            logger.error(f"Failed to decode JSON for {plugin.name} {last_version}: {e}")
        except Exception as e:
            logger.error(f"Unexpected error for {plugin.name} {last_version}: {e}")
    if output_db:
        con.close()    

def main():
    args = parse_arguments()
    
    if args.clear_results:
        con = sqlite3.connect(f"{args.output_db}")
        try:
            #con.execute(f"DELETE FROM {db_plugin_table}")
            con.execute(f"DELETE FROM {db_result_table}")
        except Exception as e:
            logger.error(f"Can't delete the table. {e}")
        con.close()

    if args.mode=="download" or args.mode=="both":
        logger.info("Started downloading.")
        download_plugins(args.search, args.author, args.tag, args.download_dir, args.last_updated, args.active_installs, args.output_db, args.verbose)

    if args.mode=="audit" or args.mode=="both":
        logger.info("Started auditing.")
        audit_plugins(args.download_dir, args.config, args.output_db, args.verbose)   

if __name__ == "__main__":
    main()