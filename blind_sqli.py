import argparse
import requests
import time
import concurrent.futures
import os
import sys
import signal
from prompt_toolkit.completion import PathCompleter
from prompt_toolkit import prompt
from colorama import Fore, Style, init
import logging
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from urllib.parse import urlparse
import random
from rich.panel import Panel
from rich.align import Align
from rich import print as rich_print


WAF_SIGNATURES = {
    'Cloudflare': ['cf-ray', 'cloudflare', 'cf-request-id', 'cf-cache-status'],
    'Akamai': ['akamai', 'akamai-ghost', 'akamai-x-cache', 'x-akamai-request-id'],
    'Sucuri': ['x-sucuri-id', 'sucuri', 'x-sucuri-cache'],
    'ModSecurity': ['mod_security', 'modsecurity', 'x-modsecurity-id', 'x-mod-sec-rule'],
    'Barracuda': ['barra', 'x-barracuda', 'bnmsg'],
    'Imperva': ['x-cdn', 'imperva', 'incapsula', 'x-iinfo', 'x-cdn-forward'],
    'F5 Big-IP ASM': ['x-waf-status', 'f5', 'x-waf-mode', 'x-asm-ver'],
    'DenyAll': ['denyall', 'sessioncookie'],
    'FortiWeb': ['fortiwafsid', 'x-fw-debug'],
    'Jiasule': ['jsluid', 'jiasule'],
    'AWS WAF': ['awswaf', 'x-amzn-requestid', 'x-amzn-trace-id'],
    'StackPath': ['stackpath', 'x-sp-url', 'x-sp-waf'],
    'BlazingFast': ['blazingfast', 'x-bf-cache-status', 'bf'],
    'NSFocus': ['nsfocus', 'nswaf', 'nsfocuswaf'],
    'Edgecast': ['ecdf', 'x-ec-custom-error'],
    'Alibaba Cloud WAF': ['ali-cdn', 'alibaba'],
    'AppTrana': ['apptrana', 'x-wf-sid'],
    'Radware': ['x-rdwr', 'rdwr'],
    'SafeDog': ['safedog', 'x-sd-id'],
    'Comodo WAF': ['x-cwaf', 'comodo'],
    'Yundun': ['yundun', 'yunsuo'],
    'Qiniu': ['qiniu', 'x-qiniu'],
    'NetScaler': ['netscaler', 'x-nsprotect'],
    'Securi': ['x-sucuri-id', 'sucuri', 'x-sucuri-cache'],
    'Reblaze': ['x-reblaze-protection', 'reblaze'],
    'Microsoft Azure WAF': ['azure', 'x-mswaf', 'x-azure-ref'],
    'NAXSI': ['x-naxsi-sig'],
    'Wallarm': ['x-wallarm-waf-check', 'wallarm'],
}

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Version/14.1.2 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/91.0.864.70",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Firefox/89.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:91.0) Gecko/20100101 Firefox/91.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:91.0) Gecko/20100101 Firefox/91.0",
    "Mozilla/5.0 (Linux; Android 10; SM-G973F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.120 Mobile Safari/537.36",
    "Mozilla/5.0 (Linux; Android 11; Pixel 5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.77 Mobile Safari/537.36",
]


stop_execution = False


def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

 
def get_file_path(prompt_text):
    completer = PathCompleter()
    return prompt(prompt_text, completer=completer).strip()

def get_retry_session(retries=3, backoff_factor=0.3, status_forcelist=(500, 502, 504)): 
    session = requests.Session()
    retry = Retry(
        total=retries, 
        read=retries,
        connect=retries,
        backoff_factor=backoff_factor,
        status_forcelist=status_forcelist,
    )
    adapter = HTTPAdapter(max_retries=retry)
    session.mount('http://', adapter)
    session.mount('https://', adapter)
    return session

def extract_domain(url): 
    parsed_url = urlparse(url)
    return parsed_url.netloc ## this returns the domain..

def detect_waf(url, headers, cookies=None): 
    session = get_retry_session()
    waf_detected = None

    try: 
        response = session.get(url, headers=headers, cookies=cookies, verify=True)
        for waf_name, waf_identifiers in WAF_SIGNATURES.items():
            if any(identifier in response.headers.get('server', '').lower() for identifier in waf_identifiers): 
                # print(f"{Fore.GREEN}[+] WAF Detected: {waf_name}{Fore.RESET}")
                waf_detected = waf_name
                break 
    
    except requests.exceptions.RequestException as e: 
        logging.error(f"Error detecting WAF: ({e})")

    # if not waf_detected: 
        # print(f"{Fore.GREEN}[+] No WAF Detected.{Fore.RESET}")
    
    return waf_detected

def detect_waf_for_urls(urls): 
    checked_domains = set() ## store already check domains 

    print("\n[!] Detecting WAF on websites...\n")
    for url in urls : 
        domain = extract_domain(url)

        if domain in checked_domains : 
            # print(f"{Fore.CYAN}[i] WAF already check for domain : {domain}. skipping WAF check. {Fore.RESET}")
            continue

        headers = {'User-Agent' : get_random_user_agent()}
        waf_detected = detect_waf(url, headers)

        if waf_detected : 
            print(f"{Fore.GREEN}[+] WAF Detected for domain {domain}: {waf_detected}")
        else : 
            print(f"{Fore.GREEN}[+] No WAF Detected for domain {domain}.")
        checked_domains.add(domain)

 
def prompt_for_urls():
    while True:
        try:
            url_input = get_file_path("[?] Enter the path to the input file containing the URLs (or press Enter to input a single URL): ")
            if url_input:
                if not os.path.isfile(url_input):
                    raise FileNotFoundError(f"File not found: {url_input}")

                with open(url_input) as file:
                    urls = [line.strip() for line in file if line.strip()]

                return urls

            else:
                single_url = input(f"{Fore.CYAN}[?] Enter a single URL to scan: ").strip()
                if single_url:
                    return [single_url]

                else:
                    print(f"{Fore.RED}[!] You must provide either a file with URLs or a single URL.")
                    input(f"{Fore.CYAN}\n[i] Press Enter to try again...")

                    clear_screen()
                    print(f"{Fore.GREEN} Welcome to the SQL-Injector!\n")

        except Exception as e:
            print(f"{Fore.RED}[!] Error reading input file: {str(e)}")
            input(f"{Fore.YELLOW}[i] Press Enter to try again.")
            clear_screen()


def prompt_for_payload():
    while True:
        try:
            payload_input = get_file_path("[?] Enter the path to the input file containing payloads: ")
            if payload_input:
                if not os.path.isfile(payload_input):
                    raise FileNotFoundError(f"File not found: {payload_input}")

                with open(payload_input) as file:
                    payloads = [line.strip() for line in file if line.strip()]

                return payloads

        except Exception as e:
            print(f"{Fore.RED}[!] Error reading payload file: {str(e)}")
            input(f"{Fore.YELLOW}[i] Press Enter to try again.")
            clear_screen()


def prompt_for_cookie():
    cookie = input(f"{Fore.CYAN}[?] Enter a cookie (or press Enter to skip): ").strip()
    return cookie if cookie else None

def save_results(vulnerable_urls):
    save_prompt(vulnerable_urls)

def save_prompt(vulnerable_urls=[]):
    save_choice = input(f"{Fore.CYAN}Do you want to save vulnerable urls to a file (y/n, press Enter for no) : ").strip().lower()
    if save_choice == 'y': 
        output_file = input(f"{Fore.CYAN}[?]Enter the name of output file (press Enter for vulnerable_urls.txt) : ").strip() or 'vulnerable_urls.txt'

        with open (output_file, 'w') as file : 
            for url in vulnerable_urls : 
                file.write(url + '\n')
        print(f"{Fore.YELLOW}Vulnerable urls have been saved to {output_file}")
    else : 
        print(f"{Fore.YELLOW}Vulnerable urls are not saved.")

def perform_request(url, payload, cookie):
    if stop_execution:
        return False, None, None, "Stopped by user"
    
    if '?' in url : 
        url_with_payload = f"{url}{payload}"
    else : 
        url_with_payload = f"{url}?{payload}"

    # url_with_payload = f"{url}{payload}"
    start_time = time.time()

    try:
        response = requests.get(url_with_payload, cookies={'cookie': cookie} if cookie else None)
        response.raise_for_status()
        success = True
        error_message = None
    except requests.exceptions.RequestException as e:
        success = False
        error_message = str(e)

    response_time = time.time() - start_time
    return success, url_with_payload, response_time, error_message


def signal_handler(sig, frame):
    global stop_execution, vulnerable_urls
    stop_execution = True
    print(f"\n{Fore.RED}✗ Stopping execution... Please wait! {Style.RESET_ALL}")

    if vulnerable_urls : 
        save_results(vulnerable_urls)
    else : 
        print(f"{Fore.CYAN}No vulnerable URLs found.")
    # os._exit(1)


def get_random_user_agent(): 
    return random.choice(USER_AGENTS)


def main():
    global stop_execution, vulnerable_urls
    clear_screen()

    signal.signal(signal.SIGINT, signal_handler)

    panel = Panel(
        r"""
 ____     _____   ___    .    
 /   \   (      .'   `.  /    
 |,_-<    `--.  |     |  |    
 |    `      |  |  ,_ |  |    
 `----' \___.'   `._.`-. /---/
    (made by :  whitecap)   
    """,
    style="bold green",
    border_style="blue",
    expand=False
    )
    rich_print(panel, "\n")

    print(f"{Fore.GREEN} Welcome to the BLIND SQLi Testing Tool!\n")

    urls = prompt_for_urls()
    payloads = prompt_for_payload()
    cookie = prompt_for_cookie()

    threads = input(f"{Fore.CYAN}[?] Enter the number of threads (5 default): ").strip()
    threads = int(threads) if threads.isdigit() else 5

    # print(f"{Fore.YELLOW}\n[!] Detecting WAF on websites ...\n")
    # for url in urls : 
    #     # print(f"{Fore.GREEN}[i] Detecting WAF for URL : {url}")
    #     headers = {'User-Agent' : get_random_user_agent()}
    #     detect_waf(url, headers)
    
    detect_waf_for_urls(urls)

    total_scanned = 0
    vulnerabilities_found = 0
    start_time = time.time()
    vulnerable_urls = []

    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
            futures = []
            for url in urls:
                for payload in payloads:
                    if stop_execution: 
                        break
                    futures.append(executor.submit(perform_request, url, payload, cookie))

            for future in concurrent.futures.as_completed(futures):
                if stop_execution:
                    print(f"\n{Fore.RED}✗ Stopping threads... Wait.{Style.RESET_ALL}")
                    break

                success, url_with_payload, response_time, error_message = future.result()
                total_scanned += 1

                print(f"{Fore.YELLOW}\n[i] Scanning with payload: {payload}")
                if success and response_time and response_time >= 10:
                    print(f"{Fore.GREEN}✓ SQLi Found! URL: {Fore.WHITE}{url_with_payload} {Fore.CYAN}- Response Time: {response_time:.2f} seconds{Style.RESET_ALL}")
                    vulnerabilities_found += 1
                    vulnerable_urls.append(url_with_payload)
                else:
                    print(f"{Fore.RED}✗ Not Vulnerable. URL: {Fore.WHITE}{url_with_payload} {Fore.CYAN}- Response Time: {response_time:.2f} seconds{Style.RESET_ALL}")

    except KeyboardInterrupt:
        print(f"\n{Fore.RED}✗ Stopped by user.{Style.RESET_ALL}")

    finally:
        total_time = time.time() - start_time
        print(f"\n{Fore.GREEN}Summary:")
        print(f"{Fore.CYAN}Total URLs/Payloads scanned: {total_scanned}")
        print(f"{Fore.CYAN}Total vulnerabilities found: {vulnerabilities_found}")
        print(f"{Fore.CYAN}Total time taken: {total_time:.2f} seconds{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}[!] Shutting down gracefully.{Style.RESET_ALL}")


if __name__ == '__main__': 
    try : 
        init(autoreset=True)
        main()
    except KeyboardInterrupt: 
        print(f"{Fore.RED}\n[!] Stopped by User!! Exiting gracefully....")
        sys.exit(1)
