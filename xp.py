import signal
import sys
import platform
import subprocess
import threading
from colorama import Fore, init
import time
import os
import re
import ipaddress
import requests
import sys
import shutil
# Initialize colorama
init(autoreset=True)


# Register the signal handler

# Function to clear the screen (teleportation effect)
def clear_screen():
   if platform.system() == "Windows":
      os.system("cls")
   else:
      os.system("clear")

# Function to show the main menu logo with blue and white mix
def show_main_menu_logo():
   logo_text = r'''
                _________             .__  __   
___  _________ /   _____/_____   ____ |__|/  |_ 
\  \/  /\____ \\_____  \\____ \ /  _ \|  \   __\
 >    < |  |_> >        \  |_> >  <_> )  ||  |  
/__/\_ \|   __/_______  /   __/ \____/|__||__|  
      \/|__|          \/|__|                    
                                
                                   
   '''
   clear_screen()
   for i, line in enumerate(logo_text.splitlines()):
      if i % 2 == 0:
        print(Fore.LIGHTWHITE_EX+ line)  # Blue for even lines
      else:
        print(Fore.LIGHTBLACK_EX + line)  # White for odd lines
      time.sleep(0.1)  # Medium delay (0.3 seconds per line)

# Function to run a scan with a given command

import subprocess
import shutil
import os
from colorama import Fore

def run_nmap():
    """Function to launch Nmap with a custom command."""
    try:
        print(Fore.LIGHTWHITE_EX + "\nChoose an Nmap option:")
        print("1. Run Nmap")
        print("99. Return to Main Menu")  # Option to return to the main menu
        choice = input(Fore.LIGHTCYAN_EX + "\nEnter your choice: ").strip()

        # Return to the main menu if the user selects option 99
        if choice == '99':
            print(Fore.LIGHTCYAN_EX + "Returning to the main menu...")
            return  # Exits the function and goes back to the main menu

        # Run Nmap with custom command if selected
        if choice == '1':
            print(Fore.LIGHTRED_EX + "\nEnter Command (Example: nmap 192.168.1.1 -vv -n):")
            command = input(Fore.LIGHTMAGENTA_EX + "Enter command: ").strip()

            if command:
                print(Fore.GREEN + f"Running command: {command}")
                try:
                    # Ensure nmap is in the system path
                    if not shutil.which("nmap"):
                        print(Fore.RED + "Nmap is not installed or not found in the system path.")
                        return
                    
                    # Launch Nmap with the manually entered command
                    result = subprocess.run(command, shell=True, capture_output=True, text=True)

                    # Check if Nmap executed successfully
                    if result.returncode == 0:
                        print(Fore.GREEN + "\nNmap scan completed successfully.")
                        output = result.stdout

                        # Show the results from Nmap
                        print(Fore.LIGHTCYAN_EX + "\nNmap Results:")
                        print(output)

                        # Ask if the user wants to save the results
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
        clear_screen()  # Clear the screen before showing the menu
        print(Fore.WHITE + "\nNmap:")
        print(Fore.GREEN + "1. Run Nmap")
        print(Fore.RED + "99. Return to main menu")

        option = input(Fore.CYAN + "\nEnter an option: ").strip()

        if option == "1":
            run_nmap()  # Launch Nmap directly when option 1 is selected
        elif option == "99":
            print(Fore.GREEN + "Exiting program...")
            break
        else:
            print(Fore.RED + "Invalid option. Please try again.")

# DO NOT call main_menu() automatically at the start of the script










init(autoreset=True)

def run_subfinder():
    """Function to open Subfinder interactively."""
    try:
        print(Fore.GREEN + "Launching Subfinder...")

        # Launch Subfinder interactively
        subprocess.run("subfinder", shell=True)

        print(Fore.GREEN + "\nSubfinder exited. Returning to the main menu.")

    except Exception as e:
        print(Fore.RED + f"Error launching Subfinder: {e}")

def save_results_to_file(file_name, content):
    """Save results to a file in a user-writable directory."""
    try:
        # Get the user's home directory
        home_dir = os.path.expanduser("~")
        save_path = os.path.join(home_dir, file_name)

        # Write content to the file
        with open(save_path, "w") as file:
            file.write(content)

        print(Fore.GREEN + f"Results saved to '{save_path}'.")
    except Exception as e:
        print(Fore.RED + f"Error saving results: {e}")

# Example usage
if __name__ == "__main__":
    # Example: Save a test result to a file
    test_content = "Example Subfinder results..."
    save_results_to_file("subfinder_results.txt", test_content)










# Function to show all Nmap commands
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
    
    # Printing the commands for the user
    for command in commands:
        print(command)
    
    print(Fore.LIGHTCYAN_EX + "\nPress any key to return to the menu...")
    input()  # Wait for the user to press a key to return to the menu
    return  # Return to the main menu


# Function to show NSE script commands
def show_nse_script_commands():
   clear_screen()
   commands = [
      "NSE Script Commands:",
      "nmap --script=vuln 192.168.1.1 Run vulnerability scripts",
      "nmap --script=http-enum 192.168.1.1 Enumerate web services",
      "nmap --script=default 192.168.1.1 Run default scripts"
   ]
   show_submenu(commands)

# Function to show firewall scan commands
def show_firewall_scan_commands():
   clear_screen()
   commands = [
      "Firewall Scan Commands:",
      "nmap -Pn 192.168.1.1 Scan without ping",
      "nmap -f 192.168.1.1 Fragment packets",
      "nmap --mtu 24 192.168.1.1 Specify custom MTU"
   ]
   show_submenu(commands)

# Function to show the submenu with command options
def show_submenu(commands):
   print("\n".join(commands))
   input(Fore.WHITE + "\nPress Enter to return to the main menu...")



# Exiting loading screen with blue and white color scheme
def exiting_loading_screen():
   clear_screen()
   loading_text = '''

  _             _             
 | |__ _  _ ___| |__ _  _ ___ 
 | '_ \ || / -_) '_ \ || / -_)
 |_.__/\_, \___|_.__/\_, \___|
       |__/          |__/     

   '''
   for i, line in enumerate(loading_text.splitlines()):
      if i % 4 == 0:
        print(Fore.LIGHTWHITE_EX + line)  # Blue for even lines
      else:
        print(Fore.LIGHTBLACK_EX + line)  # White for odd lines
      time.sleep(0.1)  # Short delay (0.1 seconds per line)
   # Display a final "Exiting..." message with a blue background and white text
   print(Fore.BLUE + Fore.WHITE + "\n")
   time.sleep(1)  # Wait for a second before program exit
   print(Fore.YELLOW + "Credits! biskit")
   # Final message
   sys.exit()  # Exit the program

# Function to run SSLScan on a given IP with command selection


def sslscan_scan():
    global scanning_in_progress
    try:
        print(Fore.BLUE + "\nChoose an SSLScan command:")
        
        print("4. Manual SSLScan")
        print("6. Show SSLScan Command List")  # Option to show the SSLScan command list
        print("99. Return to Main Menu")  # Option to return to the main menu
        choice = input(Fore.BLUE + "\nEnter your choice: ").strip()

        # Return to the main menu if the user selects option 99
        if choice == '99':
            print(Fore.LIGHTCYAN_EX + "Returning to the main menu...")
            return  # Exits the function and goes back to the main menu

        # Show SSLScan command list if selected
        if choice == '6':
            show_sslscan_commands()
            return

        ip = ""  # Default to empty, we'll ask for IP only when necessary

        # Only prompt for IP if needed (1, 2, 3, 5)
        if choice in ['1', '2', '3', '5']:  # Basic, Full, Cert, and Vuln scans
            ip = get_ip_address()  # Assuming this is your method to get the IP address
            if not ip:
                print(Fore.RED + "No IP address provided. Exiting SSLScan.")
                return

        # Define the SSLScan command based on the user's choice
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
                return  # Exit if no command is entered
            print(Fore.GREEN + f"Running custom SSLScan command: {command}")  # Debug print
        elif choice == '':
            command = f""  # New command for Vuln Scan
        else:
            print(Fore.RED + "Invalid choice. Exiting SSLScan.")
            return

        # Debugging: print the command before execution
        print(Fore.YELLOW + f"Debug: Command to run: {command}")

        # Run the selected SSLScan command quickly by using Popen directly
        process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = process.communicate()

        # Check if there's an error
        if stderr:
            print(Fore.RED + "Error during SSLScan:", stderr.decode())
        else:
            output = stdout.decode()
            if output:  # If there's output, print it
                print(Fore.BLUE + "SSLScan Completed Successfully.")
                print(output)
            else:
                print(Fore.RED + "No output received from SSLScan.")

            # Prompt if the user wants to save the results
            save_choice = input(Fore.YELLOW + "\nWould you like to save the results? (yes/no): ").strip().lower()
            if save_choice == 'yes':
                file_name = input(Fore.LIGHTWHITE_EX + "Enter file name (without extension): ").strip() + ".txt"
                if file_name:  # Ensure a valid file name is provided
                    with open(file_name, "a") as file:
                        file.write(f"IP: {ip}\n{output}\n\n")
                    print(Fore.BLUE + f"Results saved to '{file_name}'.")
                else:
                    print(Fore.RED + "Invalid file name. Results not saved.")
            elif save_choice == 'no':
                print(Fore.GREEN + "Returning to the main menu...")
            else:
                print(Fore.RED + "Invalid choice. Returning to the main menu.")
                return  # Go back to the main menu

    except Exception as e:
        print(Fore.RED + f"Error running SSLScan: {e}")
    finally:
        scanning_in_progress = False
        clear_screen()  # Assuming clear_screen() is defined elsewhere


def get_ip_address():
    # Function to get the IP address (you can replace this with your own method)
    ip = input(Fore.BLUE + "Enter the IP address to scan: ").strip()
    return ip


def clear_screen():
    # This is just an example. Adjust according to your environment.
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
    input()  # Wait for the user to press a key to return to the menu
    return  # Return to the main menu




def update_script():
   try:
      print("Updated Restart Script")
      url = "https://raw.githubusercontent.com/biskit069/xp/refs/heads/main/xp.py"
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


import subprocess
import os
import shutil
from colorama import Fore

def run_routersploit():
    """Function to run RouterSploit with sudo automatically and display host info."""
    try:
        # Get the hostname using 'whoami' on Linux
        hostname = subprocess.check_output("whoami", shell=True).decode().strip()

        # Automatically get the path to the routersploit directory
        path = shutil.which("rsf.py")
        if not path:
            print(Fore.RED + "RouterSploit is not installed or not found in the system path.")
            return

        # Change to the directory where RouterSploit is located
        os.chdir(os.path.dirname(path))

        # Run RouterSploit with sudo automatically
        print(Fore.GREEN + f"\nRunning RouterSploit as {hostname}...")
        subprocess.run(["sudo", "python3", "rsf.py"])

        print(Fore.GREEN + "RouterSploit has been stopped. Returning to the main menu...")

    except Exception as e:
        print(Fore.RED + f"Error running RouterSploit: {e}")







def metasploit_scan():
    try:
        while True:
            print(Fore.YELLOW+"99. to return to main menu")
            print("1. launch Metasploit")
            choice = input(Fore.BLUE + "\nEnter your choice: ").strip()
            
            print(Fore.YELLOW + f"launching Metasploit...: '{choice}'")

            metasploit_commands = ""
            ip = ""
            
            if choice == '':  # Scan for vulnerabilities
                ip = get_ip_address()  # Assuming get_ip_address() prompts for IP
                if not ip:
                
                    return

                metasploit_commands = f""
            elif choice == '':  # Exploit a vulnerability
                ip = get_ip_address()  # Prompt for IP address
                if not ip:
                    print(Fore.RED + "")
                    return
                metasploit_commands = input(Fore.BLUE + "")
            elif choice == '1':  # Manual Metasploit
                print(Fore.LIGHTCYAN_EX + "Launching manual Metasploit...")
                os.system("msfconsole")
                continue
            elif choice == '':  # View Network Exploits
                print(Fore.BLUE + "")

                # Full list of network exploits with payloads
                exploits = {
                    
                }

                # Display available exploits
                for key, value in exploits.items():
                    print(f"{key}: {value}")

                exploit_choice = input(Fore.BLUE + "\nEnter the number of the exploit you want to run: ").strip()

                # Debugging: Print the user's exploit choice
                print(Fore.YELLOW + f"DEBUG: Exploit choice input: '{exploit_choice}'")

                if exploit_choice in exploits:
                    ip = get_ip_address()  # Prompt for IP address
                    if not ip:
                        print(Fore.RED + "No IP address provided. Returning to the main menu...")
                        return

                    metasploit_commands = f"use {exploits[exploit_choice]} \nset RHOSTS {ip} \nrun"
                else:
                    print(Fore.RED + "Invalid exploit choice.")
                    continue
            elif choice == '99':  # Return to main menu
                print(Fore.LIGHTCYAN_EX + "Returning to the main menu...")
                break
            else:
                print(Fore.RED + "Invalid choice. Please try again.")
                continue

            # Run the command in Metasploit directly (no file writing, faster)
            if metasploit_commands:
                print(Fore.BLUE + "Launching Metasploit...")

                # Debugging: Print the full command being executed
                print(Fore.YELLOW + f"DEBUG: Full Metasploit commands:\n{metasploit_commands}")

                # Ensure correct separation of commands (with a space after 'set' commands)
                full_command = f"msfconsole -q -x \"{metasploit_commands}\""
                print(Fore.YELLOW + f"Executing: {full_command}")  # Debugging line

                # Run the command in the terminal
                result = os.system(full_command)
                
                # Debugging: Check the result of the command execution
                if result != 0:
                    print(Fore.RED + f"Error: Metasploit command failed with exit code {result}")
                break  # Exit the loop after launching Metasploit

    except Exception as e:
        print(Fore.RED + f"Error running Metasploit: {e}")












def run_subfinder():
    """Function to launch Subfinder directly with a manually entered command."""
    try:
        print(Fore.BLUE + "\nChoose a Subfinder option:")
        print("1. Run Subfinder with Custom Command")
        print("2. Show Subfinder Command List")  # Option to show Subfinder command list
        print("99. Return to Main Menu")  # Option to return to the main menu
        choice = input(Fore.BLUE + "\nEnter your choice: ").strip()

        # Return to the main menu if the user selects option 99
        if choice == '99':
            print(Fore.LIGHTCYAN_EX + "Returning to the main menu...")
            return  # Exits the function and goes back to the main menu

        # Show Subfinder command list if selected
        if choice == '2':
            show_subfinder_commands()
            return

        # Run Subfinder with custom command if selected
        if choice == '1':
            print(Fore.YELLOW + "\nEnter your custom Subfinder command (e.g., subfinder -d example.com -t 50 -timeout 3):")
            command = input(Fore.CYAN + "Enter command: ").strip()

            if command:
                print(Fore.GREEN + f"Running command: {command}")
                try:
                    # Ensure subfinder is in the system path
                    if not shutil.which("subfinder"):
                        print(Fore.RED + "Subfinder is not installed or not found in the system path.")
                        return
                    
                    # Launch Subfinder with the manually entered command
                    result = subprocess.run(command, shell=True, capture_output=True, text=True)

                    # Check if Subfinder executed successfully
                    if result.returncode == 0:
                        print(Fore.GREEN + "\nSubfinder completed successfully.")
                        output = result.stdout

                        # Show the results from Subfinder
                        print(Fore.LIGHTCYAN_EX + "\nSubfinder Results:")
                        print(output)

                        # Ask if the user wants to save the results
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
                        print(Fore.RED + "\nSubfinder did not complete successfully.")
                        print(Fore.YELLOW + f"Error: {result.stderr}")

                except Exception as e:
                    print(Fore.RED + f"Error running Subfinder: {e}")
            else:
                print(Fore.RED + "Invalid command. Please try again.")

    except Exception as e:
        print(Fore.RED + f"Error launching Subfinder: {e}")


def show_subfinder_commands():
    """Displays a list of common Subfinder commands."""
    clear_screen()
    subfinder_commands = [
        "Subfinder Command List:",
        "-d <domains>                  Domains to find subdomains for",
        "-dL <file>                    File containing list of domains for subdomain discovery",
        "-s <sources>                  Specific sources to use for discovery (e.g., crtsh, github)",
        "-recursive                    Use only sources that can handle subdomains recursively",
        "-all                          Use all sources for enumeration (slow)",
        "-es <exclude-sources>         Sources to exclude from enumeration",
        "-m <match>                    Subdomain or list of subdomains to match",
        "-f <filter>                   Subdomain or list of subdomains to filter",
        "-rl <rate-limit>              Maximum number of HTTP requests to send per second",
        "-t <concurrent>               Number of concurrent goroutines for resolving (default 10)",
        "-o <output>                   File to write output to",
        "-oJ                           Write output in JSONL format",
        "-oD <output-dir>              Directory to write output",
        "-cs                           Include all sources in the output",
        "-oI                           Include host IP in output",
        "-config <file>                Flag config file (default $HOME/.config/subfinder/config.yaml)",
        "-pc <provider-config>         Provider config file",
        "-r <resolvers>                List of resolvers to use",
        "-rL <rlist>                   File containing list of resolvers to use",
        "-nW                           Display active subdomains only",
        "-proxy <proxy>                HTTP proxy to use",
        "-ei                           Exclude IPs from the list of domains",
        "-silent                       Show only subdomains in output",
        "-version                      Show version of subfinder",
        "-v                            Show verbose output",
        "-nc                           Disable color in output",
        "-ls                           List all available sources",
        "-timeout <seconds>            Seconds to wait before timing out",
        "-max-time <minutes>           Minutes to wait for enumeration results"
    ]
    
    print(Fore.GREEN + "\nAvailable Subfinder Commands:")
    for command in subfinder_commands:
        print(Fore.YELLOW + command)
    print(Fore.LIGHTCYAN_EX + "\nPress any key to return to the menu...")
    input()  # Wait for the user to press a key to return to the menu
    return  # Return to the main menu


def clear_screen():
    """Clears the terminal screen."""
    subprocess.call('clear' if os.name == 'posix' else 'cls', shell=True)




def get_linux_username():
    """Fetch the Linux system's current username."""
    try:
        username = subprocess.check_output("whoami", shell=True).decode().strip()
        return username
    except subprocess.CalledProcessError:
        print(Fore.RED + "Error retrieving the username.")
        return None

def run_magicrecon():
    """Function to launch MagicRecon directly with predefined options or a custom command."""
    try:
        # Clear the screen when option 8 is selected
        clear_screen()

        # Fetch the Linux username
        username = get_linux_username()

        if username:
            # Automatically construct the MagicRecon path using the username
            magicrecon_path = f"/home/{username}/magicRecon/magicrecon.sh"  # Assuming MagicRecon is in the user's home directory

            if os.path.exists(magicrecon_path):
                print(Fore.GREEN + "Launching MagicRecon...")

                # Show the options for MagicRecon
                print(Fore.BLUE + "\nChoose a MagicRecon option:")
                print("1. Run MagicRecon -d example.com -a Auto Command")
                print("2. Run MagicRecon")
                print("99. Return to Main Menu")

                choice = input(Fore.CYAN + "\nEnter your choice: ").strip()

                if choice == '99':
                    print(Fore.LIGHTCYAN_EX + "Returning to the main menu...")
                    return

                if choice == '1':
                    try:
                        domain = input(Fore.CYAN + "Enter the domain for MagicRecon: ").strip()
                        command = f"bash {magicrecon_path} -d {domain} -a"
                        subprocess.Popen(command, shell=True)  # This launches MagicRecon directly without capturing output

                        # Wait for user to press Enter to go back to main menu
                        input(Fore.GREEN + "\nPress Enter to return to the main menu...")
                    except Exception as e:
                        print(Fore.RED + f"Error running MagicRecon: {e}")

                elif choice == '2':
                    try:
                        custom_command = input(Fore.CYAN + "Enter your custom MagicRecon command (without path): ").strip()
                        # Prepend the MagicRecon path to the custom command if needed
                        custom_command_with_path = f"bash {magicrecon_path} {custom_command}"
                        subprocess.Popen(custom_command_with_path, shell=True)  # Launch the custom command directly

                        # Wait for user to press Enter to go back to main menu
                        input(Fore.GREEN + "\nPress Enter to return to the main menu...")
                    except Exception as e:
                        print(Fore.RED + f"Error running custom MagicRecon command: {e}")

                else:
                    print(Fore.RED + "Invalid choice. Returning to the main menu.")
            else:
                print(Fore.RED + f"MagicRecon script not found at path: {magicrecon_path}")
        else:
            print(Fore.RED + "Could not retrieve username. Cannot proceed with MagicRecon.")
    except Exception as e:
        print(Fore.RED + f"Error launching MagicRecon: {e}")

def clear_screen():
    """Clear the screen based on the OS."""
    os.system('cls' if os.name == 'nt' else 'clear')

def main_menu():
    while True:
        clear_screen()  # Clear the screen before showing the menu
        print(Fore.WHITE + "\nMain Menu:")
        print(Fore.GREEN + "8. Run MagicRecon")
        print(Fore.RED + "9. Exit")

        option = input(Fore.CYAN + "\nEnter an option: ").strip()

        if option == "8":
            run_magicrecon()  # Launch MagicRecon directly when option 8 is selected
        elif option == "9":
            print(Fore.GREEN + "Exiting program...")
            break
        else:
            print(Fore.RED + "Invalid option. Please try again.")

# DO NOT call main_menu() automatically at the start of the script











# Main menu function with options
def main_menu():
   while True:
      show_main_menu_logo()
      print(Fore.LIGHTYELLOW_EX+ "sudo python3 xp.py To Update, Then Exit Program")
      print(Fore.LIGHTCYAN_EX + "V 0.1 biskit@")
      print(Fore.LIGHTRED_EX+"1. nmap")
      print(Fore.BLUE+"2. Show All Nmap Commands")
      print(Fore.LIGHTCYAN_EX+"3. sslscan")
      print(Fore.LIGHTRED_EX+"5. Metasploit")
      print(Fore.BLUE+"7. subfinder")
      print(Fore.LIGHTCYAN_EX+"6. Update Script")
      print(Fore.LIGHTRED_EX  +"8. MagicRecon")
      print(Fore.BLUE+         "88. Routersploit")
      print(Fore.LIGHTCYAN_EX+"99. Exit")
      choice = input(Fore.LIGHTBLACK_EX + "\nEnter your choice: ").strip()
      if choice == '2':
        show_all_nmap_commands()
      elif choice == '1':
       run_nmap()
      elif choice == '3':
        sslscan_scan()
      elif choice == '5':
        metasploit_scan()
      elif choice == '6':
        update_script()
      elif choice == '7':
       run_subfinder()
      elif choice == '8': 
        run_magicrecon()
      elif choice == '88':
        run_routersploit()
      elif choice == '99' :
        exiting_loading_screen()
      else:
        print(Fore.RED + "Invalid choice. Please try again.")

if __name__ == "__main__":
   main_menu()
