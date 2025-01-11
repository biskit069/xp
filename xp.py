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

# Initialize colorama
init(autoreset=True)

# Global flag for exit condition
exit_program = False
scanning_in_progress = False

# Function to handle Ctrl+C gracefully
def signal_handler(sig, frame):
   global exit_program, scanning_in_progress
   if scanning_in_progress:
      print("\nScan aborted. Returning to the main menu...")
      exit_program = False  # Allow return to main menu
   else:
      print("\nScan is not in progress.")
   return

# Register the signal handler
signal.signal(signal.SIGINT, signal_handler)

# Function to clear the screen (teleportation effect)
def clear_screen():
   if platform.system() == "Windows":
      os.system("cls")
   else:
      os.system("clear")

# ASCII loading screen with faster effect and blue/white color scheme
def fast_loading_screen():
   clear_screen()
   loading_text = '''
   
                                                         .__                           
  ______ ____ _____    ____   _______ __ __  ____   ____ |__| ____    ____             
 /  ___// ___\\__  \  /    \  \_  __ \  |  \/    \ /    \|  |/    \  / ___\            
 \___ \\  \___ / __ \|   |  \  |  | \/  |  /   |  \   |  \  |   |  \/ /_/  >           
/____  >\___  >____  /___|  /  |__|  |____/|___|  /___|  /__|___|  /\___  / /\  /\  /\ 
     \/     \/     \/     \/                    \/     \/        \//_____/  \/  \/  \/                                                                                                                              
   '''
   for i, line in enumerate(loading_text.splitlines()):
      if i % 2 == 0:
        print(Fore.WHITE + line)  # Blue for even lines
      else:
        print(Fore.LIGHTWHITE_EX + line)  # White for odd lines
      time.sleep(0.1)  # Short delay (0.1 seconds per line)
   print(Fore.CYAN + """Running Scan... Connection Completed Waiting For Results... """)

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
        print(Fore.RED+ line)  # Blue for even lines
      else:
        print(Fore.LIGHTRED_EX + line)  # White for odd lines
      time.sleep(0.1)  # Medium delay (0.3 seconds per line)

# Function to run a scan with a given command
import subprocess
from colorama import Fore

def run_scan(command, ip=None):
    global exit_program, scanning_in_progress
    scanning_in_progress = True
    try:
        # Display the fast loading screen (this function needs to be defined elsewhere in your code)
        fast_loading_screen()
        
        # Check if the command is not empty or None
        if command:
            print(Fore.LIGHTCYAN_EX + f"Running command: {command}")
            
            # Run the scan in a subprocess
            process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            stdout, stderr = process.communicate()
            
            if stderr:
                print(Fore.RED + "Error during scan:", stderr.decode())
            else:
                output = stdout.decode()
                print(Fore.BLUE + "Scan Completed Successfully.")
                print(output)
                
                # Save the packet data to a file
                save_results = input(Fore.YELLOW + "Would you like to save the results of the scan and the IP? (yes/no): ").strip().lower()
                
                if save_results == "yes":
                    file_name = input(Fore.LIGHTWHITE_EX + "Enter a file name to save results (e.g., results.txt): ").strip()
                    
                    # Save the results in the file without root privileges
                    with open(file_name, "a") as file:
                        file.write(f"IP: {ip}\n{output}\n\n")
                    print(Fore.LIGHTGREEN_EX + f"Results saved to '{file_name}'.")
                
                elif save_results == "no":
                    print(Fore.WHITE + "Returning to the main menu...")
                else:
                    print(Fore.RED + "Invalid choice, returning to the main menu.")
                
                # Add a prompt to ensure the user sees the output
                input(Fore.LIGHTRED_EX + "\nPress Enter to return to the main menu...")
        
        else:
            print(Fore.RED + "Error: Invalid command!")
    
    except subprocess.CalledProcessError as e:
        print(f"Error running scan: {e}")
    
    finally:
        scanning_in_progress = False  # Clear the screen after the scan if user presses Enter
        clear_screen()  # Ensure this function is defined elsewhere in your code


# Function to handle IP address input with exit option

import subprocess
from colorama import Fore

import subprocess
from colorama import Fore

import subprocess
from colorama import Fore

def get_ip_address():
    """Run an Nmap scan based on the full Nmap command input by the user."""
    try:
        # Prompt the user to enter the full Nmap command (e.g., nmap 203.211.74.76 -vv -n)
        command = input(Fore.CYAN + "Enter your Nmap command (e.g., nmap 192.168.1.1 -vv -n): ").strip()

        if command:
            print(Fore.GREEN + f"Running command: {command}\n")
            
            # Execute the Nmap command using subprocess
            process = subprocess.Popen(
                command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
            )

            # Capture the output and error
            stdout, stderr = process.communicate()

            if stderr:
                print(Fore.RED + f"Error during Nmap scan: {stderr.strip()}")
            else:
                print(Fore.LIGHTCYAN_EX + "\nScan Results:")
                print(stdout)  # Print the scan results directly to the screen

                # Ask if the user wants to save the results
                save_results = input(Fore.YELLOW + "\nWould you like to save the results to a file? (yes/no): ").strip().lower()
                if save_results == 'yes':
                    file_name = input(Fore.LIGHTWHITE_EX + "Enter the file name (e.g., scan_results.txt): ").strip()
                    with open(file_name, "w") as file:
                        file.write(stdout)  # Save the scan output to the file
                    print(Fore.GREEN + f"Results saved to '{file_name}'.")
                elif save_results == 'no':
                    print(Fore.WHITE + "Results not saved.")
                else:
                    print(Fore.RED + "Invalid choice. Results not saved.")

                # Prompt to return to the main menu after showing results
                input(Fore.LIGHTRED_EX + "\nPress Enter to return to the main menu...")

        else:
            print(Fore.RED + "No command entered. Please try again.")

    except Exception as e:
        print(Fore.RED + f"Error running Nmap scan: {e}")

# Main function will not run automatically, you call it when needed
if __name__ == "__main__":
    pass  # Nothing will run automatically at startup














# Function for automatic scan with default command
def automatic_scan():
   ip = get_ip_address()
   if ip:
      # Simplified scan command to only include the --script vuln option
      full_command = f"nmap --script vuln -n -sS {ip}"
      run_scan(full_command, ip)

# Function for automatic scan with DNS resolution disabled
def automatic_scan_no_dns():
   ip = get_ip_address()
   if ip:
      full_command = f"nmap -n -T4 {ip}"
      run_scan(full_command, ip)

# Function for automatic stealth scan
def automatic_stealth_scan():
   ip = get_ip_address()
   if ip:
      full_command = f"nmap -sS -D RND:10 -T4 {ip}"
      run_scan(full_command, ip)

# Function to scan multiple IP addresses (up to 240) with automatic CIDR 0/24 option
def scan_ip_0_24():
   clear_screen()
   ips = input("\nEnter up to 240 IP addresses in CIDR format (e.g., 192.168.1.0/24): ").split()
   if len(ips) > 240:
      print("You can only scan up to 240 IP addresses at once.")
      return
   # Update the command to scan in CIDR format 0/24
   for ip in ips:
      print(Fore.LIGHTCYAN_EX + f"Running {ip} with 0/24...")
      full_command = f"nmap -T4 -n -vv {ip}/24"
      run_scan(full_command, ip)
init(autoreset=True)



import os
import subprocess
from colorama import Fore, init

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
   clear_screen()
   commands = [
      "All Nmap Commands:",
      "nmap 192.168.1.1 Scan a single IP",
      "nmap 192.168.1.1-254 Scan a range",
      "nmap -iL targets.txt Scan targets from a file",
      "nmap -sS 192.168.1.1 TCP SYN scan",
      "nmap -sT 192.168.1.1 TCP Connect scan",
      "nmap -O 192.168.1.1 OS detection",
      "nmap -sU 192.168.1.1 UDP scan",
      "nmap -p 80 192.168.1.1 Scan port 80",
      "nmap -p 1-1000 192.168.1.1 Scan ports 1-1000",
      "nmap -sV 192.168.1.1 Version detection",
      "nmap -A 192.168.1.1 OS detection, version detection, script scanning, traceroute",
      "nmap -Pn 192.168.1.1 Disable ping scan"

   '''
-sS nmap 192.168.1.1 -sS        TCP SYN port scan (Default)
-sT     nmap 192.168.1.1 -sT    TCP connect port scan (Default without root privilege)
-sU     nmap 192.168.1.1 -sU    UDP port scan
-sA     nmap 192.168.1.1 -sA    TCP ACK port scan
-sW     nmap 192.168.1.1 -sW    TCP Window port scan
-sM     nmap 192.168.1.1 -sM    TCP Maimon port scan
-PR     nmap 192.168.1.1-1/24 -PR       ARP discovery on local network
-p      nmap 192.168.1.1 -p http,https  Port scan from service name
-sV -version-all        nmap 192.168.1.1 -sV -version-all       Enable intensity level 9. Higher possibility of correctness. Slower
-O      nmap 192.168.1.1 -O     Remote OS detection using TCP/IP stack fingerprinting
-O -osscan-limit        nmap 192.168.1.1 -O -osscan-limit       If at least one open and one closed TCP port are not found it will not try OS detection against host
-O -osscan-guess        nmap 192.168.1.1 -O -osscan-guess       Makes Nmap guess more aggressively
-O -max-os-tries        nmap 192.168.1.1 -O -max-os-tries 1     Set the maximum number x of OS detection tries against a target
-A      nmap 192.168.1.1 -A     Enables OS detection, version detection, script scanning, and traceroute
-T5     nmap 192.168.1.1 -T5    Insane (5) speeds scan; assumes you are on an extraordinarily fast network
-sC     nmap 192.168.1.1 -sC    Scan with default NSE scripts. Considered useful for discovery and safe
-script default nmap 192.168.1.1 -script default        Scan with default NSE scripts. Considered useful for discovery and safe
-script nmap 192.168.1.1 -script=banner Scan with a single script. Example banner
-script nmap 192.168.1.1 -script=http*  Scan with a wildcard. Example http
-script nmap 192.168.1.1 -script=http,banner    Scan with two scripts. Example http and banner
-script nmap 192.168.1.1 -script "not intrusive"        Scan default, but remove intrusive scripts
-script-args    nmap -script snmp-sysdescr -script-args snmpcommunity=admin 192.168.1.1 NSE script with arguments
nmap -Pn -script=http-sitemap-generator scanme.nmap.org http site map generator
nmap -n -Pn -p 80 -open -sV -vvv -script banner,http-title -iR 1000     Fast search for random web servers
nmap -Pn -script=dns-brute domain.com   Brute forces DNS hostnames guessing subdomains
nmap -n -Pn -vv -O -sV -script smb-enum*,smb-ls,smb-mbenum,smb-os-discovery,smb-s*,smb-vuln*,smbv2* -vv 192.168.1.1     Safe SMB scripts to run
nmap -script whois* domain.com  Whois query
nmap -p80 -script http-unsafe-output-escaping scanme.nmap.org   Detect cross site scripting vulnerabilities
nmap -p80 -script http-sql-injection scanme.nmap.org    Check for SQL injections
-f      nmap 192.168.1.1 -f     Requested scan (including ping scans) use tiny fragmented IP packets. Harder for packet filters
-mtu    nmap 192.168.1.1 -mtu 32        Set your own offset size
-D      nmap -D 192.168.1.101,192.168.1.102,192.168.1.103,192.168.1.23 192.168.1.1      Send scans from spoofed IPs
-D      nmap -D decoy-ip1,decoy-ip2,your-own-ip,decoy-ip3,decoy-ip4 remote-host-ip      Above example explained
-S      nmap -S www.microsoft.com www.facebook.com      Scan Facebook from Microsoft (-e eth0 -Pn may be required)
-g      nmap -g 53 192.168.1.1  Use given source port number
-proxies        nmap -proxies http://192.168.1.1:8080, http://192.168.1.2:8080 192.168.1.1      Relay connections through HTTP/SOCKS4 proxies
-data-length    nmap -data-length 200 192.168.1.1       Appends random data to sent packets
-oN     nmap 192.168.1.1 -oN normal.file        Normal output to the file normal.file
-oX     nmap 192.168.1.1 -oX xml.file   XML output to the file xml.file
-oG     nmap 192.168.1.1 -oG grep.file  Grepable output to the file grep.file
-oA     nmap 192.168.1.1 -oA results    Output in the three major formats at once
-oG -   nmap 192.168.1.1 -oG -  Grepable output to screen. -oN -, -oX - also usable
-append-output  nmap 192.168.1.1 -oN file.file -append-output   Append a scan to a previous scan file
-v      nmap 192.168.1.1 -v     Increase the verbosity level (use -vv or more for greater effect)
-d      nmap 192.168.1.1 -d     Increase debugging level (use -dd or more for greater effect)
-reason nmap 192.168.1.1 -reason        Display the reason a port is in a particular state, same output as -vv
-open   nmap 192.168.1.1 -open  Only show open (or possibly open) ports
-packet-trace   nmap 192.168.1.1 -T4 -packet-trace      Show all packets sent and received
-iflist nmap -iflist    Shows the host interfaces and routes
-resume nmap -resume results.file       Resume a scan
nmap -p80 -sV -oG - -open 192.168.1.1/24 | grep open    Scan for web servers and grep to show which IPs are running web servers
nmap -iR 10 -n -oX out.xml | grep "Nmap" | cut -d " " -f5 > live-hosts.txt      Generate a list of the IPs of live hosts
nmap -iR 10 -n -oX out2.xml | grep "Nmap" | cut -d " " -f5 >> live-hosts.txt    Append IP to the list of live hosts
ndiff scanl.xml scan2.xml       Compare output from nmap using the ndif
xsltproc nmap.xml -o nmap.html  Convert nmap xml files to html files
grep " open " results.nmap | sed -r ‘s/ +/ /g’ | sort | uniq -c | sort -rn | less       Reverse sorted list of how often ports turn up
-6      nmap -6 2607:f0d0:1002:51::4    Enable IPv6 scanning
-h      nmap -h nmap help screen
nmap -iR 10 -PS22-25,80,113,1050,35000 -v -sn   Discovery only on ports x, no port scan
nmap 192.168.1.1-1/24 -PR -sn -vv       Arp discovery only on local network, no port scan
nmap -iR 10 -sn -traceroute     Traceroute to random targets, no port scan
nmap 192.168.1.1-50 -sL -dns-server 192.168.1.1 Query the Internal DNS for hosts, list targets only
nmap 192.168.1.1 --packet-trace Show the details of the packets that are sent and received during a scan and capture the traffic.

!!! Fixing Later !!!
'''

   ]
   show_submenu(commands)

# Function to show OS scan commands
def show_os_scan_commands():
   clear_screen()
   commands = [
      "OS Scan Commands:",
      "nmap -O 192.168.1.1 Enable OS detection",
      "nmap -A 192.168.1.1 Aggressive scan with OS detection",
      "nmap --osscan-guess Guess the OS if exact match is not found"
   ]
   show_submenu(commands)

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

# Function to handle manual Nmap scan (option 1)
def normal_nmap_scan():
   ip = get_ip_address()
   if ip:
      command = input(Fore.LIGHTRED_EX + "Enter your Nmap command: ").strip()
      full_command = f"nmap {command} {ip}"
      run_scan(full_command, ip)

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
        print(Fore.WHITE + line)  # Blue for even lines
      else:
        print(Fore.WHITE + line)  # White for odd lines
      time.sleep(0.1)  # Short delay (0.1 seconds per line)
   # Display a final "Exiting..." message with a blue background and white text
   print(Fore.BLUE + Fore.WHITE + "\n")
   time.sleep(1)  # Wait for a second before program exit
   print(Fore.YELLOW + "Credits! biskit")
   # Final message
   sys.exit()  # Exit the program

# Function to run SSLScan on a given IP with command selection
import subprocess
from colorama import Fore

import subprocess
from colorama import Fore

import subprocess
from colorama import Fore

def sslscan_scan():
    global scanning_in_progress
    try:
        print(Fore.BLUE + "\nChoose an SSLScan command:")
        print("1. Basic SSL Scan")
        print("2. Full SSL Scan")
        print("3. SSL Certificate Details")
        print("4. Manual SSLScan")
        print("5. Vuln Scan")
        print("99. Return to Main Menu")  # Option to return to the main menu
        choice = input(Fore.BLUE + "\nEnter your choice: ").strip()

        # Return to the main menu if the user selects option 99
        if choice == '99':
            print(Fore.LIGHTCYAN_EX + "Returning to the main menu...")
            return  # Exits the function and goes back to the main menu

        ip = ""  # Default to empty, we'll ask for IP only when necessary

        # Only prompt for IP if needed
        if choice in ['1', '2', '3', '5']:  # Basic, Full, Cert, and Vuln scans
            ip = get_ip_address()  # Assuming this is your method to get the IP address
            if not ip:
                print(Fore.RED + "No IP address provided. Exiting SSLScan.")
                return

        # Define the SSLScan command based on the user's choice
        if choice == '1':
            command = f"sslscan {ip}"
        elif choice == '2':
            command = f"sslscan --full {ip}"
        elif choice == '3':
            command = f"sslscan --cert {ip}"
        elif choice == '4':
            print(Fore.YELLOW + "\nExample of Manual SSLScan command:")
            print(Fore.YELLOW + "sslscan --bugs 192.168.1.1")
            command = input(Fore.BLUE + "Enter your SSLScan command: ").strip()
            if not command:
                print(Fore.RED + "No command entered. Returning to menu.")
                return  # Exit if no command is entered
            print(Fore.GREEN + f"Running custom SSLScan command: {command}")  # Debug print
        elif choice == '5':
            command = f"sslscan --bugs {ip}"  # New command for Vuln Scan
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

# Function to show SSLScan commands list (option 66)
def show_sslscan_commands():
    clear_screen()
    ssl_commands = [
        "SSLScan Commands:",
        "sslscan {ip} Basic SSL Scan",
        "sslscan --full {ip} Full SSL Scan",
        "sslscan --cert {ip} SSL Certificate Details",
        "sslscan --tls1_2 {ip} Check TLS 1.2 Support"
    ]
    show_submenu(ssl_commands)  # Assuming show_submenu() is defined elsewhere

def update_script():
   try:
      print("Updated Restart Script")
      url = "https://raw.githubusercontent.com/biskit069/nethunt/refs/heads/main/nethunt.py"
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


# Function to run Routersploit
# Function to run Metasploit
# Function to run Metasploit
# Function to run Metasploit


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








import subprocess
from colorama import Fore

def run_subfinder():
    """Function to launch Subfinder directly with a manually entered command."""
    try:
        # Prompt the user to manually enter the Subfinder command
        print(Fore.YELLOW + "\nEnter your custom Subfinder command (e.g., subfinder -d example.com -t 50 -timeout 3):")
        command = input(Fore.CYAN + "Enter command: ").strip()

        if command:
            print(Fore.GREEN + f"Running command: {command}")
            try:
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

import subprocess
import os
from colorama import Fore
import time
import sys

def get_linux_username():
    """Fetch the Linux system's current username."""
    try:
        username = subprocess.check_output("whoami", shell=True).decode().strip()
        return username
    except subprocess.CalledProcessError:
        print(Fore.RED + "Error retrieving the username.")
        return None

def run_magicrecon():
    """Function to launch MagicRecon directly with predefined options."""
    try:
        # Clear the screen when option 8 is selected
        clear_screen()

        # Fetch the Linux username
        username = get_linux_username()

        if username:
            magicrecon_path = f"/home/{username}/magicRecon/magicrecon.sh"  # Assuming MagicRecon is in the user's home directory

            if os.path.exists(magicrecon_path):
                print(Fore.GREEN + "Launching MagicRecon...")

                try:
                    domain = input(Fore.CYAN + "Enter the domain for MagicRecon: ").strip()
                    command = f"bash {magicrecon_path} -d {domain} -a"
                    subprocess.Popen(command, shell=True)  # This launches MagicRecon directly without capturing output

                    # Wait for user to press Enter to go back to main menu
                    input(Fore.GREEN + "\nPress Enter to return to the main menu...")
                except Exception as e:
                    print(Fore.RED + f"Error running MagicRecon: {e}")
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
        print(Fore.GREEN + "8. Run MagicRecon (Auto Command)")
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
      print(Fore.YELLOW+ "sudo python3 nethunt.py To Update")
      print(Fore.LIGHTYELLOW_EX + "V 0.1 biskit@")
      print(Fore.LIGHTWHITE_EX+"1. nmap")
      print(Fore.LIGHTWHITE_EX+"2. Show All Nmap Commands")
      print(Fore.LIGHTWHITE_EX+"3. sslscan")
      print(Fore.LIGHTWHITE_EX+"5. Metasploit")
      print(Fore.LIGHTWHITE_EX+"7. subfinder")
      print(Fore.LIGHTWHITE_EX+"6. Update Script")
      print(Fore.LIGHTRED_EX  +"8. MagicRecon")
      print(Fore.LIGHTCYAN_EX+"99. Exit")
      choice = input(Fore.RED + "\nEnter your choice: ").strip()
      if choice == '2':
        show_all_nmap_commands()
      elif choice == '1':
        normal_nmap_scan()
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
      elif choice == '99':
        exiting_loading_screen()
      else:
        print(Fore.RED + "Invalid choice. Please try again.")

if __name__ == "__main__":
   main_menu()
