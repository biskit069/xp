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
              __           ____              __                      __       
  ____ ______/ /_   ____  / __/  ____  ___  / /__      ______  _____/ /_______
 / __ `/ ___/ __/  / __ \/ /_   / __ \/ _ \/ __/ | /| / / __ \/ ___/ //_/ ___/
/ /_/ / /  / /_   / /_/ / __/  / / / /  __/ /_ | |/ |/ / /_/ / /  / ,< (__  ) 
\__,_/_/   \__/   \____/_/    /_/ /_/\___/\__/ |__/|__/\____/_/  /_/|_/____/  
                                                                                         
  
                                _                
   ______________ _____  ____  (_)___  ____ _    
  / ___/ ___/ __ `/ __ \/ __ \/ / __ \/ __ `/    
 (__  ) /__/ /_/ / / / / / / / / / / / /_/ / _ _ 
/____/\___/\__,_/_/ /_/_/ /_/_/_/ /_/\__, (_|_|_)
                                    /____/       
  
  
   '''  
   for i, line in enumerate(loading_text.splitlines()):  
      if i % 2 == 0:  
        print(Fore.BLUE + line)  # Blue for even lines  
      else:  
        print(Fore.WHITE + line)  # White for odd lines  
      time.sleep(0.1)  # Short delay (0.1 seconds per line)  
   print(Fore.BLUE + """Running Scan... Connection Completed Waiting For Results... """)  
  
# Function to show the main menu logo with blue and white mix  
def show_main_menu_logo():  
   logo_text = r'''  
    ____        _     __         
   / __ \____ _(_)___/ /__  _____
  / /_/ / __ `/ / __  / _ \/ ___/
 / _, _/ /_/ / / /_/ /  __/ /    
/_/ |_|\__,_/_/\__,_/\___/_/     
                                                                                                             
   '''  
   clear_screen()  
   for i, line in enumerate(logo_text.splitlines()):  
      if i % 2 == 0:  
        print(Fore.BLUE + line)  # Blue for even lines  
      else:  
        print(Fore.WHITE + line)  # White for odd lines  
      time.sleep(0.1)  # Medium delay (0.3 seconds per line)  
  
# Function to run a scan with a given command  
def run_scan(command, ip=None):  
   global exit_program, scanning_in_progress  
   scanning_in_progress = True  
   try:  
      # Display the fast loading screen  
      fast_loading_screen()  
      # Check if the command is not empty or None  
      if command:  
        print(Fore.BLUE + f"Running command: {command}")  
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
           save_results = input(Fore.BLUE + "Would you like to save the results of the scan and the IP? (yes/no): ").strip().lower()  
           if save_results == "yes":  
              file_name = input(Fore.BLUE + "Enter a file name to save results (e.g., results.txt): ").strip()  
              with open(file_name, "a") as file:  
                file.write(f"IP: {ip}\n{output}\n\n")  
              print(Fore.BLUE + f"Results saved to '{file_name}'.")  
           elif save_results == "no":  
              print(Fore.BLUE + "Returning to the main menu...")  
           else:  
              print(Fore.RED + "Invalid choice, returning to the main menu.")  
           # Add a prompt to ensure the user sees the output  
           input(Fore.BLUE + "\nPress Enter to return to the main menu...")  
      else:  
        print(Fore.RED + "Error: Invalid command!")  
   except subprocess.CalledProcessError as e:  
      print(f"Error running scan: {e}")  
   finally:  
      scanning_in_progress = False  # Clear the screen after the scan if user presses Enter  
      clear_screen()  
  
# Function to handle IP address input with exit option  
def get_ip_address():  
   ip = ""  
   while True:  
      ip = input("\nEnter IP address to scan (or press 'q' to cancel): ").strip()  
      if ip.lower() == 'q':  
        print("\nExiting IP input...")  
        break  
      try:  
        ipaddress.ip_address(ip)  
        return ip  
      except ValueError:  
        print(Fore.RED + "Invalid IP address. Please try again.")  
  
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
      print(Fore.BLUE + f"Running {ip} with 0/24...")  
      full_command = f"nmap -T4 -sS -sU --script vuln -n {ip}/24"  
      run_scan(full_command, ip)  
  
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
   input(Fore.BLUE + "\nPress Enter to return to the main menu...")  
  
# Function to handle manual Nmap scan (option 1)  
def normal_nmap_scan():  
   ip = get_ip_address()  
   if ip:  
      command = input(Fore.BLUE + "Enter your Nmap command: ").strip()  
      full_command = f"nmap {command} {ip}"  
      run_scan(full_command, ip)  
  
# Exiting loading screen with blue and white color scheme  
def exiting_loading_screen():  
   clear_screen()  
   loading_text = '''  
  ___          ___          
 | _ )_  _ ___| _ )_  _ ___ 
 | _ \ || / -_) _ \ || / -_)
 |___/\_, \___|___/\_, \___|
      |__/         |__/     
   '''  
   for i, line in enumerate(loading_text.splitlines()):  
      if i % 5 == 0:  
        print(Fore.BLUE + line)  # Blue for even lines  
      else:  
        print(Fore.WHITE + line)  # White for odd lines  
      time.sleep(0.1)  # Short delay (0.1 seconds per line)  
   # Display a final "Exiting..." message with a blue background and white text  
   print(Fore.BLUE + Fore.WHITE + "\n")  
   time.sleep(1)  # Wait for a second before program exit  
   print("")  
   # Final message  
   sys.exit()  # Exit the program  
  
# Function to run SSLScan on a given IP with command selection  
def sslscan_scan():  
   global scanning_in_progress  
   ip = get_ip_address()  
   if ip:  
      scanning_in_progress = True  
      try:  
        print(Fore.BLUE + "\nChoose an SSLScan command:")  
        print("1. Basic SSL Scan")  
        print("2. Full SSL Scan")  
        print("3. SSL Certificate Details")  
        print("4. Manual SSLScan")  
        print("5. Vuln Scan")  
        # Added new option  
        choice = input(Fore.BLUE + "\nEnter your choice: ").strip()  
        # Define the SSLScan command based on the user's choice  
        if choice == '1':  
           command = f"sslscan {ip}"  
        elif choice == '2':  
           command = f"sslscan --full {ip}"  
        elif choice == '3':  
           command = f"sslscan --cert {ip}"  
        elif choice == '4':  
           command = input(Fore.BLUE + "Enter your SSLScan command: ").strip()  
        elif choice == '5':  
           command = f"sslscan --bugs {ip}"  
           # New command for Vuln Scan  
        else:  
           print(Fore.RED + "Invalid choice. Exiting SSLScan.")  
           return  
        # Run the selected SSLScan command  
        print(Fore.BLUE + f"Running {command}...")  
        process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)  
        stdout, stderr = process.communicate()  
        if stderr:  
           print(Fore.RED + "Error during SSLScan:", stderr.decode())  
        else:  
           output = stdout.decode()  
           print(Fore.BLUE + "SSLScan Completed Successfully.")  
           print(output)  
           # Save SSL scan results to a file  
           file_name = input(Fore.BLUE + "Enter file name to save the results: ").strip()  
           with open(file_name, "a") as file:  
              file.write(f"IP: {ip}\n{output}\n\n")  
           print(Fore.BLUE + f"Results saved to '{file_name}'.")  
      except Exception as e:  
        print(Fore.RED + f"Error running SSLScan: {e}")  
      finally:  
        scanning_in_progress = False  
        clear_screen()  
  
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
   show_submenu(ssl_commands)  
  
# Function to update the script from GitHub  
def update_script():  
   try:  
      print(Fore.BLUE + "Updating script from GitHub...")  
      url = "https://raw.githubusercontent.com/biskit069/magic/refs/heads/main/magic.py"  
      response = requests.get(url)  
      with open(__file__, "w") as file:  
        file.write(response.text)  
      print(Fore.GREEN + "Script updated successfully!")  
   except requests.exceptions.RequestException as e:  
      print(Fore.RED + f"Error updating script: {e}")  
   finally:  
      clear_screen()  
  
# Function to run Routersploit  
# Function to run Metasploit  
def metasploit_scan():  
   global scanning_in_progress  
   ip = get_ip_address()  
   if ip:  
      scanning_in_progress = True  
      try:  
        while True:  
           print(Fore.BLUE + "\nChoose a Metasploit option:")  
           print("1. Scan for vulnerabilities")  
           print("2. Exploit a vulnerability")  
           print("3. Manual Metasploit")  
           print("4. View all Metasploit commands (-h)")  
           print("99. Return to main menu")  
           choice = input(Fore.BLUE + "\nEnter your choice: ").strip()  
           if choice == '1':  
              command = f"msfconsole -q -x 'use auxiliary/scanner/http/http_version; set RHOSTS {ip}; run'"  
              print(Fore.BLUE + f"Running {command}...")  
              process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)  
              stdout, stderr = process.communicate()  
              if stderr:  
                print(Fore.RED + "Error during Metasploit:", stderr.decode())  
              else:  
                output = stdout.decode()  
                print(Fore.BLUE + "Metasploit Completed Successfully.")  
                print(output)  
           elif choice == '2':  
              command = f"msfconsole -q -x 'use exploit/multi/http/tomcat_mgr_upload; set RHOSTS {ip}; run'"  
              print(Fore.BLUE + f"Running {command}...")  
              process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)  
              stdout, stderr = process.communicate()  
              if stderr:  
                print(Fore.RED + "Error during Metasploit:", stderr.decode())  
              else:  
                output = stdout.decode()  
                print(Fore.BLUE + "Metasploit Completed Successfully.")  
                print(output)  
           elif choice == '3':  
              command = input(Fore.BLUE + "Enter your Metasploit command: ").strip()  
              print(Fore.BLUE + f"Running {command}...")  
              process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)  
              stdout, stderr = process.communicate()  
              if stderr:  
                print(Fore.RED + "Error during Metasploit:", stderr.decode())  
              else:  
                output = stdout.decode()  
                print(Fore.BLUE + "Metasploit Completed Successfully.")  
                print(output)  
           elif choice == '4':  
              print(Fore.BLUE + "\nViewing all Metasploit commands...")  
              command = "msfconsole -h"  
              print(Fore.BLUE + f"Running {command}...")  
              process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)  
              stdout, stderr = process.communicate()  
              if stderr:  
                print(Fore.RED + "Error during Metasploit:", stderr.decode())  
              else:  
                output = stdout.decode()  
                print(Fore.BLUE + "Metasploit Commands:")  
                print(output)  
           elif choice == '99':  
              scanning_in_progress = False  
              break  
           else:  
              print(Fore.RED + "Invalid choice. Please try again.")  
      except Exception as e:  
        print(Fore.RED + f"Error running Metasploit: {e}")  
      finally:  
        scanning_in_progress = False  
        clear_screen()  
  
# Function to run Routersploit  
def routersploit_scan():  
   global scanning_in_progress  
   ip = get_ip_address()  
   if ip:  
      scanning_in_progress = True  
      try:  
        while True:  
           print(Fore.BLUE + "\nChoose a Routersploit option:")  
           print("1. Scan for vulnerabilities")  
           print("2. Exploit a vulnerability")  
           print("3. Manual Routersploit")  
           print("4. View all Routersploit commands (-h)")  
           print("99. Return to main menu")  
           choice = input(Fore.BLUE + "\nEnter your choice: ").strip()  
           if choice == '1':  
              command = f"routersploit scan {ip}"  
              print(Fore.BLUE + f"Running {command}...")  
              process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)  
              stdout, stderr = process.communicate()  
              if stderr:  
                print(Fore.RED + "Error during Routersploit:", stderr.decode())  
              else:  
                output = stdout.decode()  
                print(Fore.BLUE + "Routersploit Completed Successfully.")  
                print(output)  
           elif choice == '2':  
              command = f"routersploit exploit {ip}"  
              print(Fore.BLUE + f"Running {command}...")  
              process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)  
              stdout, stderr = process.communicate()  
              if stderr:  
                print(Fore.RED + "Error during Routersploit:", stderr.decode())  
              else:  
                output = stdout.decode()  
                print(Fore.BLUE + "Routersploit Completed Successfully.")  
                print(output)  
           elif choice == '3':  
              command = input(Fore.BLUE + "Enter your Routersploit command: ").strip()  
              print(Fore.BLUE + f"Running {command}...")  
              process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)  
              stdout, stderr = process.communicate()  
              if stderr:  
                print(Fore.RED + "Error during Routersploit:", stderr.decode())  
              else:  
                output = stdout.decode()  
                print(Fore.BLUE + "Routersploit Completed Successfully.")  
                print(output)  
           elif choice == '4':  
              print(Fore.BLUE + "\nViewing all Routersploit commands...")  
              command = "routersploit -h"  
              print(Fore.BLUE + f"Running {command}...")  
              process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)  
              stdout, stderr = process.communicate()  
              if stderr:  
                print(Fore.RED + "Error during Routersploit:", stderr.decode())  
              else:  
                output = stdout.decode()  
                print(Fore.BLUE + "Routersploit Commands:")  
                print(output)  
           elif choice == '99':  
              scanning_in_progress = False  
              break  
           else:  
              print(Fore.RED + "Invalid choice. Please try again.")  
      except Exception as e:  
        print(Fore.RED + f"Error running Routersploit: {e}")  
      finally:  
        scanning_in_progress = False  
        clear_screen()

  
# Main menu function with options  
def main_menu():  
   while True:  
      show_main_menu_logo()  
      print("Manual Scan is Broken fixing later...")  
      print(Fore.LIGHTCYAN_EX + "V 0.1 biskit@")  
      print("1. Automatic Scan")  
      print("2. Automatic Scan (No DNS)")  
      print("3. Automatic Stealth Scan")  
      print("4. Scan Multiple IP Addresses")  
      print("5. Show All Nmap Commands")  
      print("6. Show OS Scan Commands")  
      print("7. Show NSE Script Commands")  
      print("8. Show Firewall Scan Commands")  
      print("9. Manual Nmap Scan")  
      print("10. SSLScan")  
      print("11. Routersploit")  
      print("12. Metasploit")  
      print("13. Update Script")  
      print("14. Exit")  
      choice = input(Fore.BLUE + "\nEnter your choice: ").strip()  
      if choice == '1':  
        automatic_scan()  
      elif choice == '2':  
        automatic_scan_no_dns()  
      elif choice == '3':  
        automatic_stealth_scan()  
      elif choice == '4':  
        scan_ip_0_24()  
      elif choice == '5':  
        show_all_nmap_commands()  
      elif choice == '6':  
        show_os_scan_commands()  
      elif choice == '7':  
        show_nse_script_commands()  
      elif choice == '8':  
        show_firewall_scan_commands()  
      elif choice == '9':  
        normal_nmap_scan()  
      elif choice == '10':  
        sslscan_scan()  
      elif choice == '11':  
        routersploit_scan()  
      elif choice == '12':  
        metasploit_scan()  
      elif choice == '13':  
        update_script()  
      elif choice == '14':  
        exiting_loading_screen()  
      else:  
        print(Fore.RED + "Invalid choice. Please try again.")  
  
if __name__ == "__main__":  
   main_menu()
