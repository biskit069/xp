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
 ⠀  __  ___            _      __  __      _                    
   /  |/  /___ _____ _(_)____/ / / /___  (_)________  _________  _____  
  / /|_/ / __ `/ __ `/ / ___/ / / / __ \/ / ___/ __ \/ ___/ __ \/ ___/  
 / /  / / /_/ / /_/ / / /__/ /_/ / / / / / /__/ /_/ / /  / / / (__  )  
/_/  /_/\__,_/\__, /_/\___/\____/_/ /_/_/\___/\____/_/  /_/ /_/____/   
         /____/                                  ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀  
⠀⠀⠀⠀⠀⠀⠀⠀   
   _____                        _            
  / ___/_________ _____  ____  (_)___  ____ _    
  \__ \/ ___/ __ `/ __ \/ __ \/ / __ \/ __ `/    
 ___/ / /__/ /_/ / / / / / / / / / / / /_/ / _ _  
/____/\___/\__,_/_/ /_/_/ /_/_/_/ /_/\__, (_|_|_)  
                        /____/'''    
  # Fast printing of each line with a very short delay and alternating colors  
  for i, line in enumerate(loading_text.splitlines()):  
   if i % 2 == 0:  
    print(Fore.LIGHTWHITE_EX + line)  # Blue for even lines  
   else:  
    print(Fore.LIGHTRED_EX + line)  # White for odd lines  
   time.sleep(0.1)  # Short delay (0.1 seconds per line)  
  print(Fore.BLUE + """Running Scan...    
        Connection Completed Waiting For Results...    
    """)    
  
# Function to show the main menu logo with blue and white mix  
def show_main_menu_logo():  
  logo_text = r'''    
    __  ___            _      ____        _       __                      
   /  |/  /___ _____ _(_)____/ __ \____ _(_)___  / /_  ____ _      _______
  / /|_/ / __ `/ __ `/ / ___/ /_/ / __ `/ / __ \/ __ \/ __ \ | /| / / ___/
 / /  / / /_/ / /_/ / / /__/ _, _/ /_/ / / / / / /_/ / /_/ / |/ |/ (__  ) 
/_/  /_/\__,_/\__, /_/\___/_/ |_|\__,_/_/_/ /_/_.___/\____/|__/|__/____/  
             /____/                                                                                    '''    
  clear_screen()  
  for i, line in enumerate(logo_text.splitlines()):  
   if i % 2 == 0:  
    print(Fore.LIGHTRED_EX + line)  # Blue for even lines  
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
   scanning_in_progress = False  
   # Clear the screen after the scan if user presses Enter  
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
   "nmap 192.168.1.1     Scan a single IP",  
   "nmap 192.168.1.1-254    Scan a range",  
   "nmap -iL targets.txt    Scan targets from a file",  
   "nmap -sS 192.168.1.1    TCP SYN scan",  
   "nmap -sT 192.168.1.1    TCP Connect scan",  
   "nmap -O 192.168.1.1    OS detection",  
   "nmap -sU 192.168.1.1    UDP scan",  
   "nmap -p 80 192.168.1.1   Scan port 80",  
   "nmap -p 1-1000 192.168.1.1  Scan ports 1-1000",  
   "nmap -sV 192.168.1.1    Version detection",  
   "nmap -A 192.168.1.1    OS detection, version detection, script scanning, traceroute",  
   "nmap -Pn 192.168.1.1    Disable ping scan"  
  ]  
  show_submenu(commands)  
  
# Function to show OS scan commands  
def show_os_scan_commands():  
  clear_screen()  
  commands = [  
   "OS Scan Commands:",  
   "nmap -O 192.168.1.1    Enable OS detection",  
   "nmap -A 192.168.1.1    Aggressive scan with OS detection",  
   "nmap --osscan-guess    Guess the OS if exact match is not found"  
  ]  
  show_submenu(commands)  
  
# Function to show NSE script commands  
def show_nse_script_commands():  
  clear_screen()  
  commands = [  
   "NSE Script Commands:",  
   "nmap --script=vuln 192.168.1.1  Run vulnerability scripts",  
   "nmap --script=http-enum 192.168.1.1  Enumerate web services",  
   "nmap --script=default 192.168.1.1  Run default scripts"  
  ]  
  show_submenu(commands)  
  
# Function to show firewall scan commands  
def show_firewall_scan_commands():  
  clear_screen()  
  commands = [  
   "Firewall Scan Commands:",  
   "nmap -Pn 192.168.1.1    Scan without ping",  
   "nmap -f 192.168.1.1    Fragment packets",  
   "nmap --mtu 24 192.168.1.1  Specify custom MTU"  
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
    ______      _                           _       __                      
   / __/ /_  __(_)___  ____ _   _________ _(_)___  / /_  ____ _      _______
  / /_/ / / / / / __ \/ __ `/  / ___/ __ `/ / __ \/ __ \/ __ \ | /| / / ___/
 / __/ / /_/ / / / / / /_/ /  / /  / /_/ / / / / / /_/ / /_/ / |/ |/ (__  ) 
/_/ /_/\__, /_/_/ /_/\__, /  /_/   \__,_/_/_/ /_/_.___/\____/|__/|__/____/  
      /____/        /____/                                                                        
  '''  
  
  
  # Fast printing of each line with a short delay and alternating colors  
  for i, line in enumerate(loading_text.splitlines()):  
   if i % 5 == 0:  
    print(Fore.LIGHTRED_EX + line)  # Blue for even lines  
   else:  
    print(Fore.LIGHTWHITE_EX + line)  # White for odd lines  
   time.sleep(0.1)  # Short delay (0.1 seconds per line)  
  
  # Display a final "Exiting..." message with a blue background and white text  
  print(Fore.BLUE + Fore.WHITE + "\n")  
  time.sleep(1)  # Wait for a second before program exit  
  print("Taking The Piss ingore the unicorn shit ")  # Final message  
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
  
      # Ask if you want to save the results  
      save_results = input(Fore.BLUE + "Do you want to save the results? (yes/no): ").strip().lower()  
      if save_results == "yes":  
       # Automatically save the results to a file  
       file_name = f"sslscan_results_{ip}.txt"  
       with open(file_name, "a") as file:  
        file.write(f"IP: {ip}\n{output}\n\n")  
       print(Fore.BLUE + f"Results saved to '{file_name}'.")  
      elif save_results == "no":  
       print(Fore.BLUE + "Results not saved.")  
      else:  
       print(Fore.RED + "Invalid choice. Results not saved.")  
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
   "sslscan {ip}      Basic SSL Scan",  
   "sslscan --full {ip}    Full SSL Scan",  
   "sslscan --cert {ip}    SSL Certificate Details",  
   "sslscan --tls1_2 {ip}   Check TLS 1.2 Support"  
  ]  
  show_submenu(ssl_commands)  
  
# Function to update the script from GitHub  
def update_script():  
  try:  
   print(Fore.BLUE + "Updating script from GitHub...")  
   url = "https://github.com/biskit069/magic/blob/main/magic.py"  
   response = requests.get(url)  
   if response.status_code == 200:  
    with open(__file__, "w") as file:  
      file.write(response.text)  
    print(Fore.GREEN + "Script updated successfully!")  
   else:  
    print(Fore.RED + "Failed to update script.")  
  except Exception as e:  
   print(Fore.RED + f"Error updating script: {e}")  
  finally:  
   clear_screen()  
  
# Main menu function with options  
def main_menu():  
  while True:  
   show_main_menu_logo()  
   print("Manual Scan is Broken fixing later...")  
   print(Fore.LIGHTRED_EX +   "V 0.1 biskit@ ")  
   print(Fore.WHITE +"Press Ctrl+C To Exit Scans And Return To Main Menu" )  
   print(Fore.LIGHTRED_EX + "1. Manual Nmap Scan")  
   print(Fore.LIGHTRED_EX + "2. Run SSLScan")  
   print(Fore.LIGHTRED_EX + "3. View All Nmap Commands")  
   print(Fore.LIGHTRED_EX + "4. View OS Scan Commands")  
   print(Fore.LIGHTRED_EX + "5. View NSE Script Commands")  
   print(Fore.LIGHTRED_EX + "6. View Firewall Scan Commands")  
   print(Fore.LIGHTRED_EX + "7. Run Automatic Scan")  
   print(Fore.LIGHTRED_EX + "8. Run Scan Without DNS Resolution")  
   print(Fore.LIGHTRED_EX + "9. Run Stealth Scan")  
   print(Fore.LIGHTRED_EX + "10. Scan Multiple IPs with CIDR 0/24")  
   print(Fore.LIGHTRED_EX + "11. Show SSLScan Commands")  
   print(Fore.LIGHTRED_EX + "12. Update Script")  
   print(Fore.WHITE + "13. Exit")  
  
   try:  
    option = int(input(Fore.GREEN + "Select an option: "))  
    if option == 1:  
      normal_nmap_scan()  
    elif option == 2:  
      sslscan_scan()  
    elif option == 3:  
      show_all_nmap_commands()  
    elif option == 4:  
      show_os_scan_commands()  
    elif option == 5:  
      show_nse_script_commands()  
    elif option == 6:  
      show_firewall_scan_commands()  
    elif option == 7:  
      automatic_scan()  
    elif option == 8:  
      automatic_scan_no_dns()  
    elif option == 9:  
      automatic_stealth_scan()  
    elif option == 10:  
      scan_ip_0_24()  
    elif option == 11:  
      show_sslscan_commands()  
    elif option == 12:  
      update_script()  
    elif option == 13:  
      exiting_loading_screen()  
    else:  
      print(Fore.RED + "Invalid option, please try again.")  
   except ValueError:  
    print(Fore.RED + "Invalid input. Please enter a valid option.")  
  
if __name__ == "__main__":  
  main_menu()
