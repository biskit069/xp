from setuptools import setup  
import subprocess  
import sys  
import platform  
  
def install_nmap():  
   if platform.system() == "Windows":  
      subprocess.run(["powershell", "-Command", "winget install nmap"], check=True)  
   elif platform.system() == "Darwin":  # macOS  
      subprocess.run(["brew", "install", "nmap"], check=True)  
   else:  # Linux  
      subprocess.run(["sudo", "apt-get", "install", "-y", "nmap"], check=True)  
  
def install_sslscan():  
   if platform.system() == "Windows":  
      subprocess.run(["powershell", "-Command", "winget install sslscan"], check=True)  
   elif platform.system() == "Darwin":  # macOS  
      subprocess.run(["brew", "install", "sslscan"], check=True)  
   else:  # Linux  
      subprocess.run(["sudo", "apt-get", "install", "-y", "sslscan"], check=True)  
  
def install_metasploit():  
   if platform.system() == "Windows":  
      subprocess.run(["powershell", "-Command", "choco install metasploit"], check=True)  
   elif platform.system() == "Darwin":  # macOS  
      subprocess.run(["brew", "install", "metasploit"], check=True)  
   else:  # Linux  
      subprocess.run(["sudo", "apt-get", "install", "-y", "metasploit-framework"], check=True)  
  
def install_routersploit():  
   if platform.system() == "Windows":  
      subprocess.run(["powershell", "-Command", "pip install routersploit"], check=True)  
   elif platform.system() == "Darwin":  # macOS  
      subprocess.run(["brew", "install", "routersploit"], check=True)  
   else:  # Linux  
      subprocess.run(["sudo", "apt-get", "install", "-y", "routersploit"], check=True)  
  
def main():  
   install_nmap()  
   install_sslscan()  
   install_metasploit()  
   install_routersploit()  
  
if __name__ == "__main__":  
   main()
