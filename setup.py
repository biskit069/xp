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
  
def main():  
   install_nmap()  
   install_sslscan()  
  
if __name__ == "__main__":  
   main()
