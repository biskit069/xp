import os
import subprocess
import shutil

# Function to install all required Python modules
def install_python_modules():
    print("Installing required Python modules...")
    try:
        subprocess.run(["pip", "install", "signal", "sys", "platform", "subprocess", "threading", "time", "os", "re", "ipaddress", "requests", "shutil", "colorama", "socket"], check=True)
        print("Python modules installed successfully.")
    except subprocess.CalledProcessError as e:
        print(f"Failed to install Python modules: {e}")

# Function to install tracepath using apt
def install_tracepath():
    print("Installing tracepath...")
    try:
        subprocess.run(["sudo", "apt", "install", "iputils-tracepath", "-y"], check=True, text=True)
        print("tracepath installed successfully.")
    except subprocess.CalledProcessError as e:
        print(f"Failed to install tracepath: {e}")

# Function to install golang using apt
def install_golang():
    print("Checking if golang is installed...")
    
    try:
        result = subprocess.run(["go", "version"], text=True, capture_output=True)
        if result.returncode == 0:
            print("golang is already installed.")
            return True
        else:
            print(f"golang check failed with error: {result.stderr}")
    except FileNotFoundError:
        print("golang is not installed. Installing now...")
    except Exception as e:
        print(f"An unexpected error occurred while checking golang: {e}")

    try:
        print("Installing golang...")
        subprocess.run(["sudo", "apt", "update"], check=True, text=True)
        subprocess.run(["sudo", "apt", "install", "-y", "golang"], check=True, text=True)
        print("golang installed successfully.")
        return True
    except subprocess.CalledProcessError as e:
        print(f"Failed to install golang: {e}")
        return False

# Function to install netcat using apt
def install_netcat():
    print("Installing netcat...")
    try:
        subprocess.run(["sudo", "apt", "install", "netcat", "-y"], check=True, text=True)
        print("netcat installed successfully.")
    except subprocess.CalledProcessError as e:
        print(f"Failed to install netcat: {e}")

# Function to install airgeddon using apt
def install_airgeddon():
    print("Installing airgeddon...")
    try:
        subprocess.run(["sudo", "apt", "install", "airgeddon", "-y"], check=True, text=True)
        print("airgeddon installed successfully.")
    except subprocess.CalledProcessError as e:
        print(f"Failed to install airgeddon: {e}")

# Function to install asnmap via Go and copy to the desired directory
def install_asnmap(home_dir):
    print("Installing asnmap...")
    try:
        # Ensure the GOPATH is set correctly
        go_path = os.path.join(home_dir, "go")
        os.environ["GOPATH"] = go_path
        os.environ["PATH"] += f":{os.path.join(go_path, 'bin')}"
        
        # Create GOPATH directory if it doesn't exist
        os.makedirs(go_path, exist_ok=True)

        # Install asnmap using go install
        subprocess.run(["go", "install", "github.com/projectdiscovery/asnmap/cmd/asnmap@latest"], text=True, check=True, timeout=300)
        print("asnmap installed successfully.")

        # Find the binary and copy it to the target directory
        asnmap_binary = os.path.join(go_path, "bin", "asnmap")
        if os.path.exists(asnmap_binary):
            target_path = os.path.join(home_dir, "asnmap")
            shutil.copy(asnmap_binary, target_path)
            print(f"asnmap binary copied to {target_path}.")
        else:
            print("asnmap binary not found in GOPATH bin directory.")
        
        # Ensure asnmap is executable and added to the PATH
        subprocess.run(f"chmod +x {asnmap_binary}", shell=True)
        subprocess.run(f"export PATH=$PATH:{os.path.dirname(asnmap_binary)}", shell=True)
        print("asnmap is now executable and available in the PATH.")
    except subprocess.CalledProcessError as e:
        print(f"Failed to install asnmap: {e}")
    except subprocess.TimeoutExpired:
        print("asnmap installation timed out.")
    except Exception as e:
        print(f"An unexpected error occurred while installing asnmap: {e}")

# Function to install g2l from GitHub
def install_g2l(home_dir):
    print("Installing g2l...")
    repo_url = "https://github.com/biskit069/g2l"
    repo_path = os.path.join(home_dir, "g2l")

    if not os.path.exists(repo_path):
        try:
            subprocess.run(["git", "clone", repo_url, repo_path], text=True, check=True, timeout=300)
            print(f"Cloned g2l into {repo_path}.")
        except subprocess.CalledProcessError as e:
            print(f"Failed to clone g2l: {e}")
            return
        except subprocess.TimeoutExpired:
            print("Cloning g2l timed out.")
            return

    # Install g2l
    os.chdir(repo_path)
    print("Installing g2l...")
    subprocess.run(["python3", "setup.py", "install"], check=True)
    print("g2l installed successfully.")

# Function to install routersploit from GitHub
def install_routersploit(home_dir):
    print("Installing routersploit...")
    repo_url = "https://github.com/threat9/routersploit"
    repo_path = os.path.join(home_dir, "routersploit")

    if not os.path.exists(repo_path):
        try:
            subprocess.run(["git", "clone", repo_url, repo_path], text=True, check=True, timeout=300)
            print(f"Cloned routersploit into {repo_path}.")
        except subprocess.CalledProcessError as e:
            print(f"Failed to clone routersploit: {e}")
            return
        except subprocess.TimeoutExpired:
            print("Cloning routersploit timed out.")
            return

    # Install routersploit
    os.chdir(repo_path)
    print("Installing routersploit...")
    subprocess.run(["python3", "setup.py", "install"], check=True)
    print("routersploit installed successfully.")

def install_cerbrutus(home_dir):
    print("Installing cerbrutus...")
    repo_url = "https://github.com/Cerbrutus-BruteForcer/cerbrutus"
    repo_path = os.path.join(home_dir, "cerbrutus")

    if not os.path.exists(repo_path):
        try:
            subprocess.run(["git", "clone", repo_url, repo_path], text=True, check=True, timeout=300)
            print(f"Cloned cerbrutus into {repo_path}.")
        except subprocess.CalledProcessError as e:
            print(f"Failed to clone cerbrutus: {e}")
            return
        except subprocess.TimeoutExpired:
            print("Cloning cerbrutus timed out.")
            return

    # Check if requirements.txt exists and install
    requirements_path = os.path.join(repo_path, "requirements.txt")
    if os.path.exists(requirements_path):
        try:
            # Install cerbrutus dependencies
            subprocess.run(["pip3", "install", "-r", requirements_path], check=True)
            print("cerbrutus installed successfully.")
        except subprocess.CalledProcessError as e:
            print(f"Failed to install cerbrutus: {e}")
    else:
        print(f"Error: requirements.txt not found in {repo_path}. Please check the installation method for cerbrutus.")

# Main setup function
def main():
    print("Setting up tools...")

    # Get the home directory based on the current user
    home_dir = os.environ.get('HOME', '/home/default_user')  # Default fallback if HOME is not set

    # Ensure the home directory exists
    if not os.path.exists(home_dir):
        os.makedirs(home_dir)

    # Install Python modules
    install_python_modules()

    # Install Golang
    install_golang()

    # Install Netcat
    install_netcat()

    # Install Airgeddon
    install_airgeddon()

    # Install tracepath
    install_tracepath()

    # Install asnmap
    install_asnmap(home_dir)

    # Install g2l
    install_g2l(home_dir)

    # Install routersploit
    install_routersploit(home_dir)

    # Install cerbrutus
    install_cerbrutus(home_dir)

    print(f"Setup complete! All tools are installed in the directory: {home_dir}.")

if __name__ == "__main__":
    main()
