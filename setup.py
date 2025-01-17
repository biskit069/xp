import os
import subprocess
import shutil

# Function to install golang using apt
def install_golang():
    print("Checking if golang is installed...")
    result = subprocess.run(["go", "version"], text=True, capture_output=True)
    if result.returncode == 0:
        print("golang is already installed.")
        return True
    else:
        print("golang is not installed. Installing now...")
        try:
            subprocess.run(["sudo", "apt", "update"], check=True, text=True)
            subprocess.run(["sudo", "apt", "install", "-y", "golang"], check=True, text=True)
            print("golang installed successfully.")
            return True
        except subprocess.CalledProcessError as e:
            print(f"Failed to install golang: {e}")
            return False

def install_asnmap(home_dir):
    print("Installing asnmap...")
    try:
        # Ensure the GOPATH is set correctly
        go_path = os.path.join(home_dir, "go")
        os.environ["GOPATH"] = go_path
        os.environ["GOBIN"] = os.path.join(go_path, "bin")  # Set GOBIN for Go binary location
        os.environ["PATH"] += f":{os.environ['GOBIN']}"  # Add GOBIN to PATH

        # Create GOPATH directory if it doesn't exist
        os.makedirs(go_path, exist_ok=True)

        # Install asnmap using go install
        subprocess.run(["go", "install", "github.com/projectdiscovery/asnmap/cmd/asnmap@latest"], text=True, check=True, timeout=300)
        print("asnmap installed successfully.")

        # Find the binary and copy it to the target directory
        asnmap_binary = os.path.join(go_path, "bin", "asnmap")
        if os.path.exists(asnmap_binary):
            target_path = os.path.join(home_dir, "asnmap")
            subprocess.run(["cp", asnmap_binary, "/home/host"], check=True)  # Copy binary to /home/host
            print(f"asnmap binary copied to /home/host.")
        else:
            print("asnmap binary not found in GOPATH bin directory.")
        
        # Ensure asnmap is executable
        subprocess.run(f"chmod +x {asnmap_binary}", shell=True)
        print("asnmap is now executable and available in the PATH.")
    except subprocess.CalledProcessError as e:
        print(f"Failed to install asnmap: {e}")
    except subprocess.TimeoutExpired:
        print("asnmap installation timed out.")
    except Exception as e:
        print(f"An unexpected error occurred while installing asnmap: {e}")

def install_airgeddon():
    print("Installing airgeddon...")
    try:
        subprocess.run(["sudo", "apt", "update"], check=True, text=True)
        subprocess.run(["sudo", "apt", "install", "-y", "airgeddon"], check=True, text=True)
        print("airgeddon installed successfully.")
    except subprocess.CalledProcessError as e:
        print(f"Failed to install airgeddon: {e}")

def install_pwncat(home_dir):
    print("Installing pwncat...")
    repo_url = "https://github.com/calebstewart/pwncat"
    repo_path = os.path.join(home_dir, "pwncat")

    # Clone the pwncat repository if not already cloned
    if not os.path.exists(repo_path):
        try:
            subprocess.run(["git", "clone", repo_url, repo_path], text=True, check=True, timeout=300)
            print(f"Cloned pwncat into {repo_path}.")
        except subprocess.CalledProcessError as e:
            print(f"Failed to clone pwncat: {e}")
            return
        except subprocess.TimeoutExpired:
            print("Cloning pwncat timed out.")
            return

    # Change to pwncat directory
    os.chdir(repo_path)

    # Step 1: Create the Python virtual environment in the pwncat directory
    print("Creating virtual environment in pwncat directory...")
    try:
        subprocess.run(["python3", "-m", "venv", "pwncat-env"], check=True)
        print("Virtual environment created successfully.")
    except subprocess.CalledProcessError as e:
        print(f"Failed to create virtual environment: {e}")
        return

    # Step 2: Activate the virtual environment
    print("Activating virtual environment...")
    activate_script = os.path.join(repo_path, "pwncat-env", "bin", "activate")
    try:
        subprocess.run(f"source {activate_script}", shell=True, check=True)
        print("Virtual environment activated successfully.")
    except subprocess.CalledProcessError as e:
        print(f"Failed to activate virtual environment: {e}")
        return

    # Step 3: Install python3-poetry to ensure poetry is available
    print("Installing python3-poetry...")
    subprocess.run(["sudo", "apt", "install", "-y", "python3-poetry"], check=True)

    # Step 4: Install pwncat-cs directly in the pwncat directory
    print("Installing pwncat-cs...")
    try:
        subprocess.run(["pip", "install", "pwncat-cs", "-v"], check=True)  # Added verbose flag
        print("pwncat-cs installed successfully.")
    except subprocess.CalledProcessError as e:
        print(f"Failed to install pwncat-cs: {e}")
        return

    # Step 5: Unlock the poetry lock file by running poetry lock --no-update
    print("Unlocking poetry lock file...")
    try:
        subprocess.run(["poetry", "lock", "--no-update"], check=True)
        print("Poetry lock file unlocked successfully.")
    except subprocess.CalledProcessError as e:
        print(f"Failed to unlock poetry lock file: {e}")
        return

    # Step 6: Install dependencies using poetry in the pwncat directory
    print("Installing dependencies using poetry...")
    try:
        subprocess.run(
            ["poetry", "install", "--no-dev", "--verbose"],
            check=True,
            timeout=1200,  # Increase timeout to 20 minutes
        )
        print("Poetry install completed successfully.")
    except subprocess.CalledProcessError as e:
        print(f"Poetry install failed: {e}")
    except subprocess.TimeoutExpired:
        print("Poetry install timed out.")

    print("pwncat setup completed successfully.")

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

    os.chdir(repo_path)
    print("Creating virtual environment in routersploit directory...")
    subprocess.run(["python3", "-m", "venv", "rs-env"], check=True)

    activate_script = os.path.join(repo_path, "rs-env", "bin", "activate")
    subprocess.run(f"source {activate_script}", shell=True, check=True)

    subprocess.run(["python3", "-m", "pip", "install", "--upgrade", "pip", "setuptools"], check=True)
    subprocess.run(["python3", "-m", "pip", "install", "-r", "requirements.txt"], check=True)
    subprocess.run(["python3", "-m", "pip", "install", "."], check=True)

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

    os.chdir(repo_path)
    subprocess.run(["python3", "-m", "pip", "install", "--upgrade", "pip", "setuptools"], check=True)
    subprocess.run(["python3", "-m", "pip", "install", "-r", "requirements.txt"], check=True)
    subprocess.run(["python3", "-m", "pip", "install", "."], check=True)
    print("cerbrutus installed successfully.")
