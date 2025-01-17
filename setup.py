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

# Function to install airgeddon using apt
def install_airgeddon():
    print("Installing airgeddon...")
    try:
        subprocess.run(["sudo", "apt", "update"], check=True, text=True)
        subprocess.run(["sudo", "apt", "install", "-y", "airgeddon"], check=True, text=True)
        print("airgeddon installed successfully.")
    except subprocess.CalledProcessError as e:
        print(f"Failed to install airgeddon: {e}")

# Function to install pwncat from GitHub and set up virtual environment
def install_pwncat(home_dir):
    print("Installing pwncat...")
    repo_url = "https://github.com/calebstewart/pwncat"
    repo_path = os.path.join(home_dir, "pwncat")

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

    # Install system-wide python3-poetry to ensure poetry is available
    print("Installing python3-poetry...")
    subprocess.run(["sudo", "apt", "install", "-y", "python3-poetry"], check=True)

    # Create and activate virtual environment
    print("Setting up virtual environment for pwncat...")
    subprocess.run(["python3", "-m", "venv", "pwncat-env"], check=True)
    print("Virtual environment created successfully.")

    # Activate virtual environment and install dependencies
    print("Activating virtual environment and installing pwncat-cs...")
    subprocess.run([os.path.join("pwncat-env", "bin", "pip"), "install", "pwncat-cs"], check=True)

    # Install poetry inside the virtual environment
    print("Installing poetry in the virtual environment...")
    subprocess.run([os.path.join("pwncat-env", "bin", "pip"), "install", "poetry"], check=True)

    # Run poetry lock --no-update in the pwncat directory (not in pwncat-env)
    print("Running poetry lock --no-update in the pwncat directory...")
    subprocess.run([os.path.join("pwncat-env", "bin", "poetry"), "lock", "--no-update"], cwd=repo_path, check=True)

    # Now run poetry install in the pwncat directory
    subprocess.run([os.path.join("pwncat-env", "bin", "poetry"), "install"], cwd=repo_path, check=True)

    print("pwncat setup completed.")


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

# Function to install routersploit
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

# Function to install cerbrutus
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

    # Install cerbrutus
    os.chdir(repo_path)
    print("Installing cerbrutus...")
    subprocess.run(["python3", "setup.py", "install"], check=True)
    print("cerbrutus installed successfully.")

# Main setup function
def main():
    print("Setting up tools...")

    # Get the home directory based on the current user
    home_dir = os.path.expanduser(f"/home/{os.getlogin()}")

    # Ensure the home directory exists
    if not os.path.exists(home_dir):
        os.makedirs(home_dir)

    # Install golang
    if not install_golang():
        return

    # Install asnmap
    install_asnmap(home_dir)

    # Install airgeddon
    install_airgeddon()

    # Install pwncat and its dependencies
    install_pwncat(home_dir)

    # Install g2l
    install_g2l(home_dir)

    # Install routersploit
    install_routersploit(home_dir)

    # Install cerbrutus
    install_cerbrutus(home_dir)

    print(f"Setup complete! All tools are installed in the directory: {home_dir}.")

if __name__ == "__main__":
    main()
