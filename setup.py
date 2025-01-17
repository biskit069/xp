import os
import subprocess

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

# Function to install ASNMap
def install_asnmap(home_dir):
    print("Installing asnmap...")
    try:
        go_path = os.path.join(home_dir, "go")
        os.environ["GOPATH"] = go_path
        os.environ["GOBIN"] = os.path.join(go_path, "bin")
        os.environ["PATH"] += f":{os.environ['GOBIN']}"  # Add GOBIN to PATH

        os.makedirs(go_path, exist_ok=True)
        subprocess.run(["go", "install", "github.com/projectdiscovery/asnmap/cmd/asnmap@latest"], text=True, check=True, timeout=300)
        print("asnmap installed successfully.")

        asnmap_binary = os.path.join(go_path, "bin", "asnmap")
        if os.path.exists(asnmap_binary):
            subprocess.run(["cp", asnmap_binary, "/home/host"], check=True)
            print("asnmap binary copied to /home/host.")
        else:
            print("asnmap binary not found in GOPATH bin directory.")

        subprocess.run(f"chmod +x {asnmap_binary}", shell=True)
        print("asnmap is now executable and available in the PATH.")
    except subprocess.CalledProcessError as e:
        print(f"Failed to install asnmap: {e}")
    except subprocess.TimeoutExpired:
        print("asnmap installation timed out.")
    except Exception as e:
        print(f"An unexpected error occurred while installing asnmap: {e}")

# Function to install pwncat
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

    os.chdir(repo_path)

    print("Creating virtual environment in pwncat directory...")
    try:
        subprocess.run(["python3", "-m", "venv", "pwncat-env"], check=True)
        print("Virtual environment created successfully.")
    except subprocess.CalledProcessError as e:
        print(f"Failed to create virtual environment: {e}")
        return

    activate_script = os.path.join(repo_path, "pwncat-env", "bin", "activate")
    try:
        subprocess.run(f"source {activate_script}", shell=True, check=True)
        subprocess.run(["pip", "install", "pwncat-cs"], check=True)
        print("pwncat-cs installed successfully.")
    except subprocess.CalledProcessError as e:
        print(f"Failed to install pwncat-cs: {e}")
        return

    print("pwncat setup completed successfully.")

# Function to install Netdiscover
def install_netdiscover():
    print("Installing netdiscover...")
    try:
        subprocess.run(["sudo", "apt", "install", "-y", "netdiscover"], check=True, text=True)
        print("netdiscover installed successfully.")
    except subprocess.CalledProcessError as e:
        print(f"Failed to install netdiscover: {e}")

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

    # Install ASNMap
    install_asnmap(home_dir)

    # Install pwncat
    install_pwncat(home_dir)

    # Install Netdiscover
    install_netdiscover()

    print(f"Setup complete! All tools are installed in the directory: {home_dir}.")

if __name__ == "__main__":
    main()
