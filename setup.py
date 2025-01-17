import os
import subprocess
import shutil
import sys

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
        subprocess.run(["go", "install", "github.com/projectdiscovery/asnmap/cmd/asnmap@latest"], text=True, check=True, timeout=300)
        asnmap_binary = shutil.which("asnmap")
        if asnmap_binary:
            target_path = os.path.join(home_dir, "asnmap")
            shutil.copy(asnmap_binary, target_path)
            print(f"asnmap binary copied to {target_path}.")
        else:
            print("asnmap binary not found after installation.")
    except subprocess.CalledProcessError as e:
        print(f"Failed to install asnmap: {e}")
    except subprocess.TimeoutExpired:
        print("asnmap installation timed out.")

# Function to install pwncat from GitHub
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
    try:
        subprocess.run(["pip", "install", "pwncat-cs"], text=True, check=True, timeout=300)
        subprocess.run(["pip", "install", "-r", "requirements.txt"], text=True, check=True, timeout=300)
        subprocess.run(["poetry", "install"], text=True, check=True, timeout=300)
        print("pwncat installed successfully.")
    except subprocess.CalledProcessError as e:
        print(f"Failed to install pwncat: {e}")
    except subprocess.TimeoutExpired:
        print("pwncat installation timed out.")

# Function to clone repositories and run their setup
def setup_repository(repo_url, repo_name, setup_command=None, target_dir=None):
    print(f"Cloning {repo_name}...")
    clone_path = target_dir if target_dir else os.getcwd()
    repo_path = os.path.join(clone_path, repo_name)

    if not os.path.exists(repo_path):
        try:
            subprocess.run(["git", "clone", repo_url, repo_path], text=True, check=True, timeout=300)
            print(f"Cloned {repo_name} into {repo_path}.")
            if setup_command:
                subprocess.run(setup_command, cwd=repo_path, shell=True, text=True, check=True, timeout=300)
                print(f"{repo_name} setup completed successfully.")
        except subprocess.CalledProcessError as e:
            print(f"Failed to clone or set up {repo_name}: {e}")
        except subprocess.TimeoutExpired:
            print(f"{repo_name} cloning or setup timed out.")
    else:
        print(f"{repo_name} already exists in {repo_path}. Skipping clone.")

# Function to install routersploit
def install_routersploit(home_dir):
    print("Installing routersploit...")
    repo_url = "https://github.com/threat9/routersploit"
    setup_repository(repo_url, "routersploit", "python3 setup.py install", home_dir)

# Function to install cerbrutus
def install_cerbrutus(home_dir):
    print("Installing cerbrutus...")
    repo_url = "https://github.com/Cerbrutus-BruteForcer/cerbrutus"
    setup_repository(repo_url, "cerbrutus", None, home_dir)

# Function to install g2l
def install_g2l(home_dir):
    print("Installing g2l...")
    repo_url = "https://github.com/biskit069/g2l"
    setup_repository(repo_url, "g2l", "python3 setup.py install", home_dir)

# Function to add tools to PATH
def add_tools_to_path(home_dir):
    bashrc_path = os.path.expanduser("~/.bashrc")

    with open(bashrc_path, "a") as bashrc:
        bashrc.write(f"\n# Add tools to PATH\n")
        bashrc.write(f"export PATH=\"$PATH:{home_dir}\"\n")

    print(f"Tools directory {home_dir} added to PATH. Please restart your terminal for changes to take effect.")

# Main setup function
def main():
    print("Starting setup...")

    # Install golang first
    if not install_golang():
        print("golang installation failed. Exiting setup.")
        sys.exit(1)

    # Get the home directory based on the current user
    home_dir = os.path.expanduser(f"/home/{os.getlogin()}")

    # Ensure the home directory exists
    os.makedirs(home_dir, exist_ok=True)

    # Install tools
    install_asnmap(home_dir)
    install_pwncat(home_dir)
    install_routersploit(home_dir)
    install_cerbrutus(home_dir)
    install_g2l(home_dir)

    # Add tools to PATH
    add_tools_to_path(home_dir)

    print(f"Setup complete! All tools are installed in the directory: {home_dir}.")

if __name__ == "__main__":
    main()
