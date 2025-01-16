import os
import subprocess
import sys
import shutil

# Function to install system dependencies
def install_system_packages():
    packages = [
        "airgeddon",
        "iputils-tracepath",
        "python3-venv",  # Added venv for pwncat
        "golang"
    ]

    for package in packages:
        print(f"Installing {package}...")
        subprocess.run(["sudo", "apt", "install", "-y", package], check=True)

# Function to install asnmap via Go and copy to the desired directory
def install_asnmap():
    print("Installing asnmap...")
    subprocess.run(["go", "install", "github.com/projectdiscovery/asnmap/cmd/asnmap@latest"], check=True)

    # Move the binary to the script's directory
    asnmap_binary = shutil.which("asnmap")
    if asnmap_binary:
        shutil.copy(asnmap_binary, os.getcwd())
        print("asnmap installed and copied to the current directory.")

# Function to clone repositories and run their setup
def setup_repository(repo_url, repo_name, setup_command=None):
    print(f"Cloning {repo_name}...")
    subprocess.run(["git", "clone", repo_url], check=True)

    repo_path = os.path.join(os.getcwd(), repo_name)
    if setup_command:
        print(f"Setting up {repo_name}...")
        subprocess.run(setup_command, cwd=repo_path, shell=True, check=True)

# Function to install pwncat
def install_pwncat():
    print("Installing pwncat...")
    # Create a virtual environment for pwncat
    venv_dir = os.path.join(os.getcwd(), "pwncat-env")
    subprocess.run(["python3", "-m", "venv", venv_dir], check=True)

    # Activate the virtual environment and install pwncat-cs
    activate_script = os.path.join(venv_dir, "bin", "activate")
    subprocess.run(["bash", "-c", f"source {activate_script} && pip install pwncat-cs"], shell=True, check=True)
    print("pwncat installed in virtual environment.")

# Function to install routersploit
def install_routersploit():
    print("Installing routersploit...")
    repo_url = "https://github.com/threat9/routersploit"
    setup_repository(repo_url, "routersploit", "python3 setup.py install")

# Function to install cerbrutus
def install_cerbrutus():
    print("Installing cerbrutus...")
    repo_url = "https://github.com/Cerbrutus-BruteForcer/cerbrutus"
    setup_repository(repo_url, "cerbrutus")

# Function to add tools to PATH
def add_tools_to_path():
    script_dir = os.getcwd()
    bashrc_path = os.path.expanduser("~/.bashrc")

    with open(bashrc_path, "a") as bashrc:
        bashrc.write(f"\n# Add tools to PATH\n")
        bashrc.write(f"export PATH=\"$PATH:{script_dir}\"\n")

    print("Tools directory added to PATH. Please restart your terminal for changes to take effect.")

# Main setup function
def main():
    print("Setting up tools...")

    # Install system dependencies
    install_system_packages()

    # Install asnmap
    install_asnmap()

    # Install other tools
    install_pwncat()
    install_routersploit()
    install_cerbrutus()

    # Add tools to PATH
    add_tools_to_path()

    print("Setup complete! All tools are installed in the current directory.")

if __name__ == "__main__":
    main()
