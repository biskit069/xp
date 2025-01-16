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
        "python3-poetry",  # Added poetry for pwncat
        "golang"
    ]

    for package in packages:
        print(f"Installing {package}...")
        result = subprocess.run(["sudo", "apt", "install", "-y", package], text=True, capture_output=True)
        if result.returncode == 0:
            print(f"{package} installed successfully.")
        else:
            print(f"Failed to install {package}: {result.stderr}")

# Function to install pwncat
def install_pwncat(home_dir):
    print("Installing pwncat...")
    repo_url = "https://github.com/calebstewart/pwncat"
    repo_path = os.path.join(home_dir, "pwncat")

    # Clone the pwncat repository
    if not os.path.exists(repo_path):
        result = subprocess.run(["git", "clone", repo_url, repo_path], text=True, capture_output=True)
        if result.returncode != 0:
            print(f"Failed to clone pwncat: {result.stderr}")
            return
        print(f"Cloned pwncat into {repo_path}.")

    # Install dependencies with poetry in the pwncat directory
    result = subprocess.run(["poetry", "install"], cwd=repo_path, text=True, capture_output=True)
    if result.returncode == 0:
        print("pwncat dependencies installed successfully.")
    else:
        print(f"Failed to install pwncat dependencies: {result.stderr}")

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
    
    print(f"Setup complete! All tools are installed in the directory: {home_dir}.")

if __name__ == "__main__":
    main()
