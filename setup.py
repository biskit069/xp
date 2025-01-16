import os
import subprocess
import sys
import shutil  # Ensure shutil is imported

# Function to install system packages
def install_system_packages():
    packages = [
        "airgeddon",
        "iputils-tracepath",
        "python3-poetry",  # Installing poetry via apt
        "golang",  # Ensure Go is installed for asnmap installation
    ]
    
    for package in packages:
        print(f"Installing {package}...")
        subprocess.run(["sudo", "apt", "install", "-y", package])

# Function to install asnmap using Go
def install_asnmap():
    print("Installing asnmap...")
    subprocess.run(["go", "install", "github.com/projectdiscovery/asnmap/cmd/asnmap@latest"])

# Function to clone the GitHub repositories
def clone_git_repositories():
    repos = [
        ("https://github.com/Cerbrutus-BruteForcer/cerbrutus", "cerbrutus"),
        ("https://github.com/calebstewart/pwncat", "pwncat"),
        ("https://github.com/threat9/routersploit", "routersploit"),
    ]
    
    for repo_url, repo_name in repos:
        print(f"Cloning {repo_name}...")
        subprocess.run(["git", "clone", repo_url])
        setup_repo(repo_name)

# Function to run setup commands for the repositories
def setup_repo(repo_name):
    repo_path = os.path.join(os.getcwd(), repo_name)
    
    # Check if there's a setup.py or other setup instructions
    setup_path = os.path.join(repo_path, "setup.py")
    if os.path.exists(setup_path):
        print(f"Running setup for {repo_name}...")
        subprocess.run([sys.executable, setup_path])

    # Additional setup if required (e.g., poetry, dependencies)
    if repo_name == "pwncat":
        subprocess.run(["poetry", "install"], cwd=repo_path)

    # Handle setup for routersploit
    if repo_name == "routersploit":
        print(f"Setting up {repo_name}...")
        # Routersploit might need additional dependencies (installing them)
        subprocess.run([sys.executable, "-m", "pip", "install", "-r", os.path.join(repo_path, "requirements.txt")])

# Function to add the tools to the PATH (for global usage)
def add_tools_to_path():
    home_dir = os.path.expanduser("~")
    tools_dir = os.path.join(home_dir, "tools")
    
    if not os.path.exists(tools_dir):
        os.mkdir(tools_dir)
    
    # Move the cloned tools to the tools directory
    for tool in ["cerbrutus", "pwncat", "routersploit"]:
        tool_path = os.path.join(os.getcwd(), tool)
        if os.path.exists(tool_path):
            shutil.move(tool_path, tools_dir)

    # Add tools directory to PATH in .bashrc
    bashrc_path = os.path.join(home_dir, ".bashrc")
    with open(bashrc_path, "a") as bashrc:
        bashrc.write(f"\n# Added tools directory to PATH\n")
        bashrc.write(f"export PATH=\"$PATH:{tools_dir}\"\n")

    # Source .bashrc to apply changes
    subprocess.run(["source", bashrc_path], shell=True)

# Function to install required Python packages
def install_python_packages():
    print("Installing required Python packages...")
    subprocess.run([sys.executable, "-m", "pip", "install", "colorama", "requests"])

# Main function to run all setup steps
def main():
    print("Setting up your environment...")
    
    # Install system packages
    install_system_packages()

    # Install asnmap via Go
    install_asnmap()

    # Clone git repositories
    clone_git_repositories()

    # Install Python packages
    install_python_packages()

    # Add tools to PATH
    add_tools_to_path()

    print("Setup complete! Please restart your terminal for the changes to take effect.")

if __name__ == "__main__":
    main()
