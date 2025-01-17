import os
import subprocess
import shutil

# Function to install Go
def install_go():
    print("Checking if Go is installed...")
    result = subprocess.run(["go", "version"], text=True, capture_output=True)
    if result.returncode == 0:
        print("Go is already installed.")
    else:
        print("Go is not installed. Installing Go...")
        go_download_url = "https://go.dev/dl/go1.20.7.linux-amd64.tar.gz"  # Update URL for the latest version if needed
        go_tarball = "/tmp/go.tar.gz"
        go_install_dir = "/usr/local"

        try:
            # Download Go tarball
            subprocess.run(["wget", "-O", go_tarball, go_download_url], check=True)
            print("Downloaded Go tarball.")

            # Remove any previous Go installation
            subprocess.run(["sudo", "rm", "-rf", f"{go_install_dir}/go"], check=True)

            # Extract and install Go
            subprocess.run(["sudo", "tar", "-C", go_install_dir, "-xzf", go_tarball], check=True)
            print("Go installed successfully.")

            # Add Go to PATH
            bashrc_path = os.path.expanduser("~/.bashrc")
            with open(bashrc_path, "a") as bashrc:
                bashrc.write("\n# Add Go to PATH\n")
                bashrc.write(f"export PATH=\"$PATH:{go_install_dir}/go/bin\"\n")

            print("Go has been added to PATH. Please restart your terminal or run 'source ~/.bashrc'.")
        except subprocess.CalledProcessError as e:
            print(f"Failed to install Go: {e}")
            return False

    return True

# Function to install asnmap via Go and copy to the desired directory
def install_asnmap(home_dir):
    print("Installing asnmap...")
    result = subprocess.run(["go", "install", "github.com/projectdiscovery/asnmap/cmd/asnmap@latest"], text=True, capture_output=True)
    if result.returncode == 0:
        print("asnmap installed successfully.")
        asnmap_binary = shutil.which("asnmap")
        if asnmap_binary:
            target_path = os.path.join(home_dir, "asnmap")
            shutil.copy(asnmap_binary, target_path)
            print(f"asnmap binary copied to {target_path}.")
        else:
            print("asnmap binary not found after installation.")
    else:
        print(f"Failed to install asnmap: {result.stderr}")

# Function to install pwncat from GitHub
def install_pwncat(home_dir):
    print("Installing pwncat...")
    repo_url = "https://github.com/calebstewart/pwncat"
    repo_path = os.path.join(home_dir, "pwncat")

    if not os.path.exists(repo_path):
        subprocess.run(["git", "clone", repo_url, repo_path], text=True)
        print(f"Cloned pwncat into {repo_path}.")

    os.chdir(repo_path)
    subprocess.run(["pip", "install", "pwncat-cs"], text=True)
    subprocess.run(["pip", "install", "-r", "requirements.txt"], text=True)
    subprocess.run(["poetry", "install"], text=True)

# Other tool installation functions (routersploit, cerbrutus, g2l) as defined earlier...

# Main setup function
def main():
    print("Setting up tools...")

    # Install Go first
    if not install_go():
        print("Failed to install Go. Exiting setup.")
        return

    # Get the home directory based on the current user
    home_dir = os.path.expanduser(f"/home/{os.getlogin()}")

    # Ensure the home directory exists
    os.makedirs(home_dir, exist_ok=True)

    # Install tools
    install_asnmap(home_dir)
    install_pwncat(home_dir)
    # Add other tool installation calls here...

    print(f"Setup complete! All tools are installed in the directory: {home_dir}.")

if __name__ == "__main__":
    main()
