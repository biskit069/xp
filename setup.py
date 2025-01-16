import subprocess
import os

# Function to install pwncat and pwncat-cs
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

    # Install pwncat-cs in the pwncat directory
    print("Installing pwncat-cs...")
    result = subprocess.run(["pip", "install", "pwncat-cs"], cwd=repo_path, text=True, capture_output=True)
    if result.returncode == 0:
        print("pwncat-cs installed successfully.")
    else:
        print(f"Failed to install pwncat-cs: {result.stderr}")

    # Install distutils module via apt (for Ubuntu-based systems)
    print("Installing distutils module...")
    result = subprocess.run(["sudo", "apt", "install", "-y", "python3-distutils"], text=True, capture_output=True)
    if result.returncode == 0:
        print("distutils installed successfully.")
    else:
        print(f"Failed to install distutils: {result.stderr}")

    # Install dependencies with poetry in the pwncat directory
    result = subprocess.run(["poetry", "install"], cwd=repo_path, text=True, capture_output=True)
    if result.returncode == 0:
        print("pwncat dependencies installed successfully.")
    else:
        print(f"Failed to install pwncat dependencies: {result.stderr}")
