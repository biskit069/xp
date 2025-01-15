from setuptools import setup, find_packages
import os
import subprocess

# Read the requirements.txt file if it exists
requirements_file = "requirements.txt"
if os.path.exists(requirements_file):
    with open(requirements_file, "r") as f:
        requirements = f.read().splitlines()
else:
    requirements = []

# Additional dependencies to install (Python packages)
additional_requirements = [
    "subfinder",
    "asnmap",
    "pwncat",
    "airgeddon",
    "tracepath",
    "sslscan",
    "nmap",
    "netdiscover",
    "routersploit",
]

# Merge with the ones from requirements.txt
requirements.extend(additional_requirements)

# Custom function to install external tools
def install_tools():
    tools = [
        "subfinder",
        "asnmap",
        "pwncat",
        "airgeddon",
        "tracepath",
        "sslscan",
        "nmap",
        "netdiscover",
        "routersploit",
    ]
    
    for tool in tools:
        try:
            subprocess.check_call([f"sudo", "apt", "install", "-y", tool])  # Install using apt (for Linux)
        except subprocess.CalledProcessError:
            print(f"Error installing {tool}, it may need to be installed manually.")

# Call the install_tools function after installation
install_tools()

setup(
    name="kraken",
    version="0.1",
    description="network kit",
    author="biskit",
    url="https://github.com/biskit069/kraken",
    packages=find_packages(),
    py_modules=["xp"],
    install_requires=requirements,
    entry_points={
        "console_scripts": [
            "xp= xp:main_menu",  # Allows running `xp` to start the main menu
        ]
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.6",
)
