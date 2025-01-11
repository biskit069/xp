from setuptools import setup, find_packages
import os

# Read the requirements.txt file if it exists
requirements_file = "requirements.txt"
if os.path.exists(requirements_file):
    with open(requirements_file, "r") as f:
        requirements = f.read().splitlines()
else:
    requirements = []

setup(
    name="xp",
    version="0.1",
    description="network kit plus web tools",
    author="biskit",
    author_email="no email",  # Replace with your actual email
    url="https://github.com/biskit069/xpSpoit",
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
