from setuptools import setup, find_packages

setup(
    name='magic',
    version='0.1',
    description='A powerful tool for scanning and network diagnostics',
    author='biskit069',
    author_email='your-email@example.com',
    url='https://github.com/biskit069/magic',
    packages=find_packages(),
    install_requires=[
        'colorama',  # for colored output
    ],
    entry_points={
        'console_scripts': [
            'magic = magic.main:main_menu',  # Assumes your main function is inside a file named 'main.py' within the 'magic' directory
        ],
    },
    classifiers=[
        'Programming Language :: Python :: 3',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
    ],
    python_requires='>=3.6',
)
