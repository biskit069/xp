from setuptools import setup  
  
setup(  
   name='your_project_name',  
   version='0.1',  
   author='Your Name',  
   author_email='your_email@example.com',  
   description='A brief description of your project',  
   long_description='A longer description of your project',  
   url='https://github.com/your_username/your_project_name',  
   packages=['your_package_name'],  
   install_requires=[  
      'colorama',  
      'subprocess',  
      'platform',  
      'ipaddress',  
      're',  
      'os',  
      'time',  
      'signal',  
      'threading'  
   ],  
   classifiers=[  
      'Development Status :: 3 - Alpha',  
      'Intended Audience :: Developers',  
      'License :: OSI Approved :: MIT License',  
      'Programming Language :: Python :: 3',  
      'Programming Language :: Python :: 3.6',  
      'Programming Language :: Python :: 3.7',  
      'Programming Language :: Python :: 3.8',  
   ],  
)
