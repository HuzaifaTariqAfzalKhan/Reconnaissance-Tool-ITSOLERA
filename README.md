# Custom Recon Tool

It is a simple tool created using python which performs the following required features. It can be used for both Active and Passive Recon as well as it also reports the findings. It was built as part of a cybersecurity internship program at ITSOLERA.
1. Passive Recon: 
 WHOIS lookup 
 DNS enumeration (A, MX, TXT, NS records) 
 Subdomain enumeration using external APIs (e.g., crt.sh, AlienVault OTX, etc.) 
2. Active Recon: 
 Port scanning (via Nmap) 
 Banner grabbing 
 Detecting technologies (e.g., using whatweb, wappalyzer APIs) 
3. Reporting: 
 Generate a summary report in .txt or .html format with all gathered  information.
 Include timestamps and IP resolution details. 


## Usage Tutorial 
First of all open the terminal in linux then write this command:

--->git clone https://github.com/HuzaifaTariqAfzalKhan/Reconnaissance-Tool-ITSOLERA.git
Then we would install the requirements needed for the tool by using this command:
--->pip install -r requirements.txt
After that we would install the dependencies for the nmap by this command :
--->sudo apt install nmap
Bonus steps for the docker by using these commands:
--->docker build -t Reconnaissance-Tool-ITSOLERA
--->docker run -it Reconnaissance-Tool-ITSOLERA
Now after doing all of the steps except docker , you can also skip these steps if you have already installed all of the requirement dependencies then you can change the directory to the recon tool by this command:
--->cd Reconnaissance-Tool
Inside the directory you would write this command to run the tool
--->python tool.py
After using the functions you would press the last option which would create a new directory inside it which would contain a report consisting of the data you wanted to search.
--->cd reports/
Then you would open the report file by this command:
--->cat report-filename.txt

