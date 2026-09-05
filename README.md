<img width="1536" height="1024" alt="Splunk" src="https://github.com/user-attachments/assets/1d90ac72-a755-48d2-9bec-4b551aaa3797" />

# ++++++++++ Splunk-query-assistant ++++++++++
A Python-based SOC analyst tool that recommends Splunk SPL queries based on attack types and maps detections to MITRE ATT&amp;CK techniques.

## Installation

Clone the repository:

```bash
git clone https://github.com/amedrouabhi33/splunk-query-assistant.git
cd splunk-query-assistant

Create a virtual environment:

python3 -m venv .venv
source .venv/bin/activate

Install the required dependencies:

python -m pip install -r requirements.txt
Usage

Start the Splunk Query Assistant:

python main.py
Available Commands
1-110 — Open a Splunk query by number
search — Search the query library
keywords — Display common search keywords
list — Display the full query library
exit — Exit the application

You can also search directly by typing keywords such as:

powershell
ssh
rdp
brute force
dns
sql
ransomware
phishing
lateral movement

Then commit everything:

```bash
git add .
git commit -m "Update installation and usage documentation"
git push origin main
