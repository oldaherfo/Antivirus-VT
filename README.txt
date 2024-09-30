# File Scanner and Virus Detection Tool

This is a simple file scanner and virus detection tool built in Python. It scans the Windows "Downloads" folder for new files, checks them against VirusTotal for potential threats, and sends email notifications for any detected malicious files.

## Features
- Scans a specified directory for new files
- Checks files against VirusTotal API for malware detection
- Sends email notifications for potentially malicious files
- Simple and lightweight

## Requirements
This project requires Python and the following libraries:
- os
- datetime
- virus_total_apis
- hashlib
- time
- smtplib
- email

## How to Use
1. Clone this repository.
2. Install the required dependencies using `pip install -r requirements.txt`.
3. Update the `email_recipient`, `from_email`, and `password` variables in the script with valid email credentials.
4. Update the `API_KEY` variable with your VirusTotal API key.
5. Execute the script.

## Program Execution
python AntivirusVT.py

You can execute this script automatically using the Windows Task Scheduler

This project was created by Oldaherfo - 2024