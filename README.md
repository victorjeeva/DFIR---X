
# DFIR-X

## Digital Forensics and Incident Response Investigation Platform

DFIR-X is a web-based digital forensics and incident response (DFIR) project developed using Python and Flask. It helps investigators organize digital evidence, analyze security logs, identify indicators of compromise, and support incident investigations.

## Features

- Case and evidence management
- Evidence integrity verification using SHA-256
- File analysis and triage
- IOC (Indicators of Compromise) extraction
- Security log analysis
- Incident timeline generation
- Risk analysis
- Incident summary and investigation reports

## Technologies Used

- Python
- Flask
- SQLite
- HTML and CSS
- SHA-256 hashing

## Installation

Clone the repository:

```bash
git clone YOUR_REPOSITORY_URL
cd DFIR-X
```

Create a virtual environment:

```bash
python -m venv venv
```

Activate it on Kali Linux:

```bash
source venv/bin/activate
```

Install dependencies:

```bash
pip install -r requirements.txt
```

## Run the Application

```bash
python app.py
```

Open your browser and visit:

http://127.0.0.1:5000

## Project Structure

```text
DFIR-X/
├── app.py
├── requirements.txt
├── README.md
├── modules/
├── templates/
├── static/
└── screenshots/
```

## Disclaimer

This project is intended for educational purposes and authorized digital forensic investigations. Use it only with evidence and systems you are permitted to analyze.
