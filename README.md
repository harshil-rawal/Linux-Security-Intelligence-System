# Linux Security Intelligence & Intrusion Detection System

This project is a Python-based security monitoring system that analyzes Linux authentication logs and identifies suspicious login activity. It processes log files, detects repeated failed login attempts, classifies threats based on severity, and generates reports with visual insights.

The project was built to explore cybersecurity concepts such as intrusion detection, log analysis, and threat monitoring in a practical way.

## Features

- Detects failed login attempts
- Extracts IP addresses using Regex
- Identifies targeted usernames
- Classifies threat severity (Low / Medium / High)
- Detects suspicious login behavior
- Generates TXT, JSON, and CSV reports
- Creates attack visualization graphs
- Displays results using a Flask dashboard

---

## Tech Stack

**Language**
- Python

**Libraries**
- Flask
- Matplotlib
- Regex (`re`)
- JSON
- CSV
- Collections (`Counter`)

**Concepts Used**
- Log Analysis
- Intrusion Detection
- Threat Classification
- Cybersecurity Monitoring

---

## Project Structure

```text
Linux_log_Analyzer/

├── logs/
│   └── sample.log

├── static/
│   └── attack_graph.png

├── templates/
│   └── index.html

├── Analyzer.py
├── dashboard.py
├── README.md
├── requirements.txt
```

## Installation

Clone the repository:

```bash
git clone https://github.com/harshil-rawal/Linux-Security-Intelligence-System.git
```

Move into the project folder:

```bash
cd Linux-Security-Intelligence-System
```

Install dependencies:

```bash
pip install -r requirements.txt
```

---

## Running the Project

Run the analyzer:

```bash
python Analyzer.py
```

Run the dashboard:

```bash
python dashboard.py
```

Open in browser:

```text
http://127.0.0.1:5000
```

---

## Output Files

The system generates:

- report.txt
- report.json
- report.csv
- attack_graph.png

---

## Threat Detection Logic

- More than 5 attempts → High severity
- 3–5 attempts → Medium severity
- Less than 3 attempts → Low severity

---

## Future Improvements

Some improvements I plan to add:

- Real-time log monitoring
- Email alerts for high-risk activity
- IP geolocation tracking
- More advanced threat analysis

---

## Author

Harshil Rawal
