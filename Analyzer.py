import re
import sys
import json
import csv
from collections import Counter
import matplotlib.pyplot as plt

# Get filename from command line
filename = sys.argv[1] if len(sys.argv) > 1 else "logs/sample.log"

print("Analyzing logs...\n")

ip_list = []
usernames = []

errors = 0
warnings = 0

# Read logs
with open(filename, "r") as file:
    logs = file.readlines()

# Process logs
for line in logs:

    line = line.strip()

    print("Processing:", line)

    # Count errors
    if "ERROR" in line:
        errors += 1

    # Count warnings
    if "WARNING" in line:
        warnings += 1

    # Process failed login attempts
    if "Failed password" in line:

        # Extract IP
        ip_match = re.findall(
            r'\d+\.\d+\.\d+\.\d+',
            line
        )

        # Extract username
        user_match = re.findall(
            r'for (\w+) from',
            line
        )

        if ip_match:
            ip_list.extend(ip_match)

        if user_match:
            usernames.extend(user_match)

# Count IP frequency
ip_frequency = Counter(ip_list)

# Count username frequency
user_frequency = Counter(usernames)

threat_data = []

for ip, attempts in ip_frequency.items():

    if attempts > 5:
        severity = "HIGH"
        attack_type = "Brute Force"

    elif attempts >= 3:
        severity = "MEDIUM"
        attack_type = "Suspicious Activity"

    else:
        severity = "LOW"
        attack_type = "Normal"

    threat_data.append({

        "ip": ip,
        "attempts": attempts,
        "severity": severity,
        "attack_type": attack_type

    })

# Sort attackers by frequency
threat_data.sort(
    key=lambda x: x["attempts"],
    reverse=True
)

# Generate text report
with open("report.txt", "w") as report:

    report.write(
        "===== Linux Security Report =====\n\n"
    )

    report.write(
        f"Total Logs: {len(logs)}\n"
    )

    report.write(
        f"Errors: {errors}\n"
    )

    report.write(
        f"Warnings: {warnings}\n\n"
    )

    report.write(
        "Top Attackers:\n"
    )

    for item in threat_data:

        report.write(

            f"{item['ip']} | "
            f"{item['attempts']} attempts | "
            f"{item['severity']} | "
            f"{item['attack_type']}\n"

        )

    report.write("\n")

    report.write(
        "Targeted Usernames:\n"
    )

    for user,count in user_frequency.items():

        report.write(
            f"{user} : {count}\n"
        )

# Generate JSON report
with open("report.json", "w") as report:

    json.dump(
        threat_data,
        report,
        indent=4
    )

# Generate CSV report
with open(
    "report.csv",
    "w",
    newline=""
) as report:

    writer = csv.writer(report)

    writer.writerow(
        [
            "IP Address",
            "Attempts",
            "Severity",
            "Attack Type"
        ]
    )

    for item in threat_data:

        writer.writerow(
            [
                item["ip"],
                item["attempts"],
                item["severity"],
                item["attack_type"]
            ]
        )

# Generate graph
if threat_data:

    ips = [
        x["ip"]
        for x in threat_data
    ]

    attempts = [
        x["attempts"]
        for x in threat_data
    ]

    plt.figure(figsize=(10,5))

    plt.bar(
        ips,
        attempts
    )

    plt.xlabel(
        "IP Address"
    )

    plt.ylabel(
        "Failed Attempts"
    )

    plt.title(
        "Attack Attempts by IP"
    )

    plt.xticks(rotation=20)

    plt.tight_layout()

    plt.savefig(
    "static/attack_graph.png")
    
    plt.close()

print("\nReports generated successfully.")
print("TXT, JSON, CSV and Graph files created.")