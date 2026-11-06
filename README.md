# Hack Secure – Blue Team Task 3

A controlled Blue Team security assessment using a local DVWA lab, Docker, Wireshark, web-server logs, and Python-based log analysis.

## Repository contents

| Item | Description |
|---|---|
| `Blue_Team_Task_Report_Final_report.pdf` | Final assessment report |
| `DVWA-master hack secure task.zip` | Local DVWA lab project archive |
| `Archive.zip` | Supporting evidence archive |
| `detect_task3.py` | Python script for pattern-based web-log analysis |
| `task3_sample_rules.txt` | Illustrative detection rules; not executed SIEM/Suricata rules |
| `report/README.md` | Report folder notes |

## Running the Python log analysis

1. Keep `detect_task3.py` and `dvwa_task3_logs.txt` in the same directory.
2. Run:

```bash
python3 detect_task3.py
```

3. The script writes `task3_detection_alerts.txt`.

The script uses pattern matching. Its alerts indicate suspicious test patterns in the supplied lab logs; they do not independently prove successful exploitation or represent a dedicated SIEM deployment.

## Scope and limitations

- Testing was performed in a local DVWA lab.
- Python-based log analysis was used as a lightweight detection approach.
- Wazuh/Splunk and Suricata rules are not claimed as deployed or executed.
- Review and redact sensitive information in logs, screenshots, and the PDF before sharing publicly.

## Author

Kalla Kushwanth
