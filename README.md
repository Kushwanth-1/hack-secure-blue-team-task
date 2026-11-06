# Hack Secure – Blue Team Task 3

A controlled Blue Team security assessment using a local DVWA lab, Docker, Wireshark, web-server logs, and Python-based log analysis.

## Project structure

| Folder | Contents |
|---|---|
| [reports/](reports/) | Final PDF report and report notes |
| [scripts/](scripts/) | Python log-analysis script |
| [rules/](rules/) | Illustrative detection-rule descriptions |
| [lab/](lab/) | DVWA project ZIP |
| [evidence/](evidence/) | Supporting evidence archive |

## Run the Python detector

The script expects a file named `dvwa_task3_logs.txt` in the same working directory.

```bash
cd scripts
python3 detect_task3.py
```

**Important:** The repository currently does not include `dvwa_task3_logs.txt`. Add the actual exported log file to `evidence/` (or place a copy beside the script before running it). Do not create a fabricated log file.

The script writes `task3_detection_alerts.txt` in its working directory. Its matches are pattern-based indicators for analyst review; they do not independently prove successful exploitation.

## Scope and limitations

- Testing was performed in a local DVWA lab.
- Python-based log analysis was used as a lightweight detection approach.
- Wazuh/Splunk and Suricata rules are not claimed as deployed or executed.
- `rules/task3_sample_rules.txt` contains illustrative rule logic, not rules executed in a SIEM.
- Review and redact sensitive information in logs, screenshots, and the PDF before sharing publicly.

## Author

Kalla Kushwanth
