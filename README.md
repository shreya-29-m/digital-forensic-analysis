# 🔐 Digital Forensic Analysis Tool

A cybersecurity tool that detects real-world cyber attacks like brute-force login attempts and privilege escalation using Windows Security Logs.

---

## 🎯 Why This Project?

Most log analysis tools are complex and hard to understand.

This project focuses on:
- Simple detection of real attack patterns
- Clear explanation of threats
- Easy-to-read HTML forensic reports

Even non-technical users can understand what happened in the system.

---

## ⚡ Features

- Detects failed login attempts (Brute Force)
- Identifies suspicious login patterns
- Detects privilege escalation
- Generates detailed forensic timeline
- Produces interactive HTML report

---

## 🛡 Threat Detection

This tool identifies attack patterns such as:

- Multiple failed logins → brute force attempt
- Successful login after failures → possible breach
- Admin privilege assignment → privilege escalation

---

## 📊 Sample Output (Forensic Report)

Open the sample report:

➡️ sample_report.html

---

## 🚀 How to Run

```bash
python main.py
```

Choose mode:
- demo → simulated attack
- live → real system logs

---

## 🧠 Output

- Console-based forensic analysis
- HTML report with:
  - Threat level
  - Attack summary
  - Evidence table

---

## ⚠️ Note

Live mode requires administrator privileges to access Windows Security Logs.

---

## 👩‍💻 Author

Shreya
