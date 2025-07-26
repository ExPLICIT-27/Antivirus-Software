# 🛡️ Antivirus Software

A simple yet powerful desktop antivirus application with a modern GUI (Tkinter + ttkbootstrap) and a YARA-powered malware scanning engine built in C.

---

## 📌 Features

- 🔍 Scan individual files or entire directories for malware
- 🧠 Uses [YARA](https://virustotal.github.io/yara/) rules to detect threats
- 🖼️ Modern and responsive UI with ttkbootstrap (theme: `vapor`)
- 🧰 File/Directory toggle for flexible scanning
- 📄 Real-time scan results displayed in the UI
- 📊 Summary of infected and clean files after each scan

---

---

## 💻 How It Works

### Python GUI (`gui.py`)
- Built using `tkinter` + `ttkbootstrap` for the user interface.
- Allows users to select either a **file** or a **directory**.
- On clicking **Upload**, it runs the compiled `engine` executable using `subprocess`, passing the selected path as an argument.
- The result of the scan is displayed in a scrollable text area.

### C Engine (`engine.c`)
- Uses the **YARA** library to scan the file(s) with compiled `.yar` rules.
- Recursively walks directories and checks all files.
- Produces detailed output:
  - Matched rule name
  - Clean/infected status
  - Summary of all scanned/infected/clean files

---

## 🚀 Getting Started

### 🔧 Requirements

#### Python
- Python 3.8+
- ttkbootstrap

### install dependencies (ubuntu)
sudo apt install libyara-dev yara
gcc engine.c -o engine -lyara
Add yara rules
rules/
├── malware_rule1.yar
├── trojan.yar
└── ransomware.yar

python gui.py


