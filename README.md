# Seclog
SecLog is a GUI-based Windows Event Log analyzer built with Python, Tkinter (ttkbootstrap), and matplotlib. It supports real-time monitoring, event filtering, user-role access, visual dashboards, CSV export, and theme customization. Ideal for system admins and forensic analysis.

# 🔐 Seclog – Windows Security Log Analyzer

Seclog is a Python-based GUI tool for analyzing Windows Event Logs in real time. It includes role-based login, search, filtering, visualization, export features, and is packaged for standalone use with PyInstaller and Inno Setup.

---

## 🚀 Features

- 🔒 Role-based login (admin/user)
- 📋 View Security, System, and Application logs
- 🔍 Search and filter logs by keyword, date, or event ID
- 🧠 Highlight critical events (e.g., 4624, 4625)
- 📊 Visual dashboards for login attempts and event trends
- ⏱ Real-time monitoring every few seconds
- 💾 Save/load filters (JSON)
- 📤 Export logs to CSV
- 🎨 Dark-themed modern UI using `ttkbootstrap`
- 🛠 Buildable as standalone `.exe` and installable via Inno Setup

---

## 🗂 Project Structure
LogKit/

├── .venv/ # Virtual environment

├── build/ # PyInstaller build artifacts

├── dist/ # Distribution-ready .exe

├── output/ # Installer or export outputs

├── SecLog.py # Main application

├── SecLog.spec # PyInstaller spec file

├── secLog_installer.iss # Inno Setup script

├── secLog_icon.ico # App icon


---

## 🧰 Requirements

- Windows OS
- Python 3.9+
- Python packages:
  - `ttkbootstrap`
  - `pywin32`
  - `matplotlib`

Install with:


pip install -r requirements.txt

Run Locally
 
python SecLog.py


Build Executable

pyinstaller --onefile --windowed SecLog.spec

