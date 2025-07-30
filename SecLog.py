import ttkbootstrap as ttk 
from ttkbootstrap.constants import *
from tkinter import LEFT, messagebox, scrolledtext
import win32evtlog
import pywintypes
from datetime import datetime
from collections import defaultdict, Counter
import matplotlib.pyplot as plt
import json
import threading
import time
from tkinter.filedialog import asksaveasfilename

# ----------------- User Credentials and Role Access ------------------
USER_CREDENTIALS = {
    "admin": {"password": "admin123", "role": "admin"},
    "user": {"password": "user123", "role": "user"}
}

ROLE_EVENT_VISIBILITY = {
    "admin": set(),
    "user": {4624}  # Only hiding specific events for users
}

current_user_role = None

# ----------------- Event ID Highlighting ------------------
HIGHLIGHT_EVENT_IDS = {
    4625: "#ffcccc",  # Failed login
    4624: "#ccffcc"   # Successful login
}

# ----------------- Login Window ------------------
def show_login():
    login_window = ttk.Toplevel(root)
    login_window.title("Login")

    ttk.Label(login_window, text="Username:").grid(row=0, column=0)
    username_entry = ttk.Entry(login_window)
    username_entry.grid(row=0, column=1)

    ttk.Label(login_window, text="Password:").grid(row=1, column=0)
    password_entry = ttk.Entry(login_window, show='*')
    password_entry.grid(row=1, column=1)

    def attempt_login():
        global current_user_role
        username = username_entry.get()
        password = password_entry.get()
        user = USER_CREDENTIALS.get(username)
        if user and user['password'] == password:
            current_user_role = user['role']
            login_window.destroy()
            root.deiconify()
        else:
            messagebox.showerror("Login Failed", "Invalid credentials")

    ttk.Button(login_window, text="Login", command=attempt_login).grid(row=2, columnspan=2)
    root.withdraw()
    login_window.mainloop()

# ----------------- Fetching Event Logs ------------------
def fetch_logs(log_type="Security", start_date=None, end_date=None):
    logs = []
    try:
        hand = win32evtlog.OpenEventLog("localhost", log_type)
        flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
        events = win32evtlog.ReadEventLog(hand, flags, 0)

        while events:
            for ev_obj in events:
                try:
                    event_time = ev_obj.TimeGenerated
                    if start_date and event_time < start_date:
                        continue
                    if end_date and event_time > end_date:
                        continue
                    event_id = ev_obj.EventID & 0xFFFF
                    if current_user_role == "user" and event_id in ROLE_EVENT_VISIBILITY["user"]:
                        continue
                    log_entry = {
                        "Time": event_time.Format(),
                        "Source": str(ev_obj.SourceName),
                        "Event ID": event_id,
                        "Category": ev_obj.EventCategory,
                        "Message": str(ev_obj.StringInserts)
                    }
                    logs.append(log_entry)
                except Exception:
                    continue
            events = win32evtlog.ReadEventLog(hand, flags, 0)
        win32evtlog.CloseEventLog(hand)
    except pywintypes.error as e:
        messagebox.showerror("Permission Error", f"Error: {e}\nTry running as Administrator.")
    return logs

# ----------------- UI Layout and Functionality ------------------
root = ttk.Window(themename="cyborg")
root.title("Windows Security Log Analyzer")
root.geometry("1050x900")

frame = ttk.Frame(root)
frame.pack(pady=10)

search_frame = ttk.Frame(root)
search_frame.pack()

search_label = ttk.Label(search_frame, text="Search:")
search_label.pack(side=LEFT)

search_entry = ttk.Entry(search_frame, width=40)
search_entry.pack(side=LEFT, padx=5)

log_type_frame = ttk.Frame(root)
log_type_frame.pack(pady=5)

log_type_label = ttk.Label(log_type_frame, text="Log Type:")
log_type_label.pack(side=LEFT)

log_type_var = ttk.StringVar()
log_type_options = ["Security", "System", "Application"]
if log_type_var.get() not in log_type_options:
    log_type_var.set("Security")
log_type_dropdown = ttk.OptionMenu(log_type_frame, log_type_var, log_type_var.get(), *log_type_options)
log_type_dropdown.pack(side=LEFT, padx=5)

date_filter_frame = ttk.Frame(root)
date_filter_frame.pack(pady=5)

ttk.Label(date_filter_frame, text="Start Date (YYYY-MM-DD):").pack(side=LEFT)
start_date_entry = ttk.Entry(date_filter_frame, width=12)
start_date_entry.pack(side=LEFT, padx=5)

ttk.Label(date_filter_frame, text="End Date (YYYY-MM-DD):").pack(side=LEFT)
end_date_entry = ttk.Entry(date_filter_frame, width=12)
end_date_entry.pack(side=LEFT, padx=5)

# ----------------- Log Display ------------------
text_area = scrolledtext.ScrolledText(root, width=115, height=28)
text_area.pack(pady=10)

all_filtered_logs = []
real_time_monitoring = False

# ----------------- Core Functions ------------------

def display_logs():
    global all_filtered_logs
    try:
        start_date = datetime.strptime(start_date_entry.get(), "%Y-%m-%d") if start_date_entry.get() else None
        end_date = datetime.strptime(end_date_entry.get(), "%Y-%m-%d") if end_date_entry.get() else None
    except ValueError:
        messagebox.showerror("Date Error", "Invalid date format. Use YYYY-MM-DD.")
        return
    all_filtered_logs = fetch_logs(log_type_var.get(), start_date, end_date)
    update_log_display(all_filtered_logs)

def update_log_display(logs):
    text_area.delete(1.0, "end")
    for log in logs:
        color = HIGHLIGHT_EVENT_IDS.get(log["Event ID"], None)
        start_index = text_area.index("insert")
        text_area.insert("end", f"ID: {log['Event ID']} | Time: {log['Time']} | Source: {log['Source']}\n")
        end_index = text_area.index("insert")
        if color:
            tag_name = f"highlight_{log['Event ID']}_{start_index}"
            text_area.tag_add(tag_name, start_index, end_index)
            text_area.tag_config(tag_name, background=color)

def search_logs():
    keyword = search_entry.get().lower()
    results = [log for log in all_filtered_logs if keyword in str(log).lower()]
    update_log_display(results)

def toggle_real_time():
    global real_time_monitoring
    real_time_monitoring = not real_time_monitoring
    if real_time_monitoring:
        threading.Thread(target=real_time_loop, daemon=True).start()
        btn_realtime.config(text="⏹ Stop Real-Time")
    else:
        btn_realtime.config(text="🔁 Start Real-Time")

def real_time_loop():
    while real_time_monitoring:
        display_logs()
        time.sleep(5)

def on_log_click(event):
    index = text_area.index(f"@{event.x},{event.y}")
    line = text_area.get(index + " linestart", index + " lineend")
    if "ID:" in line:
        log_id = int(line.split("ID:")[1].split("|")[0].strip())
        for log in all_filtered_logs:
            if log["Event ID"] == log_id:
                messagebox.showinfo("Log Details", json.dumps(log, indent=4))
                break

def reset_filters():
    search_entry.delete(0, "end")
    start_date_entry.delete(0, "end")
    end_date_entry.delete(0, "end")
    log_type_var.set("Security")
    text_area.delete(1.0, "end")
    all_filtered_logs.clear()

def save_filters():
    filters = {
        "log_type": log_type_var.get(),
        "start_date": start_date_entry.get(),
        "end_date": end_date_entry.get(),
        "keyword": search_entry.get()
    }
    with open("filters.json", "w") as f:
        json.dump(filters, f)
    messagebox.showinfo("Saved", "Filters saved to filters.json")

def load_filters():
    try:
        with open("filters.json", "r") as f:
            filters = json.load(f)
            log_type_var.set(filters.get("log_type", "Security"))
            start_date_entry.delete(0, "end")
            start_date_entry.insert(0, filters.get("start_date", ""))
            end_date_entry.delete(0, "end")
            end_date_entry.insert(0, filters.get("end_date", ""))
            search_entry.delete(0, "end")
            search_entry.insert(0, filters.get("keyword", ""))
            display_logs()
    except Exception as e:
        messagebox.showerror("Error", f"Failed to load filters: {e}")

def export_logs():
    if not all_filtered_logs:
        messagebox.showinfo("No Logs", "No logs to export.")
        return
    filepath = asksaveasfilename(defaultextension=".csv", filetypes=[("CSV Files", "*.csv")])
    if filepath:
        try:
            with open(filepath, "w", encoding="utf-8") as f:
                f.write("Time,Source,Event ID,Category,Message\n")
                for log in all_filtered_logs:
                    # Handle None or special characters gracefully
                    message = str(log.get("Message", "")).replace('\n', ' ').replace('\r', ' ')
                    f.write(f"{log['Time']},{log['Source']},{log['Event ID']},{log['Category']},{message}\n")
            messagebox.showinfo("Success", f"Logs exported to {filepath}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to export logs: {e}")


def login_attempts_dashboard():
    user_attempts = defaultdict(int)
    for log in all_filtered_logs:
        if log["Event ID"] == 4625:
            user = log["Source"]
            user_attempts[user] += 1

    if not user_attempts:
        messagebox.showinfo("Info", "No failed login attempts found.")
        return

    users = list(user_attempts.keys())
    attempts = list(user_attempts.values())

    plt.figure(figsize=(10, 5))
    plt.bar(users, attempts, color='red')
    plt.xlabel("Users")
    plt.ylabel("Failed Login Attempts")
    plt.title("Failed Login Attempts per User")
    plt.xticks(rotation=45)
    plt.tight_layout()
    plt.show()

def summary_view():
    total_logs = len(all_filtered_logs)
    failed_logins = len([log for log in all_filtered_logs if log["Event ID"] == 4625])
    messagebox.showinfo("Summary", f"Total Logs: {total_logs}\nFailed Logins: {failed_logins}")

def event_graph():
    date_counts = Counter()
    for log in all_filtered_logs:
        log_date = log["Time"].split(" ")[0]
        date_counts[log_date] += 1

    dates = sorted(date_counts)
    counts = [date_counts[date] for date in dates]

    plt.figure(figsize=(10, 4))
    plt.plot(dates, counts, marker='o')
    plt.title("Event Counts Over Time")
    plt.xlabel("Date")
    plt.ylabel("Events")
    plt.xticks(rotation=45)
    plt.tight_layout()
    plt.show()

def open_settings_window():
    settings_window = ttk.Toplevel(root)
    settings_window.title("Settings ⚙️")
    settings_window.geometry("300x200")

    ttk.Label(settings_window, text="Choose Theme 🎨", font=("Segoe UI", 12)).pack(pady=10)

    style = ttk.Style()
    theme_var = ttk.StringVar(value=style.theme.name)
    themes = style.theme_names()

    theme_dropdown = ttk.OptionMenu(settings_window, theme_var, theme_var.get(), *themes)
    theme_dropdown.pack(pady=10)

    def apply_theme():
        new_theme = theme_var.get()
        style.theme_use(new_theme)

    ttk.Button(settings_window, text="✅ Apply Theme", command=apply_theme).pack(pady=10)

# ----------------- Buttons ------------------
btn_fetch = ttk.Button(frame, text="📥 Fetch Logs", command=display_logs)
btn_fetch.pack(side=LEFT, padx=5)

btn_search = ttk.Button(frame, text="🔍 Search Logs", command=search_logs)
btn_search.pack(side=LEFT, padx=5)

btn_dashboard = ttk.Button(frame, text="📊 Login Dashboard", command=login_attempts_dashboard)
btn_dashboard.pack(side=LEFT, padx=5)

btn_summary = ttk.Button(frame, text="📋 Summary View", command=summary_view)
btn_summary.pack(side=LEFT, padx=5)

btn_graph = ttk.Button(frame, text="📈 Event Graph", command=event_graph)
btn_graph.pack(side=LEFT, padx=5)

btn_export = ttk.Button(frame, text="📤 Export to CSV", command=export_logs)
btn_export.pack(side=LEFT, padx=5)

btn_reset = ttk.Button(frame, text="🔄 Reset Filters", command=reset_filters)
btn_reset.pack(side=LEFT, padx=5)

btn_save = ttk.Button(frame, text="💾 Save Filters", command=save_filters)
btn_save.pack(side=LEFT, padx=5)

btn_load = ttk.Button(frame, text="📂 Load Filters", command=load_filters)
btn_load.pack(side=LEFT, padx=5)

btn_realtime = ttk.Button(frame, text="🔁 Start Real-Time", command=toggle_real_time)
btn_realtime.pack(side=LEFT, padx=5)

btn_settings = ttk.Button(frame, text="⚙️ Settings", command=open_settings_window)
btn_settings.pack(side=LEFT, padx=5)

# ----------------- Main ------------------
text_area.bind("<Button-1>", on_log_click)
show_login()
root.mainloop()
