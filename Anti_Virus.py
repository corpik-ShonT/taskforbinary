import os
import requests
import time
import threading
import tkinter as tk
from tkinter import ttk, filedialog, messagebox

virus_total_api_key = "3417ee54344a98601961f5d192bc27ea391918e1417d26efaefa5933c46a3f76"

# simple logger that prints AND (if GUI is active) writes to the log box
_gui_log = None
def log(*args):
    msg = " ".join(str(a) for a in args)
    print(msg)
    if _gui_log:
        _gui_log(msg)

def iterate_files(folder_path):
    for filename in os.listdir(folder_path):
        full_path = os.path.join(folder_path, filename)
        if os.path.isdir(full_path):
            iterate_files(full_path)
        else:
            scan_file(full_path)

def scan_file(file_path):
    response = upload_file(file_path)
    scan_id = response.get('scan_id')
    if scan_id:
        is_virus = get_report(scan_id)
        if is_virus:
            log("VIRUS DETECTED!!! Filepath:", file_path)
        else:
            log(f"{file_path} is not virus")
    else:
        log("Unexpected response, no scan id found for file:", file_path)

def upload_file(file_path):
    url = 'https://www.virustotal.com/vtapi/v2/file/scan'
    params = {'apikey': virus_total_api_key}
    with open(file_path, 'rb') as file_content:
        filename = os.path.basename(file_path)
        files = {'file': (filename, file_content)}
        response = requests.post(url, files=files, params=params)
    return response.json()

def get_report(scan_id):
    log("getting report for scan id", scan_id)
    url = 'https://www.virustotal.com/vtapi/v2/file/report'
    params = {'apikey': virus_total_api_key, 'resource': scan_id}

    # loop (instead of recursion) so GUI doesn’t risk deep recursion
    while True:
        response = requests.get(url, params=params)
        if not response:
            raise Exception("Unexpected Error in response")

        if response.status_code == 200:  # Received good response
            data = response.json()
            if data.get('response_code') != 1:  # Scan not completed
                log("Scan not completed... waiting 5s")
                time.sleep(5)
                continue
            else:
                return (data.get("positives") or 0) > 0
        elif response.status_code == 204:  # No content (often rate limit)
            log("Empty response... waiting 5s")
            time.sleep(5)
            continue
        else:
            log("Received unexpected response with status code:", response.status_code)
            return False

# TKINTER GUI 

def run_scan_thread(folder, api_key, append_log, set_buttons_disabled):
    global virus_total_api_key, _gui_log
    virus_total_api_key = api_key
    _gui_log = append_log
    try:
        iterate_files(folder)
        append_log("Scan finished.")
    except Exception as e:
        append_log(f"Error: {e}")
    finally:
        set_buttons_disabled(False)

def main_gui():
    root = tk.Tk()
    root.title("Antivirus Scanner (VirusTotal)")
    root.geometry("700x500")

    # --- controls ---
    frm = ttk.Frame(root, padding=10)
    frm.pack(fill="x")

    ttk.Label(frm, text="VirusTotal API Key:").grid(row=0, column=0, sticky="w")
    api_entry = ttk.Entry(frm, width=60, show="*")
    api_entry.grid(row=0, column=1, sticky="we", padx=6)
    api_entry.insert(0, virus_total_api_key)

    ttk.Label(frm, text="Folder to scan:").grid(row=1, column=0, sticky="w", pady=(8,0))
    folder_var = tk.StringVar()
    folder_entry = ttk.Entry(frm, textvariable=folder_var, width=60)
    folder_entry.grid(row=1, column=1, sticky="we", padx=6, pady=(8,0))

    def browse():
        p = filedialog.askdirectory()
        if p:
            folder_var.set(p)

    ttk.Button(frm, text="Browse...", command=browse).grid(row=1, column=2, padx=4, pady=(8,0))
    frm.columnconfigure(1, weight=1)

    # buttons
    btns = ttk.Frame(root, padding=(10, 0))
    btns.pack(fill="x")
    start_btn = ttk.Button(btns, text="Start Scan")
    stop_info = ttk.Label(btns, text="(Close window to stop)")
    start_btn.pack(side="left", padx=(0,8))
    stop_info.pack(side="left")

    # log box
    log_frame = ttk.LabelFrame(root, text="Log", padding=10)
    log_frame.pack(fill="both", expand=True, padx=10, pady=10)
    log_text = tk.Text(log_frame, height=18)
    log_text.pack(fill="both", expand=True)

    def append_log(msg: str):
        log_text.insert(tk.END, msg + "\n")
        log_text.see(tk.END)

    def set_buttons_disabled(disabled: bool):
        state = "disabled" if disabled else "normal"
        start_btn.configure(state=state)

    # start scan
    def start():
        folder = folder_var.get().strip()
        api_key = api_entry.get().strip()
        if not api_key or api_key == "PUT_YOUR_API_KEY_HERE":
            messagebox.showwarning("API Key", "Please paste your VirusTotal API key.")
            return
        if not folder or not os.path.isdir(folder):
            messagebox.showwarning("Folder", "Please choose a valid folder.")
            return
        set_buttons_disabled(True)
        append_log(f"Starting scan for: {folder}")
        t = threading.Thread(
            target=run_scan_thread,
            args=(folder, api_key, append_log, set_buttons_disabled),
            daemon=True
        )
        t.start()

    start_btn.configure(command=start)

    root.mainloop()

# Run the GUI
if __name__ == "__main__":
    main_gui()
