import tkinter as tk
from tkinter import scrolledtext, filedialog, messagebox
import nmap
import paramiko
import threading
import time
import socket

# Default File Paths
open_ports_file = "open_ports.txt"
successful_logins_file = "successful_logins.txt"

class SSHScannerApp:
    def __init__(self, master):
        self.master = master
        self.master.title("Multi-Port Scanner and Login Tool")
        self.master.geometry("900x800")
        self.master.configure(bg="#246EE9")  # Royal Blue background

        # State Flags for Scanning and Login Processes
        self.stop_scan_flag = False
        self.stop_login_flag = False

        # Styling
        self.default_font = ("Arial", 10)
        self.header_font = ("Arial", 12, "bold")
        self.button_bg = "#1ABC9C"
        self.button_fg = "#FFFFFF"

        # IP Scanning Section
        self.scan_frame = tk.LabelFrame(master, text="IP Scanning", padx=10, pady=10, bg="#246EE9", fg="#FFFFFF", font=self.header_font)
        self.scan_frame.pack(fill="both", padx=10, pady=5)

        # IP Address Input
        self.ip_label = tk.Label(self.scan_frame, text="Enter IP Addresses (comma-separated):", bg="#246EE9", fg="#FFFFFF", font=self.default_font)
        self.ip_label.grid(row=0, column=0, sticky="w")
        self.ip_entry = tk.Entry(self.scan_frame, width=60)
        self.ip_entry.grid(row=0, column=1, pady=5)
        self.load_ip_button = tk.Button(self.scan_frame, text="Load IPs", command=self.load_ips, bg=self.button_bg, fg=self.button_fg)
        self.load_ip_button.grid(row=0, column=2, padx=5)

        # Port Number Input
        self.port_label = tk.Label(self.scan_frame, text="Enter Ports (comma-separated, default SSH=22):", bg="#246EE9", fg="#FFFFFF", font=self.default_font)
        self.port_label.grid(row=1, column=0, sticky="w")
        self.port_entry = tk.Entry(self.scan_frame, width=60)
        self.port_entry.insert(0, "22")  # Default port SSH
        self.port_entry.grid(row=1, column=1, pady=5)

        self.scan_button = tk.Button(self.scan_frame, text="Scan for Open Ports", command=self.start_scan, bg=self.button_bg, fg=self.button_fg)
        self.scan_button.grid(row=2, column=0, pady=10)

        self.stop_scan_button = tk.Button(self.scan_frame, text="Stop Scan", command=self.stop_scan, bg="#E74C3C", fg="#FFFFFF")
        self.stop_scan_button.grid(row=2, column=1, pady=10)

        # Save Path Input
        self.save_label = tk.Label(self.scan_frame, text="Save Open Ports File Path:", bg="#246EE9", fg="#FFFFFF", font=self.default_font)
        self.save_label.grid(row=3, column=0, sticky="w")
        self.save_entry = tk.Entry(self.scan_frame, width=60)
        self.save_entry.insert(0, open_ports_file)  # Default save path
        self.save_entry.grid(row=3, column=1, pady=5)

        # Login Attempt Section
        self.login_frame = tk.LabelFrame(master, text="Login Attempts", padx=10, pady=10, bg="#246EE9", fg="#FFFFFF", font=self.header_font)
        self.login_frame.pack(fill="both", padx=10, pady=5)

        # Username Input
        self.username_label = tk.Label(self.login_frame, text="Enter Usernames (comma-separated):", bg="#246EE9", fg="#FFFFFF", font=self.default_font)
        self.username_label.grid(row=0, column=0, sticky="w")
        self.username_entry = tk.Entry(self.login_frame, width=60)
        self.username_entry.grid(row=0, column=1, pady=5)
        self.load_username_button = tk.Button(self.login_frame, text="Load Usernames", command=self.load_usernames, bg=self.button_bg, fg=self.button_fg)
        self.load_username_button.grid(row=0, column=2, padx=5)

        # Passwords Input
        self.passwords_label = tk.Label(self.login_frame, text="Enter Passwords (comma-separated):", bg="#246EE9", fg="#FFFFFF", font=self.default_font)
        self.passwords_label.grid(row=1, column=0, sticky="w")
        self.passwords_entry = tk.Entry(self.login_frame, width=60)
        self.passwords_entry.grid(row=1, column=1, pady=5)
        self.load_password_button = tk.Button(self.login_frame, text="Load Passwords", command=self.load_passwords, bg=self.button_bg, fg=self.button_fg)
        self.load_password_button.grid(row=1, column=2, padx=5)

        # Successful Logins File Path
        self.success_label = tk.Label(self.login_frame, text="Save Successful Logins File Path:", bg="#246EE9", fg="#FFFFFF", font=self.default_font)
        self.success_label.grid(row=2, column=0, sticky="w")
        self.success_entry = tk.Entry(self.login_frame, width=60)
        self.success_entry.insert(0, successful_logins_file)  # Default save path
        self.success_entry.grid(row=2, column=1, pady=5)

        self.login_button = tk.Button(self.login_frame, text="Attempt Logins", command=self.start_login, bg=self.button_bg, fg=self.button_fg)
        self.login_button.grid(row=3, column=0, pady=10)

        self.stop_login_button = tk.Button(self.login_frame, text="Stop Attempt Login", command=self.stop_login, bg="#E74C3C", fg="#FFFFFF")
        self.stop_login_button.grid(row=3, column=1, pady=10)

        # Log Output Area
        self.log_area = scrolledtext.ScrolledText(master, width=100, height=20, bg="#FFFFFF", fg="#2C3E50", font=self.default_font)
        self.log_area.pack(padx=10, pady=10)

    def log(self, message):
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        self.log_area.insert(tk.END, f"[{timestamp}] {message}\n")
        self.log_area.yview(tk.END)  # Scroll to the end

    def start_scan(self):
        self.stop_scan_flag = False
        threading.Thread(target=self.scan_ports, daemon=True).start()

    def scan_ports(self):
        ip_list = self.ip_entry.get().split(',')
        ports = self.port_entry.get().split(',')
        scanner = nmap.PortScanner()
        open_ports = []

        self.log("Starting port scan...")
        for ip in ip_list:
            if self.stop_scan_flag:
                self.log("Port scan stopped.")
                return
            ip = ip.strip()
            for port in ports:
                if self.stop_scan_flag:
                    self.log("Port scan stopped.")
                    return
                port = port.strip()
                try:
                    scanner.scan(ip, port)
                    if ip in scanner.all_hosts() and scanner[ip].has_tcp(int(port)) and scanner[ip]['tcp'][int(port)]['state'] == 'open':
                        open_ports.append((ip, port))
                        self.log(f"Open port {port} found on {ip}")
                except Exception as e:
                    self.log(f"Error scanning {ip}:{port} - {str(e)}")

        save_path = self.save_entry.get()
        with open(save_path, 'w') as f:
            for ip, port in open_ports:
                f.write(f"{ip}:{port}\n")

        self.log(f"Scan complete. Results saved to {save_path}.")

    def stop_scan(self):
        self.stop_scan_flag = True

    def start_login(self):
        self.stop_login_flag = False
        threading.Thread(target=self.attempt_login, daemon=True).start()

    def attempt_login(self):
        save_path = self.save_entry.get()
        success_path = self.success_entry.get()

        try:
            with open(save_path, 'r') as f:
                open_ports = [line.strip().split(':') for line in f.readlines()]
        except FileNotFoundError:
            messagebox.showerror("Error", "Open ports file not found. Please scan first.")
            return

        usernames = self.username_entry.get().split(',')
        passwords = self.passwords_entry.get().split(',')

        self.log("Starting login attempts...")
        for ip, port in open_ports:
            if self.stop_login_flag:
                self.log("Login attempts stopped.")
                return
            for username in usernames:
                if self.stop_login_flag:
                    self.log("Login attempts stopped.")
                    return
                for password in passwords:
                    if self.stop_login_flag:
                        self.log("Login attempts stopped.")
                        return
                    username = username.strip()
                    password = password.strip()
                    self.log(f"Trying {ip}:{port} with username '{username}' and password '{password}'")
                    if self.try_login(ip, int(port), username, password):
                        self.log(f"Successful login on {ip}:{port} with username '{username}' and password '{password}'")
                        with open(success_path, 'a') as f:
                            f.write(f"{ip}:{port}, Username: {username}, Password: {password}\n")
                        return
                    else:
                        self.log(f"Failed login on {ip}:{port} with username '{username}' and password '{password}'")

    def stop_login(self):
        self.stop_login_flag = True

    def try_login(self, ip, port, username, password):
        try:
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(ip, port=port, username=username, password=password, timeout=5)
            ssh.close()
            return True
        except (paramiko.AuthenticationException, paramiko.SSHException, socket.error):
            return False

    def load_ips(self):
        file_path = filedialog.askopenfilename(title="Select IPs File", filetypes=[("Text Files", "*.txt")])
        if file_path:
            with open(file_path, 'r') as file:
                ips = file.read().strip()
                self.ip_entry.delete(0, tk.END)
                self.ip_entry.insert(0, ips)

    def load_usernames(self):
        file_path = filedialog.askopenfilename(title="Select Usernames File", filetypes=[("Text Files", "*.txt")])
        if file_path:
            with open(file_path, 'r') as file:
                usernames = file.read().strip()
                self.username_entry.delete(0, tk.END)
                self.username_entry.insert(0, usernames)

    def load_passwords(self):
        file_path = filedialog.askopenfilename(title="Select Passwords File", filetypes=[("Text Files", "*.txt")])
        if file_path:
            with open(file_path, 'r') as file:
                passwords = file.read().strip()
                self.passwords_entry.delete(0, tk.END)
                self.passwords_entry.insert(0, passwords)

# Run the application
if __name__ == "__main__":
    root = tk.Tk()
    app = SSHScannerApp(root)
    root.mainloop()
