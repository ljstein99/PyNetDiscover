# -*- coding: utf-8 -*-
"""
Created on Thu Nov  2 01:00:57 2023

@author: ljste
"""

import tkinter as tk
from tkinter import scrolledtext
from tkinter import ttk
import socket
import nmap
import requests
import threading
import datetime
import subprocess

# Function to get the manufacturer information from MAC address
def get_manufacturer(mac_address):
    try:
        response = requests.get(f"https://api.macvendors.com/{mac_address}")
        if response.status_code == 200:
            return response.text
    except Exception as e:
        pass
    return "N/A"

def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(2)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        return local_ip
    except Exception as e:
        return "N/A"

def ping_host(host):
    try:
        response = subprocess.check_output(["ping", host, "-c", "4"])  # Send 4 ICMP ping requests
        lines = response.decode("utf-8").split('\n')
        times = [float(line.split('=')[1].split(' ')[0]) for line in lines if "time=" in line]
        if times:
            return sum(times) / len(times)  # Calculate the average response time
    except Exception as e:
        pass
    return None

def scan_network():
    local_ip = get_local_ip()
    if local_ip == "N/A":
        results_text.config(state=tk.NORMAL)
        results_text.delete(1.0, tk.END)
        results_text.insert(tk.END, "Unable to determine local IP address.")
        results_text.config(state=tk.DISABLED)
        return

    nm = nmap.PortScanner()
    ip_parts = local_ip.split(".")[:-1]
    local_subnet = ".".join(ip_parts) + ".0/24"

    nm.scan(hosts=local_subnet, arguments="-O -T4 -p 1-65535")

    devices = []
    total_hosts = len(nm.all_hosts())

    for index, host in enumerate(nm.all_hosts()):
        host_info = f"IP: {host}, "

        # Check if 'mac' is available in the dictionary
        if 'mac' in nm[host]['addresses']:
            mac_address = nm[host]['addresses']['mac']
            manufacturer = get_manufacturer(mac_address)
            host_info += f"MAC: {mac_address}, Manufacturer: {manufacturer}, "

        # OS Detection
        os_info = ""
        if 'osclass' in nm[host]:
            for osclass in nm[host]['osclass']:
                os_info += f"OS Family: {osclass['osfamily']}, OS Gen: {osclass['osgen']}, "

        # Last Seen Time
        last_seen = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        host_info += f"Last Seen: {last_seen}, "

        # Network Speed (Estimation using ICMP ping)
        response_time = ping_host(host)
        if response_time is not None:
            host_info += f"Response Time: {response_time:.2f} ms, "

        # Services Running
        services_info = ""
        if 'tcp' in nm[host]:
            for port, service in nm[host]['tcp'].items():
                services_info += f"Port {port}/TCP: {service['name']}, "

        host_info += os_info + services_info
        devices.append(host_info)

        progress_percentage = (index / total_hosts) * 100
        scan_progress.set(progress_percentage)  # Update the progress bar
        progress_label.config(text=f"Scanning: {int(progress_percentage)}%")

    results_text.config(state=tk.NORMAL)
    results_text.delete(1.0, tk.END)
    results_text.insert(tk.END, "\n".join(devices))
    results_text.config(state=tk.DISABLED)
    progress_label.config(text="Scan Complete")

app = tk.Tk()
app.title("Advanced Network Device Scanner")

scan_button = tk.Button(app, text="Scan Local Network", command=lambda: threading.Thread(target=scan_network).start())
scan_button.pack()

scan_progress = tk.DoubleVar()
progress_bar = ttk.Progressbar(app, variable=scan_progress)
progress_bar.pack()

progress_label = tk.Label(app, text="", font=("Arial", 12))
progress_label.pack()

results_text = scrolledtext.ScrolledText(app, wrap=tk.WORD, state=tk.DISABLED, height=15, width=120)
results_text.pack()

app.mainloop()
