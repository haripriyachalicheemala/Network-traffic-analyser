import os
os.environ["SCAPY_NO_SERVICE_CACHE"] = "true"
# I am importing tkinter because I need to make a window for the program
import tkinter as tk

# This is for a text box that can scroll if there's too much text
from tkinter import scrolledtext

# This is for showing message boxes like warnings
from tkinter import messagebox

# ttk is needed for table (Treeview)
from tkinter import ttk

# I need json but wait, in the original code it's not used much, maybe I can skip it? But original has it, perhaps for something, I'll keep it
import json

# For making charts, matplotlib is good for plots
import matplotlib.pyplot as plt

# This helps put the chart inside the tkinter window
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg

# Counter to count things like how many times something happens
from collections import Counter

# Threading to run monitoring without freezing the window
import threading

# This is my other file where the network monitoring code is
from network_monitor import NetworkMonitor


# Making a class for the GUI, like the main part of the program
class TrafficGUI:
    # This is the start function, it sets up the window
    def __init__(self, root):
        self.root = root  # Saving the main window
        self.root.title("Network Traffic Analyzer")  # Giving the window a title
        self.root.geometry("1000x700")  # Making the window this size
        
        self.monitor = NetworkMonitor()  # Creating the monitor object from my other file
        self.is_monitoring = False  # A flag to know if monitoring is on, starting as off
        
        self.create_widgets()  # Calling my function to make the buttons and stuff
    
    # Function to make all the buttons and text areas
    def create_widgets(self):
        # Making a frame for the top controls, like a box
        control_frame = tk.Frame(self.root, bg="#2c3e50", height=80)
        control_frame.pack(fill=tk.X, padx=10, pady=10)
        
        # Button to start monitoring
        self.start_btn = tk.Button(
            control_frame,
            text="START",
            command=self.start_monitor,
            bg="#27ae60",
            fg="white",
            font=("Arial", 12, "bold"),
            width=15
        )
        self.start_btn.pack(side=tk.LEFT, padx=10, pady=10)
        
        # Button to show charts
        self.analyze_btn = tk.Button(
            control_frame,
            text="ANALYZE",
            command=self.show_charts,
            bg="#3498db",
            fg="white",
            font=("Arial", 12, "bold"),
            width=15
        )
        self.analyze_btn.pack(side=tk.LEFT, padx=10, pady=10)
        
        # Label to show status like "Ready"
        self.status_label = tk.Label(
            control_frame,
            text="Ready",
            bg="#2c3e50",
            fg="white",
            font=("Arial", 11)
        )
        self.status_label.pack(side=tk.LEFT, padx=20)
        
        # Text area for showing traffic logs, with scroll
        self.traffic_text = scrolledtext.ScrolledText(
            self.root,
            font=("Courier", 9),
            height=10
        )
        self.traffic_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        # TABLE (NEW – required for Task 2)
        self.table = ttk.Treeview(
            self.root,
            columns=("Time", "Source IP", "Destination IP", "Protocol"),
            show="headings",
            height=8
        )
        
        self.table.heading("Time", text="Timestamp")
        self.table.heading("Source IP", text="Source IP")
        self.table.heading("Destination IP", text="Destination IP")
        self.table.heading("Protocol", text="Protocol")
        
        self.table.pack(fill=tk.X, padx=10, pady=5)
        
        # Frame for putting charts in
        self.chart_frame = tk.Frame(self.root)
        self.chart_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
    
    # Function for when start button is clicked
    def start_monitor(self):
        self.traffic_text.delete(1.0, tk.END)
        self.table.delete(*self.table.get_children())
        
        self.traffic_text.insert(tk.END, "Monitoring started...\n")
        self.status_label.config(text="Monitoring...")
        self.start_btn.config(state=tk.DISABLED)
        
        # Making a function inside to run in thread
        def monitor_thread():
            self.monitor = NetworkMonitor()
            self.monitor.start_monitoring(60)
            self.root.after(0, self.monitor_complete)
        
        threading.Thread(target=monitor_thread, daemon=True).start()
    
    # Function when monitoring finishes
    def monitor_complete(self):
        self.start_btn.config(state=tk.NORMAL)
        self.status_label.config(text="Complete")
        
        self.traffic_text.insert(
            tk.END,
            f"\n Captured {len(self.monitor.traffic_log)} packets\n"
        )
        
        # Show last 20 logs in text box
        for entry in self.monitor.traffic_log[-20:]:
            line = (
                f"{entry['timestamp']} | "
                f"{entry['source_ip']} → "
                f"{entry['dest_ip']} "
                f"({entry['protocol']})\n"
            )
            self.traffic_text.insert(tk.END, line)
        
        # Fill TABLE with all logs
        for entry in self.monitor.traffic_log:
            self.table.insert(
                "",
                tk.END,
                values=(
                    entry["timestamp"],
                    entry["source_ip"],
                    entry["dest_ip"],
                    entry["protocol"]
                )
            )
        
        # If there are suspicious IPs
        if self.monitor.suspicious_ips:
            self.traffic_text.insert(
                tk.END,
                f"\n Threats: {len(self.monitor.suspicious_ips)}\n"
            )
            for ip in self.monitor.suspicious_ips:
                self.traffic_text.insert(tk.END, f"  • {ip}\n")
    
    # Function for analyze button
    def show_charts(self):
        if not self.monitor.traffic_log:
            messagebox.showwarning("No Data", "Run monitoring first!")
            return
        
        # Clear old charts
        for widget in self.chart_frame.winfo_children():
            widget.destroy()
        
        fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(10, 4))
        
        # Pie chart
        protocols = [e['protocol'] for e in self.monitor.traffic_log]
        proto_counts = Counter(protocols)
        ax1.pie(
            proto_counts.values(),
            labels=proto_counts.keys(),
            autopct='%1.1f%%'
        )
        ax1.set_title('Protocol Distribution')
        
        # Bar chart
        ips = [e['source_ip'] for e in self.monitor.traffic_log]
        top_ips = Counter(ips).most_common(5)
        
        if top_ips:
            labels, values = zip(*top_ips)
            ax2.barh(labels, values, color='skyblue')
            ax2.set_title('Top 5 Source IPs')
            ax2.set_xlabel('Packet Count')
        
        canvas = FigureCanvasTkAgg(fig, self.chart_frame)
        canvas.draw()
        canvas.get_tk_widget().pack()


# If running this file directly
if __name__ == "__main__":
    root = tk.Tk()
    app = TrafficGUI(root)
    root.mainloop()
