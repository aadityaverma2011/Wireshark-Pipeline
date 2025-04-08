import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import pyshark
import math
from datetime import datetime
import pandas as pd
from collections import defaultdict
from scipy.stats import entropy
import nest_asyncio
import threading
import requests

nest_asyncio.apply()

# ---------- Packet feature helpers ----------
def calculate_entropy(data):
    value_counts = pd.Series(data).value_counts(normalize=True)
    return entropy(value_counts, base=2)

def process_pcap(file_path, update_progress, interval=30):
    packet_count = sum(1 for _ in pyshark.FileCapture(file_path, keep_packets=False))
    capture = pyshark.FileCapture(file_path, keep_packets=False)
    flows = defaultdict(list)

    processed = 0
    for packet in capture:
        try:
            timestamp = float(packet.sniff_timestamp)
            src_ip = packet.ip.src if hasattr(packet, 'ip') else "NA"
            dst_ip = packet.ip.dst if hasattr(packet, 'ip') else "NA"
            src_port = packet[packet.transport_layer].srcport if hasattr(packet, 'transport_layer') else "NA"
            dst_port = packet[packet.transport_layer].dstport if hasattr(packet, 'transport_layer') else "NA"
            src_mac = packet.eth.src if hasattr(packet, 'eth') else "NA"
            dst_mac = packet.eth.dst if hasattr(packet, 'eth') else "NA"
            packet_size = int(packet.length)

            flow_key = (src_ip, dst_ip, src_port, dst_port, src_mac, dst_mac)
            flows[flow_key].append((timestamp, packet_size))
        except AttributeError:
            continue

        processed += 1
        update_progress(int((processed / packet_count) * 100))

    capture.close()

    start_time = min(min(ts for ts, _ in packets) for packets in flows.values())
    grouped_flows = defaultdict(list)

    for flow_key, packets in flows.items():
        for timestamp, packet_size in packets:
            group_id = math.floor((timestamp - float(start_time)) / interval)
            grouped_flows[group_id].append((flow_key, timestamp, packet_size))

    results = []
    for group, group_packets in grouped_flows.items():
        group_start_time = float(start_time) + group * interval
        group_end_time = float(start_time) + (group + 1) * interval

        durations = []
        total_packets = 0
        src_ports = []
        dst_ports = []

        for flow_key, timestamp, packet_size in group_packets:
            _, _, src_port, dst_port, _, _ = flow_key
            durations.append(packet_size)
            total_packets += 1
            if src_port != "NA":
                src_ports.append(src_port)
            if dst_port != "NA":
                dst_ports.append(dst_port)

        results.append({
            "Group ID": group,
            "Start Time": datetime.fromtimestamp(group_start_time).strftime('%Y-%m-%d %H:%M:%S'),
            "End Time": datetime.fromtimestamp(group_end_time).strftime('%Y-%m-%d %H:%M:%S'),
            "Maximum Duration": max(durations) if durations else 0,
            "Mean Duration": sum(durations) / len(durations) if durations else 0,
            "Standard Deviation": pd.Series(durations).std() if durations else 0,
            "Total Duration": sum(durations),
            "Total Packets": total_packets,
            "Rate": total_packets / interval if interval > 0 else 0,
            "Unique Source Ports": len(set(src_ports)),
            "Unique Destination Ports": len(set(dst_ports)),
            "Total Source Ports": len(src_ports),
            "Total Destination Ports": len(dst_ports),
            "Source Port Entropy": calculate_entropy(src_ports) if src_ports else 0,
            "Destination Port Entropy": calculate_entropy(dst_ports) if dst_ports else 0,
            "Entropy Difference": (calculate_entropy(src_ports) - calculate_entropy(dst_ports)) if src_ports and dst_ports else 0,
            "Total Flows": len(set(flow_key for flow_key, _, _ in group_packets))
        })

    return pd.DataFrame(results)

# ---------- GUI Functions ----------
def run_analysis(filepath):
    def update_progress(value):
        progress_var.set(value)
        progress_bar.update_idletasks()
        progress_label.config(text=f"Processing... {value}% complete" if value < 100 else "Done!")

    try:
        df = process_pcap(filepath, update_progress)
        df.to_csv("flow_features.csv", index=False)
        messagebox.showinfo("Success", "Flow feature CSV saved as 'flow_features.csv'!")

        # Show preview window
        preview_window = tk.Toplevel(root)
        preview_window.title("Preview - flow_features.csv")
        tree = ttk.Treeview(preview_window)
        tree["columns"] = list(df.columns)
        tree["show"] = "headings"

        for col in df.columns:
            tree.heading(col, text=col)
            tree.column(col, anchor="center", width=100)

        for _, row in df.head(10).iterrows():
            tree.insert("", "end", values=list(row))

        tree.pack(expand=True, fill="both")

    except Exception as e:
        messagebox.showerror("Error", f"Something went wrong:\n{str(e)}")
    finally:
        progress_var.set(0)
        progress_label.config(text="Waiting for file...")

def select_pcap():
    filepath = filedialog.askopenfilename(filetypes=[("PCAPNG files", "*.pcapng")])
    if filepath:
        threading.Thread(target=run_analysis, args=(filepath,), daemon=True).start()

def select_csv():
    filepath = filedialog.askopenfilename(filetypes=[("CSV files", "*.csv")])
    if filepath:
        threading.Thread(target=send_csv_to_server, args=(filepath,), daemon=True).start()

def send_csv_to_server(filepath):
    try:
        with open(filepath, 'rb') as f:
            files = {'file': (filepath, f, 'text/csv')}
            response = requests.post("http://localhost:5000/train", files=files)

        if response.status_code == 200:
            result = response.json()
            messagebox.showinfo("Model Training Success", f"Accuracy: {result['accuracy']}\nModel saved as 'new.pkl'")
        else:
            error = response.json().get("error", "Unknown error occurred.")
            messagebox.showerror("Server Error", error)
    except Exception as e:
        messagebox.showerror("Error", f"Failed to send file to server:\n{str(e)}")

# ---------- GUI Setup ----------
root = tk.Tk()
root.title("PCAP Feature Extractor & CSV Trainer")
root.geometry("500x250")
root.resizable(False, False)

frame = tk.Frame(root)
frame.place(relx=0.5, rely=0.4, anchor="center")

btn_pcap = tk.Button(frame, text="Select Wireshark", command=select_pcap, font=("Helvetica", 14), width=15)
btn_pcap.grid(row=0, column=0, padx=10)

btn_csv = tk.Button(frame, text="Select CSV", command=select_csv, font=("Helvetica", 14), width=15)
btn_csv.grid(row=0, column=1, padx=10)

progress_label = tk.Label(root, text="Waiting for file...", font=("Helvetica", 10))
progress_label.place(relx=0.5, rely=0.63, anchor="center")

progress_var = tk.IntVar()
progress_bar = ttk.Progressbar(root, variable=progress_var, maximum=100, length=400)
progress_bar.place(relx=0.5, rely=0.7, anchor="center")

root.mainloop()
