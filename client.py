import os
import platform
import socket
import subprocess
import time
import tkinter as tk
from tkinter import filedialog, messagebox

from scapy.all import IP, UDP, raw, send

from encryption import calculate_hash, encrypt_data

SERVER_IP = "127.0.0.1"
SERVER_PORT = 12345
PACKET_SIZE = 16  # Fragmentation

AES_KEY = b"ThisIsASecretKey"  # 16 byte (AES-128)


def ping_latency(host="127.0.0.1", count=3):
    param = "-n" if platform.system().lower() == "windows" else "-c"
    cmd = ["ping", param, str(count), host]
    try:
        result = subprocess.run(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
        )
        output = result.stdout
        if platform.system().lower() == "windows":
            import re

            matches = re.findall(r"Average = (\d+)", output)
            return int(matches[0]) if matches else 999
        else:
            last_line = output.strip().split("\n")[-1]
            avg = last_line.split("/")[-3]
            return float(avg)
    except Exception:
        return 999  # unreachable


def calculate_ip_checksum(header_bytes):
    if len(header_bytes) % 2 == 1:
        header_bytes += b"\x00"  # padding

    checksum = 0
    for i in range(0, len(header_bytes), 2):
        word = (header_bytes[i] << 8) + header_bytes[i + 1]
        checksum += word
        checksum = (checksum & 0xFFFF) + (checksum >> 16)

    return ~checksum & 0xFFFF


def send_file(filename):
    latency = ping_latency(SERVER_IP)
    print(f"Gecikme: {latency}ms")

    if latency < 100:
        print("Dosya TCP ile gönderiliyor...")
        start_time = time.time()
        send_file_tcp(filename)
        end_time = time.time()
        rtt = (end_time - start_time) * 1000
        print(f"Manual RTT: {rtt:.2f}ms")
    else:
        print("Dosya UDP ile gönderiliyor... (yüksek gecikme)")
        start_time = time.time()
        send_file_udp(filename)
        end_time = time.time()
        rtt = (end_time - start_time) * 1000
        print(f"Manual RTT: {rtt:.2f}ms")


def send_file_tcp(filename):
    """
    Read File
    """
    with open(filename, "rb") as f:
        file_data = f.read()

    """
    Encrypt File
    """
    nonce, tag, ciphertext = encrypt_data(AES_KEY, file_data)

    """
    Merge File (Nonce + Tag + Ciphertext)
    """
    full_encrypted_data = nonce + tag + ciphertext

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((SERVER_IP, SERVER_PORT))
        s.sendall(full_encrypted_data)

    print("TCP ile dosya gönderildi.")
    print(f"Sent File Hash: {calculate_hash(file_data)}")


def send_file_udp(filename):
    """
    Read File
    """
    with open(filename, "rb") as f:
        file_data = f.read()

    """
    Encrypt File
    """
    nonce, tag, ciphertext = encrypt_data(AES_KEY, file_data)

    """
    Merge File (Nonce + Tag + Ciphertext)
    """
    full_encrypted_data = nonce + tag + ciphertext

    total_packets = (len(full_encrypted_data) + PACKET_SIZE - 1) // PACKET_SIZE
    print(f"Total packets amount: {total_packets}")

    for i in range(total_packets):
        start = i * PACKET_SIZE
        end = start + PACKET_SIZE
        chunk = full_encrypted_data[start:end]

        fragment_id = i.to_bytes(2, byteorder="big")
        payload = fragment_id + chunk

        ip_layer = IP(
            dst=SERVER_IP, ttl=64, flags="MF" if i < total_packets - 1 else 0, proto=17
        )
        udp_layer = UDP(sport=4000, dport=SERVER_PORT)
        packet = ip_layer / udp_layer / payload

        # IP Header Manual Checksum Calculation
        checksum = calculate_ip_checksum(raw(packet[IP])[:20])
        packet[IP].chksum = checksum

        send(packet, verbose=False)

    print("File sent.")
    print(f"Sent File Hash: {calculate_hash(file_data)}")


def choose_file():
    filepath = filedialog.askopenfilename()
    if filepath:
        file_path_var.set(filepath)


def btn_send():
    filepath = file_path_var.get()
    if not filepath or not os.path.isfile(filepath):
        messagebox.showwarning("Dosya hatası", "Lütfen geçerli bir dosya seçin.")
        return
    send_file(filepath)


if __name__ == "__main__":
    root = tk.Tk()
    root.title("Dosya Gönderici")

    file_path_var = tk.StringVar()

    tk.Label(root, text="Gönderilecek dosya:").pack(padx=10, pady=(10, 2))
    tk.Entry(root, textvariable=file_path_var, width=50).pack(padx=10)
    tk.Button(root, text="Dosya Seç", command=choose_file).pack(pady=(2, 10))
    tk.Button(root, text="Gönder", command=btn_send).pack(pady=(0, 10))

    root.mainloop()
