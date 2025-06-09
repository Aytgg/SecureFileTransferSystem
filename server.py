import socket
import threading
import tkinter as tk
from tkinter import messagebox

from scapy.all import IP, UDP, sniff

from encryption import calculate_hash, decrypt_data

OUTPUT_FILENAME = "received_file.txt"
AES_KEY = b"ThisIsASecretKey"

received_chunks = {}

stop_event = threading.Event()


def packet_handler(packet):
    if UDP in packet and packet[UDP].dport == 12345:
        payload = bytes(packet[UDP].payload)
        if len(payload) < 2:
            return

        fragment_id = int.from_bytes(payload[:2], byteorder="big")
        chunk_data = payload[2:]

        received_chunks[fragment_id] = chunk_data


def receive_file():
    stop_event.clear()
    received_chunks.clear()

    threading.Thread(target=receive_file_udp, daemon=True).start()
    threading.Thread(target=receive_file_tcp, daemon=True).start()

    log("Dosya bekleniyor...")


def receive_file_udp():
    print("Listening UDP... (CTRL+C to exit)")
    try:
        sniff(
            iface="lo0",
            prn=packet_handler,
            timeout=5,
            stop_filter=lambda _: stop_event.is_set(),
        )
    except KeyboardInterrupt:
        pass
    except Exception as e:
        log(f"UDP Error: {e}")
        return

    if stop_event.is_set():
        return

    if not received_chunks:
        log("No valid packets received from UDP.")
        return

    total_received = len(received_chunks)
    log(f"{total_received} packets received. Merging...")

    # Packet loss control
    expected_fragments = max(received_chunks.keys()) + 1
    missing_fragments = set(range(expected_fragments)) - set(received_chunks.keys())

    if missing_fragments:
        log(f"Missing packet IDs: {sorted(missing_fragments)}")
        return

    print("All packets received succesfully. (No packet loss)")

    ordered_fragments = [received_chunks[i] for i in sorted(received_chunks)]
    full_data = b"".join(ordered_fragments)

    if decrypt_and_save(full_data, "UDP"):
        stop_event.set()


def receive_file_tcp():
    try:
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.bind(("0.0.0.0", 12345))
        server.settimeout(1)
        server.listen(1)

        while not stop_event.is_set():
            try:
                conn, addr = server.accept()
                log(f"TCP connection: {addr}")
                data = b""
                while True:
                    chunk = conn.recv(4096)
                    if not chunk:
                        break
                    data += chunk
                conn.close()

                if decrypt_and_save(data, "TCP"):
                    stop_event.set()
                    break
            except socket.timeout:
                continue
    except Exception as e:
        log(f"TCP error: {e}")


def decrypt_and_save(full_data, protocol):
    try:
        nonce = full_data[:16]
        tag = full_data[16:32]
        ciphertext = full_data[32:]

        """
        Decyrpt File
        """
        plaintext = decrypt_data(AES_KEY, nonce, tag, ciphertext)

        """
        Save File
        """
        with open(OUTPUT_FILENAME, "wb") as f:
            f.write(plaintext)

        log(f"File saved: {OUTPUT_FILENAME}")
        log(f"Received File Hash: {calculate_hash(plaintext)}")
        return True
    except Exception as e:
        log(f"{protocol} decryption error: {e}")
        return False


def log(text):
    output_box.insert(tk.END, text + "\n")
    output_box.see(tk.END)


if __name__ == "__main__":
    root = tk.Tk()
    root.title("Dosya Alıcı")

    tk.Button(root, text="Dosya Alıcısını Başlat", command=receive_file).pack(
        padx=10, pady=10
    )

    output_box = tk.Text(root, height=15, width=60)
    output_box.pack(padx=10, pady=5)

    root.mainloop()
