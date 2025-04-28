from scapy.all import IP, UDP, sniff

from encryption import calculate_hash, decrypt_data

OUTPUT_FILENAME = "received_file.txt"
BUFFER_SIZE = 2048
AES_KEY = b"ThisIsASecretKey"

packets_data = []


def packet_handler(packet):
    if UDP in packet and packet[UDP].dport == 12345:
        payload = bytes(packet[UDP].payload)
        packets_data.append(payload)


def receive_file():
    print("Listening... (CTRL+C to exit)")
    try:
        sniff(iface="lo0", prn=packet_handler, timeout=5)
    except KeyboardInterrupt:
        pass

    print(f"{len(packets_data)} packets received. Merging...")

    full_data = b"".join(packets_data)

    nonce = full_data[:16]
    tag = full_data[16:32]
    ciphertext = full_data[32:]

    plaintext = decrypt_data(AES_KEY, nonce, tag, ciphertext)

    with open(OUTPUT_FILENAME, "wb") as f:
        f.write(plaintext)

    print(f"File saved: {OUTPUT_FILENAME}")
    print(f"Received File Hash: {calculate_hash(plaintext)}")


if __name__ == "__main__":
    receive_file()
