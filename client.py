from scapy.all import IP, UDP, send

from encryption import encrypt_data

SERVER_IP = "127.0.0.1"
SERVER_PORT = 12345
PACKET_SIZE = 16  # Fragmentation

AES_KEY = b"ThisIsASecretKey"  # 16 byte (AES-128)


def send_file(filename):
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

        ip_layer = IP(dst=SERVER_IP, ttl=64, flags=0)
        udp_layer = UDP(sport=4000, dport=SERVER_PORT)
        packet = ip_layer / udp_layer / chunk

        packet = packet.__class__(bytes(packet))  # checksum düzeltmesi
        send(packet, verbose=False)

    print("File sent.")


if __name__ == "__main__":
    # filename = input("Gönderilecek dosya adı: ")
    filename = "file_to_send.txt"
    send_file(filename)
