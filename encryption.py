import hashlib

from Crypto.Cipher import AES


def encrypt_data(key, plaintext):
    """
    Veriyi AES ile şifreler ve nonce, tag, ciphertext döndürür.
    """
    cipher = AES.new(key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    return cipher.nonce, tag, ciphertext


def decrypt_data(key, nonce, tag, ciphertext):
    """
    Şifrelenmiş veriyi çözer ve düz metni döndürür.
    """
    cipher = AES.new(key, AES.MODE_EAX, nonce)
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    return plaintext


def calculate_hash(data):
    """
    Verinin SHA-256 hash'ini hesaplar ve hex formatında döndürür.
    """
    return hashlib.sha256(data).hexdigest()
