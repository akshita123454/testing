import socket
import threading
import hashlib
import os
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2


def derive_key(password: str, salt: bytes = b'static_salt', key_len: int = 32) -> bytes:
    return PBKDF2(password, salt, dkLen=key_len)

def encrypt(data: bytes, key: bytes) -> bytes:
    hash_digest = hashlib.sha256(data).digest()
    full_data = data + hash_digest
    iv = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(full_data, AES.block_size))
    return iv + ciphertext

def decrypt(encrypted_data: bytes, key: bytes) -> bytes:
    iv = encrypted_data[:16]
    ciphertext = encrypted_data[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_padded = cipher.decrypt(ciphertext)
    decrypted = unpad(decrypted_padded, AES.block_size)
    data, recv_hash = decrypted[:-32], decrypted[-32:]
    computed_hash = hashlib.sha256(data).digest()
    if recv_hash != computed_hash:
        raise ValueError("Integrity check failed: SHA-256 hash mismatch.")
    return data


def send_message(sock, key, target_port):
    msg = input("Enter message: ").encode()
    enc_msg = encrypt(msg, key)
    sock.sendto(b"msg" + enc_msg, ("localhost", target_port))
    print("[SENT] Encrypted message with hash sent.")

def send_file(sock, key, target_port):
    filepath = input("Enter file path: ").strip()
    try:
        with open(filepath, "rb") as f:
            file_data = f.read()
        enc_data = encrypt(file_data, key)
        sock.sendto(b"file" + enc_data, ("localhost", target_port))
        print(f"[SENT] File '{filepath}' sent with integrity hash.")
    except Exception as e:
        print(f"[ERROR] File send failed: {e}")

def handle_peer(sock, key):
    while True:
        data, addr = sock.recvfrom(65536)
        if data.startswith(b"msg"):
            try:
                decrypted = decrypt(data[3:], key)
                print(f"[MESSAGE from {addr}] {decrypted.decode()}")
            except Exception as e:
                print(f"[ERROR] Message integrity failed: {e}")
        elif data.startswith(b"file"):
            try:
                decrypted = decrypt(data[4:], key)
                filename = f"received_file_from_{addr[1]}.bin"
                with open(filename, "wb") as f:
                    f.write(decrypted)
                print(f"[FILE RECEIVED] Saved as {filename}")
            except Exception as e:
                print(f"[ERROR] File integrity failed: {e}")

def main():
    password = input("Enter shared secret password: ")
    key = derive_key(password)

    my_port = int(input("Enter your listening port (e.g., 5001): "))
    peer_port = int(input("Enter target peer's port (e.g., 5002): "))

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("localhost", my_port))
    print(f"[LISTENING] on port {my_port}...")

    threading.Thread(target=handle_peer, args=(sock, key), daemon=True).start()

    while True:
        cmd = input("Enter command ('msg', 'file', 'exit'): ").strip()
        if cmd == "msg":
            send_message(sock, key, peer_port)
        elif cmd == "file":
            send_file(sock, key, peer_port)
        elif cmd == "exit":
            print("[INFO] Exiting...")
            break
        else:
            print("[ERROR] Invalid command.")

if __name__ == "__main__":
    main()
