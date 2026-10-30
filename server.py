# server.py

#%% Imports

import socket
import os
import traceback
import threading
import hashlib
from   datetime import datetime
from   Crypto.Cipher import AES
from   Crypto.Hash import HMAC, SHA256
from   Crypto.Random import get_random_bytes


#%% Important constants

HOST = "0.0.0.0"
PORT = 5000

FILE_NAME  = "users.txt"
AUDIT_FILE = "audit_log.txt"

symm_keys  = ["A"*16, "B"*16, "C"*16]
hosts      = [1, 1, 1]

lock       = threading.Lock()
audit_lock = threading.Lock()
host_lock  = threading.Lock()

ID = "S"

#%% Sec Funcs

def authenticate(conn, key, cipher):
    try:
        # C --> S: Nc
        Nc = conn.recv(1024)
        Ns = cipher.nonce
        
        ciphertext, tag = cipher.encrypt_and_digest(Nc + Ns)
        
        # S--> C: E(K, Nc + Ns)
        conn.send(cipher.nonce + ciphertext + tag)

        # C --> S: E(K, Ns)
        response   = conn.recv(1024)
        nonce      = response[:16]
        ciphertext = response[16:-16]
        tag        = response[-16:]

        cipher_decrypt = AES.new(key, AES.MODE_EAX, nonce=nonce)
        decrypted      = cipher_decrypt.decrypt_and_verify(ciphertext, tag)

        # verify Ns
        if decrypted != Ns:
            print("Authentication failed: Client is a fake!")
            return False

        print("Client authenticated successfully")
        
        # Derive master secret key
        master_secret = hashlib.sha256(Nc + Ns).digest()
        
        # Derive encryption and MAC key
        enc_key = hashlib.sha256(master_secret + b"enc").digest()[:16]
        mac_key = hashlib.sha256(master_secret + b"mac").digest()
        
        return True, enc_key, mac_key

    except Exception as e:
        print("Auth error:", e)
        print("--- Standard Traceback ---")
        traceback.print_exc()        
        return False, None, None
    

def send_secure(sock, enc_key, mac_key, message):
    plaintext = message.encode()    
    
    # Encrypt
    cipher = AES.new(enc_key, AES.MODE_EAX)
    ciphertext, tag_enc = cipher.encrypt_and_digest(plaintext)
    
    # Compute HMAC over ciphertext
    h   = HMAC.new(mac_key, ciphertext, digestmod = SHA256)
    mac = h.digest()
    
    sock.send(cipher.nonce + ciphertext + tag_enc + mac)


def recv_secure(sock, enc_key, mac_key):
    data = sock.recv(4096)
    
    nonce        = data[:16]      # AES nonce is 16 bytes
    ciphertext   = data[16:-48]   # remaining minus tag(16) + MAC(32)
    tag_enc      = data[-48:-32]  # AES tag is 16 bytes
    mac_received = data[-32:]     # HMAC-SHA256 is 32 bytes
    
    # Verify HMAC
    h = HMAC.new(mac_key, ciphertext, digestmod = SHA256)
    try:
        h.verify(mac_received)
    except ValueError:
        raise Exception("Message integrity check failed!")
    
    # Decrypt
    cipher    = AES.new(enc_key, AES.MODE_EAX, nonce = nonce)
    plaintext = cipher.decrypt_and_verify(ciphertext, tag_enc)
    
    return plaintext.decode()


#%% Util Funcs

def get_users():
    users = {}
    
    if os.path.exists(FILE_NAME):
        with open(FILE_NAME, "r") as f:
            for line in f:
                username, password, balance = line.strip().split(",")
                users[username]             = [password, int(balance)]
    
    return users


def save_user(username, password, balance):
    with open(FILE_NAME, "a") as f:
        f.write(f"{username},{password},{balance}\n")


def update_user(username, password, balance):
    lines = []
    
    with open(FILE_NAME, "r") as f:
        lines = f.readlines()
    
    with open(FILE_NAME, "w") as f:
        for line in lines:
            user, pwd, bal = line.strip().split(",")
            
            if user == username:
                f.write(f"{username},{password},{balance}\n")
            else:
                f.write(line)

def log_action(username, action):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    with audit_lock:
        with open(AUDIT_FILE, "a") as f:
            f.write(f"{username},{action},{timestamp}\n")


#%% This is where it all happens

def handle_client(conn, addr):
    print(f"[NEW CONNECTION] {addr}")
    
    current_user = None
        
    with host_lock:
        if 1 in hosts:
            client_index = hosts.index(1)
            hosts[client_index] = 0
        else:
            conn.send("SERVER BUSY!".encode())        
            conn.close()
            return
        
    conn.send(symm_keys[client_index].encode())
    CIPHER = AES.new(symm_keys[client_index].encode(), AES.MODE_EAX)
    
    flag, ENC_KEY, MAC_KEY = authenticate(conn, symm_keys[client_index].encode(), CIPHER)
    
    if not flag:
        conn.close()
        return           
    
    try:
        while True:
            data = recv_secure(conn, ENC_KEY, MAC_KEY)
            
            print(f"[{current_user}] Received: {data}")
            parts = data.split()
            cmd   = parts[0]
            
            users = get_users()

            if cmd == "REGISTER":
                username, password = parts[1], parts[2]
                
                if username in users:
                    send_secure(conn, ENC_KEY, MAC_KEY, "Registration failed! Username already exists! Please login instead...")
                else:
                    current_user = username
                    save_user(username, password, 0)
                    send_secure(conn, ENC_KEY, MAC_KEY, f"{username} registered successfully!")

            elif cmd == "LOGIN":
                username, password = parts[1], parts[2]
                
                if username in users and users[username][0] == password:
                    current_user = username
                    send_secure(conn, ENC_KEY, MAC_KEY, f"{username} logged in!")
                else:
                    send_secure(conn, ENC_KEY, MAC_KEY, "Invalid credentials!")

            elif cmd == "DEPOSIT":
                if not current_user:
                    send_secure(conn, ENC_KEY, MAC_KEY, "Please login first...")
                    continue
                
                amount = int(parts[1])

                with lock:
                    users       = get_users()
                    new_balance = users[current_user][1] + amount
                    update_user(current_user, users[current_user][0], new_balance)
                
                log_action(current_user, f"DEPOSIT {amount}")

                send_secure(conn, ENC_KEY, MAC_KEY, f"[{current_user}] Deposited ${amount}! New balance: ${new_balance}")

            elif cmd == "WITHDRAW":
                if not current_user:
                    send_secure(conn, ENC_KEY, MAC_KEY, "Please login first!")
                    continue
                
                amount = int(parts[1])

                with lock:
                    users = get_users()
                    
                    if users[current_user][1] >= amount:
                        new_balance = users[current_user][1] - amount
                        update_user(current_user, users[current_user][0], new_balance)
                        log_action(current_user, f"WITHDRAW {amount}")
                        send_secure(conn, ENC_KEY, MAC_KEY, f"[{current_user}] Withdrew ${amount}! New balance: ${new_balance}")
                    else:
                        send_secure(conn, ENC_KEY, MAC_KEY, "[{current_user}] Broke! Not enough money!")

            elif cmd == "CHK_BAL":
                if not current_user:
                    send_secure(conn, ENC_KEY, MAC_KEY, "Please login first...")
                    continue
                
                balance = users[current_user][1]
                log_action(current_user, "CHK_BAL")
                send_secure(conn, ENC_KEY, MAC_KEY, f"[{current_user}] Balance: ${balance}")
            
            elif cmd == "EXIT":
                hosts[client_index] = 1
                conn.close()
                return

    except Exception as e:
        print("Error:", e)
        print("--- Standard Traceback ---")
        traceback.print_exc()
        conn.close()


#%% Main loop

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind((HOST, PORT))
server.listen(5)

print(f"[LISTENING] Server running on port {PORT}")

while True:
    conn, addr = server.accept()
    thread = threading.Thread(target=handle_client, args=(conn, addr))
    thread.start()
    
#%%