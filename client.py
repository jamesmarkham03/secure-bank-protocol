# client.py


#%% Imports 

import sys
import traceback
import socket
import hashlib
from   Crypto.Cipher import AES
from   Crypto.Hash import HMAC, SHA256
from   Crypto.Random import get_random_bytes

#%% Important Constants

SERVER_HOST = "127.0.0.1"
SERVER_PORT = 5000

USER = ""
ID   = ""
KEY  = ""

#%% Security Funcs

def authenticate(sock, cipher):
    try:
        # C --> S: Nc
        Nc = cipher.nonce
        sock.send(Nc)

        # S --> C: E(K, Nc + Ns)
        response   = sock.recv(1024)
        nonce      = response[:16]
        ciphertext = response[16:-16]
        tag        = response[-16:]

        cipher_decrypt = AES.new(KEY, AES.MODE_EAX, nonce=nonce)
        decrypted      = cipher_decrypt.decrypt_and_verify(ciphertext, tag)

        recv_Nc = decrypted[:16]
        Ns      = decrypted[16:]

        # verify Nc
        if recv_Nc != Nc:
            print("Authentication failed: server is fake!")
            return False

        ciphertext, tag = cipher.encrypt_and_digest(Ns)
        
        # C --> S: E(K, Ns)
        sock.send(cipher.nonce + ciphertext + tag)

        print("Server authenticated successfully")
        
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
    
def register(sock):
    global USER
    
    username = input("Enter username: ")
    password = input("Enter password: ")
    
    send_secure(sock, ENC_KEY, MAC_KEY, f"REGISTER {username} {password}")
    response = recv_secure(sock, ENC_KEY, MAC_KEY)
    
    print("Server:", response)
    
    if "registered successfully" in response:
        USER = username

def login(sock):
    global USER
    
    username = input("Enter username: ")
    password = input("Enter password: ")
    
    send_secure(sock, ENC_KEY, MAC_KEY, f"LOGIN {username} {password}") #sock.send(f"LOGIN {username} {password}".encode())
    response = recv_secure(sock, ENC_KEY, MAC_KEY)
    
    print("Server:", response)
    
    if "logged in" in response:
        USER = username


def deposit(sock):
    if not USER:
        print("Please log in first...")
        return
    
    amt = input("Enter amount to deposit: ")
    
    send_secure(sock, ENC_KEY, MAC_KEY, f"DEPOSIT {amt}")
    response = recv_secure(sock, ENC_KEY, MAC_KEY)
    
    print("Server:", response)


def withdraw(sock):
    if not USER:
        print("Please log in first...")
        return
    
    amt = input("Enter amount to withdraw: ")
    
    send_secure(sock, ENC_KEY, MAC_KEY, f"WITHDRAW {amt}")
    response = recv_secure(sock, ENC_KEY, MAC_KEY)
    
    print("Server:", response)


def chk_bal(sock):
    if not USER:
        print("Please log in first...")
        return
    
    send_secure(sock, ENC_KEY, MAC_KEY, "CHK_BAL")
    response = recv_secure(sock, ENC_KEY, MAC_KEY)
    
    print("Server:", response)


#%% Main loop

try:
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((SERVER_HOST, SERVER_PORT))
    
    response = client_socket.recv(1024).decode()
    
    print(f"Server: {response}")
    
    if response == "SERVER BUSY!":
        client_socket.close()
        sys.exit()
    else:
        KEY    = response.encode()
        CIPHER = AES.new(KEY, AES.MODE_EAX)
        ID     = KEY.decode()[0]
        
        flag, ENC_KEY, MAC_KEY = authenticate(client_socket, CIPHER)
    
        if not flag:
            client_socket.close()
            sys.exit()
    
    while True:
        print("\n**************************")
        print("Welcome to our bank")
        print("1. Register")
        print("2. Login")
        print("3. Deposit")
        print("4. Withdraw")
        print("5. View Balance")    
        print("6. Exit")
        
        ch = input("Enter your choice: ")
        
        if ch == "1":
            register(client_socket)
        elif ch == "2":
            login(client_socket)
        elif ch == "3":
            deposit(client_socket)
        elif ch == "4":
            withdraw(client_socket)
        elif ch == "5":
            chk_bal(client_socket)
        elif ch == "6":
            print("Goodbye!")
            send_secure(client_socket, ENC_KEY, MAC_KEY, f"EXIT")
            client_socket.close()
            break
        else:
            print("Invalid input, try again...")

except Exception as e:
    print("Error:", e)
    print("--- Standard Traceback ---")
    traceback.print_exc()
    
#%%