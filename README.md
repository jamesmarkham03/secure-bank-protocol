# Secure Bank Protocol

A multithreaded bank server and ATM client in Python that authenticate each other, derive session keys, and encrypt and authenticate every message. Course project for **COE817 Network Security** (Toronto Metropolitan University, Winter 2026).

**Stack:** Python sockets and threads, [PyCryptodome](https://www.pycryptodome.org/) (AES-EAX, HMAC-SHA256), SHA-256 key derivation.

## How it works
1. **Mutual authentication (challenge-response).** The client sends a nonce `Nc`. The server replies with `E(K, Nc ‖ Ns)`. The client checks its own nonce came back, which proves the server knows `K`, and answers with `E(K, Ns)`, which proves the client knows `K`.
2. **Key derivation.** Both sides compute `master = SHA-256(Nc ‖ Ns)`, then two separate keys: `enc = SHA-256(master ‖ "enc")[:16]` for encryption and `mac = SHA-256(master ‖ "mac")` for integrity.
3. **Every message after that** is AES-EAX encrypted, then HMAC-SHA256 is computed over the ciphertext (encrypt-then-MAC). The receiver checks the HMAC **before** decrypting, so a tampered message is rejected.
4. **Banking:** register, login, deposit, withdraw, check balance. The server runs one thread per client (up to 3 at once) with locks around the shared account file, and writes every action to a timestamped audit log.

## Run it
```bash
pip install -r requirements.txt
python server.py          # terminal 1: listens on port 5000
python client.py          # terminal 2 (and 3, 4: up to three clients)
```
Example session:
```
Server authenticated successfully
Server: alice registered successfully!
Server: [alice] Deposited $100! New balance: $100
Server: [alice] Withdrew $30! New balance: $70
Server: [alice] Balance: $70
```
`users.txt` (accounts) and `audit_log.txt` are created next to the server at runtime and are gitignored.

## Known weaknesses and how I'd fix them
This is coursework, and reviewing it with fresh eyes, these are the real problems:

| Weakness | Why it matters | Fix |
|---|---|---|
| **The "pre-shared" key is sent in the clear.** The server sends the AES key `K` to the client as its first message. | An eavesdropper reads `K`, decrypts `Ns` from the handshake, and derives both session keys, so the encryption protects nothing against a passive attacker. | Provision keys out of band (never over the wire), or do an authenticated key exchange: ECDHE signed with the server's certificate, i.e. use TLS. |
| **Placeholder keys** (`"A"*16`, `"B"*16`, `"C"*16`) are hard-coded. | Anyone with the source has them. | Generate random keys and load them from a protected file or secret store. |
| **Passwords stored in plain text** in `users.txt`. | A leaked file exposes every password. | Store salted, slow hashes (Argon2id or bcrypt), and compare in constant time. |
| **Session keys depend only on the two nonces.** | Combined with the key leak above, nothing secret goes into the session keys. | Use HKDF with a real shared secret (from ECDHE) as the input key material. |
| **No replay protection** inside a session. | A recorded "DEPOSIT 100" message could be resent. | Add a message counter or sequence number to the MAC'd data. |
| **No message framing.** A single `recv(4096)` is assumed to hold one message. | Long or split TCP reads break parsing. | Length-prefix each message. |

## Files
- `server.py`: handshake, key derivation, secure send and receive, account logic, audit log, client threads.
- `client.py`: handshake and a menu-driven ATM.
