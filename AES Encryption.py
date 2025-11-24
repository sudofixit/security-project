"""
Phase 2: Cryptography Simulation 
encrypting students.csv passwords with AES-GCM and deriving key with PBKDF2
Steps:
- Reads students.csv (username,password,email)
- Derives AES-256 key from a passphrase using PBKDF2 (salt saved in key_salt.bin)
- Encrypts passwords with AES-GCM (nonce + ct + tag) per row, stores base64(iv+ct+tag)
- Writes students_encrypted.csv
- Verifies by decrypting the first row and printing it
- Hashes a password for a specific user and verifies it
"""

import csv
import os
import base64
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
import getpass
import hashlib

# Parameters for PBKDF2
PBKDF2_ITERATIONS = 200_000 
KEY_LEN = 32  
SALT_FILE = "key_salt.bin"

def load_or_create_salt():
    if os.path.exists(SALT_FILE):
        with open(SALT_FILE, "rb") as f:
            salt = f.read()
            print(f"Loaded salt from {SALT_FILE} (length {len(salt)} bytes)")
    else:
        salt = get_random_bytes(16)
        with open(SALT_FILE, "wb") as f:
            f.write(salt)
        print(f"Generated new salt and saved to {SALT_FILE}")
    return salt

def derive_key(passphrase, salt):
    # PBKDF2 with HMAC-SHA256
    return PBKDF2(passphrase, salt, dkLen=KEY_LEN, count=PBKDF2_ITERATIONS)

def encrypt_gcm(plaintext, key):
    # AES-GCM uses a 12-byte nonce 
    nonce = get_random_bytes(12)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ct, tag = cipher.encrypt_and_digest(plaintext)
    combined = nonce + ct + tag
    return base64.b64encode(combined).decode()

def decrypt_gcm(b64_combined, key):
    raw = base64.b64decode(b64_combined)
    nonce = raw[:12]
    tag = raw[-16:]
    ct = raw[12:-16]
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    plaintext = cipher.decrypt_and_verify(ct, tag)  # raises ValueError if tampered/wrong key
    return plaintext

def hash_record_and_verify():
    infile = "students.csv"
    
    with open(infile, newline='', encoding='utf-8') as file:
        reader = csv.DictReader(file)
        rows = list(reader)

    # Step 1: Hash password for a chosen username
    user = input("Enter username to hash password for: ")
    user_row = next((row for row in rows if row["username"] == user), None)
    
    if not user_row:
        print("Username not found.")
        return
    
    password = user_row["password"]
    hash_value = hashlib.sha256(password.encode()).hexdigest()
    print(f"Password hash for {user_row['username']}:", hash_value)

    # Step 2: Verify password hash for a username
    user_to_verify = input("Enter username to verify password hash: ")
    verify_row = next((row for row in rows if row["username"] == user_to_verify), None)

    if not verify_row:
        print("Username not found.")
        return

    stored_hash = hashlib.sha256(verify_row["password"].encode()).hexdigest()
    password_to_verify = getpass.getpass("Enter password to verify: ")
    calculated_hash_value = hashlib.sha256(password_to_verify.encode()).hexdigest()

    if calculated_hash_value == stored_hash:
        print("Password verification successful ✅")
    else:
        print("Password verification failed ❌")
    


def main():
    # 1) derive key
    salt = load_or_create_salt()
    passphrase = getpass.getpass("Enter a passphrase to derive the AES key: ")
    key = derive_key(passphrase.encode(), salt)
    print("Key derived. (It will not be printed.)")

    # 2) Read students.csv
    in_file = "students.csv"
    out_file = "students_encrypted.csv"
    if not os.path.exists(in_file):
        print(f"Error: {in_file} not found. Create students.csv first.")
        return

    encrypted_rows = []
    with open(in_file, newline='', encoding='utf-8') as file:
        reader = csv.DictReader(file)
        for r in reader:
            username = r["username"]
            pwd = r["password"]
            email = r["email"]
            enc_b64 = encrypt_gcm(pwd.encode(), key)
            encrypted_rows.append({"username": username, "password_encrypted": enc_b64, "email": email})

    # 3) Write encrypted CSV
    with open(out_file, "w", newline='', encoding='utf-8') as fout:
        fieldnames = ["username", "password_encrypted", "email"]
        writer = csv.DictWriter(fout, fieldnames=fieldnames)
        writer.writeheader()
        for row in encrypted_rows:
            writer.writerow(row)

    print(f"Encrypted CSV written to {out_file} ({len(encrypted_rows)} rows).")

    # 4) Verify by decrypting the first row
    first = encrypted_rows[0]
    try:
        decrypted = decrypt_gcm(first["password_encrypted"], key).decode()
        print("Decryption verified for first row:")
        print(f" username: {first['username']}")
        print(f" decrypted password: {decrypted}")
    except Exception as e:
        print("Verification failed:", e)

    # 5) Hash a password for a specific user and verify hash
    hash_record_and_verify()


if __name__ == "__main__":
    main()
    
