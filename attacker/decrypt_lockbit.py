#!/usr/bin/env python3
"""
LockBit 3.0 Decryption Tool
Decrypts AES-256 encrypted files
"""

import os
import json
import hashlib
from pathlib import Path
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

ENCRYPTION_EXTENSION = ".lockbit"

def derive_file_key(master_key, file_path):
    """Derive file-specific key (same as encryption)"""
    salt = hashlib.sha256(file_path.encode()).digest()
    
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    
    key = kdf.derive(master_key.encode())
    return key

def decrypt_file(encrypted_path, master_key):
    """Decrypt a single AES-256 encrypted file"""
    try:
        # Get original path
        original_path = encrypted_path[:-len(ENCRYPTION_EXTENSION)]
        
        # Read encrypted file
        with open(encrypted_path, 'rb') as f:
            iv = f.read(16)  # First 16 bytes are IV
            ciphertext = f.read()
        
        # Derive key
        key = derive_file_key(master_key, original_path)
        
        # Create cipher
        cipher = Cipher(
            algorithms.AES(key),
            modes.CBC(iv),
            backend=default_backend()
        )
        decryptor = cipher.decryptor()
        
        # Decrypt
        padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        
        # Remove padding
        unpadder = padding.PKCS7(128).unpadder()
        plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
        
        # Write decrypted file
        with open(original_path, 'wb') as f:
            f.write(plaintext)
        
        # Remove encrypted file
        os.remove(encrypted_path)
        
        # Remove recovery file if exists
        recovery_path = original_path + ".recovery"
        if os.path.exists(recovery_path):
            os.remove(recovery_path)
        
        # Remove backup file if exists
        backup_path = original_path + ".backup_safe"
        if os.path.exists(backup_path):
            os.remove(backup_path)
        
        return True, original_path
        
    except Exception as e:
        return False, str(e)

def find_key_file():
    """Find decryption key file on Desktop"""
    desktop = os.path.join(os.path.expanduser("~"), "Desktop")
    
    for file in os.listdir(desktop):
        if file.startswith("DECRYPTION_KEY_") and file.endswith(".json"):
            return os.path.join(desktop, file)
    
    return None

def load_master_key(key_file=None):
    """Load master key from file"""
    if key_file is None:
        key_file = find_key_file()
    
    if key_file is None:
        return None, None
    
    try:
        with open(key_file, 'r') as f:
            data = json.load(f)
        
        return data['master_key'], data['victim_id']
    except Exception as e:
        print(f"[!] Error loading key: {e}")
        return None, None

def decrypt_all_files(master_key=None, victim_id=None):
    """Decrypt all encrypted files"""
    
    if master_key is None:
        print("[*] Looking for decryption key...")
        master_key, victim_id = load_master_key()
        
        if master_key is None:
            print("[!] No decryption key found!")
            print("[!] Please provide the master key manually")
            return 0
    
    print(f"[+] Master key loaded")
    print(f"[+] Victim ID: {victim_id}")
    print()
    
    # Search locations
    search_dirs = [
        os.path.join(os.path.expanduser("~"), "Documents"),
        os.path.join(os.path.expanduser("~"), "Desktop"),
        os.path.join(os.path.expanduser("~"), "Downloads"),
        os.path.join(os.path.expanduser("~"), "Pictures"),
        os.path.join("C:\\lab", "test_data") if os.name == 'nt' else "/tmp/test_data",
    ]
    
    decrypted_count = 0
    failed_count = 0
    
    print("[*] Searching for encrypted files...")
    
    for search_dir in search_dirs:
        if not os.path.exists(search_dir):
            continue
        
        print(f"[*] Scanning: {search_dir}")
        
        for root, dirs, files in os.walk(search_dir):
            for file in files:
                if file.endswith(ENCRYPTION_EXTENSION):
                    encrypted_path = os.path.join(root, file)
                    
                    success, result = decrypt_file(encrypted_path, master_key)
                    
                    if success:
                        print(f"[+] Decrypted: {result}")
                        decrypted_count += 1
                    else:
                        print(f"[!] Failed: {encrypted_path} - {result}")
                        failed_count += 1
    
    # Clean up ransom notes
    print("\n[*] Removing ransom notes...")
    
    ransom_notes = [
        os.path.join(os.path.expanduser("~"), "Desktop", "README_LOCKBIT.txt"),
        os.path.join(os.path.expanduser("~"), "Documents", "README_LOCKBIT.txt"),
    ]
    
    for note in ransom_notes:
        if os.path.exists(note):
            try:
                os.remove(note)
                print(f"[+] Removed: {note}")
            except:
                pass
    
    # Clean up wallpaper
    wallpaper = os.path.join(os.path.expanduser("~"), "Desktop", "LOCKBIT_RANSOM.bmp")
    if os.path.exists(wallpaper):
        try:
            os.remove(wallpaper)
            print(f"[+] Removed: {wallpaper}")
        except:
            pass
    
    print()
    print("╔════════════════════════════════════════════════╗")
    print("║          DECRYPTION COMPLETE                   ║")
    print("╔════════════════════════════════════════════════╝")
    print(f"  Files decrypted:  {decrypted_count}")
    print("════════════════════════════════════════════════")
    
    return decrypted_count

if __name__ == "__main__":
    print("╔════════════════════════════════════════════════╗")
    print("║     LockBit 3.0 Decryption Tool               ║")
    print("╚════════════════════════════════════════════════╝")
    print()
    
    decrypt_all_files()