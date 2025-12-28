#!/usr/bin/env python3
"""
AI Ransomware Detection & Prevention Dashboard 3.0 - FIXED
Real-time monitoring with functional response actions
"""

import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import requests
import time
from datetime import datetime, timedelta

# Page configuration
st.set_page_config(
    page_title="AI Ransomware Detection System 3.0",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS
st.markdown("""
<style>
    .stAlert {padding: 1rem; margin: 1rem 0;}
    .threat-critical {
        background: linear-gradient(135deg, #ff4444 0%, #cc0000 100%);
        color: white; padding: 15px; border-radius: 10px;
        font-weight: bold; font-size: 18px;
        box-shadow: 0 4px 6px rgba(255,68,68,0.3);
        animation: pulse 2s infinite;
    }
    .threat-warning {
        background: linear-gradient(135deg, #ffaa00 0%, #ff8800 100%);
        color: white; padding: 15px; border-radius: 10px;
        font-weight: bold; font-size: 18px;
    }
    .threat-safe {
        background: linear-gradient(135deg, #00cc44 0%, #008833 100%);
        color: white; padding: 15px; border-radius: 10px;
        font-weight: bold; font-size: 18px;
    }
    @keyframes pulse {
        0%, 100% { opacity: 1; }
        50% { opacity: 0.7; }
    }
    .victim-card {
        background: #f0f2f6;
        padding: 10px;
        border-radius: 5px;
        border-left: 4px solid #ff4444;
        margin: 5px 0;
    }
    .action-success {
        background: #d4edda;
        color: #155724;
        padding: 10px;
        border-radius: 5px;
        border-left: 4px solid #28a745;
    }
</style>
""", unsafe_allow_html=True)

# Configuration
C2_SERVER = "http://192.168.64.30:5000"

# Initialize session state
if 'last_action_result' not in st.session_state:
    st.session_state.last_action_result = None

# Behavioral Analysis Engine
class BehavioralAnalyzer:
    def analyze_file_activity(self, files_encrypted, time_window):
        if time_window > 0:
            rate = files_encrypted / time_window
            if rate > 10:
                return "CRITICAL", f"Extreme encryption rate: {rate:.1f} files/sec"
            elif rate > 5:
                return "HIGH", f"High encryption rate: {rate:.1f} files/sec"
            elif rate > 1:
                return "MEDIUM", f"Moderate encryption rate: {rate:.1f} files/sec"
        return "LOW", "Normal file activity"
    
    def detect_lockbit_patterns(self, logs):
        lockbit_indicators = []
        
        encryption_logs = [l for l in logs if l['activity_type'] == 'ENCRYPTION']
        if len(encryption_logs) > 5:
            lockbit_indicators.append("✗ Mass file encryption detected")
        
        ransom_logs = [l for l in logs if l['activity_type'] == 'RANSOM_NOTE']
        if ransom_logs:
            lockbit_indicators.append("✗ Ransom note deployment confirmed")
        
        wallpaper_logs = [l for l in logs if l['activity_type'] == 'WALLPAPER']
        if wallpaper_logs:
            lockbit_indicators.append("✗ Desktop wallpaper hijacked")
        
        heartbeat_logs = [l for l in logs if l['activity_type'] == 'HEARTBEAT']
        if len(heartbeat_logs) > 3:
            lockbit_indicators.append("✗ Persistent C2 communication")
        
        return lockbit_indicators
    
    def calculate_threat_score(self, victim_data, logs):
        score = 0
        
        files = victim_data.get('files_encrypted', 0)
        score += min(files / 10, 50)
        
        activity_types = set(l['activity_type'] for l in logs if l['victim_id'] == victim_data['id'])
        score += len(activity_types) * 10
        
        if victim_data.get('infection_time'):
            try:
                infection_time = datetime.fromisoformat(victim_data['infection_time'])
                time_elapsed = (datetime.now() - infection_time).total_seconds()
                if time_elapsed < 300:
                    score += 30
            except:
                pass
        
        if victim_data.get('wallpaper_changed'):
            score += 15
        
        return min(score, 100)

analyzer = BehavioralAnalyzer()

# Sidebar
st.sidebar.title("🛡️ Control Panel")
st.sidebar.markdown("---")

refresh_rate = st.sidebar.slider("Refresh Rate (seconds)", 1, 10, 3)
auto_refresh = st.sidebar.checkbox("Auto Refresh", value=True)

st.sidebar.markdown("---")
st.sidebar.subheader("Detection Modules")
enable_behavioral = st.sidebar.checkbox("Behavioral Analysis", value=True)
enable_network = st.sidebar.checkbox("Network Monitoring", value=True)
enable_file_monitor = st.sidebar.checkbox("File System Monitor", value=True)

st.sidebar.markdown("---")
st.sidebar.subheader("System Status")
try:
    test_conn = requests.get(f"{C2_SERVER}/api/victims", timeout=2)
    st.sidebar.success("✓ C2 Server Online")
except:
    st.sidebar.error("✗ C2 Server Offline")

# Fetch data
@st.cache_data(ttl=refresh_rate)
def fetch_victims():
    try:
        response = requests.get(f"{C2_SERVER}/api/victims", timeout=5)
        return response.json()
    except Exception as e:
        st.sidebar.error(f"Error fetching victims: {e}")
        return []

@st.cache_data(ttl=refresh_rate)
def fetch_logs():
    try:
        response = requests.get(f"{C2_SERVER}/api/logs", timeout=5)
        return response.json()
    except Exception as e:
        return []

def execute_quarantine():
    try:
        response = requests.post(
            f"{C2_SERVER}/api/action/quarantine",
            json={'target': 'all'},
            timeout=10
        )
        if response.status_code == 200:
            result = response.json()
            return True, f"Successfully quarantined {result.get('affected', 0)} systems"
        else:
            return False, "Quarantine request failed"
    except Exception as e:
        return False, f"Error: {str(e)}"

def execute_decrypt():
    try:
        response = requests.post(
            f"{C2_SERVER}/api/action/decrypt",
            json={'target': 'all'},
            timeout=10
        )
        if response.status_code == 200:
            result = response.json()
            return True, f"Decryption initiated for {result.get('affected', 0)} systems"
        else:
            return False, "Decryption request failed"
    except Exception as e:
        return False, f"Error: {str(e)}"

victims = fetch_victims()
logs = fetch_logs()

# Main dashboard
st.title("🛡️ AI Ransomware Detection System 3.0")
st.markdown("**Real-time LockBit 3.0 Simulation Monitoring**")

# Show last action result
if st.session_state.last_action_result:
    if st.session_state.last_action_result['success']:
        st.markdown(f'<div class="action-success">✓ {st.session_state.last_action_result["message"]}</div>', 
                   unsafe_allow_html=True)
    else:
        st.error(f"✗ {st.session_state.last_action_result['message']}")
    st.session_state.last_action_result = None

# Metrics row
col1, col2, col3, col4 = st.columns(4)

with col1:
    st.metric("🖥️ Infected Systems", len(victims), 
              delta=len(victims) if victims else 0,
              delta_color="inverse")

with col2:
    total_encrypted = sum(v.get('files_encrypted', 0) for v in victims)
    st.metric("📁 Files Encrypted", total_encrypted,
              delta=total_encrypted if total_encrypted > 0 else 0,
              delta_color="inverse")

with col3:
    active_threats = sum(1 for v in victims if v.get('status') in ['infected', 'encrypting', 'ransom_deployed'])
    st.metric("⚠️ Active Threats", active_threats,
              delta=active_threats if active_threats > 0 else 0,
              delta_color="inverse")

with col4:
    if victims:
        avg_threat = sum(analyzer.calculate_threat_score(v, logs) for v in victims) / len(victims)
    else:
        avg_threat = 0
    st.metric("📊 Avg Threat Score", f"{avg_threat:.1f}/100",
              delta=f"+{avg_threat:.1f}" if avg_threat > 50 else None,
              delta_color="inverse")

st.markdown("---")

# Threat Level Indicator
if victims:
    max_threat = max(analyzer.calculate_threat_score(v, logs) for v in victims)
    
    if max_threat >= 70:
        st.markdown('<div class="threat-critical">🚨 CRITICAL THREAT DETECTED - IMMEDIATE ACTION REQUIRED</div>', 
                   unsafe_allow_html=True)
    elif max_threat >= 40:
        st.markdown('<div class="threat-warning">⚠️ WARNING - Suspicious Activity Detected</div>', 
                   unsafe_allow_html=True)
    else:
        st.markdown('<div class="threat-safe">✓ System Monitoring Active - No Critical Threats</div>', 
                   unsafe_allow_html=True)

st.markdown("---")

# Two column layout
col_left, col_right = st.columns([2, 1])

with col_left:
    st.subheader("📊 Real-Time Activity Monitor")
    
    if logs:
        df_logs = pd.DataFrame(logs)
        df_logs['timestamp'] = pd.to_datetime(df_logs['timestamp'])
        
        fig = px.scatter(df_logs, 
                        x='timestamp', 
                        y='activity_type',
                        color='activity_type',
                        hover_data=['description'],
                        title="Activity Timeline")
        
        fig.update_layout(height=400, showlegend=True)
        st.plotly_chart(fig, use_container_width=True)
        
        st.subheader("Recent Activity Logs")
        display_logs = df_logs.head(15)[['timestamp', 'victim_id', 'activity_type', 'description']]
        display_logs['victim_id'] = display_logs['victim_id'].str[:8] + '...'
        st.dataframe(display_logs, use_container_width=True, hide_index=True)
    else:
        st.info("📡 No activity detected yet. Waiting for infection vectors...")

with col_right:
    st.subheader("🎯 Compromised Systems")
    
    if victims:
        for victim in victims:
            threat_score = analyzer.calculate_threat_score(victim, logs)
            victim_logs = [l for l in logs if l['victim_id'] == victim['id']]
            
            # Color code based on threat
            if threat_score >= 70:
                border_color = "#ff4444"
            elif threat_score >= 40:
                border_color = "#ffaa00"
            else:
                border_color = "#00cc44"
            
            with st.expander(f"🖥️ {victim['hostname']} ({victim['ip_address']}) - ⚠️ {threat_score:.0f}/100", expanded=threat_score >= 70):
                
                # System info
                col_a, col_b = st.columns(2)
                with col_a:
                    st.write(f"**Hostname:** {victim['hostname']}")
                    st.write(f"**IP Address:** {victim['ip_address']}")
                    st.write(f"**User:** {victim['username']}")
                with col_b:
                    st.write(f"**OS:** {victim['os_info']}")
                    st.write(f"**Status:** {victim['status'].upper()}")
                    st.write(f"**Files:** {victim['files_encrypted']}")
                
                # Infection timeline
                st.write(f"**Infected:** {victim['infection_time']}")
                if victim.get('last_seen'):
                    st.write(f"**Last Seen:** {victim['last_seen']}")
                
                # Threat progress
                st.progress(threat_score / 100, text=f"Threat Level: {threat_score:.0f}%")
                
                # LockBit indicators
                if enable_behavioral:
                    patterns = analyzer.detect_lockbit_patterns(victim_logs)
                    
                    if patterns:
                        st.error("**LockBit 3.0 Indicators Detected:**")
                        for pattern in patterns:
                            st.write(f"{pattern}")
                    
                    if victim.get('ransom_note_delivered'):
                        st.warning(f"💀 Ransom Note: {victim['ransom_note_delivered']}")
                    
                    if victim.get('wallpaper_changed'):
                        st.warning(f"🖼️ Wallpaper Hijacked: {victim['wallpaper_changed']}")
                
                # Quarantine status
                if victim.get('quarantined'):
                    st.success("🔒 System Quarantined")
    else:
        st.info("✓ No infected systems detected")

# Detailed Analysis Section
st.markdown("---")
st.subheader("🔍 AI Behavioral Analysis")

if victims and enable_behavioral:
    analysis_tabs = st.tabs(["Encryption Patterns", "Network Activity", "Timeline Analysis", "Comparison"])
    
    with analysis_tabs[0]:
        st.write("**File Encryption Rate Analysis**")
        
        encryption_data = []
        for victim in victims:
            if victim.get('infection_time'):
                try:
                    infection_time = datetime.fromisoformat(victim['infection_time'])
                    time_elapsed = (datetime.now() - infection_time).total_seconds()
                    rate = victim['files_encrypted'] / max(time_elapsed, 1)
                    
                    encryption_data.append({
                        'Hostname': victim['hostname'],
                        'IP Address': victim['ip_address'],
                        'Files Encrypted': victim['files_encrypted'],
                        'Time (seconds)': time_elapsed,
                        'Rate (files/sec)': rate
                    })
                except:
                    pass
        
        if encryption_data:
            df_enc = pd.DataFrame(encryption_data)
            
            fig = px.bar(df_enc, 
                       x='Hostname', 
                       y='Rate (files/sec)',
                       title="Encryption Rate by System",
                       color='Rate (files/sec)',
                       hover_data=['IP Address', 'Files Encrypted'],
                       color_continuous_scale='Reds')
            
            st.plotly_chart(fig, use_container_width=True)
            
            # Table view
            st.dataframe(df_enc, use_container_width=True, hide_index=True)
            
            # Analysis
            for _, row in df_enc.iterrows():
                severity, message = analyzer.analyze_file_activity(
                    row['Files Encrypted'], 
                    row['Time (seconds)']
                )
                
                if severity in ['CRITICAL', 'HIGH']:
                    st.error(f"**{row['Hostname']} ({row['IP Address']}):** {message}")
                elif severity == 'MEDIUM':
                    st.warning(f"**{row['Hostname']} ({row['IP Address']}):** {message}")
    
    with analysis_tabs[1]:
        st.write("**Command & Control Communication Analysis**")
        
        heartbeat_logs = [l for l in logs if l['activity_type'] == 'HEARTBEAT']
        if heartbeat_logs:
            st.error(f"🚨 Detected {len(heartbeat_logs)} C2 heartbeat signals")
            st.write("**Analysis:** Active command and control communication - characteristic of LockBit 3.0 persistence mechanism")
            
            # Group by victim
            from collections import Counter
            victim_heartbeats = Counter(l['victim_id'] for l in heartbeat_logs)
            
            for vid, count in victim_heartbeats.most_common():
                victim_name = next((v['hostname'] for v in victims if v['id'] == vid), vid[:8])
                st.write(f"- **{victim_name}**: {count} heartbeats")
        else:
            st.info("No C2 communication detected yet")
    
    with analysis_tabs[2]:
        st.write("**Attack Timeline Reconstruction**")
        
        if logs:
            df_timeline = pd.DataFrame(logs)
            df_timeline['timestamp'] = pd.to_datetime(df_timeline['timestamp'])
            df_timeline = df_timeline.sort_values('timestamp')
            
            for _, log in df_timeline.head(30).iterrows():
                time_str = log['timestamp'].strftime('%H:%M:%S')
                victim_name = next((v['hostname'] for v in victims if v['id'] == log['victim_id']), log['victim_id'][:8])
                
                icon = {
                    'INFECTION': '🦠',
                    'ENCRYPTION': '🔒',
                    'RANSOM_NOTE': '💀',
                    'WALLPAPER': '🖼️',
                    'HEARTBEAT': '💓',
                    'COMMAND_EXEC': '⚙️'
                }.get(log['activity_type'], '•')
                
                st.write(f"{icon} **{time_str}** - [{victim_name}] {log['activity_type']}: {log['description']}")
    
    with analysis_tabs[3]:
        st.write("**Real LockBit 3.0 vs This Simulation**")
        
        comparison_data = {
            'Feature': [
                'Encryption Algorithm',
                'Encryption Speed',
                'C2 Communication',
                'Ransom Note',
                'Wallpaper Change',
                'File Extensions',
                'Persistence Mechanism',
                'Network Propagation',
                'Data Exfiltration',
                'Anti-Analysis',
                'Payment Method',
                'Targeted Files'
            ],
            'Real LockBit 3.0': [
                'AES-256 + RSA-2048',
                '10-100+ files/sec (multi-threaded)',
                'Encrypted TOR/HTTPS',
                'Multi-language, detailed instructions',
                'Yes - custom ransom image',
                '.lockbit (customizable)',
                'Registry, scheduled tasks, services',
                'SMB, RDP exploitation',
                'Yes - steals data before encryption',
                'VM detection, sandbox evasion',
                'Bitcoin/Monero via TOR',
                'Documents, databases, backups, VMs'
            ],
            'This Simulation': [
                'Base64 (non-destructive)',
                f'{sum(v.get("files_encrypted", 0) for v in victims) / max(sum((datetime.now() - datetime.fromisoformat(v["infection_time"])).total_seconds() for v in victims if v.get("infection_time")), 1):.1f} files/sec' if victims else 'N/A',
                'HTTP REST API (unencrypted)',
                'Educational notice, recovery instructions',
                'Yes - implemented',
                '.lockbit (with .backup for recovery)',
                'HTTP heartbeat only',
                'Manual deployment only',
                'No - education only',
                'None - transparent operation',
                'None - free simulation',
                'Test files only (configurable)'
            ]
        }
        
        df_compare = pd.DataFrame(comparison_data)
        st.dataframe(df_compare, use_container_width=True, hide_index=True)
        
        st.info("""
        **Key Differences:**
        - ✓ **Simulated Behaviors:** Encryption process, C2 communication, ransom notes, wallpaper hijacking
        - ✓ **Real Characteristics:** Fast encryption, persistent C2, multi-stage attack
        - ✗ **Not Implemented:** Data theft, network propagation, advanced evasion, destructive encryption
        - ✓ **Safety Features:** Backup files created, easy recovery, no actual damage
        """)

else:
    st.info("Enable behavioral analysis to see detailed threat intelligence")

# Response Actions
st.markdown("---")
st.subheader("🚨 Incident Response Actions")

col1, col2, col3 = st.columns(3)

with col1:
    if st.button("🛑 QUARANTINE ALL SYSTEMS", type="primary", use_container_width=True):
        with st.spinner("Executing quarantine..."):
            success, message = execute_quarantine()
            st.session_state.last_action_result = {'success': success, 'message': message}
            time.sleep(1)
            st.rerun()

with col2:
    if st.button("🔐 DEPLOY DECRYPTION", type="secondary", use_container_width=True):
        with st.spinner("Initiating decryption..."):
            success, message = execute_decrypt()
            st.session_state.last_action_result = {'success': success, 'message': message}
            time.sleep(1)
            st.rerun()

with col3:
    if st.button("📊 GENERATE REPORT", type="secondary", use_container_width=True):
        report_data = {
            'timestamp': datetime.now().isoformat(),
            'infected_systems': len(victims),
            'total_files_encrypted': sum(v.get('files_encrypted', 0) for v in victims),
            'threat_level': 'CRITICAL' if victims and max(analyzer.calculate_threat_score(v, logs) for v in victims) >= 70 else 'WARNING' if victims else 'NONE',
            'victims': [
                {
                    'hostname': v['hostname'],
                    'ip': v['ip_address'],
                    'files': v['files_encrypted'],
                    'score': analyzer.calculate_threat_score(v, logs)
                } for v in victims
            ]
        }
        st.json(report_data)
        st.success("Report generated successfully")

st.markdown("---")

# Response action explanation
with st.expander("ℹ️ About Response Actions"):
    st.write("""
    **🛑 Quarantine All Systems:**
    - Sends QUARANTINE command to all infected victims
    - Victims will stop encryption and C2 communication
    - Network isolation simulated
    
    **🔐 Deploy Decryption:**
    - Sends DECRYPT command to all victims
    - Initiates automatic file recovery process
    - Restores original files from .backup copies
    
    **📊 Generate Report:**
    - Creates incident report in JSON format
    - Includes all victim details and threat scores
    - Can be exported for documentation
    """)

# Auto-refresh
if auto_refresh:
    time.sleep(refresh_rate)
    st.rerun()

# Footer
st.markdown("---")
st.caption(f"AI Ransomware Detection System 3.0 | Last Update: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | Educational Lab Environment")
