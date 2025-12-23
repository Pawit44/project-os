# Honeypot Security System

[![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)](https://python.org)
[![Docker](https://img.shields.io/badge/Docker-sudyosh%2Fhoneypot--security-blue?logo=docker)](https://hub.docker.com/r/sudyosh/honeypot-security)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Raspberry%20Pi-red.svg)](https://www.raspberrypi.org/)

ระบบ Honeypot สำหรับตรวจจับและวิเคราะห์พฤติกรรมผู้โจมตี ผ่าน Web และ SSH พร้อมระบบแจ้งเตือนและตอบสนองอัตโนมัติ

A comprehensive honeypot system for detecting and analyzing attacker behavior through Web and SSH, with automated alerting and response capabilities.

---

## Table of Contents | สารบัญ

- [Features | คุณสมบัติ](#features--คุณสมบัติ)
- [Architecture | สถาปัตยกรรม](#architecture--สถาปัตยกรรม)
- [Requirements | ความต้องการระบบ](#requirements--ความต้องการระบบ)
- [Installation | การติดตั้ง](#installation--การติดตั้ง)
- [Docker Deployment | การติดตั้งด้วย Docker](#docker-deployment--การติดตั้งด้วย-docker) ⭐
- [Configuration | การตั้งค่า](#configuration--การตั้งค่า)
- [Usage | การใช้งาน](#usage--การใช้งาน)
- [Dashboard | แดชบอร์ด](#dashboard--แดชบอร์ด)
- [API Reference | อ้างอิง API](#api-reference--อ้างอิง-api)
- [Threat Scoring | การให้คะแนนภัยคุกคาม](#threat-scoring--การให้คะแนนภัยคุกคาม)
- [Troubleshooting | การแก้ไขปัญหา](#troubleshooting--การแก้ไขปัญหา)

---

## Features | คุณสมบัติ

### Web Honeypot
- 🌐 Fake login page (simulates router/admin panel)
- 📝 Captures: IP, Username, Password, User-Agent
- 🎯 Traps common attack paths (/admin, /wp-admin, /phpmyadmin)

### SSH Honeypot
- 🔐 Fake SSH server using Paramiko
- 💻 Interactive fake shell with common commands
- 📜 Records all commands and credentials
- 🎭 Simulates Linux environment

### Threat Analysis
- 🌍 GeoIP lookup (IP to Country/City)
- 🔍 Password strength analysis
- ⚠️ Dangerous command detection
- 📊 Bruteforce detection

### Threat Scoring
- 📈 Behavior-based scoring system
- 🏷️ Three threat levels: LOW, MEDIUM, HIGH
- 🎯 Configurable thresholds

### Alerting
- 💬 Discord webhook notifications
- ⚡ Real-time alerts
- 🔔 Configurable alert thresholds

### Auto Response (SOAR)
- 🛡️ Automatic IP blocking (iptables)
- ⏱️ Configurable block duration
- 📋 Block logging and management

### Dashboard
- 📊 Real-time statistics
- 📈 Attack timeline charts
- 🗺️ Top attacking countries
- 🔑 Top passwords/usernames
- 📋 Recent attacks table

---

## Architecture | สถาปัตยกรรม

```
┌─────────────────────────────────────────────────────────────────┐
│                    HONEYPOT SECURITY SYSTEM                      │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐       │
│  │ Web Honeypot │    │ SSH Honeypot │    │   Dashboard  │       │
│  │   (Flask)    │    │  (Paramiko)  │    │   (Flask)    │       │
│  │   :8080      │    │    :2222     │    │    :5000     │       │
│  └──────┬───────┘    └──────┬───────┘    └──────────────┘       │
│         │                   │                                    │
│         └─────────┬─────────┘                                    │
│                   ▼                                              │
│         ┌─────────────────┐                                      │
│         │  Attack Handler │                                      │
│         └────────┬────────┘                                      │
│                  │                                               │
│    ┌─────────────┼─────────────┐                                 │
│    ▼             ▼             ▼                                 │
│ ┌──────┐   ┌──────────┐   ┌──────────┐                          │
│ │GeoIP │   │ Threat   │   │   Log    │                          │
│ │Lookup│   │ Scorer   │   │Collector │                          │
│ └──────┘   └────┬─────┘   └────┬─────┘                          │
│                 │              │                                 │
│    ┌────────────┴────────────┐ │                                │
│    ▼                         ▼ ▼                                │
│ ┌──────────┐           ┌──────────┐                             │
│ │ Discord  │           │ SQLite   │                             │
│ │  Alert   │           │ Database │                             │
│ └──────────┘           └──────────┘                             │
│                              │                                   │
│                              ▼                                   │
│                        ┌──────────┐                              │
│                        │  Auto    │                              │
│                        │ Blocker  │                              │
│                        │(iptables)│                              │
│                        └──────────┘                              │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

---

## Requirements | ความต้องการระบบ

### Hardware
- Raspberry Pi 3/4 (recommended) or any Linux system
- Minimum 1GB RAM
- 8GB+ SD Card / Storage

### Software
- Python 3.8+
- Raspberry Pi OS Lite / Debian / Ubuntu

### Python Dependencies
```
flask>=2.0.0
paramiko>=3.0.0
requests>=2.28.0
pyyaml>=6.0
geoip2>=4.0.0
cryptography>=41.0.0
```

---

## Installation | การติดตั้ง

### Quick Install (Raspberry Pi / Linux)

```bash
# 1. Clone the repository
git clone https://github.com/yourusername/honeypot-security.git
cd honeypot-security

# 2. Run installation script
sudo chmod +x scripts/install.sh
sudo ./scripts/install.sh
```

### Manual Installation

```bash
# 1. Update system
sudo apt update && sudo apt upgrade -y

# 2. Install Python
sudo apt install python3 python3-pip python3-venv -y

# 3. Clone repository
git clone https://github.com/yourusername/honeypot-security.git
cd honeypot-security

# 4. Create virtual environment
python3 -m venv venv
source venv/bin/activate

# 5. Install dependencies
pip install -r requirements.txt

# 6. Setup configuration
cp config/config.example.yaml config/config.yaml
nano config/config.yaml

# 7. Generate SSH host key
mkdir -p data
ssh-keygen -t rsa -b 2048 -f data/ssh_host_key -N ""
```

### GeoIP Database (Optional)

For IP geolocation, download the free MaxMind GeoLite2 database:

1. Create free account at https://dev.maxmind.com/geoip/geolite2-free-geolocation-data
2. Download GeoLite2-City.mmdb
3. Place in `data/GeoLite2-City.mmdb`

---

## Docker Deployment | การติดตั้งด้วย Docker

### Docker Hub

```
Image: sudyosh/honeypot-security
Tags: latest, 1.0.0
```

### วิธีติดตั้งบน Raspberry Pi ด้วย Docker

#### ขั้นตอนที่ 1: ติดตั้ง Docker บน Raspberry Pi

```bash
# อัพเดทระบบ
sudo apt update && sudo apt upgrade -y

# ติดตั้ง Docker
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh

# เพิ่ม user ปัจจุบันเข้ากลุ่ม docker (ไม่ต้องใช้ sudo)
sudo usermod -aG docker $USER

# Logout แล้ว Login ใหม่ หรือ reboot
sudo reboot
```

#### ขั้นตอนที่ 2: Pull Docker Image

```bash
# Pull image จาก Docker Hub
docker pull sudyosh/honeypot-security:latest

# ตรวจสอบว่า pull สำเร็จ
docker images | grep honeypot
```

#### ขั้นตอนที่ 3: สร้างไฟล์ Configuration

```bash
# สร้างโฟลเดอร์สำหรับ config
mkdir -p ~/honeypot/config
mkdir -p ~/honeypot/data
mkdir -p ~/honeypot/logs

# สร้างไฟล์ config.yaml
cat > ~/honeypot/config/config.yaml << 'EOF'
honeypots:
  web:
    enabled: true
    port: 8080
    host: "0.0.0.0"
  ssh:
    enabled: true
    port: 2222
    host: "0.0.0.0"
    host_key: "data/ssh_host_key"

alerting:
  discord:
    enabled: true
    webhook_url: "YOUR_DISCORD_WEBHOOK_URL_HERE"
    alert_threshold: "MEDIUM"
    rate_limit: 60

scoring:
  thresholds:
    low: 5
    medium: 15
  behaviors:
    login_attempt: 1
    failed_login: 2
    bruteforce_threshold: 5
    bruteforce_bonus: 5
    dangerous_command: 10
    malware_download: 15
    known_bad_password: 3
  dangerous_commands:
    - "wget"
    - "curl"
    - "nc"
    - "netcat"
    - "chmod"
    - "rm -rf"
    - "/etc/passwd"
    - "/etc/shadow"
    - "base64"
    - "python -c"
    - "perl -e"
    - "bash -i"

response:
  auto_block: true
  block_threshold: "HIGH"
  block_duration: 3600
  use_iptables: true

dashboard:
  enabled: true
  port: 5000
  host: "0.0.0.0"

geoip:
  enabled: true
  database_path: "data/GeoLite2-City.mmdb"

logging:
  level: "INFO"
  main_log: "logs/honeypot.log"
  attack_log: "logs/attacks.json"

database:
  path: "data/honeypot.db"
EOF

# แก้ไข Discord Webhook URL
nano ~/honeypot/config/config.yaml
```

#### ขั้นตอนที่ 4: รัน Docker Container

**วิธีที่ 1: Docker Run (แบบง่าย)**

```bash
docker run -d \
  --name honeypot \
  --restart unless-stopped \
  --cap-add NET_ADMIN \
  --cap-add NET_RAW \
  -p 8080:8080 \
  -p 2222:2222 \
  -p 5000:5000 \
  -v ~/honeypot/config/config.yaml:/app/config/config.yaml:ro \
  -v ~/honeypot/data:/app/data \
  -v ~/honeypot/logs:/app/logs \
  -e TZ=Asia/Bangkok \
  sudyosh/honeypot-security:latest
```

**วิธีที่ 2: Docker Compose (แนะนำ)**

```bash
# สร้างไฟล์ docker-compose.yml
cat > ~/honeypot/docker-compose.yml << 'EOF'
version: '3.8'

services:
  honeypot:
    image: sudyosh/honeypot-security:latest
    container_name: honeypot-security
    restart: unless-stopped
    cap_add:
      - NET_ADMIN
      - NET_RAW
    ports:
      - "8080:8080"   # Web Honeypot
      - "2222:2222"   # SSH Honeypot
      - "5000:5000"   # Dashboard
    volumes:
      - ./config/config.yaml:/app/config/config.yaml:ro
      - ./data:/app/data
      - ./logs:/app/logs
    environment:
      - TZ=Asia/Bangkok
      - PYTHONUNBUFFERED=1
    logging:
      driver: "json-file"
      options:
        max-size: "10m"
        max-file: "3"
EOF

# รัน docker compose
cd ~/honeypot
docker compose up -d
```

#### ขั้นตอนที่ 5: ตรวจสอบการทำงาน

```bash
# ดู logs
docker logs -f honeypot

# ตรวจสอบ status
docker ps

# ดู resource usage
docker stats honeypot
```

#### ขั้นตอนที่ 6: เข้าใช้งาน

| Service | URL | Description |
|---------|-----|-------------|
| Web Honeypot | `http://PI_IP:8080` | หน้า Login ปลอม |
| SSH Honeypot | `ssh -p 2222 PI_IP` | SSH Server ปลอม |
| Dashboard | `http://PI_IP:5000` | แดชบอร์ดตรวจสอบ |

```bash
# หา IP ของ Raspberry Pi
hostname -I

# ทดสอบเข้า Dashboard
curl http://localhost:5000
```

### คำสั่ง Docker ที่ใช้บ่อย

```bash
# หยุด container
docker stop honeypot

# เริ่ม container
docker start honeypot

# รีสตาร์ท container
docker restart honeypot

# ดู logs แบบ real-time
docker logs -f honeypot

# เข้าไปใน container
docker exec -it honeypot /bin/bash

# ลบ container (ข้อมูลใน volume ยังอยู่)
docker rm -f honeypot

# อัพเดท image ใหม่
docker pull sudyosh/honeypot-security:latest
docker rm -f honeypot
# แล้วรัน docker run ใหม่

# ดู disk usage
docker system df
```

### การตั้งค่า Port Forwarding (Optional)

หากต้องการให้ honeypot รับ traffic จาก internet:

```bash
# Forward port 22 (SSH จริง) ไปที่ port 22222
# Forward port 2222 (Honeypot) ไปที่ port 22
# ทำบน router หรือใช้ iptables

# ตัวอย่าง iptables (ต้องรันบน host ไม่ใช่ใน container)
sudo iptables -t nat -A PREROUTING -p tcp --dport 22 -j REDIRECT --to-port 2222
```

### Systemd Auto-start (Optional)

สร้าง systemd service เพื่อให้ Docker Compose รันอัตโนมัติเมื่อ boot:

```bash
sudo cat > /etc/systemd/system/honeypot.service << 'EOF'
[Unit]
Description=Honeypot Security System
Requires=docker.service
After=docker.service

[Service]
Type=oneshot
RemainAfterExit=yes
WorkingDirectory=/home/pi/honeypot
ExecStart=/usr/bin/docker compose up -d
ExecStop=/usr/bin/docker compose down
User=pi

[Install]
WantedBy=multi-user.target
EOF

# เปิดใช้งาน
sudo systemctl enable honeypot.service
sudo systemctl start honeypot.service

# ตรวจสอบ status
sudo systemctl status honeypot.service
```

---

## Configuration | การตั้งค่า

Edit `config/config.yaml`:

```yaml
# Honeypot Settings
honeypots:
  web:
    enabled: true
    port: 8080          # Web honeypot port
    host: "0.0.0.0"
  ssh:
    enabled: true
    port: 2222          # SSH honeypot port
    host: "0.0.0.0"
    host_key: "data/ssh_host_key"

# Discord Alerting
alerting:
  discord:
    enabled: true
    webhook_url: "YOUR_DISCORD_WEBHOOK_URL"
    alert_threshold: "MEDIUM"    # LOW, MEDIUM, HIGH
    rate_limit: 60               # seconds between alerts

# Threat Scoring
scoring:
  thresholds:
    low: 5              # 0-4 = LOW
    medium: 15          # 5-14 = MEDIUM
                        # 15+ = HIGH
  behaviors:
    login_attempt: 1
    bruteforce_bonus: 5
    dangerous_command: 10
    known_bad_password: 3

# Auto Response (SOAR)
response:
  auto_block: true
  block_threshold: "HIGH"
  block_duration: 3600          # 1 hour

# Dashboard
dashboard:
  enabled: true
  port: 5000
  host: "0.0.0.0"
```

### Discord Webhook Setup | ตั้งค่า Discord

1. Open Discord, go to your server
2. Server Settings → Integrations → Webhooks
3. Create New Webhook
4. Copy Webhook URL
5. Paste in `config.yaml`

---

## Usage | การใช้งาน

### Start the System

```bash
# Activate virtual environment
source venv/bin/activate

# Start all components
sudo python3 main.py

# Start with options
sudo python3 main.py --no-dashboard    # Without dashboard
sudo python3 main.py --web-only        # Web honeypot only
sudo python3 main.py --ssh-only        # SSH honeypot only
```

### Access Points

| Service | URL | Description |
|---------|-----|-------------|
| Web Honeypot | http://IP:8080 | Fake login page |
| SSH Honeypot | ssh -p 2222 IP | Fake SSH server |
| Dashboard | http://IP:5000 | Monitoring dashboard |

### Testing the Honeypots

**Test Web Honeypot:**
```bash
# From another machine
curl -X POST http://HONEYPOT_IP:8080/login \
  -d "username=admin&password=test123"
```

**Test SSH Honeypot:**
```bash
# From another machine
ssh -p 2222 root@HONEYPOT_IP
# Enter any password
# Try commands: ls, whoami, wget, etc.
```

---

## Dashboard | แดชบอร์ด

Access the dashboard at `http://YOUR_IP:5000`

### Features:
- **Stats Cards**: Total attacks, unique IPs, blocked IPs, high threats
- **Attack Timeline**: Hourly attack visualization
- **Threat Distribution**: Pie chart of LOW/MEDIUM/HIGH threats
- **Top Countries**: Bar chart of attacking countries
- **Top Passwords**: Most attempted passwords
- **Recent Attacks**: Real-time attack table

### Screenshots

```
┌────────────────────────────────────────────────────────────────┐
│  🍯 Honeypot Security Dashboard                                │
├────────────────────────────────────────────────────────────────┤
│                                                                │
│  ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐  │
│  │  1,234  │ │   456   │ │    23   │ │    89   │ │   102   │  │
│  │ Attacks │ │   IPs   │ │ Blocked │ │  High   │ │  Today  │  │
│  └─────────┘ └─────────┘ └─────────┘ └─────────┘ └─────────┘  │
│                                                                │
│  ┌──────────────────────┐  ┌──────────────────────┐           │
│  │  Attack Timeline     │  │  Threat Distribution │           │
│  │  ~~~~~~~~~~~~~~~~~~~│  │      ████            │           │
│  │   ~~~    ~~  ~~~~   │  │     ██████           │           │
│  └──────────────────────┘  └──────────────────────┘           │
│                                                                │
│  Recent Attacks:                                               │
│  ┌──────────────────────────────────────────────────────────┐ │
│  │ Time      │ Source │ IP          │ Country │ Level      │ │
│  │ 12:30:45  │ SSH    │ 1.2.3.4     │ China   │ HIGH       │ │
│  │ 12:28:12  │ WEB    │ 5.6.7.8     │ Russia  │ MEDIUM     │ │
│  └──────────────────────────────────────────────────────────┘ │
└────────────────────────────────────────────────────────────────┘
```

---

## API Reference | อ้างอิง API

### GET /api/stats
Get dashboard statistics.

**Response:**
```json
{
  "total_attacks": 1234,
  "unique_ips": 456,
  "blocked_ips": 23,
  "high_threats": 89,
  "today_attacks": 102,
  "top_passwords": [{"password": "123456", "count": 50}],
  "top_countries": [{"country": "China", "count": 200}]
}
```

### GET /api/attacks
Get recent attacks.

**Parameters:**
- `limit` (int): Number of attacks to return (default: 50)

### GET /api/blocked
Get blocked IPs list.

### POST /api/block/{ip_address}
Manually block an IP.

### POST /api/unblock/{ip_address}
Unblock an IP.

---

## Threat Scoring | การให้คะแนนภัยคุกคาม

### Scoring Rules

| Behavior | Points |
|----------|--------|
| Login attempt | +1 |
| Common password | +3 |
| Root login | +2 |
| Bruteforce (>5 attempts) | +5 |
| Dangerous command | +10 |

### Threat Levels

| Level | Score | Action |
|-------|-------|--------|
| LOW | 0-4 | Log only |
| MEDIUM | 5-14 | Alert + Log |
| HIGH | 15+ | Alert + Block + Log |

### Dangerous Commands Detected

- `wget`, `curl` - Download tools
- `nc`, `netcat` - Reverse shells
- `chmod 777`, `chmod +s` - Permission changes
- `/etc/passwd`, `/etc/shadow` - Sensitive files
- `rm -rf` - Destructive commands
- `base64 -d` - Obfuscation

---

## Troubleshooting | การแก้ไขปัญหา

### Port Permission Denied

```bash
# Use ports > 1024 or run as root
sudo python3 main.py
```

### SSH Key Error

```bash
# Regenerate SSH key
rm data/ssh_host_key*
ssh-keygen -t rsa -b 2048 -f data/ssh_host_key -N ""
```

### GeoIP Not Working

1. Check if `data/GeoLite2-City.mmdb` exists
2. Download from MaxMind if missing

### Discord Alerts Not Sending

1. Verify webhook URL is correct
2. Check `enabled: true` in config
3. Check rate limiting

### Database Errors

```bash
# Reset database
rm data/honeypot.db
python3 main.py  # Will recreate
```

---

## Project Structure | โครงสร้างโปรเจกต์

```
honeypot-security/
├── main.py                 # Main entry point
├── requirements.txt        # Python dependencies
├── config/
│   ├── config.example.yaml # Example configuration
│   └── config.yaml         # Your configuration
├── honeypots/
│   ├── web_honeypot.py     # Web honeypot
│   ├── ssh_honeypot.py     # SSH honeypot
│   └── templates/
│       └── login.html      # Fake login page
├── core/
│   ├── config.py           # Configuration loader
│   ├── database.py         # SQLite handler
│   └── log_collector.py    # Central logging
├── analysis/
│   ├── geoip.py            # GeoIP lookup
│   ├── threat_intel.py     # Threat analysis
│   └── threat_scorer.py    # Scoring system
├── alerting/
│   └── discord_webhook.py  # Discord notifications
├── response/
│   └── auto_blocker.py     # Auto blocking (SOAR)
├── dashboard/
│   ├── app.py              # Flask dashboard
│   ├── templates/          # HTML templates
│   └── static/             # CSS/JS
├── scripts/
│   └── install.sh          # Installation script
├── logs/                   # Log files
└── data/                   # Database & keys
```

---

## Security Considerations | ข้อควรพิจารณาด้านความปลอดภัย

1. **Isolation**: Run on isolated network/VLAN
2. **Firewall**: Only expose honeypot ports
3. **Monitoring**: Monitor for compromise
4. **Updates**: Keep system updated
5. **Backup**: Regular backup of logs/data

---

## Contributing | การมีส่วนร่วม

1. Fork the repository
2. Create feature branch
3. Commit changes
4. Push to branch
5. Create Pull Request

---

## License | ลิขสิทธิ์

MIT License - see LICENSE file

---

## Credits | เครดิต

- [Flask](https://flask.palletsprojects.com/)
- [Paramiko](https://www.paramiko.org/)
- [Chart.js](https://www.chartjs.org/)
- [MaxMind GeoLite2](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data)

---

**Made with ❤️ for Security Research**
