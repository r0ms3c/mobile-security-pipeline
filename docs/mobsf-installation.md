# MobSF Installation

Complete installation guide for MobSF v4.5.0 on Ubuntu 24.04 LTS.

## Requirements

| Item | Minimum |
|---|---|
| OS | Ubuntu 24.04 LTS |
| RAM | 4GB (8GB recommended) |
| CPU | 2 vCPUs |
| Disk | 20GB |
| Python | 3.12 |
| Port | 8000 (TCP inbound from Jenkins server) |

---

## Step 1 — Install system dependencies

```bash
sudo apt-get update && sudo apt-get install -y \
    python3 python3-pip python3-venv python3-dev \
    build-essential libssl-dev libffi-dev \
    libxml2-dev libxslt1-dev zlib1g-dev \
    git curl wget unzip openjdk-17-jdk sqlite3
```

---

## Step 2 — Install Poetry

```bash
curl -sSL https://install.python-poetry.org | python3 -
export PATH="/root/.local/bin:$PATH"
echo 'export PATH="/root/.local/bin:$PATH"' >> ~/.bashrc
source ~/.bashrc
poetry --version
```

---

## Step 3 — Clone and install MobSF

```bash
cd /opt
sudo git clone https://github.com/MobSF/Mobile-Security-Framework-MobSF.git mobsf
sudo chown -R $USER:$USER /opt/mobsf
cd /opt/mobsf

# Fix run script to use poetry binary directly
sed -i 's/python3 -m poetry run/poetry run/' /opt/mobsf/run.sh

# Install dependencies
poetry install
```

---

## Step 4 — Create systemd service

```bash
sudo tee /etc/systemd/system/mobsf.service << 'EOF'
[Unit]
Description=Mobile Security Framework (MobSF)
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/mobsf
Environment="PATH=/root/.local/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
ExecStart=/bin/bash /opt/mobsf/run.sh 0.0.0.0:8000
Restart=always
RestartSec=10
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable mobsf
sudo systemctl start mobsf
```

MobSF takes approximately 70 seconds to fully initialise on first start.

---

## Step 5 — Get the API key

MobSF generates its API key from a secret file. Retrieve it with:

```bash
python3 -c "
from hashlib import sha256
import pathlib
secret_file = pathlib.Path('/root/.MobSF/secret')
print('API Key:', sha256(secret_file.read_bytes().strip()).hexdigest())
"
```

Store this key as a Jenkins credential (Secret text, ID: `mobsf-api-key`).

---

## Step 6 — Verify

```bash
# Check service is running
sudo systemctl status mobsf

# Wait for full initialisation
sleep 70

# Test API
curl -s -w "\nHTTP:%{http_code}" http://localhost:8000/api/v1/scans \
  -H "X-Mobsf-Api-Key: <your-api-key>"
# Should return HTTP:200 with {"content": [], "count": 0, "num_pages": 1}
```

Open in browser: `http://<server-ip>:8000`

---

## Updating MobSF

```bash
sudo systemctl stop mobsf
cd /opt/mobsf
sudo git pull
poetry install
sudo systemctl start mobsf
```

---

## Troubleshooting

**Service fails with `status=217/USER`**
The user specified in the service file does not exist. Update `User=` to match the actual user (`whoami`).

**`/usr/bin/python3: No module named poetry`**
Poetry is installed but not in PATH. Add `Environment="PATH=/root/.local/bin:..."` to the service file.

**`Command not found: gunicorn`**
MobSF dependencies not installed. Run `cd /opt/mobsf && poetry install`.

**Upload fails with `Connection reset by peer`**
Network proxy or firewall dropping large uploads. Use the Jenkins pipeline to upload via curl from the server's internal network — bypasses proxy restrictions.

**API returns HTTP 401**
Wrong API key. Retrieve the correct key from the secret file (see Step 5). The key in `/root/.MobSF/config.py` is ignored — MobSF always derives the key from the secret file.
