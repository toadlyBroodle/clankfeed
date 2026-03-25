#!/usr/bin/env python3
"""Deploy and update Clankfeed. Run directly on the VPS.

Usage:
    python deploy/update_clankfeed.py setup     # First-time setup (nginx, ssl, systemd)
    python deploy/update_clankfeed.py deploy    # Pull latest code, install deps, backup, restart
    python deploy/update_clankfeed.py backup    # Back up the database to db/backups/
    python deploy/update_clankfeed.py restart   # Just restart the service
    python deploy/update_clankfeed.py status    # Show status of all services
    python deploy/update_clankfeed.py logs      # Tail clankfeed logs
"""

import os
import shutil
import subprocess
import sys
from datetime import datetime, timezone

PROJECT_DIR = "/home/rob/Dev/clankfeed"
VENV = f"{PROJECT_DIR}/.venv"
DOMAIN = "clankfeed.com"


def _db_path() -> str:
    """Resolve the SQLite database path."""
    return os.path.normpath(os.path.join(PROJECT_DIR, "db", "relay.db"))


def run(cmd: str, check: bool = True) -> subprocess.CompletedProcess:
    print(f"  $ {cmd}")
    return subprocess.run(cmd, shell=True, check=check)


def sudo_run(cmd: str, check: bool = True) -> bool:
    print(f"  $ sudo {cmd}")
    return subprocess.run(f"sudo {cmd}", shell=True, check=check).returncode == 0


def setup():
    """First-time setup: venv, deps, nginx, ssl, systemd."""
    print("=== Clankfeed First-Time Setup ===\n")

    print("[1/6] Pulling latest code...")
    run(f"cd {PROJECT_DIR} && git pull")

    print("[2/6] Setting up Python environment...")
    run(f"python3 -m venv {VENV}")
    run(f"{VENV}/bin/pip install --upgrade pip -q")
    install_deps()

    print("[3/6] Initializing database...")
    run(f"cd {PROJECT_DIR} && {VENV}/bin/python -c '"
        "import asyncio; from app.database import init_db; asyncio.run(init_db())'")

    print("[4/6] Nginx and SSL setup...")
    sudo_run(f"mkdir -p /var/www/clankfeed")
    print("  NOTE: --standalone needs port 80. Stop nginx first if it's running.")
    sudo_run(f"systemctl stop nginx && certbot certonly --standalone -d {DOMAIN} -d www.{DOMAIN} && systemctl start nginx")
    sudo_run(f"cp {PROJECT_DIR}/deploy/clankfeed-ratelimit.conf /etc/nginx/conf.d/clankfeed-ratelimit.conf")
    sudo_run(f"ln -sf {PROJECT_DIR}/deploy/clankfeed.nginx /etc/nginx/sites-enabled/{DOMAIN}")
    sudo_run("test -f /etc/nginx/clankfeed_blocklist.conf || echo '# empty' > /etc/nginx/clankfeed_blocklist.conf")
    sudo_run("nginx -t && systemctl reload nginx")

    print("[5/6] Systemd service setup...")
    sudo_run(f"cp {PROJECT_DIR}/deploy/clankfeed.service /etc/systemd/system/")
    sudo_run("systemctl daemon-reload && systemctl enable clankfeed && systemctl start clankfeed")

    print("[6/6] Verify with:")
    sudo_run("systemctl status clankfeed")
    print(f"  Then visit: https://{DOMAIN}\n")


def backup_db():
    """Copy the SQLite DB to db/backups/ with a timestamp suffix."""
    db_path = _db_path()
    if not os.path.exists(db_path):
        print("[backup] No database to back up, skipping")
        return
    backup_dir = os.path.join(PROJECT_DIR, "db", "backups")
    os.makedirs(backup_dir, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    dest = os.path.join(backup_dir, f"relay.db.{stamp}.bak")
    shutil.copy2(db_path, dest)
    print(f"[backup] {db_path} -> {dest}")


def install_deps():
    """Install Python dependencies."""
    run(f"{VENV}/bin/pip install -q -r {PROJECT_DIR}/requirements.txt")


def deploy():
    """Standard deploy: pull, install deps, backup, nginx, restart."""
    print("=== Clankfeed Deploy ===\n")

    print("[1/5] Pulling latest code...")
    run(f"cd {PROJECT_DIR} && git pull")

    print("[2/5] Installing dependencies...")
    install_deps()

    print("[3/5] Backing up database...")
    backup_db()

    print("[4/5] Updating nginx config...")
    sudo_run(f"cp {PROJECT_DIR}/deploy/clankfeed-ratelimit.conf /etc/nginx/conf.d/clankfeed-ratelimit.conf")
    sudo_run(f"ln -sf {PROJECT_DIR}/deploy/clankfeed.nginx /etc/nginx/sites-enabled/{DOMAIN}")
    sudo_run("test -f /etc/nginx/clankfeed_blocklist.conf || echo '# empty' > /etc/nginx/clankfeed_blocklist.conf")
    sudo_run("nginx -t")
    sudo_run("nginx -s reload")

    print("[5/5] Restarting service...")
    sudo_run("systemctl restart clankfeed")


def restart():
    """Restart the clankfeed service."""
    sudo_run("systemctl restart clankfeed")


def status():
    """Show status of clankfeed-related services."""
    print("=== Service Status ===\n")
    for svc in ("lnbits", "clankfeed"):
        print(f"--- {svc} ---")
        run(f"systemctl status {svc} --no-pager -l 2>&1 | head -15", check=False)
        print()


def logs():
    """Tail clankfeed logs."""
    run("journalctl -u clankfeed -f --no-pager", check=False)


COMMANDS = {
    "setup": setup,
    "deploy": deploy,
    "backup": backup_db,
    "restart": restart,
    "status": status,
    "logs": logs,
}

if __name__ == "__main__":
    if len(sys.argv) < 2 or sys.argv[1] not in COMMANDS:
        print(__doc__)
        print(f"Commands: {', '.join(COMMANDS.keys())}")
        sys.exit(1)

    COMMANDS[sys.argv[1]]()
