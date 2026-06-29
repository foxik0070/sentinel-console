#!/usr/bin/env python3
# sentinel_client_init.py — Sentinel Console Setup v2.0

import os
import sys
import subprocess
import configparser
import urllib.request
import urllib.error
import urllib.parse
from getpass import getpass

CONFIG_DIR  = "/etc/sentinel"
CONFIG_FILE = os.path.join(CONFIG_DIR, "sentinel_client.conf")
VENV_DIR    = "/opt/sentinel/venv"
REQUIRED    = ["textual>=0.80", "httpx"]

# ── ANSI colours ───────────────────────────────────────────────────────────────
R  = "\033[1;31m"   # red (error / critical)
Y  = "\033[1;33m"   # yellow (warn)
G  = "\033[1;32m"   # green (ok)
C  = "\033[1;36m"   # cyan (info)
W  = "\033[1;37m"   # white (heading)
DM = "\033[0;90m"   # dim
NC = "\033[0m"      # reset

def p_ok(msg):    print(f"{G}  ✓{NC}  {msg}")
def p_info(msg):  print(f"{C}  ·{NC}  {msg}")
def p_warn(msg):  print(f"{Y}  !{NC}  {msg}")
def p_err(msg):   print(f"{R}  ✗{NC}  {msg}")
def p_head(msg):  print(f"\n{W}{'─'*58}{NC}\n{W}  {msg}{NC}")

# ── Root check ─────────────────────────────────────────────────────────────────
def check_root():
    if os.geteuid() != 0:
        p_warn("Spouštíš bez root práv — setup /opt a /etc/sentinel může selhat.")
        yn = input("  Pokračovat i tak? [a/N] ").strip().lower()
        if yn not in ("a", "y", "ano", "yes"):
            sys.exit(0)

# ── Venv setup ─────────────────────────────────────────────────────────────────
def setup_virtualenv():
    p_head("VIRTUÁLNÍ PROSTŘEDÍ")

    venv_py = os.path.join(VENV_DIR, "bin", "python")
    if os.path.isfile(venv_py):
        p_info(f"Venv nalezen v {VENV_DIR}")
        yn = input("  Přeinstalovat závislosti? [a/N] ").strip().lower()
        if yn not in ("a", "y", "ano", "yes"):
            p_ok("Přeskakuji instalaci.")
            return
    else:
        p_info(f"Vytvářím venv v {VENV_DIR} ...")
        try:
            os.makedirs(os.path.dirname(VENV_DIR), exist_ok=True)
            res = subprocess.run(
                [sys.executable, "-m", "venv", VENV_DIR],
                capture_output=True, text=True,
            )
            if res.returncode != 0:
                _venv_fail(res)
            p_ok("Venv vytvořen.")
        except PermissionError:
            p_err(f"Nemáš právo zapsat do {VENV_DIR}. Spusť jako root.")
            sys.exit(1)

    pip = os.path.join(VENV_DIR, "bin", "pip")
    p_info(f"Instaluji: {', '.join(REQUIRED)} ...")
    try:
        res = subprocess.run(
            [pip, "install", "--upgrade"] + REQUIRED,
            capture_output=True, text=True,
        )
        if res.returncode != 0:
            p_err("pip selhal:")
            print(res.stderr[-1500:] if res.stderr else res)
            sys.exit(1)
        p_ok("Závislosti nainstalovány.")
    except FileNotFoundError:
        p_err(f"pip nenalezen v {pip} — venv je poškozený.")
        sys.exit(1)


def _venv_fail(res):
    err = (res.stderr or "").lower()
    p_err("Vytvoření venv selhalo.")
    if "ensurepip" in err or "venv" in err:
        p_warn("Chybí python3-venv. Nainstaluj:")
        print(f"  {C}sudo apt install python3-venv{NC}")
    else:
        print(res.stderr[:1000])
    sys.exit(1)


# ── Config setup ───────────────────────────────────────────────────────────────
def setup_config():
    p_head("KONFIGURACE")

    if not os.path.exists(CONFIG_DIR):
        try:
            os.makedirs(CONFIG_DIR, mode=0o755)
            p_ok(f"Vytvořeno: {CONFIG_DIR}")
        except PermissionError:
            p_err(f"Nemáš právo vytvořit {CONFIG_DIR}. Spusť jako root.")
            sys.exit(1)

    cfg = configparser.ConfigParser()
    if os.path.exists(CONFIG_FILE):
        cfg.read(CONFIG_FILE)
        p_info(f"Existující config načten z {CONFIG_FILE}")

    if "DEFAULT" not in cfg:
        cfg["DEFAULT"] = {}

    cur_url  = cfg.get("DEFAULT", "URL",      fallback="http://192.168.2.114:5050")
    cur_user = cfg.get("DEFAULT", "USERNAME", fallback="admin")

    url  = input(f"  Sentinel URL [{cur_url}]: ").strip()
    cfg["DEFAULT"]["URL"] = url if url else cur_url

    user = input(f"  Uživatelské jméno [{cur_user}]: ").strip()
    cfg["DEFAULT"]["USERNAME"] = user if user else cur_user

    print(f"  {DM}Heslo (prázdné = bude vyžadováno při každém spuštění klienta){NC}")
    pw = getpass("  Heslo: ").strip()
    cfg["DEFAULT"]["PASSWORD"] = pw

    try:
        with open(CONFIG_FILE, "w") as f:
            cfg.write(f)
        os.chmod(CONFIG_FILE, 0o600)
        p_ok(f"Config uložen: {CONFIG_FILE}  (chmod 600)")
    except PermissionError:
        p_err(f"Nelze zapsat do {CONFIG_FILE}. Spusť jako root.")
        sys.exit(1)

    return cfg["DEFAULT"]["URL"], cfg["DEFAULT"]["USERNAME"], pw


# ── Connectivity test ──────────────────────────────────────────────────────────
def test_connection(url, username, password):
    p_head("TEST PŘIPOJENÍ")
    p_info(f"Ověřuji dostupnost {url} ...")

    # Basic TCP reachability via HEAD on /
    try:
        req = urllib.request.Request(url, method="HEAD")
        with urllib.request.urlopen(req, timeout=6) as r:
            p_ok(f"Server dostupný — HTTP {r.status}")
    except urllib.error.HTTPError as e:
        if e.code in (405, 403, 401, 302):
            p_ok(f"Server dostupný — HTTP {e.code}")
        else:
            p_warn(f"Server vrátil HTTP {e.code} — zkontroluj URL")
            return False
    except urllib.error.URLError as e:
        p_err(f"Server nedostupný: {e.reason}")
        p_warn("Zkontroluj URL a síťové připojení.")
        return False
    except Exception as e:
        p_warn(f"Test selhal: {e}")
        return False

    # Try login
    p_info("Testuji přihlášení ...")
    try:
        import http.cookiejar
        cj      = http.cookiejar.CookieJar()
        opener  = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))
        login_d = urllib.parse.urlencode({"username": username, "password": password}).encode()
        req     = urllib.request.Request(f"{url}/login", data=login_d, method="POST")
        with opener.open(req, timeout=8) as r:
            pass

        status_req = urllib.request.Request(f"{url}/api/status_check")
        with opener.open(status_req, timeout=8) as r:
            body = r.read().decode()
            if r.status == 200:
                p_ok("Přihlášení úspěšné ✓")
                return True
            else:
                p_warn(f"Přihlášení vrátilo HTTP {r.status}")
                return False
    except urllib.error.HTTPError as e:
        if e.code in (401, 403):
            p_warn("Přihlášení selhalo — špatné heslo nebo uživatel.")
        else:
            p_warn(f"Přihlášení HTTP chyba: {e.code}")
        return False
    except Exception as e:
        p_warn(f"Přihlášení nelze ověřit: {e}")
        return False


# ── Entry point ────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    print(f"\n{W}╔══════════════════════════════════════════════════════╗{NC}")
    print(f"{W}║       SENTINEL CONSOLE — Průvodce nastavením          ║{NC}")
    print(f"{W}╚══════════════════════════════════════════════════════╝{NC}")

    check_root()
    setup_virtualenv()
    url, user, pw = setup_config()
    conn_ok = test_connection(url, user, pw)

    p_head("HOTOVO")
    if conn_ok:
        p_ok("Vše nastaveno a připojení ověřeno.")
    else:
        p_warn("Nastavení uloženo, ale připojení se nepodařilo ověřit.")
        p_warn("Zkontroluj URL a přihlašovací údaje v config souboru:")
        print(f"    {C}{CONFIG_FILE}{NC}")

    venv_py = os.path.join(VENV_DIR, "bin", "python")
    client  = os.path.join(os.path.dirname(os.path.abspath(__file__)), "sentinel_client.py")
    print(f"\n  {G}Spuštění klienta:{NC}")
    print(f"    {C}{venv_py} {client}{NC}\n")
