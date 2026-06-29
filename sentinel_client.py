#!/usr/bin/env python3
# sentinel_client.py — Sentinel TUI v3.0 (HTOP-style, plná parita s web UI)

import os, sys
VENV_PYTHON = "/opt/sentinel/venv/bin/python"
if sys.executable != VENV_PYTHON and os.path.exists(VENV_PYTHON):
    os.execl(VENV_PYTHON, VENV_PYTHON, *sys.argv)

import base64, configparser, getpass, json, math, re, textwrap
import httpx
from rich.text import Text

from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Vertical, Horizontal, ScrollableContainer
from textual.screen import ModalScreen
from textual.widgets import DataTable, Input, Static, Log, Button, Label
from textual.reactive import reactive
from textual import on

# ── Config ─────────────────────────────────────────────────────────────────────
CONFIG_FILE = "/etc/sentinel/sentinel_client.conf"
VERSION     = "v2026.06.013"
CHANNELS    = ["ALL", "INFRA", "AGENT", "ROOT", "SEC"]
SORT_MODES  = ["TIME", "SEV", "HOST", "CH"]
POLL_SEC    = 5.0

def load_config():
    if not os.path.exists(CONFIG_FILE):
        print(f"Config nenalezen: {CONFIG_FILE}. Spusť sentinel_client_init.py")
        sys.exit(1)
    cfg = configparser.ConfigParser()
    cfg.read(CONFIG_FILE)
    url  = cfg.get("DEFAULT", "URL",      fallback="http://192.168.2.114:5050").strip()
    user = cfg.get("DEFAULT", "USERNAME", fallback="admin").strip()
    pw   = cfg.get("DEFAULT", "PASSWORD", fallback="").strip().strip('"').strip("'")
    if not pw:
        pw = getpass.getpass(f"Heslo pro '{user}': ").strip()
    return url, user, pw

# ── Helpers ────────────────────────────────────────────────────────────────────
SEV_WEIGHT = {"CRITICAL": 0, "HIGH": 1, "WARNING": 2, "WARN": 2, "LOW": 3}

def channel_of(issue):
    key = issue.get("key", "")
    ch  = (issue.get("channel_type") or "").upper()
    if not ch and key.startswith("AGENT|"):
        if any(x in key for x in ["root_monitor", "security_root"]):
            return "ROOT"
        if any(x in key for x in ["port_security", "vulnerability", "fail2ban"]):
            return "SECURITY"
        return "AGENT"
    return ch or "INFRA"

def issue_in_channel(issue, channel):
    if channel == "ALL":
        return True
    ch = channel_of(issue)
    if channel == "INFRA":
        return ch not in ("AGENT", "ROOT", "SECURITY")
    if channel == "SEC":
        return ch == "SECURITY"
    return ch == channel

def issue_matches(issue, filt):
    if not filt:
        return True
    f = filt.lower()
    return any(f in str(v).lower() for v in [
        issue.get("host", ""), issue.get("last_line", ""),
        issue.get("channel_type", ""), issue.get("plugin_name", ""),
        issue.get("key", ""),
    ])

def sort_issues(issues, mode):
    if mode == "SEV":
        issues.sort(key=lambda x: (SEV_WEIGHT.get(x.get("severity", "").upper(), 4), x.get("last_seen", "")))
    elif mode == "HOST":
        issues.sort(key=lambda x: x.get("host", ""))
    elif mode == "CH":
        issues.sort(key=lambda x: channel_of(x))
    else:
        issues.sort(key=lambda x: x.get("last_seen", ""), reverse=True)
    return issues

def kb64(key):
    return base64.b64encode(key.encode()).decode()

def clean_html(text):
    text = text.replace("<br>", "\n").replace("<br/>", "\n").replace("<br />", "\n")
    text = text.replace("<p>", "\n").replace("</p>", "\n")
    text = text.replace("<li>", "\n• ").replace("</li>", "")
    text = text.replace("<ul>", "").replace("</ul>", "")
    text = re.sub(r"<[^>]+>", "", text)
    text = text.replace("&lt;", "<").replace("&gt;", ">").replace("&amp;", "&") \
               .replace("&nbsp;", " ").replace("&#39;", "'").replace("&quot;", '"')
    text = re.sub(r"\n{3,}", "\n\n", text)
    return text.strip()

def _esc(s):
    """Escapuje [ aby nebylo interpretováno jako Rich markup."""
    return str(s).replace("[", "\\[")

def _chat_line(log, text):
    """Zapíše jeden řádek do chat logu — vždy na nový řádek."""
    log.write(text + "\n")

def _write_chat(log, prefix, prefix_style, text):
    """Zapíše chat odpověď — každý řádek textu na vlastní řádek."""
    lines = [l.strip() for l in text.splitlines() if l.strip()]
    if not lines:
        return
    for i, line in enumerate(lines):
        safe = _esc(line)
        if i == 0 and prefix and prefix_style:
            _chat_line(log, f"[{prefix_style}]{_esc(prefix)}[/] {safe}")
        else:
            _chat_line(log, f"  {safe}")

def make_sev_text(sev_raw):
    s = sev_raw.upper()
    if s == "CRITICAL":
        t = Text(" CRIT "); t.stylize("bold white on #c50f1f")
    elif s in ("WARNING", "WARN"):
        t = Text(" WARN "); t.stylize("bold black on #fcc419")
    elif s == "HIGH":
        t = Text(" HIGH "); t.stylize("bold white on #d4380d")
    elif s == "LOW":
        t = Text("  LOW "); t.stylize("bold black on #555555")
    else:
        t = Text(f" {s[:4]} "); t.stylize("bold black on #666666")
    return t

def make_ch_text(ch_raw):
    ch = ch_raw.upper()
    if ch == "ROOT":
        t = Text(" ROOT"); t.stylize("bold black on #f5c518")
    elif ch in ("SECURITY", "LOGIN"):
        t = Text("  SEC"); t.stylize("bold white on #c50f1f")
    elif ch == "AGENT":
        t = Text(" AGNT"); t.stylize("bold white on #107c10")
    elif ch == "INFRA":
        t = Text(" INFR"); t.stylize("bold white on #005faf")
    else:
        t = Text(f" {ch[:4]}"); t.stylize("bold black on #888888")
    return t

def gauge_bar(label, count, max_val, width=12):
    filled = min(width, int(math.ceil(width * count / max_val))) if max_val > 0 else 0
    empty  = max(0, width - filled)
    bf = "█" * filled
    be = "░" * empty
    if count == 0:
        bar_m = f"[dim]{bf}{be}[/dim]"
    elif filled >= int(width * 0.75):
        bar_m = f"[bold red]{bf}[/bold red][dim]{be}[/dim]"
    elif filled >= int(width * 0.4):
        bar_m = f"[bold yellow]{bf}[/bold yellow][dim]{be}[/dim]"
    else:
        bar_m = f"[bold green]{bf}[/bold green][dim]{be}[/dim]"
    return f"[bold cyan]{label}[/bold cyan] {bar_m} [bold white]{count:3d}[/bold white]"

# ── API Client ─────────────────────────────────────────────────────────────────
class APIClient:
    def __init__(self, base_url, username, password):
        self.base_url = base_url
        self.username = username
        self.password = password
        self._http    = httpx.AsyncClient(base_url=base_url, timeout=15.0, follow_redirects=True)
        self.authed   = False
        self._csrf    = ""

    async def login(self):
        try:
            await self._http.post("/login", data={"username": self.username, "password": self.password})
            r = await self._http.get("/api/status_check")
            if r.status_code in (401, 403):
                return False
            # Získej CSRF token z hlavní stránky
            html_r = await self._http.get("/")
            m = re.search(r'<meta name="csrf-token" content="([^"]+)"', html_r.text)
            if m:
                self._csrf = m.group(1)
            self.authed = True
            return True
        except Exception:
            return False

    def _csrf_headers(self):
        return {"X-CSRF-Token": self._csrf} if self._csrf else {}

    async def _get(self, path, **kw):
        try:
            r = await self._http.get(path, **kw)
            if r.status_code == 200:
                return r.json()
        except Exception:
            pass
        return None

    async def _post(self, path, **kw):
        try:
            hdrs = kw.pop("headers", {})
            hdrs.update(self._csrf_headers())
            return await self._http.post(path, headers=hdrs, **kw)
        except Exception:
            return None

    async def _delete(self, path, **kw):
        try:
            hdrs = kw.pop("headers", {})
            hdrs.update(self._csrf_headers())
            return await self._http.delete(path, headers=hdrs, **kw)
        except Exception:
            return None

    # Issues
    async def get_issues(self):
        d = await self._get("/api/v1/issues")
        return (d or {}).get("issues", [])

    async def ignore_issue(self, kb):
        r = await self._post(f"/api/issues/{kb}/ignore")
        return r and r.status_code == 200

    async def delete_issue(self, kb):
        r = await self._delete(f"/api/issues/{kb}/delete")
        return r and r.status_code == 200

    async def acknowledge_issue(self, kb):
        r = await self._post(f"/api/issues/{kb}/acknowledge")
        return r and r.status_code == 200

    async def unacknowledge_issue(self, kb):
        r = await self._post(f"/api/issues/{kb}/unacknowledge")
        return r and r.status_code == 200

    async def snooze_issue(self, kb, hours):
        r = await self._post("/api/issues/snooze", json={"key": kb, "hours": hours})
        return r and r.status_code == 200

    async def get_issue_comments(self, kb):
        d = await self._get(f"/api/issues/{kb}/comments")
        return (d or {}).get("comments", [])

    async def add_issue_comment(self, kb, text):
        r = await self._post(f"/api/issues/{kb}/comments", json={"text": text})
        return r and r.status_code == 200

    async def get_triage(self):
        d = await self._get("/api/issues/triage")
        return (d or {}).get("issues", [])

    async def bulk_ignore(self, keys):
        c = 0
        for k in keys:
            if await self.ignore_issue(k): c += 1
        return c

    async def bulk_delete(self, keys):
        c = 0
        for k in keys:
            if await self.delete_issue(k): c += 1
        return c

    async def bulk_acknowledge(self, keys):
        r = await self._post("/api/issues/bulk_acknowledge", json={"keys": keys})
        return r and r.status_code == 200

    # AI / Chat
    async def chat(self, message):
        r = await self._post("/api/chat", json={"message": message})
        if r is None:
            return "[AI: Chyba sítě nebo timeout]"
        if r.status_code == 403:
            return "[AI: CSRF chyba — restartuj klienta]"
        if r.status_code in (401, 302):
            return "[AI: Session vypršela — restartuj klienta]"
        if r.status_code != 200:
            return f"[AI: HTTP {r.status_code}]"
        try:
            return clean_html(r.json().get("reply", ""))
        except Exception:
            return "[AI: Neplatná odpověď serveru]"

    async def ai_batch_summary(self, channel="ALL"):
        p = {}
        if channel not in ("ALL", ""):
            p["channel"] = "security" if channel == "SEC" else channel.lower()
        r = await self._post("/api/analyze/active_issues", json=p)
        if r and r.status_code == 200:
            return clean_html(r.json().get("reply", ""))
        return "[AI souhrn selhal]"

    async def ai_correlate(self, channel="ALL"):
        p = {}
        if channel not in ("ALL", ""):
            p["channel"] = "security" if channel == "SEC" else channel.lower()
        r = await self._post("/api/analyze/correlate", json=p)
        if r and r.status_code == 200:
            return clean_html(r.json().get("reply", ""))
        return "[AI korelace selhala]"

    async def ai_trend_report(self, days=7):
        r = await self._post("/api/analyze/trend_report", json={"days": days})
        if r and r.status_code == 200:
            return clean_html(r.json().get("reply", ""))
        return "[Trend report selhal]"

    # Agents
    async def get_agents(self):
        d = await self._get("/api/agents/list")
        return (d or {}).get("agents", [])

    # Actions
    async def get_pending_actions(self):
        d = await self._get("/api/v1/actions")
        return (d or {}).get("actions", [])

    async def execute_action(self, aid, node, command):
        r = await self._post(f"/api/v1/actions/{aid}/execute", json={"node": node, "command": command})
        if r and r.status_code == 200:
            return r.json()
        return {"status": "error"}

    async def reject_action(self, aid):
        r = await self._post(f"/api/v1/actions/{aid}/review", json={"status": "rejected"})
        return r and r.status_code == 200

    # Logs
    async def get_log_list(self):
        d = await self._get("/api/logs/list")
        return (d or {}).get("files", [])

    async def get_log_content(self, filename):
        r = await self._post("/api/logs/view", json={"filename": filename})
        if r and r.status_code == 200:
            return r.json().get("content", "")
        return ""

    # Predictions / system
    async def get_predictions(self):
        d = await self._get("/api/predictions")
        return (d or {}).get("predictions", [])

    async def get_sys_info(self):
        return await self._get("/api/sys_info") or {}

    async def close(self):
        await self._http.aclose()


# ── Help modal ─────────────────────────────────────────────────────────────────
HELP_TEXT = """\
 [bold cyan]NAVIGACE[/]
   [yellow]↑↓[/]          Pohyb v tabulce issues
   [yellow]PgUp/PgDn[/]   Rychlý pohyb
   [yellow]Enter[/]       Detail issue (komentáře, akce)
   [yellow]Space[/]       Bulk: přepnout výběr řádku
   [yellow]Ctrl+A[/]      Bulk: vybrat vše

 [bold cyan]KANÁLY[/]
   [yellow]Tab[/]/[yellow]Shift+Tab[/]   Přepnout kanál
   [yellow]1[/] VŠE  [yellow]2[/] INFRA  [yellow]3[/] AGENT  [yellow]4[/] ROOT  [yellow]5[/] SEC

 [bold cyan]ISSUE AKCE[/]
   [yellow]i[/] Ignorovat         [yellow]d[/] Smazat
   [yellow]f[/] AI Autofix        [yellow]a[/] Acknowledge / Un-ack
   [yellow]s[/] Snooze (1/4/24/72h)

 [bold cyan]BULK AKCE[/] (po výběru Space / Ctrl+A)
   [yellow]I[/] Bulk Ignore       [yellow]D[/] Bulk Delete
   [yellow]A[/] Bulk Acknowledge  [yellow]Esc[/] Zrušit výběr

 [bold cyan]ZOBRAZENÍ[/]
   [yellow]/[/] nebo [yellow]F2[/]  Filter (live)    [yellow]o[/] Přepnout sort
   [yellow]c[/]           Toggle chat panel [yellow]p[/] Toggle akce panel
   [yellow]r[/]/[yellow]F5[/]       Refresh

 [bold cyan]MODALY / POHLEDY[/]
   [yellow]l[/]  Log Viewer        [yellow]g[/] Správa agentů
   [yellow]n[/]  AI Návrhy akcí    [yellow]t[/] Predikce & Trendy
   [yellow]x[/]  AI Batch Souhrn   [yellow]z[/] AI Korelace

 [yellow]F1[/]/[yellow]?[/] Nápověda   [yellow]q[/]/[yellow]F10[/] Ukončit
"""

class HelpModal(ModalScreen):
    DEFAULT_CSS = """
    HelpModal { align: center middle; }
    #hm-box {
        width: 62; height: auto; max-height: 90%;
        background: #0d0d0d; border: solid #4fc1ff; padding: 1 2;
    }
    #hm-title {
        text-align: center; color: #4fc1ff; text-style: bold;
        margin-bottom: 1; border-bottom: solid #333333;
    }
    """
    BINDINGS = [Binding("escape,f1,q", "dismiss", show=False)]

    def compose(self):
        with Vertical(id="hm-box"):
            yield Static(f"[bold]SENTINEL TUI {VERSION} — NÁPOVĚDA[/]", id="hm-title")
            yield Static(HELP_TEXT)
            yield Static("[dim]Stiskni Esc nebo ? pro zavření[/]", id="hm-close")

    def on_key(self, event):
        self.dismiss()


# ── Issue Detail modal ─────────────────────────────────────────────────────────
class IssueDetailModal(ModalScreen):
    DEFAULT_CSS = """
    IssueDetailModal { align: center middle; }
    #idm-box {
        width: 92; max-width: 98%; max-height: 90%;
        background: #0d0d0d; border: solid #4fc1ff; layout: vertical;
    }
    #idm-title {
        height: 1; background: #003d7a; color: #ffffff;
        padding: 0 1; text-style: bold;
    }
    #idm-body {
        height: auto; max-height: 14; padding: 1 2;
        background: #050505;
    }
    #idm-comments-hdr {
        height: 1; background: #1a1a2e; color: #4fc1ff;
        padding: 0 1; text-style: bold;
    }
    #idm-comments {
        height: 8; background: #000000; color: #cccccc;
    }
    #idm-input {
        height: 1; background: #111111; color: #4fc1ff;
        border: none; padding: 0 1;
    }
    #idm-keys {
        height: 1; background: #1a1a1a; color: #888888; padding: 0 1;
    }
    """
    BINDINGS = [
        Binding("escape", "dismiss_modal", show=False),
        Binding("i", "do_ignore",  "Ignorovat"),
        Binding("d", "do_delete",  "Smazat"),
        Binding("f", "do_autofix", "Autofix"),
        Binding("a", "do_ack",     "Ack"),
        Binding("s", "do_snooze",  "Snooze"),
    ]

    def __init__(self, meta, issue, api):
        super().__init__()
        self.meta  = meta
        self.issue = issue
        self.api   = api

    def compose(self):
        with Vertical(id="idm-box"):
            yield Static("", id="idm-title")
            with ScrollableContainer(id="idm-body"):
                yield Static("", id="idm-body-text")
            yield Static("[bold cyan]KOMENTÁŘE[/]  — Enter: přidat komentář", id="idm-comments-hdr")
            yield Log(id="idm-comments")
            yield Input(placeholder="Přidat komentář nebo příkaz AI...", id="idm-input")
            yield Static("", id="idm-keys")

    async def on_mount(self):
        i      = self.issue
        ts     = (i.get("last_seen") or "N/A").replace("T", " ").split(".")[0]
        first  = (i.get("first_seen") or "N/A").replace("T", " ").split(".")[0]
        sev    = (i.get("severity") or "WARN").upper()
        ch     = channel_of(i)
        host   = i.get("host", "?")
        plugin = i.get("plugin_name") or i.get("channel_type") or "?"
        msg    = i.get("last_line", "")
        occ    = i.get("occurrence_count", 1) or 1
        ack_by = i.get("acknowledged_by", "")
        assigned = i.get("assigned_to", "")

        self.query_one("#idm-title", Static).update(
            f"[bold]DETAIL:[/] {host}  [SEV: {sev}]  [CH: {ch}]"
        )
        lines = [
            f"[bold]Host:[/]        {host}",
            f"[bold]Plugin:[/]      {plugin}",
            f"[bold]Kanál:[/]       {ch}",
            f"[bold]Závažnost:[/]   {sev}",
            f"[bold]Naposledy:[/]   {ts}",
            f"[bold]Poprvé:[/]      {first}",
            f"[bold]Výskyty:[/]     ×{occ}",
        ]
        if ack_by:
            lines.append(f"[bold #40c057]ACK by:[/]      {ack_by}")
        if assigned:
            lines.append(f"[bold]Přiřazeno:[/]   {assigned}")
        lines.append(f"\n[bold]Zpráva:[/]\n[dim]{msg}[/]")
        self.query_one("#idm-body-text", Static).update("\n".join(lines))
        self.query_one("#idm-keys", Static).update(
            "[bold](i)[/]Ignore  [bold](d)[/]Delete  [bold](f)[/]Autofix  "
            "[bold](a)[/]Ack  [bold](s)[/]Snooze  [bold]Esc[/]:Zavřít"
        )
        await self._load_comments()

    async def _load_comments(self):
        log = self.query_one("#idm-comments", Log)
        log.clear()
        key = self.meta.get("key", "")
        if not key:
            return
        comments = await self.api.get_issue_comments(kb64(key))
        if not comments:
            log.write("[dim]Žádné komentáře.[/]")
        else:
            for c in comments:
                ts = (c.get("created_at", "") or "").replace("T", " ").split(".")[0]
                log.write(f"[bold]{c.get('username','?')}[/] [{ts}]: {c.get('text','')}")

    async def on_input_submitted(self, event):
        text = event.value.strip()
        if not text:
            return
        event.input.value = ""
        key = self.meta.get("key", "")
        if key:
            ok = await self.api.add_issue_comment(kb64(key), text)
            if ok:
                await self._load_comments()

    def action_dismiss_modal(self):
        self.dismiss(None)

    async def action_do_ignore(self):
        key = self.meta.get("key", "")
        if key:
            await self.api.ignore_issue(kb64(key))
        self.dismiss("refresh")

    async def action_do_delete(self):
        key = self.meta.get("key", "")
        if key:
            await self.api.delete_issue(kb64(key))
        self.dismiss("refresh")

    async def action_do_ack(self):
        key = self.meta.get("key", "")
        if key:
            if self.meta.get("acked"):
                await self.api.unacknowledge_issue(kb64(key))
            else:
                await self.api.acknowledge_issue(kb64(key))
        self.dismiss("refresh")

    async def action_do_autofix(self):
        log = self.query_one("#idm-comments", Log)
        log.write("[dim]AI Autofix request...[/]")
        payload = f"{self.meta.get('host','?')}: {self.meta.get('message','')}"
        reply   = await self.api.chat(f"autofix_text {base64.b64encode(payload.encode()).decode()}")
        log.write(f"[bold #a855f7]Autofix:[/] {reply}")

    def action_do_snooze(self):
        self.dismiss("snooze")


# ── Snooze modal ───────────────────────────────────────────────────────────────
class SnoozeModal(ModalScreen):
    DEFAULT_CSS = """
    SnoozeModal { align: center middle; }
    #sm-box {
        width: 52; height: auto;
        background: #0d0d0d; border: solid #fcc419; padding: 1 2;
    }
    #sm-title { text-align: center; color: #fcc419; text-style: bold; margin-bottom: 1; }
    #sm-btns  { height: 3; align: center middle; margin-top: 1; }
    .sm-btn   { min-width: 9; margin: 0 1; }
    """
    BINDINGS = [Binding("escape", "dismiss", show=False)]

    def __init__(self, meta):
        super().__init__()
        self.meta = meta

    def compose(self):
        with Vertical(id="sm-box"):
            yield Static(f"[bold]SNOOZE:[/] {self.meta.get('host','?')}", id="sm-title")
            yield Static("Vyberte dobu odložení:", id="sm-label")
            with Horizontal(id="sm-btns"):
                yield Button("1h",     id="sm-1",  classes="sm-btn")
                yield Button("4h",     id="sm-4",  classes="sm-btn")
                yield Button("24h",    id="sm-24", classes="sm-btn")
                yield Button("72h",    id="sm-72", classes="sm-btn")
                yield Button("Zrušit", id="sm-x",  classes="sm-btn")

    def on_button_pressed(self, event):
        h = {"sm-1": 1, "sm-4": 4, "sm-24": 24, "sm-72": 72}
        self.dismiss(h.get(event.button.id))


# ── Log Viewer modal ───────────────────────────────────────────────────────────
class LogViewerModal(ModalScreen):
    DEFAULT_CSS = """
    LogViewerModal { align: center middle; }
    #lv-box {
        width: 99%; height: 92%;
        background: #0d0d0d; border: solid #333333; layout: vertical;
    }
    #lv-title {
        height: 1; background: #003d7a; color: #ffffff;
        padding: 0 1; text-style: bold;
    }
    #lv-split { height: 1fr; layout: horizontal; }
    #lv-files {
        width: 32; border-right: solid #444444;
        background: #050505;
    }
    #lv-files > .datatable--header {
        background: #003d7a; color: #4fc1ff; text-style: bold;
    }
    #lv-files > .datatable--cursor {
        background: #fcc419; color: #000000; text-style: bold;
    }
    #lv-right { width: 1fr; layout: vertical; }
    #lv-toolbar {
        height: 1; background: #111111;
        layout: horizontal; padding: 0 1;
    }
    #lv-search {
        width: 1fr; height: 1; background: #111111;
        color: #4fc1ff; border: none; padding: 0 1;
    }
    #lv-stat {
        width: 18; color: #888888;
        content-align: right middle; padding: 0 1;
    }
    #lv-content { height: 1fr; background: #000000; color: #cccccc; }
    #lv-footer  {
        height: 1; background: #1a1a1a; color: #888888; padding: 0 1;
    }
    """
    BINDINGS = [
        Binding("escape", "dismiss", show=False),
        Binding("r",      "reload",  "Reload"),
        Binding("enter",  "open_sel","Otevřít"),
    ]

    def __init__(self, api):
        super().__init__()
        self.api     = api
        self._files  = []
        self._sel    = None
        self._filter = ""

    def compose(self):
        with Vertical(id="lv-box"):
            yield Static(
                "[bold]LOG VIEWER[/]  ↑↓:soubor  Enter:otevřít  Filtr:search  R:reload  Esc:zavřít",
                id="lv-title",
            )
            with Horizontal(id="lv-split"):
                yield DataTable(id="lv-files", cursor_type="row", show_header=True)
                with Vertical(id="lv-right"):
                    with Horizontal(id="lv-toolbar"):
                        yield Input(placeholder="Filtr řádků obsahu...", id="lv-search")
                        yield Static("", id="lv-stat")
                    yield Log(id="lv-content")
            yield Static(
                "[bold]↑↓[/]:výběr souboru  [bold]Enter[/]:otevřít  [bold]Tab[/]:přepnout panel  [bold]R[/]:reload  [bold]Esc[/]:zavřít",
                id="lv-footer",
            )

    async def on_mount(self):
        t = self.query_one("#lv-files", DataTable)
        t.add_columns("SOUBOR", "VELIKOST", "DATUM")
        await self._load_files()

    async def _load_files(self):
        t = self.query_one("#lv-files", DataTable)
        t.clear()
        self._files = await self.api.get_log_list()
        if not self._files:
            return
        for f in self._files:
            name  = f.get("name", "?")
            size  = f.get("size", "") or ""
            mtime = (f.get("mtime", "") or "")[:16]
            t.add_row(name, size, mtime)
        t.focus()

    async def _load_content(self, filename):
        self._sel = filename
        log  = self.query_one("#lv-content", Log)
        stat = self.query_one("#lv-stat", Static)
        log.clear()
        stat.update("Načítám...")
        content = await self.api.get_log_content(filename)
        if not content:
            log.write("[red]Chyba načítání nebo prázdný soubor[/]")
            stat.update("Chyba")
            return
        lines = content.splitlines()
        filt  = self._filter.lower()
        shown = 0
        for line in lines[-2000:]:
            if not filt or filt in line.lower():
                log.write(line)
                shown += 1
        stat.update(f"{shown}/{len(lines)} ř.")

    async def action_open_sel(self):
        t   = self.query_one("#lv-files", DataTable)
        idx = t.cursor_row
        if 0 <= idx < len(self._files):
            await self._load_content(self._files[idx]["name"])

    async def action_reload(self):
        if self._sel:
            await self._load_content(self._sel)
        else:
            await self._load_files()

    async def on_input_changed(self, event):
        if event.input.id == "lv-search":
            self._filter = event.value
            if self._sel:
                await self._load_content(self._sel)


# ── Agent Manager modal ────────────────────────────────────────────────────────
class AgentManagerModal(ModalScreen):
    DEFAULT_CSS = """
    AgentManagerModal { align: center middle; }
    #am-box {
        width: 97%; height: 88%;
        background: #0d0d0d; border: solid #107c10; layout: vertical;
    }
    #am-title {
        height: 1; background: #0a3d0a; color: #ffffff;
        padding: 0 1; text-style: bold;
    }
    #am-table {
        height: 1fr; background: #000000; color: #dddddd;
    }
    #am-table > .datatable--header {
        background: #0a3d0a; color: #4ade80; text-style: bold;
    }
    #am-table > .datatable--cursor {
        background: #107c10; color: #ffffff;
    }
    #am-footer {
        height: 1; background: #1a1a1a; color: #888888; padding: 0 1;
    }
    """
    BINDINGS = [
        Binding("escape", "dismiss", show=False),
        Binding("r", "reload", "Reload"),
    ]

    def __init__(self, api):
        super().__init__()
        self.api = api

    def compose(self):
        with Vertical(id="am-box"):
            yield Static("[bold]SPRÁVA AGENTŮ[/]  R:reload  Esc:zavřít", id="am-title")
            yield DataTable(id="am-table", cursor_type="row")
            yield Static("", id="am-footer")

    async def on_mount(self):
        t = self.query_one("#am-table", DataTable)
        t.add_columns("HOSTNAME", "STATUS", "POSLEDNÍ HB", "ISSUES", "VERZE")
        await self._load()
        t.focus()

    async def _load(self):
        t      = self.query_one("#am-table", DataTable)
        footer = self.query_one("#am-footer", Static)
        t.clear()
        agents = await self.api.get_agents()
        if not agents:
            footer.update("[dim]Žádní agenti registrováni[/]")
            return
        online = 0
        for a in agents:
            host    = a.get("hostname", "?")
            status  = (a.get("status") or "unknown").upper()
            hb      = (a.get("last_heartbeat") or "N/A").replace("T", " ").split(".")[0]
            issues  = str(a.get("issue_count", 0))
            ver     = a.get("agent_version", "?") or "?"
            st = Text(f" {status[:7]} ")
            if status == "ONLINE":
                st.stylize("bold white on #107c10"); online += 1
            elif status == "OFFLINE":
                st.stylize("bold white on #c50f1f")
            else:
                st.stylize("bold black on #555555")
            t.add_row(host, st, hb, issues, ver)
        footer.update(
            f"Celkem: [bold]{len(agents)}[/]  "
            f"Online: [bold #40c057]{online}[/]  "
            f"Offline: [bold #c50f1f]{len(agents)-online}[/]"
        )

    async def action_reload(self):
        await self._load()


# ── Pending Actions modal ──────────────────────────────────────────────────────
class PendingActionsModal(ModalScreen):
    DEFAULT_CSS = """
    PendingActionsModal { align: center middle; }
    #pa-box {
        width: 97%; height: 88%;
        background: #0d0d0d; border: solid #a855f7; layout: vertical;
    }
    #pa-title {
        height: 1; background: #3b0764; color: #ffffff;
        padding: 0 1; text-style: bold;
    }
    #pa-table {
        height: 1fr; background: #000000; color: #dddddd;
    }
    #pa-table > .datatable--header {
        background: #3b0764; color: #d8b4fe; text-style: bold;
    }
    #pa-table > .datatable--cursor {
        background: #6b21a8; color: #ffffff;
    }
    #pa-footer {
        height: 1; background: #1a1a1a; color: #888888; padding: 0 1;
    }
    """
    BINDINGS = [
        Binding("escape", "dismiss", show=False),
        Binding("r", "reload",   "Reload"),
        Binding("e", "do_exec",  "Execute"),
        Binding("x", "do_reject","Reject"),
    ]

    def __init__(self, api):
        super().__init__()
        self.api      = api
        self._actions = []

    def compose(self):
        with Vertical(id="pa-box"):
            yield Static(
                "[bold]AI NÁVRHY AKCÍ[/]  e:Execute  x:Reject  r:Reload  Esc:zavřít",
                id="pa-title",
            )
            yield DataTable(id="pa-table", cursor_type="row")
            yield Static("", id="pa-footer")

    async def on_mount(self):
        t = self.query_one("#pa-table", DataTable)
        t.add_columns("#", "NODE", "PŘÍKAZ", "RISK", "DŮVOD")
        await self._load()
        t.focus()

    async def _load(self):
        t      = self.query_one("#pa-table", DataTable)
        footer = self.query_one("#pa-footer", Static)
        t.clear()
        self._actions = await self.api.get_pending_actions()
        if not self._actions:
            footer.update("[dim #40c057]Žádné čekající AI návrhy akcí[/]")
            return
        for idx, a in enumerate(self._actions):
            node   = a.get("node", "?")
            cmd    = (a.get("command") or "?")[:55]
            risk   = a.get("risk_score", 0)
            reason = (a.get("reason") or "")[:45]
            rt = Text(f" {risk:3d} ")
            if risk >= 70:   rt.stylize("bold white on #c50f1f")
            elif risk >= 40: rt.stylize("bold black on #fcc419")
            else:            rt.stylize("bold white on #107c10")
            t.add_row(str(idx + 1), node, cmd, rt, reason)
        footer.update(
            f"{len(self._actions)} čekajících  |  "
            "[bold](e)[/]Execute  [bold](x)[/]Reject  [bold](r)[/]Reload"
        )

    async def action_reload(self):
        await self._load()

    async def action_do_exec(self):
        t = self.query_one("#pa-table", DataTable)
        footer = self.query_one("#pa-footer", Static)
        idx = t.cursor_row
        if 0 <= idx < len(self._actions):
            a   = self._actions[idx]
            aid = a.get("id")
            if aid is None:
                return
            footer.update(f"[yellow]Spouštím #{idx+1}...[/]")
            res = await self.api.execute_action(aid, a.get("node", ""), a.get("command", ""))
            footer.update(f"[bold #40c057]Výsledek: {res.get('status','?')}[/]")
            await self._load()

    async def action_do_reject(self):
        t = self.query_one("#pa-table", DataTable)
        idx = t.cursor_row
        if 0 <= idx < len(self._actions):
            aid = self._actions[idx].get("id")
            if aid is not None:
                await self.api.reject_action(aid)
                await self._load()

    async def on_data_table_row_selected(self, event):
        await self.action_do_exec()


# ── Predictions modal ──────────────────────────────────────────────────────────
class PredictionsModal(ModalScreen):
    DEFAULT_CSS = """
    PredictionsModal { align: center middle; }
    #pm-box {
        width: 85%; height: 82%;
        background: #0d0d0d; border: solid #fcc419; layout: vertical;
    }
    #pm-title {
        height: 1; background: #4a3500; color: #fcc419;
        padding: 0 1; text-style: bold;
    }
    #pm-scroll { height: 1fr; background: #000000; }
    #pm-body   { padding: 1 2; color: #cccccc; }
    #pm-footer {
        height: 1; background: #1a1a1a; color: #888888; padding: 0 1;
    }
    """
    BINDINGS = [
        Binding("escape", "dismiss", show=False),
        Binding("r", "reload", "Reload"),
    ]

    def __init__(self, api):
        super().__init__()
        self.api = api

    def compose(self):
        with Vertical(id="pm-box"):
            yield Static("[bold]PREDIKCE & TRENDY (AI, 7 dní)[/]  r:reload  Esc:zavřít", id="pm-title")
            with ScrollableContainer(id="pm-scroll"):
                yield Static("[dim]Načítám...[/]", id="pm-body")
            yield Static("", id="pm-footer")

    async def on_mount(self):
        await self._load()

    async def _load(self):
        body   = self.query_one("#pm-body", Static)
        footer = self.query_one("#pm-footer", Static)
        footer.update("[dim]Načítám AI trend report...[/]")
        report = await self.api.ai_trend_report(7)
        body.update(report)
        footer.update("[dim]AI Trend Report (7 dní)  |  r:Obnovit  Esc:Zavřít[/]")

    async def action_reload(self):
        await self._load()


# ── Main App ───────────────────────────────────────────────────────────────────
class SentinelConsole(App):
    """Sentinel TUI v3.0 — HTOP style."""

    CSS = """
    Screen {
        layout: vertical;
        background: #0d0d0d;
    }
    #header {
        height: 1; background: #003d7a; color: #ffffff;
        padding: 0 1; content-align: left middle;
    }
    #gauges {
        height: 2; background: #0d0d0d;
        padding: 0 1; border-bottom: solid #1c1c1c;
    }
    #g1 { height: 1; }
    #g2 { height: 1; }
    #ch-bar {
        height: 1; background: #111111;
        border-bottom: solid #333333; layout: horizontal;
    }
    .ch-tab {
        height: 1; width: auto;
        background: #111111; color: #555555;
        padding: 0 2; content-align: center middle;
    }
    .ch-tab.ch-active {
        background: #fcc419; color: #000000;
        text-style: bold; padding: 0 2;
    }
    #sort-label {
        height: 1; width: 1fr;
        background: #111111; color: #666666;
        content-align: right middle; padding: 0 1;
    }
    #filter-input {
        height: 1; background: #111111; color: #4fc1ff;
        border: none; padding: 0 1; display: none;
    }
    #main-area {
        height: 1fr; layout: horizontal;
    }
    #side-panel {
        width: 26; background: #080808;
        border-right: solid #1e1e1e;
    }
    .side-hdr {
        height: 1; background: #1a1a2e;
        color: #4fc1ff; padding: 0 1; text-style: bold;
    }
    .side-item {
        height: 1; color: #999999; padding: 0 1 0 3;
    }
    .side-item:hover { background: #1a1a2e; color: #ffffff; }
    #table-area {
        width: 1fr; layout: vertical;
    }
    #bulk-bar {
        height: 1; background: #003d7a; color: #4fc1ff;
        padding: 0 1; display: none;
    }
    DataTable {
        height: 1fr; background: #000000; color: #dddddd;
    }
    DataTable > .datatable--header {
        background: #1a1a2e; color: #4fc1ff; text-style: bold;
    }
    DataTable > .datatable--cursor {
        background: #003d7a; color: #ffffff; text-style: bold;
    }
    DataTable > .datatable--hover { background: #0d1117; }
    #chat-area {
        height: 9; border-top: solid #2a2a2a; layout: vertical;
    }
    #chat-log  { height: 1fr; background: #000000; color: #cccccc; }
    #cmd-input {
        height: 1; background: #111111; color: #4fc1ff;
        border: none; padding: 0 1;
    }
    #footer-bar {
        height: 1; background: #1a1a1a; color: #777777; padding: 0 1;
    }

    /* Class-driven visibility */
    Screen.hide-side   #side-panel    { display: none; }
    Screen.hide-chat   #chat-area     { display: none; }
    Screen.show-filter #filter-input  { display: block; }
    Screen.bulk-mode   #bulk-bar      { display: block; }
    """

    BINDINGS = [
        Binding("f1",       "help",          "Help",    show=False),
        Binding("question", "help",          "Help",    show=False),
        Binding("f10",      "quit",          "Quit",    show=False),
        Binding("q",        "quit",          "Quit",    show=False),
        Binding("r",        "refresh",       "Refresh", show=False),
        Binding("f5",       "refresh",       "Refresh", show=False),
        # Channels
        Binding("tab",        "next_ch",   "Další kanál", show=False),
        Binding("shift+tab",  "prev_ch",   "Předchozí",   show=False),
        Binding("1",          "ch_all",    "ALL",  show=False),
        Binding("2",          "ch_infra",  "INFRA",show=False),
        Binding("3",          "ch_agent",  "AGENT",show=False),
        Binding("4",          "ch_root",   "ROOT", show=False),
        Binding("5",          "ch_sec",    "SEC",  show=False),
        # Filter / Sort
        Binding("slash",      "toggle_filter", "Filter", show=False),
        Binding("f2",         "toggle_filter", "Filter", show=False),
        Binding("o",          "toggle_sort",   "Sort",   show=False),
        Binding("f3",         "toggle_sort",   "Sort",   show=False),
        Binding("escape",     "do_escape",     "Esc",    show=False),
        # Issue actions
        Binding("enter",      "issue_detail",  "Detail",     show=False),
        Binding("i",          "do_ignore",     "Ignorovat",  show=False),
        Binding("d",          "do_delete",     "Smazat",     show=False),
        Binding("f",          "do_autofix",    "Autofix",    show=False),
        Binding("a",          "do_ack",        "Ack",        show=False),
        Binding("s",          "do_snooze",     "Snooze",     show=False),
        # Bulk
        Binding("space",      "bulk_toggle",  "Select",  show=False),
        Binding("ctrl+a",     "bulk_all",     "Sel All", show=False),
        Binding("I",          "bulk_ignore",  "BIgnore", show=False),
        Binding("D",          "bulk_delete",  "BDelete", show=False),
        Binding("A",          "bulk_ack",     "BAck",    show=False),
        # Views
        Binding("c",          "toggle_chat",  "Chat",    show=False),
        Binding("p",          "toggle_side",  "Panel",   show=False),
        Binding("l",          "open_logs",    "Logy",    show=False),
        Binding("g",          "open_agents",  "Agenti",  show=False),
        Binding("n",          "open_actions", "Návrhy",  show=False),
        Binding("t",          "open_trends",  "Trendy",  show=False),
        Binding("x",          "ai_summary",   "AI Sum",  show=False),
        Binding("z",          "ai_correlate", "AI Kor",  show=False),
    ]

    def __init__(self, api):
        super().__init__()
        self.api            = api
        self._all_issues    = []
        self._row_meta      = []
        self._channel       = "ALL"
        self._filter        = ""
        self._sort_mode     = "TIME"
        self._sort_idx      = 0
        self._bulk_sel      = set()
        self._bulk_mode     = False
        self._show_filter   = False
        self._show_chat     = True
        self._show_side     = True
        self._auth_locked   = False

    def compose(self):
        yield Static("", id="header")
        with Vertical(id="gauges"):
            yield Static("", id="g1")
            yield Static("", id="g2")
        with Horizontal(id="ch-bar"):
            for ch in CHANNELS:
                yield Static(f" {ch} ", id=f"ch-{ch}", classes="ch-tab")
            yield Static("", id="sort-label")
        yield Input(placeholder="Filter (host / zpráva / plugin / klíč)...", id="filter-input")
        with Horizontal(id="main-area"):
            with Vertical(id="side-panel"):
                yield Static("RYCHLÉ AKCE",           classes="side-hdr")
                yield Static("(l) Log Viewer",         classes="side-item")
                yield Static("(g) Správa agentů",      classes="side-item")
                yield Static("(n) AI Návrhy akcí",     classes="side-item")
                yield Static("(t) Predikce / Trendy",  classes="side-item")
                yield Static("(x) AI Batch Souhrn",    classes="side-item")
                yield Static("(z) AI Korelace",        classes="side-item")
                yield Static("─" * 24,                 classes="side-hdr")
                yield Static("ISSUE AKCE",             classes="side-hdr")
                yield Static("(i) Ignorovat",          classes="side-item")
                yield Static("(d) Smazat",             classes="side-item")
                yield Static("(f) AI Autofix",         classes="side-item")
                yield Static("(a) Acknowledge",        classes="side-item")
                yield Static("(s) Snooze",             classes="side-item")
                yield Static("─" * 24,                 classes="side-hdr")
                yield Static("BULK AKCE",              classes="side-hdr")
                yield Static("Space  toggle výběr",    classes="side-item")
                yield Static("Ctrl+A vybrat vše",      classes="side-item")
                yield Static("(I) Bulk Ignore",        classes="side-item")
                yield Static("(D) Bulk Delete",        classes="side-item")
                yield Static("(A) Bulk Ack",           classes="side-item")
                yield Static("─" * 24,                 classes="side-hdr")
                yield Static("KANÁLY",                 classes="side-hdr")
                yield Static("1 ALL   2 INFRA",        classes="side-item")
                yield Static("3 AGENT 4 ROOT",         classes="side-item")
                yield Static("5 SEC   Tab/S+Tab",      classes="side-item")
            with Vertical(id="table-area"):
                yield Static("", id="bulk-bar")
                yield DataTable(id="issues-table", cursor_type="row")
        with Vertical(id="chat-area"):
            yield Log(id="chat-log")
            yield Input(placeholder="AI chat — dotaz nebo příkaz...", id="cmd-input")
        yield Static("", id="footer-bar")

    async def on_mount(self):
        t = self.query_one("#issues-table", DataTable)
        t.add_columns("★", "ČAS", "SEV", "CH", "HOST", "ZPRÁVA")
        self._update_header("Přihlašuji...")
        self._update_footer()
        self._update_ch_bar()

        ok = await self.api.login()
        if not ok:
            self._auth_locked = True
            self._update_header("⛔ PŘIHLÁŠENÍ SELHALO — zkontroluj config")
            return

        self.set_interval(POLL_SEC, self._poll)
        await self._poll()
        self.query_one("#issues-table", DataTable).focus()

    # ── Polling ───────────────────────────────────────────────────────────────

    async def _poll(self):
        if self._auth_locked:
            return
        issues = await self.api.get_issues()
        if issues is not None:
            self._all_issues = issues
        self._render_table()
        self._update_gauges()
        self._update_header()

    # ── Rendering helpers ─────────────────────────────────────────────────────

    def _filtered(self):
        issues = [i for i in self._all_issues
                  if issue_in_channel(i, self._channel)
                  and issue_matches(i, self._filter)]
        return sort_issues(issues, self._sort_mode)

    def _render_table(self):
        t   = self.query_one("#issues-table", DataTable)
        cur = t.cursor_row
        t.clear()
        self._row_meta.clear()

        for issue in self._filtered():
            key     = issue.get("key", "")
            ts      = (issue.get("last_seen", "N/A")).replace("T", " ").split(".")[0][-16:]
            sev_raw = (issue.get("severity") or "WARN").upper()
            ch_raw  = channel_of(issue)
            host    = issue.get("host", "?")
            msg     = (issue.get("last_line") or "")[:80]
            occ     = issue.get("occurrence_count", 1) or 1
            acked   = bool(issue.get("acknowledged_by"))

            if key in self._bulk_sel:
                star = Text("[✓]"); star.stylize("bold white on #005faf")
            elif acked:
                star = Text("ACK"); star.stylize("bold #40c057")
            elif occ > 1:
                star = Text(f"×{occ}"); star.stylize("dim")
            else:
                star = Text("   ")

            self._row_meta.append({
                "key": key, "host": host, "message": msg,
                "channel": ch_raw, "sev": sev_raw, "acked": acked,
            })
            t.add_row(star, ts, make_sev_text(sev_raw), make_ch_text(ch_raw), host, msg)

        if self._filtered() and cur < t.row_count:
            try:
                t.move_cursor(row=cur)
            except Exception:
                pass

    def _update_gauges(self):
        iss = self._all_issues
        c   = {
            "INFRA": sum(1 for i in iss if channel_of(i) not in ("AGENT","ROOT","SECURITY")),
            "AGENT": sum(1 for i in iss if channel_of(i) == "AGENT"),
            "ROOT":  sum(1 for i in iss if channel_of(i) == "ROOT"),
            "SEC":   sum(1 for i in iss if channel_of(i) == "SECURITY"),
        }
        total   = len(iss)
        mx      = max(max(c.values(), default=1), 1)
        self.query_one("#g1", Static).update(
            f"  {gauge_bar('INFRA', c['INFRA'], mx)}    "
            f"{gauge_bar('AGENT', c['AGENT'], mx)}"
        )
        self.query_one("#g2", Static).update(
            f"  {gauge_bar('ROOT',  c['ROOT'],  mx)}    "
            f"{gauge_bar('SEC',   c['SEC'],   mx)}"
            f"    [bold]TOTAL:[/] {total}"
        )

    def _update_header(self, status=""):
        iss   = self._all_issues
        sec   = sum(1 for i in iss if channel_of(i) in ("SECURITY","ROOT"))
        total = len(iss)
        filt  = len(self._filtered())

        if self._auth_locked:
            state = "[bold white on #c50f1f] ⛔ AUTH ERROR [/]"
        elif status:
            state = f"[dim]{status}[/]"
        elif sec > 0:
            state = "[bold white on #c50f1f] CRITICAL [/]"
        elif total > 0:
            state = "[bold black on #fcc419] WARNING [/]"
        else:
            state = "[bold white on #107c10] OK [/]"

        ch_col = {"ROOT": "#fcc419", "SEC": "#c50f1f"}.get(self._channel, "#4fc1ff")
        user   = self.api.username.upper()
        url    = self.api.base_url

        hdr = (
            f"[bold white]SENTINEL TUI {VERSION}[/]  {state}"
            f"  |  [bold {ch_col}]{self._channel}[/]"
            f"  |  Sort:[bold]{self._sort_mode}[/]"
            f"  |  Issues: [bold]{filt}[/]/{total}"
            f"  |  [bold #888888]{user}[/]"
            f"  |  [dim]{url}[/]"
        )
        if self._filter:
            hdr += f"  |  Filter:[bold yellow]{self._filter}[/]"
        if self._bulk_mode and self._bulk_sel:
            hdr += f"  |  [bold #4fc1ff]Vybráno: {len(self._bulk_sel)}[/]"
        self.query_one("#header", Static).update(hdr)

    def _update_ch_bar(self):
        for ch in CHANNELS:
            tab = self.query_one(f"#ch-{ch}", Static)
            if ch == self._channel:
                tab.update(Text(f"[{ch}]", style="bold black on #fcc419"))
                tab.styles.background = "#fcc419"
                tab.styles.color = "#000000"
            else:
                tab.update(Text(f" {ch} ", style="dim"))
                tab.styles.background = "#111111"
                tab.styles.color = "#555555"
        self.query_one("#sort-label", Static).update(f"  Sort: {self._sort_mode} ")

    def _update_footer(self):
        self.query_one("#footer-bar", Static).update(
            "[bold]?[/]:Help  [bold]Enter[/]:Detail  [bold]Space[/]:Sel  "
            "[bold]i[/]:Ign  [bold]d[/]:Del  [bold]f[/]:Fix  "
            "[bold]a[/]:Ack  [bold]s[/]:Snooze  "
            "[bold]/[/]:Filter  [bold]o[/]:Sort  [bold]Tab[/]:Kanál  "
            "[bold]l[/]:Logs  [bold]g[/]:Agenti  [bold]n[/]:Návrhy  "
            "[bold]t[/]:Trendy  [bold]x[/]:AI  [bold]c[/]:Chat  "
            "[bold]p[/]:Panel  [bold]q[/]:Quit"
        )

    def _update_bulk_bar(self):
        n = len(self._bulk_sel)
        self.query_one("#bulk-bar", Static).update(
            f"[bold]BULK:[/] {n} vybráno  "
            "[bold](I)[/]Ignore  [bold](D)[/]Delete  [bold](A)[/]Ack  "
            "[bold]Esc[/]:Zrušit výběr  [bold]Ctrl+A[/]:Vše"
        )

    def _sel_meta(self):
        t = self.query_one("#issues-table", DataTable)
        if t.row_count > 0:
            idx = t.cursor_row
            if 0 <= idx < len(self._row_meta):
                return self._row_meta[idx]
        return None

    def _sel_issue(self):
        meta = self._sel_meta()
        if not meta:
            return None
        key = meta.get("key", "")
        for i in self._all_issues:
            if i.get("key", "") == key:
                return i
        return None

    def _set_channel(self, ch):
        self._channel = ch
        self._bulk_sel.clear()
        self._bulk_mode = False
        self.screen.remove_class("bulk-mode")
        self._render_table()
        self._update_gauges()
        self._update_header()
        self._update_ch_bar()

    # ── Actions ───────────────────────────────────────────────────────────────

    def action_help(self):
        self.push_screen(HelpModal())

    async def action_refresh(self):
        if not self._auth_locked:
            await self._poll()

    def action_next_ch(self):
        self._set_channel(CHANNELS[(CHANNELS.index(self._channel) + 1) % len(CHANNELS)])

    def action_prev_ch(self):
        self._set_channel(CHANNELS[(CHANNELS.index(self._channel) - 1) % len(CHANNELS)])

    def action_ch_all(self):   self._set_channel("ALL")
    def action_ch_infra(self): self._set_channel("INFRA")
    def action_ch_agent(self): self._set_channel("AGENT")
    def action_ch_root(self):  self._set_channel("ROOT")
    def action_ch_sec(self):   self._set_channel("SEC")

    def action_toggle_filter(self):
        self._show_filter = not self._show_filter
        if self._show_filter:
            self.screen.add_class("show-filter")
            self.query_one("#filter-input", Input).focus()
        else:
            self.screen.remove_class("show-filter")
            self._filter = ""
            self.query_one("#filter-input", Input).value = ""
            self._render_table()
            self._update_header()
            self.query_one("#issues-table", DataTable).focus()

    def action_toggle_sort(self):
        self._sort_idx  = (self._sort_idx + 1) % len(SORT_MODES)
        self._sort_mode = SORT_MODES[self._sort_idx]
        self._render_table()
        self._update_header()
        self._update_ch_bar()

    def action_do_escape(self):
        if self._bulk_mode:
            self._bulk_sel.clear()
            self._bulk_mode = False
            self.screen.remove_class("bulk-mode")
            self._render_table()
            self._update_header()
        elif self._show_filter:
            self.action_toggle_filter()

    def action_issue_detail(self):
        meta  = self._sel_meta()
        issue = self._sel_issue()
        if not meta or not issue:
            return

        def on_detail(result):
            if result == "refresh":
                self.run_worker(self._poll())
            elif result == "snooze":
                def on_snooze(hours):
                    if hours:
                        async def _do():
                            await self.api.snooze_issue(kb64(meta["key"]), hours)
                            await self._poll()
                        self.run_worker(_do())
                self.push_screen(SnoozeModal(meta), callback=on_snooze)

        self.push_screen(IssueDetailModal(meta, issue, self.api), callback=on_detail)

    async def _do_issue_action(self, action):
        meta = self._sel_meta()
        if not meta:
            return
        key  = meta.get("key", "")
        log  = self.query_one("#chat-log", Log)

        if action == "ignore":
            await self.api.ignore_issue(kb64(key))
            log.write(f"[dim]Ignorováno: {meta['host']}[/]")
        elif action == "delete":
            await self.api.delete_issue(kb64(key))
            log.write(f"[dim]Smazáno: {meta['host']}[/]")
        elif action == "ack":
            if meta.get("acked"):
                await self.api.unacknowledge_issue(kb64(key))
                log.write(f"[bold #888888]Un-ack: {meta['host']}[/]")
            else:
                await self.api.acknowledge_issue(kb64(key))
                log.write(f"[bold #40c057]Ack: {meta['host']}[/]")
        elif action == "autofix":
            _chat_line(log, f"[bold yellow]Autofix: {_esc(meta['host'])}[/]")
            payload = f"{meta['host']}: {meta['message']}"
            reply   = await self.api.chat(f"autofix_text {base64.b64encode(payload.encode()).decode()}")
            _write_chat(log, "◆", "bold magenta", reply)
            _chat_line(log, "[dim]" + "─" * 50 + "[/]")
            return
        await self._poll()

    async def action_do_ignore(self):  await self._do_issue_action("ignore")
    async def action_do_delete(self):  await self._do_issue_action("delete")
    async def action_do_autofix(self): await self._do_issue_action("autofix")
    async def action_do_ack(self):     await self._do_issue_action("ack")

    def action_do_snooze(self):
        meta = self._sel_meta()
        if not meta:
            return

        def on_snooze(hours):
            if hours:
                async def _do():
                    await self.api.snooze_issue(kb64(meta["key"]), hours)
                    await self._poll()
                self.run_worker(_do())

        self.push_screen(SnoozeModal(meta), callback=on_snooze)

    # Bulk
    def action_bulk_toggle(self):
        meta = self._sel_meta()
        if not meta:
            return
        key = meta.get("key", "")
        if not key:
            return
        self._bulk_sel.symmetric_difference_update({key})
        self._bulk_mode = bool(self._bulk_sel)
        if self._bulk_mode:
            self.screen.add_class("bulk-mode")
            self._update_bulk_bar()
        else:
            self.screen.remove_class("bulk-mode")
        self._render_table()
        self._update_header()
        t = self.query_one("#issues-table", DataTable)
        if t.cursor_row < t.row_count - 1:
            t.move_cursor(row=t.cursor_row + 1)

    def action_bulk_all(self):
        self._bulk_sel = {i.get("key", "") for i in self._filtered() if i.get("key")}
        self._bulk_mode = bool(self._bulk_sel)
        self.screen.add_class("bulk-mode")
        self._update_bulk_bar()
        self._render_table()
        self._update_header()

    async def action_bulk_ignore(self):
        if not self._bulk_sel:
            return
        keys = [kb64(k) for k in self._bulk_sel]
        log  = self.query_one("#chat-log", Log)
        n    = await self.api.bulk_ignore(keys)
        log.write(f"[bold]Bulk ignorováno: {n}[/]")
        self._bulk_sel.clear(); self._bulk_mode = False
        self.screen.remove_class("bulk-mode")
        await self._poll()

    async def action_bulk_delete(self):
        if not self._bulk_sel:
            return
        keys = [kb64(k) for k in self._bulk_sel]
        log  = self.query_one("#chat-log", Log)
        n    = await self.api.bulk_delete(keys)
        log.write(f"[bold]Bulk smazáno: {n}[/]")
        self._bulk_sel.clear(); self._bulk_mode = False
        self.screen.remove_class("bulk-mode")
        await self._poll()

    async def action_bulk_ack(self):
        if not self._bulk_sel:
            return
        keys = [kb64(k) for k in self._bulk_sel]
        log  = self.query_one("#chat-log", Log)
        ok   = await self.api.bulk_acknowledge(keys)
        log.write(f"[bold #40c057]Bulk ack: {'OK' if ok else 'chyba'}[/]")
        self._bulk_sel.clear(); self._bulk_mode = False
        self.screen.remove_class("bulk-mode")
        await self._poll()

    # Panels / Modals
    def action_toggle_chat(self):
        self._show_chat = not self._show_chat
        (self.screen.remove_class if self._show_chat else self.screen.add_class)("hide-chat")

    def action_toggle_side(self):
        self._show_side = not self._show_side
        (self.screen.remove_class if self._show_side else self.screen.add_class)("hide-side")

    def action_open_logs(self):
        self.push_screen(LogViewerModal(self.api))

    def action_open_agents(self):
        self.push_screen(AgentManagerModal(self.api))

    def action_open_actions(self):
        self.push_screen(PendingActionsModal(self.api))

    def action_open_trends(self):
        self.push_screen(PredictionsModal(self.api))

    async def action_ai_summary(self):
        log = self.query_one("#chat-log", Log)
        _chat_line(log, f"[bold yellow]AI Souhrn — {self._channel}[/]")
        reply = await self.api.ai_batch_summary(self._channel)
        _write_chat(log, "", "", reply)
        _chat_line(log, "[dim]" + "─" * 50 + "[/]")
        if not self._show_chat:
            self.action_toggle_chat()

    async def action_ai_correlate(self):
        log = self.query_one("#chat-log", Log)
        _chat_line(log, f"[bold yellow]AI Korelace — {self._channel}[/]")
        reply = await self.api.ai_correlate(self._channel)
        _write_chat(log, "", "", reply)
        _chat_line(log, "[dim]" + "─" * 50 + "[/]")
        if not self._show_chat:
            self.action_toggle_chat()

    # ── Input handlers ────────────────────────────────────────────────────────

    async def on_input_changed(self, event):
        if event.input.id == "filter-input":
            self._filter = event.value
            self._render_table()
            self._update_header()

    async def on_input_submitted(self, event):
        inp = event.input
        val = event.value.strip()

        if inp.id == "filter-input":
            self._filter = val
            self._render_table()
            self._update_header()
            return

        if inp.id == "cmd-input":
            if not val:
                return
            inp.value = ""
            log = self.query_one("#chat-log", Log)
            _chat_line(log, f"[bold cyan]» {_esc(val)}[/]")
            reply = await self.api.chat(val)
            reply = re.sub(r"^[🤖\s]*Sentinel\s*\([^)]+\):\s*", "", reply).strip()
            _write_chat(log, "◆", "bold magenta", reply)
            _chat_line(log, "[dim]" + "─" * 50 + "[/]")
            await self._poll()

    async def on_unmount(self):
        await self.api.close()


# ── Entry point ────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    url, user, pw = load_config()
    api = APIClient(url, user, pw)
    SentinelConsole(api).run()
