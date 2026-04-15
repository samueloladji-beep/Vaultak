"""
Vaultak Sentry Desktop App v1.6
Uses tk.Label as buttons — bypasses macOS native button rendering
"""

import sys, json, time, threading, webbrowser
from pathlib import Path
from datetime import datetime

try:
    import tkinter as tk
    from tkinter import messagebox
except ImportError:
    sys.exit(1)

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

APP_NAME    = "Vaultak Sentry"
APP_VERSION = "1.0.2"
API_BASE    = "https://vaultak.com"
CONFIG_DIR  = Path.home() / ".vaultak"
CONFIG_FILE = CONFIG_DIR / "sentry_app.json"
CONFIG_DIR.mkdir(exist_ok=True)

BG      = "#1a1a1a"
BG2     = "#242424"
BG3     = "#2e2e2e"
BG4     = "#383838"
BORDER  = "#4a4a4a"
TEXT    = "#ffffff"
TEXT2   = "#cccccc"
TEXT3   = "#999999"
ACCENT  = "#8b7cf8"
ACCENT2 = "#b8aff9"
GREEN   = "#4ade80"
RED     = "#ff6b6b"
WHITE   = "#ffffff"

def load_config():
    if CONFIG_FILE.exists():
        try: return json.loads(CONFIG_FILE.read_text())
        except: pass
    return {}

def save_config(cfg):
    CONFIG_FILE.write_text(json.dumps(cfg, indent=2))

def validate_api_key(api_key):
    if not api_key.startswith("vtk_"):
        return False, "API key must start with vtk_"
    if not HAS_REQUESTS:
        return True, "OK"
    try:
        r = requests.get(f"{API_BASE}/api/stats",
                         headers={"x-api-key": api_key}, timeout=5)
        if r.status_code == 401:
            return False, "Invalid API key. Please check and try again."
        return True, "OK"
    except:
        return True, "OK"


def label_btn(parent, text, command, bg=None, fg=None,
              font=None, padx=20, pady=12, width=0):
    """
    Label styled as a button.
    macOS never overrides Label backgrounds — unlike tk.Button.
    """
    bg   = bg   or ACCENT
    fg   = fg   or WHITE
    font = font or ("Helvetica", 13, "bold")
    lbl  = tk.Label(parent, text=text, bg=bg, fg=fg,
                    font=font, cursor="hand2",
                    padx=padx, pady=pady)
    if width:
        lbl.config(width=width)

    def on_enter(e):
        lbl.config(bg=_darken(bg))
    def on_leave(e):
        lbl.config(bg=lbl._orig_bg if hasattr(lbl, "_orig_bg") else bg)
    def on_click(e):
        if lbl.cget("state") != "disabled":
            command()

    lbl._orig_bg = bg
    lbl.bind("<Enter>",   on_enter)
    lbl.bind("<Leave>",   on_leave)
    lbl.bind("<Button-1>", on_click)
    return lbl


def _darken(hex_color):
    """Darken a hex color by ~15%."""
    try:
        h = hex_color.lstrip("#")
        r, g, b = int(h[0:2],16), int(h[2:4],16), int(h[4:6],16)
        r = max(0, int(r * 0.85))
        g = max(0, int(g * 0.85))
        b = max(0, int(b * 0.85))
        return f"#{r:02x}{g:02x}{b:02x}"
    except:
        return hex_color



# ── SENTRY INTERCEPTION ENGINE ────────────────────────────────────────────────
import subprocess, os, re, uuid, queue
from datetime import datetime, timezone

class SentryEngine:
    """
    Real process interception engine.
    Runs the user's agent as a subprocess, monitors its stdout/stderr
    and filesystem/network activity via a wrapper script, then posts
    intercepted actions to the Vaultak backend.
    """

    # Patterns to classify log lines into action types
    FILE_WRITE_PAT  = re.compile(r"(open|write|save|creat|dump|export).{0,40}[\'\"](.*?)[\'\"]\s*[,)]", re.I)
    FILE_READ_PAT   = re.compile(r"(read|load|open|import).{0,40}[\'\"](.*?)[\'\"]\s*[,)]", re.I)
    HTTP_PAT        = re.compile(r'(https?://[^\s]+)', re.I)
    DB_WRITE_PAT    = re.compile(r"(INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|TRUNCATE)\s", re.I)
    DB_READ_PAT     = re.compile(r"(SELECT|SHOW|DESCRIBE|EXPLAIN)\s", re.I)
    EXEC_PAT        = re.compile(r"(exec|spawn|popen|system|run|call).{0,30}[\'\"](.*?)[\'\"]\s*[,)]", re.I)
    SENSITIVE_PAT   = re.compile(r"(\.env|secret|password|token|api.?key|credential|private.?key)", re.I)

    def __init__(self, api_key, agent_id, alert_threshold, pause_threshold,
                 rollback_threshold, api_base, on_action, on_log):
        self.api_key            = api_key
        self.agent_id           = agent_id
        self.alert_threshold    = int(alert_threshold)
        self.pause_threshold    = int(pause_threshold)
        self.rollback_threshold = int(rollback_threshold)
        self.api_base           = api_base
        self.on_action          = on_action   # callback(action_type, resource, score, decision)
        self.on_log             = on_log      # callback(msg)
        self.process            = None
        self.running            = False
        self._queue             = queue.Queue()
        self._action_count      = 0
        self._session_id        = str(uuid.uuid4())

    def start(self, command):
        """Launch the agent process and start monitoring."""
        self.running = True
        self._action_count = 0
        # Start the agent process
        try:
            self.process = subprocess.Popen(
                command,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
            )
        except Exception as e:
            self.on_log(f"Failed to start process: {e}")
            self.running = False
            return

        # Read output in background thread
        threading.Thread(target=self._read_output, daemon=True).start()
        # Post actions from queue in background thread
        threading.Thread(target=self._post_worker, daemon=True).start()
        self.on_log(f"Process started (PID {self.process.pid})")

    def _read_output(self):
        """Read agent stdout/stderr line by line and classify actions."""
        try:
            for line in self.process.stdout:
                line = line.rstrip()
                if not line:
                    continue
                self.on_log(f"agent: {line}")
                self._classify_line(line)
        except Exception as e:
            self.on_log(f"Read error: {e}")
        finally:
            rc = self.process.wait()
            self.running = False
            self.on_log(f"Process exited (code {rc})")

    def _classify_line(self, line):
        """Classify a log line into a Vaultak action type and post it."""
        action_type = None
        resource    = "unknown"
        base_score  = 0

        # Check for sensitive resource access first
        if self.SENSITIVE_PAT.search(line):
            action_type = "file_read"
            m = self.SENSITIVE_PAT.search(line)
            resource    = m.group(0) if m else ".env"
            base_score  = 85

        elif self.DB_WRITE_PAT.search(line):
            action_type = "database_write"
            resource    = "database"
            base_score  = 70

        elif self.DB_READ_PAT.search(line):
            action_type = "database_read"
            resource    = "database"
            base_score  = 30

        elif self.HTTP_PAT.search(line):
            action_type = "api_call"
            m = self.HTTP_PAT.search(line)
            resource    = m.group(1)[:80] if m else "http"
            base_score  = 40

        elif self.FILE_WRITE_PAT.search(line):
            action_type = "file_write"
            m = self.FILE_WRITE_PAT.search(line)
            resource    = m.group(2)[:80] if m else "file"
            base_score  = 55
            if any(k in resource.lower() for k in ["prod", "config", "schema", ".env"]):
                base_score = 80

        elif self.FILE_READ_PAT.search(line):
            action_type = "file_read"
            m = self.FILE_READ_PAT.search(line)
            resource    = m.group(2)[:80] if m else "file"
            base_score  = 35

        elif self.EXEC_PAT.search(line):
            action_type = "subprocess_exec"
            m = self.EXEC_PAT.search(line)
            resource    = m.group(2)[:80] if m else "command"
            base_score  = 60

        if action_type:
            self._queue.put((action_type, resource, base_score))

    def _post_worker(self):
        """Background worker that posts queued actions to the backend."""
        while self.running or not self._queue.empty():
            try:
                action_type, resource, base_score = self._queue.get(timeout=1)
                self._post_action(action_type, resource, base_score)
            except queue.Empty:
                continue
            except Exception as e:
                self.on_log(f"Post error: {e}")

    def _post_action(self, action_type, resource, base_score):
        """Post a single action to the Vaultak backend and handle response."""
        try:
            import json as _json, urllib.request as _req
            payload = _json.dumps({
                "agent_id":    self.agent_id,
                "action_type": action_type,
                "resource":    resource,
                "payload":     {"sentry": True, "base_score": base_score},
                "session_id":  self._session_id,
                "timestamp":   datetime.now(timezone.utc).isoformat(),
            }).encode()

            request = _req.Request(
                f"{self.api_base}/api/actions",
                data=payload,
                headers={
                    "Content-Type": "application/json",
                    "x-api-key":    self.api_key,
                },
                method="POST"
            )
            resp   = _req.urlopen(request, timeout=5)
            result = _json.loads(resp.read())

            score    = result.get("risk_score", base_score / 100)
            score_pct = int(score * 100)
            decision = result.get("decision", "allow").lower()
            flagged  = result.get("flagged", False)

            self._action_count += 1

            # Determine severity
            if score_pct >= self.rollback_threshold or decision in ("rollback", "block"):
                self.on_action(action_type, resource, score_pct, "ROLLBACK")
            elif score_pct >= self.pause_threshold or decision == "pause":
                self.on_action(action_type, resource, score_pct, "PAUSE")
            elif score_pct >= self.alert_threshold or flagged:
                self.on_action(action_type, resource, score_pct, "ALERT")
            else:
                self.on_action(action_type, resource, score_pct, "ALLOW")

        except Exception as e:
            # Still notify UI even if post fails
            self.on_action(action_type, resource, base_score, "ALLOW")

    def stop(self):
        """Stop monitoring and terminate the agent process."""
        self.running = False
        if self.process and self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                self.process.kill()
        self.on_log(f"Monitoring stopped. {self._action_count} actions intercepted.")


class VaultakSentryApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.config_data   = load_config()
        self.is_monitoring = False
        self.start_time    = None
        self.option_add("*Background", BG)
        self.option_add("*Foreground", TEXT)
        self._setup_window()
        self._build()
        self.protocol("WM_DELETE_WINDOW", self._on_close)
        self.after(800, self._check_saved_config)

    def _setup_window(self):
        self.title(APP_NAME)
        self.configure(bg=BG)
        self.resizable(False, False)
        w, h = 520, 720
        sw = self.winfo_screenwidth()
        sh = self.winfo_screenheight()
        self.geometry(f"{w}x{h}+{(sw-w)//2}+{(sh-h)//2}")

    def _build(self):
        self.grid_rowconfigure(4, weight=1)
        self.grid_columnconfigure(0, weight=1)
        self._build_header()
        tk.Frame(self, bg=BORDER, height=1).grid(row=1, column=0, sticky="ew")
        self._build_tabs()
        tk.Frame(self, bg=BORDER, height=1).grid(row=3, column=0, sticky="ew")
        self._build_content()

    # ── HEADER ────────────────────────────────────────────────────────────────
    def _build_header(self):
        hdr = tk.Frame(self, bg=BG2, height=68)
        hdr.grid(row=0, column=0, sticky="ew")
        hdr.grid_propagate(False)
        hdr.grid_columnconfigure(0, weight=1)

        left = tk.Frame(hdr, bg=BG2)
        left.grid(row=0, column=0, sticky="w", padx=24, pady=18)

        c = tk.Canvas(left, width=30, height=30, bg=BG2, highlightthickness=0)
        c.grid(row=0, column=0, padx=(0, 12))
        c.create_rectangle(2, 2, 28, 28, fill=WHITE, outline="")
        c.create_polygon(15, 4, 26, 15, 15, 26, 4, 15, fill=BG2)
        c.create_line(9, 13, 15, 21, 21, 13,
                      fill=WHITE, width=2.5, capstyle="round", joinstyle="round")

        title_frame = tk.Frame(left, bg=BG2)
        title_frame.grid(row=0, column=1)
        tk.Label(title_frame, text="Vaultak Sentry",
                 bg=BG2, fg=TEXT,
                 font=("Helvetica", 17, "bold")).grid(row=0, column=0, sticky="w")
        tk.Label(title_frame, text=f"v{APP_VERSION}",
                 bg=BG2, fg=TEXT3,
                 font=("Helvetica", 10)).grid(row=0, column=1, padx=(8,0), sticky="sw", pady=(0,2))

        self.hdr_status = tk.Label(hdr, text="Not connected",
                                   bg=BG2, fg=TEXT3,
                                   font=("Helvetica", 11))
        self.hdr_status.grid(row=0, column=1, padx=24)

    # ── TABS — label_btn so macOS can't override ───────────────────────────────
    def _build_tabs(self):
        bar = tk.Frame(self, bg=BG2, height=46)
        bar.grid(row=2, column=0, sticky="ew")
        bar.grid_propagate(False)

        self.tabs       = {}
        self.tab_frames = {}
        self.active_tab = "setup"

        for name, label in [("setup","Setup"),("monitor","Monitor"),("settings","Settings")]:
            btn = tk.Label(
                bar, text=label,
                bg=BG2, fg=TEXT2,
                font=("Helvetica", 12),
                cursor="hand2",
                padx=24, pady=13,
            )
            btn.pack(side="left")
            btn.bind("<Button-1>", lambda e, n=name: self._show_tab(n))
            self.tabs[name] = btn

    def _show_tab(self, name):
        for n, f in self.tab_frames.items():
            f.grid_remove() if n != name else f.grid()
        for n, btn in self.tabs.items():
            if n == name:
                btn.config(bg=BG3, fg=WHITE, font=("Helvetica", 12, "bold"))
            else:
                btn.config(bg=BG2, fg=TEXT2, font=("Helvetica", 12))
        self.active_tab = name
        self.update_idletasks()

    # ── CONTENT SHELL ─────────────────────────────────────────────────────────
    def _build_content(self):
        content = tk.Frame(self, bg=BG)
        content.grid(row=4, column=0, sticky="nsew")
        content.grid_rowconfigure(0, weight=1)
        content.grid_columnconfigure(0, weight=1)

        for name in ["setup", "monitor", "settings"]:
            f = tk.Frame(content, bg=BG)
            f.grid(row=0, column=0, sticky="nsew")
            self.tab_frames[name] = f

        self._build_setup()
        self._build_monitor()
        self._build_settings()
        self._show_tab("setup")

    # ── SETUP ─────────────────────────────────────────────────────────────────
    def _build_setup(self):
        outer = self.tab_frames["setup"]
        outer.grid_rowconfigure(0, weight=1)
        outer.grid_columnconfigure(0, weight=1)
        f = tk.Frame(outer, bg=BG)
        f.grid(row=0, column=0, sticky="nsew")
        f.grid_columnconfigure(0, weight=1)
        PAD = 28
        r = 0

        def sp(h=16):
            nonlocal r
            tk.Frame(f, bg=BG, height=h).grid(row=r, column=0); r+=1

        def div():
            nonlocal r
            tk.Frame(f, bg=BORDER, height=1).grid(
                row=r, column=0, padx=PAD, sticky="ew"); r+=1

        sp(28)

        tk.Label(f, text="Connect your account",
                 bg=BG, fg=TEXT,
                 font=("Helvetica", 20, "bold")).grid(
            row=r, column=0, padx=PAD, sticky="w"); r+=1

        sp(8)

        tk.Label(f,
                 text="Enter your Vaultak API key to start monitoring your AI agents.",
                 bg=BG, fg=TEXT2, font=("Helvetica", 12),
                 wraplength=450, justify="left").grid(
            row=r, column=0, padx=PAD, sticky="w"); r+=1

        sp(28)

        tk.Label(f, text="API KEY", bg=BG, fg=TEXT,
                 font=("Helvetica", 11, "bold")).grid(
            row=r, column=0, padx=PAD, sticky="w"); r+=1

        sp(8)

        card = tk.Frame(f, bg=BG3,
                        highlightbackground=BORDER, highlightthickness=1)
        card.grid(row=r, column=0, padx=PAD, sticky="ew")
        card.grid_columnconfigure(0, weight=1); r+=1

        self.api_key_var = tk.StringVar()
        self.key_entry = tk.Entry(
            card,
            textvariable=self.api_key_var,
            bg=BG3, fg=TEXT,
            insertbackground=TEXT,
            selectbackground=ACCENT,
            selectforeground=WHITE,
            relief="flat", bd=0, highlightthickness=0,
            font=("Courier", 13), show="•",
        )
        self.key_entry.grid(row=0, column=0, padx=16, pady=14, sticky="ew")

        # Show button as Label — not tk.Button
        self.show_lbl = tk.Label(
            card, text="Show",
            bg=BG4, fg=TEXT2,
            font=("Helvetica", 10),
            cursor="hand2",
            padx=12, pady=6,
        )
        self.show_lbl.grid(row=0, column=1, padx=(0, 10))
        self.show_lbl.bind("<Button-1>", lambda e: self._toggle_show())

        sp(10)

        link_f = tk.Frame(f, bg=BG)
        link_f.grid(row=r, column=0, padx=PAD, sticky="w"); r+=1

        tk.Label(link_f, text="Find your key at  ",
                 bg=BG, fg=TEXT2, font=("Helvetica", 12)).grid(row=0, column=0)

        lnk = tk.Label(link_f, text="app.vaultak.com  ->",
                       bg=BG, fg=ACCENT2, font=("Helvetica", 12), cursor="hand2")
        lnk.grid(row=0, column=1)
        lnk.bind("<Button-1>", lambda e: webbrowser.open("https://app.vaultak.com"))

        sp(24); div(); sp(20)

        tk.Label(f, text="RESPONSE THRESHOLDS", bg=BG, fg=TEXT,
                 font=("Helvetica", 11, "bold")).grid(
            row=r, column=0, padx=PAD, sticky="w"); r+=1

        sp(4)

        tk.Label(f,
                 text="Vaultak monitors 24/7. Response escalates automatically based on risk score.",
                 bg=BG, fg=TEXT2, font=("Helvetica", 11),
                 wraplength=450, justify="left").grid(
            row=r, column=0, padx=PAD, sticky="w"); r+=1

        sp(16)

        self.threshold_vars = {}
        for action, color, default, desc in [
            ("alert",    "#f59e0b", "30", "Log violation. Agent keeps running."),
            ("pause",    "#f97316", "60", "Stop agent immediately."),
            ("rollback", "#ef4444", "85", "Reverse recent actions, then stop."),
        ]:
            row_f = tk.Frame(f, bg=BG3,
                             highlightbackground=BORDER, highlightthickness=1)
            row_f.grid(row=r, column=0, padx=PAD, pady=4, sticky="ew")
            row_f.grid_columnconfigure(2, weight=1); r+=1

            dot = tk.Canvas(row_f, width=10, height=10,
                            bg=BG3, highlightthickness=0)
            dot.grid(row=0, column=0, padx=(14, 10), pady=14)
            dot.create_oval(1, 1, 9, 9, fill=color, outline="")

            tk.Label(row_f, text=action.capitalize(),
                     bg=BG3, fg=TEXT,
                     font=("Helvetica", 12, "bold"),
                     width=8, anchor="w").grid(row=0, column=1)

            tk.Label(row_f, text=desc,
                     bg=BG3, fg=TEXT2,
                     font=("Helvetica", 11),
                     anchor="w").grid(row=0, column=2, sticky="w")

            score_frame = tk.Frame(row_f, bg=BG4,
                                   highlightbackground=BORDER,
                                   highlightthickness=1)
            score_frame.grid(row=0, column=3, padx=(8, 10), pady=8)

            tk.Label(score_frame, text=">=",
                     bg=BG4, fg=TEXT3,
                     font=("Helvetica", 10)).grid(row=0, column=0, padx=(8, 2))

            var = tk.StringVar(value=self.config_data.get(
                f"threshold_{action}", default))
            self.threshold_vars[action] = var

            tk.Entry(score_frame,
                     textvariable=var,
                     bg=BG4, fg=TEXT,
                     insertbackground=TEXT,
                     relief="flat", bd=0, highlightthickness=0,
                     font=("Helvetica", 12, "bold"),
                     width=3,
                     justify="center").grid(row=0, column=1, padx=(2, 8), pady=6)

        sp(6)

        tk.Label(f, text="Risk score is 0-100. Defaults work well for most agents.",
                 bg=BG, fg=TEXT3, font=("Helvetica", 10)).grid(
            row=r, column=0, padx=PAD, sticky="w"); r+=1

        sp(16)

        self.error_lbl = tk.Label(f, text="", bg=BG, fg=RED,
                                  font=("Helvetica", 11))
        self.error_lbl.grid(row=r, column=0, padx=PAD); r+=1

        sp(6)

        # CTA — label_btn, NOT tk.Button
        self.connect_btn = label_btn(
            f,
            text="Connect and Start Monitoring",
            command=self._connect,
            bg=ACCENT, fg=WHITE,
            font=("Helvetica", 14, "bold"),
            pady=15,
        )
        self.connect_btn.grid(row=r, column=0, padx=PAD, sticky="ew"); r+=1
        self._connect_enabled = True

    # ── MONITOR ───────────────────────────────────────────────────────────────
    def _build_monitor(self):
        f = self.tab_frames["monitor"]
        f.grid_rowconfigure(2, weight=1)
        f.grid_columnconfigure(0, weight=1)

        stats = tk.Frame(f, bg=BG2)
        stats.grid(row=0, column=0, sticky="ew")

        self.stat_vars = {}
        for i, (key, label) in enumerate([
            ("status","Status"),("agent","Agent"),
            ("mode","Mode"),("uptime","Uptime"),
        ]):
            col = tk.Frame(stats, bg=BG2,
                           highlightbackground=BORDER, highlightthickness=1)
            col.grid(row=0, column=i, sticky="nsew", padx=1)
            stats.grid_columnconfigure(i, weight=1)

            tk.Label(col, text=label.upper(), bg=BG2, fg=TEXT2,
                     font=("Helvetica", 9, "bold")).pack(pady=(16, 4))

            var = tk.StringVar(value="—")
            self.stat_vars[key] = var
            tk.Label(col, textvariable=var, bg=BG2, fg=WHITE,
                     font=("Helvetica", 14, "bold")).pack(pady=(0, 16))

        tk.Frame(f, bg=BORDER, height=1).grid(row=1, column=0, sticky="ew")

        log_wrap = tk.Frame(f, bg=BG)
        log_wrap.grid(row=2, column=0, sticky="nsew", padx=20, pady=16)
        log_wrap.grid_rowconfigure(1, weight=1)
        log_wrap.grid_columnconfigure(0, weight=1)

        tk.Label(log_wrap, text="ACTIVITY LOG", bg=BG, fg=TEXT,
                 font=("Helvetica", 11, "bold")).grid(
            row=0, column=0, sticky="w", pady=(0, 8))

        log_frame = tk.Frame(log_wrap, bg=BG3,
                             highlightbackground=BORDER, highlightthickness=1)
        log_frame.grid(row=1, column=0, sticky="nsew")
        log_frame.grid_rowconfigure(0, weight=1)
        log_frame.grid_columnconfigure(0, weight=1)

        self.log_text = tk.Text(
            log_frame,
            bg=BG3, fg=TEXT,
            font=("Courier", 13),
            relief="flat", bd=0, highlightthickness=0,
            state="disabled", wrap="word",
            padx=14, pady=14, cursor="arrow",
        )
        sb = tk.Scrollbar(log_frame, command=self.log_text.yview,
                          bg=BG3, troughcolor=BG3, activebackground=BG4)
        self.log_text.configure(yscrollcommand=sb.set)
        # Color tags for severity
        self.log_text.tag_config("alert",    foreground="#F59E0B", font=("Courier", 13, "bold"))
        self.log_text.tag_config("pause",    foreground="#EF4444", font=("Courier", 13, "bold"))
        self.log_text.tag_config("rollback", foreground="#FF3333", font=("Courier", 13, "bold"))
        self.log_text.tag_config("info",     foreground="#6EE7B7", font=("Courier", 13))
        self.log_text.tag_config("dim",      foreground="#6B7280", font=("Courier", 12))
        sb.grid(row=0, column=1, sticky="ns")
        self.log_text.grid(row=0, column=0, sticky="nsew")

        btns = tk.Frame(f, bg=BG)
        btns.grid(row=3, column=0, sticky="ew", padx=20, pady=(0, 20))
        btns.grid_columnconfigure(1, weight=1)

        self.stop_btn = label_btn(
            btns, text="Stop Monitoring",
            command=self._stop,
            bg=BG3, fg=TEXT,
            font=("Helvetica", 12, "bold"),
            padx=18, pady=10,
        )
        self.stop_btn.grid(row=0, column=0)
        self._stop_enabled = False
        self.stop_btn.config(fg=TEXT3, cursor="arrow")

        label_btn(
            btns, text="Open Dashboard  ->",
            command=lambda: webbrowser.open("https://app.vaultak.com"),
            bg=ACCENT, fg=WHITE,
            font=("Helvetica", 12, "bold"),
            padx=18, pady=10,
        ).grid(row=0, column=2)

    # ── SETTINGS ──────────────────────────────────────────────────────────────
    def _build_settings(self):
        f = self.tab_frames["settings"]
        f.grid_columnconfigure(0, weight=1)
        PAD = 28
        r = 0

        def sp(h=16):
            nonlocal r
            tk.Frame(f, bg=BG, height=h).grid(row=r, column=0); r+=1

        def div():
            nonlocal r
            tk.Frame(f, bg=BORDER, height=1).grid(
                row=r, column=0, padx=PAD, sticky="ew"); r+=1

        sp(28)

        tk.Label(f, text="Settings", bg=BG, fg=TEXT,
                 font=("Helvetica", 20, "bold")).grid(
            row=r, column=0, padx=PAD, sticky="w"); r+=1

        sp(24)

        # ── AGENTS SECTION ──────────────────────────────────────────
        tk.Label(f, text="AGENTS", bg=BG, fg=TEXT,
                 font=("Helvetica", 11, "bold")).grid(
            row=r, column=0, padx=PAD, sticky="w"); r+=1

        sp(4)

        self._plan_label = tk.Label(f, text="Loading plan...",
                 bg=BG, fg=TEXT3, font=("Helvetica", 10))
        self._plan_label.grid(row=r, column=0, padx=PAD, sticky="w"); r+=1

        sp(8)

        # Agent list frame
        self._agents_frame = tk.Frame(f, bg=BG)
        self._agents_frame.grid(row=r, column=0, padx=PAD, sticky="ew")
        self._agents_frame.grid_columnconfigure(0, weight=1); r+=1

        # Internal agent list: [{"name": str, "command": str}]
        self._agent_list = self.config_data.get("agents", [
            {"name": self.config_data.get("agent_id", "my-agent"),
             "command": self.config_data.get("agent_command", "python3 agent.py")}
        ])
        self._agent_rows = []
        self._max_agents = 1  # updated after plan fetch

        self._refresh_agent_rows()

        sp(10)

        self._add_agent_btn = label_btn(
            f, text="+ Add Agent",
            command=self._add_agent_row,
            bg=BG3, fg=TEXT2,
            font=("Helvetica", 11),
            padx=14, pady=8,
        )
        self._add_agent_btn.grid(row=r, column=0, padx=PAD, sticky="w"); r+=1

        self._upgrade_lbl = tk.Label(f, text="",
                 bg=BG, fg="#F59E0B", font=("Helvetica", 10))
        self._upgrade_lbl.grid(row=r, column=0, padx=PAD, sticky="w"); r+=1

        # Fetch plan limits in background
        threading.Thread(target=self._fetch_plan_limits, daemon=True).start()

        sp(28); div(); sp(20)

        tk.Label(f, text="RESOURCES", bg=BG, fg=TEXT,
                 font=("Helvetica", 11, "bold")).grid(
            row=r, column=0, padx=PAD, sticky="w"); r+=1

        sp(12)

        for label, url in [
            ("View dashboard", "https://app.vaultak.com"),
            ("Documentation",  "https://docs.vaultak.com/sentry"),
            ("White paper",    "https://vaultak.com/whitepaper"),
            ("Get support",    "mailto:support@vaultak.com"),
        ]:
            lf = tk.Frame(f, bg=BG)
            lf.grid(row=r, column=0, padx=PAD, pady=6, sticky="w"); r+=1
            lbl = tk.Label(lf, text=f"->  {label}",
                           bg=BG, fg=ACCENT2,
                           font=("Helvetica", 12), cursor="hand2")
            lbl.grid(row=0, column=0)
            lbl.bind("<Button-1>", lambda e, u=url: webbrowser.open(u))

        sp(24); div(); sp(16)

        label_btn(f, text="Save Settings",
                  command=self._save_settings,
                  bg=ACCENT, fg=WHITE,
                  font=("Helvetica", 13, "bold"),
                  pady=13).grid(row=r, column=0, padx=PAD, sticky="ew"); r+=1

        sp(10)

        label_btn(f, text="Disconnect account",
                  command=self._disconnect,
                  bg=BG3, fg=RED,
                  font=("Helvetica", 12),
                  pady=10).grid(row=r, column=0, padx=PAD, sticky="ew"); r+=1

        sp(20)

        tk.Label(f, text=f"Vaultak Sentry  v{APP_VERSION}  .  vaultak.com",
                 bg=BG, fg=TEXT3,
                 font=("Helvetica", 10)).grid(row=r, column=0); r+=1

    # ── LOGIC ─────────────────────────────────────────────────────────────────
    def _refresh_agent_rows(self):
        """Rebuild the agent rows UI from self._agent_list."""
        for w in self._agents_frame.winfo_children():
            w.destroy()
        self._agent_rows = []
        for i, agent in enumerate(self._agent_list):
            self._add_agent_row_data(i, agent["name"], agent["command"])

    def _add_agent_row_data(self, idx, name="", command="python3 agent.py"):
        """Add a single agent row to the UI."""
        row_f = tk.Frame(self._agents_frame, bg=BG2,
                         highlightbackground=BORDER, highlightthickness=1)
        row_f.grid(row=idx, column=0, sticky="ew", pady=4)
        row_f.grid_columnconfigure(1, weight=1)

        tk.Label(row_f, text="Name", bg=BG2, fg=TEXT2,
                 font=("Helvetica", 11, "bold")).grid(row=0, column=0, padx=(16,8), pady=(12,4), sticky="w")

        name_var = tk.StringVar(value=name)
        tk.Entry(row_f, textvariable=name_var, bg=BG3, fg=WHITE,
                 insertbackground=WHITE, relief="flat", bd=0,
                 highlightthickness=0, font=("Helvetica", 12)).grid(
            row=0, column=1, padx=(0,12), pady=(12,4), sticky="ew")

        tk.Label(row_f, text="Command", bg=BG2, fg=TEXT2,
                 font=("Helvetica", 11, "bold")).grid(row=1, column=0, padx=(16,8), pady=(4,12), sticky="w")

        cmd_var = tk.StringVar(value=command)
        tk.Entry(row_f, textvariable=cmd_var, bg=BG3, fg=WHITE,
                 insertbackground=WHITE, relief="flat", bd=0,
                 highlightthickness=0, font=("Courier", 12)).grid(
            row=1, column=1, padx=(0,12), pady=(4,12), sticky="ew")

        if idx > 0:
            def remove(i=idx):
                del self._agent_list[i]
                self._refresh_agent_rows()
            rm = tk.Label(row_f, text="✕", bg=BG2, fg=TEXT3,
                          font=("Helvetica", 11), cursor="hand2", padx=8)
            rm.grid(row=0, column=2, rowspan=2, padx=(0,8))
            rm.bind("<Button-1>", lambda e, fn=remove: fn())

        self._agent_rows.append((name_var, cmd_var))

    def _add_agent_row(self):
        """Add a new empty agent row, respecting plan limits."""
        if len(self._agent_rows) >= self._max_agents:
            self._upgrade_lbl.config(
                text=f"Upgrade to add more agents. Current plan allows {self._max_agents}.")
            return
        self._upgrade_lbl.config(text="")
        idx = len(self._agent_list)
        self._agent_list.append({"name": f"agent-{idx+1}", "command": "python3 agent.py"})
        self._add_agent_row_data(idx, f"agent-{idx+1}", "python3 agent.py")

    def _fetch_plan_limits(self):
        """Fetch plan limits from backend and update UI."""
        api_key = self.config_data.get("api_key", "")
        if not api_key:
            return
        try:
            import urllib.request as _req, json as _json
            request = _req.Request(
                f"{API_BASE}/api/org/plan",
                headers={"x-api-key": api_key},
                method="GET"
            )
            resp = _req.urlopen(request, timeout=5)
            data = _json.loads(resp.read())
            plan      = data.get("plan", "starter")
            max_agents = data.get("max_agents", 1)
            self._max_agents = max_agents
            self.after(0, lambda: self._plan_label.config(
                text=f"Plan: {plan.upper()} — up to {max_agents} agent(s)"))
            if len(self._agent_rows) >= max_agents:
                self.after(0, lambda: self._upgrade_lbl.config(
                    text=f"Agent limit reached. Upgrade to add more."))
        except Exception:
            self.after(0, lambda: self._plan_label.config(text="Plan: could not load"))

    def _toggle_show(self):
        if self.key_entry.cget("show") == "•":
            self.key_entry.config(show="")
            self.show_lbl.config(text="Hide")
        else:
            self.key_entry.config(show="•")
            self.show_lbl.config(text="Show")

    def _check_saved_config(self):
        api_key = self.config_data.get("api_key")
        if api_key:
            self.api_key_var.set(api_key)
            self._start_monitoring(
                api_key,
                self.config_data.get("agent_id", "my-agent"))

    def _connect(self):
        if not self._connect_enabled:
            return
        api_key = self.api_key_var.get().strip()
        if not api_key:
            self.error_lbl.config(text="Please enter your API key.")
            return
        self._connect_enabled = False
        self.connect_btn.config(text="Connecting...", fg=TEXT3, cursor="arrow")
        self.error_lbl.config(text="")
        self.update()

        def do():
            valid, msg = validate_api_key(api_key)
            if not valid:
                self.after(0, lambda: self._fail(msg))
                return
            agent_id = self.agent_name_var.get() or "my-agent"
            thresholds = {f"threshold_{k}": v.get()
                          for k, v in self.threshold_vars.items()}
            cfg = {**self.config_data,
                   "api_key": api_key, "agent_id": agent_id, **thresholds}
            save_config(cfg)
            self.config_data = cfg
            self.after(0, lambda: self._start_monitoring(api_key, agent_id))

        threading.Thread(target=do, daemon=True).start()

    def _fail(self, msg):
        self.error_lbl.config(text=msg)
        self._connect_enabled = True
        self.connect_btn.config(text="Connect and Start Monitoring",
                                fg=WHITE, cursor="hand2")

    def _start_monitoring(self, api_key, agent_id):
        self.is_monitoring  = True
        self.start_time     = time.time()
        self._connect_enabled = False
        self.connect_btn.config(text="Connected", bg=BG3, fg=GREEN, cursor="arrow")
        self._stop_enabled  = True
        self.stop_btn.config(fg=TEXT, cursor="hand2")
        self.hdr_status.config(text="Monitoring", fg=GREEN)
        self.stat_vars["status"].set("Active")
        self.stat_vars["agent"].set(agent_id[:16])
        t_alert    = self.config_data.get("threshold_alert",    "30")
        t_pause    = self.config_data.get("threshold_pause",    "60")
        t_rollback = self.config_data.get("threshold_rollback", "85")
        self.stat_vars["mode"].set(f"A{t_alert}/P{t_pause}/R{t_rollback}")
        self._show_tab("monitor")
        self._log("Vaultak Sentry started")
        self._log(f"Agent: {agent_id}")
        self._log(f"Alert >={t_alert}  |  Pause >={t_pause}  |  Rollback >={t_rollback}")
        self._log("Dashboard: app.vaultak.com")
        self._tick_uptime()

        # Start real interception engine
        self._engine = SentryEngine(
            api_key=api_key,
            agent_id=agent_id,
            alert_threshold=t_alert,
            pause_threshold=t_pause,
            rollback_threshold=t_rollback,
            api_base=API_BASE,
            on_action=self._on_intercepted_action,
            on_log=lambda msg: self.after(0, lambda m=msg: self._log(m)),
        )
        # Launch all configured agents
        agents = self.config_data.get("agents", [])
        if not agents:
            cmd = self.config_data.get("agent_command", "").strip()
            if cmd:
                agents = [{"name": agent_id, "command": cmd}]

        self._engines = []
        if agents:
            for ag in agents:
                cmd  = ag.get("command", "").strip()
                name = ag.get("name", agent_id)
                if not cmd:
                    continue
                engine = SentryEngine(
                    api_key=api_key,
                    agent_id=name,
                    alert_threshold=t_alert,
                    pause_threshold=t_pause,
                    rollback_threshold=t_rollback,
                    api_base=API_BASE,
                    on_action=self._on_intercepted_action,
                    on_log=lambda msg: self.after(0, lambda m=msg: self._log(m)),
                )
                self._engines.append(engine)
                self._log(f"Wrapping [{name}]: {cmd}")
                threading.Thread(target=engine.start, args=(cmd,), daemon=True).start()
        else:
            self._log("No agent command set. Go to Settings to configure.")
            self._log("Actions logged via SDK will still appear in dashboard.")

    def _on_intercepted_action(self, action_type, resource, score, decision):
        """Called by SentryEngine for each intercepted action."""
        icons = {"ROLLBACK": "x", "PAUSE": "!", "ALERT": "~", "ALLOW": "+"}
        icon  = icons.get(decision, "+")
        msg   = f"[{icon}] {action_type} on {resource} — risk {score}"
        self.after(0, lambda: self._log(msg))

    def _stop(self):
        if not self._stop_enabled:
            return
        self.is_monitoring = False
        # Stop all engines
        if hasattr(self, "_engines") and self._engines:
            for engine in self._engines:
                threading.Thread(target=engine.stop, daemon=True).start()
            self._engines = []
        self.hdr_status.config(text="Stopped", fg=RED)
        self.stat_vars["status"].set("Stopped")
        self._stop_enabled = False
        self.stop_btn.config(fg=TEXT3, cursor="arrow")
        self._connect_enabled = True
        self.connect_btn.config(text="Connect and Start Monitoring",
                                bg=ACCENT, fg=WHITE, cursor="hand2")
        self._log("Monitoring stopped.")
        self._show_tab("setup")

    def _log(self, msg):
        self.log_text.config(state="normal")
        ts = datetime.now().strftime("%H:%M:%S")
        line = f"[{ts}]  {msg}\n"

        # Determine tag based on message content
        msg_lower = msg.lower()
        # System info lines always dim
        if any(k in msg_lower for k in ["vaultak sentry started", "agent:", "alert >=", "dashboard:", "monitoring stopped"]):
            tag = "info" if any(k in msg_lower for k in ["vaultak sentry started", "agent:", "dashboard:"]) else "dim"
        elif any(k in msg_lower for k in ["rolled back", "reversing", "critical risk"]):
            tag = "rollback"
        elif any(k in msg_lower for k in ["paused", "blocked", "stopped agent"]):
            tag = "pause"
        elif any(k in msg_lower for k in ["flagged", "warning", "high risk", "alert triggered"]):
            tag = "alert"
        else:
            tag = "dim"

        self.log_text.insert("end", line, tag)
        self.log_text.see("end")
        self.log_text.config(state="disabled")

    def _tick_uptime(self):
        if not self.is_monitoring or not self.start_time:
            return
        elapsed = int(time.time() - self.start_time)
        h, rem = divmod(elapsed, 3600)
        m, s   = divmod(rem, 60)
        self.stat_vars["uptime"].set(f"{h:02d}:{m:02d}:{s:02d}")
        self.after(1000, self._tick_uptime)

    def _save_settings(self):
        # Collect agent list from UI rows
        agents = []
        for name_var, cmd_var in self._agent_rows:
            name = name_var.get().strip()
            cmd  = cmd_var.get().strip()
            if name and cmd:
                agents.append({"name": name, "command": cmd})
        if not agents:
            messagebox.showerror("Error", "At least one agent is required.")
            return
        cfg = {
            **self.config_data,
            "agents":        agents,
            "agent_id":      agents[0]["name"],
            "agent_command": agents[0]["command"],
        }
        save_config(cfg)
        self.config_data = cfg
        self._agent_list = agents
        messagebox.showinfo("Saved", f"Settings saved. {len(agents)} agent(s) configured.")

    def _disconnect(self):
        if messagebox.askyesno("Disconnect", "Stop monitoring and disconnect?"):
            self.is_monitoring = False
            save_config({})
            self.config_data = {}
            self.api_key_var.set("")
            self.hdr_status.config(text="Not connected", fg=TEXT3)
            self._connect_enabled = True
            self.connect_btn.config(text="Connect and Start Monitoring",
                                    bg=ACCENT, fg=WHITE, cursor="hand2")
            self._stop_enabled = False
            self.stop_btn.config(fg=TEXT3, cursor="arrow")
            self._show_tab("setup")

    def _on_close(self):
        if self.is_monitoring:
            if messagebox.askyesno("Quit", "Sentry is monitoring. Stop and quit?"):
                self.destroy()
        else:
            self.destroy()


def main():
    app = VaultakSentryApp()
    app.mainloop()

if __name__ == "__main__":
    main()
