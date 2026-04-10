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
APP_VERSION = "1.0.0"
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
        self.after(200, self._check_saved_config)

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

        tk.Label(left, text="Vaultak Sentry",
                 bg=BG2, fg=TEXT,
                 font=("Helvetica", 17, "bold")).grid(row=0, column=1)

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
        f = self.tab_frames["setup"]
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
            font=("Courier", 11),
            relief="flat", bd=0, highlightthickness=0,
            state="disabled", wrap="word",
            padx=14, pady=14, cursor="arrow",
        )
        sb = tk.Scrollbar(log_frame, command=self.log_text.yview,
                          bg=BG3, troughcolor=BG3, activebackground=BG4)
        self.log_text.configure(yscrollcommand=sb.set)
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

        tk.Label(f, text="AGENT NAME", bg=BG, fg=TEXT,
                 font=("Helvetica", 11, "bold")).grid(
            row=r, column=0, padx=PAD, sticky="w"); r+=1

        sp(8)

        name_frame = tk.Frame(f, bg=BG3,
                              highlightbackground=BORDER, highlightthickness=1)
        name_frame.grid(row=r, column=0, padx=PAD, sticky="ew"); r+=1
        name_frame.grid_columnconfigure(0, weight=1)

        self.agent_name_var = tk.StringVar(
            value=self.config_data.get("agent_id", "my-agent"))
        tk.Entry(name_frame,
                 textvariable=self.agent_name_var,
                 bg=BG3, fg=TEXT, insertbackground=TEXT,
                 selectbackground=ACCENT, selectforeground=WHITE,
                 relief="flat", bd=0, highlightthickness=0,
                 font=("Helvetica", 12)).grid(
            row=0, column=0, padx=16, pady=14, sticky="ew")

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

    def _stop(self):
        if not self._stop_enabled:
            return
        self.is_monitoring = False
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
        self.log_text.insert("end", f"[{ts}]  {msg}\n")
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
        cfg = {**self.config_data, "agent_id": self.agent_name_var.get()}
        save_config(cfg)
        self.config_data = cfg
        messagebox.showinfo("Saved", "Settings saved.")

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
