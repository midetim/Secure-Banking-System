import tkinter as tk
from tkinter import ttk
import threading
import queue
import socket
import hashlib
from datetime import datetime

from storage import AccountStorage
from bank_logic import BankLogic
from client_session import ClientSession
from audit_logger import AuditLogger


HOST = "0.0.0.0"
PORT = 5000
ACCOUNTS_FILE = "data/accounts.json"
AUDIT_LOG_FILE = "data/audit.log"

# Match client GUI palette exactly
BG        = "#0d1117"
PANEL     = "#161b22"
BORDER    = "#30363d"
ACCENT    = "#238636"
RED       = "#da3633"
PURPLE    = "#6e40c9"
GOLD      = "#d29922"
BLUE      = "#79c0ff"
TEXT      = "#e6edf3"
MUTED     = "#8b949e"
GREEN     = "#3fb950"
YELLOW    = "#e3b341"
MONO      = ("Courier New", 10)
SANS      = ("Segoe UI", 11)
SANS_SM   = ("Segoe UI", 10)
SANS_LG   = ("Segoe UI", 13, "bold")
SANS_XL   = ("Segoe UI", 18, "bold")


def build_audit_key() -> bytes:
    return hashlib.sha256("secure_audit_log_key_2026".encode()).digest()


def styled_button(parent, text, color, command, width=14):
    return tk.Button(
        parent, text=text, bg=color, fg=TEXT,
        font=("Segoe UI", 10, "bold"), relief="flat",
        activebackground=color, activeforeground=TEXT,
        cursor="hand2", width=width, pady=5,
        command=command
    )


class ServerApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Secure Bank Server — COE817")
        self.geometry("980x680")
        self.minsize(820, 560)
        self.configure(bg=BG)
        self.protocol("WM_DELETE_WINDOW", self._on_close)

        # Server runtime state
        self.event_queue: queue.Queue = queue.Queue()
        self.sessions: dict = {}        # "ip:port" -> {"username": str|None}
        self.server_socket = None
        self.server_thread = None
        self.running = False

        # Banking data — shared with all sessions
        self.storage = AccountStorage(ACCOUNTS_FILE)
        self.bank_logic = BankLogic(self.storage)
        self.audit_key = build_audit_key()
        self.audit_logger = AuditLogger(AUDIT_LOG_FILE, self.audit_key)

        self._build_ui()
        self._start_server()
        self._poll()

    # ── UI Construction ───────────────────────────────────────────────────────

    def _build_ui(self):
        # Top bar
        topbar = tk.Frame(self, bg=PANEL, pady=10,
                          highlightthickness=1, highlightbackground=BORDER)
        topbar.pack(fill="x")

        tk.Label(topbar, text="Secure Bank Server",
                 font=SANS_XL, bg=PANEL, fg=TEXT).pack(side="left", padx=20)
        tk.Label(topbar, text="COE817",
                 font=SANS_SM, bg=PANEL, fg=MUTED).pack(side="left", padx=(0, 20))

        self.stop_btn = styled_button(topbar, "Stop Server", RED, self._stop_server, width=13)
        self.stop_btn.pack(side="right", padx=20)

        self.status_dot = tk.Label(topbar, text="●", font=("Segoe UI", 16),
                                   bg=PANEL, fg=MUTED)
        self.status_dot.pack(side="right")

        self.status_lbl = tk.Label(topbar, text="STARTING…",
                                   font=SANS, bg=PANEL, fg=MUTED)
        self.status_lbl.pack(side="right", padx=(0, 6))

        # Body: sidebar | main
        body = tk.Frame(self, bg=BG)
        body.pack(fill="both", expand=True)

        self._build_sidebar(body)
        self._build_main(body)

    def _build_sidebar(self, parent):
        sidebar = tk.Frame(parent, bg=PANEL, width=252,
                           highlightthickness=1, highlightbackground=BORDER)
        sidebar.pack(side="left", fill="y")
        sidebar.pack_propagate(False)

        # ── Active Sessions ───────────────────────────────────────────
        tk.Label(sidebar, text="Active Sessions", font=SANS_LG,
                 bg=PANEL, fg=TEXT, pady=8).pack(fill="x", padx=14)

        self.session_count_lbl = tk.Label(sidebar, text="0 connected",
                                          font=SANS_SM, bg=PANEL, fg=MUTED)
        self.session_count_lbl.pack(anchor="w", padx=14)

        sess_wrap = tk.Frame(sidebar, bg=BORDER)
        sess_wrap.pack(fill="x", padx=14, pady=(6, 0))

        self.session_box = tk.Text(
            sess_wrap, font=MONO, bg=PANEL, fg=TEXT,
            relief="flat", bd=6, state="disabled",
            selectbackground=BORDER, height=9, width=28
        )
        self.session_box.pack(fill="x")
        self.session_box.tag_config("user", foreground=GREEN)
        self.session_box.tag_config("addr", foreground=MUTED)

        tk.Frame(sidebar, bg=BORDER, height=1).pack(fill="x", padx=14, pady=10)

        # ── Audit Log ─────────────────────────────────────────────────
        tk.Label(sidebar, text="Audit Log", font=SANS_LG,
                 bg=PANEL, fg=TEXT, pady=4).pack(fill="x", padx=14)

        tk.Label(sidebar, text="Stored encrypted at rest (AES-256-CBC)",
                 font=("Segoe UI", 9), bg=PANEL, fg=MUTED, wraplength=220).pack(
            anchor="w", padx=14, pady=(0, 6))

        styled_button(sidebar, "View Decrypted Log", PURPLE,
                      self._show_audit_popup, width=24).pack(padx=14)

        tk.Frame(sidebar, bg=BORDER, height=1).pack(fill="x", padx=14, pady=10)

        # ── Accounts ──────────────────────────────────────────────────
        hdr = tk.Frame(sidebar, bg=PANEL)
        hdr.pack(fill="x", padx=14)
        tk.Label(hdr, text="Accounts", font=SANS_LG,
                 bg=PANEL, fg=TEXT).pack(side="left")
        tk.Button(hdr, text="↻", font=("Segoe UI", 13), bg=PANEL, fg=GOLD,
                  relief="flat", activebackground=PANEL, cursor="hand2",
                  command=self._refresh_accounts).pack(side="right")

        acct_wrap = tk.Frame(sidebar, bg=BORDER)
        acct_wrap.pack(fill="x", padx=14, pady=(6, 10))

        self.account_box = tk.Text(
            acct_wrap, font=MONO, bg=PANEL, fg=TEXT,
            relief="flat", bd=6, state="disabled",
            selectbackground=BORDER, height=9, width=28
        )
        self.account_box.pack(fill="x")
        self.account_box.tag_config("user", foreground=BLUE)
        self.account_box.tag_config("bal",  foreground=YELLOW)
        self.account_box.tag_config("none", foreground=MUTED)

    def _build_main(self, parent):
        right = tk.Frame(parent, bg=BG, padx=16, pady=12)
        right.pack(side="left", fill="both", expand=True)

        hdr = tk.Frame(right, bg=BG)
        hdr.pack(fill="x", pady=(0, 8))
        tk.Label(hdr, text="Server Activity Log", font=SANS_LG,
                 bg=BG, fg=TEXT).pack(side="left")
        tk.Button(hdr, text="Clear", font=SANS_SM, bg=BG, fg=MUTED,
                  relief="flat", cursor="hand2", activebackground=BG,
                  command=self._clear_log).pack(side="right")

        log_wrap = tk.Frame(right, bg=PANEL,
                            highlightthickness=1, highlightbackground=BORDER)
        log_wrap.pack(fill="both", expand=True)

        self.activity_box = tk.Text(
            log_wrap, font=MONO, bg=PANEL, fg=TEXT,
            relief="flat", bd=10, state="disabled",
            selectbackground=BORDER
        )
        self.activity_box.pack(side="left", fill="both", expand=True)

        sb = ttk.Scrollbar(log_wrap, command=self.activity_box.yview)
        sb.pack(side="right", fill="y")
        self.activity_box.config(yscrollcommand=sb.set)

        # Colour tags that match what each event type means
        self.activity_box.tag_config("connect",     foreground=GREEN)
        self.activity_box.tag_config("disconnect",  foreground=MUTED)
        self.activity_box.tag_config("auth",        foreground=BLUE)
        self.activity_box.tag_config("transaction", foreground=YELLOW)
        self.activity_box.tag_config("error",       foreground=RED)
        self.activity_box.tag_config("info",        foreground=MUTED)

    # ── Server lifecycle ──────────────────────────────────────────────────────

    def _start_server(self):
        self.running = True
        self.server_thread = threading.Thread(target=self._server_loop, daemon=True)
        self.server_thread.start()
        self._log("Server starting…", "info")

    def _stop_server(self):
        self.running = False
        if self.server_socket:
            try:
                self.server_socket.close()
            except Exception:
                pass
        self.status_dot.config(fg=RED)
        self.status_lbl.config(text="STOPPED", fg=RED)
        self.stop_btn.config(state="disabled", text="Stopped")
        self._log("Server stopped.", "disconnect")

    def _server_loop(self):
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind((HOST, PORT))
            self.server_socket.listen(5)
            self.event_queue.put(("status_ok", {}))

            while self.running:
                try:
                    self.server_socket.settimeout(1.0)
                    client_sock, addr = self.server_socket.accept()
                except socket.timeout:
                    continue
                except OSError:
                    break

                t = threading.Thread(
                    target=self._handle_client,
                    args=(client_sock, addr),
                    daemon=True
                )
                t.start()

        except Exception as e:
            self.event_queue.put(("status_error", {"msg": str(e)}))

    def _handle_client(self, client_sock, addr):
        def callback(event_type: str, data: dict):
            self.event_queue.put((event_type, data))

        session = ClientSession(
            client_sock, addr,
            self.bank_logic, self.audit_logger,
            event_callback=callback
        )
        session.run()

    # ── Event polling — runs on GUI thread via after() ─────────────────────────

    def _poll(self):
        try:
            while True:
                event_type, data = self.event_queue.get_nowait()
                self._handle_event(event_type, data)
        except queue.Empty:
            pass
        self.after(100, self._poll)

    def _handle_event(self, event_type: str, data: dict):
        addr = data.get("addr")
        addr_str = f"{addr[0]}:{addr[1]}" if addr else "?"

        if event_type == "status_ok":
            self.status_dot.config(fg=ACCENT)
            self.status_lbl.config(text=f"RUNNING  {HOST}:{PORT}", fg=TEXT)
            self._log(f"Listening on {HOST}:{PORT}", "info")
            self._refresh_accounts()

        elif event_type == "status_error":
            self.status_dot.config(fg=RED)
            self.status_lbl.config(text=f"ERROR: {data.get('msg', '')}", fg=RED)
            self._log(f"Server error: {data.get('msg', '')}", "error")

        elif event_type == "connect":
            self.sessions[addr_str] = {"username": None}
            self._log(f"Connected:    {addr_str}", "connect")
            self._refresh_sessions()

        elif event_type == "disconnect":
            user = self.sessions.pop(addr_str, {}).get("username") or data.get("username")
            label = f"{user} ({addr_str})" if user else addr_str
            self._log(f"Disconnected: {label}", "disconnect")
            self._refresh_sessions()
            self._refresh_accounts()

        elif event_type == "login":
            username = data.get("username", "")
            if addr_str in self.sessions:
                self.sessions[addr_str]["username"] = username
            self._log(f"Login:        {username}  from {addr_str}", "auth")
            self._refresh_sessions()

        elif event_type == "auth_success":
            username = data.get("username", "")
            self._log(f"Handshake OK: {username} — Master Secret derived, session keys active", "auth")

        elif event_type == "auth_fail":
            self._log(f"Auth failed:  {addr_str}", "error")

        elif event_type == "transaction":
            username = data.get("username", "")
            action = data.get("action", "")
            self._log(f"Transaction:  {username}  →  {action}", "transaction")
            self._refresh_accounts()

        elif event_type == "error":
            self._log(f"Error [{addr_str}]: {data.get('msg', '')}", "error")

    # ── UI helpers ────────────────────────────────────────────────────────────

    def _log(self, message: str, tag: str = "info"):
        ts = datetime.now().strftime("%H:%M:%S")
        self.activity_box.config(state="normal")
        self.activity_box.insert("end", f"[{ts}]  {message}\n", tag)
        self.activity_box.see("end")
        self.activity_box.config(state="disabled")

    def _clear_log(self):
        self.activity_box.config(state="normal")
        self.activity_box.delete("1.0", "end")
        self.activity_box.config(state="disabled")

    def _refresh_sessions(self):
        self.session_box.config(state="normal")
        self.session_box.delete("1.0", "end")

        for addr_str, info in self.sessions.items():
            user = info.get("username")
            if user:
                self.session_box.insert("end", f"● {user}\n", "user")
                self.session_box.insert("end", f"  {addr_str}\n", "addr")
            else:
                self.session_box.insert("end", f"○ {addr_str}  (not logged in)\n", "addr")

        self.session_box.config(state="disabled")
        count = len(self.sessions)
        self.session_count_lbl.config(
            text=f"{count} connected",
            fg=GREEN if count > 0 else MUTED
        )

    def _refresh_accounts(self):
        try:
            accounts = self.storage._load_accounts()
            self.account_box.config(state="normal")
            self.account_box.delete("1.0", "end")

            if not accounts:
                self.account_box.insert("end", "No accounts yet.\n", "none")
            else:
                for username, info in accounts.items():
                    balance = info.get("balance", 0.0)
                    self.account_box.insert("end", f"{username}\n", "user")
                    self.account_box.insert("end", f"  ${balance:,.2f}\n", "bal")

            self.account_box.config(state="disabled")
        except Exception as e:
            self._log(f"Failed to load accounts: {e}", "error")

    # ── Audit log popup ───────────────────────────────────────────────────────

    def _show_audit_popup(self):
        popup = tk.Toplevel(self)
        popup.title("Audit Log — Decrypted View")
        popup.geometry("720x520")
        popup.configure(bg=BG)
        popup.grab_set()

        # Header
        topbar = tk.Frame(popup, bg=PANEL, pady=10,
                          highlightthickness=1, highlightbackground=BORDER)
        topbar.pack(fill="x")

        tk.Label(topbar, text="Audit Log", font=SANS_LG,
                 bg=PANEL, fg=TEXT).pack(side="left", padx=16)

        lock_lbl = tk.Label(
            topbar,
            text="  Encrypted at rest with AES-256-CBC  |  Decrypted here using server log key",
            font=("Segoe UI", 9), bg=PANEL, fg=MUTED
        )
        lock_lbl.pack(side="left")

        # Refresh button inside popup
        styled_button(topbar, "↻ Refresh", PURPLE,
                      lambda: self._reload_audit(log_text), width=10).pack(side="right", padx=12)

        # Table header row
        col_frame = tk.Frame(popup, bg=BORDER, padx=12, pady=6)
        col_frame.pack(fill="x")
        for col, w in [("Customer ID", 16), ("Action", 24), ("Timestamp", 22)]:
            tk.Label(col_frame, text=col, font=("Segoe UI", 9, "bold"),
                     bg=BORDER, fg=MUTED, width=w, anchor="w").pack(side="left")

        # Log content
        log_wrap = tk.Frame(popup, bg=PANEL,
                            highlightthickness=1, highlightbackground=BORDER)
        log_wrap.pack(fill="both", expand=True, padx=16, pady=10)

        log_text = tk.Text(
            log_wrap, font=MONO, bg=PANEL, fg=TEXT,
            relief="flat", bd=10, state="disabled",
            selectbackground=BORDER
        )
        log_text.pack(side="left", fill="both", expand=True)

        sb = ttk.Scrollbar(log_wrap, command=log_text.yview)
        sb.pack(side="right", fill="y")
        log_text.config(yscrollcommand=sb.set)

        log_text.tag_config("user",   foreground=BLUE)
        log_text.tag_config("action", foreground=YELLOW)
        log_text.tag_config("ts",     foreground=MUTED)
        log_text.tag_config("err",    foreground=RED)
        log_text.tag_config("empty",  foreground=MUTED)

        # Status bar at bottom of popup
        status_var = tk.StringVar()
        tk.Label(popup, textvariable=status_var, font=SANS_SM,
                 bg=BG, fg=MUTED, anchor="w", padx=16).pack(fill="x", pady=(0, 6))
        self._status_var_audit = status_var

        self._reload_audit(log_text)

    def _reload_audit(self, log_text: tk.Text):
        log_text.config(state="normal")
        log_text.delete("1.0", "end")

        try:
            entries = self.audit_logger.read_decrypted_logs()

            if not entries:
                log_text.insert("end", "No audit entries yet.\n", "empty")
            else:
                for entry in entries:
                    if "error" in entry:
                        log_text.insert("end", f"[DECRYPT ERROR] {entry['error']}\n", "err")
                    else:
                        log_text.insert("end",
                                        f"{entry.get('customer_id', '?'):<16}", "user")
                        log_text.insert("end",
                                        f"{entry.get('action', '?'):<24}", "action")
                        log_text.insert("end",
                                        f"{entry.get('timestamp', '?')}\n", "ts")

            ts = datetime.now().strftime("%H:%M:%S")
            count = len(entries)
            if hasattr(self, "_status_var_audit"):
                self._status_var_audit.set(
                    f"  {count} entr{'y' if count == 1 else 'ies'} — loaded at {ts}"
                )

        except Exception as e:
            log_text.insert("end", f"Failed to read log: {e}\n", "err")

        log_text.config(state="disabled")

    # ── Window close ──────────────────────────────────────────────────────────

    def _on_close(self):
        self._stop_server()
        self.destroy()


if __name__ == "__main__":
    app = ServerApp()
    app.mainloop()
